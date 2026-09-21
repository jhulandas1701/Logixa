import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

from app.core.processor import process
from app.intelligence.profile_store import load_all as load_profiles

app = FastAPI(title="Logixa Python Pipeline", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://logixa-three.vercel.app",
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATA = Path(os.getenv("PIPELINE_DATA_DIR", "/data"))
LINEAGE = DATA / "lineage"
LINEAGE.mkdir(parents=True, exist_ok=True)

WORKERS = int(os.getenv("WORKERS", "4"))
MAX_LINES_PER_FILE = int(os.getenv("MAX_LINES_PER_FILE", "10000"))

queue: "asyncio.Queue[dict]" = asyncio.Queue()
jobs: dict[str, dict] = {}
events: dict[str, dict] = {}

stats = {k: 0 for k in [
    "received_jobs",
    "completed_jobs",
    "failed_jobs",
    "known_events",
    "unknown_discovered",
    "profile_reuses",
    "raw_preserved",
]}

by_source: dict[str, int] = {}
by_mode: dict[str, int] = {
    "deterministic": 0,
    "ai_assisted_discovery": 0
}
confidence_bands: dict[str, int] = {
    "high": 0,
    "medium": 0,
    "low": 0
}


class Job(BaseModel):
    ingestion_id: str
    filename: str
    raw_text: str


@app.on_event("startup")
async def startup():
    for i in range(WORKERS):
        asyncio.create_task(worker(i))


@app.get("/health")
async def health():
    return {
        "service": "logixa-python-pipeline",
        "status": "ok",
        "workers": WORKERS,
        "queue_depth": queue.qsize()
    }


# ---------------------------------------------------------
# NEW DIRECT INGESTION ENDPOINT
# ---------------------------------------------------------
@app.post("/internal/process-file")
async def process_file(
    ingestion_id: str = Form(...),
    filename: str = Form(...),
    file: UploadFile = File(...)
):
    try:
        raw_bytes = await file.read()
        raw_text = raw_bytes.decode("utf-8", "replace")

        if not raw_text.strip():
            raise HTTPException(
                status_code=400,
                detail="file contained no log lines"
            )

        job_key = f"{ingestion_id}/{filename}"

        stats["received_jobs"] += 1

        jobs[job_key] = {
            "ingestion_id": ingestion_id,
            "filename": filename,
            "status": "queued",
            "queued_at": now(),
        }

        await queue.put({
            "ingestion_id": ingestion_id,
            "filename": filename,
            "raw_text": raw_text,
            "job_key": job_key,
        })

        return {
            "status": "accepted",
            "ingestion_id": ingestion_id,
            "filename": filename,
            "job_key": job_key,
            "queue_depth": queue.qsize(),
        }

    except HTTPException:
        raise

    except Exception as e:
        stats["failed_jobs"] += 1
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )


@app.get("/api/v1/jobs/{ingestion_id}")
async def get_jobs(ingestion_id: str):
    return {
        "ingestion_id": ingestion_id,
        "jobs": [
            {"job_key": k, **v}
            for k, v in jobs.items()
            if v.get("ingestion_id") == ingestion_id
        ],
    }


@app.get("/api/v1/events/{event_id}")
async def get_event(event_id: str):
    if event_id not in events:
        raise HTTPException(404, "event not found")

    return events[event_id]


@app.get("/api/v1/profiles")
async def profiles():
    return {"profiles": load_profiles()}


@app.get("/api/v1/stats")
async def get_stats():
    return {
        **stats,
        "queue_depth": queue.qsize(),
        "known_profiles": len(load_profiles()),
        "by_source": by_source,
        "by_mode": by_mode,
        "confidence_bands": confidence_bands,
    }


async def worker(worker_id: int):
    while True:
        j = await queue.get()

        try:
            await process_job(j, worker_id)

        except Exception as e:
            stats["failed_jobs"] += 1

            key = j.get("job_key", j.get("filename", "unknown"))

            jobs[key] = {
                **jobs.get(key, {}),
                "status": "failed",
                "error": str(e)
            }

        finally:
            queue.task_done()


async def process_job(j: dict[str, Any], worker_id: int):

    job_key = j["job_key"]
    filename = j["filename"]
    ingestion_id = j["ingestion_id"]

    jobs[job_key] = {
        **jobs.get(job_key, {}),
        "status": "processing",
        "worker_id": worker_id,
        "started_at": now()
    }

    text = j["raw_text"]

    # Preserve raw content.
    stats["raw_preserved"] += 1

    # A file contains multiple log events.
    lines = [
        ln for ln in text.splitlines()
        if ln.strip()
    ]

    if MAX_LINES_PER_FILE and len(lines) > MAX_LINES_PER_FILE:
        truncated = len(lines) - MAX_LINES_PER_FILE
        lines = lines[:MAX_LINES_PER_FILE]
    else:
        truncated = 0

    if not lines:
        jobs[job_key] = {
            **jobs[job_key],
            "status": "failed",
            "error": "file contained no log lines"
        }

        stats["failed_jobs"] += 1
        return

    # Existing ULPF processor.
    results = await asyncio.to_thread(
        _process_lines,
        lines,
        filename,
        job_key
    )

    if not results:
        jobs[job_key] = {
            **jobs[job_key],
            "status": "failed",
            "error": "no log events could be processed"
        }

        stats["failed_jobs"] += 1
        return

    first_event = results[0]["event"]

    sources_seen: dict[str, int] = {}
    lineage_entries = []

    for result in results:

        ev = result["event"]
        mode = result["processing_mode"]

        events[ev["event_id"]] = ev

        if mode == "deterministic":
            stats["known_events"] += 1

        else:
            if result["discovered"]:
                stats["unknown_discovered"] += 1

            if result["reused"]:
                stats["profile_reuses"] += 1

        by_mode[mode] = by_mode.get(mode, 0) + 1

        by_source[ev["source_type"]] = (
            by_source.get(ev["source_type"], 0) + 1
        )

        sources_seen[ev["source_type"]] = (
            sources_seen.get(ev["source_type"], 0) + 1
        )

        band = result["confidence_band"]

        confidence_bands[band] = (
            confidence_bands.get(band, 0) + 1
        )

        lineage_entries.append({
            "event_id": ev["event_id"],
            "raw_event_id": ev["raw_event_id"],
            "profile_id": result["profile_id"],
            "processing_mode": mode,
            "confidence": ev["confidence"],
            "confidence_band": result["confidence_band"],
            "raw_location": result["raw_location"],
        })

    # One lineage file for the complete uploaded file.
    lineage_file = LINEAGE / f"{first_event['event_id']}.json"

    lineage_file.write_text(
        json.dumps({
            "object_name": job_key,
            "ingestion_id": ingestion_id,
            "filename": filename,
            "event_count": len(results),
            "truncated_lines": truncated,
            "sources": sources_seen,
            "events": lineage_entries,
            "processed_at": now(),
        }, indent=2),
        encoding="utf-8"
    )

    dominant = max(
        sources_seen.items(),
        key=lambda kv: kv[1]
    )[0]

    avg_confidence = round(
        sum(
            r["event"]["confidence"]
            for r in results
        ) / len(results),
        3
    )

    jobs[job_key] = {
        **jobs[job_key],
        "status": "completed",
        "event_id": first_event["event_id"],
        "event_count": len(results),
        "source": dominant,
        "sources": sources_seen,
        "processing_mode": results[0]["processing_mode"],
        "confidence": avg_confidence,
        "truncated_lines": truncated,
        "completed_at": now(),
    }

    stats["completed_jobs"] += 1


def _process_lines(
    lines: list[str],
    filename: str,
    obj: str
) -> list[dict]:

    out = []

    for line in lines:
        try:
            out.append(
                process(
                    line,
                    filename,
                    obj
                )
            )

        except Exception as exc:
            stats["failed_jobs"] += 1

            print(
                f"[pipeline] skipped line in "
                f"{obj}: {type(exc).__name__}: {exc}"
            )

    return out


def now() -> str:
    return datetime.now(timezone.utc).isoformat()
