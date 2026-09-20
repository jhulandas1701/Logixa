import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from minio import Minio
from pydantic import BaseModel

from app.core.processor import process
from app.intelligence.profile_store import load_all as load_profiles

app = FastAPI(title="Logixa Python Pipeline", version="2.0.0")

DATA = Path(os.getenv("PIPELINE_DATA_DIR", "/data"))
LINEAGE = DATA / "lineage"
LINEAGE.mkdir(parents=True, exist_ok=True)

mc = Minio(
    os.getenv("MINIO_ENDPOINT", "localhost:9000"),
    access_key=os.getenv("MINIO_ACCESS_KEY", "minioadmin"),
    secret_key=os.getenv("MINIO_SECRET_KEY", "minioadmin"),
    secure=os.getenv("MINIO_SECURE", "false").lower() == "true",
)
BUCKET = os.getenv("MINIO_BUCKET", "logixa-raw")
WORKERS = int(os.getenv("WORKERS", "4"))
# Guard against a single enormous upload monopolizing a worker. 0 disables.
MAX_LINES_PER_FILE = int(os.getenv("MAX_LINES_PER_FILE", "10000"))

queue: "asyncio.Queue[dict]" = asyncio.Queue()
jobs: dict[str, dict] = {}
events: dict[str, dict] = {}
stats = {k: 0 for k in [
    "received_jobs", "completed_jobs", "failed_jobs",
    "known_events", "unknown_discovered", "profile_reuses", "raw_preserved",
]}
# Per-source and per-mode breakdowns backing the dashboard charts.
by_source: dict[str, int] = {}
by_mode: dict[str, int] = {"deterministic": 0, "ai_assisted_discovery": 0}
confidence_bands: dict[str, int] = {"high": 0, "medium": 0, "low": 0}


class Job(BaseModel):
    ingestion_id: str
    object_name: str
    filename: str


@app.on_event("startup")
async def startup():
    for i in range(WORKERS):
        asyncio.create_task(worker(i))


@app.get("/health")
async def health():
    return {"service": "logixa-python-pipeline", "status": "ok", "workers": WORKERS, "queue_depth": queue.qsize()}


# Called by go-ingestor once a file has landed in MinIO.
@app.post("/internal/process")
async def enqueue(j: Job):
    stats["received_jobs"] += 1
    jobs[j.object_name] = {
        "ingestion_id": j.ingestion_id,
        "filename": j.filename,
        "status": "queued",
        "queued_at": now(),
    }
    await queue.put(j.model_dump())
    return {"status": "accepted", "object_name": j.object_name, "queue_depth": queue.qsize()}


@app.get("/api/v1/jobs/{ingestion_id}")
async def get_jobs(ingestion_id: str):
    return {
        "ingestion_id": ingestion_id,
        "jobs": [{"object_name": k, **v} for k, v in jobs.items() if v.get("ingestion_id") == ingestion_id],
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
            jobs[j["object_name"]] = {**jobs.get(j["object_name"], {}), "status": "failed", "error": str(e)}
        finally:
            queue.task_done()


async def process_job(j: dict[str, Any], worker_id: int):
    obj = j["object_name"]
    jobs[obj] = {**jobs.get(obj, {}), "status": "processing", "worker_id": worker_id, "started_at": now()}

    raw_bytes = await asyncio.to_thread(download, obj)
    stats["raw_preserved"] += 1
    text = raw_bytes.decode("utf-8", "replace")

    # A log file is a sequence of events, one per line — not a single
    # event. Feeding the whole blob to process() produced one giant
    # pseudo-event per upload, which also corrupted learned profile IDs
    # (the slug was derived from many concatenated lines).
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if MAX_LINES_PER_FILE and len(lines) > MAX_LINES_PER_FILE:
        truncated = len(lines) - MAX_LINES_PER_FILE
        lines = lines[:MAX_LINES_PER_FILE]
    else:
        truncated = 0

    if not lines:
        jobs[obj] = {**jobs[obj], "status": "failed", "error": "file contained no log lines"}
        stats["failed_jobs"] += 1
        return

    # process() does fingerprinting, known-vs-adaptive parsing, ULPF
    # normalization, DB + raw persistence — see app/core/processor.py.
    # filename/object_name are passed through as metadata hints for
    # SourceDetector (e.g. "auth.log", "access.log").
    results = await asyncio.to_thread(_process_lines, lines, j["filename"], obj)

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
        by_source[ev["source_type"]] = by_source.get(ev["source_type"], 0) + 1
        sources_seen[ev["source_type"]] = sources_seen.get(ev["source_type"], 0) + 1
        band = result["confidence_band"]
        confidence_bands[band] = confidence_bands.get(band, 0) + 1

        lineage_entries.append({
            "event_id": ev["event_id"],
            "raw_event_id": ev["raw_event_id"],
            "profile_id": result["profile_id"],
            "processing_mode": mode,
            "confidence": ev["confidence"],
            "confidence_band": result["confidence_band"],
            "raw_location": result["raw_location"],
        })

    # One lineage document per uploaded object, listing every event derived
    # from it — rather than one file per event, which would scale badly.
    (LINEAGE / f"{first_event['event_id']}.json").write_text(json.dumps({
        "object_name": obj,
        "ingestion_id": j["ingestion_id"],
        "filename": j["filename"],
        "event_count": len(results),
        "truncated_lines": truncated,
        "sources": sources_seen,
        "events": lineage_entries,
        "processed_at": now(),
    }, indent=2))

    # The dominant source is what the UI shows for the file as a whole;
    # per-event detail is available via /api/v1/events/{event_id}.
    dominant = max(sources_seen.items(), key=lambda kv: kv[1])[0]
    avg_confidence = round(sum(r["event"]["confidence"] for r in results) / len(results), 3)

    jobs[obj] = {
        **jobs[obj],
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


def _process_lines(lines: list[str], filename: str, obj: str) -> list[dict]:
    """Run the synchronous processor over every line. Called via
    asyncio.to_thread so a large file doesn't block the event loop."""
    out = []
    for line in lines:
        try:
            out.append(process(line, filename, obj))
        except Exception as exc:
            # One malformed line shouldn't sink the whole file.
            stats["failed_jobs"] += 1
            print(f"[pipeline] skipped line in {obj}: {type(exc).__name__}: {exc}")
    return out


def download(name: str) -> bytes:
    r = mc.get_object(BUCKET, name)
    try:
        return r.read()
    finally:
        r.close()
        r.release_conn()


def now() -> str:
    return datetime.now(timezone.utc).isoformat()
