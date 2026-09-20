from datetime import datetime, timezone
from typing import Optional

from app.core.utils import TS_RE, event_id, parse_timestamp, raw_id
from app.detection.fingerprint import fingerprint
from app.intelligence.confidence import route
from app.intelligence.profile_store import learn_profile, match_profile, record_reuse
from app.intelligence.unknown import analyze_unknown
from app.parsers.registry import PARSERS
from app.schemas.ulpf_event import ULPFEvent
from app.storage.db import EventRecord, SessionLocal
from app.storage.raw_store import RawStore

raw_store = RawStore()

# The exact set of top-level attributes ULPFEvent will accept. Some parsers
# (cisco_asa in particular) attach extra descriptive attributes straight to
# the top level of the dict they return — e.g. connection_id, src_zone —
# which aren't part of the canonical schema. Pydantic silently drops unknown
# kwargs by default, so without this fold-in step that data would just
# vanish. Instead we sweep anything unrecognized into `fields`.
_ULPF_FIELDS = set(ULPFEvent.model_fields.keys())


def _fold_unrecognized_into_fields(data: dict) -> dict:
    fields = data.setdefault("fields", {})
    for key in list(data.keys()):
        if key in _ULPF_FIELDS or key == "fields":
            continue
        fields.setdefault(key, data.pop(key))
    return data


def _fill_missing_timestamp(data: dict, raw: str) -> None:
    if data.get("timestamp"):
        return
    m = TS_RE.search(raw)
    if m:
        data["timestamp"] = parse_timestamp(m.group())


def process(raw: str, filename: Optional[str] = None, path: Optional[str] = None) -> dict:
    rid = raw_id(raw)
    eid = event_id(raw)

    # filename/path are optional file-metadata hints (e.g. "auth.log",
    # "/var/log/apache2/access.log") that let SourceDetector use its
    # metadata signals in addition to structural/keyword ones — see
    # app/detection/source_detector.py.
    fp = fingerprint(raw, filename=filename, path=path)

    discovered = False
    reused = False

    if fp.source_type in PARSERS and fp.score >= 0.50:
        data = PARSERS[fp.source_type].parse(raw)
        confidence = min(0.99, 0.65 + 0.35 * fp.score)
        status = "normalized"
        mode = "deterministic"
        profile_id = f"{fp.source_type}_v1"

    else:
        # Reuse the fingerprint we already computed (including its format
        # detection) instead of recomputing it from scratch inside
        # analyze_unknown.
        fp_unknown, fields, confidence, status = analyze_unknown(raw, fp=fp)
        mode = "ai_assisted_discovery"

        existing = match_profile(raw)
        if existing:
            profile_id = existing["profile_id"]
            source_type = existing.get("source_type", fp_unknown.source_type)
            confidence = max(confidence, 0.95)
            reused = True
            record_reuse(profile_id)
        else:
            profile = learn_profile(raw, confidence, fp_unknown.source_type or "unknown_source")
            profile_id = profile["profile_id"]
            source_type = profile["source_type"]
            discovered = True

        data = {
            "source_type": source_type,
            "source_vendor": fp_unknown.vendor,
            "message": raw,
            "fields": dict(fields),
            "confidence": confidence,
            "parser_name": "adaptive_intelligence",
            "parser_version": "0.1",
        }
        for k, v in fields.items():
            data[k] = v

    _fold_unrecognized_into_fields(data)
    _fill_missing_timestamp(data, raw)

    data["event_id"] = eid
    data["raw_event_id"] = rid
    data["confidence"] = confidence
    data["processing_status"] = status

    ev = ULPFEvent(**data)
    raw_location = raw_store.put(rid, raw)

    db = SessionLocal()
    try:
        # merge (upsert), not add: identical raw content — e.g. the same
        # sample file uploaded twice for a discovery/reuse demo — hashes to
        # the same event_id, and add() would raise on the primary-key clash.
        db.merge(EventRecord(
            event_id=eid,
            raw_event_id=rid,
            source_profile=profile_id,
            parser_version=ev.parser_version,
            schema_version=ev.schema_version,
            confidence=ev.confidence,
            status=ev.processing_status,
            raw_event=raw,
            normalized_json=ev.model_dump_json(),
            created_at=datetime.now(timezone.utc).replace(tzinfo=None),
        ))
        db.commit()
    finally:
        db.close()

    return {
        "event": ev.model_dump(mode="json"),
        "raw_location": raw_location,
        "confidence_band": route(confidence),
        "processing_mode": mode,
        "profile_id": profile_id,
        "discovered": discovered,
        "reused": reused,
    }
