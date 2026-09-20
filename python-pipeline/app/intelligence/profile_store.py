"""Persistence for source profiles learned from unknown/proprietary logs.

app.intelligence.unknown does the per-event field extraction (given a raw
line, pull out src_ip/dst_ip/etc using the SEMANTIC alias table). What it
doesn't do is remember that extraction across events — every unknown line is
analyzed from scratch. This module adds that memory: the first time a new
log *shape* is seen, it's fingerprinted by its set of key= tokens and saved
as a profile; every later event with the same key set reuses that profile
instead of being rediscovered, and is reported back as a reuse rather than a
fresh discovery.
"""
import json
import os
import re
from pathlib import Path
from typing import Optional

from app.core.utils import kv_pairs
from app.intelligence.unknown import SEMANTIC

PROFILES_DIR = Path(os.getenv("PROFILES_DIR", "/data/profiles"))
PROFILES_DIR.mkdir(parents=True, exist_ok=True)

_SLUG_HINT_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9_-]{2,24})[:=|\s]")


def _structural_keys(raw: str) -> list[str]:
    """The set of key= tokens present is a decent structural fingerprint for
    delimited proprietary logs — two lines from the same appliance/format
    will consistently expose the same key set even as values change."""
    return sorted(kv_pairs(raw).keys())


def _slug(raw: str, keys: list[str]) -> str:
    hint_match = _SLUG_HINT_RE.match(raw.strip())
    hint = hint_match.group(1) if hint_match else None
    base = hint or (keys[0] if keys else "unknown")
    slug = re.sub(r"[^a-z0-9]+", "_", base.lower()).strip("_")
    slug = slug[:24].strip("_")  # hard cap — this is a display label, not a hash
    return slug or "unknown"


def _field_mapping(raw: str) -> dict:
    """raw key -> canonical ULPF field name, for whichever keys we recognize."""
    mapping = {}
    for key in kv_pairs(raw):
        sem = SEMANTIC.get(key.lower())
        if sem:
            mapping[key] = sem
    return mapping


def load_all() -> list[dict]:
    out = []
    for p in sorted(PROFILES_DIR.glob("*.json")):
        try:
            out.append(json.loads(p.read_text()))
        except (OSError, json.JSONDecodeError):
            continue
    return out


def match_profile(raw: str) -> Optional[dict]:
    """Find the best existing profile whose required keys are a subset of
    this event's keys. Preferring the most specific (largest) match avoids a
    short generic profile shadowing a more precise one."""
    keys = set(_structural_keys(raw))
    if not keys:
        return None
    best = None
    for profile in load_all():
        required = set(profile.get("fingerprint", {}).get("required_keys", []))
        if required and required.issubset(keys):
            if best is None or len(required) > len(best["fingerprint"]["required_keys"]):
                best = profile
    return best


def record_reuse(profile_id: str) -> None:
    """Bump a profile's reuse_count on disk. Called every time
    match_profile() finds a hit, so /api/v1/profiles can show which
    learned shapes are actually pulling weight versus one-off discoveries."""
    path = PROFILES_DIR / f"{profile_id}.json"
    try:
        profile = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return
    profile["reuse_count"] = profile.get("reuse_count", 0) + 1
    try:
        path.write_text(json.dumps(profile, indent=2))
    except OSError:
        pass


def learn_profile(raw: str, confidence: float, source_type_hint: str) -> dict:
    keys = _structural_keys(raw)
    slug = _slug(raw, keys)

    # Two unrelated log shapes can truncate to the same slug (e.g. both
    # starting with a month name). Before reusing an existing file on disk,
    # confirm it's actually the same shape (same required_keys) — otherwise
    # walk _v2, _v3, ... until we find a real match or a free slot.
    suffix = 1
    while True:
        profile_id = f"{slug}_v{suffix}"
        path = PROFILES_DIR / f"{profile_id}.json"
        if not path.exists():
            break
        try:
            existing = json.loads(path.read_text())
            if existing.get("fingerprint", {}).get("required_keys") == keys:
                return existing
        except (OSError, json.JSONDecodeError):
            pass
        suffix += 1

    profile = {
        "profile_id": profile_id,
        "source_type": source_type_hint or "unknown_source",
        "format": "delimited_key_value",
        "fingerprint": {"required_keys": keys},
        "field_mapping": _field_mapping(raw),
        "confidence": round(confidence, 3),
        "reuse_count": 0,
        "version": "1.0",
        "generated_by": "logixa_discovery_engine",
    }
    path.write_text(json.dumps(profile, indent=2))
    return profile
