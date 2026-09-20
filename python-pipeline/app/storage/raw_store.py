"""Content-addressed storage for raw event bodies, keyed by raw_event_id.

Backed by the local filesystem under the same /data volume already used for
profiles and lineage — no extra service needed for an MVP. The raw upload
itself already lives in MinIO (that's what go-ingestor stores); this is a
second, smaller copy indexed by content hash so a single normalized event
can always be traced back to exactly the bytes it was derived from, even if
the source object in MinIO is later moved or deleted.
"""
import os
from pathlib import Path
from typing import Optional


class RawStore:
    def __init__(self, base_dir: Optional[str] = None):
        self.base = Path(base_dir or os.getenv("RAW_STORE_DIR", "/data/raw"))
        self.base.mkdir(parents=True, exist_ok=True)

    def put(self, raw_event_id: str, raw: str) -> str:
        path = self.base / f"{raw_event_id}.raw"
        if not path.exists():
            path.write_text(raw, encoding="utf-8", errors="replace")
        return str(path)

    def get(self, raw_event_id: str) -> Optional[str]:
        path = self.base / f"{raw_event_id}.raw"
        if not path.exists():
            return None
        return path.read_text(encoding="utf-8", errors="replace")
