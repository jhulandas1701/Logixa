"""
Logixa Fingerprint Orchestrator
================================

Thin, backward-compatible facade over the two-stage deterministic detection
pipeline:

    FormatDetector   -> structural shape  (json, kv, syslog, combined_log,
                                            cef, leef, csv, ...)
    SourceDetector   -> product identity  (cisco_asa, fortigate,
                                            suricata_eve, apache, nginx,
                                            linux_auth, security_device,
                                            unknown)

`fingerprint(raw)` is the existing public entry point used by
app/core/processor.py and app/intelligence/unknown.py — its signature and
FingerprintResult shape (source_type, vendor, score, reasons) are preserved
so neither caller needs to change beyond optionally passing filename/path
for stronger metadata-driven detection.

The richer DetectionResult (per-source scores, matched format, etc.) is
still available on the result via `.detection` / `.format_result` for
callers that want it (e.g. for surfacing "why" in the UI/API).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.detection.format_detector import FormatDetector, FormatDetectionResult, LogFormat
from app.detection.source_detector import SourceDetector, DetectionResult


# ============================================================
# RESULT
# ============================================================

@dataclass
class FingerprintResult:

    source_type: str
    vendor: Optional[str]
    score: float
    reasons: List[str]

    # Extra context beyond the legacy fields, kept optional so existing
    # `FingerprintResult('unknown', None, 0.0, [])`-style construction
    # elsewhere (tests, etc.) still works.
    format: Optional[LogFormat] = None
    detection: Optional[DetectionResult] = None
    scores: Dict[str, float] = field(default_factory=dict)


# ============================================================
# VENDOR NAME LOOKUP
# ============================================================

_VENDOR_BY_SOURCE = {
    "cisco_asa": "Cisco",
    "fortigate": "Fortinet",
    "suricata_eve": "Suricata",
    "apache": "Apache Software Foundation",
    "nginx": "NGINX",
    "linux_auth": "Linux (PAM/sshd/sudo)",
}

_source_detector = SourceDetector()


# ============================================================
# PUBLIC ENTRY POINT
# ============================================================

def fingerprint(
    raw: str,
    filename: Optional[str] = None,
    path: Optional[str] = None,
    extension: Optional[str] = None,
) -> FingerprintResult:

    format_result: FormatDetectionResult = FormatDetector.detect(raw)

    detection: DetectionResult = _source_detector.detect(
        raw,
        filename=filename,
        path=path,
        extension=extension,
        format_result=format_result,
    )

    vendor = detection.vendor or _VENDOR_BY_SOURCE.get(detection.source_type)

    return FingerprintResult(
        source_type=detection.source_type,
        vendor=vendor,
        score=detection.confidence,
        reasons=detection.evidence,
        format=format_result.format,
        detection=detection,
        scores=detection.scores,
    )
