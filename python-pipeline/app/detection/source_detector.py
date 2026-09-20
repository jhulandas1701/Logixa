"""
Logixa Source Detector
=======================

Determines WHICH system/product most likely produced a log line, given the
FormatDetector's structural classification plus keyword, structural, and
file-metadata signals.

This module is stage 2 of a two-stage deterministic pipeline:

    raw text -> FormatDetector (shape: json / kv / syslog / combined_log /
                cef / leef / csv / ... )
             -> SourceDetector  (identity: cisco_asa / fortigate /
                suricata_eve / apache / nginx / linux_auth /
                security_device / unknown)

Known, deterministically-parseable sources
--------------------------------------------
    cisco_asa          Cisco ASA syslog                 (RFC3164 + %ASA-)
    fortigate          FortiGate traffic/UTM logs        (key=value)
    suricata_eve       Suricata EVE JSON                 (json)
    apache             Apache HTTP Server access logs    (common/combined)
    nginx              Nginx access logs                 (common/combined)
    linux_auth         Linux /var/log/auth.log, sshd/sudo/PAM (syslog)
    security_device    Vendor-neutral CEF/LEEF security appliance

Anything that doesn't clear a confidence floor for one of the above is
reported as "unknown" so Logixa's adaptive discovery pipeline
(app/intelligence/unknown.py + app/intelligence/profile_store.py) can take
over and learn a profile for it instead.

Detection is layered so that highly specific, near-unambiguous signatures
(exact vendor syslog headers, exact JSON field sets) are checked before the
broader, more heuristic multi-signal scoring used for apache/nginx/
linux_auth/security_device — this avoids, e.g., a FortiGate kv log being
mis-scored as a generic "security_device" just because it also contains
SRC=/DST=-style tokens.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from app.detection.format_detector import FormatDetector, FormatDetectionResult, LogFormat


# ============================================================
# DETECTION RESULT
# ============================================================

@dataclass
class DetectionResult:

    source_type: str

    confidence: float

    method: str

    evidence: List[str] = field(default_factory=list)

    scores: Dict[str, float] = field(default_factory=dict)

    # The FormatDetector's output that informed this decision — carried
    # through so callers (fingerprint.py) can expose it without re-running
    # format detection.
    format_result: Optional[FormatDetectionResult] = None

    # Best-effort vendor name, when derivable (e.g. from a CEF/LEEF header).
    vendor: Optional[str] = None


# ============================================================
# SOURCE DETECTOR
# ============================================================

class SourceDetector:

    # --------------------------------------------------------
    # Confidence floor below which we report "unknown" and hand
    # off to the adaptive discovery pipeline.
    # --------------------------------------------------------

    UNKNOWN_FLOOR = 0.30

    # ========================================================
    # VENDOR FAST-PATH SIGNATURES
    #
    # These are near-unambiguous exact-format signatures for the three
    # vendors Logixa already ships hand-written parsers for. They are
    # checked first, before the generic multi-signal scoring below, so a
    # FortiGate/Cisco/Suricata log is never miscategorized as a generic
    # "security_device" just because it also happens to contain SRC=/DST=
    # style tokens.
    # ========================================================

    CISCO_ASA_RE = re.compile(r"%ASA-\d-\d+")
    CISCO_ASA_CONN_RE = re.compile(r"\b(?:Built|Teardown)\b.*\bconnection\b", re.IGNORECASE)

    FORTIGATE_DEVID_RE = re.compile(r'\bdevid="?FG', re.IGNORECASE)
    FORTIGATE_TYPE_RE = re.compile(r'\btype="(?:traffic|utm|event)"', re.IGNORECASE)
    FORTIGATE_IP_RE = re.compile(r"\b(?:srcip|dstip)=", re.IGNORECASE)

    SURICATA_KEYS = ("event_type", "src_ip", "dest_ip", "proto")

    # ========================================================
    # APACHE / NGINX
    # ========================================================

    APACHE_KEYWORDS = ("apache", "apache2", "httpd")
    APACHE_PATHS = (
        "/var/log/apache", "/var/log/apache2",
        "/usr/local/apache", "/usr/local/apache2",
        "/etc/apache", "/etc/httpd",
    )
    APACHE_FILENAMES = ("apache.log", "apache2.log", "httpd.log")

    NGINX_KEYWORDS = ("nginx",)
    NGINX_PATHS = ("/var/log/nginx", "/etc/nginx", "/usr/local/nginx")
    NGINX_FILENAMES = ("nginx.log",)

    GENERIC_ACCESS_FILENAMES = ("access.log", "access_log", "error.log")

    HTTP_REQUEST_RE = re.compile(
        r'"(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)'
        r'\s+\S+\s+HTTP/\d(?:\.\d)?"',
        re.IGNORECASE,
    )
    HTTP_STATUS_RE = re.compile(r'"\s+(?:[1-5]\d{2})\s+(?:\d+|-)')
    APACHE_TIMESTAMP_RE = re.compile(
        r"\[[0-9]{1,2}/"
        r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
        r"/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\]",
        re.IGNORECASE,
    )

    # ========================================================
    # LINUX AUTHENTICATION
    # ========================================================

    LINUX_AUTH_FILENAMES = ("auth.log", "secure", "sshd.log")
    LINUX_AUTH_PATHS = ("/var/log/auth", "/var/log/secure")

    LINUX_AUTH_PATTERNS = [
        re.compile(r"\bsshd(?:\[\d+\])?:", re.IGNORECASE),
        re.compile(r"\bsudo(?:\[\d+\])?:", re.IGNORECASE),
        re.compile(r"\bPAM\b", re.IGNORECASE),
        re.compile(r"\bauthentication failure\b", re.IGNORECASE),
        re.compile(r"\binvalid user\b", re.IGNORECASE),
        re.compile(r"\bsession (?:opened|closed) for user\b", re.IGNORECASE),
    ]

    LINUX_AUTH_STRONG_RE = re.compile(
        r"\b(?:Accepted|Failed)\s+(?:password|publickey|keyboard-interactive)\b",
        re.IGNORECASE,
    )

    # ========================================================
    # GENERIC SECURITY DEVICE (vendor-neutral CEF / LEEF)
    # ========================================================

    FIREWALL_KEYWORD_PATTERNS = [
        re.compile(r"\b(?:ALLOW|DENY|DROP|ACCEPT)\b.*\b(?:SRC|DST|SOURCE|DEST|PROTO)\b", re.IGNORECASE),
        re.compile(r"\b(?:SRC|DST|PROTO|SPORT|DPORT)=", re.IGNORECASE),
        re.compile(r"\bfirewall\b", re.IGNORECASE),
    ]

    # CEF header: CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extension
    CEF_HEADER_RE = re.compile(
        r"^\s*CEF:\d+\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|"
    )

    # LEEF header: LEEF:Version|Vendor|Product|Version|EventID|[delim]|Extension
    LEEF_HEADER_RE = re.compile(
        r"^\s*LEEF:\d+(?:\.\d+)?\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|"
    )

    IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    # ========================================================
    # PUBLIC ENTRY POINT
    # ========================================================

    def detect(
        self,
        raw_log: str,
        filename: Optional[str] = None,
        path: Optional[str] = None,
        extension: Optional[str] = None,
        format_result: Optional[FormatDetectionResult] = None,
    ) -> DetectionResult:

        log = raw_log if isinstance(raw_log, str) else str(raw_log)

        filename_lower = (filename or "").lower()
        path_lower = (path or "").lower()
        extension_lower = (extension or "").lower()

        if format_result is None:
            format_result = FormatDetector.detect(log)

        # ----------------------------------------------------
        # STAGE A — vendor fast path
        # ----------------------------------------------------

        vendor_result = self._detect_vendor_signature(log, format_result)

        if vendor_result:
            return vendor_result

        # ----------------------------------------------------
        # STAGE B — generic multi-signal scoring
        # ----------------------------------------------------

        return self._detect_generic(
            log,
            format_result,
            filename_lower=filename_lower,
            path_lower=path_lower,
            extension_lower=extension_lower,
        )

    # ========================================================
    # STAGE A — VENDOR FAST PATH
    # ========================================================

    @classmethod
    def _detect_vendor_signature(
        cls,
        log: str,
        format_result: FormatDetectionResult,
    ) -> Optional[DetectionResult]:

        # ---- Cisco ASA -------------------------------------
        if cls.CISCO_ASA_RE.search(log):

            evidence = ["%ASA-<facility>-<msg_id> syslog signature"]
            score = 0.95

            if cls.CISCO_ASA_CONN_RE.search(log):
                evidence.append("Built/Teardown connection phrasing")
                score = 0.99

            return DetectionResult(
                source_type="cisco_asa",
                confidence=score,
                method="vendor_signature",
                evidence=evidence,
                scores={"cisco_asa": score},
                format_result=format_result,
                vendor="Cisco",
            )

        # ---- FortiGate --------------------------------------
        if format_result.format == LogFormat.KEY_VALUE or "=" in log:

            forti_hits = sum([
                bool(cls.FORTIGATE_DEVID_RE.search(log)),
                bool(cls.FORTIGATE_TYPE_RE.search(log)),
                bool(cls.FORTIGATE_IP_RE.search(log)),
            ])

            if forti_hits >= 2:

                evidence = ["FortiGate devid/type/srcip-dstip key=value signature"]
                score = min(0.97, 0.70 + 0.10 * forti_hits)

                return DetectionResult(
                    source_type="fortigate",
                    confidence=score,
                    method="vendor_signature",
                    evidence=evidence,
                    scores={"fortigate": score},
                    format_result=format_result,
                    vendor="Fortinet",
                )

        # ---- Suricata EVE JSON ------------------------------
        if format_result.format == LogFormat.JSON:

            keys = format_result.features.get("keys", [])
            hits = sum(1 for k in cls.SURICATA_KEYS if k in keys)

            if hits >= 3:

                evidence = [f"{hits}/{len(cls.SURICATA_KEYS)} Suricata EVE field names present"]
                score = min(0.97, 0.70 + 0.09 * hits)

                return DetectionResult(
                    source_type="suricata_eve",
                    confidence=score,
                    method="vendor_signature",
                    evidence=evidence,
                    scores={"suricata_eve": score},
                    format_result=format_result,
                    vendor="Suricata",
                )

        return None

    # ========================================================
    # STAGE B — GENERIC MULTI-SIGNAL SCORING
    # ========================================================

    @classmethod
    def _detect_generic(
        cls,
        log: str,
        format_result: FormatDetectionResult,
        *,
        filename_lower: str,
        path_lower: str,
        extension_lower: str,
    ) -> DetectionResult:

        log_lower = log.lower()

        scores: Dict[str, float] = {
            "apache": 0.0,
            "nginx": 0.0,
            "linux_auth": 0.0,
            "security_device": 0.0,
        }
        evidence: Dict[str, List[str]] = {k: [] for k in scores}

        # ----------------------------------------------------
        # 1. FILE METADATA SIGNALS
        # ----------------------------------------------------

        if any(p in path_lower for p in cls.APACHE_PATHS):
            scores["apache"] += 0.35
            evidence["apache"].append("Apache log path")

        if any(p in path_lower for p in cls.NGINX_PATHS):
            scores["nginx"] += 0.35
            evidence["nginx"].append("Nginx log path")

        if any(p in path_lower for p in cls.LINUX_AUTH_PATHS):
            scores["linux_auth"] += 0.35
            evidence["linux_auth"].append("Linux auth log path")

        if any(k in filename_lower for k in ("apache", "apache2", "httpd")):
            scores["apache"] += 0.30
            evidence["apache"].append("Apache filename")

        if "nginx" in filename_lower:
            scores["nginx"] += 0.30
            evidence["nginx"].append("Nginx filename")

        if any(f in filename_lower for f in cls.LINUX_AUTH_FILENAMES):
            scores["linux_auth"] += 0.35
            evidence["linux_auth"].append("Linux auth filename (auth.log/secure)")

        if filename_lower in cls.GENERIC_ACCESS_FILENAMES:
            # access.log / error.log alone is not vendor-specific — weak
            # shared signal only.
            scores["apache"] += 0.05
            scores["nginx"] += 0.05
            evidence["apache"].append("generic web access filename")
            evidence["nginx"].append("generic web access filename")

        if extension_lower == ".log":
            scores["apache"] += 0.01
            scores["nginx"] += 0.01

        # ----------------------------------------------------
        # 2. EXPLICIT KEYWORDS
        #
        # A bare keyword mention is weak evidence on its own: "nginx" or
        # "apache2" routinely appear inside unrelated lines, e.g. a sudo
        # command (`COMMAND=/usr/bin/systemctl restart nginx`) or an sshd
        # failure for a user literally named "apache2". Neither log came
        # from a web server. Give keywords full weight only when
        # corroborated by real web-access structure; otherwise cap them
        # low so they can't outrank a genuine structural match from
        # another category (e.g. linux_auth's sshd/sudo patterns).
        #
        # Count once per category, not once per matching keyword:
        # APACHE_KEYWORDS contains overlapping substrings ("apache" is a
        # substring of "apache2"), so a single mention of "apache2" would
        # otherwise score 0.45 twice and reach 0.90 unaided.
        # ----------------------------------------------------

        has_web_structure = (
            format_result.format in (LogFormat.COMMON_LOG, LogFormat.COMBINED_LOG)
            or bool(cls.HTTP_REQUEST_RE.search(log))
            or bool(cls.APACHE_TIMESTAMP_RE.search(log))
        )

        KEYWORD_WEIGHT_CORROBORATED = 0.45
        KEYWORD_WEIGHT_BARE = 0.15
        keyword_weight = (
            KEYWORD_WEIGHT_CORROBORATED if has_web_structure else KEYWORD_WEIGHT_BARE
        )

        matched_apache_kw = next((kw for kw in cls.APACHE_KEYWORDS if kw in log_lower), None)
        if matched_apache_kw:
            scores["apache"] += keyword_weight
            evidence["apache"].append(f"keyword:{matched_apache_kw}")

        matched_nginx_kw = next((kw for kw in cls.NGINX_KEYWORDS if kw in log_lower), None)
        if matched_nginx_kw:
            scores["nginx"] += keyword_weight
            evidence["nginx"].append(f"keyword:{matched_nginx_kw}")

        # ----------------------------------------------------
        # 3. FORMAT-DRIVEN STRUCTURAL SIGNALS
        #
        # The FormatDetector already did the hard work of confirming this
        # is a well-formed Common/Combined Log Format line — that alone is
        # very strong evidence of an Apache/Nginx-style access log, on par
        # with (and more reliable than) the ad-hoc regex re-checks below.
        # ----------------------------------------------------

        if format_result.format in (LogFormat.COMMON_LOG, LogFormat.COMBINED_LOG):
            scores["apache"] += 0.45
            scores["nginx"] += 0.45
            evidence["apache"].append(f"format={format_result.format.value}")
            evidence["nginx"].append(f"format={format_result.format.value}")

        http_request = bool(cls.HTTP_REQUEST_RE.search(log))
        http_status = bool(cls.HTTP_STATUS_RE.search(log))
        apache_timestamp = bool(cls.APACHE_TIMESTAMP_RE.search(log))

        if http_request:
            scores["apache"] += 0.15
            scores["nginx"] += 0.15
            evidence["apache"].append("HTTP request structure")
            evidence["nginx"].append("HTTP request structure")

        if http_status:
            scores["apache"] += 0.08
            scores["nginx"] += 0.08
            evidence["apache"].append("HTTP status + response size")
            evidence["nginx"].append("HTTP status + response size")

        if apache_timestamp:
            scores["apache"] += 0.08
            scores["nginx"] += 0.08
            evidence["apache"].append("Apache/Nginx access timestamp")
            evidence["nginx"].append("Apache/Nginx access timestamp")

        # ----------------------------------------------------
        # 4. LINUX AUTHENTICATION
        # ----------------------------------------------------

        if format_result.format in (LogFormat.SYSLOG_RFC3164, LogFormat.SYSLOG_RFC5424):
            scores["linux_auth"] += 0.10
            evidence["linux_auth"].append(f"format={format_result.format.value}")

        for pattern in cls.LINUX_AUTH_PATTERNS:
            if pattern.search(log):
                scores["linux_auth"] += 0.25
                evidence["linux_auth"].append(f"pattern:{pattern.pattern}")

        if cls.LINUX_AUTH_STRONG_RE.search(log):
            scores["linux_auth"] += 0.35
            evidence["linux_auth"].append("SSH authentication event (Accepted/Failed password)")

        # ----------------------------------------------------
        # 5. GENERIC SECURITY DEVICE (CEF / LEEF / unbranded FW)
        # ----------------------------------------------------

        vendor_hint = None

        if format_result.format == LogFormat.CEF:
            scores["security_device"] += 0.90
            evidence["security_device"].append("CEF signature")
            m = cls.CEF_HEADER_RE.match(log)
            if m:
                vendor_hint = m.group("vendor").strip() or None

        if format_result.format == LogFormat.LEEF:
            scores["security_device"] += 0.90
            evidence["security_device"].append("LEEF signature")
            m = cls.LEEF_HEADER_RE.match(log)
            if m:
                vendor_hint = m.group("vendor").strip() or None

        for pattern in cls.FIREWALL_KEYWORD_PATTERNS:
            if pattern.search(log):
                scores["security_device"] += 0.20
                evidence["security_device"].append("firewall keyword/field pattern")

        if format_result.format == LogFormat.KEY_VALUE:
            kv_keys = format_result.features.get("keys", [])
            if len(kv_keys) >= 3:
                scores["security_device"] += 0.10
                evidence["security_device"].append("multiple key=value fields")

        # ----------------------------------------------------
        # 6. IP + HTTP co-occurrence (web access reinforcement)
        # ----------------------------------------------------

        ip_count = len(cls.IP_RE.findall(log))

        if ip_count >= 1 and http_request:
            scores["apache"] += 0.10
            scores["nginx"] += 0.10
            evidence["apache"].append("IP + HTTP access structure")
            evidence["nginx"].append("IP + HTTP access structure")

        # ----------------------------------------------------
        # NORMALIZE
        # ----------------------------------------------------

        normalized = {k: min(round(v, 4), 1.0) for k, v in scores.items()}

        ranked = sorted(normalized.items(), key=lambda item: item[1], reverse=True)
        best_source, best_score = ranked[0]
        second_score = ranked[1][1] if len(ranked) > 1 else 0.0

        # ----------------------------------------------------
        # DECISION
        # ----------------------------------------------------

        if best_score < cls.UNKNOWN_FLOOR:

            return DetectionResult(
                source_type="unknown",
                confidence=round(best_score, 4),
                method="insufficient_evidence",
                evidence=[],
                scores=normalized,
                format_result=format_result,
            )

        # Ambiguous apache-vs-nginx: content alone can't tell them apart
        # (both speak identical Common/Combined Log Format by default).
        # Prefer whichever metadata explicitly names; otherwise report the
        # higher scorer but keep both scores visible.
        if (
            best_source in {"apache", "nginx"}
            and second_score >= 0.75
            and abs(best_score - second_score) < 0.15
        ):

            if any(p in path_lower for p in cls.APACHE_PATHS) or any(
                k in filename_lower for k in ("apache", "apache2", "httpd")
            ):
                return DetectionResult(
                    source_type="apache",
                    confidence=round(min(best_score + 0.15, 1.0), 4),
                    method="metadata_plus_structure",
                    evidence=evidence["apache"],
                    scores=normalized,
                    format_result=format_result,
                )

            if any(p in path_lower for p in cls.NGINX_PATHS) or "nginx" in filename_lower:
                return DetectionResult(
                    source_type="nginx",
                    confidence=round(min(best_score + 0.15, 1.0), 4),
                    method="metadata_plus_structure",
                    evidence=evidence["nginx"],
                    scores=normalized,
                    format_result=format_result,
                )

            return DetectionResult(
                source_type=best_source,
                confidence=round(best_score, 4),
                method="structural_web_log_ambiguous",
                evidence=evidence[best_source],
                scores=normalized,
                format_result=format_result,
            )

        return DetectionResult(
            source_type=best_source,
            confidence=round(best_score, 4),
            method="multi_signal",
            evidence=evidence[best_source],
            scores=normalized,
            format_result=format_result,
            vendor=vendor_hint if best_source == "security_device" else None,
        )
