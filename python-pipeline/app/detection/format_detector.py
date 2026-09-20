"""
ULPF - Deterministic Log Format Detector
=========================================

Purpose
-------
Determines the structural format of a log BEFORE source detection.

The detector uses deterministic signals only:

1. Exact formats
   - JSON
   - XML
   - CEF
   - LEEF

2. Standard log formats
   - Syslog RFC3164
   - Syslog RFC5424
   - Common Log Format
   - Combined Log Format

3. Structured formats
   - Key-Value
   - CSV
   - TSV
   - Pipe-delimited
   - Semicolon-delimited

4. Other known structures
   - JSON Lines
   - Timestamped application logs
   - Custom structured logs

5. Fallback
   - Plaintext
   - Empty

Important
---------
This detector identifies FORMAT, not SOURCE.

Example:

Apache Combined Log
-------------------
Format = combined_log
Source = apache

Nginx Combined Log
------------------
Format = combined_log
Source = nginx

Linux SSH syslog
----------------
Format = syslog
Source = linux_auth
"""

from __future__ import annotations

import csv
import io
import json
import re
import xml.etree.ElementTree as ET

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional


# ============================================================
# FORMAT ENUM
# ============================================================

class LogFormat(str, Enum):

    EMPTY = "empty"

    JSON = "json"
    JSON_LINES = "json_lines"

    XML = "xml"

    CEF = "cef"
    LEEF = "leef"

    SYSLOG_RFC3164 = "syslog_rfc3164"
    SYSLOG_RFC5424 = "syslog_rfc5424"

    COMMON_LOG = "common_log"
    COMBINED_LOG = "combined_log"

    KEY_VALUE = "key_value"

    CSV = "csv"
    TSV = "tsv"
    PIPE_DELIMITED = "pipe_delimited"
    SEMICOLON_DELIMITED = "semicolon_delimited"

    TIMESTAMPED_TEXT = "timestamped_text"

    CUSTOM = "custom"
    PLAINTEXT = "plaintext"


# ============================================================
# DETECTION RESULT
# ============================================================

@dataclass
class FormatDetectionResult:

    format: LogFormat
    confidence: float

    method: str

    # Useful for debugging and for your SIH demo
    evidence: List[str]

    # Extracted structural information
    features: Dict[str, object]


# ============================================================
# FORMAT DETECTOR
# ============================================================

class FormatDetector:

    # --------------------------------------------------------
    # Confidence thresholds
    # --------------------------------------------------------

    HIGH_CONFIDENCE = 0.90
    MEDIUM_CONFIDENCE = 0.70

    # --------------------------------------------------------
    # Common patterns
    # --------------------------------------------------------

    # IPv4
    IPV4_RE = re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    )

    # Timestamp:
    # 2026-08-28 20:10:20
    # 2026-08-28T20:10:20
    ISO_TIMESTAMP_RE = re.compile(
        r"\b\d{4}-\d{2}-\d{2}"
        r"[T\s]"
        r"\d{2}:\d{2}:\d{2}"
    )

    # Timestamp with milliseconds
    ISO_TIMESTAMP_MS_RE = re.compile(
        r"\b\d{4}-\d{2}-\d{2}"
        r"[T\s]"
        r"\d{2}:\d{2}:\d{2}"
        r"(?:\.\d+)?"
        r"(?:Z|[+-]\d{2}:?\d{2})?"
    )

    # Syslog RFC3164:
    #
    # Aug 28 20:10:20 server sshd[1234]: message
    #
    RFC3164_RE = re.compile(
        r"^(?:<\d{1,3}>)?"
        r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
        r"\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
        r"\s+\S+"
    )

    # Syslog RFC5424:
    #
    # <34>1 2026-08-28T20:10:20Z host app 123 ID47 - message
    #
    RFC5424_RE = re.compile(
        r"^<\d{1,3}>"
        r"\d+\s+"
        r"\d{4}-\d{2}-\d{2}T"
        r"\d{2}:\d{2}:\d{2}"
    )

    # --------------------------------------------------------
    # Apache / Nginx Common Log Format
    #
    # %h %l %u %t "%r" %>s %b
    #
    # Example:
    # 192.168.1.1 - - [28/Aug/2026:20:10:20 +0530]
    # "GET /index.html HTTP/1.1" 200 1234
    # --------------------------------------------------------

    COMMON_LOG_RE = re.compile(
        r'^\S+\s+\S+\s+\S+\s+'
        r'\[[^\]]+\]\s+'
        r'"[^"]+"\s+'
        r'\d{3}\s+'
        r'(?:\d+|-)'
        r'(?:\s*)$'
    )

    # --------------------------------------------------------
    # Apache/Nginx Combined Log Format
    #
    # %h %l %u %t "%r" %>s %b "%{Referer}i"
    # "%{User-agent}i"
    # --------------------------------------------------------

    COMBINED_LOG_RE = re.compile(
    r'^\S+\s+\S+\s+\S+\s+'
    r'\[[^\]]+\]\s+'
    r'"[^"]+"\s+'
    r'\d{3}\s+'
    r'(?:\d+|-)\s+'
    r'"[^"]*"\s+'
    r'"[^"]*"'
    r'(?:\s+\S+)*\s*$'
)

    # --------------------------------------------------------
    # HTTP request pattern
    # --------------------------------------------------------

    HTTP_REQUEST_RE = re.compile(
        r'"(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)'
        r'\s+\S+\s+HTTP/\d(?:\.\d)?"',
        re.IGNORECASE
    )

    # --------------------------------------------------------
    # CEF
    #
    # CEF:Version|Device Vendor|Device Product|...
    # --------------------------------------------------------

    CEF_RE = re.compile(
        r"^\s*CEF:\d+\|"
    )

    # --------------------------------------------------------
    # LEEF
    #
    # LEEF:Version|Vendor|Product|Version|EventID|
    # --------------------------------------------------------

    LEEF_RE = re.compile(
        r"^\s*LEEF:\d+(?:\.\d+)?\|"
    )

    # --------------------------------------------------------
    # Key=value
    # --------------------------------------------------------

    KV_TOKEN_RE = re.compile(
        r"""
        (?P<key>[A-Za-z_][A-Za-z0-9_.-]*)
        =
        (?:
            "(?:[^"\\]|\\.)*"
            |
            '(?:[^'\\]|\\.)*'
            |
            [^\s]+
        )
        """,
        re.VERBOSE
    )

    # --------------------------------------------------------
    # Log levels
    # --------------------------------------------------------

    LOG_LEVEL_RE = re.compile(
        r"\b(?:TRACE|DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|"
        r"ERR|CRITICAL|FATAL|ALERT|EMERGENCY)\b",
        re.IGNORECASE
    )

    # ========================================================
    # PUBLIC DETECTION METHOD
    # ========================================================

    @classmethod
    def detect(
        cls,
        raw_log: str
    ) -> FormatDetectionResult:

        if raw_log is None:

            return cls._result(
                LogFormat.EMPTY,
                1.0,
                "empty_input",
                ["Input is None"],
            )

        s = raw_log.strip()

        if not s:

            return cls._result(
                LogFormat.EMPTY,
                1.0,
                "empty_input",
                ["Input is empty"],
            )

        # ====================================================
        # STEP 1 - JSON
        # ====================================================

        json_result = cls._detect_json(s)

        if json_result:
            return json_result

        # ====================================================
        # STEP 2 - XML
        # ====================================================

        xml_result = cls._detect_xml(s)

        if xml_result:
            return xml_result

        # ====================================================
        # STEP 3 - CEF
        # ====================================================

        if cls.CEF_RE.search(s):

            return cls._result(
                LogFormat.CEF,
                1.0,
                "cef_signature",
                ["CEF header detected"],
            )

        # ====================================================
        # STEP 4 - LEEF
        # ====================================================

        if cls.LEEF_RE.search(s):

            return cls._result(
                LogFormat.LEEF,
                1.0,
                "leef_signature",
                ["LEEF header detected"],
            )

        # ====================================================
        # STEP 5 - SYSLOG RFC5424
        # ====================================================

        if cls.RFC5424_RE.search(s):

            return cls._result(
                LogFormat.SYSLOG_RFC5424,
                0.99,
                "rfc5424_signature",
                ["RFC5424 priority and ISO timestamp detected"],
            )

        # ====================================================
        # STEP 6 - SYSLOG RFC3164
        # ====================================================

        if cls.RFC3164_RE.search(s):

            return cls._result(
                LogFormat.SYSLOG_RFC3164,
                0.98,
                "rfc3164_signature",
                ["RFC3164 timestamp and hostname structure detected"],
            )

        # ====================================================
        # STEP 7 - COMBINED LOG
        # ====================================================

        if cls.COMBINED_LOG_RE.match(s):

            return cls._result(
                LogFormat.COMBINED_LOG,
                0.99,
                "combined_log_signature",
                [
                    "IP/host field",
                    "timestamp in brackets",
                    "quoted HTTP request",
                    "HTTP status code",
                    "response size",
                    "referer",
                    "user-agent",
                ],
            )

        # ====================================================
        # STEP 8 - COMMON LOG
        # ====================================================

        if cls.COMMON_LOG_RE.match(s):

            return cls._result(
                LogFormat.COMMON_LOG,
                0.98,
                "common_log_signature",
                [
                    "host field",
                    "identity/user fields",
                    "timestamp",
                    "HTTP request",
                    "HTTP status code",
                    "response size",
                ],
            )

        # ====================================================
        # STEP 9 - KEY-VALUE
        # ====================================================

        kv_result = cls._detect_key_value(s)

        if kv_result:

            return kv_result

        # ====================================================
        # STEP 10 - DELIMITED FORMATS
        # ====================================================

        delimiter_result = cls._detect_delimited(s)

        if delimiter_result:

            return delimiter_result

        # ====================================================
        # STEP 11 - TIMESTAMPED APPLICATION LOG
        # ====================================================

        if cls.ISO_TIMESTAMP_MS_RE.search(s):

            evidence = [
                "ISO-style timestamp detected"
            ]

            if cls.LOG_LEVEL_RE.search(s):

                evidence.append(
                    "application log level detected"
                )

            return cls._result(
                LogFormat.TIMESTAMPED_TEXT,
                0.85,
                "timestamp_structure",
                evidence,
            )

        # ====================================================
        # STEP 12 - CUSTOM STRUCTURED FORMAT
        # ====================================================

        custom_result = cls._detect_custom(s)

        if custom_result:

            return custom_result

        # ====================================================
        # STEP 13 - PLAINTEXT
        # ====================================================

        return cls._result(
            LogFormat.PLAINTEXT,
            0.45,
            "fallback",
            [
                "No known deterministic format signature matched"
            ],
        )

    # ========================================================
    # JSON DETECTION
    # ========================================================

    @classmethod
    def _detect_json(
        cls,
        s: str
    ) -> Optional[FormatDetectionResult]:

        # Complete JSON document
        if s[0] not in "{[":
            return None

        try:

            obj = json.loads(s)

        except (json.JSONDecodeError, ValueError):

            return None

        if isinstance(obj, dict):

            return cls._result(
                LogFormat.JSON,
                1.0,
                "json_parser",
                [
                    "Valid JSON object"
                ],
                {
                    "json_type": "object",
                    "keys": list(obj.keys()),
                    "key_count": len(obj),
                },
            )

        if isinstance(obj, list):

            return cls._result(
                LogFormat.JSON,
                1.0,
                "json_parser",
                [
                    "Valid JSON array"
                ],
                {
                    "json_type": "array",
                    "item_count": len(obj),
                },
            )

        return cls._result(
            LogFormat.JSON,
            1.0,
            "json_parser",
            [
                "Valid JSON value"
            ],
        )

    # ========================================================
    # XML DETECTION
    # ========================================================

    @classmethod
    def _detect_xml(
        cls,
        s: str
    ) -> Optional[FormatDetectionResult]:

        if not s.startswith("<"):

            return None

        # Avoid treating <34> syslog as XML
        if re.match(r"^<\d{1,3}>", s):

            return None

        try:

            root = ET.fromstring(s)

        except ET.ParseError:

            return None

        return cls._result(
            LogFormat.XML,
            1.0,
            "xml_parser",
            [
                "Valid XML document"
            ],
            {
                "root_tag": root.tag,
            },
        )

    # ========================================================
    # KEY-VALUE DETECTION
    # ========================================================

    @classmethod
    def _detect_key_value(
        cls,
        s: str
    ) -> Optional[FormatDetectionResult]:

        matches = list(cls.KV_TOKEN_RE.finditer(s))

        if len(matches) < 2:

            return None

        # Reconstruct matched region to determine whether
        # most of the line follows key=value syntax.

        matched_text = " ".join(
            match.group(0)
            for match in matches
        )

        compact_original = re.sub(
            r"\s+",
            " ",
            s
        ).strip()

        # Percentage of recognizable KV tokens
        coverage = len(matched_text) / max(
            len(compact_original),
            1
        )

        keys = [
            match.group("key")
            for match in matches
        ]

        # Strong KV structure
        if len(matches) >= 3 and coverage >= 0.45:

            return cls._result(
                LogFormat.KEY_VALUE,
                min(0.98, 0.75 + coverage * 0.25),
                "key_value_parser",
                [
                    f"{len(matches)} key=value pairs detected"
                ],
                {
                    "keys": keys,
                    "key_count": len(keys),
                    "coverage": round(coverage, 3),
                },
            )

        return None

    # ========================================================
    # DELIMITED FORMAT DETECTION
    # ========================================================

    @classmethod
    def _detect_delimited(
        cls,
        s: str
    ) -> Optional[FormatDetectionResult]:

        # Don't classify an arbitrary line containing a
        # delimiter. Require consistent field structure.

        candidates = [
            (",", LogFormat.CSV, "CSV"),
            ("\t", LogFormat.TSV, "TSV"),
            ("|", LogFormat.PIPE_DELIMITED, "pipe"),
            (";", LogFormat.SEMICOLON_DELIMITED, "semicolon"),
        ]

        for delimiter, fmt, name in candidates:

            if delimiter not in s:

                continue

            fields = cls._parse_delimited(
                s,
                delimiter
            )

            if fields is None:

                continue

            if len(fields) < 3:

                continue

            # Prevent obvious false positives.
            if any(
                not field.strip()
                for field in fields
            ):

                continue

            confidence = cls._delimiter_confidence(
                s,
                delimiter,
                fields,
            )

            if confidence >= 0.70:

                return cls._result(
                    fmt,
                    confidence,
                    f"{name}_structure",
                    [
                        f"{len(fields)} consistent fields",
                        f"delimiter={repr(delimiter)}",
                    ],
                    {
                        "delimiter": delimiter,
                        "field_count": len(fields),
                        "fields": fields,
                    },
                )

        return None

    # ========================================================
    # CSV / DELIMITER PARSER
    # ========================================================

    @staticmethod
    def _parse_delimited(
        s: str,
        delimiter: str
    ) -> Optional[List[str]]:

        try:

            reader = csv.reader(
                io.StringIO(s),
                delimiter=delimiter,
                quotechar='"'
            )

            rows = list(reader)

            if len(rows) != 1:

                return None

            return rows[0]

        except (csv.Error, ValueError):

            return None

    # ========================================================
    # DELIMITER CONFIDENCE
    # ========================================================

    @classmethod
    def _delimiter_confidence(
        cls,
        s: str,
        delimiter: str,
        fields: List[str],
    ) -> float:

        field_count = len(fields)

        if field_count < 3:

            return 0.0

        score = 0.70

        # More fields → stronger evidence
        if field_count >= 5:
            score += 0.08

        if field_count >= 8:
            score += 0.08

        # Quoted fields are common in CSV
        if '"' in s:
            score += 0.05

        # Repeated delimiter structure
        delimiter_count = s.count(delimiter)

        if delimiter_count == field_count - 1:
            score += 0.08

        return min(score, 0.98)

    # ========================================================
    # CUSTOM STRUCTURE DETECTION
    # ========================================================

    @classmethod
    def _detect_custom(
        cls,
        s: str
    ) -> Optional[FormatDetectionResult]:

        evidence = []

        # Multiple structured signals
        token_count = len(s.split())

        ip_count = len(
            cls.IPV4_RE.findall(s)
        )

        timestamp_count = len(
            cls.ISO_TIMESTAMP_RE.findall(s)
        )

        http_count = len(
            cls.HTTP_REQUEST_RE.findall(s)
        )

        log_level = bool(
            cls.LOG_LEVEL_RE.search(s)
        )

        # ----------------------------------------------------
        # Custom structured log
        # ----------------------------------------------------

        if token_count >= 4:

            if ip_count > 0:

                evidence.append(
                    f"{ip_count} IP address(es)"
                )

            if timestamp_count > 0:

                evidence.append(
                    f"{timestamp_count} timestamp(s)"
                )

            if http_count > 0:

                evidence.append(
                    f"{http_count} HTTP request(s)"
                )

            if log_level:

                evidence.append(
                    "log level detected"
                )

        # At least two structural signals
        signal_count = sum(
            [
                ip_count > 0,
                timestamp_count > 0,
                http_count > 0,
                log_level,
            ]
        )

        if signal_count >= 2:

            return cls._result(
                LogFormat.CUSTOM,
                0.70,
                "multi_structure",
                evidence,
                {
                    "token_count": token_count,
                    "ip_count": ip_count,
                    "timestamp_count": timestamp_count,
                    "http_count": http_count,
                    "has_log_level": log_level,
                },
            )

        return None

    # ========================================================
    # RESULT BUILDER
    # ========================================================

    @staticmethod
    def _result(
        fmt: LogFormat,
        confidence: float,
        method: str,
        evidence: List[str],
        features: Optional[Dict[str, object]] = None,
    ) -> FormatDetectionResult:

        return FormatDetectionResult(
            format=fmt,
            confidence=round(
                max(0.0, min(confidence, 1.0)),
                4
            ),
            method=method,
            evidence=evidence,
            features=features or {},
        )


# ============================================================
# TEST CASES (manual smoke test only — not executed by the app)
# ============================================================

if __name__ == "__main__":  # pragma: no cover

    detector = FormatDetector()

    test_logs = {

        "JSON": """
        {
            "timestamp": "2026-08-28T20:10:20Z",
            "level": "ERROR",
            "source": "auth",
            "message": "Login failed",
            "ip": "10.0.0.5"
        }
        """,

        "XML": """
        <event>
            <timestamp>2026-08-28T20:10:20Z</timestamp>
            <level>ERROR</level>
            <message>Login failed</message>
        </event>
        """,

        "CEF": (
            "CEF:0|SecurityVendor|Firewall|1.0|100|"
            "Connection blocked|8|src=10.0.0.5 dst=192.168.1.20"
        ),

        "LEEF": (
            "LEEF:2.0|SecurityVendor|Firewall|1.0|"
            "100|src=10.0.0.5\tdst=192.168.1.20"
        ),

        "RFC3164": (
            "Aug 28 20:10:20 server sshd[1234]: "
            "Failed password for admin from 10.0.0.5"
        ),

        "RFC5424": (
            "<34>1 2026-08-28T20:10:20Z server "
            "sshd 1234 ID47 - "
            "Failed password for admin"
        ),

        "Common Log": (
            '192.168.1.20 - admin '
            '[28/Aug/2026:20:10:20 +0530] '
            '"GET /index.html HTTP/1.1" 200 5234'
        ),

        "Combined Log": (
            '192.168.1.20 - admin '
            '[28/Aug/2026:20:10:20 +0530] '
            '"GET /index.html HTTP/1.1" 200 5234 '
            '"https://example.com" '
            '"Mozilla/5.0"'
        ),

        "Key Value": (
            'timestamp=2026-08-28T20:10:20Z '
            'level=ERROR '
            'src_ip=10.0.0.5 '
            'dst_ip=192.168.1.20 '
            'action=DENY'
        ),

        "CSV": (
            '2026-08-28,20:10:20,10.0.0.5,'
            'admin,LOGIN_FAILED'
        ),

        "TSV": (
            '2026-08-28\t20:10:20\t10.0.0.5\t'
            'admin\tLOGIN_FAILED'
        ),

        "Pipe": (
            '2026-08-28|20:10:20|10.0.0.5|'
            'admin|LOGIN_FAILED'
        ),

        "Semicolon": (
            '2026-08-28;20:10:20;10.0.0.5;'
            'admin;LOGIN_FAILED'
        ),

        "Application": (
            '2026-08-28 20:10:20 ERROR '
            'AuthenticationService Login failed '
            'for user admin from 10.0.0.5'
        ),

        "Plaintext": (
            'Server restarted successfully'
        ),
    }

    for name, log in test_logs.items():

        result = detector.detect(log)

        print("=" * 70)
        print(f"TEST:       {name}")
        print(f"FORMAT:     {result.format.value}")
        print(f"CONFIDENCE: {result.confidence}")
        print(f"METHOD:     {result.method}")
        print(f"EVIDENCE:   {result.evidence}")
        print(f"FEATURES:   {result.features}")