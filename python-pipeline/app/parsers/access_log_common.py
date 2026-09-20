"""
Shared parsing for Apache/Nginx-style Common and Combined Log Format access
logs.

    %h %l %u %t "%r" %>s %b                       (Common Log Format)
    %h %l %u %t "%r" %>s %b "%{Referer}i" "%{UA}i" (Combined Log Format)

Apache and Nginx emit the (near-)identical wire format by default, so the
extraction logic is shared between app/parsers/apache.py and
app/parsers/nginx.py — only the source_type/vendor differ.
"""

import re
from typing import Any, Dict

from app.core.utils import normalize_severity, parse_timestamp

# 192.168.1.20 - admin [28/Aug/2026:20:10:20 +0530] "GET /index.html HTTP/1.1" 200 5234 "https://example.com" "Mozilla/5.0"
ACCESS_LOG_RE = re.compile(
    r'^(?P<host>\S+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
    r'(?P<extra>(?:\s+.*)?)$'
)

REQUEST_RE = re.compile(
    r'^(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/(?P<http_version>\d(?:\.\d)?)$'
)

# [28/Aug/2026:20:10:20 +0530]
ACCESS_TIME_RE = re.compile(
    r'(?P<day>\d{1,2})/(?P<mon>[A-Za-z]{3})/(?P<year>\d{4}):'
    r'(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})\s+'
    r'(?P<tz>[+-]\d{4})'
)

_MONTHS = {
    m: i for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
        start=1,
    )
}


def parse_access_time(value: str):
    """Parse Apache/Nginx bracket timestamp into an ISO-8601 string that
    app.core.utils.parse_timestamp can consume, or None if unparseable."""

    m = ACCESS_TIME_RE.match(value)
    if not m:
        return None

    month = _MONTHS.get(m.group("mon")[:3].title())
    if not month:
        return None

    iso = (
        f"{m.group('year')}-{month:02d}-{int(m.group('day')):02d}"
        f"T{m.group('hour')}:{m.group('minute')}:{m.group('second')}"
        f"{m.group('tz')[:3]}:{m.group('tz')[3:]}"
    )

    return parse_timestamp(iso)


def status_to_severity(status: int) -> str:
    if status >= 500:
        return normalize_severity("error")
    if status >= 400:
        return normalize_severity("warning")
    return normalize_severity("info")


def status_to_outcome(status: int) -> str:
    return "success" if status < 400 else "failure"


def parse_common_or_combined(raw: str) -> Dict[str, Any]:
    """Extract the canonical field set shared by Apache/Nginx access logs.
    Returns an empty dict if the line doesn't match the expected shape —
    callers fall back to their own generic handling in that case."""

    m = ACCESS_LOG_RE.match(raw.strip())
    if not m:
        return {}

    d: Dict[str, Any] = {}

    host = m.group("host")
    if host and host != "-":
        # Could be an IP or a hostname depending on server config.
        if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", host):
            d["src_ip"] = host
        else:
            d["hostname"] = host

    ident = m.group("ident")
    user = m.group("user")
    if user and user != "-":
        d["username"] = user
    elif ident and ident != "-":
        d["username"] = ident

    ts = parse_access_time(m.group("time"))
    if ts:
        d["timestamp"] = ts

    request = m.group("request")
    rm = REQUEST_RE.match(request) if request else None
    if rm:
        d["event_type"] = "http_request"
        d.setdefault("fields", {})
        d["fields"]["http_method"] = rm.group("method")
        d["fields"]["http_path"] = rm.group("path")
        d["fields"]["http_version"] = rm.group("http_version")
    elif request:
        d.setdefault("fields", {})
        d["fields"]["http_request_raw"] = request

    status_str = m.group("status")
    try:
        status = int(status_str)
        d["fields"] = d.get("fields", {})
        d["fields"]["http_status"] = status
        d["severity"] = status_to_severity(status)
        d["outcome"] = status_to_outcome(status)
        d["action"] = "request"
    except (TypeError, ValueError):
        pass

    size = m.group("size")
    if size and size != "-":
        d.setdefault("fields", {})
        d["fields"]["response_bytes"] = int(size)

    referer = m.group("referer")
    if referer is not None:
        d.setdefault("fields", {})
        d["fields"]["referer"] = referer

    user_agent = m.group("user_agent")
    if user_agent is not None:
        d.setdefault("fields", {})
        d["fields"]["user_agent"] = user_agent

    # ------------------------------------------------------------
    # Optional vendor/custom extension fields
    #
    # Example:
    #   ... "Mozilla/5.0 ..." 3594
    #
    # Preserve all trailing fields and promote a single numeric
    # trailing field to response_time.
    # ------------------------------------------------------------
    extra = (m.group("extra") or "").strip()

    if extra:
        tokens = extra.split()

        d.setdefault("fields", {})

        # Lossless preservation of any extra fields
        d["fields"]["extra_fields"] = tokens

        # Common case in your logfiles.log:
        # one numeric field after the User-Agent
        if len(tokens) == 1 and re.fullmatch(r"\d+(?:\.\d+)?", tokens[0]):
            number = float(tokens[0]) if "." in tokens[0] else int(tokens[0])
            d["fields"]["response_time"] = number

    return d
