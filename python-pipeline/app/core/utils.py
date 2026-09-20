import hashlib, re
from datetime import datetime, timezone

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
KV_RE = re.compile(r"(?P<key>[A-Za-z_][\w.-]*)=(?P<value>\"[^\"]*\"|'[^']*'|[^\s,|]+)")
TS_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b")
PORT_RE = re.compile(r"\bport[= ](?P<p>\d{1,5})\b", re.I)

def event_id(raw: str) -> str:
    return "EVT-" + hashlib.sha256(raw.encode()).hexdigest()[:16]

def raw_id(raw: str) -> str:
    return "RAW-" + hashlib.sha256(raw.encode()).hexdigest()[:16]

def ips(raw: str): return IP_RE.findall(raw)

def kv_pairs(raw: str):
    out={}
    for m in KV_RE.finditer(raw):
        v=m.group('value').strip('"\'')
        out[m.group('key')]=v
    return out

def parse_timestamp(value: str | None):
    if not value: return None
    v=value.replace('Z','+00:00')
    try: return datetime.fromisoformat(v)
    except ValueError: return None

def normalize_severity(value):
    if value is None: return None
    v=str(value).lower()
    return {'emerg':'critical','alert':'critical','crit':'critical','critical':'critical','err':'high','error':'high','warning':'medium','warn':'medium','notice':'low','info':'info','debug':'debug'}.get(v,v)
