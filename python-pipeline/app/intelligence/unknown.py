import re

from app.core.utils import kv_pairs, ips, parse_timestamp, normalize_severity
from app.detection.fingerprint import fingerprint, FingerprintResult
from app.detection.format_detector import LogFormat

SEMANTIC = {
    'srcip': 'src_ip', 'src_ip': 'src_ip', 'source_ip': 'src_ip', 'source': 'src_ip', 'src': 'src_ip',
    'dstip': 'dst_ip', 'dst_ip': 'dst_ip', 'dest_ip': 'dst_ip', 'destination': 'dst_ip', 'dst': 'dst_ip',
    'srcport': 'src_port', 'sp': 'src_port', 'dstport': 'dst_port', 'dp': 'dst_port',
    'user': 'username', 'username': 'username', 'host': 'hostname', 'hostname': 'hostname',
    'proto': 'protocol', 'protocol': 'protocol', 'p': 'protocol',
    'severity': 'severity', 'level': 'severity', 'action': 'action', 'dec': 'action',
    'status': 'outcome', 'event': 'event_type', 'event_type': 'event_type',
    'rsn': 'reason', 'reason': 'reason',
}


def analyze_unknown(raw: str, fp: "FingerprintResult | None" = None):
    """Adaptive-discovery fallback for anything the deterministic
    fingerprint/source-detector pipeline didn't confidently claim.

    `fp` can be passed in by the caller (app.core.processor.process) to
    reuse a fingerprint it already computed — including its format
    detection — instead of recomputing it here. If omitted, it's computed
    fresh, same as before.
    """

    if fp is None:
        fp = fingerprint(raw)

    fields = {}
    confidence = 0.15

    k = kv_pairs(raw)
    for key, val in k.items():
        mapped = SEMANTIC.get(key.lower())
        if mapped:
            if mapped in {'src_port', 'dst_port'}:
                try:
                    val = int(val)
                except (TypeError, ValueError):
                    pass
            elif mapped == 'severity':
                val = normalize_severity(val)
            fields[mapped] = val

    ip_list = ips(raw)
    if 'src_ip' not in fields and ip_list:
        fields['src_ip'] = ip_list[0]
    if 'dst_ip' not in fields and len(ip_list) > 1:
        fields['dst_ip'] = ip_list[1]

    ts = re.search(
        r'\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b',
        raw,
    )
    if ts:
        fields['timestamp'] = parse_timestamp(ts.group())

    # ---------------------------------------------------------------
    # Format-aware generic extraction.
    #
    # Even when no specific source/vendor parser claimed this event
    # (fp.source_type == "unknown", or its score fell below the
    # deterministic-parser threshold), the FormatDetector may still have
    # confidently recognized its *shape* — e.g. a well-formed Combined Log
    # Format line from an unbranded/embedded web server, or a CEF/LEEF
    # event from a security vendor Logixa doesn't have a keyword/path hint
    # for. In those cases we can still extract the canonical structural
    # fields generically, which meaningfully raises confidence over the
    # bare key=value/IP-regex sweep above.
    # ---------------------------------------------------------------

    extra_boost = 0.0

    if fp.format in (LogFormat.COMMON_LOG, LogFormat.COMBINED_LOG):

        from app.parsers.access_log_common import parse_common_or_combined

        parsed = parse_common_or_combined(raw)
        if parsed:
            nested = parsed.pop('fields', {})
            for key, val in parsed.items():
                fields.setdefault(key, val)
            for key, val in nested.items():
                fields.setdefault(key, val)
            extra_boost = 0.20

    elif fp.format in (LogFormat.CEF, LogFormat.LEEF):

        from app.parsers.security_device import SecurityDeviceParser

        parsed = SecurityDeviceParser().parse(raw)
        nested = parsed.pop('fields', {})

        for key in (
            'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
            'username', 'action', 'outcome', 'severity', 'event_type',
        ):
            if parsed.get(key) is not None:
                fields.setdefault(key, parsed[key])

        for key, val in nested.items():
            fields.setdefault(key, val)

        if parsed.get('source_vendor'):
            fields.setdefault('device_vendor', parsed['source_vendor'])

        extra_boost = 0.20

    confidence += min(0.45, len(fields) * 0.07)
    confidence += fp.score * 0.30
    confidence += extra_boost

    status = 'normalized' if confidence >= 0.70 else 'low_confidence'

    return fp, fields, min(round(confidence, 3), 0.99), status
