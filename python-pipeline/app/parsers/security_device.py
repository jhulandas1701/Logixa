import re

from .base import Parser
from app.core.utils import kv_pairs, normalize_severity

# CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
CEF_HEADER_RE = re.compile(
    r"^\s*CEF:(?P<cef_version>\d+)\|"
    r"(?P<vendor>[^|]*)\|"
    r"(?P<product>[^|]*)\|"
    r"(?P<device_version>[^|]*)\|"
    r"(?P<signature_id>[^|]*)\|"
    r"(?P<name>[^|]*)\|"
    r"(?P<severity>[^|]*)\|"
    r"(?P<extension>.*)$"
)

# LEEF:Version|Vendor|Product|Version|EventID|Extension
LEEF_HEADER_RE = re.compile(
    r"^\s*LEEF:(?P<leef_version>[\d.]+)\|"
    r"(?P<vendor>[^|]*)\|"
    r"(?P<product>[^|]*)\|"
    r"(?P<device_version>[^|]*)\|"
    r"(?P<event_id>[^|]*)\|"
    r"(?P<extension>.*)$"
)

# Common CEF/LEEF extension key aliases -> canonical ULPF fields.
_EXTENSION_ALIASES = {
    "src": "src_ip",
    "dvc": None,  # device address — kept in fields, not necessarily src
    "dst": "dst_ip",
    "spt": "src_port",
    "dpt": "dst_port",
    "proto": "protocol",
    "act": "action",
    "suser": "username",
    "duser": None,
    "shost": None,
    "dhost": None,
    "cat": "event_type",
    "outcome": "outcome",
    "sev": "severity",
}

_ACTION_OUTCOME = {
    "allow": "success", "allowed": "success", "accept": "success", "permit": "success",
    "deny": "failure", "denied": "failure", "drop": "failure", "block": "failure", "blocked": "failure",
}


def _cef_severity_to_band(value: str):
    """CEF's Severity header field is a 0-10 numeric scale (ArcSight
    convention: 0-3 Low, 4-6 Medium, 7-8 High, 9-10 Very-High) — not one of
    the textual levels app.core.utils.normalize_severity expects, so it
    needs its own mapping before falling back to normalize_severity for
    LEEF/text severities."""

    try:
        n = int(float(value))
    except (TypeError, ValueError):
        return normalize_severity(value)

    if n >= 9:
        return "critical"
    if n >= 7:
        return "high"
    if n >= 4:
        return "medium"
    return "low"


class SecurityDeviceParser(Parser):
    """Vendor-neutral parser for CEF/LEEF-formatted logs from any security
    appliance that doesn't have a dedicated Logixa parser (Cisco ASA,
    FortiGate and Suricata EVE are handled by their own, richer parsers
    before this one is ever reached — see app/detection/source_detector.py)."""

    name = "security_device"
    version = "1.0"

    def parse(self, raw: str):

        stripped = raw.strip()

        d = {
            "source_type": "security_device",
            "source_vendor": None,
            "message": raw,
            "parser_name": self.name,
            "parser_version": self.version,
            "fields": {},
        }

        cef_match = CEF_HEADER_RE.match(stripped)
        leef_match = LEEF_HEADER_RE.match(stripped)

        if cef_match:
            self._apply_header(d, cef_match, log_format="cef")
        elif leef_match:
            self._apply_header(d, leef_match, log_format="leef")
        else:
            # Fell through to this parser without a CEF/LEEF header (e.g. a
            # generic ALLOW/DENY SRC=/DST= line) — extract what we can from
            # bare key=value tokens.
            d["fields"]["log_format"] = "generic_kv"

        extension = None
        if cef_match:
            extension = cef_match.group("extension")
        elif leef_match:
            extension = leef_match.group("extension")
        else:
            extension = stripped

        self._apply_extension(d, extension)

        return d

    @staticmethod
    def _apply_header(d, match, log_format: str):

        vendor = match.group("vendor").strip()
        product = match.group("product").strip()

        if vendor:
            d["source_vendor"] = vendor
            d["fields"]["device_vendor"] = vendor

        if product:
            d["fields"]["device_product"] = product

        device_version = match.group("device_version").strip()
        if device_version:
            d["fields"]["device_version"] = device_version

        d["fields"]["log_format"] = log_format

        if log_format == "cef":
            signature_id = match.group("signature_id").strip()
            name = match.group("name").strip()
            severity = match.group("severity").strip()

            if signature_id:
                d["fields"]["signature_id"] = signature_id
            if name:
                d["fields"]["signature_name"] = name
                d["event_type"] = name
            if severity:
                d["severity"] = _cef_severity_to_band(severity)

        else:  # leef
            event_id = match.group("event_id").strip()
            if event_id:
                d["fields"]["event_id_code"] = event_id
                d["event_type"] = event_id

    @staticmethod
    def _apply_extension(d, extension: str):

        if not extension:
            return

        # LEEF extensions may use tab as a field delimiter but still contain
        # key=value pairs; kv_pairs' regex tolerates that since it doesn't
        # anchor on whitespace-only separation.
        kv = kv_pairs(extension)

        for raw_key, value in kv.items():

            key_lower = raw_key.lower()
            canonical = _EXTENSION_ALIASES.get(key_lower, None)

            if canonical == "src_port" or canonical == "dst_port":
                try:
                    value = int(value)
                except (TypeError, ValueError):
                    pass

            if canonical == "severity":
                # LEEF's "sev" extension field is also numeric (QRadar
                # convention: 1-10), so the same banding applies.
                value = _cef_severity_to_band(value)

            if canonical:
                d[canonical] = value
            else:
                d["fields"][raw_key] = value

        action = d.get("action")
        if action and "outcome" not in d:
            outcome = _ACTION_OUTCOME.get(str(action).lower())
            if outcome:
                d["outcome"] = outcome
