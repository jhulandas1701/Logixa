import re

from .base import Parser
from app.core.utils import kv_pairs, normalize_severity, parse_timestamp


class FortiGateParser(Parser):

    name = "fortigate"
    version = "1.1"

    def parse(self, raw: str):

        # ---------------------------------------------------------
        # Base event
        # ---------------------------------------------------------

        d = {
            "source_type": "fortigate",
            "source_vendor": "Fortinet",
            "message": raw,
            "parser_name": self.name,
            "parser_version": self.version,
            "fields": {}
        }

        # ---------------------------------------------------------
        # Parse key=value pairs
        # ---------------------------------------------------------

        k = kv_pairs(raw)

        # ---------------------------------------------------------
        # Helper
        # ---------------------------------------------------------

        def first_value(*keys):

            for key in keys:
                value = k.get(key)

                if value is not None and value != "":
                    return value

            return None

        def to_int(value):

            if value is None:
                return None

            try:
                return int(value)
            except (ValueError, TypeError):
                return value

        # ---------------------------------------------------------
        # Basic FortiGate metadata
        # ---------------------------------------------------------

        devname = first_value("devname", "hostname")

        if devname:
            d["hostname"] = devname

        d["fields"]["device_id"] = first_value(
            "devid",
            "deviceid"
        )

        d["fields"]["vd"] = first_value("vd")

        d["fields"]["log_id"] = first_value(
            "logid",
            "log_id"
        )

        # ---------------------------------------------------------
        # Event classification
        # ---------------------------------------------------------

        event_type = first_value(
            "eventtype",
            "event_type",
            "subtype",
            "type"
        )

        if event_type:
            d["event_type"] = event_type

        # Keep FortiGate's original type/subtype information
        if "type" in k:
            d["fields"]["fortigate_type"] = k["type"]

        if "subtype" in k:
            d["fields"]["fortigate_subtype"] = k["subtype"]

        # ---------------------------------------------------------
        # Network fields
        # ---------------------------------------------------------

        src_ip = first_value(
            "srcip",
            "src_ip",
            "sourceip",
            "source_ip"
        )

        dst_ip = first_value(
            "dstip",
            "dst_ip",
            "destinationip",
            "destination_ip"
        )

        src_port = first_value(
            "srcport",
            "src_port",
            "sourceport"
        )

        dst_port = first_value(
            "dstport",
            "dst_port",
            "destinationport"
        )

        if src_ip:
            d["src_ip"] = src_ip

        if dst_ip:
            d["dst_ip"] = dst_ip

        if src_port is not None:
            d["src_port"] = to_int(src_port)

        if dst_port is not None:
            d["dst_port"] = to_int(dst_port)

        # ---------------------------------------------------------
        # Protocol normalization
        # ---------------------------------------------------------

        proto = first_value(
            "proto",
            "protocol"
        )

        if proto is not None:

            protocol_map = {
                "1": "ICMP",
                "6": "TCP",
                "17": "UDP",
                "icmp": "ICMP",
                "tcp": "TCP",
                "udp": "UDP"
            }

            d["protocol"] = protocol_map.get(
                str(proto).lower(),
                str(proto).upper()
            )

        # ---------------------------------------------------------
        # Username
        # ---------------------------------------------------------

        username = first_value(
            "user",
            "username",
            "srcuser",
            "dstuser"
        )

        if username:
            d["username"] = username

        # ---------------------------------------------------------
        # Action
        # ---------------------------------------------------------

        action = first_value(
            "action",
            "status"
        )

        if action:
            d["action"] = str(action).lower()

        # ---------------------------------------------------------
        # Outcome
        # ---------------------------------------------------------

        status = first_value("status")

        if status:
            status_lower = str(status).lower()

            if status_lower in {
                "success",
                "accepted",
                "accept",
                "allowed",
                "allow",
                "ok"
            }:
                d["outcome"] = "success"

            elif status_lower in {
                "failed",
                "failure",
                "denied",
                "deny",
                "blocked",
                "block",
                "error"
            }:
                d["outcome"] = "failure"

            else:
                d["outcome"] = status_lower

        elif action:

            action_lower = str(action).lower()

            if action_lower in {
                "accept",
                "accepted",
                "allow",
                "allowed"
            }:
                d["outcome"] = "success"

            elif action_lower in {
                "deny",
                "denied",
                "block",
                "blocked",
                "reject",
                "rejected"
            }:
                d["outcome"] = "failure"

        # ---------------------------------------------------------
        # Severity
        # ---------------------------------------------------------

        severity = first_value(
            "level",
            "severity"
        )

        if severity is not None:
            d["severity"] = normalize_severity(
                str(severity)
            )

        # ---------------------------------------------------------
        # Timestamp
        # ---------------------------------------------------------

        date = first_value("date")
        time = first_value("time")

        if date and time:

            try:
                d["timestamp"] = parse_timestamp(
                    f"{date}T{time}"
                )
            except Exception:
                pass

        # Some FortiGate logs may already provide a timestamp
        if "timestamp" in k and "timestamp" not in d:

            try:
                d["timestamp"] = parse_timestamp(
                    k["timestamp"]
                )
            except Exception:
                pass

        # ---------------------------------------------------------
        # Interface information
        # ---------------------------------------------------------

        if "srcintf" in k:
            d["fields"]["src_interface"] = k["srcintf"]

        if "dstintf" in k:
            d["fields"]["dst_interface"] = k["dstintf"]

        if "srcintfrole" in k:
            d["fields"]["src_interface_role"] = k["srcintfrole"]

        if "dstintfrole" in k:
            d["fields"]["dst_interface_role"] = k["dstintfrole"]

        # ---------------------------------------------------------
        # Firewall-specific information
        # ---------------------------------------------------------

        firewall_fields = [
            "policyid",
            "policytype",
            "policyname",
            "sessionid",
            "service",
            "app",
            "appcat",
            "trandisp",
            "transip",
            "transport",
            "sentbyte",
            "rcvdbyte",
            "sentpkt",
            "rcvdpkt",
            "duration",
            "logid",
            "vd",
            "devtype",
            "devcategory",
            "osname",
            "srcmac",
            "dstmac"
        ]

        for field in firewall_fields:

            if field in k:
                d["fields"][field] = k[field]

        # ---------------------------------------------------------
        # Useful geographic information
        # ---------------------------------------------------------

        for field in [
            "srccountry",
            "dstcountry",
            "srcintf",
            "dstintf"
        ]:

            if field in k and field not in d["fields"]:
                d["fields"][field] = k[field]

        # ---------------------------------------------------------
        # Preserve additional vendor-specific fields
        # ---------------------------------------------------------

        universal_keys = {
            "devname",
            "hostname",
            "devid",
            "deviceid",
            "vd",
            "logid",
            "log_id",
            "type",
            "subtype",
            "eventtype",
            "event_type",
            "srcip",
            "src_ip",
            "dstip",
            "dst_ip",
            "srcport",
            "src_port",
            "dstport",
            "dst_port",
            "sourceip",
            "source_ip",
            "destinationip",
            "destination_ip",
            "sourceport",
            "destinationport",
            "proto",
            "protocol",
            "user",
            "username",
            "srcuser",
            "dstuser",
            "action",
            "status",
            "level",
            "severity",
            "date",
            "time",
            "timestamp"
        }

        for key, value in k.items():

            if key not in universal_keys:

                if key not in d["fields"]:
                    d["fields"][key] = value

        return d
