import re

from .base import Parser
from app.core.utils import normalize_severity


class CiscoASAParser(Parser):
    name = "cisco_asa"
    version = "1.1"

    def parse(self, raw: str):

        d = {
            "source_type": "cisco_asa",
            "source_vendor": "Cisco",
            "message": raw,
            "parser_name": self.name,
            "parser_version": self.version,
        }

        # ---------------------------------------------------------
        # 1. Cisco ASA syslog severity
        # ---------------------------------------------------------
        severity_match = re.search(
            r"%ASA-(?P<facility>\d+)-(?P<msg_id>\d+)",
            raw,
            re.I
        )

        if severity_match:
            severity_level = severity_match.group("facility")

            # Cisco ASA syslog severity:
            # 0 = Emergency
            # 1 = Alert
            # 2 = Critical
            # 3 = Error
            # 4 = Warning
            # 5 = Notification
            # 6 = Informational
            # 7 = Debugging

            severity_map = {
                "0": "critical",
                "1": "critical",
                "2": "critical",
                "3": "high",
                "4": "medium",
                "5": "low",
                "6": "info",
                "7": "debug",
            }

            d["severity"] = normalize_severity(
                severity_map.get(severity_level)
            )

            d["event_id_code"] = severity_match.group("msg_id")

        # ---------------------------------------------------------
        # 2. TCP / UDP connection extraction
        #
        # Example:
        # Built outbound TCP connection 123
        # for outside:10.0.0.5/443
        # to inside:192.168.1.20/51500
        # ---------------------------------------------------------

        connection_match = re.search(
            r"""
            (?P<direction>inbound|outbound)?
            \s*
            (?P<protocol>TCP|UDP)
            \s+
            connection\s+
            (?P<connection_id>\d+)
            .*?
            (?P<src_zone>[A-Za-z0-9_-]+):
            (?P<src_ip>(?:\d{1,3}\.){3}\d{1,3})
            /
            (?P<src_port>\d+)
            \s+
            to
            \s+
            (?P<dst_zone>[A-Za-z0-9_-]+):
            (?P<dst_ip>(?:\d{1,3}\.){3}\d{1,3})
            /
            (?P<dst_port>\d+)
            """,
            raw,
            re.IGNORECASE | re.VERBOSE
        )

        if connection_match:

            d["protocol"] = connection_match.group("protocol").upper()

            d["src_ip"] = connection_match.group("src_ip")
            d["src_port"] = int(connection_match.group("src_port"))

            d["dst_ip"] = connection_match.group("dst_ip")
            d["dst_port"] = int(connection_match.group("dst_port"))

            d["connection_id"] = int(
                connection_match.group("connection_id")
            )

            d["src_zone"] = connection_match.group("src_zone")
            d["dst_zone"] = connection_match.group("dst_zone")

            d["direction"] = connection_match.group("direction")

            d["event_type"] = "network_connection"

        # ---------------------------------------------------------
        # 3. Generic IP fallback
        #
        # If the connection-specific regex fails,
        # still try to recover IP addresses.
        # ---------------------------------------------------------

        if not d.get("src_ip") or not d.get("dst_ip"):

            ip_matches = re.findall(
                r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
                raw
            )

            if len(ip_matches) >= 2:

                d["src_ip"] = ip_matches[0]
                d["dst_ip"] = ip_matches[1]

        # ---------------------------------------------------------
        # 4. Generic port fallback
        # ---------------------------------------------------------

        if not d.get("src_port") or not d.get("dst_port"):

            connection_ports = re.findall(
                r":(?:\d{1,3}\.){3}\d{1,3}/(\d+)",
                raw
            )

            if len(connection_ports) >= 2:

                d["src_port"] = int(connection_ports[0])
                d["dst_port"] = int(connection_ports[1])

        # ---------------------------------------------------------
        # 5. Action
        # ---------------------------------------------------------

        if re.search(r"\bBuilt\b", raw, re.I):
            d["action"] = "allow"

        elif re.search(r"\bTeardown\b", raw, re.I):
            d["action"] = "terminate"

        # ---------------------------------------------------------
        # 6. Outcome
        # ---------------------------------------------------------

        if d.get("action") == "allow":
            d["outcome"] = "success"

        elif d.get("action") == "terminate":
            d["outcome"] = "terminated"

        return d
