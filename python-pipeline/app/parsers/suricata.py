import json

from .base import Parser
from app.core.utils import parse_timestamp, normalize_severity


class SuricataEVEParser(Parser):

    name = "suricata_eve"
    version = "1.1"

    def parse(self, raw: str):

        # ---------------------------------------------------------
        # Parse JSON
        # ---------------------------------------------------------

        x = json.loads(raw)

        # ---------------------------------------------------------
        # Base event
        # ---------------------------------------------------------

        d = {
            "source_type": "suricata_eve",
            "source_vendor": "Suricata",
            "message": raw,
            "parser_name": self.name,
            "parser_version": self.version,
            "fields": {}
        }

        # ---------------------------------------------------------
        # Timestamp
        # ---------------------------------------------------------

        if x.get("timestamp"):

            try:
                d["timestamp"] = parse_timestamp(
                    x["timestamp"]
                )
            except Exception:
                d["timestamp"] = x["timestamp"]

        # ---------------------------------------------------------
        # Event type
        # ---------------------------------------------------------

        if x.get("event_type"):

            d["event_type"] = x["event_type"]

        # ---------------------------------------------------------
        # Network information
        # ---------------------------------------------------------

        if x.get("src_ip") is not None:
            d["src_ip"] = x["src_ip"]

        if x.get("src_port") is not None:

            try:
                d["src_port"] = int(x["src_port"])
            except (ValueError, TypeError):
                d["src_port"] = x["src_port"]

        if x.get("dest_ip") is not None:
            d["dst_ip"] = x["dest_ip"]

        if x.get("dest_port") is not None:

            try:
                d["dst_port"] = int(x["dest_port"])
            except (ValueError, TypeError):
                d["dst_port"] = x["dest_port"]

        # ---------------------------------------------------------
        # Protocol
        # ---------------------------------------------------------

        if x.get("proto") is not None:

            protocol_map = {
                "TCP": "TCP",
                "UDP": "UDP",
                "ICMP": "ICMP",
                "1": "ICMP",
                "6": "TCP",
                "17": "UDP"
            }

            proto = str(x["proto"])

            d["protocol"] = protocol_map.get(
                proto.upper(),
                proto.upper()
            )

        # ---------------------------------------------------------
        # Application protocol
        # ---------------------------------------------------------

        if x.get("app_proto"):

            d["fields"]["application_protocol"] = (
                x["app_proto"]
            )

        # ---------------------------------------------------------
        # Flow information
        # ---------------------------------------------------------

        flow_fields = [
            "flow_id",
            "community_id",
            "packet",
            "pkts_toserver",
            "pkts_toclient",
            "bytes_toserver",
            "bytes_toclient"
        ]

        for field in flow_fields:

            if field in x:
                d["fields"][field] = x[field]

        # ---------------------------------------------------------
        # Alert information
        # ---------------------------------------------------------

        alert = x.get("alert")

        if isinstance(alert, dict):

            # An alert itself is an action
            d["action"] = "alert"

            # Detection outcome
            d["outcome"] = "detected"

            # Signature
            if alert.get("signature"):

                d["fields"]["signature"] = (
                    alert["signature"]
                )

            # Signature ID
            if alert.get("signature_id") is not None:

                d["fields"]["signature_id"] = (
                    alert["signature_id"]
                )

            # Revision
            if alert.get("rev") is not None:

                d["fields"]["signature_revision"] = (
                    alert["rev"]
                )

            # Category
            if alert.get("category"):

                d["fields"]["category"] = (
                    alert["category"]
                )

            # Severity
            if alert.get("severity") is not None:

                severity = alert["severity"]

                # Suricata commonly uses:
                # 1 = high
                # 2 = medium
                # 3 = low

                severity_map = {
                    1: "high",
                    2: "medium",
                    3: "low",
                    "1": "high",
                    "2": "medium",
                    "3": "low"
                }

                normalized = severity_map.get(
                    severity,
                    str(severity)
                )

                d["severity"] = normalize_severity(
                    normalized
                )

        # ---------------------------------------------------------
        # HTTP information
        # ---------------------------------------------------------

        if isinstance(x.get("http"), dict):

            http = x["http"]

            http_fields = [
                "hostname",
                "url",
                "http_method",
                "protocol",
                "status",
                "length",
                "user_agent",
                "http_user_agent"
            ]

            for field in http_fields:

                if field in http:

                    d["fields"][
                        f"http_{field}"
                    ] = http[field]

            # Suricata may use hostname inside HTTP
            if http.get("hostname") and not d.get("hostname"):
                d["hostname"] = http["hostname"]

        # ---------------------------------------------------------
        # DNS information
        # ---------------------------------------------------------

        if isinstance(x.get("dns"), dict):

            dns = x["dns"]

            for field in [
                "type",
                "rrname",
                "rrtype",
                "rcode",
                "ttl",
                "version"
            ]:

                if field in dns:

                    d["fields"][
                        f"dns_{field}"
                    ] = dns[field]

        # ---------------------------------------------------------
        # TLS information
        # ---------------------------------------------------------

        if isinstance(x.get("tls"), dict):

            tls = x["tls"]

            for field in [
                "subject",
                "issuer",
                "version",
                "sni",
                "ja3",
                "ja3s"
            ]:

                if field in tls:

                    d["fields"][
                        f"tls_{field}"
                    ] = tls[field]

        # ---------------------------------------------------------
        # SSH information
        # ---------------------------------------------------------

        if isinstance(x.get("ssh"), dict):

            ssh = x["ssh"]

            for field, value in ssh.items():

                d["fields"][
                    f"ssh_{field}"
                ] = value

        # ---------------------------------------------------------
        # File information
        # ---------------------------------------------------------

        if isinstance(x.get("fileinfo"), dict):

            fileinfo = x["fileinfo"]

            for field, value in fileinfo.items():

                d["fields"][
                    f"file_{field}"
                ] = value

        # ---------------------------------------------------------
        # Hostname
        # ---------------------------------------------------------

        if x.get("hostname"):

            d["hostname"] = x["hostname"]

        # ---------------------------------------------------------
        # Username
        # ---------------------------------------------------------

        if x.get("username"):

            d["username"] = x["username"]

        # ---------------------------------------------------------
        # Preserve remaining EVE fields
        # ---------------------------------------------------------

        handled = {
            "timestamp",
            "event_type",
            "src_ip",
            "src_port",
            "dest_ip",
            "dest_port",
            "proto",
            "app_proto",
            "alert",
            "flow_id",
            "community_id",
            "packet",
            "pkts_toserver",
            "pkts_toclient",
            "bytes_toserver",
            "bytes_toclient",
            "http",
            "dns",
            "tls",
            "ssh",
            "fileinfo",
            "hostname",
            "username"
        }

        for key, value in x.items():

            if key not in handled:

                if key not in d["fields"]:

                    d["fields"][key] = value

        return d
