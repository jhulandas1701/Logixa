import re

from .base import Parser
from app.core.utils import normalize_severity, parse_timestamp

# Aug 28 20:10:20 server sshd[1234]: Failed password for admin from 10.0.0.5 port 51422 ssh2
RFC3164_HEADER_RE = re.compile(
    r"^(?:<\d{1,3}>)?"
    r"(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[\w.-]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<msg>.*)$"
)

_MONTHS = {
    m: i for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
        start=1,
    )
}

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PORT_RE = re.compile(r"\bport\s+(\d{1,5})\b", re.IGNORECASE)

SSH_RESULT_RE = re.compile(
    r"\b(?P<result>Accepted|Failed)\s+(?P<method>password|publickey|keyboard-interactive)"
    r"\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
    re.IGNORECASE,
)

INVALID_USER_RE = re.compile(
    r"\binvalid user\s+(?P<user>\S+)\s+from\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
    re.IGNORECASE,
)

SUDO_RE = re.compile(
    r"session\s+(?P<action>opened|closed)\s+for\s+user\s+(?P<user>[\w.\-$]+)"
    r"(?:\s+by\s+(?P<by_user>[\w.\-$]*)\s*\(uid=(?P<by_uid>\d+)\))?",
    re.IGNORECASE,
)

SUDO_COMMAND_RE = re.compile(
    r"\bUSER=(?P<runas>\S+)\s*;\s*COMMAND=(?P<command>.*)$",
    re.IGNORECASE,
)

# The account that *invoked* sudo, which precedes the TTY/PWD/USER block:
#   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/id
# SUDO_COMMAND_RE above starts matching at USER=, so without this the
# invoking user — the whole point of attribution on a privilege-escalation
# event — was never recorded.
SUDO_INVOKER_RE = re.compile(r"^\s*(?P<invoker>[\w.\-$]+)\s*:\s*(?=.*\bTTY=|.*\bCOMMAND=)")


class LinuxAuthParser(Parser):

    name = "linux_auth"
    version = "1.0"

    def parse(self, raw: str):

        d = {
            "source_type": "linux_auth",
            "source_vendor": "Linux (PAM/sshd/sudo)",
            "message": raw,
            "parser_name": self.name,
            "parser_version": self.version,
            "fields": {},
        }

        header = RFC3164_HEADER_RE.match(raw.strip())
        body = raw

        if header:

            month = _MONTHS.get(header.group("mon"))
            if month:
                # RFC3164 has no year — assume current year at parse time
                # is out of scope for a deterministic parser, so we surface
                # the components and let downstream enrichment fill in the
                # year from ingestion context if it needs to.
                d["fields"]["log_month"] = header.group("mon")
                d["fields"]["log_day"] = int(header.group("day"))
                d["fields"]["log_time"] = header.group("time")

            d["hostname"] = header.group("host")
            d["fields"]["process"] = header.group("proc")

            if header.group("pid"):
                d["fields"]["pid"] = int(header.group("pid"))

            body = header.group("msg")

        # ---------------------------------------------------------
        # SSH authentication result
        # ---------------------------------------------------------

        ssh_match = SSH_RESULT_RE.search(body)

        if ssh_match:

            d["event_type"] = "authentication"
            d["username"] = ssh_match.group("user")
            d["src_ip"] = ssh_match.group("ip")
            d["fields"]["auth_method"] = ssh_match.group("method").lower()

            result = ssh_match.group("result").lower()
            d["action"] = "login"
            d["outcome"] = "success" if result == "accepted" else "failure"
            d["severity"] = normalize_severity("info" if result == "accepted" else "warning")

            port_match = PORT_RE.search(body)
            if port_match:
                d["src_port"] = int(port_match.group(1))

        # ---------------------------------------------------------
        # Invalid user
        # ---------------------------------------------------------

        elif INVALID_USER_RE.search(body):

            invalid_match = INVALID_USER_RE.search(body)
            d["event_type"] = "authentication"
            d["username"] = invalid_match.group("user")
            d["src_ip"] = invalid_match.group("ip")
            d["action"] = "login"
            d["outcome"] = "failure"
            d["severity"] = normalize_severity("warning")
            d["fields"]["reason"] = "invalid_user"

        # ---------------------------------------------------------
        # sudo / PAM session open/close
        # ---------------------------------------------------------

        elif SUDO_RE.search(body):

            sudo_match = SUDO_RE.search(body)
            d["event_type"] = "session"
            d["username"] = sudo_match.group("user")
            d["action"] = f'session_{sudo_match.group("action").lower()}'
            d["outcome"] = "success"
            d["severity"] = normalize_severity("info")
            if sudo_match.group("by_user"):
                d["fields"]["initiated_by"] = sudo_match.group("by_user")
            if sudo_match.group("by_uid"):
                d["fields"]["initiated_by_uid"] = sudo_match.group("by_uid")

        # ---------------------------------------------------------
        # sudo command execution
        # ---------------------------------------------------------

        elif SUDO_COMMAND_RE.search(body):

            cmd_match = SUDO_COMMAND_RE.search(body)
            d["event_type"] = "privilege_escalation"
            d["fields"]["run_as_user"] = cmd_match.group("runas")
            d["fields"]["command"] = cmd_match.group("command").strip()
            invoker = SUDO_INVOKER_RE.match(body)
            if invoker:
                d["username"] = invoker.group("invoker")
            d["action"] = "sudo_exec"
            d["outcome"] = "success"
            d["severity"] = normalize_severity("info")

        # ---------------------------------------------------------
        # Generic authentication failure phrasing fallback
        # ---------------------------------------------------------

        elif re.search(r"\bauthentication failure\b", body, re.IGNORECASE):

            d["event_type"] = "authentication"
            d["action"] = "login"
            d["outcome"] = "failure"
            d["severity"] = normalize_severity("warning")

            ip_matches = IP_RE.findall(body)
            if ip_matches:
                d["src_ip"] = ip_matches[0]

        else:
            # Unrecognized auth-log body — still preserve any IP found so
            # downstream analytics aren't left empty-handed.
            ip_matches = IP_RE.findall(body)
            if ip_matches:
                d["src_ip"] = ip_matches[0]

        return d
