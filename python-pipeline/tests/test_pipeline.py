"""Regression tests for the Logixa detection + parsing pipeline.

Every case here corresponds to a bug that was actually shipped at some
point, or to a behaviour the demo depends on. Run under pytest:

    cd python-pipeline && python -m pytest tests -q

or standalone with no dependencies at all:

    cd python-pipeline && python tests/test_pipeline.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Point profile/raw storage at a scratch dir before importing anything that
# creates directories at import time.
_TMP = tempfile.mkdtemp(prefix="logixa-tests-")
os.environ.setdefault("PROFILES_DIR", os.path.join(_TMP, "profiles"))
os.environ.setdefault("RAW_STORE_DIR", os.path.join(_TMP, "raw"))
os.environ.setdefault("PIPELINE_DATA_DIR", _TMP)

from app.core.utils import kv_pairs                          # noqa: E402
from app.detection.fingerprint import fingerprint            # noqa: E402
from app.detection.format_detector import FormatDetector     # noqa: E402
from app.detection.source_detector import SourceDetector     # noqa: E402
from app.parsers.registry import PARSERS                     # noqa: E402

_sd = SourceDetector()


# ============================================================
# Source detection
# ============================================================

def test_real_web_access_logs_detected():
    apache = ('192.168.1.20 - - [09/Sep/2026:10:22:31 +0530] '
              '"GET /index.html HTTP/1.1" 200 1234 "https://example.com" "Apache/2.4"')
    nginx = ('10.0.0.5 - - [09/Sep/2026:10:22:31 +0000] '
             '"POST /api/login HTTP/1.1" 401 512 "-" "nginx/1.24"')
    assert _sd.detect(apache).source_type == "apache"
    assert _sd.detect(nginx).source_type == "nginx"


def test_bare_keyword_does_not_beat_structural_match():
    """REGRESSION: a sudo command that merely *mentions* a web server was
    classified as that web server, because an unqualified keyword hit
    (0.45) outscored linux_auth's real structural evidence."""
    for cmd in ("restart nginx", "restart apache2", "restart httpd"):
        raw = (f'Sep  9 10:23:00 web01 sudo: deploy : TTY=pts/0 ; '
               f'PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/systemctl {cmd}')
        assert _sd.detect(raw).source_type == "linux_auth", cmd


def test_overlapping_keywords_not_double_counted():
    """REGRESSION: APACHE_KEYWORDS contains both 'apache' and 'apache2',
    so one mention of 'apache2' matched twice and reached 0.90 unaided —
    enough to outrank a genuine sshd authentication failure."""
    raw = ('Sep  9 10:24:00 web01 sshd[1234]: Failed password for apache2 '
           'from 203.0.113.9 port 51322 ssh2')
    result = _sd.detect(raw)
    assert result.source_type == "linux_auth"
    assert result.scores.get("apache", 0) < 0.5


def test_vendor_appliances_detected():
    cases = {
        '%ASA-6-302013: Built outbound TCP connection 123 for '
        'outside:203.0.113.5/443 to inside:10.0.0.12/51500': "cisco_asa",

        'date=2026-09-08 time=10:22:31 devname="FGT1" devid="FG100E" '
        'type="traffic" subtype="forward" srcip=10.1.1.5 dstip=8.8.8.8 '
        'srcport=51000 dstport=53 proto=17 action=accept': "fortigate",

        'CEF:0|CheckPoint|NGFW|3.2|100|Connection blocked|8|'
        'src=10.0.0.5 dst=192.168.1.20 spt=51422 dpt=443 act=deny': "security_device",
    }
    for raw, want in cases.items():
        assert _sd.detect(raw).source_type == want, raw[:40]


# ============================================================
# Format detection
# ============================================================

def test_format_detection():
    cases = {
        '{"event_type":"alert","src_ip":"10.1.1.5"}': "json",
        'Sep  9 10:22:31 web01 sshd[1234]: Failed password': "syslog_rfc3164",
        'GXFW|20260904|203455|EDGE-07|SRC=172.16.4.21': "pipe_delimited",
    }
    for raw, want in cases.items():
        assert FormatDetector.detect(raw).format.value == want, raw[:40]


# ============================================================
# Key/value extraction
# ============================================================

def test_kv_pairs_stops_at_pipe_delimiter():
    """REGRESSION: the unquoted-value character class didn't exclude '|',
    so the first key swallowed the whole rest of a pipe-delimited line and
    only one field was ever extracted."""
    raw = ('GXFW|20260904|203455|EDGE-07|IN=eth0|OUT=wan0|SRC=172.16.4.21|'
           'DST=45.33.21.9|SP=49220|DP=443|P=TCP|DEC=PASS|RSN=POL-17')
    kv = kv_pairs(raw)
    assert kv["SRC"] == "172.16.4.21"
    assert kv["DST"] == "45.33.21.9"
    assert kv["DEC"] == "PASS"
    assert len(kv) >= 9


# ============================================================
# Parsers
# ============================================================

def test_sudo_fields_extracted():
    """REGRESSION: sudo detection checked the message body *after* the
    syslog header was stripped, but 'sudo' only appears in the header's
    process tag — so sudo lines parsed to almost nothing."""
    raw = ('Sep  9 10:23:00 web01 sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; '
           'USER=root ; COMMAND=/usr/bin/systemctl restart nginx')
    d = PARSERS["linux_auth"].parse(raw)
    assert d["username"] == "deploy"
    assert "systemctl restart nginx" in str(d["fields"].get("command", ""))


def test_ssh_auth_events():
    failed = PARSERS["linux_auth"].parse(
        'Sep  9 10:22:31 web01 sshd[1234]: Failed password for invalid user '
        'admin from 203.0.113.9 port 51322 ssh2')
    assert failed["outcome"] == "failure"
    assert failed["username"] == "admin"
    assert failed["src_ip"] == "203.0.113.9"

    ok = PARSERS["linux_auth"].parse(
        'Sep  9 10:22:35 web01 sshd[1234]: Accepted publickey for deploy '
        'from 10.0.0.7 port 51400 ssh2')
    assert ok["outcome"] == "success"
    assert ok["username"] == "deploy"


def test_pam_session_lines_parsed():
    """REGRESSION: the PAM session regex anchored on `\\w+:` immediately
    before 'session', but real lines read 'pam_unix(sudo:session): session
    opened ...' — the text before the colon ends in ')', so nothing
    matched and these lines parsed to no fields at all."""
    d = PARSERS["linux_auth"].parse(
        'Sep  9 10:25:00 web01 sudo: pam_unix(sudo:session): '
        'session opened for user root by deploy(uid=1000)')
    assert d["username"] == "root"
    assert d["action"] == "session_opened"
    assert d["fields"]["initiated_by"] == "deploy"

    closed = PARSERS["linux_auth"].parse(
        'Sep  9 10:27:00 web01 sshd[77]: pam_unix(sshd:session): '
        'session closed for user admin')
    assert closed["username"] == "admin"
    assert closed["action"] == "session_closed"


def test_common_log_format_without_referer_or_agent():
    """Common Log Format omits referer/user-agent; those groups are
    optional and must not break the match."""
    d = PARSERS["apache"].parse(
        '192.168.1.20 - admin [28/Aug/2026:20:10:20 +0530] '
        '"GET /index.html HTTP/1.1" 200 5234')
    assert d["src_ip"] == "192.168.1.20"
    assert d["username"] == "admin"
    assert d["fields"]["http_status"] == 200


def test_every_registered_parser_handles_its_own_source():
    """Whatever the detector routes to a parser, that parser must not
    raise and must return the source_type it was routed for."""
    samples = {
        "apache": '192.168.1.20 - - [09/Sep/2026:10:22:31 +0530] "GET / HTTP/1.1" 200 12 "-" "Apache/2.4"',
        "nginx": '10.0.0.5 - - [09/Sep/2026:10:22:31 +0000] "GET / HTTP/1.1" 200 12 "-" "nginx/1.24"',
        "linux_auth": 'Sep  9 10:22:31 web01 sshd[1234]: Failed password for admin from 203.0.113.9 port 51322 ssh2',
        "cisco_asa": '%ASA-6-302013: Built outbound TCP connection 123 for outside:203.0.113.5/443 to inside:10.0.0.12/51500',
        "security_device": 'CEF:0|CheckPoint|NGFW|3.2|100|Blocked|8|src=10.0.0.5 dst=192.168.1.20',
    }
    for source, raw in samples.items():
        d = PARSERS[source].parse(raw)
        assert d["source_type"] == source
        assert d.get("message")


# ============================================================
# Adaptive discovery
# ============================================================

def test_unknown_format_learns_then_reuses_profile():
    """The GXFW demo: first sighting learns a profile, later sightings of
    the same shape (different values) reuse it rather than relearning."""
    from app.intelligence.profile_store import learn_profile, match_profile
    from app.intelligence.unknown import analyze_unknown

    first = ('GXFW|20260904|203455|EDGE-07|IN=eth0|OUT=wan0|SRC=172.16.4.21|'
             'DST=45.33.21.9|SP=49220|DP=443|P=TCP|DEC=PASS|RSN=POL-17')
    second = ('GXFW|20260905|101010|EDGE-09|IN=eth1|OUT=wan1|SRC=10.0.0.5|'
              'DST=93.184.216.34|SP=51000|DP=80|P=TCP|DEC=DROP|RSN=POL-03')

    fp = fingerprint(first)
    _, _, conf, _ = analyze_unknown(first, fp=fp)
    learned = learn_profile(first, conf, "unknown_source")

    # Terse abbreviated keys (SRC/DST/SP/DP) must map to canonical names.
    assert learned["field_mapping"]["SRC"] == "src_ip"
    assert learned["field_mapping"]["DP"] == "dst_port"

    reused = match_profile(second)
    assert reused is not None
    assert reused["profile_id"] == learned["profile_id"]


def test_unknown_format_not_routed_to_a_parser():
    raw = ('GXFW|20260904|203455|EDGE-07|IN=eth0|OUT=wan0|SRC=172.16.4.21|'
           'DST=45.33.21.9|SP=49220|DP=443|P=TCP|DEC=PASS|RSN=POL-17')
    fp = fingerprint(raw)
    assert not (fp.source_type in PARSERS and fp.score >= 0.50)


# ============================================================
# Standalone runner (no pytest required)
# ============================================================

if __name__ == "__main__":
    tests = [(n, o) for n, o in sorted(globals().items())
             if n.startswith("test_") and callable(o)]
    failures = []
    for name, fn in tests:
        try:
            fn()
            print(f"PASS  {name}")
        except Exception as exc:
            failures.append((name, exc))
            print(f"FAIL  {name}: {type(exc).__name__}: {exc}")
    print(f"\n{len(tests) - len(failures)}/{len(tests)} passed")
    sys.exit(1 if failures else 0)
