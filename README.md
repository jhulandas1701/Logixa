# Logixa MVP — Go + MinIO + FastAPI

Runnable local MVP for demonstrating scalable streaming ingestion and the Logixa processing lifecycle.

## Flow

Client -> Go/Gin :8080 -> MinIO -> FastAPI worker queue -> detection -> known parser OR unknown discovery -> source profile -> normalization -> lineage.

### Detection architecture

Detection (`app/detection/`) is a two-stage, fully deterministic pipeline —
no ML, no LLM calls, same input always yields the same output:

1. **`format_detector.py`** — classifies the *structural shape* of the raw
   line: JSON, XML, CEF, LEEF, Syslog RFC3164/RFC5424, Common/Combined Log
   Format, key=value, CSV/TSV/pipe/semicolon-delimited, timestamped text,
   custom multi-signal, or plaintext. This never looks at *who* produced
   the log, only *how it's shaped*.
2. **`source_detector.py`** — given that shape plus keyword, structural,
   and optional file-metadata signals (filename/path, e.g. `auth.log`,
   `/var/log/apache2/access.log`), decides *which system* produced it.
   Vendor-exact signatures (Cisco ASA's `%ASA-`, FortiGate's
   `devid="FG"`/`type="traffic"`, Suricata's EVE JSON field set) are
   checked first as a fast path; everything else goes through multi-signal
   scoring for Apache, Nginx, Linux auth, and generic CEF/LEEF security
   devices.

`fingerprint.py` is a thin orchestrator over both stages, kept as the
single entry point `app/core/processor.py` and `app/intelligence/unknown.py`
already called — so the richer detection is a drop-in upgrade, not a
breaking change.

### Known inputs (deterministic parser exists for each)
- Cisco ASA Syslog
- FortiGate key=value
- Suricata EVE JSON
- Apache access logs (Common/Combined Log Format)
- Nginx access logs (Common/Combined Log Format)
- Linux authentication logs (`auth.log`/`secure` — sshd, sudo, PAM)
- Generic CEF/LEEF security devices (any vendor Logixa doesn't have a
  dedicated parser for yet — vendor/product/severity are still extracted
  from the CEF/LEEF header itself)

### Unknown input
- GXFW fictional proprietary firewall format

The first GXFW event is discovered and creates `gxfw_v1.json`. Subsequent GXFW events match that fingerprint and are processed deterministically.

Even in the unknown/adaptive-discovery path, format detection isn't wasted:
if a log's *shape* is still recognized as, say, Combined Log Format or
CEF/LEEF but no specific vendor/keyword/metadata signal cleared the
deterministic threshold, `app/intelligence/unknown.py` reuses that shape to
extract structured fields (HTTP method/path/status, CEF src/dst/action/
severity, etc.) generically — rather than falling back to a bare
key=value/IP-regex sweep.

## Start

```bash
docker compose up --build
```

Health:

```bash
curl http://localhost:8080/health
curl http://localhost:8000/health
```

MinIO console: http://localhost:9001 (minioadmin / minioadmin)

## Generate 100 or 1000 files

```bash
python tools/generate_logs.py --count 100 --out testdata/100
python tools/benchmark_upload.py --dir testdata/100

python tools/generate_logs.py --count 1000 --out testdata/1000
python tools/benchmark_upload.py --dir testdata/1000
```

The benchmark measures your actual laptop/container performance. Do not put numbers in the SIH PPT until you have run the test.

## Inspect processing

The upload response gives an `ingestion_id`.

```bash
curl http://localhost:8080/api/v1/ingest/ING-ID
curl http://localhost:8000/api/v1/jobs/ING-ID
curl http://localhost:8000/api/v1/stats
curl http://localhost:8000/api/v1/profiles
```

## Manual unknown-source demo

Upload `samples/unknown_gxfw.log` with curl or the benchmark client. Then upload a second GXFW event. The first creates the source profile; the second should show profile reuse in `/api/v1/stats` and the job status.

## Manual known-source demo (Apache / Nginx / Linux auth / generic CEF)

```bash
curl -F "file=@samples/apache_access.log"      http://localhost:8080/api/v1/ingest/files
curl -F "file=@samples/nginx_access.log"       http://localhost:8080/api/v1/ingest/files
curl -F "file=@samples/linux_auth.log"         http://localhost:8080/api/v1/ingest/files
curl -F "file=@samples/cef_generic_device.log" http://localhost:8080/api/v1/ingest/files
```

Each should come back `processing_mode: deterministic` with `source: apache`
/ `nginx` / `linux_auth` / `security_device` respectively in
`/api/v1/jobs/ING-ID` — no discovery, no profile learned, because these are
now known, deterministically-parsed sources.

## Scale-up path

This MVP intentionally uses a direct Go -> FastAPI job notification after raw storage so it is easy to run on one laptop. For production-scale deployment, replace that notification with Kafka:

`Go -> MinIO -> Kafka -> Python workers`

The Python processing contract remains the same.
