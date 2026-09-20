# Logixa frontend

A static, dependency-free ingestion console (plain HTML/CSS/JS, served by
nginx) for the Logixa MVP. No `npm install` or build step — nginx just
serves the files in `public/`.

## What it does

- Drag-and-drop or browse to queue log files, then upload them as one
  multipart batch to the Go ingestor (`POST /api/v1/ingest/files`).
- Polls the Python pipeline's job endpoint per ingestion until every file
  is `completed` or `failed`, streaming rows into a live event table.
- Fetches the full normalized event for each completed job and shows it
  as pretty-printed JSON when you click a row.
- Shows global stats (`/api/v1/stats`) and discovered source profiles
  (`/api/v1/profiles`), so the GXFW unknown-source discovery flow is
  visible as it happens.
- Three status dots in the header ping `go-ingestor`, `python-pipeline`,
  and MinIO's `/minio/health/live` every 5s.

## How it talks to the backends

The browser never calls `go-ingestor:8080` or `python-pipeline:8000`
directly — nginx reverse-proxies same-origin paths to them (see
`nginx.conf`):

| Frontend calls        | Proxied to                          |
|------------------------|--------------------------------------|
| `/go/*`                | `http://go-ingestor:8080/*`          |
| `/pipeline/*`          | `http://python-pipeline:8000/*`      |
| `/minio-health`        | `http://minio:9000/minio/health/live`|

This avoids CORS entirely and means no backend code changes were needed.
It only works when the frontend container is on the same Docker network
as the other services (docker-compose gives you this by default).

## Local dev without Docker

You can point a plain static server at `public/` and it will still load,
but the `/go/`, `/pipeline/`, and `/minio-health` calls will 404 unless
something is proxying them — so for real use, run it via
`docker compose up --build` from the project root.
