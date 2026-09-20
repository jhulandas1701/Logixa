// Runtime configuration. These are same-origin paths that nginx (see
// nginx.conf) reverse-proxies to the go-ingestor and python-pipeline
// containers, so the browser never needs to know their internal ports
// or deal with CORS. Change these only if you rename the proxy locations.
window.LOGIXA_CONFIG = {
  GO_BASE: "/go",
  PIPELINE_BASE: "/pipeline",
  MINIO_HEALTH: "/minio-health",
  POLL_INTERVAL_MS: 1500,
  STATS_INTERVAL_MS: 4000,
};
