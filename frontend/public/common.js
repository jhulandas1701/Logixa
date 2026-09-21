// Shared across index.html (ingestion) and dashboard.html (dashboard).
// Kept dependency-free and tiny since there's no build step to bundle it.
window.LogixaCommon = (() => {
  const CFG = window.LOGIXA_CONFIG;

  function escapeHtml(str) {
    return String(str).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    }[c]));
  }

  function formatBytes(n) {
    if (n < 1024) return n + " B";
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
    return (n / (1024 * 1024)).toFixed(1) + " MB";
  }

  async function checkHealth(id, url) {
    const dot = document.getElementById(`dot-${id}`);
    if (!dot) return;
    try {
      const res = await fetch(url, { cache: "no-store" });
      dot.classList.toggle("up", res.ok);
      dot.classList.toggle("down", !res.ok);
    } catch (e) {
      dot.classList.remove("up");
      dot.classList.add("down");
    }
  }

  function pollHealth() {
    checkHealth("go", `${CFG.GO_BASE}/health`);
    checkHealth("pipeline", `${CFG.PIPELINE_BASE}/health`);
    // checkHealth("minio", CFG.MINIO_HEALTH);
  }

  function startHealthPolling() {
    pollHealth();
    setInterval(pollHealth, 5000);
  }

  // Highlight whichever nav link matches the current page.
  function markActiveNav() {
    const here = location.pathname.split("/").pop() || "index.html";
    document.querySelectorAll(".topnav-link").forEach(a => {
      const target = a.getAttribute("href").split("/").pop();
      a.classList.toggle("active", target === here);
    });
  }

  return { escapeHtml, formatBytes, startHealthPolling, markActiveNav };
})();

window.LogixaCommon.markActiveNav();
window.LogixaCommon.startHealthPolling();
