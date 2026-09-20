(() => {
  "use strict";

  const CFG = window.LOGIXA_CONFIG;
  const { escapeHtml } = window.LogixaCommon;
  const $ = (sel) => document.querySelector(sel);

  const sourceBarList = $("#sourceBarList");
  const modeSegDeterministic = $("#modeSegDeterministic");
  const modeSegAdaptive = $("#modeSegAdaptive");
  const modeCountDeterministic = $("#modeCountDeterministic");
  const modeCountAdaptive = $("#modeCountAdaptive");
  const confSegHigh = $("#confSegHigh");
  const confSegMedium = $("#confSegMedium");
  const confSegLow = $("#confSegLow");
  const confCountHigh = $("#confCountHigh");
  const confCountMedium = $("#confCountMedium");
  const confCountLow = $("#confCountLow");
  const efficiencyValue = $("#efficiencyValue");
  const efficiencyFill = $("#efficiencyFill");
  const efficiencyCaption = $("#efficiencyCaption");
  const leaderboard = $("#leaderboard");

  // Stable color per source name, cycling through the palette so the same
  // source always gets the same color across refreshes.
  const SOURCE_PALETTE = ["#3FCFB4", "#8C7CF0", "#F2A93C", "#E8674F", "#4C8DF0", "#C25FD6"];
  function colorForSource(name) {
    let hash = 0;
    for (let i = 0; i < name.length; i++) hash = (hash * 31 + name.charCodeAt(i)) >>> 0;
    return SOURCE_PALETTE[hash % SOURCE_PALETTE.length];
  }

  function setStat(id, value) {
    const el = document.getElementById(id);
    if (!el) return;
    if (Number(el.textContent) !== value) {
      el.textContent = value;
      el.classList.add("pulse");
      setTimeout(() => el.classList.remove("pulse"), 400);
    }
  }

  async function refreshStats() {
    try {
      const res = await fetch(`${CFG.PIPELINE_BASE}/api/v1/stats`, { cache: "no-store" });
      if (!res.ok) return;
      const s = await res.json();
      setStat("stat-received", s.received_jobs ?? 0);
      setStat("stat-completed", s.completed_jobs ?? 0);
      setStat("stat-known", s.known_events ?? 0);
      setStat("stat-unknown", s.unknown_discovered ?? 0);
      setStat("stat-reuse", s.profile_reuses ?? 0);
      setStat("stat-failed", s.failed_jobs ?? 0);
      setStat("stat-raw", s.raw_preserved ?? 0);
      setStat("stat-queue", s.queue_depth ?? 0);
      renderSourceBars(s.by_source || {});
      renderModeSplit(s.by_mode || {});
      renderConfidenceBands(s.confidence_bands || {});
      renderEfficiency(s.unknown_discovered ?? 0, s.profile_reuses ?? 0);
    } catch (e) { /* pipeline unreachable; health dot already reflects this */ }
  }

  function renderSourceBars(bySource) {
    const entries = Object.entries(bySource).sort((a, b) => b[1] - a[1]);
    if (!entries.length) {
      sourceBarList.innerHTML = `<p class="empty-state">No events processed yet.</p>`;
      return;
    }
    const max = entries[0][1] || 1;
    sourceBarList.innerHTML = entries.map(([name, count]) => `
      <div class="bar-row">
        <div class="bar-row-top">
          <span class="bar-label">${escapeHtml(name)}</span>
          <span class="bar-count">${count}</span>
        </div>
        <div class="bar-track">
          <div class="bar-fill" style="width:${Math.round((count / max) * 100)}%; background:${colorForSource(name)}"></div>
        </div>
      </div>
    `).join("");
  }

  function renderModeSplit(byMode) {
    const det = byMode.deterministic || 0;
    const adaptive = byMode.ai_assisted_discovery || 0;
    const total = det + adaptive;
    modeSegDeterministic.style.width = total ? `${(det / total) * 100}%` : "0%";
    modeSegAdaptive.style.width = total ? `${(adaptive / total) * 100}%` : "0%";
    modeCountDeterministic.textContent = det;
    modeCountAdaptive.textContent = adaptive;
  }

  function renderConfidenceBands(bands) {
    const high = bands.high || 0;
    const medium = bands.medium || 0;
    const low = bands.low || 0;
    const total = high + medium + low;
    confSegHigh.style.width = total ? `${(high / total) * 100}%` : "0%";
    confSegMedium.style.width = total ? `${(medium / total) * 100}%` : "0%";
    confSegLow.style.width = total ? `${(low / total) * 100}%` : "0%";
    confCountHigh.textContent = high;
    confCountMedium.textContent = medium;
    confCountLow.textContent = low;
  }

  function renderEfficiency(discovered, reused) {
    const total = discovered + reused;
    const rate = total ? Math.round((reused / total) * 100) : 0;
    efficiencyValue.textContent = `${rate}%`;
    efficiencyFill.style.width = `${rate}%`;
    if (!total) {
      efficiencyCaption.textContent = "No unknown-format events processed yet.";
    } else {
      efficiencyCaption.textContent =
        `${reused} of ${total} adaptive events reused a previously learned profile ` +
        `(${discovered} were genuinely new shapes).`;
    }
  }

  async function refreshProfiles() {
    try {
      const res = await fetch(`${CFG.PIPELINE_BASE}/api/v1/profiles`, { cache: "no-store" });
      if (!res.ok) return;
      const data = await res.json();
      renderLeaderboard(data.profiles || []);
    } catch (e) { /* ignore */ }
  }

  function renderLeaderboard(profiles) {
    if (!profiles.length) {
      leaderboard.innerHTML = `<p class="empty-state">No profiles learned yet.</p>`;
      return;
    }
    const ranked = profiles.slice().sort((a, b) => (b.reuse_count || 0) - (a.reuse_count || 0));
    const maxReuse = Math.max(1, ranked[0].reuse_count || 0);
    leaderboard.innerHTML = ranked.map((p, i) => `
      <div class="leaderboard-row">
        <span class="leaderboard-rank">#${i + 1}</span>
        <div class="leaderboard-main">
          <div class="leaderboard-top">
            <span class="leaderboard-id" title="${escapeHtml(p.profile_id)}">${escapeHtml(p.profile_id)}</span>
            <span class="leaderboard-source">${escapeHtml(p.source_type)}</span>
          </div>
          <div class="bar-track">
            <div class="bar-fill" style="width:${Math.round(((p.reuse_count || 0) / maxReuse) * 100)}%; background:var(--amber)"></div>
          </div>
        </div>
        <span class="leaderboard-reuse">${p.reuse_count || 0}× reused</span>
        <span class="leaderboard-conf">conf ${(p.confidence * 100).toFixed(0)}%</span>
      </div>
    `).join("");
  }

  // ---------------------------------------------------------------
  // Boot
  // ---------------------------------------------------------------

  refreshStats();
  refreshProfiles();
  setInterval(refreshStats, CFG.STATS_INTERVAL_MS);
  setInterval(refreshProfiles, CFG.STATS_INTERVAL_MS * 2);
})();
