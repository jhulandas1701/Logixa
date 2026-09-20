(() => {
  "use strict";

  const CFG = window.LOGIXA_CONFIG;
  const { escapeHtml, formatBytes } = window.LogixaCommon;
  const $ = (sel) => document.querySelector(sel);

  const dropzone = $("#dropzone");
  const fileInput = $("#fileInput");
  const queueList = $("#queueList");
  const sendBtn = $("#sendBtn");
  const uploadProgress = $("#uploadProgress");
  const progressFill = $("#progressFill");
  const progressLabel = $("#progressLabel");
  const streamTable = $("#streamTable");
  const streamEmpty = $("#streamEmpty");
  const streamCount = $("#streamCount");
  const profileList = $("#profileList");
  const schemaGrid = $("#schemaGrid");
  const schemaSourceNote = $("#schemaSourceNote");
  const schemaLiveBadge = $("#schemaLiveBadge");

  let queuedFiles = [];
  let knownEventIds = new Set();
  let activePolls = new Set();

  // ---------------------------------------------------------------
  // Profiles
  // ---------------------------------------------------------------

  async function refreshProfiles() {
    try {
      const res = await fetch(`${CFG.PIPELINE_BASE}/api/v1/profiles`, { cache: "no-store" });
      if (!res.ok) return;
      const data = await res.json();
      renderProfiles(data.profiles || []);
    } catch (e) { /* ignore */ }
  }

  function renderProfiles(profiles) {
    if (!profiles.length) {
      profileList.innerHTML = `<li class="empty-state">No profiles learned yet.</li>`;
      return;
    }
    const sorted = profiles.slice().sort((a, b) => (b.reuse_count || 0) - (a.reuse_count || 0));
    profileList.innerHTML = sorted.map(p => `
      <li class="profile-card">
        <div class="profile-id" title="${escapeHtml(p.profile_id)}">${escapeHtml(p.profile_id)}</div>
        <div class="profile-meta">
          <span><b>${escapeHtml(p.source_type)}</b></span>
          <span>${escapeHtml(p.format)}</span>
          <span>conf ${(p.confidence * 100).toFixed(0)}%</span>
          <span>${Object.keys(p.field_mapping || {}).length} fields mapped</span>
          <span>reused ${p.reuse_count || 0}×</span>
        </div>
      </li>
    `).join("");
  }

  // ---------------------------------------------------------------
  // File queue UI
  // ---------------------------------------------------------------

  function addFiles(fileListLike) {
    for (const f of fileListLike) queuedFiles.push(f);
    renderQueue();
  }

  function renderQueue() {
    queueList.innerHTML = queuedFiles.map((f, i) => `
      <li class="queue-item">
        <span class="qi-name" title="${escapeHtml(f.name)}">${escapeHtml(f.name)}</span>
        <span class="qi-size">${formatBytes(f.size)}</span>
        <button class="qi-remove" data-idx="${i}" aria-label="Remove ${escapeHtml(f.name)}">&times;</button>
      </li>
    `).join("");
    sendBtn.disabled = queuedFiles.length === 0;
    queueList.querySelectorAll(".qi-remove").forEach(btn => {
      btn.addEventListener("click", () => {
        queuedFiles.splice(Number(btn.dataset.idx), 1);
        renderQueue();
      });
    });
  }

  dropzone.addEventListener("click", () => fileInput.click());
  dropzone.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fileInput.click(); }
  });
  fileInput.addEventListener("change", () => { addFiles(fileInput.files); fileInput.value = ""; });

  ["dragenter", "dragover"].forEach(evt =>
    dropzone.addEventListener(evt, (e) => { e.preventDefault(); dropzone.classList.add("drag-over"); })
  );
  ["dragleave", "drop"].forEach(evt =>
    dropzone.addEventListener(evt, (e) => { e.preventDefault(); dropzone.classList.remove("drag-over"); })
  );
  dropzone.addEventListener("drop", (e) => {
    if (e.dataTransfer?.files?.length) addFiles(e.dataTransfer.files);
  });

  // ---------------------------------------------------------------
  // Upload
  // ---------------------------------------------------------------

  sendBtn.addEventListener("click", () => {
    if (!queuedFiles.length) return;
    uploadBatch(queuedFiles.slice());
    queuedFiles = [];
    renderQueue();
  });

  function uploadBatch(files) {
    const form = new FormData();
    files.forEach(f => form.append("files", f, f.name));

    uploadProgress.hidden = false;
    progressFill.style.width = "0%";
    progressLabel.textContent = `Uploading ${files.length} file${files.length > 1 ? "s" : ""}…`;
    sendBtn.disabled = true;

    const xhr = new XMLHttpRequest();
    xhr.open("POST", `${CFG.GO_BASE}/api/v1/ingest/files`);
    xhr.upload.addEventListener("progress", (e) => {
      if (e.lengthComputable) {
        const pct = Math.round((e.loaded / e.total) * 100);
        progressFill.style.width = pct + "%";
        progressLabel.textContent = `Uploading… ${pct}%`;
      }
    });
    xhr.onload = () => {
      uploadProgress.hidden = true;
      sendBtn.disabled = queuedFiles.length === 0;
      if (xhr.status === 202 || xhr.status === 200) {
        try {
          const data = JSON.parse(xhr.responseText);
          onUploadAccepted(data);
        } catch (e) {
          progressLabel.textContent = "Upload accepted but response could not be parsed.";
        }
      } else {
        progressLabel.textContent = `Upload failed (HTTP ${xhr.status}).`;
        uploadProgress.hidden = false;
        setTimeout(() => { uploadProgress.hidden = true; }, 4000);
      }
    };
    xhr.onerror = () => {
      uploadProgress.hidden = false;
      progressLabel.textContent = "Upload failed — is go-ingestor reachable?";
      sendBtn.disabled = queuedFiles.length === 0;
      setTimeout(() => { uploadProgress.hidden = true; }, 4000);
    };
    xhr.send(form);
  }

  function onUploadAccepted(data) {
    const id = data.ingestion_id;
    if (!id) return;
    // Seed rows immediately in a "queued" state so the stream feels live,
    // then let job polling upgrade each row as the pipeline processes it.
    (data.uploaded_files || []).forEach(f => upsertRow(f.object_name, { filename: f.filename, status: "queued" }));
    (data.failed_files || []).forEach(f => upsertRow(`failed:${f.filename}`, { filename: f.filename, status: "failed", source_type: "upload rejected" }));
    pollJobs(id);
  }

  // ---------------------------------------------------------------
  // Job polling
  // ---------------------------------------------------------------

  function pollJobs(ingestionId) {
    if (activePolls.has(ingestionId)) return;
    activePolls.add(ingestionId);
    let attempts = 0;
    const maxAttempts = 60; // ~90s at 1.5s interval

    const tick = async () => {
      attempts++;
      try {
        const res = await fetch(`${CFG.PIPELINE_BASE}/api/v1/jobs/${encodeURIComponent(ingestionId)}`, { cache: "no-store" });
        if (res.ok) {
          const data = await res.json();
          const jobs = data.jobs || [];
          let allDone = jobs.length > 0;
          for (const j of jobs) {
            upsertRow(j.object_name, j);
            if (j.status !== "completed" && j.status !== "failed") allDone = false;
            if (j.status === "completed" && j.event_id && !knownEventIds.has(j.event_id)) {
              knownEventIds.add(j.event_id);
              fetchEventDetail(j.object_name, j.event_id);
            }
          }
          if (allDone || attempts >= maxAttempts) {
            activePolls.delete(ingestionId);
            refreshProfiles();
            return;
          }
        }
      } catch (e) { /* ignore transient errors, keep polling */ }
      setTimeout(tick, CFG.POLL_INTERVAL_MS);
    };
    tick();
  }

  async function fetchEventDetail(objectName, eventId) {
    try {
      const res = await fetch(`${CFG.PIPELINE_BASE}/api/v1/events/${encodeURIComponent(eventId)}`, { cache: "no-store" });
      if (!res.ok) return;
      const event = await res.json();
      rowStore[objectName] = rowStore[objectName] || {};
      rowStore[objectName].event = event;
      renderDetailIfExpanded(objectName);
      renderSchema(event); // keep the schema showcase pinned to the latest real event
    } catch (e) { /* ignore */ }
  }

  // ---------------------------------------------------------------
  // Event stream table
  // ---------------------------------------------------------------

  const rowStore = {}; // object_name -> { filename, status, source_type, processing_mode, confidence, event, el }
  const rowOrder = [];

  function upsertRow(key, patch) {
    const isNew = !rowStore[key];
    rowStore[key] = { ...(rowStore[key] || {}), ...patch };
    if (isNew) rowOrder.unshift(key);
    renderStream();
  }

  function renderStream() {
    streamEmpty.hidden = rowOrder.length > 0;
    const totalEvents = rowOrder.reduce((sum, k) => sum + (rowStore[k].event_count || 1), 0);
    streamCount.textContent = `${rowOrder.length} file${rowOrder.length === 1 ? "" : "s"} · ${totalEvents} event${totalEvents === 1 ? "" : "s"}`;

    // Remove stale rendered rows not in current order (rare), then rebuild in order.
    const existing = streamTable.querySelectorAll(".stream-row--data, .stream-detail");
    existing.forEach(el => el.remove());

    const head = streamTable.querySelector(".stream-row--head");
    rowOrder.forEach(key => {
      const r = rowStore[key];
      const row = document.createElement("div");
      row.className = "stream-row stream-row--data" + (r._rendered ? "" : " enter");
      r._rendered = true;
      const mode = r.processing_mode || "";
      const status = r.status || "queued";
      const conf = typeof r.confidence === "number" ? (r.confidence * 100).toFixed(0) + "%" : "—";
      const sourceLabel = r.source || r.source_type || "detecting…";
      const countBadge = r.event_count > 1 ? ` <span class="cell-source-count">×${r.event_count}</span>` : "";
      row.innerHTML = `
        <span class="cell-file">${escapeHtml(r.filename || key)}</span>
        <span class="cell-source">${escapeHtml(sourceLabel)}${countBadge}</span>
        <span class="cell-mode ${mode}">${mode ? escapeHtml(mode.replace("_", " ")) : "—"}</span>
        <span class="cell-conf">${conf}</span>
        <span class="cell-status ${status}">${escapeHtml(status.replace(/_/g, " "))}</span>
        <span class="cell-chevron">▸</span>
      `;
      row.addEventListener("click", () => toggleDetail(key, row));
      head.insertAdjacentElement("afterend", row);
      if (r._expanded) {
        row.classList.add("expanded");
        const detail = buildDetailNode(r);
        row.insertAdjacentElement("afterend", detail);
      }
    });
  }

  function toggleDetail(key, rowEl) {
    const r = rowStore[key];
    r._expanded = !r._expanded;
    renderStream();
  }

  function renderDetailIfExpanded(key) {
    const r = rowStore[key];
    if (r && r._expanded) renderStream();
  }

  function buildDetailNode(r) {
    const wrap = document.createElement("div");
    wrap.className = "stream-detail";
    if (r.event) {
      let note = "";
      if (r.event_count > 1) {
        const breakdown = Object.entries(r.sources || {}).map(([s, n]) => `${escapeHtml(s)} ×${n}`).join(", ");
        note = `<p class="stream-detail-note">This file produced ${r.event_count} events (${breakdown}). Showing the first as a sample — every event is individually queryable via its own event_id.</p>`;
      }
      wrap.innerHTML = `${note}<pre>${syntaxHighlightJson(r.event)}</pre>`;
    } else if (r.status === "failed") {
      wrap.innerHTML = `<pre>${escapeHtml(r.error || "Processing failed.")}</pre>`;
    } else {
      wrap.innerHTML = `<pre>Waiting for normalized output…</pre>`;
    }
    return wrap;
  }

  function syntaxHighlightJson(obj) {
    const json = JSON.stringify(obj, null, 2);
    const escaped = escapeHtml(json);
    return escaped.replace(/"([^"]+)":/g, '<span class="detail-json-key">"$1"</span>:');
  }

  // ---------------------------------------------------------------
  // Universal schema showcase
  // ---------------------------------------------------------------

  // Grouped to match the ULPF schema (app/schemas/ulpf_event.py). Every
  // parser — deterministic or adaptive — ends up populating this same set
  // of top-level fields, whatever the source.
  const SCHEMA_GROUPS = [
    { label: "Identity", accent: "neutral", fields: [
      ["event_id", "hash of this normalized event"],
      ["raw_event_id", "hash of the original raw line"],
    ]},
    { label: "Timing", accent: "neutral", fields: [
      ["timestamp", "when the event occurred"],
      ["created_at", "when Logixa processed it"],
    ]},
    { label: "Source", accent: "teal", fields: [
      ["source_type", "what produced this log"],
      ["source_vendor", "vendor label"],
      ["parser_name", "which parser normalized it"],
      ["schema_version", "ULPF schema version"],
    ]},
    { label: "Classification", accent: "violet", fields: [
      ["event_type", "category of activity"],
      ["severity", "normalized severity"],
      ["action", "what was attempted"],
      ["outcome", "what happened"],
    ]},
    { label: "Network", accent: "amber", fields: [
      ["src_ip", "source address"],
      ["src_port", "source port"],
      ["dst_ip", "destination address"],
      ["dst_port", "destination port"],
      ["protocol", "network protocol"],
    ]},
    { label: "Actors", accent: "coral", fields: [
      ["username", "account involved"],
      ["hostname", "device/host involved"],
    ]},
    { label: "Content", accent: "neutral", fields: [
      ["message", "original raw line"],
      ["fields", "vendor-specific extension bag"],
    ]},
    { label: "Quality", accent: "neutral", fields: [
      ["confidence", "how sure the pipeline is"],
      ["processing_status", "normalized / low_confidence / failed"],
    ]},
  ];

  function formatSchemaValue(key, event) {
    if (!event) return "—";
    const v = event[key];
    if (key === "fields") {
      const n = v ? Object.keys(v).length : 0;
      return n ? `${n} extra field${n === 1 ? "" : "s"} captured` : "—";
    }
    if (key === "message") {
      if (!v) return "—";
      return v.length > 64 ? v.slice(0, 64) + "…" : v;
    }
    if (v === null || v === undefined || v === "") return "—";
    if (key === "confidence" && typeof v === "number") return `${(v * 100).toFixed(0)}%`;
    return String(v);
  }

  function renderSchema(event) {
    schemaLiveBadge.textContent = event ? "live" : "example";
    schemaLiveBadge.classList.toggle("is-live", !!event);
    if (event) {
      schemaSourceNote.textContent = `Showing a real event just normalized from a ${event.source_type || "unknown"} source.`;
    }
    schemaGrid.innerHTML = SCHEMA_GROUPS.map(group => `
      <div class="schema-group schema-group--${group.accent}">
        <div class="schema-group-label">${escapeHtml(group.label)}</div>
        ${group.fields.map(([key, desc]) => `
          <div class="schema-field">
            <div class="schema-field-top">
              <span class="schema-field-name">${escapeHtml(key)}</span>
              <span class="schema-field-value" title="${escapeHtml(formatSchemaValue(key, event))}">${escapeHtml(formatSchemaValue(key, event))}</span>
            </div>
            <div class="schema-field-desc">${escapeHtml(desc)}</div>
          </div>
        `).join("")}
      </div>
    `).join("");
  }

  // ---------------------------------------------------------------
  // Boot
  // ---------------------------------------------------------------

  renderSchema(null); // illustrative placeholder until the first real event lands
  refreshProfiles();
  setInterval(refreshProfiles, CFG.STATS_INTERVAL_MS * 2);
})();
