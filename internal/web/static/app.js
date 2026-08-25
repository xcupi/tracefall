// Tracefall dashboard. Plain JS, no build step, no framework -- it only
// ever talks to the JSON API under /api/; it contains no forensic logic
// of its own (see internal/api's package doc for why that boundary
// matters).

const app = document.getElementById("app");
const connStatus = document.getElementById("conn-status");

// currentCollections holds the active case's evidence collections
// (fetched once per page render) so every tab can label an event/finding
// with "Collection #N" without a separate fetch per tab. Collections are
// numbered by upload order, not stored -- see collectionLabel().
let currentCollections = [];

// apiError builds an Error from a failed response body. A 409 carrying
// duplicate_collection_label (see api.DuplicateEvidenceError) is tagged
// so callers can show "Evidence already exists" instead of a generic
// error -- rejecting a duplicate upload/ingest must never look silent or
// like an unrelated failure.
function apiError(res, body) {
  const err = new Error((body && body.error) || res.statusText);
  if (res.status === 409 && body && body.duplicate_collection_label) {
    err.duplicateCollectionLabel = body.duplicate_collection_label;
  }
  return err;
}

async function api(path, opts) {
  const res = await fetch("/api" + path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  const body = await res.json().catch(() => null);
  if (!res.ok) {
    throw apiError(res, body);
  }
  return body;
}

// apiUpload posts a file as multipart/form-data. Deliberately not using
// api() above: fetch needs to set its own multipart boundary in
// Content-Type, which api()'s hardcoded "application/json" header would
// clobber.
async function apiUpload(path, file) {
  const fd = new FormData();
  fd.append("file", file);
  const res = await fetch("/api" + path, { method: "POST", body: fd });
  const body = await res.json().catch(() => null);
  if (!res.ok) {
    throw apiError(res, body);
  }
  return body;
}

function h(html) {
  const t = document.createElement("template");
  t.innerHTML = html.trim();
  return t.content.firstElementChild;
}

function esc(s) {
  if (s === null || s === undefined) return "";
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function fmtTime(ts) {
  if (!ts) return "-";
  const d = new Date(ts);
  if (isNaN(d.getTime())) return ts;
  return d.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
}

function fmtDate(ts) {
  if (!ts) return "-";
  const d = new Date(ts);
  if (isNaN(d.getTime())) return ts;
  return d.toLocaleDateString(undefined, { day: "2-digit", month: "short", year: "numeric" }) + " " + d.toISOString().slice(11, 16) + " UTC";
}

function severityBadge(sev) {
  return `<span class="badge ${esc(sev)}">${esc(sev)}</span>`;
}

function confBadge(conf) {
  return `<span class="badge conf">${esc(conf)} confidence</span>`;
}

function statusBadge(status) {
  return `<span class="badge status ${esc(status)}">${esc(status)}</span>`;
}

function techChips(techniques) {
  if (!techniques || techniques.length === 0) return "";
  return techniques.map((t) => `<span class="tech-chip">${esc(t)}</span>`).join("");
}

function errorBox(err) {
  if (err.duplicateCollectionLabel) {
    return `<div class="error-box">
      <strong>Evidence already exists</strong>
      <div>This evidence package has already been added to this case as ${esc(err.duplicateCollectionLabel)}.</div>
    </div>`;
  }
  return `<div class="error-box">${esc(err.message || String(err))}</div>`;
}

// ---------------- Collection labeling ----------------

// collectionLabel returns "Collection #N" for a collection ID, numbered
// by upload order (1-based) against the currently loaded collections
// list. Falls back gracefully if the ID isn't found (e.g. stale data).
function collectionLabel(collectionId) {
  const idx = currentCollections.findIndex((c) => c.collection_id === collectionId);
  if (idx === -1) return collectionId ? esc(collectionId).slice(0, 8) : "-";
  return `Collection #${idx + 1}`;
}

function collectionBadge(collectionId) {
  if (!collectionId) return "";
  return `<span class="badge conf collection-badge">${esc(collectionLabel(collectionId))}</span>`;
}

const SOURCE_TYPE_LABELS = {
  kape_upload: "KAPE Upload",
  local_path: "Local Path",
  legacy: "Legacy",
};

// ---------------- Long-value rendering (findings UI fix) ----------------
//
// Long values (a base64-encoded PowerShell command, in particular) must
// never be allowed to force a container wider than its layout -- see
// the .finding-desc / .detail-cell CSS rules (overflow-wrap) -- and a
// value long enough to hurt readability is truncated with an expandable
// "Show full value" + Copy affordance, never silently cut off with no
// way to see the rest.

let cellIdCounter = 0;

// detailCell renders a table-cell-safe value: short values render
// as-is; long ones truncate with a toggle to reveal the full text and a
// button to copy it, so the full value is always reachable even though
// it isn't dumped as one unbounded line by default.
function detailCell(value) {
  if (!value) return "";
  const str = String(value);
  if (str.length <= 100) {
    return `<span class="detail-cell">${esc(str)}</span>`;
  }
  const id = `detail-${++cellIdCounter}`;
  return `
    <div class="detail-cell detail-cell-long">
      <span id="${id}" class="detail-text truncated">${esc(str.slice(0, 100))}&hellip;</span>
      <div class="detail-actions">
        <button type="button" class="secondary small detail-toggle-btn" data-target="${id}" data-full="${esc(str)}" data-short="${esc(str.slice(0, 100))}&hellip;">Show full command</button>
        <button type="button" class="secondary small detail-copy-btn" data-copy="${esc(str)}">Copy</button>
      </div>
    </div>`;
}

// wireDetailCells attaches the show-full/copy handlers for every
// detailCell rendered under root. Safe to call repeatedly.
function wireDetailCells(root) {
  root.querySelectorAll(".detail-toggle-btn").forEach((btn) => {
    if (btn.dataset.wired) return;
    btn.dataset.wired = "1";
    btn.addEventListener("click", (ev) => {
      ev.stopPropagation();
      const target = document.getElementById(btn.dataset.target);
      if (!target) return;
      const expanded = target.classList.toggle("truncated") === false;
      if (expanded) {
        target.textContent = btn.dataset.full;
        btn.textContent = "Show less";
      } else {
        target.innerHTML = btn.dataset.short.replace(/&hellip;/, "…");
        btn.textContent = "Show full command";
      }
    });
  });
  root.querySelectorAll(".detail-copy-btn").forEach((btn) => {
    if (btn.dataset.wired) return;
    btn.dataset.wired = "1";
    btn.addEventListener("click", async (ev) => {
      ev.stopPropagation();
      try {
        await navigator.clipboard.writeText(btn.dataset.copy);
        const original = btn.textContent;
        btn.textContent = "Copied!";
        setTimeout(() => (btn.textContent = original), 1500);
      } catch (e) {
        btn.textContent = "Copy failed";
      }
    });
  });
}

// eventDetailValue picks the most relevant single field to show for an
// event in a "Detail" column.
function eventDetailValue(e) {
  return e.command_line || e.registry_path || e.file_path || e.network_dest || "";
}

// ---------------- Router ----------------

window.addEventListener("hashchange", route);
window.addEventListener("DOMContentLoaded", () => {
  checkHealth();
  route();
});

async function checkHealth() {
  try {
    await api("/healthz");
    connStatus.textContent = "connected";
  } catch (e) {
    connStatus.textContent = "disconnected";
  }
}

function route() {
  const hash = window.location.hash.replace(/^#/, "") || "/";
  const caseMatch = hash.match(/^\/cases\/([^/]+)(?:\/(\w+))?$/);
  if (caseMatch) {
    renderCaseDetail(caseMatch[1], caseMatch[2] || "summary");
    return;
  }
  renderCaseList();
}

// ---------------- Case list ----------------

async function renderCaseList() {
  app.innerHTML = `
    <div class="panel">
      <h2>New case</h2>
      <div class="field"><label>Name</label><input id="new-case-name" placeholder="e.g. WKSTN-042 Phishing Triage" /></div>
      <div class="field"><label>Description</label><input id="new-case-desc" placeholder="optional" /></div>
      <button id="create-case-btn">Create case</button>
      <div id="new-case-error"></div>
    </div>
    <div class="panel">
      <h2>Cases</h2>
      <div id="case-list"><p class="empty">Loading...</p></div>
    </div>
  `;

  document.getElementById("create-case-btn").addEventListener("click", async () => {
    const name = document.getElementById("new-case-name").value.trim();
    const description = document.getElementById("new-case-desc").value.trim();
    const errBox = document.getElementById("new-case-error");
    errBox.innerHTML = "";
    if (!name) {
      errBox.innerHTML = errorBox(new Error("Name is required"));
      return;
    }
    try {
      const c = await api("/cases", { method: "POST", body: JSON.stringify({ name, description }) });
      window.location.hash = `#/cases/${c.id}`;
    } catch (e) {
      errBox.innerHTML = errorBox(e);
    }
  });

  try {
    const cases = await api("/cases");
    const list = document.getElementById("case-list");
    if (cases.length === 0) {
      list.innerHTML = `<p class="empty">No cases yet. Create one above to get started.</p>`;
      return;
    }
    list.innerHTML = cases
      .map(
        (c) => `
      <a class="case-card" href="#/cases/${c.id}">
        <div class="row between">
          <strong>${esc(c.name)}</strong>
          ${statusBadge(c.status)}
        </div>
        <div class="muted small">${esc(c.description || "")}</div>
        <div class="muted small mono">${esc(c.id)} &middot; created ${fmtTime(c.created_at)}</div>
      </a>`
      )
      .join("");
  } catch (e) {
    document.getElementById("case-list").innerHTML = errorBox(e);
  }
}

// ---------------- Case detail ----------------

async function renderCaseDetail(caseId, tab) {
  app.innerHTML = `<p class="empty">Loading case...</p>`;
  let data, collections;
  try {
    [data, collections] = await Promise.all([api(`/cases/${caseId}`), api(`/cases/${caseId}/evidence`)]);
  } catch (e) {
    app.innerHTML = errorBox(e);
    return;
  }
  const c = data.case;
  const summary = data.summary;
  currentCollections = collections;

  app.innerHTML = `
    <p><a href="#/">&larr; All cases</a></p>
    <div class="panel">
      <div class="row between">
        <div>
          <h1>${esc(c.name)}</h1>
          <div class="muted">${esc(c.description || "")}</div>
        </div>
        ${statusBadge(c.status)}
      </div>
      <div class="muted small mono" style="margin-top:6px">${esc(c.id)}</div>

      <div class="summary-grid">
        <div class="stat"><div class="n">${summary.collections}</div><div class="l">Collections</div></div>
        <div class="stat"><div class="n">${summary.source_files}</div><div class="l">Source files</div></div>
        <div class="stat"><div class="n">${summary.events}</div><div class="l">Events</div></div>
        <div class="stat"><div class="n">${summary.findings}</div><div class="l">Findings</div></div>
        <div class="stat"><div class="n">${summary.correlations}</div><div class="l">Correlations</div></div>
        <div class="stat"><div class="n">${summary.technique_count}</div><div class="l">ATT&amp;CK techniques</div></div>
      </div>
      <div class="row" style="margin-top:10px">
        ${severityBadge("critical")} ${summary.severity_counts.critical || 0}
        ${severityBadge("high")} ${summary.severity_counts.high || 0}
        ${severityBadge("medium")} ${summary.severity_counts.medium || 0}
        ${severityBadge("low")} ${summary.severity_counts.low || 0}
      </div>
    </div>

    <div class="panel">
      <div class="row between">
        <h2>Evidence Collections</h2>
        <button id="add-evidence-btn">+ Add Evidence</button>
      </div>
      <div id="add-evidence-form" class="add-evidence-form hidden">
        <h3>Upload KAPE package</h3>
        <p class="muted small">Upload a ZIP archive of a KAPE triage collection. Tracefall safely extracts it, discovers supported artifacts (EvtxECmd/PECmd/RECmd CSV, Scheduled Task XML), and parses them automatically -- no local path required.</p>
        <div class="row">
          <input type="file" id="upload-file" accept=".zip,application/zip" />
          <button id="upload-btn">Upload KAPE Package</button>
        </div>
        <div id="upload-progress"></div>
        <div id="upload-error"></div>

        <details style="margin-top:16px">
          <summary class="muted small" style="cursor:pointer">Advanced: ingest from a local path instead</summary>
          <p class="muted small">For local/dev use (e.g. the bundled synthetic dataset at <code>testdata/synthetic_case</code>) when the evidence is already on the machine running Tracefall.</p>
          <div class="row">
            <div style="flex:1"><input id="ingest-path" placeholder="/path/to/evidence" value="testdata/synthetic_case" /></div>
            <button id="ingest-btn" class="secondary">Ingest</button>
          </div>
          <div id="ingest-error"></div>
        </details>
      </div>
      <div id="collections-list">${renderCollectionsList(collections)}</div>
    </div>

    <div class="panel" id="analysis-panel">${renderAnalysisAction(c, summary)}</div>

    <div class="tabs">
      ${tabLink(caseId, "summary", "Timeline", tab)}
      ${tabLink(caseId, "findings", "Findings", tab)}
      ${tabLink(caseId, "attack", "ATT&CK", tab)}
      ${tabLink(caseId, "correlations", "Activity Chains", tab)}
      ${tabLink(caseId, "evidence", "Evidence", tab)}
    </div>
    <div id="tab-content" class="panel"><p class="empty">Loading...</p></div>
  `;

  wireEvidenceHeader(caseId);
  wireAnalysisAction(caseId);

  const content = document.getElementById("tab-content");
  try {
    switch (tab) {
      case "findings":
        await renderFindingsTab(content, caseId);
        break;
      case "attack":
        await renderAttackTab(content, caseId);
        break;
      case "correlations":
        await renderCorrelationsTab(content, caseId);
        break;
      case "evidence":
        await renderEvidenceTab(content, caseId, collections);
        break;
      default:
        await renderTimelineTab(content, caseId, collections);
    }
  } catch (e) {
    content.innerHTML = errorBox(e);
  }
}

function tabLink(caseId, key, label, active) {
  const cls = key === active || (key === "summary" && active === "summary") ? "tab active" : "tab";
  return `<a class="${cls}" href="#/cases/${caseId}/${key}">${label}</a>`;
}

// ---------------- Evidence Collections header ----------------

function renderCollectionsList(collections) {
  if (collections.length === 0) {
    return `<p class="empty">No evidence yet. Click "+ Add Evidence" to upload a KAPE package.</p>`;
  }
  return collections
    .map((col, i) => {
      const statusCls = col.ingestion_status === "failed" ? "critical" : col.ingestion_status === "pending" ? "medium" : "status analyzed";
      return `
      <div class="collection-card">
        <div class="row between">
          <strong>Collection #${i + 1}</strong>
          <span class="badge ${statusCls}">${esc(col.ingestion_status)}</span>
        </div>
        <div class="muted small">${esc(SOURCE_TYPE_LABELS[col.source_type] || col.source_type)}${col.original_filename ? " &middot; " + esc(col.original_filename) : ""}</div>
        <div class="muted small">${esc(fmtDate(col.created_at))}</div>
        <div class="small" style="margin-top:4px">${col.supported_file_count} file(s) &middot; ${col.parsed_event_count} event(s)${col.unsupported_file_count ? ` &middot; ${col.unsupported_file_count} unsupported` : ""}</div>
      </div>`;
    })
    .join("");
}

function wireEvidenceHeader(caseId) {
  const addBtn = document.getElementById("add-evidence-btn");
  const form = document.getElementById("add-evidence-form");
  addBtn.addEventListener("click", () => {
    const hidden = form.classList.toggle("hidden");
    addBtn.textContent = hidden ? "+ Add Evidence" : "Cancel";
  });

  const uploadBtn = document.getElementById("upload-btn");
  uploadBtn.addEventListener("click", async () => {
    const fileInput = document.getElementById("upload-file");
    const errBox = document.getElementById("upload-error");
    const progress = document.getElementById("upload-progress");
    errBox.innerHTML = "";
    progress.innerHTML = "";

    const file = fileInput.files[0];
    if (!file) {
      errBox.innerHTML = errorBox(new Error("Choose a .zip file first"));
      return;
    }

    uploadBtn.disabled = true;
    uploadBtn.textContent = "Uploading...";
    progress.innerHTML = uploadStep("Uploading and extracting archive...", false);

    try {
      const res = await apiUpload(`/cases/${caseId}/evidence`, file);
      progress.innerHTML = renderUploadResults(res);
      document.getElementById("upload-continue-btn").addEventListener("click", () => window.location.reload());
    } catch (e) {
      errBox.innerHTML = errorBox(e);
      progress.innerHTML = "";
    } finally {
      uploadBtn.disabled = false;
      uploadBtn.textContent = "Upload KAPE Package";
    }
  });

  const ingestBtn = document.getElementById("ingest-btn");
  ingestBtn.addEventListener("click", async () => {
    const path = document.getElementById("ingest-path").value.trim();
    const errBox = document.getElementById("ingest-error");
    errBox.innerHTML = "";
    ingestBtn.disabled = true;
    ingestBtn.textContent = "Ingesting...";
    try {
      await api(`/cases/${caseId}/ingest`, { method: "POST", body: JSON.stringify({ path }) });
      window.location.reload();
    } catch (e) {
      errBox.innerHTML = errorBox(e);
      ingestBtn.disabled = false;
      ingestBtn.textContent = "Ingest";
    }
  });
}

// uploadStep renders one line of the upload progress list. done=true
// shows a check mark instead of a spinner glyph.
function uploadStep(label, done) {
  return `<div class="row small" style="margin:4px 0"><span>${done ? "&check;" : "&hellip;"}</span><span>${esc(label)}</span></div>`;
}

// renderUploadResults shows what the upload endpoint discovered and
// parsed -- archive accepted, files discovered, supported vs.
// unsupported artifacts, parsed/new/duplicate event counts -- plus a
// button to continue into the case dashboard.
function renderUploadResults(res) {
  const byArtifact = {};
  for (const sf of res.source_files || []) {
    byArtifact[sf.artifact_type] = (byArtifact[sf.artifact_type] || 0) + 1;
  }
  const supportedLines = Object.keys(byArtifact).length
    ? Object.entries(byArtifact)
        .map(([type, n]) => `<div class="small">&nbsp;&nbsp;&bull; ${esc(type)}: ${n} file(s)</div>`)
        .join("")
    : `<div class="small muted">&nbsp;&nbsp;none recognized</div>`;

  return `
    <div class="panel" style="background:var(--bg-panel-2); margin-top:12px; margin-bottom:0">
      <h3>Upload complete</h3>
      ${uploadStep(`Archive accepted (${fmtBytes(res.upload_size_bytes)})`, true)}
      ${uploadStep(`${res.extracted_files} file(s) discovered in archive`, true)}
      <div class="small" style="margin:4px 0">&check; Supported artifacts:</div>
      ${supportedLines}
      ${uploadStep(`${(res.skipped_files || []).length} unsupported file(s) (not analyzable, ingestion continued)`, true)}
      ${uploadStep(`${res.event_count} event(s) parsed (${res.new_event_count} new, ${res.duplicate_event_count} already known from another collection)`, true)}
      ${res.errors && res.errors.length ? `<div class="small" style="color:var(--high)">${res.errors.length} file(s) had parse errors</div>` : ""}
      <div style="margin-top:12px">
        <button id="upload-continue-btn">Continue to case dashboard</button>
      </div>
    </div>`;
}

function fmtBytes(n) {
  if (!n && n !== 0) return "-";
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${units[i]}`;
}

// ---------------- Analysis action ----------------

function renderAnalysisAction(c, summary) {
  if (summary.collections === 0) {
    return `<p class="empty">Add evidence above, then run analysis.</p>`;
  }
  if (c.status === "analyzed") {
    return `
      <p class="muted small">Analysis reflects all ${summary.collections} collection(s) currently in this case. Adding more evidence will mark this stale.</p>
      <button id="analyze-btn" class="secondary">Re-run analysis</button>
      <div id="analyze-error"></div>`;
  }
  return `
    <p class="muted small">Run the deterministic detection and correlation engines across all ${summary.collections} collection(s) in this case.</p>
    <button id="analyze-btn">Run analysis</button>
    <div id="analyze-error"></div>`;
}

function wireAnalysisAction(caseId) {
  const analyzeBtn = document.getElementById("analyze-btn");
  if (!analyzeBtn) return;
  analyzeBtn.addEventListener("click", async () => {
    const errBox = document.getElementById("analyze-error");
    errBox.innerHTML = "";
    analyzeBtn.disabled = true;
    const original = analyzeBtn.textContent;
    analyzeBtn.textContent = "Analyzing...";
    try {
      await api(`/cases/${caseId}/analyze`, { method: "POST" });
      window.location.reload();
    } catch (e) {
      errBox.innerHTML = errorBox(e);
      analyzeBtn.disabled = false;
      analyzeBtn.textContent = original;
    }
  });
}

// ---------------- Timeline tab ----------------

async function renderTimelineTab(content, caseId, collections) {
  const filterOptions = collections
    .map((col, i) => `<option value="${esc(col.collection_id)}">Collection #${i + 1}</option>`)
    .join("");
  content.innerHTML = `
    <div class="row between">
      <h2 id="timeline-heading">Unified timeline</h2>
      ${collections.length > 1 ? `<select id="timeline-filter"><option value="">All collections</option>${filterOptions}</select>` : ""}
    </div>
    <div id="timeline-body"><p class="empty">Loading...</p></div>
  `;
  const filter = document.getElementById("timeline-filter");
  if (filter) {
    filter.addEventListener("change", () => loadTimeline(caseId, filter.value));
  }
  await loadTimeline(caseId, "");
}

async function loadTimeline(caseId, collectionId) {
  const body = document.getElementById("timeline-body");
  const heading = document.getElementById("timeline-heading");
  body.innerHTML = `<p class="empty">Loading...</p>`;
  const qs = collectionId ? `?collection=${encodeURIComponent(collectionId)}` : "";
  const events = await api(`/cases/${caseId}/timeline${qs}`);
  heading.textContent = `Unified timeline (${events.length} events)`;
  if (events.length === 0) {
    body.innerHTML = `<p class="empty">No events yet. Add evidence first.</p>`;
    return;
  }
  body.innerHTML = `
    <div class="table-wrap"><table>
      <thead><tr><th>Time (UTC)</th><th>Type</th><th>Host</th><th>User</th><th>Process</th><th>Parent</th><th>Detail</th><th>Artifact</th><th>Collection</th></tr></thead>
      <tbody>
        ${events.map(rowForEvent).join("")}
      </tbody>
    </table></div>
  `;
  wireDetailCells(body);
}

function rowForEvent(e) {
  return `<tr>
    <td class="mono small">${esc(fmtTime(e.timestamp))}</td>
    <td>${esc(e.event_type)}</td>
    <td class="mono small">${esc(e.host)}</td>
    <td class="mono small">${esc(e.user)}</td>
    <td class="mono small">${esc(e.process_name)}</td>
    <td class="mono small">${esc(e.parent_process)}</td>
    <td class="mono small detail-td">${detailCell(eventDetailValue(e))}</td>
    <td class="small">${esc(e.artifact_type)}</td>
    <td class="small">${collectionBadge(e.collection_id)}</td>
  </tr>`;
}

// ---------------- Findings tab ----------------

async function renderFindingsTab(content, caseId) {
  const findings = await api(`/cases/${caseId}/findings`);
  if (findings.length === 0) {
    content.innerHTML = `<p class="empty">No findings yet. Run analysis first.</p>`;
    return;
  }
  content.innerHTML = `
    <h2>Findings (${findings.length})</h2>
    <div id="finding-cards"></div>
  `;
  const container = document.getElementById("finding-cards");
  findings.forEach((f) => {
    const longDesc = f.description && f.description.length > 280;
    const descId = `desc-${++cellIdCounter}`;
    const descHtml = longDesc
      ? `<span id="${descId}" class="truncated">${esc(f.description.slice(0, 280))}&hellip;</span>
         <button type="button" class="secondary small detail-toggle-btn" data-target="${descId}" data-full="${esc(f.description)}" data-short="${esc(f.description.slice(0, 280))}&hellip;">Show more</button>`
      : esc(f.description || "");
    const card = h(`
      <div class="finding-card">
        <div class="row between">
          <div class="row">${severityBadge(f.severity)} ${confBadge(f.confidence)}</div>
          <span class="muted small mono">${esc(f.detection_rule)}</span>
        </div>
        <div class="finding-title">${esc(f.title)}</div>
        <div class="finding-desc">${descHtml}</div>
        <div>${techChips(f.attack_techniques)}</div>
        <div class="muted small">${esc(fmtTime(f.first_seen))} &rarr; ${esc(fmtTime(f.last_seen))} &middot; ${f.supporting_event_ids.length} supporting event(s)</div>
        <div class="finding-detail" data-id="${esc(f.finding_id)}"></div>
      </div>
    `);
    card.addEventListener("click", (ev) => {
      if (ev.target.closest(".evidence-box") || ev.target.closest(".detail-toggle-btn") || ev.target.closest(".detail-copy-btn")) return;
      toggleFindingDetail(card, caseId, f.finding_id);
    });
    wireDetailCells(card);
    container.appendChild(card);
  });
}

async function toggleFindingDetail(card, caseId, findingId) {
  const detail = card.querySelector(".finding-detail");
  const open = detail.classList.contains("open");
  if (open) {
    detail.classList.remove("open");
    return;
  }
  detail.classList.add("open");
  if (detail.dataset.loaded) return;
  detail.innerHTML = `<p class="empty">Loading evidence...</p>`;
  try {
    const fd = await api(`/cases/${caseId}/findings/${findingId}`);
    detail.innerHTML = `
      <h3>Supporting evidence</h3>
      <div class="table-wrap"><table>
        <thead><tr><th>Time</th><th>Type</th><th>Process</th><th>Detail</th><th>Source</th><th>Collection</th><th></th></tr></thead>
        <tbody>
          ${fd.supporting_event_details
            .map(
              (e) => `<tr>
                <td class="mono small">${esc(fmtTime(e.timestamp))}</td>
                <td>${esc(e.event_type)}</td>
                <td class="mono small">${esc(e.process_name)}</td>
                <td class="mono small detail-td">${detailCell(eventDetailValue(e))}</td>
                <td class="small">${esc(e.artifact_type)}</td>
                <td class="small">${collectionBadge(e.collection_id)}</td>
                <td><button class="secondary small view-raw-btn" data-event="${esc(e.id)}">raw</button></td>
              </tr>
              <tr class="raw-row" data-for="${esc(e.id)}" style="display:none"><td colspan="7"><div class="evidence-box"></div></td></tr>`
            )
            .join("")}
        </tbody>
      </table></div>
    `;
    detail.dataset.loaded = "1";
    wireDetailCells(detail);
    detail.querySelectorAll(".view-raw-btn").forEach((btn) => {
      btn.addEventListener("click", async (ev) => {
        ev.stopPropagation();
        const eventId = btn.dataset.event;
        const row = detail.querySelector(`.raw-row[data-for="${eventId}"]`);
        const box = row.querySelector(".evidence-box");
        const showing = row.style.display !== "none";
        if (showing) {
          row.style.display = "none";
          return;
        }
        if (!box.dataset.loaded) {
          try {
            const prov = await api(`/cases/${caseId}/events/${eventId}`);
            const observedIn = (prov.observations || []).map((o) => collectionLabel(o.collection_id));
            box.textContent =
              `source file: ${prov.source_file.path}\nparser: ${prov.source_file.parser}\nsource reference: ${prov.event.source_reference}\n` +
              `observed in: ${observedIn.join(", ")}\n\nraw record:\n` +
              prov.raw_evidence.raw;
            box.dataset.loaded = "1";
          } catch (e) {
            box.textContent = "Error loading evidence: " + e.message;
          }
        }
        row.style.display = "table-row";
      });
    });
  } catch (e) {
    detail.innerHTML = errorBox(e);
  }
}

// ---------------- ATT&CK tab ----------------

async function renderAttackTab(content, caseId) {
  const techniques = await api(`/cases/${caseId}/attack`);
  if (techniques.length === 0) {
    content.innerHTML = `<p class="empty">No ATT&amp;CK techniques mapped yet. Run analysis first.</p>`;
    return;
  }
  content.innerHTML = `
    <h2>MITRE ATT&amp;CK coverage (${techniques.length} techniques)</h2>
    ${techniques
      .map(
        (t) => `
      <div class="finding-card" style="cursor:default">
        <div class="row between">
          <div><span class="tech-chip">${esc(t.id)}</span> <strong>${esc(t.name)}</strong></div>
          <a href="${esc(t.url)}" target="_blank" rel="noopener">mitre.org &#8599;</a>
        </div>
        <div class="muted small">${esc(t.tactic)}</div>
        <div class="muted small" style="margin-top:8px">${t.findings.length} finding(s): ${t.findings.map((f) => esc(f.title)).join("; ")}</div>
      </div>`
      )
      .join("")}
  `;
}

// ---------------- Correlations tab ----------------

const CORR_LABELS = {
  activity_chain: "Activity chain",
  process_chain: "Process chain",
  entity: "Entity correlation",
  temporal: "Temporal cluster",
};

async function renderCorrelationsTab(content, caseId) {
  const corrs = await api(`/cases/${caseId}/correlations`);
  if (corrs.length === 0) {
    content.innerHTML = `<p class="empty">No correlations yet. Run analysis first.</p>`;
    return;
  }
  // Resolve which collections each correlation's events belong to, so a
  // cross-collection chain is visibly labeled as such.
  let eventsById = null;
  if (currentCollections.length > 1) {
    const timeline = await api(`/cases/${caseId}/timeline`);
    eventsById = Object.fromEntries(timeline.map((e) => [e.id, e]));
  }

  content.innerHTML = `
    <h2>Correlated activity (${corrs.length})</h2>
    ${corrs
      .map((c) => {
        let collectionsLine = "";
        if (eventsById) {
          const collIds = new Set(c.event_ids.map((id) => eventsById[id] && eventsById[id].collection_id).filter(Boolean));
          if (collIds.size > 1) {
            collectionsLine = `<div class="muted small" style="margin-top:6px">Spans ${[...collIds].map(collectionLabel).join(", ")}</div>`;
          }
        }
        return `
      <div class="finding-card" style="cursor:default">
        <div class="row between">
          <span class="badge conf">${esc(CORR_LABELS[c.correlation_type] || c.correlation_type)}</span>
          <span class="muted small">${c.event_ids.length} event(s)</span>
        </div>
        <div class="finding-title">${esc(c.title)}</div>
        <div class="finding-desc">${esc(c.description)}</div>
        ${collectionsLine}
      </div>`;
      })
      .join("")}
  `;
}

// ---------------- Evidence tab ----------------

async function renderEvidenceTab(content, caseId, collections) {
  if (collections.length === 0) {
    content.innerHTML = `<p class="empty">No evidence collections yet. Click "+ Add Evidence" above.</p>`;
    return;
  }
  content.innerHTML = `
    <h2>Evidence Collections (${collections.length})</h2>
    <p class="muted small">Click a collection to see the source files it produced.</p>
    <div id="evidence-collections"></div>
  `;
  const container = document.getElementById("evidence-collections");
  collections.forEach((col, i) => {
    const statusCls = col.ingestion_status === "failed" ? "critical" : col.ingestion_status === "pending" ? "medium" : "status analyzed";
    const card = h(`
      <div class="finding-card">
        <div class="row between">
          <strong>Collection #${i + 1}</strong>
          <span class="badge ${statusCls}">${esc(col.ingestion_status)}</span>
        </div>
        <div class="muted small">${esc(SOURCE_TYPE_LABELS[col.source_type] || col.source_type)}${col.original_filename ? " &middot; " + esc(col.original_filename) : ""}</div>
        <div class="muted small">${esc(fmtDate(col.created_at))}</div>
        <div class="small" style="margin-top:4px">${col.supported_file_count} file(s) &middot; ${col.parsed_event_count} event(s)${col.unsupported_file_count ? ` &middot; ${col.unsupported_file_count} unsupported` : ""}</div>
        ${col.archive_hash ? `<div class="muted small mono" style="margin-top:4px">sha256: ${esc(col.archive_hash.slice(0, 24))}&hellip;</div>` : ""}
        <div class="collection-sources" data-id="${esc(col.collection_id)}"></div>
      </div>
    `);
    card.addEventListener("click", () => toggleCollectionSources(card, caseId, col.collection_id));
    container.appendChild(card);
  });
}

async function toggleCollectionSources(card, caseId, collectionId) {
  const box = card.querySelector(".collection-sources");
  const open = box.classList.contains("open");
  if (open) {
    box.classList.remove("open");
    return;
  }
  box.classList.add("open");
  if (box.dataset.loaded) return;
  box.innerHTML = `<p class="empty">Loading...</p>`;
  try {
    const detail = await api(`/cases/${caseId}/evidence/${collectionId}`);
    const sources = detail.source_files || [];
    box.innerHTML = sources.length
      ? `<div class="table-wrap"><table>
          <thead><tr><th>Path</th><th>Artifact type</th><th>Parser</th><th>Rows</th><th>SHA-256</th></tr></thead>
          <tbody>
            ${sources
              .map(
                (s) => `<tr>
                  <td class="mono small">${esc(s.path)}</td>
                  <td class="small">${esc(s.artifact_type)}</td>
                  <td class="mono small">${esc(s.parser)}</td>
                  <td class="small">${s.row_count}</td>
                  <td class="mono small">${esc(s.sha256.slice(0, 16))}&hellip;</td>
                </tr>`
              )
              .join("")}
          </tbody>
        </table></div>`
      : `<p class="empty">No supported source files in this collection.</p>`;
    box.dataset.loaded = "1";
  } catch (e) {
    box.innerHTML = errorBox(e);
  }
}
