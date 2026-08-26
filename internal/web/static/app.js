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
// duplicate_collection_label (see api.DuplicateEvidenceError) or
// duplicate_case_name (see api.DuplicateCaseError) is tagged so callers
// can show a dedicated "already exists" message instead of a generic
// error -- rejecting a duplicate upload/ingest/case must never look
// silent or like an unrelated failure.
function apiError(res, body) {
  const err = new Error((body && body.error) || res.statusText);
  if (res.status === 409 && body && body.duplicate_collection_label) {
    err.duplicateCollectionLabel = body.duplicate_collection_label;
  }
  if (res.status === 409 && body && body.duplicate_case_name) {
    err.duplicateCaseName = body.duplicate_case_name;
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

// fmtTime renders a timestamp with an explicit "UTC" label rather than
// just an ISO "Z" suffix (Phase 6: "the investigator must be able to
// distinguish event timestamp / collection timestamp / analysis
// timestamp" -- part of that is never leaving a reader to infer the
// timezone from an easily-missed single letter). Every timestamp
// Tracefall's API returns is always UTC already (see
// internal/normalize.Timestamp) -- this only formats for display, it
// never converts a timezone.
function fmtTime(ts) {
  if (!ts) return "-";
  const d = new Date(ts);
  if (isNaN(d.getTime())) return ts;
  return d.toISOString().replace("T", " ").replace(/\.\d+Z$/, "").replace(/Z$/, "") + " UTC";
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

// nameFieldError/setNameFieldError/clearNameFieldError render the New
// Case form's Name validation as a compact, field-scoped component
// (red input border + icon + a small error box directly beneath the
// input) rather than the full-width .error-box used elsewhere -- the
// error belongs visually to the Name field, not to whatever happens to
// be below it in the form.
function nameFieldError(err) {
  if (err.duplicateCaseName) {
    return `<div class="field-error-box">
      <strong>Case already exists</strong>
      <div>This case name is already in use. Please choose a different name.</div>
    </div>`;
  }
  return `<div class="field-error-box">${esc(err.message || String(err))}</div>`;
}

function setNameFieldError(err) {
  document.getElementById("new-case-name").classList.add("input-error");
  document.getElementById("new-case-name-icon").classList.remove("hidden");
  document.getElementById("new-case-error").innerHTML = nameFieldError(err);
}

function clearNameFieldError() {
  document.getElementById("new-case-name").classList.remove("input-error");
  document.getElementById("new-case-name-icon").classList.add("hidden");
  document.getElementById("new-case-error").innerHTML = "";
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

// ---------------- Investigation cross-referencing ----------------
//
// Tracefall's API already returns everything these helpers need --
// Finding.supporting_event_ids, Correlation.event_ids, and each
// technique's tactic from GET /attack -- so linking "this timeline row
// is part of finding X, which maps to ATT&CK technique Y, which is part
// of activity chain Z" is done here, client-side, from data already
// fetched once per tab. This is a join over real IDs already present in
// the data model, never an invented relationship -- see this phase's
// "no fabricated confidence" rule.

// EVENT_CATEGORIES buckets internal/model's EventType constants into the
// coarse forensic categories the timeline/filters distinguish -- see
// Phase's "Unified Forensic Timeline" requirement. Deliberately a fixed,
// exhaustive table (not inferred from the string) so a new event type
// added later fails visibly (falls into "other") rather than silently
// miscategorized.
const EVENT_CATEGORIES = {
  logon_success: "authentication",
  logon_failure: "authentication",
  process_create: "execution",
  powershell_script_block: "execution",
  prefetch_execution: "execution",
  registry_run_key_set: "persistence",
  scheduled_task_created: "persistence",
  network_connection: "network",
  // Phase 4 additions.
  logon_explicit_credentials: "authentication",
  privileged_logon: "authentication",
  kerberos_tgt_request: "authentication",
  kerberos_service_ticket_request: "authentication",
  ntlm_authentication: "authentication",
  service_install: "persistence",
  registry_persistence: "persistence",
  file_create: "execution",
  dns_query: "network",
};
const EVENT_CATEGORY_LABELS = {
  authentication: "Authentication",
  execution: "Execution",
  persistence: "Persistence",
  network: "Network",
  other: "Other",
};
function eventCategory(e) {
  return EVENT_CATEGORIES[e.event_type] || "other";
}

// CANONICAL_TACTICS is MITRE ATT&CK's own tactic ordering (kill-chain
// order), used to group and sort the ATT&CK tab and the Investigation
// Summary -- not alphabetical, since tactic order itself carries
// forensic meaning (an investigator reads left-to-right as "how did they
// get in, then what did they do").
const CANONICAL_TACTICS = [
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
];

// splitTactics turns attck.Technique's comma-joined Tactic string (e.g.
// "Persistence, Privilege Escalation" -- a technique can genuinely belong
// to more than one MITRE tactic) into a list.
function splitTactics(tacticStr) {
  return (tacticStr || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

// buildEventFindingIndex maps event ID -> every finding that lists it in
// supporting_event_ids, so a timeline row or activity-chain node can show
// "this event is part of finding X" (severity, techniques) without a
// per-row fetch.
function buildEventFindingIndex(findings) {
  const idx = {};
  (findings || []).forEach((f) => {
    (f.supporting_event_ids || []).forEach((eid) => {
      (idx[eid] = idx[eid] || []).push(f);
    });
  });
  return idx;
}

// buildEventCorrelationIndex maps event ID -> every correlation
// (including activity chains) whose event_ids includes it.
function buildEventCorrelationIndex(correlations) {
  const idx = {};
  (correlations || []).forEach((c) => {
    (c.event_ids || []).forEach((eid) => {
      (idx[eid] = idx[eid] || []).push(c);
    });
  });
  return idx;
}

// findingsForEvents resolves a set of event IDs to the union of findings
// that support any of them, deduplicated by finding_id -- used to show
// "this activity chain node is covered by finding X" without refetching.
function findingsForEvents(eventFindingIndex, eventIds) {
  const seen = {};
  const out = [];
  (eventIds || []).forEach((eid) => {
    (eventFindingIndex[eid] || []).forEach((f) => {
      if (!seen[f.finding_id]) {
        seen[f.finding_id] = true;
        out.push(f);
      }
    });
  });
  return out;
}

// maxSeverity returns the highest of a list of severities (critical >
// high > medium > low), or "" if the list is empty -- used to roll up a
// single badge for a timeline row or chain node backed by more than one
// finding.
const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };
function maxSeverity(severities) {
  let best = "";
  (severities || []).forEach((s) => {
    if (!best || (SEVERITY_RANK[s] || 0) > (SEVERITY_RANK[best] || 0)) best = s;
  });
  return best;
}

// techniquesForFindings unions attack_techniques across a list of
// findings, deduplicated.
function techniquesForFindings(findings) {
  const seen = {};
  const out = [];
  (findings || []).forEach((f) => {
    (f.attack_techniques || []).forEach((t) => {
      if (!seen[t]) {
        seen[t] = true;
        out.push(t);
      }
    });
  });
  return out;
}

// buildInvestigationSummary composes a short, deterministic-facts-only
// paragraph from counts Tracefall already computed -- never an AI
// narrative (see this phase's "Do NOT generate an AI narrative yet"
// rule). Every number here is a direct count or a grouping of existing
// finding/technique data; nothing is inferred or estimated. attackTechniques
// is GET /attack's response, used only for its technique_id -> tactic
// mapping (real MITRE data already resolved server-side by
// internal/attck) so findings can be grouped the same way the ATT&CK tab
// groups them.
function buildInvestigationSummary(caseObj, summary, findings, attackTechniques) {
  if (summary.collections === 0) {
    return `<p class="muted small">No evidence has been added to this case yet.</p>`;
  }
  if (findings.length === 0) {
    const analyzed = caseObj.status === "analyzed";
    return `<p class="small">${summary.imported_source_files} imported source file(s) across ${summary.collections} evidence collection(s), ${summary.events} event(s) total. ${
      analyzed ? "Analysis found no findings against the current evidence." : "Evidence has not been analyzed yet -- run analysis to check for findings."
    }</p>`;
  }

  const tacticByTechnique = {};
  (attackTechniques || []).forEach((t) => (tacticByTechnique[t.id] = t.tactic));

  const findingsByTactic = {};
  findings.forEach((f) => {
    const tactics = new Set();
    (f.attack_techniques || []).forEach((tid) => splitTactics(tacticByTechnique[tid]).forEach((t) => tactics.add(t)));
    tactics.forEach((t) => (findingsByTactic[t] = (findingsByTactic[t] || 0) + 1));
  });
  const tacticFragments = CANONICAL_TACTICS.filter((t) => findingsByTactic[t]).map((t) => `${findingsByTactic[t]} ${t.toLowerCase()}`);

  const critical = summary.severity_counts.critical || 0;
  const high = summary.severity_counts.high || 0;
  const highConfidence = findings.filter((f) => f.confidence === "high").length;

  const parts = [];
  let headline = `${findings.length} finding(s) were observed across ${summary.collections} evidence collection(s)`;
  if (tacticFragments.length) headline += ` (${tacticFragments.join(", ")})`;
  headline += ".";
  parts.push(headline);

  if (highConfidence > 0) {
    parts.push(`${highConfidence} of these are high-confidence.`);
  }
  if (critical > 0 || high > 0) {
    const bits = [];
    if (critical > 0) bits.push(`${critical} critical`);
    if (high > 0) bits.push(`${high} high-severity`);
    parts.push(`${bits.join(" and ")} finding(s) warrant immediate review.`);
  }
  if (summary.technique_count > 0) {
    parts.push(`${summary.technique_count} distinct ATT&amp;CK technique(s) and ${summary.correlations} correlation(s) (including reconstructed activity chains, where evidenced) are mapped to this case.`);
  }

  return `<p class="small">${parts.join(" ")}</p>`;
}

// ---------------- Shared filter bar (Timeline + Findings) ----------------
//
// One small, config-driven filter component shared by both tabs rather
// than two bespoke ones -- each tab passes which fields it has data for
// (Timeline: category/process; Findings: confidence/rule), and filtering
// itself always runs client-side over that tab's already-fetched data
// (see renderTimelineTab/renderFindingsTab) rather than round-tripping
// to the server per filter change.

function categoryBadge(cat) {
  return `<span class="badge status category-${esc(cat)}">${esc(EVENT_CATEGORY_LABELS[cat] || cat)}</span>`;
}

function filterSelect(prefix, field, allLabel, options) {
  return `<select id="${prefix}-f-${field}" class="filter-input"><option value="">${esc(allLabel)}</option>${options
    .map(([v, l]) => `<option value="${esc(v)}">${esc(l)}</option>`)
    .join("")}</select>`;
}

// renderFilterBar builds the filter controls present in cfg. Supported
// keys: severity, confidence, category, host, user, process (booleans),
// technique/rule (arrays to populate a dropdown), collection (the
// case's collections, only rendered when there's more than one), and
// timeRange (boolean).
function renderFilterBar(prefix, cfg) {
  const parts = [];
  if (cfg.severity) {
    parts.push(
      filterSelect(prefix, "severity", "All severities", [
        ["critical", "Critical"],
        ["high", "High"],
        ["medium", "Medium"],
        ["low", "Low"],
      ])
    );
  }
  if (cfg.confidence) {
    parts.push(
      filterSelect(prefix, "confidence", "All confidence", [
        ["high", "High"],
        ["medium", "Medium"],
        ["low", "Low"],
      ])
    );
  }
  if (cfg.category) {
    parts.push(filterSelect(prefix, "category", "All categories", Object.entries(EVENT_CATEGORY_LABELS)));
  }
  if (cfg.host) parts.push(`<input type="text" id="${prefix}-f-host" class="filter-input" placeholder="Host" />`);
  if (cfg.user) parts.push(`<input type="text" id="${prefix}-f-user" class="filter-input" placeholder="User" />`);
  if (cfg.process) parts.push(`<input type="text" id="${prefix}-f-process" class="filter-input" placeholder="Process" />`);
  if (cfg.technique && cfg.technique.length) {
    parts.push(filterSelect(prefix, "technique", "All ATT&CK techniques", cfg.technique.map((t) => [t, t])));
  }
  if (cfg.rule && cfg.rule.length) {
    parts.push(filterSelect(prefix, "rule", "All rules", cfg.rule.map((r) => [r.id, r.title])));
  }
  if (cfg.collection && cfg.collection.length > 1) {
    parts.push(filterSelect(prefix, "collection", "All collections", cfg.collection.map((c, i) => [c.collection_id, `Collection #${i + 1}`])));
  }
  if (cfg.timeRange) {
    parts.push(`<input type="datetime-local" id="${prefix}-f-from" class="filter-input" title="From (UTC)" />`);
    parts.push(`<input type="datetime-local" id="${prefix}-f-to" class="filter-input" title="To (UTC)" />`);
  }
  parts.push(`<button type="button" class="secondary small" id="${prefix}-f-clear">Clear filters</button>`);
  return `<div class="filter-bar" id="${prefix}-filter-bar">${parts.join("")}</div>`;
}

function wireFilterBar(prefix, onChange) {
  const bar = document.getElementById(`${prefix}-filter-bar`);
  bar.querySelectorAll("select").forEach((el) => el.addEventListener("change", onChange));
  bar.querySelectorAll('input[type="text"]').forEach((el) => el.addEventListener("input", onChange));
  bar.querySelectorAll('input[type="datetime-local"]').forEach((el) => el.addEventListener("change", onChange));
  const clearBtn = document.getElementById(`${prefix}-f-clear`);
  clearBtn.addEventListener("click", () => {
    bar.querySelectorAll("select, input").forEach((el) => (el.value = ""));
    onChange();
  });
}

// readFilterBar reads whatever controls renderFilterBar actually
// rendered for prefix; a field this tab didn't configure simply reads as
// empty/falsy and its filter is a no-op. datetime-local values are
// parsed by the browser as local time -- comparisons below are against
// each event's own UTC timestamp, so filter bounds are intentionally
// entered in the browser's local time zone, same as the input control
// itself displays.
function readFilterBar(prefix) {
  const get = (field) => {
    const el = document.getElementById(`${prefix}-f-${field}`);
    return el ? el.value.trim() : "";
  };
  const from = get("from");
  const to = get("to");
  return {
    severity: get("severity"),
    confidence: get("confidence"),
    category: get("category"),
    host: get("host").toLowerCase(),
    user: get("user").toLowerCase(),
    process: get("process").toLowerCase(),
    technique: get("technique"),
    rule: get("rule"),
    collection: get("collection"),
    from: from ? new Date(from) : null,
    to: to ? new Date(to) : null,
  };
}

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
    const health = await api("/healthz");
    connStatus.textContent = "connected";
    document.getElementById("lan-warning").classList.toggle("hidden", !health.lan_exposed);
  } catch (e) {
    connStatus.textContent = "disconnected";
  }
}

function route() {
  const hash = window.location.hash.replace(/^#/, "") || "/";
  // Checked before the general case-detail pattern below, since both
  // start with /cases/{id}/investigations -- this one requires a third
  // segment (the investigation ID).
  const invMatch = hash.match(/^\/cases\/([^/]+)\/investigations\/([^/]+)$/);
  if (invMatch) {
    renderInvestigationDetail(invMatch[1], invMatch[2]);
    return;
  }
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
      <div class="field">
        <label>Name</label>
        <div class="input-wrap">
          <input id="new-case-name" placeholder="e.g. WKSTN-042 Phishing Triage" />
          <span id="new-case-name-icon" class="input-error-icon hidden">!</span>
        </div>
        <div id="new-case-error"></div>
      </div>
      <div class="field"><label>Description</label><input id="new-case-desc" placeholder="optional" /></div>
      <div class="field-info-box">Case names must be unique (case-insensitive, trimmed of leading/trailing spaces).</div>
      <button id="create-case-btn">Create case</button>
    </div>
    <div class="panel">
      <div class="row between">
        <h2>Cases</h2>
        <div class="row">
          <button type="button" class="secondary small" id="case-select-all-btn">Select All</button>
          <button type="button" class="secondary small" id="case-clear-btn">Clear Selection</button>
        </div>
      </div>
      <div id="case-bulk-bar" class="hidden"></div>
      <div id="case-list"><p class="empty">Loading...</p></div>
    </div>
  `;

  const nameInput = document.getElementById("new-case-name");
  // Editing the name after a rejected submit invalidates whatever error
  // is showing (duplicate or otherwise) -- clear it immediately rather
  // than leaving a stale red border/message next to what the user is now
  // typing. Full revalidation still happens on the next submit.
  nameInput.addEventListener("input", clearNameFieldError);

  document.getElementById("create-case-btn").addEventListener("click", async () => {
    const name = nameInput.value.trim();
    const description = document.getElementById("new-case-desc").value.trim();
    clearNameFieldError();
    if (!name) {
      setNameFieldError(new Error("Name is required"));
      return;
    }
    try {
      const c = await api("/cases", { method: "POST", body: JSON.stringify({ name, description }) });
      window.location.hash = `#/cases/${c.id}`;
    } catch (e) {
      setNameFieldError(e);
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
      <div class="case-card-row">
        <input type="checkbox" class="case-checkbox" data-id="${esc(c.id)}" aria-label="Select case ${esc(c.name)}" />
        <a class="case-card" href="#/cases/${c.id}">
          <div class="row between">
            <strong>${esc(c.name)}</strong>
            ${statusBadge(c.status)}
          </div>
          <div class="muted small">${esc(c.description || "")}</div>
          <div class="muted small mono">${esc(c.id)} &middot; created ${fmtTime(c.created_at)}</div>
        </a>
      </div>`
      )
      .join("");
    wireCaseSelection();
  } catch (e) {
    document.getElementById("case-list").innerHTML = errorBox(e);
  }
}

// wireCaseSelection powers the case list's checkbox selection and bulk
// delete bar. The bar (with its Delete Selected count) is only ever
// injected into the DOM while at least one case is checked, per "bulk
// action bar appears only when items are selected."
function wireCaseSelection() {
  const checkboxes = () => Array.from(document.querySelectorAll(".case-checkbox"));
  const bulkBar = document.getElementById("case-bulk-bar");

  function update() {
    const selected = checkboxes()
      .filter((cb) => cb.checked)
      .map((cb) => cb.dataset.id);
    if (selected.length === 0) {
      bulkBar.classList.add("hidden");
      bulkBar.innerHTML = "";
      return;
    }
    bulkBar.classList.remove("hidden");
    bulkBar.innerHTML = `
      <div class="bulk-action-bar">
        <span>${selected.length} case(s) selected</span>
        <button type="button" class="danger" id="case-delete-selected-btn">Delete Selected (${selected.length})</button>
      </div>`;
    document.getElementById("case-delete-selected-btn").addEventListener("click", () => confirmAndDeleteCases(selected));
  }

  checkboxes().forEach((cb) => cb.addEventListener("change", update));
  document.getElementById("case-select-all-btn").addEventListener("click", () => {
    checkboxes().forEach((cb) => (cb.checked = true));
    update();
  });
  document.getElementById("case-clear-btn").addEventListener("click", () => {
    checkboxes().forEach((cb) => (cb.checked = false));
    update();
  });
}

// confirmAndDeleteCases requires explicit confirmation (never a silent
// destructive action -- see requirement 13) before permanently deleting
// one or more cases and everything associated with them. onSuccess
// defaults to reloading the current page (right for the case list, where
// "the current page" is still valid afterward); the case detail page
// passes its own onSuccess to navigate back to the list instead, since
// its own case no longer exists to reload.
async function confirmAndDeleteCases(ids, onSuccess) {
  const title = ids.length === 1 ? "Delete Case?" : `Delete ${ids.length} Cases?`;
  const detail =
    ids.length === 1
      ? "This will permanently delete this case and all associated evidence and analysis (events, observations, findings, correlations, ATT&CK mappings, and case files on disk)."
      : "This will permanently delete the selected cases and all associated evidence and analysis (events, observations, findings, correlations, ATT&CK mappings, and case files on disk).";
  if (!window.confirm(`${title}\n\n${detail}`)) return;
  try {
    if (ids.length === 1) {
      await api(`/cases/${ids[0]}`, { method: "DELETE" });
    } else {
      await api(`/cases`, { method: "DELETE", body: JSON.stringify({ case_ids: ids }) });
    }
    (onSuccess || (() => window.location.reload()))();
  } catch (e) {
    window.alert("Failed to delete: " + (e.message || e));
  }
}

// ---------------- Case detail ----------------

async function renderCaseDetail(caseId, tab) {
  app.innerHTML = `<p class="empty">Loading case...</p>`;
  let data, collections, findings, attackTechniques, investigations;
  try {
    [data, collections, findings, attackTechniques, investigations] = await Promise.all([
      api(`/cases/${caseId}`),
      api(`/cases/${caseId}/evidence`),
      api(`/cases/${caseId}/findings`).catch(() => []),
      api(`/cases/${caseId}/attack`).catch(() => []),
      api(`/cases/${caseId}/investigations`).catch(() => []),
    ]);
  } catch (e) {
    app.innerHTML = errorBox(e);
    return;
  }
  const c = data.case;
  const summary = data.summary;
  currentCollections = collections;
  // Evidence changed since the last successful analysis (imported or
  // deleted) but findings/correlations from that older analysis are still
  // what summary/findings/investigations below reflect -- shown on every
  // tab (not just the "Run analysis" panel down by Evidence Collections)
  // so a reviewer glancing at Findings/Investigations/ATT&CK can't mistake
  // stale numbers for current ones. See renderAnalysisAction's identical
  // condition, which additionally offers the "Re-run analysis" action.
  const staleAnalysis = c.status !== "analyzed" && (summary.findings > 0 || summary.correlations > 0);

  app.innerHTML = `
    <p><a href="#/">&larr; All cases</a></p>
    <div class="panel">
      <div class="row between">
        <div>
          <h1>${esc(c.name)}</h1>
          <div class="muted">${esc(c.description || "")}</div>
        </div>
        <div class="row">
          ${statusBadge(c.status)}
          <button type="button" class="secondary small" id="export-case-btn">Export &#9662;</button>
          <button type="button" class="danger small" id="delete-case-btn">Delete Case</button>
        </div>
      </div>
      <div class="muted small mono" style="margin-top:6px">${esc(c.id)}</div>

      <div class="row" style="margin-top:10px; gap:16px; flex-wrap:wrap">
        <div>
          <label class="muted small" for="case-status-select">Case status</label><br/>
          <select id="case-status-select" class="filter-input">
            ${["open", "investigating", "contained", "closed"].map((s) => `<option value="${s}" ${c.case_status === s ? "selected" : ""}>${s[0].toUpperCase() + s.slice(1)}</option>`).join("")}
          </select>
        </div>
        <div>
          <label class="muted small" for="case-priority-select">Priority</label><br/>
          <select id="case-priority-select" class="filter-input">
            ${["low", "medium", "high", "critical"].map((p) => `<option value="${p}" ${c.priority === p ? "selected" : ""}>${p[0].toUpperCase() + p.slice(1)}</option>`).join("")}
          </select>
        </div>
        <div>
          <span class="muted small">Created</span><br/>
          <span class="small">${esc(fmtTime(c.created_at))}</span>
        </div>
        <div>
          <span class="muted small">Last analyzed</span><br/>
          <span class="small">${c.analyzed_at ? esc(fmtTime(c.analyzed_at)) : "Never analyzed"}</span>
        </div>
      </div>
      <div id="case-metadata-error"></div>
      <div id="export-menu" class="hidden" style="margin-top:8px">
        <a class="secondary small" href="/api/cases/${caseId}/export" target="_blank" rel="noopener">Case JSON</a>
        <a class="secondary small" href="/api/cases/${caseId}/export/timeline.csv" target="_blank" rel="noopener">Timeline CSV</a>
        <a class="secondary small" href="/api/cases/${caseId}/export/findings.csv" target="_blank" rel="noopener">Findings CSV</a>
      </div>

      ${
        staleAnalysis
          ? `<div class="stale-banner" style="margin-top:12px">
        <strong>Evidence changed since last analysis</strong>
        <div>The findings, correlations, investigations, and ATT&amp;CK techniques shown below (on every tab) are from the analysis run at ${esc(fmtTime(c.analyzed_at))} and do not reflect evidence added or removed since. Re-run analysis (below, under Evidence Collections) before treating these as current.</div>
      </div>`
          : ""
      }

      <div class="summary-grid">
        <div class="stat"><div class="n">${summary.collections}</div><div class="l">Collections</div></div>
        <div class="stat"><div class="n">${summary.imported_source_files}</div><div class="l">Imported source files</div></div>
        <div class="stat"><div class="n">${summary.events}</div><div class="l">Events</div></div>
        <div class="stat"><div class="n">${summary.findings}</div><div class="l">Findings</div></div>
        <div class="stat"><div class="n">${summary.correlations}</div><div class="l">Correlations</div></div>
        <div class="stat"><div class="n">${summary.technique_count}</div><div class="l">ATT&amp;CK techniques</div></div>
        <div class="stat"><div class="n">${summary.investigations}</div><div class="l">Investigations</div></div>
      </div>
      <div class="row" style="margin-top:10px">
        ${severityBadge("critical")} ${summary.severity_counts.critical || 0}
        ${severityBadge("high")} ${summary.severity_counts.high || 0}
        ${severityBadge("medium")} ${summary.severity_counts.medium || 0}
        ${severityBadge("low")} ${summary.severity_counts.low || 0}
      </div>
      <div class="investigation-summary">${buildInvestigationSummary(c, summary, findings, attackTechniques)}</div>
    </div>

    <div class="panel">
      <h2>Analyst Notes &amp; Tags</h2>
      <p class="muted small">Free-text observations and labels an analyst adds -- never generated by Tracefall, never affecting the deterministic findings/investigations above.</p>
      <div id="case-notes"></div>
      <div id="case-tags"></div>
    </div>

    <div class="panel" id="investigations-panel">
      <div class="row between">
        <h2>Investigations</h2>
        ${investigations.length ? `<a class="small" href="#/cases/${caseId}/investigations">View all &rarr;</a>` : ""}
      </div>
      <div class="row" style="margin-top:2px; margin-bottom:10px">
        ${severityBadge("critical")} ${summary.investigation_severity_counts.critical || 0}
        ${severityBadge("high")} ${summary.investigation_severity_counts.high || 0}
        ${severityBadge("medium")} ${summary.investigation_severity_counts.medium || 0}
        ${severityBadge("low")} ${summary.investigation_severity_counts.low || 0}
      </div>
      ${renderInvestigationList(caseId, investigations.slice(0, 5))}
    </div>

    <div class="panel">
      <div class="row between">
        <h2>Evidence Collections</h2>
        <button id="add-evidence-btn">+ Add Evidence</button>
      </div>
      <div id="add-evidence-form" class="add-evidence-form hidden">
        <h3>Upload KAPE package</h3>
        <p class="muted small">Upload a ZIP archive of a KAPE triage collection. Tracefall safely extracts it and discovers every file inside (EvtxECmd/PECmd/RECmd CSV, Scheduled Task XML, and anything else) -- you choose which discovered files to import next.</p>
        <div class="row">
          <input type="file" id="upload-file" accept=".zip,application/zip" />
          <button id="upload-btn">Upload KAPE Package</button>
        </div>
        <div id="upload-error"></div>
        <div id="upload-progress"></div>

        <details style="margin-top:16px">
          <summary class="muted small" style="cursor:pointer">Advanced: ingest from a local path instead</summary>
          <p class="muted small">For local/dev use (e.g. the bundled synthetic dataset at <code>testdata/synthetic_case</code>) when the evidence is already on the machine running Tracefall.</p>
          <div class="row">
            <div style="flex:1"><input id="ingest-path" placeholder="/path/to/evidence" value="testdata/synthetic_case" /></div>
            <button id="ingest-btn" class="secondary">Discover</button>
          </div>
          <div id="ingest-error"></div>
          <div id="ingest-progress"></div>
        </details>
      </div>
      <div id="collections-list">${renderCollectionsList(caseId, collections)}</div>
    </div>

    <div class="panel" id="analysis-panel">${renderAnalysisAction(c, summary)}</div>

    <div class="tabs">
      ${tabLink(caseId, "investigations", "Investigations", tab)}
      ${tabLink(caseId, "summary", "Timeline", tab)}
      ${tabLink(caseId, "findings", "Findings", tab)}
      ${tabLink(caseId, "attack", "ATT&CK", tab)}
      ${tabLink(caseId, "correlations", "Activity Chains", tab)}
      ${tabLink(caseId, "evidence", "Evidence", tab)}
      ${tabLink(caseId, "audit", "Audit History", tab)}
    </div>
    <div id="tab-content" class="panel"><p class="empty">Loading...</p></div>
  `;

  wireEvidenceHeader(caseId);
  wireAnalysisAction(caseId);
  wireCollectionIntegrity(caseId, document.getElementById("collections-list"));
  wireCaseMetadataControls(caseId);
  renderNotesSection(document.getElementById("case-notes"), caseId, "case", caseId);
  renderTagsSection(document.getElementById("case-tags"), caseId, "case", caseId);
  document.getElementById("delete-case-btn").addEventListener("click", () =>
    confirmAndDeleteCases([caseId], () => {
      window.location.hash = "#/";
    })
  );

  const content = document.getElementById("tab-content");
  try {
    switch (tab) {
      case "investigations":
        await renderInvestigationsTab(content, caseId);
        break;
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
      case "audit":
        await renderAuditTab(content, caseId);
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

function renderCollectionsList(caseId, collections) {
  if (collections.length === 0) {
    return `<p class="empty">No evidence yet. Click "+ Add Evidence" to upload a KAPE package.</p>`;
  }
  return collections
    .map((col, i) => {
      const statusCls = col.ingestion_status === "failed" ? "critical" : col.ingestion_status === "pending" ? "medium" : "status analyzed";
      return `
      <div class="collection-card" data-collection="${esc(col.collection_id)}" tabindex="0">
        <div class="row between">
          <strong>Collection #${i + 1}</strong>
          <span class="badge ${statusCls}">${esc(col.ingestion_status)}</span>
        </div>
        <div class="muted small">${esc(SOURCE_TYPE_LABELS[col.source_type] || col.source_type)}${col.original_filename ? " &middot; " + esc(col.original_filename) : ""}</div>
        <div class="muted small">${esc(fmtDate(col.created_at))}</div>
        <div class="small" style="margin-top:4px">${col.file_count} file(s) discovered &middot; ${col.imported_file_count} imported &middot; ${col.parsed_event_count} event(s)${col.unsupported_file_count ? ` &middot; ${col.unsupported_file_count} unsupported` : ""}</div>
        <div class="muted small" style="margin-top:4px; cursor:pointer">Evidence integrity &amp; metadata &#9662;</div>
        <div class="collection-integrity-detail"></div>
      </div>`;
    })
    .join("");
}

// wireCollectionIntegrity makes each collection card's "Evidence
// integrity & metadata" line expand in place -- archive hash, hosts
// observed, time range, and parser coverage, all computed at read time
// by Service.CollectionDetail (Phase 6 section 4), never invented: a
// field that's genuinely unknown (e.g. no events imported yet) renders
// as "Unknown", never a guess.
function wireCollectionIntegrity(caseId, root) {
  root.querySelectorAll(".collection-card").forEach((card) => {
    card.addEventListener("click", async () => {
      const detail = card.querySelector(".collection-integrity-detail");
      const open = detail.classList.contains("open");
      if (open) {
        detail.classList.remove("open");
        return;
      }
      detail.classList.add("open");
      if (detail.dataset.loaded) return;
      detail.innerHTML = `<p class="empty">Loading...</p>`;
      try {
        const cd = await api(`/cases/${caseId}/evidence/${card.dataset.collection}`);
        detail.innerHTML = `
          <div class="integrity-grid">
            <div><span class="muted small">Collection ID</span><div class="mono small">${esc(cd.collection_id)}</div></div>
            <div><span class="muted small">Evidence package hash (SHA-256)</span><div class="mono small">${cd.archive_hash ? esc(cd.archive_hash) : "Unknown"}</div></div>
            <div><span class="muted small">Hosts observed</span><div class="small">${cd.hosts_observed && cd.hosts_observed.length ? esc(cd.hosts_observed.join(", ")) : "Unknown"}</div></div>
            <div><span class="muted small">Event time range</span><div class="small">${cd.earliest_event ? esc(fmtTime(cd.earliest_event)) + " &rarr; " + esc(fmtTime(cd.latest_event)) : "Unknown"}</div></div>
          </div>
          <div class="muted small" style="margin-top:8px">Parser coverage</div>
          ${
            cd.parser_coverage && cd.parser_coverage.length
              ? `<div class="table-wrap"><table><thead><tr><th>Parser</th><th>Artifact type</th><th>Files</th><th>Events</th></tr></thead><tbody>
                  ${cd.parser_coverage.map((p) => `<tr><td class="mono small">${esc(p.parser)}</td><td class="small">${esc(p.artifact_type)}</td><td class="small">${p.file_count}</td><td class="small">${p.event_count}</td></tr>`).join("")}
                 </tbody></table></div>`
              : `<p class="empty">Unknown -- no files imported from this collection yet.</p>`
          }
          <div class="muted small" style="margin-top:8px">Per-file integrity</div>
          <div class="table-wrap"><table>
            <thead><tr><th>Filename</th><th>SHA-256</th><th>Size</th><th>Discovered</th><th>Imported</th><th>Status</th><th>Events</th></tr></thead>
            <tbody>
              ${cd.source_files
                .map(
                  (sf) => `<tr>
                <td class="mono small">${esc(sf.original_filename)}</td>
                <td class="mono small">${esc(sf.sha256)}</td>
                <td class="small">${fmtBytes(sf.size_bytes)}</td>
                <td class="small">${esc(fmtTime(sf.discovered_at))}</td>
                <td class="small">${sf.imported_at ? esc(fmtTime(sf.imported_at)) : "-"}</td>
                <td class="small">${esc(sf.import_status)}</td>
                <td class="small">${sf.event_count || "-"}</td>
              </tr>`
                )
                .join("")}
            </tbody>
          </table></div>
        `;
        detail.dataset.loaded = "1";
      } catch (e) {
        detail.innerHTML = errorBox(e);
      }
    });
  });
}

// ---------------- Phase 6: analyst workflow (case metadata, notes, tags, audit) ----------------
//
// Everything in this section is analyst-entered workflow state, never
// forensic evidence, and never able to alter a Finding/Investigation's
// own deterministic Severity/Confidence -- see docs/analyst-workflow.md.
// The dashboard keeps this visually distinct from engine output: these
// sections are always labeled "Analyst..." and never share a badge/color
// with severity/confidence badges.

function wireCaseMetadataControls(caseId) {
  const statusSel = document.getElementById("case-status-select");
  const prioritySel = document.getElementById("case-priority-select");
  const errBox = document.getElementById("case-metadata-error");
  const exportBtn = document.getElementById("export-case-btn");
  const exportMenu = document.getElementById("export-menu");

  const update = async (patch) => {
    errBox.innerHTML = "";
    try {
      await api(`/cases/${caseId}`, { method: "PATCH", body: JSON.stringify(patch) });
    } catch (e) {
      errBox.innerHTML = errorBox(e);
    }
  };
  statusSel.addEventListener("change", () => update({ case_status: statusSel.value }));
  prioritySel.addEventListener("change", () => update({ priority: prioritySel.value }));

  exportBtn.addEventListener("click", () => exportMenu.classList.toggle("hidden"));
}

// renderNotesSection is reused for every target type Phase 6 supports
// (case, collection, source file, event, finding, investigation) --
// container gets a small add-note form plus the existing notes list,
// each with an inline delete control. Deleting a note here removes only
// the note itself; it never touches the target it's attached to (see
// model.Note's doc comment on why deleting a note's target does NOT
// delete the note, and vice versa here -- the two lifecycles are
// independent in both directions).
async function renderNotesSection(container, caseId, targetType, targetId) {
  if (!container) return;
  container.innerHTML = `<p class="empty small">Loading notes...</p>`;
  let notes;
  try {
    notes = await api(`/cases/${caseId}/notes?target_type=${encodeURIComponent(targetType)}&target_id=${encodeURIComponent(targetId)}`);
  } catch (e) {
    container.innerHTML = errorBox(e);
    return;
  }
  container.innerHTML = `
    <h3 class="small" style="margin:10px 0 4px">Notes (${notes.length})</h3>
    <div class="notes-list">
      ${notes
        .map(
          (n) => `<div class="note-row" data-id="${esc(n.id)}">
            <div class="small">${esc(n.note)}</div>
            <div class="muted small">${esc(fmtTime(n.updated_at))} <button type="button" class="secondary small delete-note-btn" data-id="${esc(n.id)}">Delete</button></div>
          </div>`
        )
        .join("") || `<p class="muted small">No notes yet.</p>`}
    </div>
    <div class="row" style="margin-top:6px">
      <input type="text" class="note-input" placeholder="Add a note..." style="flex:1" />
      <button type="button" class="secondary small add-note-btn">Add Note</button>
    </div>
    <div class="note-error"></div>
  `;
  container.querySelectorAll(".delete-note-btn").forEach((btn) =>
    btn.addEventListener("click", async () => {
      await api(`/notes/${btn.dataset.id}`, { method: "DELETE" });
      renderNotesSection(container, caseId, targetType, targetId);
    })
  );
  const addBtn = container.querySelector(".add-note-btn");
  const input = container.querySelector(".note-input");
  addBtn.addEventListener("click", async () => {
    const text = input.value.trim();
    if (!text) return;
    try {
      await api(`/cases/${caseId}/notes`, { method: "POST", body: JSON.stringify({ target_type: targetType, target_id: targetId, note: text }) });
      renderNotesSection(container, caseId, targetType, targetId);
    } catch (e) {
      container.querySelector(".note-error").innerHTML = errorBox(e);
    }
  });
}

// renderTagsSection: quick-add from model.CommonTags (mirrored here as
// COMMON_TAGS) or a free-text tag, plus removable chips for existing tags.
const COMMON_TAGS = ["phishing", "persistence", "credential-access", "lateral-movement", "suspicious", "false-positive", "requires-review"];

async function renderTagsSection(container, caseId, targetType, targetId) {
  if (!container) return;
  container.innerHTML = `<p class="empty small">Loading tags...</p>`;
  let tags;
  try {
    tags = await api(`/cases/${caseId}/tags?target_type=${encodeURIComponent(targetType)}&target_id=${encodeURIComponent(targetId)}`);
  } catch (e) {
    container.innerHTML = errorBox(e);
    return;
  }
  const existing = new Set(tags.map((t) => t.tag));
  container.innerHTML = `
    <h3 class="small" style="margin:10px 0 4px">Tags</h3>
    <div class="row" style="flex-wrap:wrap; gap:6px">
      ${tags.map((t) => `<span class="badge conf tag-chip" data-tag="${esc(t.tag)}">${esc(t.tag)} &times;</span>`).join("")}
    </div>
    <div class="row" style="margin-top:6px; flex-wrap:wrap; gap:6px">
      ${COMMON_TAGS.filter((t) => !existing.has(t))
        .map((t) => `<button type="button" class="secondary small add-common-tag-btn" data-tag="${esc(t)}">+ ${esc(t)}</button>`)
        .join("")}
    </div>
    <div class="row" style="margin-top:6px">
      <input type="text" class="tag-input" placeholder="custom tag..." style="flex:1" />
      <button type="button" class="secondary small add-custom-tag-btn">Add Tag</button>
    </div>
  `;
  const addTag = async (tag) => {
    if (!tag) return;
    await api(`/cases/${caseId}/tags`, { method: "POST", body: JSON.stringify({ target_type: targetType, target_id: targetId, tag }) });
    renderTagsSection(container, caseId, targetType, targetId);
  };
  container.querySelectorAll(".tag-chip").forEach((chip) =>
    chip.addEventListener("click", async () => {
      await api(`/cases/${caseId}/tags`, { method: "DELETE", body: JSON.stringify({ target_type: targetType, target_id: targetId, tag: chip.dataset.tag }) });
      renderTagsSection(container, caseId, targetType, targetId);
    })
  );
  container.querySelectorAll(".add-common-tag-btn").forEach((btn) => btn.addEventListener("click", () => addTag(btn.dataset.tag)));
  const customInput = container.querySelector(".tag-input");
  container.querySelector(".add-custom-tag-btn").addEventListener("click", () => addTag(customInput.value.trim().toLowerCase()));
}

// renderStatusControl renders a small "Analyst Assessment" box (status
// select + note field) for one finding or investigation -- deliberately
// a visually separate box from the engine's severity/confidence badges
// it sits next to, per Phase 6's "make the distinction... visually
// obvious" requirement.
function renderStatusControl(caseId, kind, targetId, current) {
  const statuses = kind === "finding" ? FINDING_STATUSES : INVESTIGATION_STATUSES;
  const box = h(`
    <div class="analyst-assessment">
      <div class="muted small" style="text-transform:uppercase; letter-spacing:.03em">Analyst Assessment</div>
      <div class="row" style="margin-top:4px; gap:8px">
        <select class="filter-input status-select">
          ${statuses.map((s) => `<option value="${s}" ${current && current.status === s ? "selected" : ""}>${STATUS_LABELS[s] || s}</option>`).join("")}
        </select>
      </div>
      <input type="text" class="analyst-note-input small" placeholder="Reason (optional)" value="${esc((current && current.note) || "")}" style="margin-top:6px; width:100%" />
      <div class="analyst-status-saved muted small" style="display:none; margin-top:4px">Saved.</div>
    </div>
  `);
  const select = box.querySelector(".status-select");
  const noteInput = box.querySelector(".analyst-note-input");
  const saved = box.querySelector(".analyst-status-saved");
  const save = async () => {
    const endpoint = kind === "finding" ? `/cases/${caseId}/findings/${targetId}/status` : `/cases/${caseId}/investigations/${targetId}/status`;
    await api(endpoint, { method: "PATCH", body: JSON.stringify({ status: select.value, note: noteInput.value }) });
    saved.style.display = "block";
    setTimeout(() => (saved.style.display = "none"), 1500);
  };
  select.addEventListener("change", save);
  noteInput.addEventListener("blur", save);
  box.addEventListener("click", (ev) => ev.stopPropagation());
  return box;
}
const FINDING_STATUSES = ["new", "reviewing", "confirmed", "dismissed", "false_positive"];
const INVESTIGATION_STATUSES = ["open", "investigating", "confirmed", "dismissed", "closed"];
const STATUS_LABELS = {
  new: "New",
  reviewing: "Reviewing",
  confirmed: "Confirmed",
  dismissed: "Dismissed",
  false_positive: "False Positive",
  open: "Open",
  investigating: "Investigating",
  closed: "Closed",
};

async function renderAuditTab(content, caseId) {
  content.innerHTML = `<p class="empty">Loading audit history...</p>`;
  const events = await api(`/cases/${caseId}/audit`);
  if (events.length === 0) {
    content.innerHTML = `<p class="empty">No audit events yet.</p>`;
    return;
  }
  content.innerHTML = `
    <h2>Audit History (${events.length})</h2>
    <p class="muted small">Actor is always "local-user" -- Tracefall has no authentication yet, so this is not an authoritative identity. See docs/analyst-workflow.md.</p>
    <div class="table-wrap"><table>
      <thead><tr><th>Time (UTC)</th><th>Action</th><th>Actor</th><th>Target</th><th>Summary</th></tr></thead>
      <tbody>
        ${events
          .map(
            (e) => `<tr>
          <td class="mono small">${esc(fmtTime(e.timestamp))}</td>
          <td class="small">${esc(e.action)}</td>
          <td class="mono small">${esc(e.actor)}</td>
          <td class="mono small">${esc(e.target_type || "")}</td>
          <td class="small">${esc(e.summary)}</td>
        </tr>`
          )
          .join("")}
      </tbody>
    </table></div>
  `;
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
      const disc = await apiUpload(`/cases/${caseId}/evidence`, file);
      progress.innerHTML = renderDiscoveryResults(disc);
      wireDiscoverySelection(progress, caseId, disc.collection.collection_id);
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
    const progress = document.getElementById("ingest-progress");
    errBox.innerHTML = "";
    progress.innerHTML = "";
    ingestBtn.disabled = true;
    ingestBtn.textContent = "Discovering...";
    try {
      const disc = await api(`/cases/${caseId}/ingest`, { method: "POST", body: JSON.stringify({ path }) });
      progress.innerHTML = renderDiscoveryResults(disc);
      wireDiscoverySelection(progress, caseId, disc.collection.collection_id);
    } catch (e) {
      errBox.innerHTML = errorBox(e);
    } finally {
      ingestBtn.disabled = false;
      ingestBtn.textContent = "Discover";
    }
  });
}

// uploadStep renders one line of the upload progress list. done=true
// shows a check mark instead of a spinner glyph.
function uploadStep(label, done) {
  return `<div class="row small" style="margin:4px 0"><span>${done ? "&check;" : "&hellip;"}</span><span>${esc(label)}</span></div>`;
}

// SOURCE_FILE_STATUS_LABELS maps internal/model.SourceFile* import
// status constants to the short badge text shown next to a discovered
// (not-yet-selectable) file -- see rowForDiscoveredFile.
const SOURCE_FILE_STATUS_LABELS = {
  unsupported: "unsupported",
  duplicate: "duplicate in this batch",
  imported: "imported",
  failed: "failed to parse",
};

// renderDiscoveryResults is the FILE SELECTION SCREEN: every file
// Tracefall just discovered (upload or local-path), with a checkbox per
// selectable (supported, non-duplicate) file, Select All / Select
// Supported / Clear All controls, and an Import Selected action. Nothing
// here has been parsed yet -- only the files actually selected here
// become evidence, via wireDiscoverySelection's import call.
function renderDiscoveryResults(disc) {
  const rows = (disc.source_files || []).map(rowForDiscoveredFile).join("");
  return `
    <div class="panel" style="background:var(--bg-panel-2); margin-top:12px; margin-bottom:0">
      <h3>Select evidence to import</h3>
      <p class="small">${disc.discovered_count} file(s) discovered &middot; ${disc.supported_count} supported${
    disc.duplicate_count ? ` (${disc.duplicate_count} duplicate within this package)` : ""
  }</p>
      <p class="muted small">Only selected files will be parsed and imported as evidence. Unsupported files are listed but cannot be selected.</p>
      <div class="row" style="margin:10px 0">
        <button type="button" class="secondary small" id="discover-select-all-btn">Select All</button>
        <button type="button" class="secondary small" id="discover-select-supported-btn">Select Supported</button>
        <button type="button" class="secondary small" id="discover-clear-btn">Clear All</button>
      </div>
      <div class="table-wrap"><table>
        <thead><tr><th></th><th>Filename</th><th>Path</th><th>Artifact type</th><th>Size</th><th>SHA-256</th><th></th></tr></thead>
        <tbody>${rows}</tbody>
      </table></div>
      <div class="row" style="margin-top:12px; align-items:center; gap:12px">
        <button id="import-selected-btn" disabled>Import Selected (<span id="import-selected-count">0</span>)</button>
      </div>
      <div id="import-error"></div>
      <div id="import-result"></div>
    </div>`;
}

function rowForDiscoveredFile(f) {
  const selectable = f.import_status === "discovered";
  const statusBadgeHTML = selectable ? "" : `<span class="badge status">${esc(SOURCE_FILE_STATUS_LABELS[f.import_status] || f.import_status)}</span>`;
  return `<tr class="${selectable ? "" : "muted"}">
    <td><input type="checkbox" class="discover-file-checkbox" data-id="${esc(f.id)}" ${selectable ? "checked" : "disabled"} /></td>
    <td class="mono small">${esc(f.original_filename)}</td>
    <td class="mono small">${esc(f.path)}</td>
    <td class="small">${esc(f.artifact_type || "-")}</td>
    <td class="small">${fmtBytes(f.size_bytes)}</td>
    <td class="mono small">${f.sha256 ? esc(f.sha256.slice(0, 12)) + "&hellip;" : "-"}</td>
    <td class="small">${statusBadgeHTML}</td>
  </tr>`;
}

// wireDiscoverySelection powers the file-selection screen's checkboxes,
// Select All/Supported/Clear controls, and the Import Selected action --
// scoped to `container` (not the whole document) so the upload and
// local-path forms' selection screens never interfere with each other if
// both happen to have been used.
function wireDiscoverySelection(container, caseId, collectionId) {
  const checkboxes = () => Array.from(container.querySelectorAll(".discover-file-checkbox"));
  const importBtn = container.querySelector("#import-selected-btn");
  const countSpan = container.querySelector("#import-selected-count");

  function updateCount() {
    const n = checkboxes().filter((cb) => cb.checked).length;
    countSpan.textContent = String(n);
    importBtn.disabled = n === 0;
  }
  checkboxes().forEach((cb) => cb.addEventListener("change", updateCount));
  container.querySelector("#discover-select-all-btn").addEventListener("click", () => {
    checkboxes().forEach((cb) => {
      if (!cb.disabled) cb.checked = true;
    });
    updateCount();
  });
  container.querySelector("#discover-select-supported-btn").addEventListener("click", () => {
    checkboxes().forEach((cb) => (cb.checked = !cb.disabled));
    updateCount();
  });
  container.querySelector("#discover-clear-btn").addEventListener("click", () => {
    checkboxes().forEach((cb) => (cb.checked = false));
    updateCount();
  });
  updateCount();

  importBtn.addEventListener("click", async () => {
    const ids = checkboxes()
      .filter((cb) => cb.checked)
      .map((cb) => cb.dataset.id);
    const errBox = container.querySelector("#import-error");
    errBox.innerHTML = "";
    importBtn.disabled = true;
    const original = importBtn.textContent;
    importBtn.textContent = "Importing...";
    try {
      const res = await api(`/cases/${caseId}/evidence/${collectionId}/import`, {
        method: "POST",
        body: JSON.stringify({ source_file_ids: ids }),
      });
      container.querySelector("#import-result").innerHTML = renderImportResults(res);
      container.querySelector("#import-continue-btn").addEventListener("click", () => window.location.reload());
    } catch (e) {
      errBox.innerHTML = errorBox(e);
      importBtn.disabled = false;
      importBtn.textContent = original;
    }
  });
}

// renderImportResults shows what the import endpoint actually parsed --
// how many files were imported, how many events (new vs. already known
// from another collection), plus a button to continue into the case
// dashboard.
function renderImportResults(res) {
  return `
    <div class="panel" style="background:var(--bg-panel); margin-top:12px; margin-bottom:0">
      <h3>Import complete</h3>
      ${uploadStep(`${res.imported.length} file(s) imported`, true)}
      ${uploadStep(`${res.event_count} event(s) parsed (${res.new_event_count} new, ${res.duplicate_event_count} already known from another collection)`, true)}
      ${res.skipped && res.skipped.length ? `<div class="small muted">${res.skipped.length} file(s) skipped (already imported/unsupported/duplicate)</div>` : ""}
      ${res.errors && res.errors.length ? `<div class="small" style="color:var(--high)">${res.errors.length} file(s) had parse errors</div>` : ""}
      <div style="margin-top:12px">
        <button id="import-continue-btn">Continue to case dashboard</button>
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
      <p class="muted small">Analysis reflects all ${summary.collections} collection(s) currently in this case. Adding or removing evidence will mark this stale.</p>
      <button id="analyze-btn" class="secondary">Re-run analysis</button>
      <div id="analyze-error"></div>`;
  }
  // summary.findings/correlations > 0 while status isn't "analyzed" means
  // analysis ran at some point but evidence has changed (imported or
  // deleted) since -- the full "results below are stale" warning is
  // rendered once, at the top of the page (see renderCaseDetail's
  // staleAnalysis banner, visible on every tab); this is just the
  // in-context call to action next to the button that clears it.
  const stale = summary.findings > 0 || summary.correlations > 0;
  return `
    <p class="muted small">${stale ? "Evidence changed since the last analysis (see banner above). Re-run" : "Run"} the deterministic detection and correlation engines across all ${summary.collections} collection(s) in this case.</p>
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
//
// The primary investigation view: every event across every collection in
// the case, chronological, cross-referenced client-side against findings
// (buildEventFindingIndex) and correlations (buildEventCorrelationIndex)
// -- both already fetched in full for their own tabs, so joining them
// here costs no extra requests. Filtering is entirely client-side over
// this one fetch (see renderTimelineTab's doc note on why that beats
// round-tripping to the server for a dataset this size).

async function renderTimelineTab(content, caseId, collections) {
  content.innerHTML = `<p class="empty">Loading timeline...</p>`;
  const [events, findings, correlations] = await Promise.all([
    api(`/cases/${caseId}/timeline`),
    api(`/cases/${caseId}/findings`).catch(() => []),
    api(`/cases/${caseId}/correlations`).catch(() => []),
  ]);
  const eventFindingIdx = buildEventFindingIndex(findings);
  const eventCorrIdx = buildEventCorrelationIndex(correlations);

  if (events.length === 0) {
    content.innerHTML = `<p class="empty">No events yet. Add evidence first.</p>`;
    return;
  }

  const techniqueIds = Array.from(new Set(findings.flatMap((f) => f.attack_techniques || []))).sort();
  content.innerHTML = `
    <div class="row between">
      <h2 id="timeline-heading">Unified timeline (${events.length} events)</h2>
    </div>
    ${renderFilterBar("tl", {
      severity: true,
      category: true,
      host: true,
      user: true,
      process: true,
      technique: techniqueIds,
      collection: collections,
      timeRange: true,
    })}
    <div id="timeline-body"></div>
  `;

  const rerender = () => renderTimelineRows(caseId, events, eventFindingIdx, eventCorrIdx, readFilterBar("tl"));
  wireFilterBar("tl", rerender);
  rerender();
}

function renderTimelineRows(caseId, events, eventFindingIdx, eventCorrIdx, filters) {
  const body = document.getElementById("timeline-body");
  const heading = document.getElementById("timeline-heading");
  const filtered = events.filter((e) => eventMatchesFilters(e, filters, eventFindingIdx));
  heading.textContent = `Unified timeline (${filtered.length} of ${events.length} events)`;

  if (filtered.length === 0) {
    body.innerHTML = `<p class="empty">No events match the current filters.</p>`;
    return;
  }
  body.innerHTML = `
    <div class="table-wrap"><table>
      <thead><tr>
        <th>Time (UTC)</th><th>Category</th><th>Type</th><th>Host</th><th>User</th>
        <th>Process</th><th>Parent</th><th>PID</th><th>PPID</th><th>Detail</th>
        <th>Finding</th><th>ATT&amp;CK</th><th>Source</th><th>Collection</th>
      </tr></thead>
      <tbody>
        ${filtered.map((e) => rowForEvent(e, eventFindingIdx[e.id], eventCorrIdx[e.id])).join("")}
      </tbody>
    </table></div>
  `;
  wireDetailCells(body);
  wireTimelineRowClicks(caseId, body);
}

// eventMatchesFilters is shared predicate logic: severity/technique are
// resolved through the event's associated findings (an event has no
// severity of its own -- see model.Event's doc comment -- a detection
// verdict belongs to the Finding it supports), everything else is a
// direct field on the event.
function eventMatchesFilters(e, f, eventFindingIdx) {
  if (f.collection && e.collection_id !== f.collection) return false;
  if (f.category && eventCategory(e) !== f.category) return false;
  if (f.host && !(e.host || "").toLowerCase().includes(f.host)) return false;
  if (f.user && !(e.user || "").toLowerCase().includes(f.user)) return false;
  if (f.process && !(e.process_name || "").toLowerCase().includes(f.process)) return false;
  if (f.from && new Date(e.timestamp) < f.from) return false;
  if (f.to && new Date(e.timestamp) > f.to) return false;

  if (f.severity || f.technique) {
    const relatedFindings = eventFindingIdx[e.id] || [];
    if (f.severity && !relatedFindings.some((rf) => rf.severity === f.severity)) return false;
    if (f.technique && !relatedFindings.some((rf) => (rf.attack_techniques || []).includes(f.technique))) return false;
  }
  return true;
}

// rowForEvent renders one timeline row. relatedFindings/relatedCorrs (may
// be undefined) are this event's cross-referenced Finding/Correlation
// rows, resolved once for the whole tab via buildEventFindingIndex /
// buildEventCorrelationIndex -- their presence is what visually
// distinguishes a plain observed event from one that's part of a
// detection or a reconstructed activity chain.
function rowForEvent(e, relatedFindings, relatedCorrs) {
  const sev = maxSeverity((relatedFindings || []).map((f) => f.severity));
  const techniques = techniquesForFindings(relatedFindings || []);
  const hasChain = (relatedCorrs || []).some((c) => c.correlation_type === "activity_chain");
  return `<tr class="timeline-row" data-event="${esc(e.id)}" tabindex="0">
    <td class="mono small">${esc(fmtTime(e.timestamp))}</td>
    <td class="small">${categoryBadge(eventCategory(e))}</td>
    <td class="small">${esc(e.event_type)}${hasChain ? ' <span class="badge conf chain-badge" title="Part of a reconstructed activity chain">chain</span>' : ""}</td>
    <td class="mono small">${esc(e.host)}</td>
    <td class="mono small">${esc(e.user)}</td>
    <td class="mono small">${esc(e.process_name)}</td>
    <td class="mono small">${esc(e.parent_process)}</td>
    <td class="mono small">${e.pid || ""}</td>
    <td class="mono small">${e.ppid || ""}</td>
    <td class="mono small detail-td">${detailCell(eventDetailValue(e))}</td>
    <td class="small">${sev ? severityBadge(sev) : ""}</td>
    <td class="small">${techChips(techniques)}</td>
    <td class="small">${esc(e.artifact_type)}</td>
    <td class="small">${collectionBadge(e.collection_id)}</td>
  </tr>
  <tr class="raw-row" data-for="${esc(e.id)}" style="display:none"><td colspan="14"><div class="evidence-box"></div></td></tr>`;
}

// wireTimelineRowClicks makes every timeline row open its own
// detail/provenance inline (Timeline event -> normalized event ->
// source file -> original raw record) -- the trace-back this phase's
// spec requires, reusing the exact same drill-down component the
// Findings tab uses (see loadProvenanceInto).
function wireTimelineRowClicks(caseId, root) {
  root.querySelectorAll(".timeline-row").forEach((row) => {
    row.addEventListener("click", (ev) => {
      if (ev.target.closest(".detail-toggle-btn") || ev.target.closest(".detail-copy-btn")) return;
      const eventId = row.dataset.event;
      const raw = root.querySelector(`.raw-row[data-for="${eventId}"]`);
      const box = raw.querySelector(".evidence-box");
      const showing = raw.style.display !== "none";
      raw.style.display = showing ? "none" : "table-row";
      row.classList.toggle("selected", !showing);
      if (!showing) loadProvenanceInto(caseId, eventId, box);
    });
    row.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter" || ev.key === " ") {
        ev.preventDefault();
        row.click();
      }
    });
  });
}

// loadProvenanceInto fetches an event's full provenance (Event ->
// RawEvidence -> SourceFile -> every collection that observed it) and
// renders it into box, the shared drill-down box used by the Timeline,
// Findings, and Activity Chain views alike. Cached on the element so
// repeat toggles don't refetch.
async function loadProvenanceInto(caseId, eventId, box) {
  if (box.dataset.loaded) return;
  box.textContent = "Loading...";
  try {
    const prov = await api(`/cases/${caseId}/events/${eventId}`);
    box.textContent = renderProvenanceText(prov);
    box.dataset.loaded = "1";
  } catch (e) {
    box.textContent = "Error loading evidence: " + (e.message || e);
  }
}

function renderProvenanceText(prov) {
  const observedIn = (prov.observations || []).map((o) => collectionLabel(o.collection_id));
  const multi = observedIn.length > 1 ? " (independently observed via more than one source file)" : "";
  return (
    `event type: ${prov.event.event_type}\n` +
    `source file: ${prov.source_file.path}\n` +
    `parser: ${prov.source_file.parser}\n` +
    `source reference: ${prov.event.source_reference}\n` +
    `observed in: ${observedIn.join(", ")}${multi}\n\n` +
    `raw record:\n${prov.raw_evidence.raw}`
  );
}

// ---------------- Findings tab ----------------

// buildStatusIndex maps target_id -> AnalystStatus, from the flat list
// GET .../analyst-status returns -- the same client-side-join pattern
// buildEventFindingIndex etc. already use for other cross-references.
function buildStatusIndex(statuses) {
  const idx = {};
  (statuses || []).forEach((a) => (idx[a.target_id] = a));
  return idx;
}

async function renderFindingsTab(content, caseId) {
  content.innerHTML = `<p class="empty">Loading findings...</p>`;
  const [findings, correlations, timeline, statuses] = await Promise.all([
    api(`/cases/${caseId}/findings`),
    api(`/cases/${caseId}/correlations`).catch(() => []),
    api(`/cases/${caseId}/timeline`).catch(() => []),
    api(`/cases/${caseId}/analyst-status`).catch(() => []),
  ]);
  const statusIdx = buildStatusIndex(statuses);
  if (findings.length === 0) {
    content.innerHTML = `<p class="empty">No findings yet. Run analysis first.</p>`;
    return;
  }
  const eventsById = Object.fromEntries(timeline.map((e) => [e.id, e]));
  const eventCorrIdx = buildEventCorrelationIndex(correlations);
  const ruleOptions = Array.from(new Map(findings.map((f) => [f.detection_rule, f.title])).entries()).map(([id, title]) => ({ id, title }));
  const techniqueIds = Array.from(new Set(findings.flatMap((f) => f.attack_techniques || []))).sort();

  content.innerHTML = `
    <div class="row between"><h2 id="findings-heading">Findings (${findings.length})</h2></div>
    ${renderFilterBar("fd", {
      severity: true,
      confidence: true,
      host: true,
      user: true,
      technique: techniqueIds,
      rule: ruleOptions,
      collection: currentCollections,
      timeRange: true,
    })}
    <div id="finding-cards"></div>
  `;
  const rerender = () => renderFindingCards(caseId, findings, eventsById, eventCorrIdx, readFilterBar("fd"), statusIdx);
  wireFilterBar("fd", rerender);
  rerender();
}

// findingMatchesFilters resolves host/user/collection through the
// finding's own supporting events (a Finding has no host/user field of
// its own -- see model.Finding -- it's a property of the evidence it's
// backed by), exactly the same join renderFindingCards uses to display
// them on the card.
function findingMatchesFilters(f, filters, eventsById) {
  if (filters.severity && f.severity !== filters.severity) return false;
  if (filters.confidence && f.confidence !== filters.confidence) return false;
  if (filters.rule && f.detection_rule !== filters.rule) return false;
  if (filters.technique && !(f.attack_techniques || []).includes(filters.technique)) return false;
  if (filters.from && new Date(f.last_seen) < filters.from) return false;
  if (filters.to && new Date(f.first_seen) > filters.to) return false;

  if (filters.host || filters.user || filters.collection) {
    const supporting = (f.supporting_event_ids || []).map((id) => eventsById[id]).filter(Boolean);
    if (filters.host && !supporting.some((e) => (e.host || "").toLowerCase().includes(filters.host))) return false;
    if (filters.user && !supporting.some((e) => (e.user || "").toLowerCase().includes(filters.user))) return false;
    if (filters.collection && !supporting.some((e) => e.collection_id === filters.collection)) return false;
  }
  return true;
}

// findingEntities returns the distinct hosts/users among a finding's
// supporting events, for the card's Host/User summary line -- "insufficient
// evidence" is shown (never a blank) if no supporting event resolved.
function findingEntities(f, eventsById) {
  const supporting = (f.supporting_event_ids || []).map((id) => eventsById[id]).filter(Boolean);
  const hosts = Array.from(new Set(supporting.map((e) => e.host).filter(Boolean)));
  const users = Array.from(new Set(supporting.map((e) => e.user).filter(Boolean)));
  return { hosts, users };
}

function renderFindingCards(caseId, findings, eventsById, eventCorrIdx, filters, statusIdx) {
  statusIdx = statusIdx || {};
  const container = document.getElementById("finding-cards");
  const heading = document.getElementById("findings-heading");
  const filtered = findings.filter((f) => findingMatchesFilters(f, filters, eventsById));
  heading.textContent = `Findings (${filtered.length} of ${findings.length})`;
  container.innerHTML = "";
  if (filtered.length === 0) {
    container.innerHTML = `<p class="empty">No findings match the current filters.</p>`;
    return;
  }

  filtered.forEach((f) => {
    const longDesc = f.description && f.description.length > 280;
    const descId = `desc-${++cellIdCounter}`;
    const descHtml = longDesc
      ? `<span id="${descId}" class="truncated">${esc(f.description.slice(0, 280))}&hellip;</span>
         <button type="button" class="secondary small detail-toggle-btn" data-target="${descId}" data-full="${esc(f.description)}" data-short="${esc(f.description.slice(0, 280))}&hellip;">Show more</button>`
      : esc(f.description || "");

    const { hosts, users } = findingEntities(f, eventsById);
    const entityLine = hosts.length || users.length ? `${hosts.length ? "Host: " + esc(hosts.join(", ")) : ""}${hosts.length && users.length ? " &middot; " : ""}${users.length ? "User: " + esc(users.join(", ")) : ""}` : `<span class="muted">insufficient evidence for host/user</span>`;

    // Correlation/activity-chain cross-reference: any correlation that
    // shares at least one supporting event with this finding.
    const relatedCorrIds = new Set();
    const relatedCorrs = [];
    (f.supporting_event_ids || []).forEach((eid) => {
      (eventCorrIdx[eid] || []).forEach((c) => {
        if (!relatedCorrIds.has(c.correlation_id)) {
          relatedCorrIds.add(c.correlation_id);
          relatedCorrs.push(c);
        }
      });
    });
    const corrLine = relatedCorrs.length
      ? `<div class="muted small" style="margin-top:4px">Part of: ${relatedCorrs.map((c) => `<span class="badge conf">${esc(CORR_LABELS[c.correlation_type] || c.correlation_type)}</span>`).join(" ")}</div>`
      : "";

    const card = h(`
      <div class="finding-card">
        <div class="row between">
          <div class="row">${severityBadge(f.severity)} ${confBadge(f.confidence)}</div>
          <span class="muted small mono">${esc(f.detection_rule)}</span>
        </div>
        <div class="finding-title">${esc(f.title)}</div>
        <div class="finding-desc">${descHtml}</div>
        <div>${techChips(f.attack_techniques)}</div>
        <div class="muted small" style="margin-top:4px">${entityLine}</div>
        <div class="muted small">${esc(fmtTime(f.first_seen))} &rarr; ${esc(fmtTime(f.last_seen))} &middot; ${f.supporting_event_ids.length} supporting event(s)</div>
        ${corrLine}
        <div class="finding-assessment-slot"></div>
        <div class="finding-detail" data-id="${esc(f.finding_id)}"></div>
      </div>
    `);
    card.querySelector(".finding-assessment-slot").appendChild(renderStatusControl(caseId, "finding", f.finding_id, statusIdx[f.finding_id]));
    card.addEventListener("click", (ev) => {
      if (ev.target.closest(".evidence-box") || ev.target.closest(".detail-toggle-btn") || ev.target.closest(".detail-copy-btn") || ev.target.closest(".analyst-assessment")) return;
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
        row.style.display = "table-row";
        await loadProvenanceInto(caseId, eventId, box);
      });
    });
  } catch (e) {
    detail.innerHTML = errorBox(e);
  }
}

// ---------------- Investigations (Phase 5) ----------------
//
// An Investigation groups related Findings/Correlations into one
// evidence-backed story (see internal/investigate) -- distinct from
// buildInvestigationSummary above, which is Phase 1's short deterministic
// paragraph on the case overview; naming collision is unfortunate but
// pre-existing, so functions below are named renderInvestigation* to stay
// clearly distinguishable at a glance.

const INVESTIGATION_CATEGORY_LABELS = {
  suspicious_execution: "Suspicious Execution",
  persistence: "Persistence",
  credential_attack: "Credential/Authentication Attack",
  suspicious_network: "Suspicious Network Activity",
  service_persistence: "Service-Based Persistence",
  script_based_attack: "Script-Based Attack",
  multi_stage_attack: "Multi-Stage Attack",
};

const SEVERITY_EMOJI = { critical: "\u{1F534}", high: "\u{1F7E0}", medium: "\u{1F7E1}", low: "\u{1F7E2}" };

// renderInvestigationList is the compact list used both on the case
// overview (top 5) and, unsliced, on the full Investigations tab --
// title, severity/confidence, time range, and event/finding/technique
// counts, per this phase's dashboard mockup. Each row links to
// renderInvestigationDetail.
function renderInvestigationList(caseId, investigations) {
  if (investigations.length === 0) {
    return `<p class="empty">No investigations yet -- run analysis first. Investigations are derived from Findings/Correlations, so they appear as soon as analysis produces any.</p>`;
  }
  return `<div class="investigation-list">
    ${investigations
      .map(
        (inv) => `
      <a class="investigation-row" href="#/cases/${caseId}/investigations/${esc(inv.investigation_id)}">
        <div class="row between">
          <div>
            <span>${SEVERITY_EMOJI[inv.severity] || ""}</span>
            ${severityBadge(inv.severity)} ${confBadge(inv.confidence)}
            <strong style="margin-left:6px">${esc(inv.title)}</strong>
          </div>
          <span class="muted small mono">score ${inv.risk_score}</span>
        </div>
        <div class="muted small" style="margin-top:4px">
          ${esc(fmtTime(inv.start_time))} &rarr; ${esc(fmtTime(inv.end_time))}
          &middot; ${inv.event_ids.length} event(s) &middot; ${inv.finding_ids.length} finding(s)
          &middot; ${inv.attack_techniques.length} ATT&amp;CK technique(s)
          ${inv.hosts.length ? "&middot; " + esc(inv.hosts.join(", ")) : ""}
        </div>
      </a>`
      )
      .join("")}
  </div>`;
}

async function renderInvestigationsTab(content, caseId) {
  content.innerHTML = `<p class="empty">Loading investigations...</p>`;
  const investigations = await api(`/cases/${caseId}/investigations`);
  const techniqueIds = Array.from(new Set(investigations.flatMap((i) => i.attack_techniques || []))).sort();

  content.innerHTML = `
    <div class="row between"><h2 id="investigations-heading">Investigations (${investigations.length})</h2></div>
    ${renderFilterBar("iv", { severity: true, confidence: true, technique: techniqueIds })}
    <div id="investigations-body"></div>
  `;
  const rerender = () => {
    const filters = readFilterBar("iv");
    const filtered = investigations.filter((inv) => {
      if (filters.severity && inv.severity !== filters.severity) return false;
      if (filters.confidence && inv.confidence !== filters.confidence) return false;
      if (filters.technique && !(inv.attack_techniques || []).includes(filters.technique)) return false;
      return true;
    });
    document.getElementById("investigations-heading").textContent = `Investigations (${filtered.length} of ${investigations.length})`;
    document.getElementById("investigations-body").innerHTML =
      filtered.length === 0 ? `<p class="empty">No investigations match the current filters.</p>` : renderInvestigationList(caseId, filtered);
  };
  wireFilterBar("iv", rerender);
  rerender();
}

// renderInvestigationDetail is the dedicated page opened by clicking an
// investigation ("Overview / Timeline / Findings / Correlations / ATT&CK
// / Evidence / Raw Records" -- shown here as sections on one page rather
// than sub-tabs, so every section is reachable without extra clicks).
// It deliberately REUSES the existing Timeline/Findings/Correlations
// rendering (renderTimelineRows, renderFindingCards, renderCorrelationCard,
// renderActivityChain) scoped to this investigation's own event/finding/
// correlation IDs, rather than building a second, parallel
// implementation of any of them -- exactly the "reuse the existing
// timeline/event model" requirement.
async function renderInvestigationDetail(caseId, investigationId) {
  app.innerHTML = `<p class="empty">Loading investigation...</p>`;
  let detail, collections, statuses;
  try {
    [detail, collections, statuses] = await Promise.all([
      api(`/cases/${caseId}/investigations/${investigationId}`),
      api(`/cases/${caseId}/evidence`),
      api(`/cases/${caseId}/analyst-status`).catch(() => []),
    ]);
  } catch (e) {
    app.innerHTML = errorBox(e);
    return;
  }
  currentCollections = collections;
  const statusIdx = buildStatusIndex(statuses);

  const eventsById = Object.fromEntries(detail.event_details.map((e) => [e.id, e]));
  const eventFindingIdx = buildEventFindingIndex(detail.finding_details);
  const eventCorrIdx = buildEventCorrelationIndex(detail.correlation_details);
  const chains = detail.correlation_details.filter((c) => isChainCorrelationType(c.correlation_type));
  const others = detail.correlation_details.filter((c) => !isChainCorrelationType(c.correlation_type));

  const collectionsLine =
    detail.collection_ids.length > 1
      ? `<p class="small">Evidence Collections: ${detail.collection_ids.map(collectionLabel).join(", ")}<br/>
         <span class="muted">Independently observed in ${detail.collection_ids.length} evidence collections.</span></p>`
      : detail.collection_ids.length === 1
        ? `<p class="small">Evidence Collection: ${collectionLabel(detail.collection_ids[0])}</p>`
        : "";

  app.innerHTML = `
    <p><a href="#/cases/${caseId}/investigations">&larr; All investigations</a></p>
    <div class="panel">
      <div class="row between">
        <div>
          <span>${SEVERITY_EMOJI[detail.severity] || ""}</span>
          ${severityBadge(detail.severity)} ${confBadge(detail.confidence)}
          <span class="badge conf">${esc(INVESTIGATION_CATEGORY_LABELS[detail.category] || detail.category)}</span>
        </div>
        <span class="muted small mono">risk score ${detail.risk_score} / 100</span>
      </div>
      <h1 style="margin-top:8px">${esc(detail.title)}</h1>
      <div class="muted small">${esc(fmtTime(detail.start_time))} &rarr; ${esc(fmtTime(detail.end_time))}
        ${detail.hosts.length ? "&middot; Host(s): " + esc(detail.hosts.join(", ")) : ""}
        ${detail.users.length ? "&middot; User(s): " + esc(detail.users.join(", ")) : ""}
      </div>
      <p style="margin-top:10px">${esc(detail.summary)}</p>
      ${collectionsLine}
      <details style="margin-top:10px">
        <summary class="muted small" style="cursor:pointer">Risk score rationale</summary>
        <ul class="small">${detail.score_rationale.map((r) => `<li>${esc(r)}</li>`).join("")}</ul>
        <p class="small muted">${esc(detail.confidence_rationale)}</p>
      </details>
      <div id="inv-assessment-slot" style="margin-top:10px"></div>
    </div>

    <div class="panel">
      <a class="secondary small" href="/api/cases/${caseId}/investigations/${investigationId}/export" target="_blank" rel="noopener">Export Investigation JSON</a>
      <div id="inv-notes"></div>
      <div id="inv-tags"></div>
    </div>

    <div class="panel">
      <h2 id="timeline-heading">Timeline</h2>
      <div id="timeline-body"></div>
    </div>

    <div class="panel">
      <h2 id="findings-heading">Findings (${detail.finding_details.length})</h2>
      <div id="finding-cards"></div>
    </div>

    ${
      detail.correlation_details.length
        ? `<div class="panel">
      <h2>Correlations (${detail.correlation_details.length})</h2>
      ${chains.length ? `<div id="inv-activity-chains"></div>` : ""}
      ${others.length ? `<div id="inv-other-correlations" style="margin-top:10px"></div>` : ""}
    </div>`
        : ""
    }

    ${
      detail.attack_breakdown.length
        ? `<div class="panel">
      <h2>ATT&amp;CK</h2>
      <div id="inv-attack-groups"></div>
    </div>`
        : ""
    }
  `;

  document.getElementById("inv-assessment-slot").appendChild(renderStatusControl(caseId, "investigation", investigationId, statusIdx[investigationId]));
  renderNotesSection(document.getElementById("inv-notes"), caseId, "investigation", investigationId);
  renderTagsSection(document.getElementById("inv-tags"), caseId, "investigation", investigationId);

  // Timeline: exact reuse of renderTimelineRows/rowForEvent/wireTimelineRowClicks.
  renderTimelineRows(caseId, detail.event_details, eventFindingIdx, eventCorrIdx, {});
  wireTimelineRowClicks(caseId, document.getElementById("timeline-body"));

  // Findings: exact reuse of renderFindingCards.
  renderFindingCards(caseId, detail.finding_details, eventsById, eventCorrIdx, {}, statusIdx);

  // Correlations: exact reuse of renderActivityChain/renderCorrelationCard.
  if (chains.length) {
    const container = document.getElementById("inv-activity-chains");
    chains.forEach((c) => container.appendChild(renderActivityChain(caseId, c, eventsById, eventFindingIdx)));
  }
  if (others.length) {
    const container = document.getElementById("inv-other-correlations");
    others.forEach((c) => container.appendChild(renderCorrelationCard(c, eventsById)));
  }

  // ATT&CK: Tactic -> Techniques -> Supporting Findings -> Supporting Events,
  // scoped to this investigation (see InvestigationTacticGroup on the Go side).
  if (detail.attack_breakdown.length) {
    const groups = document.getElementById("inv-attack-groups");
    detail.attack_breakdown.forEach((tg) => {
      const group = h(`
        <div class="tactic-group">
          <h3 class="tactic-heading">${esc(tg.tactic)} <span class="muted small">(${tg.techniques.length} technique${tg.techniques.length === 1 ? "" : "s"})</span></h3>
          <div class="tactic-techniques"></div>
        </div>`);
      const list = group.querySelector(".tactic-techniques");
      tg.techniques.forEach((t) => {
        list.appendChild(
          h(`<div class="finding-card" style="cursor:default">
            <div class="row between">
              <div><span class="tech-chip">${esc(t.id)}</span> <strong>${esc(t.name)}</strong></div>
              <a href="${esc(t.url)}" target="_blank" rel="noopener">mitre.org &#8599;</a>
            </div>
            <div class="muted small" style="margin-top:6px">${t.finding_ids.length} finding(s) &middot; ${t.event_ids.length} event(s)</div>
          </div>`)
        );
      });
      groups.appendChild(group);
    });
  }
}

// isChainCorrelationType matches internal/investigate's isChainCorrelation:
// the three narrative-chain types render as a visual step flow
// (renderActivityChain); everything else renders as a plain card.
function isChainCorrelationType(t) {
  return t === "activity_chain" || t === "credential_chain" || t === "service_chain";
}

// ---------------- ATT&CK tab ----------------

// renderAttackTab groups techniques by MITRE tactic, in kill-chain order
// (CANONICAL_TACTICS), not alphabetically or by discovery order. A
// technique belonging to more than one tactic (attck.Technique.Tactic is
// a real, sometimes multi-valued MITRE field, e.g. "Persistence,
// Privilege Escalation") is shown once under each -- that's accurate
// coverage, not duplication. Only techniques /attack actually returns
// (i.e. this case has a finding mapped to) are ever shown; there is no
// tactic heading for a tactic with zero techniques.
async function renderAttackTab(content, caseId) {
  content.innerHTML = `<p class="empty">Loading ATT&amp;CK coverage...</p>`;
  const techniques = await api(`/cases/${caseId}/attack`);
  if (techniques.length === 0) {
    content.innerHTML = `<p class="empty">No ATT&amp;CK techniques mapped yet. Run analysis first.</p>`;
    return;
  }

  const byTactic = {};
  techniques.forEach((t) => {
    splitTactics(t.tactic).forEach((tac) => {
      (byTactic[tac] = byTactic[tac] || []).push(t);
    });
  });
  const order = [...CANONICAL_TACTICS.filter((t) => byTactic[t]), ...Object.keys(byTactic).filter((t) => !CANONICAL_TACTICS.includes(t))];

  content.innerHTML = `<h2>MITRE ATT&amp;CK coverage (${techniques.length} technique(s) across ${order.length} tactic(s))</h2><div id="attack-groups"></div>`;
  const groups = document.getElementById("attack-groups");
  order.forEach((tactic) => {
    const group = h(`
      <div class="tactic-group">
        <h3 class="tactic-heading">${esc(tactic)} <span class="muted small">(${byTactic[tactic].length} technique${byTactic[tactic].length === 1 ? "" : "s"})</span></h3>
        <div class="tactic-techniques"></div>
      </div>`);
    const list = group.querySelector(".tactic-techniques");
    byTactic[tactic].forEach((t) => list.appendChild(attackTechniqueCard(t)));
    groups.appendChild(group);
  });
}

// attackTechniqueCard shows technique ID/name, the finding+event counts
// this case's evidence actually supports (not MITRE's abstract
// technique description), a rolled-up severity badge, and -- on click
// -- the specific findings behind the mapping, per "do not claim a
// technique merely because a process name resembles it."
function attackTechniqueCard(t) {
  const eventIds = new Set();
  t.findings.forEach((f) => (f.supporting_event_ids || []).forEach((id) => eventIds.add(id)));
  const sev = maxSeverity(t.findings.map((f) => f.severity));
  const card = h(`
    <div class="finding-card">
      <div class="row between">
        <div><span class="tech-chip">${esc(t.id)}</span> <strong>${esc(t.name)}</strong></div>
        <div class="row">${sev ? severityBadge(sev) : ""}<a href="${esc(t.url)}" target="_blank" rel="noopener">mitre.org &#8599;</a></div>
      </div>
      <div class="muted small" style="margin-top:6px">${t.findings.length} finding(s) &middot; ${eventIds.size} supporting event(s)</div>
      <div class="attack-technique-detail"></div>
    </div>`);
  card.addEventListener("click", (ev) => {
    if (ev.target.tagName === "A") return;
    toggleAttackTechniqueDetail(card, t);
  });
  return card;
}

function toggleAttackTechniqueDetail(card, t) {
  const detail = card.querySelector(".attack-technique-detail");
  if (detail.classList.contains("open")) {
    detail.classList.remove("open");
    return;
  }
  detail.classList.add("open");
  if (detail.dataset.loaded) return;
  detail.innerHTML = `
    <h4 class="small" style="margin:8px 0 4px">Supporting findings</h4>
    ${t.findings
      .map(
        (f) => `<div class="row between small" style="padding:4px 0; border-top:1px solid var(--border)">
          <span>${severityBadge(f.severity)} ${esc(f.title)}</span>
          <span class="muted mono">${esc(f.detection_rule)}</span>
        </div>`
      )
      .join("")}
    <p class="muted small" style="margin-top:6px">See the Findings tab (filter by this ATT&amp;CK technique) for full supporting-event and raw-evidence drill-down.</p>
  `;
  detail.dataset.loaded = "1";
}

// ---------------- Correlations tab ----------------

const CORR_LABELS = {
  activity_chain: "Activity chain",
  process_chain: "Process chain",
  entity: "Entity correlation",
  temporal: "Temporal cluster",
  // Phase 4 additions -- both are narrative chains like activity_chain
  // (ordered event_ids, a beginning and an end), not a bare link like
  // process_chain/entity/temporal.
  credential_chain: "Credential chain",
  service_chain: "Service chain",
};

// renderCorrelationsTab splits correlations into activity chains (a
// reconstructed narrative sequence, rendered as a visual step flow --
// see renderActivityChain) and everything else (process/entity/temporal
// relationships, still shown as compact cards, same as before -- they
// describe a link between events, not a story with a beginning and end).
async function renderCorrelationsTab(content, caseId) {
  content.innerHTML = `<p class="empty">Loading correlated activity...</p>`;
  const [corrs, timeline, findings] = await Promise.all([
    api(`/cases/${caseId}/correlations`),
    api(`/cases/${caseId}/timeline`).catch(() => []),
    api(`/cases/${caseId}/findings`).catch(() => []),
  ]);
  if (corrs.length === 0) {
    content.innerHTML = `<p class="empty">No correlations yet. Run analysis first.</p>`;
    return;
  }
  const eventsById = Object.fromEntries(timeline.map((e) => [e.id, e]));
  const eventFindingIdx = buildEventFindingIndex(findings);
  const chains = corrs.filter((c) => isChainCorrelationType(c.correlation_type));
  const others = corrs.filter((c) => !isChainCorrelationType(c.correlation_type));

  content.innerHTML = `
    <h2>Correlated activity (${corrs.length})</h2>
    ${chains.length ? `<h3 class="tactic-heading">Activity chains (${chains.length})</h3><div id="activity-chains"></div>` : ""}
    ${others.length ? `<h3 class="tactic-heading" style="margin-top:16px">Other correlations (${others.length})</h3><div id="other-correlations"></div>` : ""}
  `;
  if (chains.length) {
    const container = document.getElementById("activity-chains");
    chains.forEach((c) => container.appendChild(renderActivityChain(caseId, c, eventsById, eventFindingIdx)));
  }
  if (others.length) {
    const container = document.getElementById("other-correlations");
    others.forEach((c) => container.appendChild(renderCorrelationCard(c, eventsById)));
  }
}

function renderCorrelationCard(c, eventsById) {
  const collIds = new Set(c.event_ids.map((id) => eventsById[id] && eventsById[id].collection_id).filter(Boolean));
  const collectionsLine = collIds.size > 1 ? `<div class="muted small" style="margin-top:6px">Spans ${[...collIds].map(collectionLabel).join(", ")}</div>` : "";
  return h(`
    <div class="finding-card" style="cursor:default">
      <div class="row between">
        <span class="badge conf">${esc(CORR_LABELS[c.correlation_type] || c.correlation_type)}</span>
        <span class="muted small">${c.event_ids.length} event(s)</span>
      </div>
      <div class="finding-title">${esc(c.title)}</div>
      <div class="finding-desc">${esc(c.description)}</div>
      ${collectionsLine}
    </div>`);
}

// renderActivityChain builds the vertical step-by-step visualization
// (User Logon -> WINWORD.EXE -> POWERSHELL.EXE -> ... -> Network
// Connection). Steps render in exactly the order
// correlate.BuildActivityChains recorded them -- c.event_ids is already
// an ordered narrative, never re-sorted or re-inferred here; see
// internal/correlate/activity_chain.go and
// TestBuildActivityChains_FullNarrative, which locks that ordering
// guarantee in on the Go side. If an event ID fails to resolve (should
// not happen against a consistent case, but never silently draw a
// shorter chain as if it were the whole story), that's surfaced
// explicitly rather than skipped quietly.
function renderActivityChain(caseId, c, eventsById, eventFindingIdx) {
  const steps = c.event_ids.map((id) => eventsById[id]).filter(Boolean);
  const wrap = h(`
    <div class="finding-card activity-chain-card" style="cursor:default">
      <div class="row between">
        <span class="badge conf">Activity chain</span>
        <span class="muted small">${esc(fmtTime(c.first_seen))} &rarr; ${esc(fmtTime(c.last_seen))}</span>
      </div>
      <div class="chain-flow"></div>
    </div>`);
  const flow = wrap.querySelector(".chain-flow");
  if (steps.length < c.event_ids.length) {
    flow.appendChild(h(`<p class="muted small">insufficient evidence to resolve ${c.event_ids.length - steps.length} step(s) of this chain</p>`));
  }
  steps.forEach((e, i) => {
    if (i > 0) flow.appendChild(h(`<div class="chain-connector">&darr;</div>`));
    flow.appendChild(renderChainNode(caseId, e, eventFindingIdx[e.id] || []));
  });
  return wrap;
}

// chainNodeLabel names a step by what it actually represents forensically
// (User Logon, a process name, a persistence mechanism, a network
// destination), not its raw internal event_type string.
function chainNodeLabel(e) {
  switch (e.event_type) {
    case "logon_success":
      return `User Logon${e.user ? " (" + e.user + ")" : ""}`;
    case "logon_failure":
      return `Failed Logon${e.user ? " (" + e.user + ")" : ""}`;
    case "process_create":
    case "prefetch_execution":
    case "powershell_script_block":
      return e.process_name || e.event_type;
    case "registry_run_key_set":
      return "Registry Persistence";
    case "scheduled_task_created":
      return "Scheduled Task Persistence";
    case "network_connection":
      return `Network Connection${e.network_dest ? " (" + e.network_dest + ")" : ""}`;
    // Phase 4 additions.
    case "logon_explicit_credentials":
      return `Explicit Credential Logon${e.user ? " (" + e.user + ")" : ""}`;
    case "privileged_logon":
      return `Privileged Logon${e.user ? " (" + e.user + ")" : ""}`;
    case "kerberos_tgt_request":
      return "Kerberos TGT Request";
    case "kerberos_service_ticket_request":
      return "Kerberos Service Ticket Request";
    case "ntlm_authentication":
      return "NTLM Authentication";
    case "service_install":
      return "Service Persistence";
    case "registry_persistence":
      return "Registry Persistence";
    case "file_create":
      return `File Dropped${e.file_path ? " (" + e.file_path + ")" : ""}`;
    case "dns_query":
      return `DNS Query${e.network_dest ? " (" + e.network_dest + ")" : ""}`;
    default:
      return e.event_type;
  }
}

// renderChainNode is one step: timestamp, process/entity, a rolled-up
// severity badge and ATT&CK chips from whatever findings actually cover
// this event (never fabricated if none do), and -- per "clicking a node
// should reveal the underlying evidence" -- a click-to-expand provenance
// panel using the exact same drill-down as Timeline/Findings.
function renderChainNode(caseId, e, relatedFindings) {
  const sev = maxSeverity(relatedFindings.map((f) => f.severity));
  const techniques = techniquesForFindings(relatedFindings);
  const node = h(`
    <div class="chain-node" data-event="${esc(e.id)}" tabindex="0">
      <div class="row between">
        <strong>${esc(chainNodeLabel(e))}</strong>
        ${sev ? severityBadge(sev) : ""}
      </div>
      <div class="muted small mono">${esc(fmtTime(e.timestamp))} &middot; ${esc(e.host)}</div>
      ${techniques.length ? `<div style="margin-top:4px">${techChips(techniques)}</div>` : ""}
      <div class="chain-node-detail"></div>
    </div>`);
  node.addEventListener("click", () => toggleChainNodeDetail(caseId, node, e.id));
  node.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter" || ev.key === " ") {
      ev.preventDefault();
      node.click();
    }
  });
  return node;
}

async function toggleChainNodeDetail(caseId, node, eventId) {
  const detail = node.querySelector(".chain-node-detail");
  if (detail.classList.contains("open")) {
    detail.classList.remove("open");
    return;
  }
  detail.classList.add("open");
  if (!detail.dataset.loaded) {
    detail.innerHTML = `<div class="evidence-box"></div>`;
    await loadProvenanceInto(caseId, eventId, detail.querySelector(".evidence-box"));
    detail.dataset.loaded = "1";
  }
}

// ---------------- Evidence tab ----------------
//
// Unlike the dashboard's compact "Evidence Collections" panel (a
// collection-level summary), this tab operates at the individual
// evidence-FILE level: every imported file gets its own checkbox and
// Delete action, grouped under the collection ("import batch") it came
// from -- see docs/data-model.md's "Evidence file model" section for why
// both levels of the hierarchy are kept.

async function renderEvidenceTab(content, caseId, collections) {
  if (collections.length === 0) {
    content.innerHTML = `<p class="empty">No evidence collections yet. Click "+ Add Evidence" above.</p>`;
    return;
  }
  content.innerHTML = `
    <div class="row between">
      <h2>Evidence</h2>
      <div class="row">
        <button type="button" class="secondary small" id="evidence-select-all-btn">Select All</button>
        <button type="button" class="secondary small" id="evidence-clear-btn">Clear</button>
      </div>
    </div>
    <div id="evidence-bulk-bar" class="hidden"></div>
    <div id="evidence-collections-detail"></div>
  `;
  const container = document.getElementById("evidence-collections-detail");
  for (const [i, col] of collections.entries()) {
    const card = h(`<div class="finding-card" style="cursor:default" data-collection="${esc(col.collection_id)}"><p class="empty">Loading files...</p></div>`);
    container.appendChild(card);
    try {
      const detail = await api(`/cases/${caseId}/evidence/${col.collection_id}`);
      card.innerHTML = renderEvidenceCollectionCard(i, col, detail.source_files || []);
    } catch (e) {
      card.innerHTML = errorBox(e);
    }
  }
  wireEvidenceFileSelection(caseId, container);
}

// renderEvidenceCollectionCard shows one collection's imported files as
// the primary itemized list (checkbox, artifact type, size, event
// count, Delete), with the collection's discovered-but-not-yet-imported
// or unsupported files tucked into a collapsed <details> below -- the
// main list stays focused on actual evidence, not clutter.
function renderEvidenceCollectionCard(index, col, files) {
  const imported = files.filter((f) => f.import_status === "imported");
  const other = files.filter((f) => f.import_status !== "imported");
  return `
    <div class="row between">
      <strong>Collection #${index + 1}</strong>
      <span class="muted small">${esc(fmtDate(col.created_at))}</span>
    </div>
    <div class="muted small">${esc(SOURCE_TYPE_LABELS[col.source_type] || col.source_type)}${col.original_filename ? " &middot; " + esc(col.original_filename) : ""}</div>
    <div class="small" style="margin-top:4px">${col.file_count} file(s) discovered &middot; ${col.imported_file_count} file(s) imported</div>
    <div class="evidence-file-list" style="margin-top:10px">
      ${imported.length ? imported.map(rowForEvidenceFile).join("") : `<p class="empty">No evidence files imported yet from this collection.</p>`}
    </div>
    ${
      other.length
        ? `<details style="margin-top:10px">
      <summary class="muted small" style="cursor:pointer">${other.length} file(s) not imported (discovered or unsupported)</summary>
      <div class="table-wrap" style="margin-top:8px"><table>
        <thead><tr><th>Filename</th><th>Path</th><th>Type</th><th>Status</th></tr></thead>
        <tbody>
          ${other
            .map(
              (f) => `<tr>
              <td class="mono small">${esc(f.original_filename)}</td>
              <td class="mono small">${esc(f.path)}</td>
              <td class="small">${esc(f.artifact_type || "-")}</td>
              <td class="small">${esc(SOURCE_FILE_STATUS_LABELS[f.import_status] || f.import_status)}</td>
            </tr>`
            )
            .join("")}
        </tbody>
      </table></div>
    </details>`
        : ""
    }
  `;
}

// rowForEvidenceFile renders one imported evidence file: a checkbox for
// bulk selection, its key facts, and a per-row Delete action (deleting
// exactly this one file never requires deleting the whole collection).
function rowForEvidenceFile(f) {
  return `
    <div class="evidence-file-row" data-file-id="${esc(f.id)}">
      <label class="evidence-file-label">
        <input type="checkbox" class="evidence-file-checkbox" data-id="${esc(f.id)}" data-name="${esc(f.original_filename)}" />
        <span>
          <div>${esc(f.original_filename)}</div>
          <div class="muted small">${esc(f.artifact_type || "-")} &middot; ${fmtBytes(f.size_bytes)} &middot; ${f.event_count} event(s)</div>
        </span>
      </label>
      <button type="button" class="secondary small danger evidence-file-delete-btn" data-id="${esc(f.id)}" data-name="${esc(f.original_filename)}">Delete</button>
    </div>`;
}

// wireEvidenceFileSelection powers per-file Delete buttons, the Select
// All/Clear controls, and the bulk action bar -- which, per requirement
// 16, is only ever injected into the DOM while at least one file is
// checked.
function wireEvidenceFileSelection(caseId, container) {
  const checkboxes = () => Array.from(container.querySelectorAll(".evidence-file-checkbox"));
  const bulkBar = document.getElementById("evidence-bulk-bar");

  function updateBulkBar() {
    const selected = checkboxes().filter((cb) => cb.checked);
    if (selected.length === 0) {
      bulkBar.classList.add("hidden");
      bulkBar.innerHTML = "";
      return;
    }
    bulkBar.classList.remove("hidden");
    bulkBar.innerHTML = `
      <div class="bulk-action-bar">
        <span>${selected.length} evidence file(s) selected</span>
        <button type="button" class="danger" id="evidence-delete-selected-btn">Delete Selected (${selected.length})</button>
      </div>`;
    document.getElementById("evidence-delete-selected-btn").addEventListener("click", () =>
      confirmAndDeleteEvidence(
        caseId,
        selected.map((cb) => cb.dataset.id)
      )
    );
  }

  checkboxes().forEach((cb) => cb.addEventListener("change", updateBulkBar));
  document.getElementById("evidence-select-all-btn").addEventListener("click", () => {
    checkboxes().forEach((cb) => (cb.checked = true));
    updateBulkBar();
  });
  document.getElementById("evidence-clear-btn").addEventListener("click", () => {
    checkboxes().forEach((cb) => (cb.checked = false));
    updateBulkBar();
  });
  container.querySelectorAll(".evidence-file-delete-btn").forEach((btn) => {
    btn.addEventListener("click", () => confirmAndDeleteEvidence(caseId, [btn.dataset.id]));
  });
}

// confirmAndDeleteEvidence requires explicit confirmation (see
// requirement 13) and explains that derived analysis will need to be
// recalculated, before permanently removing one or more evidence files.
async function confirmAndDeleteEvidence(caseId, ids) {
  const title = ids.length === 1 ? "Delete Evidence File?" : `Delete ${ids.length} Evidence Files?`;
  const detail = "This will remove the selected evidence. Any events, findings, and correlations that depended only on it will be removed too; the case will be marked for re-analysis.";
  if (!window.confirm(`${title}\n\n${detail}`)) return;
  try {
    if (ids.length === 1) {
      await api(`/cases/${caseId}/evidence/${ids[0]}`, { method: "DELETE" });
    } else {
      await api(`/cases/${caseId}/evidence`, { method: "DELETE", body: JSON.stringify({ source_file_ids: ids }) });
    }
    window.location.reload();
  } catch (e) {
    window.alert("Failed to delete evidence: " + (e.message || e));
  }
}
