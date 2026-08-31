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

// Which case/tab is currently mounted, and each tab's last scroll offset.
// Together these let a tab change re-render only #tab-content and put the
// investigator back where they were, instead of rebuilding the page and
// losing their position -- see switchTab.
let renderedCaseId = null;
let renderedTab = null;
const tabScroll = new Map();

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
// apiUpload posts a file as multipart/form-data, reporting genuine
// byte-level upload progress.
//
// It uses XMLHttpRequest rather than fetch because fetch still has no
// upload-progress event: a fetch-based upload can report that it started
// and that it finished, and nothing in between. For a two-gigabyte AD1
// that is the difference between an investigator watching a real
// transfer and watching a spinner with no idea whether anything is
// happening.
//
// onProgress receives {loaded, total, lengthComputable}. When the browser
// cannot determine the total (lengthComputable false), the caller is told
// so and shows an indeterminate indicator rather than inventing a
// percentage.
function apiUpload(path, file, onProgress) {
  return new Promise((resolve, reject) => {
    const fd = new FormData();
    fd.append("file", file);

    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api" + path, true);

    if (onProgress) {
      xhr.upload.addEventListener("progress", (e) => {
        onProgress({ loaded: e.loaded, total: e.total, lengthComputable: e.lengthComputable });
      });
      // The last byte leaving the browser is NOT the end of the
      // operation: the server still has to hash, inspect and catalog the
      // evidence. Signalling that transition is the whole point of
      // distinguishing the stages.
      xhr.upload.addEventListener("load", () => {
        onProgress({ loaded: file.size, total: file.size, lengthComputable: true, uploadComplete: true });
      });
    }

    xhr.addEventListener("load", () => {
      let body = null;
      try {
        body = JSON.parse(xhr.responseText);
      } catch (_) {
        body = null;
      }
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(body);
        return;
      }
      // Preserve the existing error shape so duplicate-evidence and
      // validation errors render exactly as they did before.
      reject(apiError({ status: xhr.status, statusText: xhr.statusText || `HTTP ${xhr.status}` }, body));
    });
    xhr.addEventListener("error", () => reject(new Error("the upload failed to reach the server")));
    xhr.addEventListener("abort", () => reject(new Error("the upload was cancelled")));

    xhr.send(fd);
  });
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
// isNoTimestamp recognizes an event whose artifact records no time at
// all. Go marshals such a zero time.Time as "0001-01-01T00:00:00Z", and
// rendering that literally puts a year-1 date on the screen -- a date
// that was never in the evidence. The parsers deliberately refuse to
// substitute a file mtime for a missing execution time (see
// internal/parsers/pshistory), and the UI must not undo that by
// displaying a fabricated one.
function isNoTimestamp(ts) {
  if (!ts) return true;
  const d = new Date(ts);
  return isNaN(d.getTime()) ? false : d.getUTCFullYear() <= 1;
}

const NO_TIMESTAMP_LABEL = "No timestamp";

function fmtTime(ts) {
  if (!ts) return "-";
  if (isNoTimestamp(ts)) return NO_TIMESTAMP_LABEL;
  const d = new Date(ts);
  if (isNaN(d.getTime())) return ts;
  return d.toISOString().replace("T", " ").replace(/\.\d+Z$/, "").replace(/Z$/, "") + " UTC";
}

function fmtDate(ts) {
  if (!ts) return "-";
  if (isNoTimestamp(ts)) return NO_TIMESTAMP_LABEL;
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
  return `<div class="error-box">${esc(sentenceCase(err.message || String(err)))}</div>`;
}

// sentenceCase capitalizes the first letter of a backend error message.
// Go error strings are lowercase by convention ("evidence path does not
// exist..."), which is right for a log line and wrong for a sentence
// shown to an investigator. Presentation-only: the API contract keeps
// the Go convention.
function sentenceCase(msg) {
  const s = String(msg);
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
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
  ad1_image: "AD1 Forensic Image",
};

// ARTIFACT_TYPE_LABELS renders internal/model's Artifact* constants for
// an investigator. The raw constants are stable identifiers meant for
// code and provenance, not for reading -- "windows_event_log" tells an
// analyst less than "Windows Event Log (EVTX)" does, especially now that
// the same artifact type can arrive either as a raw .evtx or as an
// EvtxECmd CSV export of one.
const ARTIFACT_TYPE_LABELS = {
  windows_event_log: "Windows Event Log (EVTX)",
  prefetch: "Prefetch",
  registry_run_key: "Registry (RECmd export)",
  registry_hive: "Windows Registry Hive",
  scheduled_task: "Scheduled Task",
};
function artifactLabel(t) {
  if (!t) return "-";
  return ARTIFACT_TYPE_LABELS[t] || t;
}

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
  // Phase 9: a registry key's last-write time, observed in a raw hive.
  // Not persistence in itself -- see model.EventRegistryKeyLastWrite.
  registry_key_last_write: "other",
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

// FILTER_UNKNOWN is the option value standing in for "this record has no
// value for this field" (a Prefetch event with no user, say). Records
// with a blank value are neither silently dropped nor shown as an
// unlabelled blank row -- they're selectable explicitly, under this
// sentinel. A NUL would be mangled inside an HTML attribute, so the
// bracketed form is used: it round-trips through the checkbox value
// intact and can't collide with a real host/user/process/rule value.
const FILTER_UNKNOWN = "<<tracefall:unknown>>";

const FILTER_FIELD_LABELS = {
  severity: "Severity",
  confidence: "Confidence",
  category: "Category",
  host: "Host",
  user: "User",
  process: "Process",
  technique: "ATT&CK",
  rule: "Rule",
  collection: "Collection",
  // Phase 9A: the evidence-selection toolbar reuses this same filter
  // component rather than growing a second one -- so search inside a
  // dropdown, the selected/total counts, keyboard handling and the
  // active-filter chips all behave identically to the Timeline and
  // Findings bars an investigator already knows.
  family: "Artifact type",
  priority: "Priority",
  status: "Status",
};

// filterStates holds ONE state object per filter bar (keyed by prefix).
// Both the dropdown checkboxes and the active-filter chips read and
// write this same object -- the selection is never mirrored into a
// second place that could drift out of sync with it.
const filterStates = new Map();

// filterOptions turns raw values into deduped, sorted {value,label}
// options. Blank/missing values collapse into a single explicit
// "Unknown" entry rather than appearing as an unlabelled blank row.
function filterOptions(values, labelFor) {
  const seen = new Map();
  let sawBlank = false;
  for (const v of values) {
    if (v === undefined || v === null || v === "") {
      sawBlank = true;
      continue;
    }
    if (!seen.has(v)) seen.set(v, labelFor ? labelFor(v) : String(v));
  }
  const out = Array.from(seen, ([value, label]) => ({ value, label }));
  out.sort((a, b) => a.label.localeCompare(b.label));
  if (sawBlank) out.push({ value: FILTER_UNKNOWN, label: "(Unknown)" });
  return out;
}

const SEVERITY_FILTER_OPTIONS = [
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
];
const CONFIDENCE_FILTER_OPTIONS = [
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
];

// hasSel / selMatches / selMatchesAny are the multi-select predicates
// every tab's filter logic runs through. An empty set means "no filter
// on this field" (matches everything), which is what keeps an untouched
// filter a no-op exactly as the previous single-select version was.
function hasSel(set) {
  return !!set && set.size > 0;
}
function selMatches(set, value) {
  if (!hasSel(set)) return true;
  return set.has(value ? value : FILTER_UNKNOWN);
}
function selMatchesAny(set, values) {
  if (!hasSel(set)) return true;
  if (!values || values.length === 0) return set.has(FILTER_UNKNOWN);
  return values.some((v) => set.has(v));
}

// renderFilterBar builds a compact filter bar: one dropdown button per
// categorical field, an optional date-range popover, a Clear all button,
// and a reserved row beneath for the active-filter chips.
//
// cfg keys map to FILTER_FIELD_LABELS. severity/confidence take `true`
// (their vocabularies are fixed); every other field takes an options
// array built by the calling tab from its own already-loaded dataset --
// see renderTimelineTab/renderFindingsTab. A field with no options is
// omitted entirely rather than rendered as an empty dropdown.
function renderFilterBar(prefix, cfg) {
  const fields = [];
  const add = (key, options) => {
    if (options && options.length) fields.push({ key, label: FILTER_FIELD_LABELS[key], options });
  };
  if (cfg.severity) add("severity", SEVERITY_FILTER_OPTIONS);
  if (cfg.confidence) add("confidence", CONFIDENCE_FILTER_OPTIONS);
  add("category", cfg.category);
  add("host", cfg.host);
  add("user", cfg.user);
  add("process", cfg.process);
  add("technique", cfg.technique);
  add("rule", cfg.rule);
  // Evidence-selection fields (Phase 9A).
  add("family", cfg.family);
  add("priority", cfg.priority);
  add("status", cfg.status);
  // A single-collection case has nothing to filter between.
  if (cfg.collection && cfg.collection.length > 1) add("collection", cfg.collection);

  // Carry the previous selection across a re-render of this same bar.
  // Switching tabs re-runs the owning tab's render (see switchTab), and
  // an investigator who filters the Timeline, glances at Findings and
  // comes back expects their filter still applied -- especially now that
  // their scroll position is restored, which would otherwise put them at
  // the same offset in a silently unfiltered list. Selections whose
  // value no longer exists in the data (evidence deleted since) are
  // dropped rather than silently matching nothing.
  // Carry-over is scoped to one case. A date range set while triaging
  // case A must never silently pre-filter case B's timeline: unlike a
  // host selection, a range can't be validated away against the new
  // case's data, so it would survive into an unrelated investigation
  // and hide events the analyst never chose to exclude.
  const stored = filterStates.get(prefix);
  const prev = stored && stored.scope === cfg.scope ? stored : null;
  const state = {
    fields,
    scope: cfg.scope,
    sel: {},
    from: prev ? prev.from : null,
    to: prev ? prev.to : null,
    raw: prev ? prev.raw : {},
    timeRange: !!cfg.timeRange,
    // q is the free-text search term. It lives in the same carried state
    // as the dropdowns, so a search survives a tab switch exactly as a
    // filter selection does -- an investigator who searched the Timeline,
    // glanced at Findings and came back expects their search still
    // applied, and their scroll position restored into a list that still
    // matches it.
    hasSearch: !!cfg.search,
    q: prev ? prev.q || "" : "",
  };
  fields.forEach((f) => {
    const carried = prev && prev.sel[f.key] ? f.options.filter((o) => prev.sel[f.key].has(o.value)).map((o) => o.value) : [];
    state.sel[f.key] = new Set(carried);
  });
  filterStates.set(prefix, state);

  const dropdowns = fields.map((f) => renderFilterDropdown(prefix, f, state.sel[f.key])).join("");
  const dateBtn = cfg.timeRange
    ? `<div class="filter-dd" data-field="__date">
         <button type="button" class="filter-trigger" id="${prefix}-f-date-btn"
                 aria-haspopup="dialog" aria-expanded="false" aria-controls="${prefix}-f-date-pop">
           <span class="filter-trigger-label">Date range</span><span class="filter-caret">&#9662;</span>
         </button>
         ${renderDatePopover(prefix)}
       </div>`
    : "";

  // The search box sits ABOVE the dropdown row: search is how an
  // investigator finds something they can already name, filters are how
  // they narrow a set they cannot. They reach for them in that order.
  const searchBox = cfg.search
    ? `<div class="filter-search-row">
         <input type="search" class="filter-q" id="${prefix}-f-q"
                placeholder="${esc(cfg.search)}" aria-label="${esc(cfg.search)}" autocomplete="off"
                value="${esc(state.q)}" />
       </div>`
    : "";

  return `
    ${searchBox}
    <div class="filter-bar" id="${prefix}-filter-bar">
      ${dropdowns}
      ${dateBtn}
      <button type="button" class="secondary small" id="${prefix}-f-clear">Clear all</button>
    </div>
    <div class="filter-chips-host" id="${prefix}-filter-chips"></div>`;
}

// Search haystacks.
//
// Each builds the lower-cased text one row is searchable by, from fields
// the investigator can actually see or would reasonably type. They are
// cached on the object (a non-enumerable property, so it never reaches
// JSON or a re-render) because a 100,000-event timeline would otherwise
// rebuild every string on every keystroke.
function searchHaystack(obj, build) {
  let v = obj.__hay;
  if (v === undefined) {
    v = build().filter(Boolean).join(" \u0001 ").toLowerCase();
    Object.defineProperty(obj, "__hay", { value: v, enumerable: false, configurable: true });
  }
  return v;
}

function eventSearchHaystack(e, eventFindingIdx) {
  return searchHaystack(e, () => [
    e.host, e.user, e.process_name, e.process_path, e.parent_process, e.parent_process_path,
    e.event_type, e.command_line, e.file_path, e.registry_path,
    e.network_source, e.network_dest, e.provider, e.artifact_type, e.parser,
    e.event_id ? "eventid:" + e.event_id : "",
    // ATT&CK techniques reach a timeline row through the findings that
    // cite it, which the tab has already indexed.
    (eventFindingIdx[e.id] || []).flatMap((f) => f.attack_techniques || []).join(" "),
  ]);
}

function findingSearchHaystack(f) {
  return searchHaystack(f, () => [
    f.title, f.description, f.detection_rule, f.severity, f.confidence,
    (f.attack_techniques || []).join(" "),
  ]);
}

function investigationSearchHaystack(inv) {
  return searchHaystack(inv, () => [
    inv.title, inv.summary, inv.severity, inv.confidence,
    (inv.attack_techniques || []).join(" "),
    (inv.hosts || []).join(" "),
    (inv.users || []).join(" "),
  ]);
}

// Below this many options a search field is more visual noise than help
// -- a four-item Severity list is faster to read than to type into.
const FILTER_SEARCH_THRESHOLD = 10;

function renderFilterDropdown(prefix, f, selected) {
  const id = `${prefix}-f-${f.key}`;
  const sel = selected || new Set();
  const withSearch = f.options.length > FILTER_SEARCH_THRESHOLD;
  const searchBox = withSearch
    ? `<input type="search" class="filter-search" id="${id}-search"
              placeholder="Search ${esc(f.label.toLowerCase())}..."
              aria-label="Search ${esc(f.label)} options" autocomplete="off" />`
    : "";

  return `
    <div class="filter-dd" data-field="${esc(f.key)}">
      <button type="button" class="filter-trigger" id="${id}-btn"
              aria-haspopup="true" aria-expanded="false" aria-controls="${id}-pop">
        <span class="filter-trigger-label">${esc(f.label)}</span><span class="filter-caret">&#9662;</span>
      </button>
      <div class="filter-pop" id="${id}-pop" role="group" aria-label="${esc(f.label)} filter" hidden>
        <div class="filter-pop-head">
          <span class="filter-pop-title">${esc(f.label)}</span>
          <span class="filter-pop-count" id="${id}-count"></span>
        </div>
        ${searchBox}
        <div class="filter-pop-list">
          ${f.options
            .map(
              (o) => `<label class="filter-opt" title="${esc(o.label)}" data-search="${esc(o.label.toLowerCase())}">
                        <input type="checkbox" data-field="${esc(f.key)}" value="${esc(o.value)}" ${sel.has(o.value) ? "checked" : ""} />
                        <span class="filter-opt-label">${esc(o.label)}</span>
                      </label>`
            )
            .join("")}
        </div>
        <p class="filter-pop-empty empty" hidden>No matching options.</p>
        <div class="filter-pop-actions">
          <button type="button" class="secondary small" data-act="all">Select all</button>
          <button type="button" class="secondary small" data-act="none">Clear</button>
        </div>
      </div>
    </div>`;
}

// filterSearchApply hides option rows that don't match the search term.
// It only ever changes row VISIBILITY -- never a checkbox's checked state
// and never the selection set -- so an option selected earlier stays
// selected while hidden, and reappears still ticked when the term is
// cleared. That separation is what makes "search then select more"
// behave the way an investigator expects.
function filterSearchApply(dd) {
  const input = dd.querySelector(".filter-search");
  const term = input ? input.value.trim().toLowerCase() : "";
  let visible = 0;
  dd.querySelectorAll(".filter-opt").forEach((opt) => {
    const match = !term || opt.dataset.search.includes(term);
    opt.hidden = !match;
    if (match) visible++;
  });
  const empty = dd.querySelector(".filter-pop-empty");
  if (empty) empty.hidden = visible !== 0;
}

// browserUtcOffsetLabel renders the browser's CURRENT offset from UTC,
// computed live (never hardcoded) so it's correct for the running
// machine and for whichever side of a DST boundary today falls on.
// getTimezoneOffset returns minutes BEHIND UTC, hence the negation.
function browserUtcOffsetLabel() {
  const mins = -new Date().getTimezoneOffset();
  if (mins === 0) return "UTC";
  const sign = mins > 0 ? "+" : "-";
  const abs = Math.abs(mins);
  const pad = (n) => String(n).padStart(2, "0");
  return `UTC${sign}${pad(Math.floor(abs / 60))}:${pad(abs % 60)}`;
}

// True when the browser is already on UTC, in which case there is no
// local-vs-UTC ambiguity to warn about and the extra wording is noise.
function browserIsUTC() {
  return new Date().getTimezoneOffset() === 0;
}

// The date range is entered through native date/time inputs, kept inside
// a compact popover instead of stretched across the bar as four
// full-width rows.
//
// The timezone line is the point of this popover's header: the Timeline
// column displays timestamps in UTC, while these native inputs are read
// in the browser's local zone (unchanged, deliberately -- see
// readDateTime). Rather than silently converting either one, the two
// readings are labelled so the investigator can see exactly which is
// which.
function renderDatePopover(prefix) {
  const tz = browserUtcOffsetLabel();
  return `
    <div class="filter-pop filter-pop-date" id="${prefix}-f-date-pop" role="dialog" aria-label="Date range filter" hidden>
      <div class="filter-pop-head">
        <span class="filter-pop-title">Date range</span>
      </div>
      <p class="filter-tz-note small muted">
        Timezone: <strong>${esc(tz)}</strong>${browserIsUTC() ? "" : " (browser local)"}
        ${browserIsUTC() ? "" : `<br/>Timeline timestamps are shown in UTC.`}
      </p>
      <div class="filter-date-row">
        <label for="${prefix}-f-from-d">From</label>
        <div class="row" style="gap:var(--space-2)">
          <input type="date" id="${prefix}-f-from-d" class="filter-date-input" />
          <input type="time" id="${prefix}-f-from-t" class="filter-time-input" step="1" />
        </div>
      </div>
      <div class="filter-date-row">
        <label for="${prefix}-f-to-d">To</label>
        <div class="row" style="gap:var(--space-2)">
          <input type="date" id="${prefix}-f-to-d" class="filter-date-input" />
          <input type="time" id="${prefix}-f-to-t" class="filter-time-input" step="1" />
        </div>
      </div>
      <div class="filter-pop-actions">
        <button type="button" class="secondary small" data-act="clear-date">Clear</button>
        <button type="button" class="small" data-act="apply-date">Apply</button>
      </div>
    </div>`;
}

// fmtFilterDate renders a bound compactly for the trigger label, e.g.
// "Jan 15, 09:00". Uses the same local-time reading the input itself
// shows (see readFilterBar's note on bound parsing).
function fmtFilterDate(d) {
  const month = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][d.getMonth()];
  const pad = (n) => String(n).padStart(2, "0");
  return `${month} ${d.getDate()}, ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

// dateRangeLabel appends the offset the bounds were entered in whenever
// that differs from UTC, so a range read off the filter bar can't be
// mistaken for the UTC timestamps shown in the Timeline column. On a
// UTC browser the suffix is omitted -- there's nothing to disambiguate.
function dateRangeLabel(state) {
  const tz = browserIsUTC() ? "" : ` (${browserUtcOffsetLabel()})`;
  if (state.from && state.to) return `Date: ${fmtFilterDate(state.from)} → ${fmtFilterDate(state.to)}${tz}`;
  if (state.from) return `Date: From ${fmtFilterDate(state.from)}${tz}`;
  if (state.to) return `Date: Until ${fmtFilterDate(state.to)}${tz}`;
  return "Date range";
}

// refreshFilterBar re-paints every trigger label and the chip row from
// the single state object, then calls onChange. Only text/ chips are
// rewritten -- the dropdown checkboxes are left in the DOM as-is, so an
// open popover doesn't close or lose scroll while the investigator is
// still ticking boxes.
function refreshFilterBar(prefix, onChange) {
  const state = filterStates.get(prefix);
  if (!state) return;

  for (const f of state.fields) {
    const btn = document.getElementById(`${prefix}-f-${f.key}-btn`);
    if (!btn) continue;
    const sel = state.sel[f.key];
    const labelEl = btn.querySelector(".filter-trigger-label");

    // "3 of 12 selected" inside the popover -- the context the compact
    // trigger label deliberately can't carry.
    const countEl = document.getElementById(`${prefix}-f-${f.key}-count`);
    if (countEl) countEl.textContent = sel.size ? `${sel.size} of ${f.options.length} selected` : `${f.options.length} available`;
    if (sel.size === 0) {
      labelEl.textContent = f.label;
      btn.classList.remove("active");
      btn.title = "";
    } else if (sel.size === 1) {
      const only = f.options.find((o) => sel.has(o.value));
      labelEl.textContent = `${f.label}: ${only ? only.label : ""}`;
      btn.classList.add("active");
      btn.title = only ? only.label : "";
    } else {
      labelEl.textContent = `${f.label}: ${sel.size} selected`;
      btn.classList.add("active");
      btn.title = f.options.filter((o) => sel.has(o.value)).map((o) => o.label).join(", ");
    }
  }

  if (state.timeRange) {
    const dbtn = document.getElementById(`${prefix}-f-date-btn`);
    if (dbtn) {
      dbtn.querySelector(".filter-trigger-label").textContent = dateRangeLabel(state);
      dbtn.classList.toggle("active", !!(state.from || state.to));
    }
  }

  renderFilterChips(prefix);
  if (onChange) onChange();
}

// Active filters, each individually removable. Rendered into a host row
// whose height is reserved by CSS (.filter-chips-host) so chips
// appearing or disappearing never shift the table below them.
function renderFilterChips(prefix) {
  const state = filterStates.get(prefix);
  const host = document.getElementById(`${prefix}-filter-chips`);
  if (!state || !host) return;

  const chips = [];
  for (const f of state.fields) {
    for (const o of f.options) {
      if (state.sel[f.key].has(o.value)) {
        chips.push(`<button type="button" class="filter-chip" data-field="${esc(f.key)}" data-value="${esc(o.value)}"
                      title="Remove ${esc(f.label)} filter: ${esc(o.label)}"
                      aria-label="Remove ${esc(f.label)} filter ${esc(o.label)}">
                      <span class="filter-chip-text">${esc(o.label)}</span><span aria-hidden="true">&times;</span>
                    </button>`);
      }
    }
  }
  if (state.from || state.to) {
    chips.push(`<button type="button" class="filter-chip" data-field="__date"
                  title="Remove date range filter" aria-label="Remove date range filter">
                  <span class="filter-chip-text">${esc(dateRangeLabel(state))}</span><span aria-hidden="true">&times;</span>
                </button>`);
  }
  if ((state.q || "").trim()) {
    chips.push(`<button type="button" class="filter-chip" data-field="__search"
                  title="Clear search" aria-label="Clear search">
                  <span class="filter-chip-text">Search: ${esc(state.q.trim())}</span><span aria-hidden="true">&times;</span>
                </button>`);
  }

  host.innerHTML = chips.length
    ? `<span class="filter-chips-label muted small">Active filters:</span>${chips.join("")}`
    : "";
}

function wireFilterBar(prefix, onChange) {
  const bar = document.getElementById(`${prefix}-filter-bar`);
  const state = filterStates.get(prefix);
  if (!bar || !state) return;

  const closeAll = (except) => {
    bar.querySelectorAll(".filter-pop").forEach((pop) => {
      if (pop === except) return;
      pop.hidden = true;
      const btn = pop.parentElement.querySelector(".filter-trigger");
      if (btn) btn.setAttribute("aria-expanded", "false");
    });
  };

  // Trigger buttons open their own popover and close any other.
  bar.querySelectorAll(".filter-dd").forEach((dd) => {
    const btn = dd.querySelector(".filter-trigger");
    const pop = dd.querySelector(".filter-pop");
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const willOpen = pop.hidden;
      closeAll(pop);
      pop.hidden = !willOpen;
      btn.setAttribute("aria-expanded", String(willOpen));
      if (!willOpen) return;
      positionFilterPop(dd, pop);
      // Focus goes where typing is most likely to be useful: the search
      // box when there is one, otherwise the first option. Focus is not
      // trapped -- Tab continues out of the popover normally.
      const search = dd.querySelector(".filter-search");
      if (search) {
        search.focus();
        search.select();
      } else {
        const first = dd.querySelector('.filter-opt:not([hidden]) input[type="checkbox"]');
        if (first) first.focus();
      }
    });
  });

  // Type-ahead: filters which options are VISIBLE only (see
  // filterSearchApply) -- selections are untouched.
  bar.querySelectorAll(".filter-search").forEach((input) => {
    const dd = input.closest(".filter-dd");
    input.addEventListener("input", () => filterSearchApply(dd));
    // Keep typing (and the native clear "x") from closing the popover.
    input.addEventListener("click", (e) => e.stopPropagation());
    input.addEventListener("keydown", (e) => {
      if (e.key === "Escape") return; // let the bar-level Escape handler close it
      e.stopPropagation();
    });
  });

  // Checkbox toggles write straight into the shared state.
  bar.querySelectorAll('.filter-pop-list input[type="checkbox"]').forEach((cb) => {
    cb.addEventListener("change", () => {
      const set = state.sel[cb.dataset.field];
      if (cb.checked) set.add(cb.value);
      else set.delete(cb.value);
      refreshFilterBar(prefix, onChange);
    });
  });

  // Per-dropdown Select all / Clear.
  bar.querySelectorAll(".filter-pop .filter-pop-actions [data-act]").forEach((btn) => {
    const act = btn.dataset.act;
    if (act !== "all" && act !== "none") return;
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const dd = btn.closest(".filter-dd");
      const key = dd.dataset.field;
      // Scoped to what the search currently shows: with a term typed,
      // "Select all" means "all of these matches", which is the obvious
      // reading and the useful one. With no term every option is
      // visible, so this is a plain select-all/clear.
      const rows = Array.from(dd.querySelectorAll(".filter-opt")).filter((r) => !r.hidden);
      rows.forEach((row) => {
        const cb = row.querySelector('input[type="checkbox"]');
        cb.checked = act === "all";
        if (act === "all") state.sel[key].add(cb.value);
        else state.sel[key].delete(cb.value);
      });
      refreshFilterBar(prefix, onChange);
    });
  });

  // Date popover Apply / Clear.
  const dateDD = bar.querySelector('.filter-dd[data-field="__date"]');
  if (dateDD) {
    // Restore any previously-applied range into the inputs, so a bar
    // re-rendered by a tab switch shows the range it's actually applying.
    ["from-d", "from-t", "to-d", "to-t"].forEach((s) => {
      const el = document.getElementById(`${prefix}-f-${s}`);
      if (el && state.raw[s]) el.value = state.raw[s];
    });

    dateDD.querySelector('[data-act="apply-date"]').addEventListener("click", (e) => {
      e.stopPropagation();
      ["from-d", "from-t", "to-d", "to-t"].forEach((s) => {
        const el = document.getElementById(`${prefix}-f-${s}`);
        state.raw[s] = el ? el.value : "";
      });
      state.from = readDateTime(prefix, "from");
      state.to = readDateTime(prefix, "to");
      dateDD.querySelector(".filter-pop").hidden = true;
      dateDD.querySelector(".filter-trigger").setAttribute("aria-expanded", "false");
      refreshFilterBar(prefix, onChange);
    });
    dateDD.querySelector('[data-act="clear-date"]').addEventListener("click", (e) => {
      e.stopPropagation();
      ["from-d", "from-t", "to-d", "to-t"].forEach((s) => {
        const el = document.getElementById(`${prefix}-f-${s}`);
        if (el) el.value = "";
        state.raw[s] = "";
      });
      state.from = null;
      state.to = null;
      refreshFilterBar(prefix, onChange);
    });
    // Keep clicks inside the date popover from bubbling to the
    // close-on-outside-click handler below.
    dateDD.querySelector(".filter-pop").addEventListener("click", (e) => e.stopPropagation());
  }

  // Chips remove exactly one selection (or the whole date range).
  document.getElementById(`${prefix}-filter-chips`).addEventListener("click", (e) => {
    const chip = e.target.closest(".filter-chip");
    if (!chip) return;
    if (chip.dataset.field === "__search") {
      state.q = "";
      const q = document.getElementById(`${prefix}-f-q`);
      if (q) q.value = "";
      refreshFilterBar(prefix, onChange);
      return;
    }
    if (chip.dataset.field === "__date") {
      ["from-d", "from-t", "to-d", "to-t"].forEach((s) => {
        const el = document.getElementById(`${prefix}-f-${s}`);
        if (el) el.value = "";
        state.raw[s] = "";
      });
      state.from = null;
      state.to = null;
    } else {
      state.sel[chip.dataset.field].delete(chip.dataset.value);
      const cb = bar.querySelector(`.filter-pop-list input[data-field="${CSS.escape(chip.dataset.field)}"][value="${CSS.escape(chip.dataset.value)}"]`);
      if (cb) cb.checked = false;
    }
    refreshFilterBar(prefix, onChange);
  });

  // Filtering is entirely client-side over data the tab already loaded,
  // so there is no network call per keystroke. The debounce exists only
  // to avoid re-rendering a large table on every character.
  const qInput = document.getElementById(`${prefix}-f-q`);
  if (qInput) {
    let timer = null;
    qInput.addEventListener("input", () => {
      state.q = qInput.value;
      clearTimeout(timer);
      timer = setTimeout(() => refreshFilterBar(prefix, onChange), 120);
    });
  }

  document.getElementById(`${prefix}-f-clear`).addEventListener("click", () => {
    state.fields.forEach((f) => state.sel[f.key].clear());
    state.from = null;
    state.to = null;
    state.raw = {};
    state.q = "";
    const q = document.getElementById(`${prefix}-f-q`);
    if (q) q.value = "";
    bar.querySelectorAll('input[type="checkbox"]').forEach((cb) => (cb.checked = false));
    bar.querySelectorAll('input[type="date"], input[type="time"]').forEach((el) => (el.value = ""));
    closeAll(null);
    refreshFilterBar(prefix, onChange);
  });

  // Keeping the popover open while ticking boxes is the point of the
  // stopPropagation here -- only clicks outside any popover dismiss.
  bar.querySelectorAll(".filter-pop-list").forEach((list) => list.addEventListener("click", (e) => e.stopPropagation()));
  document.addEventListener("click", () => closeAll(null));
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    const open = bar.querySelector(".filter-pop:not([hidden])");
    if (!open) return;
    closeAll(null);
    const btn = open.parentElement.querySelector(".filter-trigger");
    if (btn) btn.focus();
  });

  refreshFilterBar(prefix, null);
}

// positionFilterPop flips a popover to right-aligned when opening it
// left-aligned would push it past the viewport edge, so a dropdown near
// the right of the bar stays fully visible instead of being clipped.
function positionFilterPop(dd, pop) {
  pop.classList.remove("align-right");
  const r = pop.getBoundingClientRect();
  if (r.right > window.innerWidth - 8) pop.classList.add("align-right");
}

// readDateTime combines the date + time inputs of one bound into a Date,
// or null if no date was given (a time alone has nothing to anchor to).
// An empty time defaults to 00:00:00 for `from` and 23:59:59 for `to`,
// so picking whole days does the obviously-intended thing.
function readDateTime(prefix, which) {
  const d = (document.getElementById(`${prefix}-f-${which}-d`) || {}).value || "";
  const t = (document.getElementById(`${prefix}-f-${which}-t`) || {}).value || "";
  if (!d) return null;
  const time = t || (which === "from" ? "00:00:00" : "23:59:59");
  // Same construction the previous datetime-local control used: the
  // string is parsed in the browser's local time zone and compared
  // against each record's absolute timestamp, so bounds are entered in
  // local time exactly as before. Deliberately unchanged -- see
  // readFilterBar's note.
  const parsed = new Date(`${d}T${time}`);
  return isNaN(parsed.getTime()) ? null : parsed;
}

// readFilterBar returns the live state object for prefix. Fields this
// tab didn't configure are absent, and their predicates (selMatches /
// selMatchesAny) treat that as "no filter", so an unconfigured field is
// a no-op exactly as before.
//
// Time bounds keep the original semantics: the value is read in the
// browser's local time zone and compared against each record's own
// absolute timestamp. That comparison is instant-against-instant and is
// intentionally unchanged from the previous datetime-local controls.
function readFilterBar(prefix) {
  const state = filterStates.get(prefix);
  if (!state) return { from: null, to: null };
  return { ...state.sel, from: state.from, to: state.to, q: (state.q || "").trim().toLowerCase() };
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
    const [, caseId, rawTab] = caseMatch;
    // Overview is the landing view now that it is a destination rather
    // than several screens of scrolling above every other view.
    const tab = rawTab || "overview";
    // Same case already on screen: swap just the tab body. Falls through
    // to a full render when switchTab declines (different case, or the
    // chrome isn't mounted).
    if (renderedCaseId === caseId && renderedTab !== null) {
      switchTab(caseId, tab).then((handled) => {
        if (!handled) renderCaseDetail(caseId, tab);
      });
      return;
    }
    renderCaseDetail(caseId, tab);
    return;
  }
  renderedCaseId = null;
  renderedTab = null;
  tabScroll.clear();
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
      <div id="case-bulk-bar" class="bulk-bar-host"></div>
      <div id="case-list" class="case-list"><p class="empty">Loading...</p></div>
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
          <div class="case-card-head">
            <span class="case-card-name">${esc(c.name)}</span>
            ${statusBadge(c.status)}
          </div>
          ${c.description ? `<div class="muted small case-card-meta">${esc(c.description)}</div>` : ""}
          <div class="muted small mono case-card-meta">${esc(c.id)} &middot; created ${fmtTime(c.created_at)}</div>
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
    // The host reserves its height either way (.bulk-bar-host), so
    // showing/hiding the bar never shifts the list beneath it.
    if (selected.length === 0) {
      bulkBar.innerHTML = "";
      return;
    }
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

  // ---- Application shell (Phase 10B) ----
  //
  // The horizontal tab strip is replaced by a sidebar. Two things follow
  // from that and both matter:
  //
  //  * The case header stays mounted in <main>, so case identity, status
  //    and priority are visible from every view -- an investigator must
  //    never have to remember which case they are reading.
  //  * The panels that used to sit permanently above the tabs (notes,
  //    investigations preview, evidence collections, analysis) move into
  //    an "Overview" view. They were several screens of scrolling in
  //    front of every other tab; as a destination they cost nothing to
  //    reach and nothing to scroll past.
  app.innerHTML = `
    <div class="app-shell">
      ${renderSidebar(caseId, c, tab)}
      <main class="app-main" id="app-main">
        ${renderCaseHeader(caseId, c, summary, staleAnalysis)}
        <div id="tab-content"><p class="empty">Loading...</p></div>
      </main>
    </div>
  `;

  // Data the Overview view needs but that is fetched once, here, with
  // the rest of the case. Held so switching away and back does not
  // refetch what has not changed.
  overviewData = { c, summary, collections, findings, attackTechniques, investigations };

  wireSidebar(caseId);
  wireCaseMetadataControls(caseId);
  document.getElementById("delete-case-btn").addEventListener("click", () =>
    confirmAndDeleteCases([caseId], () => {
      window.location.hash = "#/";
    })
  );

  renderedCaseId = caseId;
  renderedTab = tab;
  await renderTabContent(caseId, tab, collections);
}

// overviewData caches the case-level payloads the Overview view renders,
// so moving between views does not refetch them.
let overviewData = null;

// CASE_NAV is the single definition of the case's navigation: order,
// labels, and the route key each maps to. The sidebar renders from it
// and switchTab marks the active item from it, so the two can never
// disagree about what "findings" means.
const CASE_NAV = [
  { key: "overview", label: "Overview" },
  { key: "evidence", label: "Evidence" },
  { key: "summary", label: "Timeline" },
  { key: "findings", label: "Findings" },
  { key: "investigations", label: "Investigations" },
  { key: "correlations", label: "Activity Chains" },
  { key: "attack", label: "ATT&CK" },
  { key: "audit", label: "Audit History" },
];

// renderSidebar draws the application navigation.
//
// It is a real <nav> of <a href> elements: these DO change location
// (the hash route), so they are links, and middle-click/open-in-new-tab
// keep working. The active item carries aria-current="page".
function renderSidebar(caseId, c, tab) {
  const item = (n) => {
    const active = n.key === tab;
    return `<a class="sidenav-item${active ? " active" : ""}" data-tab="${n.key}"
               href="#/cases/${caseId}/${n.key}"${active ? ' aria-current="page"' : ""}>${n.label}</a>`;
  };
  return `
    <a class="skip-link" href="#app-main">Skip to main content</a>
    <button type="button" class="sidebar-toggle" id="sidebar-toggle"
            aria-expanded="false" aria-controls="sidebar" aria-label="Open navigation menu">
      <span class="sidebar-toggle-bars" aria-hidden="true"></span>
      <span>Menu</span>
    </button>
    <div class="sidebar-scrim" id="sidebar-scrim" hidden></div>
    <aside class="sidebar" id="sidebar">
      <div class="sidebar-brand">Tracefall</div>
      <nav class="sidenav" aria-label="Case navigation">
        <div class="sidenav-group">
          <div class="sidenav-heading" id="sidenav-case-heading">Case</div>
          <div class="sidenav-case" title="${esc(c.name)}">${esc(c.name)}</div>
          ${CASE_NAV.map(item).join("")}
        </div>
        <div class="sidenav-group">
          <div class="sidenav-heading">System</div>
          <a class="sidenav-item" href="#/">All Cases</a>
        </div>
      </nav>
    </aside>`;
}

// wireSidebar handles the small-viewport menu.
//
// aria-expanded tracks the real state, focus moves into the panel when
// it opens and back to the button when it closes, Escape closes it, and
// choosing a destination closes it -- a menu that stayed open over the
// content it just navigated to would hide the answer.
function wireSidebar(caseId) {
  const toggle = document.getElementById("sidebar-toggle");
  const sidebar = document.getElementById("sidebar");
  const scrim = document.getElementById("sidebar-scrim");
  if (!toggle || !sidebar) return;

  toggle.addEventListener("click", () => setSidebarOpen(!document.body.classList.contains("sidebar-open")));
  scrim.addEventListener("click", () => closeSidebarAndRestoreFocus());
  sidebar.addEventListener("click", (e) => {
    if (e.target.closest("a")) setSidebarOpen(false);
  });
}

// setSidebarOpen looks its elements up at CALL TIME rather than closing
// over them.
//
// The sidebar is re-rendered on every case render, so a handler that
// captured the elements would keep driving a detached toggle from a
// previous render: Escape closed the menu (the body class is global) but
// set aria-expanded on an element no longer in the document, leaving the
// real button announcing "expanded" over a closed menu, and moving focus
// to a detached node.
function setSidebarOpen(open) {
  const toggle = document.getElementById("sidebar-toggle");
  const sidebar = document.getElementById("sidebar");
  const scrim = document.getElementById("sidebar-scrim");
  document.body.classList.toggle("sidebar-open", open);
  if (toggle) {
    toggle.setAttribute("aria-expanded", String(open));
    toggle.setAttribute("aria-label", open ? "Close navigation menu" : "Open navigation menu");
  }
  if (scrim) scrim.hidden = !open;
  if (open && sidebar) sidebar.querySelector(".sidenav-item")?.focus();
}

function closeSidebarAndRestoreFocus() {
  setSidebarOpen(false);
  document.getElementById("sidebar-toggle")?.focus();
}

// Registered ONCE for the life of the page, not per render -- see
// setSidebarOpen. Re-registering per render accumulated a listener for
// every case ever opened.
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && document.body.classList.contains("sidebar-open")) {
    closeSidebarAndRestoreFocus();
  }
});

// renderCaseHeader is the always-visible case identity band.
//
// Two rows by design (section 15): identity and actions on top,
// metadata below. Both wrap rather than overflow, so a narrow viewport
// stacks them instead of introducing a horizontal scrollbar -- and
// nothing is hidden to achieve that, because case status and priority
// are forensic context, not decoration.
function renderCaseHeader(caseId, c, summary, staleAnalysis) {
  return `
    <header class="case-header">
      <div class="case-header-top">
        <div class="case-identity">
          <h1>${esc(c.name)}</h1>
          ${c.description ? `<div class="muted small">${esc(c.description)}</div>` : ""}
          <div class="muted small mono case-id">${esc(c.id)}</div>
        </div>
        <div class="case-header-actions">
          ${statusBadge(c.status)}
          <div class="dropdown">
            <button type="button" class="secondary small" id="export-case-btn"
                    aria-haspopup="true" aria-expanded="false" aria-controls="export-menu">Export &#9662;</button>
            <div id="export-menu" class="dropdown-menu hidden" role="menu" aria-labelledby="export-case-btn">
              <a role="menuitem" href="/api/cases/${caseId}/export" target="_blank" rel="noopener">Case JSON</a>
              <a role="menuitem" href="/api/cases/${caseId}/export/timeline.csv" target="_blank" rel="noopener">Timeline CSV</a>
              <a role="menuitem" href="/api/cases/${caseId}/export/findings.csv" target="_blank" rel="noopener">Findings CSV</a>
            </div>
          </div>
          <button type="button" class="danger small" id="delete-case-btn">Delete Case</button>
        </div>
      </div>

      <div class="case-meta">
        <div class="case-meta-item">
          <label class="muted small" for="case-status-select">Case status</label>
          <select id="case-status-select" class="filter-input">
            ${["open", "investigating", "contained", "closed"].map((st) => `<option value="${st}" ${c.case_status === st ? "selected" : ""}>${st[0].toUpperCase() + st.slice(1)}</option>`).join("")}
          </select>
        </div>
        <div class="case-meta-item">
          <label class="muted small" for="case-priority-select">Priority</label>
          <select id="case-priority-select" class="filter-input">
            ${["low", "medium", "high", "critical"].map((pr) => `<option value="${pr}" ${c.priority === pr ? "selected" : ""}>${pr[0].toUpperCase() + pr.slice(1)}</option>`).join("")}
          </select>
        </div>
        <div class="case-meta-item">
          <span class="muted small">Created</span>
          <span class="small">${esc(fmtTime(c.created_at))}</span>
        </div>
        <div class="case-meta-item">
          <span class="muted small">Last analyzed</span>
          <span class="small">${c.analyzed_at ? esc(fmtTime(c.analyzed_at)) : "Never analyzed"}</span>
        </div>
      </div>
      <div id="case-metadata-error"></div>
      ${
        staleAnalysis
          ? `<div class="stale-banner">
        <strong>Evidence changed since last analysis</strong>
        <div>The findings, correlations, investigations, and ATT&amp;CK techniques shown on every view are from the analysis run at ${esc(fmtTime(c.analyzed_at))} and do not reflect evidence added or removed since. Re-run analysis (Overview &rarr; Evidence Collections) before treating these as current.</div>
      </div>`
          : ""
      }
    </header>`;
}

// renderOverviewTab is the case's landing view: the panels that used to
// sit permanently above the tab strip. Everything it renders and wires
// is unchanged -- only where it lives has moved.
function renderOverviewTab(content, caseId) {
  if (!overviewData) {
    content.innerHTML = `<p class="empty">Loading...</p>`;
    return;
  }
  const { c, summary, collections, findings, attackTechniques, investigations } = overviewData;

  content.innerHTML = `
    <div class="panel">
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
        <h3>Upload evidence</h3>
        <p class="muted small">Upload a ZIP archive of a KAPE triage collection, or a single AD1 forensic image (FTK Imager's logical/custom-content format, detected from the file's contents, not just its <code>.ad1</code> extension). Tracefall safely inspects it and catalogs every file inside (EvtxECmd/PECmd/RECmd CSV, Scheduled Task XML, and anything else, or the files inside the AD1) without extracting or parsing anything yet -- you choose which discovered files to import next.</p>
        <div class="row">
          <input type="file" id="upload-file" accept=".zip,.ad1,application/zip" />
          <button id="upload-btn">Upload Evidence</button>
        </div>
        <div id="upload-error"></div>
        <div id="upload-progress"></div>

        <details style="margin-top:16px">
          <summary class="muted small" style="cursor:pointer">Advanced: ingest from a local path instead</summary>
          <p class="muted small">For local/dev use, when the evidence is already on the machine running Tracefall: point this at a KAPE-style directory (e.g. the bundled synthetic dataset at <code>testdata/synthetic_case</code>), or directly at a single AD1 file (e.g. <code>DiskDrigger.ad1</code>) -- detected the same way an upload is.</p>
          <div class="row">
            <div style="flex:1"><input id="ingest-path" placeholder="/path/to/evidence or /path/to/image.ad1" value="testdata/synthetic_case" /></div>
            <button id="ingest-btn" class="secondary">Discover</button>
          </div>
          <div id="ingest-error"></div>
          <div id="ingest-progress"></div>
        </details>
      </div>
      <div id="collections-list">${renderCollectionsList(caseId, collections)}</div>
    </div>

    <div class="panel" id="analysis-panel">${renderAnalysisAction(c, summary)}</div>
  `;

  wireEvidenceHeader(caseId);
  wireAnalysisAction(caseId);
  wireCollectionIntegrity(caseId, document.getElementById("collections-list"));
  renderNotesSection(document.getElementById("case-notes"), caseId, "case", caseId);
  renderTagsSection(document.getElementById("case-tags"), caseId, "case", caseId);
}

// renderTabContent renders exactly one tab into #tab-content. Split out
// of renderCaseDetail so switching tabs can re-render only this, leaving
// the page chrome (header, evidence, analysis panels) untouched -- see
// switchTab.
async function renderTabContent(caseId, tab, collections) {
  const content = document.getElementById("tab-content");
  if (!content) return;
  try {
    switch (tab) {
      case "overview":
        renderOverviewTab(content, caseId);
        break;
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

// switchTab handles a tab change within the case already on screen.
//
// The whole point is NOT re-running renderCaseDetail: that starts by
// blanking #app to "Loading case..." while it refetches, which collapses
// the document to ~190px. The browser clamps scrollY to 0 against that
// height, and the position is gone before the new content restores the
// height -- which is exactly the "clicking a tab jumps me back to the
// top" the investigator sees after scrolling deep into a Timeline.
//
// Instead the chrome stays mounted and only #tab-content is replaced.
// Each tab's scroll offset is remembered on the way out and restored on
// the way back in, so returning to a tab returns to where you were.
async function switchTab(caseId, tab) {
  if (renderedCaseId !== caseId) return false; // different case -- full render needed
  const content = document.getElementById("tab-content");
  if (!content) return false;

  tabScroll.set(renderedTab, window.scrollY);
  renderedTab = tab;

  document.querySelectorAll(".sidenav-item[data-tab]").forEach((a) => {
    const active = a.dataset.tab === tab;
    a.classList.toggle("active", active);
    if (active) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });

  // Hold the content box at its current height while the new tab loads,
  // so the page can't collapse (and lose scroll) in the gap between
  // clearing the old content and the new content arriving.
  const heightFloor = content.getBoundingClientRect().height;
  content.style.minHeight = `${heightFloor}px`;
  try {
    await renderTabContent(caseId, tab, currentCollections);
  } finally {
    content.style.minHeight = "";
  }

  const saved = tabScroll.get(tab);
  if (saved !== undefined) {
    // Only restore if the new content is actually tall enough; otherwise
    // leave the browser's own clamped position rather than fighting it.
    const max = document.documentElement.scrollHeight - window.innerHeight;
    window.scrollTo({ top: Math.min(saved, Math.max(max, 0)), behavior: "instant" });
  }
  return true;
}

// ---------------- Pagination (Phase 10B) ----------------
//
// ONE pagination implementation, shared by Evidence, Timeline, Findings
// and Investigations. Four screens needing the same control is exactly
// how four subtly different controls get written -- one that clamps an
// out-of-range page and one that blanks, one that resets on filter and
// one that does not -- so the behaviour is defined once here.
//
// The rule that matters forensically: a page is a VIEW, never a filter
// on what exists. Every pager states the true total of matching records,
// so a page boundary is never mistaken for the end of the evidence.

// pagerStates holds one state object per pager, keyed by prefix. Like
// filterStates it is scoped, so paging one case's Findings never
// restores a page number from a different case.
const pagerStates = new Map();

// pagerFor returns the live state for a pager, creating it (or replacing
// a state belonging to a different scope) as needed.
function pagerFor(prefix, cfg) {
  const sizes = cfg.sizes || [25, 50, 100];
  const scope = cfg.scope || "";
  const stored = pagerStates.get(prefix);
  if (stored && stored.scope === scope) return stored;
  const fresh = {
    scope,
    sizes,
    page: 1,
    pageSize: sizes.includes(cfg.defaultSize) ? cfg.defaultSize : sizes[0],
  };
  pagerStates.set(prefix, fresh);
  return fresh;
}

// resetPage sends a pager back to page 1. Called whenever the RESULT SET
// changes -- a filter, a search, a page-size change -- because staying on
// page 7 of a result that now has two pages shows an empty screen and
// reads as "no results".
function resetPage(prefix) {
  const st = pagerStates.get(prefix);
  if (st) st.page = 1;
}

// paginate slices the current page out of an already-filtered, ordered
// array, clamping the page if the set shrank underneath it.
function paginate(prefix, items) {
  const st = pagerStates.get(prefix);
  if (!st) return { items, page: 1, pageSize: items.length, total: items.length, totalPages: 1, from: 1, to: items.length };
  const total = items.length;
  const totalPages = Math.max(1, Math.ceil(total / st.pageSize));
  if (st.page > totalPages) st.page = totalPages;
  if (st.page < 1) st.page = 1;
  const start = (st.page - 1) * st.pageSize;
  const slice = items.slice(start, start + st.pageSize);
  return {
    items: slice,
    page: st.page,
    pageSize: st.pageSize,
    total,
    totalPages,
    from: total === 0 ? 0 : start + 1,
    to: start + slice.length,
  };
}

// renderPager draws the control. `p` is either the object paginate()
// returned (client-side pagers) or the same shape built from a server
// page response, so both kinds render identically.
//
// It is a <nav> with labelled buttons rather than links: these change a
// view, not a location, and a screen reader announcing "link" for
// something that does not navigate is a lie.
function renderPager(prefix, p, opts) {
  const o = opts || {};
  const noun = o.noun || "records";
  const sizes = (pagerStates.get(prefix) || {}).sizes || [25, 50, 100];
  const first = p.page <= 1;
  const last = p.page >= p.totalPages;
  const btn = (action, label, aria, disabled) =>
    `<button type="button" class="pager-btn" data-pager="${esc(prefix)}" data-page-action="${action}"
             aria-label="${esc(aria)}"${disabled ? " disabled" : ""}>${label}</button>`;

  return `
    <nav class="pager" data-total-pages="${p.totalPages}" aria-label="${esc(o.label || "Pagination")}">
      <div class="pager-summary small muted" role="status" aria-live="polite">
        ${p.total === 0
          ? `No ${esc(noun)}`
          : `Showing <strong>${fmtCount(p.from)}–${fmtCount(p.to)}</strong> of <strong>${fmtCount(p.total)}</strong> ${esc(noun)}`}
      </div>
      <div class="pager-controls">
        <label class="pager-size small muted">
          <span>Per page</span>
          <select class="filter-input" data-pager="${esc(prefix)}" data-page-size aria-label="Records per page">
            ${sizes.map((n) => `<option value="${n}"${n === p.pageSize ? " selected" : ""}>${n}</option>`).join("")}
          </select>
        </label>
        <div class="pager-nav">
          ${btn("first", "&laquo;", "First page", first)}
          ${btn("prev", "&lsaquo;", "Previous page", first)}
          <span class="pager-position small" aria-current="page">Page ${fmtCount(p.page)} of ${fmtCount(p.totalPages)}</span>
          ${btn("next", "&rsaquo;", "Next page", last)}
          ${btn("last", "&raquo;", "Last page", last)}
        </div>
      </div>
    </nav>`;
}

// wirePager delegates from a container, so the pager can be re-rendered
// as part of the content it pages without needing to be re-wired.
//
// onChange is called after the state has already been updated, so a
// caller only ever has to re-render.
function wirePager(prefix, container, onChange) {
  if (!container || container.dataset[`pagerWired${prefix}`]) return;
  container.dataset[`pagerWired${prefix}`] = "1";

  container.addEventListener("click", (e) => {
    const b = e.target.closest(`.pager-btn[data-pager="${prefix}"]`);
    if (!b || b.disabled) return;
    const st = pagerStates.get(prefix);
    if (!st) return;
    const totalPages = Number(b.closest(".pager").dataset.totalPages || 1);
    switch (b.dataset.pageAction) {
      case "first": st.page = 1; break;
      case "prev": st.page = Math.max(1, st.page - 1); break;
      case "next": st.page = st.page + 1; break;
      case "last": st.page = totalPages; break;
    }
    onChange();
  });

  container.addEventListener("change", (e) => {
    const sel = e.target.closest(`select[data-pager="${prefix}"][data-page-size]`);
    if (!sel) return;
    const st = pagerStates.get(prefix);
    if (!st) return;
    st.pageSize = Number(sel.value);
    // A page-size change re-cuts the whole result, so the old page
    // number means nothing against the new pages.
    st.page = 1;
    onChange();
  });
}

// ---------------- Evidence Collections header ----------------

// FAILED_COLLECTION_NOTE explains a collection that only a database
// written by an older Tracefall version can contain. Discovery is now
// atomic -- it either creates a fully-cataloged collection or creates
// nothing -- so no new collection can reach this state. The note exists
// so an investigator meeting a legacy row understands it is a dead end
// holding no evidence, rather than assuming evidence was lost.
const FAILED_COLLECTION_NOTE = `<p class="collection-failed-note small">This collection was left behind by a discovery that never finished cataloging. It contains no evidence and cannot be imported or analyzed. Add the evidence again to create a new collection; this one can be ignored.</p>`;

function renderCollectionsList(caseId, collections) {
  if (collections.length === 0) {
    // Shown for a genuinely empty case AND after a failed discovery --
    // a failed discovery creates no collection (see
    // internal/store.Store.CreateCollectionWithSourceFiles), so the case
    // correctly remains empty rather than showing a phantom FAILED row.
    return `<p class="empty">No evidence yet. Add evidence to begin discovery -- click "+ Add Evidence" to upload a KAPE package or an AD1 forensic image.</p>`;
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
        ${col.ingestion_status === "failed" ? FAILED_COLLECTION_NOTE : ""}
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
        // The backend guarantees these are arrays (see
        // internal/store.Store.ListSourceFilesByCollection). This is the
        // secondary safety net for a database written by an older build,
        // where a collection with no files served `"source_files": null`
        // and this panel threw "Cannot read properties of null (reading
        // 'map')" -- taking the whole Evidence tab down with it.
        const files = Array.isArray(cd.source_files) ? cd.source_files : [];
        detail.innerHTML = `
          <div class="integrity-grid">
            <div><span class="muted small">Collection ID</span><div class="mono small">${esc(cd.collection_id)}</div></div>
            <div><span class="muted small">Evidence package hash (SHA-256)</span><div class="mono small">${cd.archive_hash ? esc(cd.archive_hash) : "Unknown"}</div></div>
            <div><span class="muted small">Evidence integrity (SHA-512)</span>${integrityHashCell(cd.integrity_sha512)}</div>
            <div><span class="muted small">Hosts observed</span><div class="small">${cd.hosts_observed && cd.hosts_observed.length ? esc(cd.hosts_observed.join(", ")) : "Unknown"}</div></div>
            <div><span class="muted small">Event time range</span><div class="small">${cd.earliest_event ? esc(fmtTime(cd.earliest_event)) + " &rarr; " + esc(fmtTime(cd.latest_event)) : "Unknown"}${cd.undated_events ? `<div class="muted small" title="These events are real observations, but their artifact records no time, so they fall outside the range above rather than being placed on it.">+ ${cd.undated_events} event(s) with no timestamp</div>` : ""}</div></div>
          </div>
          <div class="muted small" style="margin-top:8px">Parser coverage</div>
          ${
            cd.parser_coverage && cd.parser_coverage.length
              ? `<div class="table-wrap"><table><thead><tr><th>Parser</th><th>Artifact type</th><th>Files</th><th>Events</th></tr></thead><tbody>
                  ${cd.parser_coverage.map((p) => `<tr><td class="mono small">${esc(p.parser)}</td><td class="small">${esc(artifactLabel(p.artifact_type))}</td><td class="small">${p.file_count}</td><td class="small">${p.event_count}</td></tr>`).join("")}
                 </tbody></table></div>`
              : `<p class="empty">Unknown -- no files imported from this collection yet.</p>`
          }
          <div class="muted small" style="margin-top:8px">Per-file integrity</div>
          ${
            files.length
              ? `<div class="table-wrap"><table class="data-table">
            <thead><tr><th>Filename</th><th>SHA-256</th><th>Size</th><th>Discovered</th><th>Imported</th><th>Status</th><th>Events</th></tr></thead>
            <tbody>
              ${files
                .map(
                  (sf) => `<tr>
                <td class="mono small">${esc(sf.original_filename)}</td>
                <td class="mono small">${sha256Cell(sf, "Unknown")}</td>
                <td class="small">${fmtBytes(sf.size_bytes)}</td>
                <td class="small">${esc(fmtTime(sf.discovered_at))}</td>
                <td class="small">${sf.imported_at ? esc(fmtTime(sf.imported_at)) : "-"}</td>
                <td class="small">${esc(sf.import_status)}</td>
                <td class="small">${sf.event_count || "-"}</td>
              </tr>`
                )
                .join("")}
            </tbody>
          </table></div>`
              : `<p class="empty">No files recorded in this collection.${
                  cd.ingestion_status === "failed"
                    ? " This collection was left behind by a discovery that failed before it finished cataloging (an older Tracefall version); it holds no evidence and cannot be imported."
                    : ""
                }</p>`
          }
        `;
        detail.dataset.loaded = "1";
        wireIntegrityHash(detail);
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

  // The menu is absolutely positioned (see .dropdown-menu), so opening it
  // overlays the page instead of growing it -- it previously sat in normal
  // flow and shoved everything below it down by its own height.
  const setExportOpen = (open) => {
    exportMenu.classList.toggle("hidden", !open);
    exportBtn.setAttribute("aria-expanded", String(open));
  };
  exportBtn.addEventListener("click", (e) => {
    e.stopPropagation(); // don't immediately re-close via the document handler below
    setExportOpen(exportMenu.classList.contains("hidden"));
  });
  // Clicking anywhere outside closes it; clicks on the menu's own links
  // are allowed to proceed (and close it, since navigation follows).
  document.addEventListener("click", (e) => {
    if (!exportMenu.classList.contains("hidden") && !exportMenu.contains(e.target)) setExportOpen(false);
  });
  exportMenu.addEventListener("click", () => setExportOpen(false));
  // Escape closes and returns focus to the trigger, so keyboard users
  // aren't stranded inside a dismissed menu.
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !exportMenu.classList.contains("hidden")) {
      setExportOpen(false);
      exportBtn.focus();
    }
  });
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
    <div class="table-wrap"><table class="data-table">
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
      errBox.innerHTML = errorBox(new Error("Choose a .zip or .ad1 file first"));
      return;
    }

    uploadBtn.disabled = true;
    uploadBtn.textContent = "Uploading...";
    // Four stages, each corresponding to work that actually happens:
    // bytes leaving the browser, the server hashing and identifying the
    // upload, discovery cataloging every file inside it, and the
    // selection screen being ready. See renderUploadProgress.
    let stage = { phase: "uploading", loaded: 0, total: file.size, lengthComputable: file.size > 0 };
    const paint = () => (progress.innerHTML = renderUploadProgress(stage));
    paint();

    try {
      const disc = await apiUpload(`/cases/${caseId}/evidence`, file, (p) => {
        if (p.uploadComplete) {
          // Every byte is on the server; it is now hashing and
          // identifying the evidence. Staying at "100% uploading" here
          // would tell the investigator the operation had finished when
          // the slowest part may just have started.
          stage = { phase: "inspecting" };
        } else {
          stage = { phase: "uploading", loaded: p.loaded, total: p.total, lengthComputable: p.lengthComputable };
        }
        paint();
      });
      stage = { phase: "ready" };
      progress.innerHTML = renderDiscoveryResults(disc);
      wireDiscoverySelection(progress, caseId, disc.collection.collection_id, disc);
    } catch (e) {
      errBox.innerHTML = errorBox(e);
      progress.innerHTML = "";
    } finally {
      uploadBtn.disabled = false;
      uploadBtn.textContent = "Upload Evidence";
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
      wireDiscoverySelection(progress, caseId, disc.collection.collection_id, disc);
    } catch (e) {
      errBox.innerHTML = errorBox(e);
    } finally {
      ingestBtn.disabled = false;
      ingestBtn.textContent = "Discover";
    }
  });
}

// renderUploadProgress shows where a browser upload actually is.
//
// Four stages, each backed by real work:
//
//   uploading   bytes leaving the browser -- a genuine percentage from
//               XMLHttpRequest's upload progress events, never a timer
//   inspecting  every byte is on the server, which is hashing (SHA-256
//               for duplicate detection and SHA-512 for integrity) and
//               identifying the container. Indeterminate: the server
//               does not stream progress for this step, so no percentage
//               is invented for it
//   cataloging  discovery is walking and classifying every file inside
//   ready       the selection screen is up
//
// The upload bar is NEVER left sitting at 100% while the server works:
// that would report the operation as finished when the slowest part may
// have just started.
const UPLOAD_STAGES = [
  { key: "uploading", label: "Uploading" },
  { key: "inspecting", label: "Inspecting" },
  { key: "cataloging", label: "Cataloging" },
  { key: "ready", label: "Ready for selection" },
];

function renderUploadProgress(stage) {
  const activeIndex = UPLOAD_STAGES.findIndex((s) => s.key === stage.phase);
  const steps = UPLOAD_STAGES.map((s, i) => {
    const state = i < activeIndex ? "done" : i === activeIndex ? "active" : "pending";
    return `<span class="upload-stage upload-stage-${state}">${
      state === "done" ? "&check; " : ""
    }${esc(s.label)}</span>`;
  }).join('<span class="upload-stage-sep" aria-hidden="true">&rsaquo;</span>');

  const uploading = stage.phase === "uploading";
  const known = uploading && stage.lengthComputable && stage.total > 0;
  const pct = known ? Math.floor((stage.loaded / stage.total) * 100) : -1;

  return `
    <div class="panel import-progress" style="background:var(--bg-panel); margin-top:var(--space-3); margin-bottom:0">
      <h3>Uploading evidence</h3>
      <div class="upload-stages small">${steps}</div>
      <div class="progress-track${pct < 0 ? " indeterminate" : ""}" role="progressbar"
           ${pct < 0 ? 'aria-valuetext="in progress"' : `aria-valuenow="${pct}" aria-valuemin="0" aria-valuemax="100"`}>
        <div class="progress-fill" style="${pct < 0 ? "" : `width:${pct}%`}"></div>
      </div>
      <div class="row between small" style="margin-top:var(--space-2)">
        <span>${pct < 0 ? esc(uploadStageNote(stage.phase)) : `${pct}%`}</span>
        ${
          known
            ? `<span class="muted">${esc(fmtBytes(stage.loaded))} / ${esc(fmtBytes(stage.total))}</span>`
            : ""
        }
      </div>
    </div>`;
}

// uploadStageNote says what is happening whenever there is no honest
// percentage to show.
function uploadStageNote(phase) {
  switch (phase) {
    case "inspecting":
      return "Hashing and identifying the uploaded evidence...";
    case "cataloging":
      return "Cataloging files inside the evidence...";
    case "ready":
      return "Ready";
    default:
      return "Uploading... (total size unknown)";
  }
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

// ---------------- Phase 9A: evidence triage & selection ----------------
//
// The selection screen used to be one table of every discovered file. On
// a KAPE ZIP or an AD1 image that is thousands of rows, of which a
// handful matter, with nothing to say which -- an investigator had no
// way to find the six registry hives inside seven thousand files, and no
// way to know that the eighty-four Prefetch files were being ignored.
//
// This replaces it with a triage view: a coverage summary of what the
// collection actually holds, a compact search/filter toolbar, and a
// table that renders only what the current filter matches.
//
// Two behaviors are load-bearing and easy to get wrong:
//
//   - SELECTION IS NOT THE DOM. Which files are selected lives in a Set
//     of IDs (evidenceSelection), so filtering, searching and re-rendering
//     never lose a selection. A file selected then filtered out stays
//     selected -- and the count says so -- because the investigator chose
//     it and nothing since has unchosen it.
//   - SELECT ALL MEANS THE FILTERED VIEW. Acting on hidden rows would be
//     the single most dangerous thing this screen could do: an
//     investigator who filtered to "Registry" and pressed Select All
//     must not silently queue seven thousand files for import.

// evidenceCatalogs holds the live SELECTION for the collection being
// triaged, keyed by collection ID so the upload and local-path screens
// never read each other's state.
//
// It no longer holds the catalog itself (Phase 10B): the catalog lives
// on the server and arrives one page at a time. What has to persist
// across pages is the selection, and only the selection.
const evidenceCatalogs = new Map();

const PRIORITY_LABELS = { critical: "Critical", high: "High", medium: "Medium", low: "Low", unknown: "Unknown" };

// renderDiscoveryResults is the FILE SELECTION SCREEN.
//
// Phase 10B made it server-paginated. The screen no longer holds the
// catalog: it holds a page of it, plus a SELECTION of stable IDs. That
// split is what lets a 7,000-file image be triaged without the browser
// ever receiving 7,000 rows.
function renderDiscoveryResults(disc) {
  const coverage = disc.coverage || {};
  return `
    <div class="panel" style="background:var(--bg-panel-2); margin-top:12px; margin-bottom:0">
      <h3>Select evidence to import</h3>
      ${renderEvidenceCoverage(coverage)}
      <p class="muted small" style="margin-top:var(--space-3)">
        Only selected files are parsed and imported. Unsupported files are listed with the reason Tracefall cannot read them --
        they are evidence you may still need to collect another way, not broken files.
      </p>

      <div class="evidence-toolbar">
        <input type="search" id="ev-search" class="evidence-search" placeholder="Search evidence..."
               aria-label="Search evidence by filename, path, artifact type or source" autocomplete="off" />
        <div id="ev-filters"></div>
      </div>

      <div class="row evidence-actions">
        <button type="button" class="secondary small" id="ev-select-recommended">Select recommended (<span id="ev-recommended-count">${fmtCount(coverage.recommended || 0)}</span>)</button>
        <button type="button" class="secondary small" id="ev-select-page">Select page</button>
        <button type="button" class="secondary small" id="ev-select-all">Select all matching</button>
        <button type="button" class="secondary small" id="ev-clear">Clear selection</button>
      </div>
      <div id="ev-selection-note"></div>

      <div id="ev-list" class="evidence-list"><p class="empty">Loading evidence...</p></div>
      <div id="ev-pager"></div>

      <div class="row" style="margin-top:var(--space-3); align-items:center; gap:var(--space-3)">
        <button id="import-selected-btn" disabled>Import Selected (<span id="import-selected-count">0</span>)</button>
      </div>
      <div id="import-error"></div>
      <div id="import-progress-panel"></div>
      <div id="import-result"></div>
    </div>`;
}

// rowForDiscoveredFile renders one file as a table row.
//
// The Path column is gone. It was the widest column by far and forced
// the whole table into horizontal scrolling, while being the one field
// nobody reads in full at a glance. The path is still present three
// ways -- truncated under the filename, in the title attribute, and in
// full in the details row -- so nothing forensic was traded away to
// make the table fit.
function rowForDiscoveredFile(f, selected) {
  const canSelect = f.import_status === "discovered" && f.supported;
  const detailsId = `evd-${++cellIdCounter}`;
  return `<tr class="evidence-row${canSelect ? "" : " muted"}" data-id="${esc(f.id)}">
    <td class="ev-check"><input type="checkbox" class="discover-file-checkbox" data-id="${esc(f.id)}"
        aria-label="Select ${esc(f.original_filename)}"
        ${selected ? "checked" : ""} ${canSelect ? "" : "disabled"} /></td>
    <td class="ev-name">
      <div class="mono small ev-filename">${esc(f.original_filename)}</div>
      <div class="muted ev-path" title="${esc(f.path)}">${esc(f.path)}</div>
    </td>
    <td class="small ev-type">${esc(f.type_label || artifactLabel(f.artifact_type))}</td>
    <td class="ev-priority">${priorityBadge(f.priority)}</td>
    <td class="small nowrap num ev-size">${fmtBytes(f.size_bytes)}</td>
    <td class="ev-status">${evidenceStatusBadge(f)}</td>
    <td class="ev-actions">
      <button type="button" class="secondary small ev-details-btn" aria-expanded="false"
              aria-controls="${detailsId}" data-details="${detailsId}">Details</button>
    </td>
  </tr>
  <tr class="evidence-details-row" id="${detailsId}" hidden>
    <td colspan="7">${evidenceDetails(f)}</td>
  </tr>`;
}

// cardForDiscoveredFile is the same record below the 900px breakpoint,
// where a seven-column table cannot fit without either horizontal
// scrolling or unreadable type.
function cardForDiscoveredFile(f, selected) {
  const canSelect = f.import_status === "discovered" && f.supported;
  const detailsId = `evdc-${++cellIdCounter}`;
  return `<article class="evidence-card${canSelect ? "" : " muted"}" data-id="${esc(f.id)}">
    <div class="evidence-card-head">
      <input type="checkbox" class="discover-file-checkbox" data-id="${esc(f.id)}"
             aria-label="Select ${esc(f.original_filename)}"
             ${selected ? "checked" : ""} ${canSelect ? "" : "disabled"} />
      <div class="evidence-card-title">
        <div class="mono small ev-filename">${esc(f.original_filename)}</div>
        <div class="muted ev-path" title="${esc(f.path)}">${esc(f.path)}</div>
      </div>
    </div>
    <div class="evidence-card-meta">
      <span class="small">${esc(f.type_label || artifactLabel(f.artifact_type))}</span>
      ${priorityBadge(f.priority)}
      ${evidenceStatusBadge(f)}
      <span class="small muted nowrap">${fmtBytes(f.size_bytes)}</span>
    </div>
    <button type="button" class="secondary small ev-details-btn" aria-expanded="false"
            aria-controls="${detailsId}" data-details="${detailsId}">Details</button>
    <div class="evidence-card-details" id="${detailsId}" hidden>${evidenceDetails(f)}</div>
  </article>`;
}

function evidenceStatusBadge(f) {
  const canSelect = f.import_status === "discovered" && f.supported;
  if (canSelect) return `<span class="badge status ok-badge">supported</span>`;
  const status = evidenceStatusValue(f);
  return `<span class="badge status${status === "failed" ? " critical" : ""}"${
    f.unsupported_reason ? ` title="${esc(f.unsupported_reason)}"` : ""
  }>${esc(EVIDENCE_STATUS_LABELS[status] || status)}</span>`;
}

// evidenceDetails is where everything the narrower table no longer shows
// as a column still lives, in full and untruncated.
function evidenceDetails(f) {
  const row = (label, value) =>
    value ? `<div class="ev-detail"><span class="muted small">${label}</span><div class="small mono ev-detail-value">${esc(value)}</div></div>` : "";
  return `
    <div class="ev-detail-grid">
      ${row("Full path", f.path)}
      ${row("Artifact type", f.type_label || artifactLabel(f.artifact_type))}
      ${row("Artifact family", f.family_label)}
      ${row("Parser", f.parser)}
      ${row("Forensic priority", PRIORITY_LABELS[f.priority] || f.priority)}
      ${row("Status", EVIDENCE_STATUS_LABELS[evidenceStatusValue(f)] || f.import_status)}
      ${row("Size", fmtBytes(f.size_bytes))}
      ${row("SHA-256", f.sha256)}
      ${row("Embedded hash (from container)", f.embedded_hash)}
      ${row("Source collection", collectionLabel(f.collection_id))}
      ${row("Events imported", f.event_count ? String(f.event_count) : "")}
    </div>
    ${f.unsupported_reason ? `<p class="muted small ev-detail-reason">${esc(f.unsupported_reason)}</p>` : ""}`;
}

// EVIDENCE_STATUS_LABELS maps the status vocabulary the toolbar filters
// on. "Supported"/"Unsupported" is a capability fact; the rest are
// import states -- deliberately in one list because that is the single
// question an investigator asks ("what is the state of this file?").
const EVIDENCE_STATUS_LABELS = {
  supported: "Supported (not imported)",
  unsupported: "Unsupported",
  imported: "Imported",
  duplicate: "Duplicate",
  failed: "Parse error",
};

// evidenceStatusValue collapses a file's capability and import state into
// the one status value the filter offers.
function evidenceStatusValue(f) {
  if (f.import_status === "imported") return "imported";
  if (f.import_status === "duplicate") return "duplicate";
  if (f.import_status === "failed") return "failed";
  return f.supported ? "supported" : "unsupported";
}

// renderEvidenceCoverage summarizes what the collection holds. Every
// number comes from the catalog the server actually built.
function renderEvidenceCoverage(cov) {
  if (!cov || !cov.discovered) return "";
  const buckets = cov.by_type || [];
  return `
    <div class="coverage">
      <div class="coverage-totals">
        <div class="coverage-stat"><div class="n">${fmtCount(cov.discovered)}</div><div class="l">Files discovered</div></div>
        <div class="coverage-stat"><div class="n ok">${fmtCount(cov.supported)}</div><div class="l">Supported</div></div>
        <div class="coverage-stat"><div class="n muted">${fmtCount(cov.unsupported)}</div><div class="l">Unsupported</div></div>
        <div class="coverage-stat"><div class="n muted">${fmtCount(cov.duplicates)}</div><div class="l">Duplicates</div></div>
        ${cov.parse_failed ? `<div class="coverage-stat"><div class="n bad">${fmtCount(cov.parse_failed)}</div><div class="l">Parse errors</div></div>` : ""}
      </div>
      ${
        buckets.length
          ? `<details class="coverage-detail" open>
               <summary class="muted small" style="cursor:pointer">Coverage by artifact type</summary>
               <div class="table-wrap" style="margin-top:var(--space-2)"><table class="data-table">
                 <thead><tr><th>Artifact type</th><th>Priority</th><th class="num">Files</th><th class="num">Supported</th><th>Notes</th></tr></thead>
                 <tbody>${buckets.map(coverageRow).join("")}</tbody>
               </table></div>
             </details>`
          : ""
      }
    </div>`;
}

function coverageRow(b) {
  return `<tr>
    <td class="small">${esc(b.type_label)}</td>
    <td class="small">${priorityBadge(b.priority)}</td>
    <td class="small num">${fmtCount(b.files)}</td>
    <td class="small num">${b.supported ? fmtCount(b.supported_files) : "0"}</td>
    <td class="small muted">${b.reason ? esc(b.reason) : ""}</td>
  </tr>`;
}

// priorityBadge renders forensic triage priority. Deliberately styled
// apart from finding severity: they are different judgements and must
// never be read as the same thing. A HIGH-priority artifact Tracefall
// cannot parse is normal and worth saying out loud.
function priorityBadge(p) {
  if (!p) return "";
  return `<span class="badge prio prio-${esc(p)}">${esc(PRIORITY_LABELS[p] || p)}</span>`;
}

function fmtCount(n) {
  return typeof n === "number" ? n.toLocaleString() : "0";
}

// wireDiscoverySelection powers the triage screen: search, filters,
// pagination, selection, and the import action.
//
// # The selection model (Phase 10B section 4)
//
// Selection is an explicit set of STABLE SOURCE-FILE IDs, held here and
// never in the DOM. That is the whole design, and it is what makes
// paginated selection safe:
//
//   * A checkbox is a view of the set, not the set itself, so a file
//     stays selected when its page is left, when the page size changes,
//     and when a filter hides it.
//   * "Select all matching" asks the SERVER to resolve the current
//     filter to IDs (GET .../files/ids) and adds every one of them. It
//     can never quietly mean "the first 100": the server returns the
//     whole match set, and the count shown is the length of what was
//     actually added.
//   * The alternative -- storing the filter and re-evaluating it at
//     import time -- was rejected. It would let the imported set differ
//     from the set the investigator was looking at when they chose it.
//
// Because a selection can outlive the filter that produced it, a bulk
// selection records the filter it was made under. When the filter later
// changes, the mismatch is stated in plain language with an explicit
// recompute, rather than silently importing files outside the filter on
// screen.
function wireDiscoverySelection(container, caseId, collectionId, disc) {
  const prefix = "ev";
  const selected = new Set();
  // bulk records a "select all matching" action: how many IDs it added
  // and the filter signature in force at the time.
  let bulk = null;
  let currentPage = null;
  let inFlight = 0;

  evidenceCatalogs.set(collectionId, { selected });

  const searchInput = container.querySelector("#ev-search");
  const filtersHost = container.querySelector("#ev-filters");
  const listHost = container.querySelector("#ev-list");
  const pagerHost = container.querySelector("#ev-pager");
  const noteHost = container.querySelector("#ev-selection-note");
  const importBtn = container.querySelector("#import-selected-btn");
  const importCount = container.querySelector("#import-selected-count");

  pagerFor(prefix, { scope: collectionId, sizes: [25, 50, 100, 250], defaultSize: 100 });

  // filterSignature is the identity of "the current filter". Two
  // selections made under the same signature are comparable; a change
  // means a bulk selection no longer describes what is on screen.
  //
  // .toString(), NOT JSON.stringify: URLSearchParams has no own
  // enumerable properties, so JSON.stringify returns "{}" for every
  // filter alike. That made every signature compare equal, and a bulk
  // selection made under one filter silently kept claiming to be
  // "every file matching the current search and filters" after the
  // filter changed -- the precise unsafe state this check exists to
  // prevent.
  const filterSignature = () => queryParams().toString();

  function queryParams() {
    const f = filtersHost.dataset.ready ? readFilterBar(prefix) : {};
    const q = new URLSearchParams();
    const term = (searchInput.value || "").trim();
    if (term) q.set("q", term);
    (f.family || []).forEach((v) => q.append("family", v));
    (f.priority || []).forEach((v) => q.append("priority", v));
    (f.status || []).forEach((v) => q.append("status", v));
    return q;
  }

  function pageQuery() {
    const q = queryParams();
    const st = pagerStates.get(prefix);
    q.set("page", String(st.page));
    q.set("page_size", String(st.pageSize));
    return q;
  }

  async function load() {
    const token = ++inFlight;
    listHost.setAttribute("aria-busy", "true");
    let page;
    try {
      page = await api(`/cases/${caseId}/evidence/${collectionId}/files?${pageQuery()}`);
    } catch (e) {
      if (token !== inFlight) return;
      listHost.innerHTML = errorBox(e);
      listHost.removeAttribute("aria-busy");
      return;
    }
    // A slower earlier request must never overwrite a newer page.
    if (token !== inFlight) return;
    currentPage = page;
    listHost.removeAttribute("aria-busy");
    renderFiltersOnce(page);
    renderList(page);
    renderSelectionNote(page);
    pagerHost.innerHTML = renderPager(prefix, {
      page: page.page, pageSize: page.page_size, total: page.total,
      totalPages: page.total_pages,
      from: page.total === 0 ? 0 : (page.page - 1) * page.page_size + 1,
      to: (page.page - 1) * page.page_size + page.items.length,
    }, { noun: "files", label: "Evidence pagination" });
    updateImportButton();
  }

  // The filter dropdowns are built from vocabularies the SERVER derives
  // from the whole collection, so they describe every value present --
  // not merely the values on the page being viewed. They are rendered
  // once: rebuilding them on each page would close any open dropdown.
  function renderFiltersOnce(page) {
    if (filtersHost.dataset.ready) return;
    const opts = (list) => list.map((v) => ({ value: v.value, label: `${v.label} (${fmtCount(v.count)})` }));
    filtersHost.innerHTML = renderFilterBar(prefix, {
      scope: collectionId,
      family: opts(page.families || []),
      priority: opts(page.priorities || []),
      status: opts(page.statuses || []),
    });
    filtersHost.dataset.ready = "1";
    wireFilterBar(prefix, onFilterChanged);
  }

  function renderList(page) {
    if (page.total === 0) {
      listHost.innerHTML = `<p class="empty">No files match the current search and filters.</p>`;
      return;
    }
    // Both presentations are always emitted; CSS shows exactly one, so
    // resizing the window never needs a re-render or a JS media query.
    listHost.innerHTML = `
      <div class="table-wrap evidence-table-wrap"><table class="data-table evidence-table">
        <thead><tr>
          <th class="ev-check"><span class="sr-only">Select</span></th>
          <th>Filename</th><th>Artifact type</th><th>Priority</th><th class="num">Size</th><th>Status</th><th>Details</th>
        </tr></thead>
        <tbody>${page.items.map((f) => rowForDiscoveredFile(f, selected.has(f.id))).join("")}</tbody>
      </table></div>
      <div class="evidence-cards">${page.items.map((f) => cardForDiscoveredFile(f, selected.has(f.id))).join("")}</div>`;
  }

  // renderSelectionNote is where the two selection modes are told apart
  // in words, because "100 selected" and "7,074 selected" must never
  // look the same to someone about to press Import.
  function renderSelectionNote(page) {
    const onPage = page.items.filter((f) => selected.has(f.id)).length;
    const stale = bulk && bulk.signature !== filterSignature();

    let html = `<div class="ev-counts small">`;
    if (selected.size === 0) {
      html += `<span class="muted">Nothing selected. ${fmtCount(page.selectable_total)} of ${fmtCount(page.total)} matching file(s) can be imported.</span>`;
    } else if (bulk && !stale) {
      html += `<strong>${fmtCount(selected.size)} matching file(s) selected</strong>
               <span class="muted"> &middot; every file matching the current search and filters</span>`;
    } else {
      html += `<strong>${fmtCount(selected.size)} file(s) selected</strong>
               <span class="muted"> &middot; ${fmtCount(onPage)} on this page</span>`;
    }
    html += `</div>`;

    if (stale) {
      // Explicit recompute, never a silent one: the selection still
      // holds exactly the IDs chosen earlier, and the investigator
      // decides whether that is still what they want.
      html += `<div class="ev-selection-warning" role="status">
        <strong>Filters changed since "Select all matching"</strong>
        <div class="small">${fmtCount(selected.size)} file(s) are still selected from the earlier filter. Importing now would include files outside the filter currently on screen.</div>
        <div class="row" style="margin-top:var(--space-2)">
          <button type="button" class="secondary small" id="ev-reselect">Re-select all matching (${fmtCount(page.selectable_total)})</button>
          <button type="button" class="secondary small" id="ev-clear-stale">Clear selection</button>
        </div>
      </div>`;
    }
    noteHost.innerHTML = html;

    noteHost.querySelector("#ev-reselect")?.addEventListener("click", selectAllMatching);
    noteHost.querySelector("#ev-clear-stale")?.addEventListener("click", clearSelection);
  }

  function updateImportButton() {
    importCount.textContent = fmtCount(selected.size);
    importBtn.disabled = selected.size === 0 || importInFlight;
  }

  function refreshSelectionUI() {
    if (currentPage) renderSelectionNote(currentPage);
    updateImportButton();
  }

  // Any change to the RESULT SET returns to page 1: staying on page 40
  // of a result that now has three pages shows an empty screen and reads
  // as "no matches".
  function onFilterChanged() {
    resetPage(prefix);
    load();
  }

  async function selectAllMatching() {
    const btn = container.querySelector("#ev-select-all");
    const original = btn.textContent;
    btn.disabled = true;
    btn.textContent = "Selecting...";
    try {
      const res = await api(`/cases/${caseId}/evidence/${collectionId}/files/ids?${queryParams()}`);
      selected.clear();
      (res.ids || []).forEach((id) => selected.add(id));
      bulk = { signature: filterSignature(), count: selected.size };
      await load();
    } catch (e) {
      container.querySelector("#import-error").innerHTML = errorBox(e);
    } finally {
      btn.disabled = false;
      btn.textContent = original;
    }
  }

  function clearSelection() {
    // Clears the ENTIRE selection, not just what is on screen.
    selected.clear();
    bulk = null;
    listHost.querySelectorAll(".discover-file-checkbox").forEach((cb) => (cb.checked = false));
    refreshSelectionUI();
  }

  // Individual ticks refine a bulk selection rather than invalidating
  // it; the count shown updates, which is what the investigator is
  // actually watching.
  listHost.addEventListener("change", (e) => {
    const cb = e.target.closest(".discover-file-checkbox");
    if (!cb) return;
    if (cb.checked) selected.add(cb.dataset.id);
    else selected.delete(cb.dataset.id);
    // Both presentations render the same record, so keep them in step.
    listHost.querySelectorAll(`.discover-file-checkbox[data-id="${cb.dataset.id}"]`)
      .forEach((other) => (other.checked = cb.checked));
    refreshSelectionUI();
  });

  listHost.addEventListener("click", (e) => {
    const btn = e.target.closest(".ev-details-btn");
    if (!btn) return;
    const target = document.getElementById(btn.dataset.details);
    if (!target) return;
    const open = !target.hidden;
    target.hidden = open;
    btn.setAttribute("aria-expanded", String(!open));
    btn.textContent = open ? "Details" : "Hide";
  });

  searchInput.addEventListener("input", debounceRender(onFilterChanged));
  wirePager(prefix, container, load);

  container.querySelector("#ev-select-page").addEventListener("click", () => {
    (currentPage?.items || []).forEach((f) => {
      if (f.supported && f.import_status === "discovered") selected.add(f.id);
    });
    listHost.querySelectorAll(".discover-file-checkbox:not(:disabled)").forEach((cb) => (cb.checked = true));
    refreshSelectionUI();
  });
  container.querySelector("#ev-select-all").addEventListener("click", selectAllMatching);
  container.querySelector("#ev-clear").addEventListener("click", clearSelection);

  // Phase 9A's "Select recommended", preserved: high/critical-priority
  // files that can ACTUALLY be imported, across the whole catalog rather
  // than the current filter. Unsupported files are never recommended,
  // because selecting one would do nothing.
  //
  // It is additive and filter-independent, so it deliberately does NOT
  // set the bulk-selection marker: it is not a claim about "everything
  // matching the current filter", and flagging it stale when the filter
  // changed would be a warning about something that was never true.
  container.querySelector("#ev-select-recommended").addEventListener("click", async () => {
    const btn = container.querySelector("#ev-select-recommended");
    const original = btn.innerHTML;
    btn.disabled = true;
    btn.textContent = "Selecting...";
    try {
      const res = await api(`/cases/${caseId}/evidence/${collectionId}/files/ids?recommended=true`);
      (res.ids || []).forEach((id) => selected.add(id));
      await load();
    } catch (e) {
      container.querySelector("#import-error").innerHTML = errorBox(e);
    } finally {
      btn.disabled = false;
      btn.innerHTML = original;
    }
  });

  let importInFlight = false;
  importBtn.addEventListener("click", async () => {
    if (importInFlight) return; // belt and braces; the button is disabled too
    importInFlight = true;
    importBtn.disabled = true;
    const originalLabel = importBtn.textContent;
    importBtn.textContent = "Importing...";

    const errBox = container.querySelector("#import-error");
    const progressHost = container.querySelector("#import-progress-panel");
    errBox.innerHTML = "";

    try {
      await runImportWithProgress(caseId, collectionId, [...selected], progressHost, container);
    } catch (e) {
      errBox.innerHTML = errorBox(e);
      progressHost.innerHTML = "";
      importInFlight = false;
      importBtn.textContent = originalLabel;
      updateImportButton();
    }
  });

  load();
}

// debounceRender keeps typing responsive on a large catalog: filtering
// 7,000 objects is fast, but rebuilding the table on every keystroke is
// not, so renders coalesce.
function debounceRender(fn) {
  let timer = null;
  return () => {
    clearTimeout(timer);
    timer = setTimeout(fn, 120);
  };
}

// ---------------- import progress ----------------

// runImportWithProgress starts a background import and polls it. The
// progress shown is entirely server-reported: percentages come from work
// units the server actually completed, and when the total is unknown the
// bar is indeterminate rather than guessing (see internal/api/importjob.go).
async function runImportWithProgress(caseId, collectionId, ids, progressHost, container) {
  const started = await api(`/cases/${caseId}/evidence/${collectionId}/import/start`, {
    method: "POST",
    body: JSON.stringify({ source_file_ids: ids }),
  });

  progressHost.innerHTML = renderImportProgress({ phase: "preparing", files_total: ids.length, percent: 0 });

  // Poll at a human cadence: fast enough to feel live, slow enough not to
  // spend the browser's time on requests instead of rendering.
  for (;;) {
    await sleep(400);
    const p = await api(`/cases/${caseId}/import-jobs/${started.job_id}`);
    progressHost.innerHTML = renderImportProgress(p);
    if (!p.done) continue;

    if (p.phase === "failed") {
      throw new Error(p.error || "the import failed");
    }
    progressHost.innerHTML = "";
    container.querySelector("#import-result").innerHTML = renderImportResults(p.result || {});
    const cont = container.querySelector("#import-continue-btn");
    if (cont) cont.addEventListener("click", () => window.location.reload());
    wireParseFailureToggle(container);
    return;
  }
}

const IMPORT_PHASE_LABELS = {
  preparing: "Preparing",
  parsing: "Parsing files",
  enriching: "Resolving hosts",
  persisting: "Saving evidence",
  finalizing: "Finalizing",
  complete: "Complete",
  failed: "Failed",
};

function renderImportProgress(p) {
  const pct = typeof p.percent === "number" ? p.percent : -1;
  const indeterminate = pct < 0;
  return `
    <div class="panel import-progress" style="background:var(--bg-panel); margin-top:var(--space-3); margin-bottom:0">
      <h3>Importing evidence</h3>
      <div class="small">${esc(IMPORT_PHASE_LABELS[p.phase] || p.phase || "Working")}</div>
      <div class="progress-track${indeterminate ? " indeterminate" : ""}" role="progressbar"
           ${indeterminate ? 'aria-valuetext="in progress"' : `aria-valuenow="${pct}" aria-valuemin="0" aria-valuemax="100"`}>
        <div class="progress-fill" style="${indeterminate ? "" : `width:${pct}%`}"></div>
      </div>
      <div class="row between small" style="margin-top:var(--space-2)">
        <span>${indeterminate ? "Working..." : `${pct}%`}</span>
        <span class="muted">${fmtCount(p.files_parsed || 0)} / ${fmtCount(p.files_total || 0)} selected files parsed</span>
      </div>
      ${
        p.current_file
          ? `<div class="muted small mono import-current" title="${esc(p.current_file)}">${esc(p.current_file)}</div>`
          : ""
      }
      <div class="small muted" style="margin-top:var(--space-2)">
        ${fmtCount(p.events_parsed || 0)} event(s) parsed
        &middot; ${fmtCount(p.events_skipped || 0)} already known
        &middot; ${fmtCount(p.parse_errors || 0)} parse error(s)
        &middot; elapsed ${fmtElapsed(p.elapsed_seconds || 0)}
      </div>
    </div>`;
}

function fmtElapsed(seconds) {
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// wireParseFailureToggle makes the parse-error list expandable in place.
function wireParseFailureToggle(container) {
  const btn = container.querySelector("#view-parse-errors-btn");
  const panel = container.querySelector("#parse-errors-panel");
  if (!btn || !panel) return;
  btn.addEventListener("click", () => {
    panel.hidden = !panel.hidden;
    btn.textContent = panel.hidden ? "View parse errors" : "Hide parse errors";
  });
}

// renderParseFailures lists the files that were selected and supported
// but could not be parsed. This is deliberately separate from
// "unsupported": an unsupported file is one Tracefall was never able to
// read, while a parse failure is evidence that SHOULD have been readable
// and was not -- which is a finding about the evidence itself.
function renderParseFailures(failures) {
  if (!failures || !failures.length) return "";
  return `
    <div style="margin-top:var(--space-3)">
      <button type="button" class="secondary small" id="view-parse-errors-btn">View parse errors</button>
      <div id="parse-errors-panel" hidden style="margin-top:var(--space-2)">
        <div class="table-wrap"><table class="data-table">
          <thead><tr><th>File</th><th>Artifact type</th><th>Stage</th><th>Problem</th><th>Events kept</th></tr></thead>
          <tbody>
            ${failures
              .map(
                (f) => `<tr>
                  <td class="mono small" title="${esc(f.path)}">${esc(f.filename || f.path)}</td>
                  <td class="small">${esc(artifactLabel(f.artifact_type))}</td>
                  <td class="small">${esc(PARSE_STAGE_LABELS[f.stage] || f.stage)}</td>
                  <td class="small">${esc(f.message)}</td>
                  <td class="small">${f.partial_events ? "partial" : "none"}</td>
                </tr>`
              )
              .join("")}
          </tbody>
        </table></div>
      </div>
    </div>`;
}

const PARSE_STAGE_LABELS = {
  extract: "Extracting from container",
  parse: "Parsing",
};

// renderImportResults shows what the import endpoint actually parsed --
// how many files were imported, how many events (new vs. already known
// from another collection), plus a button to continue into the case
// dashboard.
function renderImportResults(res) {
  return `
    <div class="panel" style="background:var(--bg-panel); margin-top:12px; margin-bottom:0">
      <h3>Import complete</h3>
      ${uploadStep(`${(res.imported || []).length} file(s) imported`, true)}
      ${uploadStep(`${fmtCount(res.event_count)} event(s) parsed (${fmtCount(res.new_event_count)} new, ${fmtCount(res.duplicate_event_count)} already known from another collection)`, true)}
      ${res.skipped && res.skipped.length ? `<div class="small muted">${res.skipped.length} file(s) skipped (already imported/unsupported/duplicate)</div>` : ""}
      ${
        res.parse_failures && res.parse_failures.length
          ? `<div class="small" style="color:var(--high)">${res.parse_failures.length} supported file(s) failed to parse -- this is not the same as unsupported evidence</div>
             ${renderParseFailures(res.parse_failures)}`
          : ""
      }
      <div style="margin-top:12px">
        <button id="import-continue-btn">Continue to case dashboard</button>
      </div>
    </div>`;
}

// sha256Cell renders a source file's hash cell: Tracefall's own SHA-256
// once known (after import), else the hash the source container itself
// reported (sf.embedded_hash, format "algo:hexdigest" -- currently only
// ever populated for an AD1-sourced file, see
// internal/model.SourceFile.EmbeddedHash's doc comment), clearly labeled
// as such so it's never mistaken for one Tracefall verified itself, else
// emptyLabel ("Unknown" or "-" depending on context -- never invented).
function sha256Cell(sf, emptyLabel) {
  if (sf.sha256) return esc(sf.sha256);
  if (sf.embedded_hash) return esc(sf.embedded_hash) + ' <span class="muted small">(as reported by AD1, not yet independently verified)</span>';
  return emptyLabel;
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

  // Every categorical filter's option list is derived from the data this
  // tab already loaded -- no hardcoded hosts/users/processes/techniques,
  // and no extra request to build them.
  const techniqueIds = Array.from(new Set(findings.flatMap((f) => f.attack_techniques || []))).sort();
  content.innerHTML = `
    <div class="row between">
      <h2 id="timeline-heading">Unified timeline (${events.length} events)</h2>
    </div>
    ${renderFilterBar("tl", {
      scope: caseId,
      search: "Search events...",
      severity: true,
      category: filterOptions(events.map(eventCategory), (c) => EVENT_CATEGORY_LABELS[c] || c),
      host: filterOptions(events.map((e) => e.host)),
      user: filterOptions(events.map((e) => e.user)),
      process: filterOptions(events.map((e) => e.process_name)),
      technique: filterOptions(techniqueIds),
      collection: filterOptions(
        collections.map((c) => c.collection_id),
        (id) => collectionLabel(id)
      ),
      timeRange: true,
    })}
    <div id="timeline-body"></div>
  `;

  pagerFor("tl", { scope: caseId, sizes: [25, 50, 100, 250], defaultSize: 50 });

  const rerender = () => renderTimelineRows(caseId, events, eventFindingIdx, eventCorrIdx, readFilterBar("tl"));
  wireFilterBar("tl", () => {
    resetPage("tl");
    rerender();
  });
  wirePager("tl", content, rerender);
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
  // Only the current page is built into the DOM. The filtered set is
  // still counted in full above, and the ORDER is untouched -- paging
  // slices an already-ordered array, so a page boundary never changes
  // which event comes before which.
  const page = paginate("tl", filtered);
  body.innerHTML = `
    <div class="table-wrap"><table class="data-table wide">
      <thead><tr>
        <th>Time (UTC)</th><th>Category</th><th>Type</th><th>Host</th><th>User</th>
        <th>Process</th><th>Parent</th><th>PID</th><th>PPID</th><th>Detail</th>
        <th>Finding</th><th>ATT&amp;CK</th><th>Source</th><th>Collection</th>
      </tr></thead>
      <tbody>
        ${page.items.map((e) => rowForEvent(e, eventFindingIdx[e.id], eventCorrIdx[e.id])).join("")}
      </tbody>
    </table></div>
    ${renderPager("tl", page, { noun: "events", label: "Timeline pagination" })}
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
  if (!selMatches(f.collection, e.collection_id)) return false;
  if (!selMatches(f.category, eventCategory(e))) return false;
  if (!selMatches(f.host, e.host)) return false;
  if (!selMatches(f.user, e.user)) return false;
  if (!selMatches(f.process, e.process_name)) return false;
  // Date bounds are INCLUSIVE at both ends: an event exactly on the
  // boundary is inside the range. See docs/investigation-filtering.md.
  if (f.from && new Date(e.timestamp) < f.from) return false;
  if (f.to && new Date(e.timestamp) > f.to) return false;
  if (f.q && !eventSearchHaystack(e, eventFindingIdx).includes(f.q)) return false;

  if (hasSel(f.severity) || hasSel(f.technique)) {
    const relatedFindings = eventFindingIdx[e.id] || [];
    if (hasSel(f.severity) && !relatedFindings.some((rf) => f.severity.has(rf.severity))) return false;
    if (hasSel(f.technique) && !relatedFindings.some((rf) => selMatchesAny(f.technique, rf.attack_techniques))) return false;
  }
  return true;
}

// rowForEvent renders one timeline row. relatedFindings/relatedCorrs (may
// be undefined) are this event's cross-referenced Finding/Correlation
// rows, resolved once for the whole tab via buildEventFindingIndex /
// buildEventCorrelationIndex -- their presence is what visually
// distinguishes a plain observed event from one that's part of a
// detection or a reconstructed activity chain.
// eventTimeCell renders an event's time, or -- for artifacts that record
// none -- says so plainly and explains why, quoting the parser's own
// stated basis rather than inventing wording in the UI. A timestamp-less
// event is still a real observation; what it is not is a point on a
// clock, and the cell has to make that difference obvious at a glance.
function eventTimeCell(e) {
  if (!isNoTimestamp(e.timestamp)) return esc(fmtTime(e.timestamp));
  const basis = (e.extra && e.extra.timestamp_basis) || "This artifact does not record a timestamp.";
  return `<span class="no-timestamp" title="${esc(basis)}">${esc(NO_TIMESTAMP_LABEL)}</span>`;
}

function rowForEvent(e, relatedFindings, relatedCorrs) {
  const sev = maxSeverity((relatedFindings || []).map((f) => f.severity));
  const techniques = techniquesForFindings(relatedFindings || []);
  const hasChain = (relatedCorrs || []).some((c) => c.correlation_type === "activity_chain");
  return `<tr class="timeline-row" data-event="${esc(e.id)}" tabindex="0">
    <td class="mono small nowrap">${eventTimeCell(e)}</td>
    <td class="small nowrap">${categoryBadge(eventCategory(e))}</td>
    <td class="small nowrap">${esc(e.event_type)}${hasChain ? ' <span class="badge conf chain-badge" title="Part of a reconstructed activity chain">chain</span>' : ""}</td>
    <td class="mono small nowrap">${esc(e.host)}</td>
    <td class="mono small nowrap">${esc(e.user)}</td>
    <td class="mono small nowrap">${esc(e.process_name)}</td>
    <td class="mono small nowrap">${esc(e.parent_process)}</td>
    <td class="mono small num">${e.pid || ""}</td>
    <td class="mono small num">${e.ppid || ""}</td>
    <td class="mono small detail-td">${detailCell(eventDetailValue(e))}</td>
    <td class="small nowrap">${sev ? severityBadge(sev) : ""}</td>
    <td class="small">${techChips(techniques)}</td>
    <td class="small nowrap">${esc(artifactLabel(e.artifact_type))}</td>
    <td class="small nowrap">${collectionBadge(e.collection_id)}</td>
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
  // Host/user/collection options come from the findings' own supporting
  // events -- the same join findingMatchesFilters uses to match on them,
  // so the offered options and the filter's behavior can't disagree.
  const ruleTitles = new Map(findings.map((f) => [f.detection_rule, f.title]));
  const supportingOf = (f) => (f.supporting_event_ids || []).map((id) => eventsById[id]).filter(Boolean);
  const supportingEvents = findings.flatMap(supportingOf);

  content.innerHTML = `
    <div class="row between"><h2 id="findings-heading">Findings (${findings.length})</h2></div>
    ${renderFilterBar("fd", {
      scope: caseId,
      search: "Search findings...",
      severity: true,
      confidence: true,
      host: filterOptions(supportingEvents.map((e) => e.host)),
      user: filterOptions(supportingEvents.map((e) => e.user)),
      technique: filterOptions(findings.flatMap((f) => f.attack_techniques || [])),
      rule: filterOptions(
        findings.map((f) => f.detection_rule),
        (id) => ruleTitles.get(id) || id
      ),
      collection: filterOptions(
        supportingEvents.map((e) => e.collection_id),
        (id) => collectionLabel(id)
      ),
      timeRange: true,
    })}
    <div id="finding-cards"></div>
  `;
  pagerFor("fd", { scope: caseId, sizes: [25, 50, 100], defaultSize: 50 });

  const rerender = () => renderFindingCards(caseId, findings, eventsById, eventCorrIdx, readFilterBar("fd"), statusIdx);
  wireFilterBar("fd", () => {
    resetPage("fd");
    rerender();
  });
  wirePager("fd", content, rerender);
  rerender();
}

// findingMatchesFilters resolves host/user/collection through the
// finding's own supporting events (a Finding has no host/user field of
// its own -- see model.Finding -- it's a property of the evidence it's
// backed by), exactly the same join renderFindingCards uses to display
// them on the card.
function findingMatchesFilters(f, filters, eventsById) {
  if (!selMatches(filters.severity, f.severity)) return false;
  if (!selMatches(filters.confidence, f.confidence)) return false;
  if (!selMatches(filters.rule, f.detection_rule)) return false;
  if (!selMatchesAny(filters.technique, f.attack_techniques)) return false;
  // A finding spans a time range, so a date filter is an OVERLAP test:
  // a finding is shown when any part of its first_seen..last_seen span
  // falls inside the selected window. Both bounds are inclusive.
  if (filters.from && new Date(f.last_seen) < filters.from) return false;
  if (filters.to && new Date(f.first_seen) > filters.to) return false;
  if (filters.q && !findingSearchHaystack(f).includes(filters.q)) return false;

  if (hasSel(filters.host) || hasSel(filters.user) || hasSel(filters.collection)) {
    const supporting = (f.supporting_event_ids || []).map((id) => eventsById[id]).filter(Boolean);
    if (hasSel(filters.host) && !supporting.some((e) => selMatches(filters.host, e.host))) return false;
    if (hasSel(filters.user) && !supporting.some((e) => selMatches(filters.user, e.user))) return false;
    if (hasSel(filters.collection) && !supporting.some((e) => selMatches(filters.collection, e.collection_id))) return false;
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

// integrityHashCell renders the SHA-512 of the original evidence object.
//
// A 128-character hash is unreadable inline, so it is shown truncated
// with the FULL value available three ways: the title attribute, the
// copy button, and expansion. Truncation is display-only -- what gets
// copied is always the complete digest, because a partially-copied hash
// is worse than no hash at all.
function integrityHashCell(hash) {
  if (!hash) {
    return `<div class="mono small muted">Not recorded (collection predates integrity hashing)</div>`;
  }
  return `<div class="integrity-hash">
    <code class="hash-value" title="${esc(hash)}" data-full="${esc(hash)}">${esc(hash.slice(0, 32))}&hellip;</code>
    <button type="button" class="secondary small copy-hash" data-hash="${esc(hash)}"
            title="Copy the full SHA-512">Copy</button>
    <button type="button" class="secondary small expand-hash" title="Show the full value">Show full</button>
  </div>`;
}

// wireIntegrityHash makes the copy and expand controls work. Copying
// uses the async clipboard API where available and falls back to a
// hidden selection, so it still works over plain HTTP on a LAN -- which
// is exactly how Tracefall is normally reached.
function wireIntegrityHash(root) {
  root.querySelectorAll(".copy-hash").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      e.stopPropagation();
      const value = btn.dataset.hash;
      let ok = false;
      try {
        if (navigator.clipboard && window.isSecureContext) {
          await navigator.clipboard.writeText(value);
          ok = true;
        }
      } catch (_) {
        ok = false;
      }
      if (!ok) {
        const ta = document.createElement("textarea");
        ta.value = value;
        ta.setAttribute("readonly", "");
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        try {
          ok = document.execCommand("copy");
        } catch (_) {
          ok = false;
        }
        document.body.removeChild(ta);
      }
      if (!ok) {
        // Neither the clipboard API (unavailable over plain HTTP, which
        // is how Tracefall is normally reached on a LAN) nor execCommand
        // worked. Rather than tell the investigator to press Ctrl+C with
        // nothing selected, expand the hash in place and SELECT it, so
        // Ctrl+C actually copies the complete digest.
        const code = setHashExpanded(btn.parentElement, true);
        const range = document.createRange();
        range.selectNodeContents(code);
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
      }
      const original = btn.textContent;
      btn.textContent = ok ? "Copied" : "Selected - press Ctrl+C";
      btn.classList.toggle("copy-ok", ok);
      setTimeout(() => {
        btn.textContent = original;
        btn.classList.remove("copy-ok");
      }, 2000);
    });
  });
  root.querySelectorAll(".expand-hash").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const code = btn.parentElement.querySelector(".hash-value");
      setHashExpanded(btn.parentElement, code.textContent !== code.dataset.full);
    });
  });
}

// setHashExpanded is the SINGLE place the expanded/collapsed state of a
// hash is changed, because two controls can change it: the "Show full"
// toggle, and the copy fallback (which expands the value so it can be
// selected). When the fallback expanded the hash on its own, the toggle
// still read "Show full" while already showing the full value -- so
// clicking it collapsed the hash the investigator had just been told to
// press Ctrl+C on. Driving the text and the button label together makes
// that state impossible.
function setHashExpanded(container, expanded) {
  const code = container.querySelector(".hash-value");
  const btn = container.querySelector(".expand-hash");
  const full = code.dataset.full;
  code.textContent = expanded ? full : full.slice(0, 32) + "\u2026";
  if (btn) btn.textContent = expanded ? "Show less" : "Show full";
  return code;
}

// renderSeverityExplanation answers "why is this finding this severe?".
//
// Every statement it shows is generated by the server from either the
// producing rule's declared reasoning or facts counted from this
// finding's own supporting events (see internal/api/explain.go). The UI
// adds no judgement of its own -- if a factor is not in the data, it is
// not displayed.
function renderSeverityExplanation(x) {
  if (!x || !Array.isArray(x.factors) || x.factors.length === 0) return "";

  const rows = x.factors
    .map(
      (f) => `<div class="why-factor why-${esc(f.kind)}">
                <div class="why-label">${esc(f.label)}</div>
                <div class="why-detail small">${esc(f.detail)}</div>
              </div>`
    )
    .join("");

  return `
    <div class="why-panel">
      <div class="why-head">
        <span class="why-title">Why this severity?</span>
        ${severityBadge(x.severity)}
        ${confBadge(x.confidence)}
        ${x.escalated ? `<span class="badge conf why-escalated">raised above rule baseline</span>` : ""}
      </div>
      <div class="why-factors">${rows}</div>
      ${
        x.rule
          ? `<p class="muted small why-rule-note">Rule <span class="mono">${esc(x.rule.rule_id)}</span> assigns
               ${esc(x.rule.base_severity)} severity at minimum${
              x.rule.max_severity !== x.rule.base_severity ? `, up to ${esc(x.rule.max_severity)}` : ""
            }. Severity is set by the detection rule from the evidence, not scored or configurable.</p>`
          : ""
      }
    </div>`;
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

  const page = paginate("fd", filtered);
  page.items.forEach((f) => {
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

  container.insertAdjacentHTML("beforeend",
    renderPager("fd", page, { noun: "findings", label: "Findings pagination" }));
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
      ${renderSeverityExplanation(fd.severity_explanation)}
      <h3>Supporting evidence</h3>
      <div class="table-wrap"><table class="data-table">
        <thead><tr><th>Time</th><th>Type</th><th>Process</th><th>Detail</th><th>Source</th><th>Collection</th><th></th></tr></thead>
        <tbody>
          ${fd.supporting_event_details
            .map(
              (e) => `<tr>
                <td class="mono small">${esc(fmtTime(e.timestamp))}</td>
                <td>${esc(e.event_type)}</td>
                <td class="mono small">${esc(e.process_name)}</td>
                <td class="mono small detail-td">${detailCell(eventDetailValue(e))}</td>
                <td class="small">${esc(artifactLabel(e.artifact_type))}</td>
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
  content.innerHTML = `
    <div class="row between"><h2 id="investigations-heading">Investigations (${investigations.length})</h2></div>
    ${renderFilterBar("iv", {
      scope: caseId,
      search: "Search investigations...",
      severity: true,
      confidence: true,
      technique: filterOptions(investigations.flatMap((i) => i.attack_techniques || [])),
    })}
    <div id="investigations-body"></div>
  `;
  pagerFor("iv", { scope: caseId, sizes: [25, 50, 100], defaultSize: 50 });

  const rerender = () => {
    const filters = readFilterBar("iv");
    const filtered = investigations.filter((inv) => {
      if (!selMatches(filters.severity, inv.severity)) return false;
      if (!selMatches(filters.confidence, inv.confidence)) return false;
      if (!selMatchesAny(filters.technique, inv.attack_techniques)) return false;
      if (filters.q && !investigationSearchHaystack(inv).includes(filters.q)) return false;
      return true;
    });
    document.getElementById("investigations-heading").textContent = `Investigations (${filtered.length} of ${investigations.length})`;
    // Only the current page reaches the DOM: a case can hold a thousand
    // investigations, and rendering them all is what makes the tab slow
    // to open and impossible to scan.
    const page = paginate("iv", filtered);
    document.getElementById("investigations-body").innerHTML =
      filtered.length === 0
        ? `<p class="empty">No investigations match the current filters.</p>`
        : renderInvestigationList(caseId, page.items) + renderPager("iv", page, { noun: "investigations", label: "Investigations pagination" });
  };
  // A filter change alters the result set, so page 7 of the old result
  // is meaningless against the new one -- back to page 1. Pagination
  // itself must NOT reset the filters, which is why only this direction
  // is wired.
  wireFilterBar("iv", () => {
    resetPage("iv");
    rerender();
  });
  wirePager("iv", content, rerender);
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
        <button type="button" class="secondary small" id="evidence-select-all-btn">Select shown</button>
        <button type="button" class="secondary small" id="evidence-clear-btn">Clear</button>
      </div>
    </div>
    <div id="evidence-bulk-bar" class="bulk-bar-host"></div>
    <div id="evidence-collections-detail"></div>
  `;
  const container = document.getElementById("evidence-collections-detail");
  for (const [i, col] of collections.entries()) {
    const card = h(`<div class="finding-card" style="cursor:default" data-collection="${esc(col.collection_id)}"><p class="empty">Loading files...</p></div>`);
    container.appendChild(card);
    await mountCollectionFileList(card, caseId, col, i);
  }
  wireEvidenceFileSelection(caseId, container);
}

// mountCollectionFileList renders one collection's files, a page at a
// time, from the same server-paginated endpoint the selection screen
// uses.
//
// Before Phase 10B this rendered every file the collection held. On a
// 7,074-file image that was a megabyte of markup in one card -- the
// exact "renders a large number of evidence rows at once" problem, just
// on a different screen from the one usually blamed for it.
async function mountCollectionFileList(card, caseId, col, index) {
  // A pager per collection: two collections on screen page independently.
  const prefix = `evc${index}`;
  pagerFor(prefix, { scope: col.collection_id, sizes: [25, 50, 100, 250], defaultSize: 50 });

  // Imported files are the default view -- this screen is about evidence
  // actually in the case. Everything else stays one control away rather
  // than padding the list.
  let status = "imported";

  async function load() {
    const st = pagerStates.get(prefix);
    const q = new URLSearchParams({ page: String(st.page), page_size: String(st.pageSize) });
    if (status) q.set("status", status);
    try {
      const page = await api(`/cases/${caseId}/evidence/${col.collection_id}/files?${q}`);
      card.innerHTML = renderEvidenceCollectionCard(index, col, page, status, prefix);
    } catch (e) {
      card.innerHTML = errorBox(e);
    }
  }

  card.addEventListener("change", (e) => {
    const sel = e.target.closest(`select[data-evstatus="${prefix}"]`);
    if (!sel) return;
    status = sel.value;
    resetPage(prefix);
    load();
  });
  wirePager(prefix, card, load);
  await load();
}

// renderEvidenceCollectionCard shows one page of a collection's files.
//
// The status control replaces the old "imported list plus a collapsed
// <details> of everything else" split. That split rendered BOTH lists in
// full, so a large collection paid for every file twice over; a filter
// the server applies costs one page either way, and lets an
// investigator look at duplicates or parse errors directly rather than
// scrolling a mixed list.
function renderEvidenceCollectionCard(index, col, page, status, prefix) {
  const statusOptions = [
    ["imported", "Imported"],
    ["supported", "Discovered (not imported)"],
    ["unsupported", "Unsupported"],
    ["duplicate", "Duplicate"],
    ["failed", "Parse error"],
    ["", "All files"],
  ];
  const p = {
    page: page.page, pageSize: page.page_size, total: page.total, totalPages: page.total_pages,
    from: page.total === 0 ? 0 : (page.page - 1) * page.page_size + 1,
    to: (page.page - 1) * page.page_size + page.items.length,
  };
  return `
    <div class="row between">
      <strong>Collection #${index + 1}</strong>
      <span class="muted small">${esc(fmtDate(col.created_at))}</span>
    </div>
    <div class="muted small">${esc(SOURCE_TYPE_LABELS[col.source_type] || col.source_type)}${col.original_filename ? " &middot; " + esc(col.original_filename) : ""}</div>
    <div class="small" style="margin-top:4px">${fmtCount(col.file_count)} file(s) discovered &middot; ${fmtCount(col.imported_file_count)} file(s) imported</div>
    ${col.ingestion_status === "failed" ? FAILED_COLLECTION_NOTE : ""}

    <div class="row" style="margin-top:10px; align-items:center; gap:var(--space-2)">
      <label class="muted small" for="evstatus-${esc(prefix)}">Show</label>
      <select id="evstatus-${esc(prefix)}" class="filter-input" data-evstatus="${esc(prefix)}" style="width:auto">
        ${statusOptions.map(([v, l]) => `<option value="${v}"${v === status ? " selected" : ""}>${l}</option>`).join("")}
      </select>
    </div>

    <div class="evidence-file-list" style="margin-top:10px">
      ${
        page.items.length
          ? page.items.map(rowForEvidenceFile).join("")
          : `<p class="empty">No files in this collection match that status.</p>`
      }
    </div>
    ${page.total > 0 ? renderPager(prefix, p, { noun: "files", label: `Collection ${index + 1} file pagination` }) : ""}
  `;
}

// rowForEvidenceFile renders one imported evidence file: a checkbox for
// bulk selection, its key facts, and a per-row Delete action (deleting
// exactly this one file never requires deleting the whole collection).
function rowForEvidenceFile(f) {
  return `
    <div class="evidence-file-row" data-file-id="${esc(f.id)}">
      <label class="evidence-file-label" title="${esc(f.original_filename)}">
        <input type="checkbox" class="evidence-file-checkbox" data-id="${esc(f.id)}" data-name="${esc(f.original_filename)}" />
        <span class="evidence-file-name">${esc(f.original_filename)}</span>
      </label>
      <span class="evidence-file-meta" title="${esc(artifactLabel(f.artifact_type))}">${esc(artifactLabel(f.artifact_type))}</span>
      <span class="evidence-file-meta num">${fmtBytes(f.size_bytes)}</span>
      <span class="evidence-file-meta num">${
        f.import_status === "imported"
          ? `${fmtCount(f.event_count)} event(s)`
          : esc(SOURCE_FILE_STATUS_LABELS[f.import_status] || f.import_status)
      }</span>
      <span class="evidence-file-actions">
        <button type="button" class="small danger evidence-file-delete-btn" data-id="${esc(f.id)}" data-name="${esc(f.original_filename)}">Delete</button>
      </span>
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
    // .bulk-bar-host reserves this row's height whether or not a bar is
    // in it, so ticking a checkbox no longer pushes the whole evidence
    // list down (and the row under the cursor no longer moves).
    if (selected.length === 0) {
      bulkBar.innerHTML = "";
      return;
    }
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

  // DELEGATED, not bound per element. The collection cards re-render on
  // every page change now that this list is paginated, and per-element
  // handlers would be discarded with the markup -- leaving Delete and
  // the checkboxes silently inert from page 2 onwards.
  container.addEventListener("change", (e) => {
    if (e.target.closest(".evidence-file-checkbox")) updateBulkBar();
  });
  container.addEventListener("click", (e) => {
    const btn = e.target.closest(".evidence-file-delete-btn");
    if (btn) confirmAndDeleteEvidence(caseId, [btn.dataset.id]);
  });

  // Scoped to the files currently shown, and labelled that way. Unlike
  // the import selection screen -- where selection is a set that
  // outlives the page -- these buttons feed a DELETE, so acting on
  // records the investigator cannot see would be the most dangerous
  // thing this screen could do.
  document.getElementById("evidence-select-all-btn").addEventListener("click", () => {
    checkboxes().forEach((cb) => (cb.checked = true));
    updateBulkBar();
  });
  document.getElementById("evidence-clear-btn").addEventListener("click", () => {
    checkboxes().forEach((cb) => (cb.checked = false));
    updateBulkBar();
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
