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
  err.status = res.status;
  if (res.status === 409 && body && body.duplicate_collection_label) {
    err.duplicateCollectionLabel = body.duplicate_collection_label;
  }
  if (res.status === 409 && body && body.duplicate_case_name) {
    err.duplicateCaseName = body.duplicate_case_name;
  }
  return err;
}

// csrfToken reads the CSRF cookie the server set at login.
//
// Deliberately NOT HttpOnly on the server side: the double-submit check
// requires this page to read the value and echo it back in a header,
// which is precisely what a cross-site attacker cannot do. Its only
// power is to prove the request came from Tracefall's own page.
function csrfToken() {
  const m = document.cookie.match(/(?:^|;\s*)tracefall_csrf=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : "";
}

// SAFE_METHODS need no CSRF token; the server applies the same rule.
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

async function api(path, opts) {
  const method = ((opts && opts.method) || "GET").toUpperCase();
  const headers = { "Content-Type": "application/json", ...((opts && opts.headers) || {}) };
  if (!SAFE_METHODS.has(method)) {
    // Required on every write in every auth mode; see clientHeader in the server's middleware.
    headers["X-Tracefall-Client"] = "dashboard";
    const t = csrfToken();
    if (t) headers["X-Tracefall-CSRF"] = t;
  }
  const res = await fetch("/api" + path, { ...opts, headers });
  const body = await res.json().catch(() => null);
  if (!res.ok) {
    // A 401 mid-session means the session expired or was revoked. Send
    // the analyst to the login screen rather than surfacing a confusing
    // error on whatever they happened to be reading.
    //
    // The login endpoint itself is excluded: a 401 there means "wrong
    // password", not "session lost". Treating it as a session loss
    // re-rendered the login form and destroyed the error box before the
    // caller could write the message into it, so a failed sign-in
    // silently did nothing.
    if (res.status === 401 && authState.enabled && !path.startsWith("/auth/login")) {
      handleSessionLost();
    }
    // The server refuses everything but the password change while the
    // account is gated. Honour that rather than showing the refusal as a
    // generic error on whatever view happened to make the request.
    if (res.status === 403 && body && /change your password/i.test(body.error || "")) {
      authState.mustChangePassword = true;
      renderPasswordChange();
    }
    throw apiError(res, body);
  }
  return body;
}

// ---------------- authentication (Phase 12) ----------------

// authState is what the dashboard knows about the current session. It is
// a CONVENIENCE for rendering only: every permission it reflects is
// re-checked by the server on every request, so hiding a button is never
// the thing that stops an action.
const authState = { enabled: false, authenticated: false, username: "", role: "", canDelete: true, setupRequired: false, mustChangePassword: false };

async function loadSession() {
  try {
    const info = await api("/auth/session");
    authState.enabled = !!info.auth_enabled;
    authState.authenticated = !!info.authenticated;
    authState.username = info.username || "";
    authState.role = info.role || "";
    // With authentication off, the single local operator is unrestricted
    // -- exactly as before Phase 12.
    authState.canDelete = info.auth_enabled ? !!info.can_delete : true;
    authState.setupRequired = !!info.setup_required;
    authState.mustChangePassword = !!info.must_change_password;
  } catch (e) {
    authState.enabled = false;
  }
}

function handleSessionLost() {
  authState.authenticated = false;
  renderLogin("Your session has expired. Sign in again to continue.");
}

// renderLogin replaces the whole application with the sign-in form.
function renderLogin(message) {
  document.getElementById("user-bar").innerHTML = "";
  app.innerHTML = `
    <div class="login-wrap">
      <form class="login-card panel" id="login-form" autocomplete="on">
        <h1 class="login-title">Tracefall</h1>
        <p class="muted small">Sign in to continue.</p>
        ${message ? `<div class="login-message" role="status">${esc(message)}</div>` : ""}
        <div class="field">
          <label for="login-username">Username</label>
          <div class="input-wrap"><input id="login-username" name="username" autocomplete="username" required autofocus /></div>
        </div>
        <div class="field">
          <label for="login-password">Password</label>
          <div class="input-wrap"><input id="login-password" name="password" type="password" autocomplete="current-password" required /></div>
        </div>
        <div id="login-error" role="alert"></div>
        <button type="submit" id="login-submit">Sign in</button>
      </form>
    </div>`;

  const form = document.getElementById("login-form");
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = document.getElementById("login-submit");
    const errBox = document.getElementById("login-error");
    errBox.innerHTML = "";
    btn.disabled = true;
    btn.textContent = "Signing in...";
    try {
      const info = await api("/auth/login", {
        method: "POST",
        body: JSON.stringify({
          username: document.getElementById("login-username").value,
          password: document.getElementById("login-password").value,
        }),
      });
      authState.enabled = true;
      authState.authenticated = true;
      authState.username = info.username;
      authState.role = info.role;
      authState.canDelete = !!info.can_delete;
      authState.mustChangePassword = !!info.must_change_password;
      renderUserBar();
      if (authState.mustChangePassword) {
        renderPasswordChange();
        return;
      }
      route();
    } catch (err) {
      errBox.innerHTML = errorBox(err);
      btn.disabled = false;
      btn.textContent = "Sign in";
      document.getElementById("login-password").value = "";
      document.getElementById("login-password").focus();
    }
  });
}

// canDelete reports whether the signed-in user may destroy evidence.
//
// Used ONLY to decide whether to render a destructive control. It is not
// a security boundary: the server re-checks the role on every
// destructive request (see requiredRole in internal/api/middleware.go),
// so a user who forges the UI state still gets a 403. Hiding the button
// exists so an analyst is not offered an action that can only fail.
function canDelete() {
  return !authState.enabled || authState.canDelete;
}

// renderPasswordChange is the mandatory password-change screen.
//
// It replaces the whole application rather than appearing as a banner:
// the account genuinely cannot do anything else, and the server enforces
// that independently (see isPasswordChangeRoute in
// internal/api/middleware.go), so an interface that let the user browse
// around would only be showing them things every request would refuse.
function renderPasswordChange(message) {
  app.innerHTML = `
    <div class="login-wrap">
      <form class="login-card panel" id="pwchange-form" autocomplete="on">
        <h1 class="login-title">Change your password</h1>
        <p class="muted small">
          This account was created with a password generated by the server and shown once in the
          startup output. Choose your own password to continue.
        </p>
        ${message ? `<div class="login-message" role="status">${esc(message)}</div>` : ""}
        <input type="text" name="username" autocomplete="username" value="${esc(authState.username)}" hidden readonly />
        <div class="field">
          <label for="pw-current">Current password</label>
          <div class="input-wrap"><input id="pw-current" type="password" autocomplete="current-password" required autofocus /></div>
        </div>
        <div class="field">
          <label for="pw-new">New password</label>
          <div class="input-wrap"><input id="pw-new" type="password" autocomplete="new-password" required minlength="12" /></div>
          <p class="muted small">At least 12 characters. Length matters more than symbols.</p>
        </div>
        <div class="field">
          <label for="pw-confirm">Confirm new password</label>
          <div class="input-wrap"><input id="pw-confirm" type="password" autocomplete="new-password" required minlength="12" /></div>
        </div>
        <div id="pw-error" role="alert"></div>
        <button type="submit" id="pw-submit">Set new password</button>
      </form>
    </div>`;

  const form = document.getElementById("pwchange-form");
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = document.getElementById("pw-submit");
    const errBox = document.getElementById("pw-error");
    const next = document.getElementById("pw-new").value;
    const confirm = document.getElementById("pw-confirm").value;
    errBox.innerHTML = "";

    // Checked here purely to save a round trip; every other rule
    // (length, correctness of the current password, difference from it)
    // is enforced by the server.
    if (next !== confirm) {
      errBox.innerHTML = errorBox(new Error("The two new passwords do not match."));
      return;
    }
    btn.disabled = true;
    btn.textContent = "Saving...";
    try {
      const info = await api("/auth/change-password", {
        method: "POST",
        body: JSON.stringify({
          current_password: document.getElementById("pw-current").value,
          new_password: next,
        }),
      });
      authState.mustChangePassword = false;
      if (info && info.authenticated) {
        authState.authenticated = true;
        authState.username = info.username;
        authState.role = info.role;
        authState.canDelete = !!info.can_delete;
        renderUserBar();
        route();
        return;
      }
      // The change succeeded but the fresh session was not issued; sign
      // in again rather than pretending to be authenticated.
      authState.authenticated = false;
      renderLogin("Your password has been changed. Sign in with your new password.");
    } catch (err) {
      errBox.innerHTML = errorBox(err);
      btn.disabled = false;
      btn.textContent = "Set new password";
      document.getElementById("pw-current").value = "";
      document.getElementById("pw-current").focus();
    }
  });
}

// renderTimezoneControl puts the display-timezone setting in the top
// bar, next to the session controls.
//
// In the top bar rather than behind a settings page because the value it
// carries is CONTEXT for everything on screen: an analyst reading a
// timeline needs to know which zone they are reading, and a setting they
// have to go looking for is a setting they will forget they changed.
//
// The control shows the human-readable zone with its current
// abbreviation and offset, and persists the canonical IANA identifier.
function renderTimezoneControl() {
  const host = document.getElementById("timezone-control");
  if (!host) return;
  const zones = timezoneOptions();
  host.innerHTML = `
    <label class="tz-label" for="tz-select">Timezone</label>
    <select id="tz-select" class="tz-select" title="Timezone used to display every timestamp. Stored evidence timestamps are always UTC and are never changed by this.">
      ${zones
        .map((z) => `<option value="${esc(z)}" ${z === displayTimezone ? "selected" : ""}>${esc(timezoneOptionLabel(z))}</option>`)
        .join("")}
    </select>
    <span class="tz-error small" id="tz-error"></span>`;

  document.getElementById("tz-select").addEventListener("change", async (e) => {
    const chosen = e.target.value;
    const errBox = document.getElementById("tz-error");
    errBox.textContent = "";
    try {
      const res = await api("/settings", { method: "PUT", body: JSON.stringify({ timezone: chosen }) });
      applyDisplaySettings(res.display);
      // Re-render the current view so every timestamp on screen converts
      // at once. Nothing is re-fetched from the server and no analysis is
      // re-run: the instants are unchanged, only their rendering is.
      renderTimezoneControl();
      // route() alone is not enough. When the same case is already on
      // screen it takes the switchTab fast path, which swaps only the tab
      // body -- leaving the case header, and the Created / Last analyzed
      // timestamps in it, rendered in the PREVIOUS zone. Two timestamps
      // on one screen disagreeing about which zone they are in is exactly
      // the misreading this feature exists to prevent, so the fast path
      // is deliberately given up here and the whole case view rebuilt.
      renderedCaseId = null;
      renderedTab = null;
      route();
    } catch (err) {
      // Keep the previous zone selected rather than leaving the control
      // showing a zone that was refused.
      errBox.textContent = err.message || String(err);
      renderTimezoneControl();
    }
  });
}

// timezoneOptions is the shortlist plus whatever is currently set, so a
// zone chosen outside the shortlist still displays correctly rather than
// silently reverting the control to UTC.
function timezoneOptions() {
  const list = [...COMMON_TIMEZONES];
  if (displayTimezone && !list.includes(displayTimezone)) list.unshift(displayTimezone);
  return list;
}

// timezoneOptionLabel shows the zone the way an analyst reads it. The
// currently-active zone carries its live abbreviation and offset; the
// others show only their identifier, because computing an offset for
// every option would be both slow and, for a zone on the other side of a
// DST boundary, misleading.
function timezoneOptionLabel(z) {
  // "UTC \u2014 UTC" is noise; the abbreviation only adds information
  // when it differs from the identifier.
  if (z === displayTimezone && displayTimezoneAbbr && displayTimezoneAbbr !== z) {
    return `${z} \u2014 ${displayTimezoneAbbr}`;
  }
  return z;
}

// COMMON_TIMEZONES mirrors api.CommonTimezones. Populated from the
// server at startup so the two cannot drift; the literal here is only
// the fallback used if that request fails.
let COMMON_TIMEZONES = [
  "UTC",
  "Asia/Jakarta",
  "Asia/Singapore",
  "Asia/Tokyo",
  "Europe/London",
  "America/New_York",
];

// renderUserBar shows who is signed in and offers sign-out.
function renderUserBar() {
  const bar = document.getElementById("user-bar");
  if (!bar) return;
  if (!authState.enabled) {
    // Single-operator mode: say so plainly rather than implying an
    // identity Tracefall does not have.
    bar.innerHTML = `${integrationSettingsLink()}<span class="user-chip muted small" title="Authentication is disabled; Tracefall is bound to localhost.">Local operator &middot; no authentication</span>`;
    return;
  }
  if (!authState.authenticated) {
    bar.innerHTML = "";
    return;
  }
  bar.innerHTML = `
    <span class="user-chip">
      <span class="user-name">${esc(authState.username)}</span>
      <span class="badge status user-role">${esc(authState.role)}</span>
    </span>
    ${integrationSettingsLink()}
    <button type="button" class="secondary small" id="logout-btn">Sign out</button>`;
  document.getElementById("logout-btn").addEventListener("click", async () => {
    try {
      await api("/auth/logout", { method: "POST" });
    } catch (e) {
      /* signing out locally regardless is the safer failure mode */
    }
    authState.authenticated = false;
    window.location.hash = "#/";
    renderLogin("You have been signed out.");
  });
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

    // An upload is a state-changing POST and needs the same CSRF token
    // every other write carries. api() sets this for fetch-based calls;
    // this function predates authentication and bypassed it, so uploads
    // were rejected by the middleware with 403 before the handler ever
    // ran.
    //
    // The failure was invisible for a small file and looked like a
    // network fault for a large one: the middleware rejects without
    // reading the body, and Go's server refuses to drain more than
    // maxPostHandlerReadBytes (256 KB) of an unread body, closing the
    // connection instead. A browser still uploading then reports
    // net::ERR_CONNECTION_RESET rather than the 403 that actually
    // occurred.
    xhr.setRequestHeader("X-Tracefall-Client", "dashboard");
    const token = csrfToken();
    if (token) xhr.setRequestHeader("X-Tracefall-CSRF", token);

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

// ---------------- Clipboard ----------------
//
// Tracefall is normally reached over plain HTTP on a LAN address, which
// is NOT a secure context. navigator.clipboard is undefined there in
// Chrome and rejects in Firefox, so the async Clipboard API cannot be
// the only path -- a Copy button that only works on localhost is a
// button that does not work where the tool is actually used.
//
// The secure-context check is deliberately made BEFORE any await. If we
// awaited a clipboard promise that then rejected, the browser's
// transient user activation from the click may already have expired by
// the time execCommand runs, and the fallback would fail too. On plain
// HTTP we therefore go straight to the synchronous fallback and keep
// the gesture intact; the async API is still tried first wherever it
// can actually succeed.

// copyText copies the COMPLETE text and reports whether it worked. It
// never reports success it did not get: a false return has to reach the
// analyst, or they paste whatever was on the clipboard before into a
// report believing it is the value they clicked.
async function copyText(text) {
  const value = text === null || text === undefined ? "" : String(text);
  if (value === "") return false;
  if (window.isSecureContext && navigator.clipboard && navigator.clipboard.writeText) {
    try {
      await navigator.clipboard.writeText(value);
      return true;
    } catch (_) {
      // Permission denied or a non-focused document: fall through.
    }
  }
  return copyTextFallback(value);
}

// copyTextFallback is the plain-HTTP path: a temporary off-screen
// textarea holding the full value, selected and copied with the legacy
// command, then removed again whatever the outcome. Focus is returned
// to whatever had it so the page does not visibly jump.
function copyTextFallback(value) {
  const previous = document.activeElement;
  const ta = document.createElement("textarea");
  ta.value = value;
  ta.setAttribute("readonly", "");
  ta.setAttribute("aria-hidden", "true");
  // position:fixed with a zero opacity keeps the textarea out of the
  // layout and off the screen without using display:none or
  // visibility:hidden, neither of which can be selected.
  ta.style.position = "fixed";
  ta.style.top = "0";
  ta.style.left = "0";
  ta.style.width = "1px";
  ta.style.height = "1px";
  ta.style.padding = "0";
  ta.style.border = "none";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  let ok = false;
  try {
    ta.focus();
    ta.select();
    // iOS Safari ignores select() on a readonly textarea.
    if (ta.setSelectionRange) ta.setSelectionRange(0, value.length);
    ok = document.execCommand("copy") === true;
  } catch (_) {
    ok = false;
  } finally {
    ta.remove();
  }
  if (previous && typeof previous.focus === "function") previous.focus();
  return ok;
}

// flashCopyState shows the outcome on the button that was clicked and
// restores its normal label afterwards. State lives on the button, so
// several Copy buttons on one page never interfere with each other, and
// a second click while a state is showing does not capture "Copied" as
// the label to restore.
function flashCopyState(btn, ok) {
  if (btn.dataset.copyTimer) clearTimeout(Number(btn.dataset.copyTimer));
  else btn.dataset.copyLabel = btn.textContent;
  btn.textContent = ok ? "Copied" : "Copy failed";
  btn.classList.toggle("copy-ok", ok);
  btn.classList.toggle("copy-failed", !ok);
  if (!ok) btn.title = "Could not write to the clipboard. Select the value and press Ctrl+C.";
  const timer = setTimeout(() => {
    btn.textContent = btn.dataset.copyLabel || "Copy";
    btn.classList.remove("copy-ok", "copy-failed");
    btn.removeAttribute("title");
    delete btn.dataset.copyTimer;
  }, ok ? 1500 : 2500);
  btn.dataset.copyTimer = String(timer);
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

// ---------------- display timezone ----------------
//
// Every timestamp Tracefall stores is an INSTANT in UTC, and stays that
// way (see internal/normalize.Timestamp). The analyst can choose the
// zone those instants are RENDERED in, and that choice lives here --
// in the two formatters every view already calls -- rather than being
// reimplemented per page. One conversion point is the only way the
// Timeline, Findings, Investigations, Activity Chains and Audit History
// can be guaranteed to agree about what a given event's time was.
//
// Conversion goes through Intl.DateTimeFormat with an IANA timeZone,
// which uses the browser's own copy of the timezone database and is
// therefore DST-correct. No offset arithmetic is performed anywhere in
// this file; adding hours by hand is exactly how a timestamp ends up an
// hour wrong for half the year.

// displayTimezone is the IANA identifier currently in effect. UTC until
// the settings load, so a slow settings request can never cause a
// timestamp to render in an unexpected zone.
let displayTimezone = "UTC";
let displayTimezoneAbbr = "UTC";

// tzFormatterCache avoids rebuilding an Intl.DateTimeFormat per row; on
// a 10,000-row timeline that cost is real.
const tzFormatterCache = new Map();

function tzFormatter(zone, opts) {
  const key = zone + "|" + JSON.stringify(opts);
  let f = tzFormatterCache.get(key);
  if (!f) {
    try {
      f = new Intl.DateTimeFormat("en-GB", { ...opts, timeZone: zone });
    } catch {
      // An unknown zone must never break rendering. Fall back to UTC and
      // keep the label honest about what is actually being shown.
      f = new Intl.DateTimeFormat("en-GB", { ...opts, timeZone: "UTC" });
    }
    tzFormatterCache.set(key, f);
  }
  return f;
}

// tzLabel is the suffix shown after every timestamp. It is never
// omitted: a timestamp with no zone on it is the thing that gets
// misread, which is the whole reason this feature exists.
function tzLabel() {
  return displayTimezoneAbbr || displayTimezone || "UTC";
}

// applyDisplaySettings sets the zone used by every formatter. The
// formatter cache is not cleared because it is keyed by zone.
function applyDisplaySettings(display) {
  if (!display || !display.timezone) return;
  displayTimezone = display.timezone;
  displayTimezoneAbbr = display.abbreviation || display.timezone;
}

// loadDisplaySettings fetches the stored preference once at startup.
// A failure leaves UTC in place rather than blocking the dashboard.
async function loadDisplaySettings() {
  try {
    const s = await api("/settings");
    applyDisplaySettings(s.display);
    if (Array.isArray(s.common_timezones) && s.common_timezones.length) {
      COMMON_TIMEZONES = s.common_timezones;
    }
    return s;
  } catch {
    return null;
  }
}

const TZ_DATE_TIME_OPTS = {
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
};

// tzParts renders one instant into the display zone as y/m/d h:m:s.
function tzParts(d, opts) {
  const parts = tzFormatter(displayTimezone, opts).formatToParts(d);
  const get = (t) => (parts.find((p) => p.type === t) || {}).value || "";
  return get;
}

// TZ_WALL_OPTS is TZ_DATE_TIME_OPTS pinned to the h23 hour cycle.
//
// hour12:false alone is not enough: some engines render midnight as
// "24" under that setting, and an hour of 24 fed back into Date.UTC
// silently becomes the next day. The wall-clock arithmetic below depends
// on reading the hour back exactly as written, so it asks for h23
// explicitly.
const TZ_WALL_OPTS = { ...TZ_DATE_TIME_OPTS, hourCycle: "h23" };

// zoneOffsetMs is the display zone's offset from UTC at instant ts.
//
// Derived by asking Intl what the wall clock reads there and subtracting
// -- there is no direct offset API, and hardcoding one would be wrong
// twice a year for every zone that observes daylight saving.
function zoneOffsetMs(ts) {
  const g = tzParts(new Date(ts), TZ_WALL_OPTS);
  const hour = Number(g("hour")) % 24;
  const asIfUTC = Date.UTC(
    Number(g("year")), Number(g("month")) - 1, Number(g("day")),
    hour, Number(g("minute")), Number(g("second"))
  );
  return asIfUTC - ts;
}

// wallTimeToInstant interprets a wall-clock reading in the DISPLAY
// timezone and returns the instant it names.
//
// This is what makes a date filter mean what the analyst sees. Every
// timestamp on screen is rendered in the configured display zone, so
// "29 April, 00:00" typed into a date box has to mean midnight in that
// same zone. Before this it was parsed with `new Date("2021-04-29T00:00")`,
// which is midnight in the BROWSER's zone -- so an analyst in a UTC
// browser reading Jakarta timestamps filtered a window seven hours away
// from the one they were looking at, and quietly got the wrong day's
// evidence.
//
// The offset is applied twice because the offset itself depends on the
// instant: the first pass gets close enough to land in the right side of
// a daylight-saving transition, and the second uses the offset actually
// in force there.
function wallTimeToInstant(y, month, day, hour, minute, second) {
  const guess = Date.UTC(y, month - 1, day, hour, minute, second);
  const first = guess - zoneOffsetMs(guess);
  return new Date(guess - zoneOffsetMs(first));
}

function fmtTime(ts) {
  if (!ts) return "-";
  if (isNoTimestamp(ts)) return NO_TIMESTAMP_LABEL;
  const d = new Date(ts);
  if (isNaN(d.getTime())) return ts;
  const g = tzParts(d, TZ_DATE_TIME_OPTS);
  return `${g("year")}-${g("month")}-${g("day")} ${g("hour")}:${g("minute")}:${g("second")} ${tzLabel()}`;
}

function fmtDate(ts) {
  if (!ts) return "-";
  if (isNoTimestamp(ts)) return NO_TIMESTAMP_LABEL;
  const d = new Date(ts);
  if (isNaN(d.getTime())) return ts;
  const g = tzParts(d, { ...TZ_DATE_TIME_OPTS, month: "short" });
  return `${g("day")} ${g("month")} ${g("year")} ${g("hour")}:${g("minute")} ${tzLabel()}`;
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
  disk_image: "Disk Image",
  memory_image: "Memory Image",
};

// ARTIFACT_TYPE_LABELS renders internal/model's Artifact* constants for
// an investigator. The raw constants are stable identifiers meant for
// code and provenance, not for reading -- "windows_event_log" tells an
// analyst less than "Windows Event Log (EVTX)" does, especially now that
// the same artifact type can arrive either as a raw .evtx or as an
// EvtxECmd CSV export of one.
// ARTIFACT_TYPE_LABELS names an artifact type for the views that do NOT
// receive a label from the server.
//
// The SERVER is authoritative: the forensic timeline reads
// `artifact_label` off each event, which comes from the capability
// registry (internal/artifacts), and the evidence views prefer
// `type_label` for the same reason. This table exists only for the
// endpoints that return a bare model.Event -- the investigation detail
// view and the correlation cards -- and its values must match the
// registry's, or the same artifact would be called two things in one
// application.
//
// It is kept in step by TestUI_ArtifactLabelsMatchTheServerRegistry,
// which fails if a supported artifact type is missing here or is named
// differently from the registry.
const ARTIFACT_TYPE_LABELS = {
  mssql_extended_events: "SQL Server Extended Events",
  mssql_audit: "SQL Server Audit",
  mssql_error_log: "SQL Server ERRORLOG",
  sql_agent_log: "SQL Server Agent text log",
  sql_instance_configuration: "SQL Server instance configuration",
  windows_event_log: "Windows Event Log (EVTX)",
  prefetch: "Prefetch",
  registry_run_key: "Registry (RECmd export)",
  registry_hive: "Windows Registry Hive",
  scheduled_task: "Scheduled Task XML",
  powershell_history: "PowerShell console history",
  bash_history: "Bash history",
  wtmp: "Login records (wtmp)",
  auth_log: "Authentication log (auth.log)",
  syslog: "System log (syslog)",
  web_access_log: "Web server access log",
  cryptnet_url_cache: "CryptoAPI URL cache (CryptnetUrlCache)",
  srum_db: "System Resource Usage Monitor (SRUM)",
  webcache_db: "IE / Edge Legacy web cache (WebCache)",
  defender_cmd_log: "Defender command-line log (MpCmdRun.log)",
  iis_w3c_log: "IIS web log (W3C)",
  container_json_log: "Container log (Docker json-file)",
  container_config: "Container configuration (Docker)",
  grafana_log: "Grafana log",
  grafana_database: "Grafana database",
  network_capture: "Network capture (pcap)",
  package_log: "Package log (dpkg)",
  journal: "Systemd journal",
  browser_history: "Browser history (Chromium / Firefox)",
  browser_download: "Browser download",
  ntfs_mft: "NTFS $MFT",
  ntfs_usnjrnl: "NTFS $UsnJrnl change journal",
  ntfs_logfile: "NTFS $LogFile transaction log",
  browser_cache: "Browser cache entry",
  browser_cache_index: "Browser cache container/index",
  windows_lnk: "Windows LNK shortcut",
  jumplist_automatic: "Windows Jump List (Automatic Destinations)",
  jumplist_custom: "Windows Jump List (Custom Destinations)",
  recycle_bin_metadata: "Recycle Bin",
  recycle_bin_content: "Recycle Bin content ($R)",
  userassist: "UserAssist",
  shellbags: "ShellBags",
  amcache: "Amcache",
  recent_docs: "RecentDocs",
  run_mru: "Run dialog (RunMRU)",
  typed_paths: "TypedPaths",
  opensave_mru: "Open/Save dialog (OpenSavePidlMRU)",
  muicache: "MUICache",
  sam_account: "Windows SAM",
  activities_cache: "Windows Timeline (ActivitiesCache)",
  filezilla_server: "FileZilla server entry",
  image_metadata: "Image metadata (EXIF)",
  image_gps: "Image location (EXIF GPS)",
  memory_analysis: "Memory Analysis",
};

// artifactLabel names an artifact type for display.
//
// An unlisted type is HUMANIZED rather than shown raw. A new artifact
// type reaching this path is a gap in the table above, and rendering
// "recycle_bin_metadata" in a column an analyst reads is a worse way to
// surface that gap than rendering "Recycle Bin Metadata" -- the test
// catches the omission; the UI should not punish the reader for it.
function artifactLabel(t) {
  if (!t) return "-";
  if (ARTIFACT_TYPE_LABELS[t]) return ARTIFACT_TYPE_LABELS[t];
  return t
    .split("_")
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
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
  mssql_xe_event: "other",
  mssql_audit_event: "other",
  sql_message: "other",
  sql_login_failed: "authentication",
  sql_login_success: "authentication",
  sql_agent_message: "other",
  sql_instance_configuration: "other",
  logon_success: "authentication",
  logon_failure: "authentication",
  process_create: "execution",
  powershell_script_block: "execution",
  prefetch_execution: "execution",
  registry_run_key_set: "persistence",
  scheduled_task_created: "persistence",
  network_connection: "network",
  crypto_url_retrieval: "network",
  defender_command: "execution",
  srum_app_usage: "execution",
  srum_network_usage: "network",
  srum_network_connection: "network",
  srum_push_notification: "other",
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
  // Phase 15: NTFS $MFT filesystem metadata. Its own category, not
  // "execution": a file's creation time says the file came into
  // existence, not that anything ran. Four types rather than one so an
  // examiner can filter "created" apart from "accessed".
  filesystem_created: "filesystem",
  filesystem_modified: "filesystem",
  filesystem_changed: "filesystem",
  filesystem_accessed: "filesystem",
  // Phase 16: USN change journal. A SEPARATE category from "filesystem"
  // on purpose -- an $MFT event is a file's current metadata, a journal
  // event is a historical record that the volume observed a change. An
  // examiner filtering the timeline needs to be able to hold them apart.
  usnjrnl_create: "filesystem_journal",
  usnjrnl_delete: "filesystem_journal",
  usnjrnl_modify: "filesystem_journal",
  usnjrnl_rename: "filesystem_journal",
  usnjrnl_metadata_change: "filesystem_journal",
  // Phase 14: browser cache, and browser history alongside it. Two
  // categories, NOT one and not "network": history is navigation
  // evidence, cache is response evidence, and an analyst filtering a
  // timeline has to be able to keep them apart. Before cache support
  // browser_visit had no entry at all and fell into "other", which put
  // a recorded navigation in the same bucket as everything unclassified.
  browser_visit: "browser_history",
  browser_cache_entry: "browser_cache",
  // Phase 17: shortcut target metadata and Recycle Bin deletions. Both
  // sit in the filesystem category: a shortcut describes a target FILE
  // and a $I record describes a deleted one. Neither is execution, and
  // putting either under "execution" would say it was.
  // A Jump List ties an APPLICATION to a target. Its own access event
  // belongs with execution-adjacent application activity; the target
  // timestamps it carries describe a file, exactly as the standalone
  // shortcut events do, and sit with them under filesystem.
  jumplist_entry_access: "execution",
  jumplist_target_metadata: "filesystem",
  lnk_target_created: "filesystem",
  lnk_target_modified: "filesystem",
  lnk_target_accessed: "filesystem",
  recyclebin_deletion: "filesystem",
  // Phase 15/16 artifacts. Each is bucketed by what the OBSERVATION is,
  // not by where it was stored -- a UserAssist entry is user activity
  // whether or not it lives in a registry hive. Leaving these unmapped
  // dropped every one of them into "Other", which told an analyst
  // scanning the Category column nothing at all.
  userassist_activity: "execution",
  amcache_application: "execution",
  // An account record is not activity of any kind -- see
  // model.EventSAMLocalAccount. Its own category so it can never be
  // read off the timeline as a logon or an execution.
  sam_local_account: "account",
  activity_recorded: "execution",
  shellbag_navigation: "user_activity",
  recent_document: "user_activity",
  run_mru_command: "user_activity",
  typed_path: "user_activity",
  opensave_mru: "user_activity",
  muicache_entry: "other",
  powershell_history_command: "execution",
  // Shell history records a command was TYPED, like PowerShell history.
  bash_history_command: "execution",
  // Login records: a session opening or closing is an authentication event.
  // A boot has no category of its own, so it is "other" rather than invented.
  session_start: "authentication",
  remote_authentication: "authentication",
  session_change: "authentication",
  scheduled_task_change: "persistence",
  // Task Scheduler execution-side records: the scheduler observed a run.
  scheduled_task_run: "execution",
  // Engine lifecycle only; says nothing about which command ran.
  powershell_engine_lifecycle: "other",
  event_log_cleared: "other",
  audit_policy_change: "other",
  session_end: "authentication",
  system_boot: "other",
  // An su attempt is a change of account, so it is an authentication event.
  privilege_switch: "authentication",
  // sudo authorised the command; it is execution evidence like shell history.
  sudo_command: "execution",
  // Server and host logs. An account change is recorded by the system, not
  // by a person's activity, so it sits with accounts. A web request is what
  // a server was asked, not what a host did, so it has its own category,
  // and package and service messages describe the host's configuration.
  account_change: "account",
  web_request: "web",
  package_change: "system",
  service_message: "system",
  // A capture summary and a clock reading describe the capture, not a host.
  clock_observation: "network",
  capture_summary: "network",
  // cron started a scheduled job as an account: execution, and a persistence lead.
  scheduled_job_run: "execution",
  // Generic service log entries: context, not a classified action.
  journal_entry: "other",
  browser_download: "browser_download",
  logoff: "authentication",
  // Phase 20. A FileZilla entry is a CONFIGURATION record naming a
  // remote endpoint -- "network" is where an analyst looks for it, and
  // the event's own evidence_meaning is what stops it reading as an
  // observed connection.
  filezilla_server_entry: "network",
  // Image metadata is neither activity nor filesystem evidence: it is
  // what a file CONTAINS. Its own category so it can never be read off
  // the timeline as something having happened on this machine.
  image_metadata_recorded: "image_metadata",
  image_gps_recorded: "image_metadata",
  // Memory-image events. The first two are what a process or socket was
  // doing; a malfind hit is a heuristic indicator of injected code, and a
  // service in memory is a state, not an installation.
  network_listener: "network",
  memory_injection_suspect: "execution",
  service_in_memory: "persistence",
  // What a console still held, and the files the kernel still had open.
  console_command_in_memory: "execution",
  console_screen_in_memory: "execution",
  file_object_in_memory: "filesystem",
  file_content_from_memory: "filesystem",
  memory_snapshot: "other",
};
const EVENT_CATEGORY_LABELS = {
  authentication: "Authentication",
  execution: "Execution",
  persistence: "Persistence",
  network: "Network",
  filesystem: "File System",
  filesystem_journal: "File System Journal",
  browser_history: "Browser History",
  browser_cache: "Browser Cache",
  browser_download: "Browser Download",
  // "User activity" covers the shell artifacts that record what a person
  // did through Explorer -- navigation, recent documents, typed paths,
  // dialog selections. Deliberately not "Execution": none of them
  // records a process.
  user_activity: "User Activity",
  account: "Account / Credential",
  web: "Web Server",
  system: "System / Service",
  // Metadata carried INSIDE a file, as opposed to anything the machine
  // did. An EXIF timestamp is the writing device's clock, not this
  // host's, and the category keeps that distinction visible in the
  // column an analyst scans.
  image_metadata: "Image Metadata",
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
  // Phase 14 forensic timeline. "Artifact" and "Event type" are the
  // model's own vocabularies (model.Artifact* / model.Event*), offered
  // as the values the case actually contains -- not a UI-invented
  // grouping over them.
  artifact: "Artifact",
  eventType: "Event type",
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
  add("artifact", cfg.artifact);
  add("eventType", cfg.eventType);
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
    // searchFields, when given, turns the one search box into a
    // field-scoped one: the analyst picks WHICH forensic field the term
    // applies to. It is a select next to the box rather than seven
    // separate inputs, because a forensic search is one term looked for
    // in one place, and seven boxes would imply they combine.
    searchFields: cfg.searchFields || null,
    qField: prev && prev.searchFields ? prev.qField || "" : "",
    // searchDebounceMs is longer for a bar that queries the SERVER on
    // each change: 120ms is right for re-rendering an in-memory table
    // and wrong for issuing a request per keystroke.
    searchDebounceMs: cfg.searchDebounceMs || 120,
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
  const fieldSelect = cfg.searchFields
    ? `<select class="filter-q-field" id="${prefix}-f-qfield"
               aria-label="Field to search">
         ${cfg.searchFields
           .map((f) => `<option value="${esc(f.value)}" ${f.value === state.qField ? "selected" : ""}>${esc(f.label)}</option>`)
           .join("")}
       </select>`
    : "";
  const searchBox = cfg.search
    ? `<div class="filter-search-row">
         ${fieldSelect}
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
    // Web evidence -- browser history visits, browser cache entries --
    // carries its URL in extra, not in a top-level column. Searching
    // "payload.exe" or a full URL has to reach it, and matching only
    // network_dest would restrict the analyst to bare hostnames.
    (e.extra && e.extra.url) || "",
    (e.extra && e.extra.content_type) || "",
    // A shortcut's target and a deleted file's original path are what an
    // investigator actually knows to search for -- neither is a
    // top-level column.
    (e.extra && e.extra.target_path) || "",
    (e.extra && e.extra.original_path) || "",
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

// The date range is entered through native date/time inputs, kept inside
// a compact popover instead of stretched across the bar as four
// full-width rows.
//
// The header states ONE zone, because since Phase 14 there is only one:
// the bounds typed here are read as wall-clock readings in the display
// timezone (readDateTime -> wallTimeToInstant), which is the same zone
// every timestamp in the table is rendered in. Previously the inputs
// were read in the browser's zone while the table showed another, and
// the popover had to explain the mismatch rather than not have one.
function renderDatePopover(prefix) {
  return `
    <div class="filter-pop filter-pop-date" id="${prefix}-f-date-pop" role="dialog" aria-label="Date range filter" hidden>
      <div class="filter-pop-head">
        <span class="filter-pop-title">Date range</span>
      </div>
      <p class="filter-tz-note small muted">
        Entered and displayed in <strong>${esc(displayTimezone)}</strong> (${esc(tzLabel())}),
        the same zone as every timestamp shown.
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
  // Rendered in the DISPLAY timezone, matching how the bound was
  // entered and how the table below shows its timestamps. Using the
  // browser's zone here (as this did before Phase 14) put a chip on
  // screen that disagreed with both.
  //
  // SECONDS are always shown. The filter resolves to second precision,
  // so a chip reading "18:17 → 18:17" described a one-second range and a
  // whole-minute range identically -- and the chip is the only place an
  // analyst can see what a collapsed popover is still filtering by.
  const g = tzParts(d, { ...TZ_WALL_OPTS, month: "short" });
  return `${g("month")} ${Number(g("day"))}, ${g("hour")}:${g("minute")}:${g("second")}`;
}

// dateRangeLabel names the zone the bounds are expressed in. It is shown
// always, not only when it differs from UTC: a range with no zone on it
// is exactly the thing that gets misread, and "Apr 29, 00:00" means two
// different windows depending on an answer the chip would otherwise
// leave to the reader.
function dateRangeLabel(state) {
  const tz = ` (${tzLabel()})`;
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

  // The debounce keeps a keystroke from costing a full re-render -- and,
  // for a server-driven bar like the forensic timeline, a full request.
  // Its length comes from the bar's own config (searchDebounceMs) rather
  // than being fixed here, because those two costs are not comparable.
  const qInput = document.getElementById(`${prefix}-f-q`);
  if (qInput) {
    let timer = null;
    qInput.addEventListener("input", () => {
      state.q = qInput.value;
      clearTimeout(timer);
      timer = setTimeout(() => refreshFilterBar(prefix, onChange), state.searchDebounceMs);
    });
  }

  // Changing WHICH field is searched re-runs the search immediately: the
  // analyst has already typed the term and is telling us where to look.
  const qField = document.getElementById(`${prefix}-f-qfield`);
  if (qField) {
    qField.addEventListener("change", () => {
      state.qField = qField.value;
      refreshFilterBar(prefix, onChange);
    });
  }

  document.getElementById(`${prefix}-f-clear`).addEventListener("click", () => {
    state.fields.forEach((f) => state.sel[f.key].clear());
    state.from = null;
    state.to = null;
    state.raw = {};
    state.q = "";
    state.qField = "";
    const q = document.getElementById(`${prefix}-f-q`);
    if (q) q.value = "";
    const qf = document.getElementById(`${prefix}-f-qfield`);
    if (qf) qf.value = "";

    // Some screens own a search box OUTSIDE the filter bar -- the
    // evidence triage screen's #ev-search sits next to the bar rather
    // than inside it, because it drives a server-side query rather than
    // the bar's own client-side matching.
    //
    // "Clear all" cleared only the in-bar input, so a search-only filter
    // survived the button that says it clears everything: the chips
    // disappeared while the result set stayed narrowed, with no visible
    // cause. Clearing by the same prefix convention keeps one control
    // responsible for the whole filter state.
    const screenSearch = document.getElementById(`${prefix}-search`);
    if (screenSearch) screenSearch.value = "";
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

  const [yy, mm, dd] = d.split("-").map(Number);
  if (!yy || !mm || !dd) return null;

  // The bound is read as a wall-clock reading in the DISPLAY timezone,
  // not in the browser's -- see wallTimeToInstant for why that
  // distinction is a correctness matter and not a nicety. The value
  // returned is still a plain instant, so every comparison downstream is
  // instant-against-instant.
  //
  // A `to` bound is extended to the END of whatever unit the analyst
  // actually specified. Stored event times carry sub-second precision,
  // so a range written [18:17:38, 18:17:38] and taken literally is one
  // nanosecond wide and excludes an event at 18:17:38.900891 -- the
  // range names the second the event is in, and returns nothing. The
  // rule is uniform: no time given means the whole day, HH:MM means
  // that whole minute, HH:MM:SS means that whole second.
  const isEnd = which === "to";
  if (!t) {
    const start = wallTimeToInstant(yy, mm, dd, 0, 0, 0);
    if (isNaN(start.getTime())) return null;
    return isEnd ? endOfUnit(start, 24 * 3600 * 1000) : start;
  }

  const parts = t.split(":");
  const hh = Number(parts[0]);
  const mi = Number(parts[1]);
  const hasSeconds = parts.length > 2 && parts[2] !== "";
  const ss = hasSeconds ? Number(parts[2]) : 0;
  if (Number.isNaN(hh) || Number.isNaN(mi) || Number.isNaN(ss)) return null;

  const at = wallTimeToInstant(yy, mm, dd, hh, mi, ss);
  if (isNaN(at.getTime())) return null;
  if (!isEnd) return at;
  return endOfUnit(at, hasSeconds ? 1000 : 60 * 1000);
}

// endOfUnit returns the last representable instant of a unit beginning
// at start. One millisecond short of the next unit, because a JS Date
// cannot hold anything finer -- the backend widens its own bounds to the
// nanosecond, and this bound is sent as an instant, so the millisecond
// granularity here only ever affects the client-side Findings filter,
// where finding timestamps are second-resolution anyway.
function endOfUnit(start, widthMs) {
  return new Date(start.getTime() + widthMs - 1);
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
  return {
    ...state.sel,
    from: state.from,
    to: state.to,
    q: (state.q || "").trim().toLowerCase(),
    // qRaw preserves the analyst's own casing. Server-side search is
    // case-insensitive in the database, so lowercasing before sending
    // would only throw away what they typed -- which matters when the
    // term is echoed back in a chip or an empty-state message.
    qRaw: (state.q || "").trim(),
    qField: state.qField || "",
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

// detailCell renders a table-cell-safe value. EVERY non-empty value
// gets a Copy button, whatever its length: the Detail column is the
// column an analyst pastes into a report, and a short browser URL or a
// deleted file's original path is no less worth copying than a long
// PowerShell command line. Only the truncation toggle is conditional,
// because only a truncated value has anything to reveal.
//
// The two controls are independent. "Show full" changes what is
// DISPLAYED; Copy always copies the complete original value, which is
// carried on the button in data-copy and is never read back out of the
// rendered text -- that text may be the truncated form ending in an
// ellipsis, and copying it would silently hand the analyst a value that
// is not the one on the event.
const DETAIL_TRUNCATE_AT = 100;

function detailCell(value, opts) {
  if (value === null || value === undefined) return "";
  const str = String(value);
  if (str === "") return "";

  // truncateAt is overridable so a value that should be shown shorter
  // than a timeline cell -- a credential hash in the evidence panel --
  // reuses this one Copy implementation instead of growing a second.
  const at = (opts && opts.truncateAt) || DETAIL_TRUNCATE_AT;
  const revealLabel = (opts && opts.revealLabel) || "Show full";
  const long = str.length > at;
  const short = str.slice(0, at);
  const id = `detail-${++cellIdCounter}`;
  // A short value keeps its controls on the same line so a dense
  // timeline does not double in height; a long one stacks them under
  // the wrapped text.
  const layout = long ? "detail-cell-long" : "detail-cell-inline";
  const toggle = long
    ? `<button type="button" class="secondary small detail-toggle-btn" data-target="${id}" data-full="${esc(str)}" data-short="${esc(short)}&hellip;" data-label="${esc(revealLabel)}">${esc(revealLabel)}</button>`
    : "";
  return `
    <div class="detail-cell ${layout}">
      <span id="${id}" class="detail-text${long ? " truncated" : ""}">${long ? esc(short) + "&hellip;" : esc(str)}</span>
      <div class="detail-actions">
        ${toggle}
        <button type="button" class="secondary small detail-copy-btn" data-copy="${esc(str)}" title="Copy the full value">Copy</button>
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
        // textContent, not innerHTML: the attribute value has already
        // been decoded by the HTML parser, so re-parsing it would
        // reinterpret any "&" the value legitimately contains.
        target.textContent = btn.dataset.short;
        btn.textContent = btn.dataset.label || "Show full";
      }
    });
  });
  root.querySelectorAll(".detail-copy-btn").forEach((btn) => {
    if (btn.dataset.wired) return;
    btn.dataset.wired = "1";
    btn.addEventListener("click", async (ev) => {
      ev.stopPropagation();
      // data-copy, never the cell's text: the cell may be showing the
      // truncated form, and the toggle's state must not change what a
      // copy produces.
      flashCopyState(btn, await copyText(btn.dataset.copy));
    });
  });
}

// eventDetailValue picks the most relevant single field to show for an
// event in a "Detail" column.
function eventDetailValue(e) {
  // For web evidence the URL is the detail -- a browser-cache row whose
  // detail read "0a1b2c3d_0" would name the cache file on disk rather
  // than the resource that was cached. A shortcut is the same shape of
  // problem: the row exists to say which TARGET was referenced, not
  // which .lnk file recorded it.
  const url = e.extra && e.extra.url;
  const target = e.extra && e.extra.target_path;

  // The same argument covers the two artifacts a registry hive yields
  // (Phase 15). A UserAssist row exists to say WHICH ITEM the shell
  // launched, and a ShellBag row to say WHICH LOCATION Explorer
  // recorded -- not to repeat the registry key both happen to live
  // under, which is nearly identical on every row and pushes the one
  // distinguishing value off the end of the cell. The key is still on
  // the event, and the detail view still shows it.
  const extra = e.extra || {};
  const shellItem = extra.reconstructed_path;
  const launched = extra.resolved_path || extra.decoded_name;

  // Phase 16 extends the same rule to the application and MRU
  // artifacts. Every one of them lives under a registry key that is
  // nearly identical on every row of its kind, so falling through to
  // registry_path filled the column with
  // "HKCU\Software\...\Explorer\RecentDocs" repeated down the page
  // while the value that actually distinguishes the rows was not shown.
  //
  // Selected by artifact_class rather than by reordering the fallbacks,
  // so the detail shown for every OTHER kind of event -- a registry Run
  // key in particular, where the key itself is the point -- is
  // unchanged.
  const p16 = {
    amcache: extra.application_path || extra.application_name,
    activities_cache: extra.display_text || extra.content_uri,
    recent_docs: e.file_path,
    muicache: extra.display_name || e.file_path,
    typed_paths: e.file_path,
    opensave_mru: e.file_path,
    // Phase 18. The account is what distinguishes one SAM row from the
    // next; the registry key differs only in the RID and would fill the
    // column with HKLM\SAM\Domains\Account\Users repeated down the page.
    //
    // The NTLM hash is deliberately NOT here. The Detail column is
    // rendered into every timeline row, is what the Copy button beside
    // it copies by default, and is the column an analyst screenshots.
    // Credential material belongs in the event's own detail view, where
    // it has its own labelled field and its own Copy control.
    sam_account: extra.account_name
      ? `${extra.account_name} (RID ${extra.rid})`
      : `RID ${extra.rid || "?"}`,
    // Phase 20. The endpoint is the whole point of a FileZilla row --
    // which host, over what, as whom. Falling through would have shown
    // the source filename, identical on every entry in the file.
    filezilla_server_entry: filezillaDetail(extra),
    // An image row is identified by its file; a GPS row by the position
    // it carries, which is the one value an analyst is scanning for.
    image_metadata: e.file_path,
    image_gps: extra.gps_coordinates
      ? `${extra.gps_coordinates}${extra.country ? ` (${extra.country})` : ""} - ${e.file_path || ""}`.trim()
      : e.file_path,
  }[extra.artifact_class];

  return e.command_line || shellItem || launched || p16 ||
    e.registry_path || url || target || e.file_path || e.network_dest || "";
}

// filezillaDetail renders a FileZilla entry as the connection it
// describes. The password is not part of it and never can be: the field
// does not exist on the event -- see internal/filezilla.
function filezillaDetail(extra) {
  const host = extra.server_ipv4 || extra.server_ipv6 || extra.server_hostname || extra.server_host;
  if (!host) return "";
  const proto = extra.protocol && extra.protocol !== "unrecognized" ? extra.protocol : "";
  const port = extra.server_port ? `:${extra.server_port}` : "";
  const user = extra.server_username ? ` as ${extra.server_username}` : "";
  return `${proto ? proto + " " : ""}${host}${port}${user}`;
}


// ---------------- Photo Map (Phase 21) ----------------
//
// A map of the images in this case whose EXIF recorded a coordinate.
//
// # It shows evidence, and says which part is which
//
// A marker's POSITION is observed: the latitude and longitude the image
// itself carries. Its COUNTRY is derived -- an offline point-in-polygon
// test Tracefall performed against a bundled boundary dataset, not
// something the camera wrote. Every card and the lightbox header keep
// the two apart, because a country name rendered beside a pin is exactly
// the value an analyst will otherwise assume came out of the file.
//
// # It creates nothing
//
// Every marker IS an existing image_gps event. The map neither parses an
// image nor derives a coordinate; it reads back what the EXIF parser
// already produced, which is why "View timeline event" can go straight
// to the same event rather than to a copy of it.
//
// # Why the map is drawn here rather than fetched
//
// The basemap is country outlines from the dataset already compiled into
// the binary, drawn to a canvas. No tile server, no API key, no network
// request -- and no third party learns which coordinates are being
// investigated, which a tile request would disclose one tile at a time.
// The trade is that this is a plain political outline rather than
// streets and terrain; for placing a photograph in a country and
// verifying a coordinate, that is what is needed.

const GEO_MAP_MIN_ZOOM = 0;
const GEO_MAP_MAX_ZOOM = 12;
// Screen-space cell size for clustering. Markers are ~64px, so a cell
// this size means two markers cluster exactly when they would overlap.
const GEO_CLUSTER_CELL_PX = 76;

// geoState holds the current map view and dataset. Module-level so
// switching tabs and returning does not refetch the basemap, which is
// the largest payload the UI ever requests.
const geoState = {
  caseId: null,
  photos: [],
  result: null,
  basemap: null,
  // View: the world-pixel centre and integer-ish zoom. Fractional zoom
  // is allowed so wheel zooming is smooth.
  zoom: 2,
  centerLon: 0,
  centerLat: 20,
  sort: "time",
  filters: { country: "", collection: "", filename: "", from: "", to: "" },
  selected: null,
  dragging: null,
};

// --- Web Mercator ---
//
// The standard projection for slippy maps, used here so the drawn
// outlines and the markers share one coordinate system. Latitude is
// clamped to the Mercator limit rather than allowed to run to infinity
// at the poles.
const GEO_MERCATOR_MAX_LAT = 85.05112878;

function geoWorldSize(zoom) {
  return 256 * Math.pow(2, zoom);
}

function geoLonToX(lon, zoom) {
  return ((lon + 180) / 360) * geoWorldSize(zoom);
}

function geoLatToY(lat, zoom) {
  const clamped = Math.max(-GEO_MERCATOR_MAX_LAT, Math.min(GEO_MERCATOR_MAX_LAT, lat));
  const rad = (clamped * Math.PI) / 180;
  const y = Math.log(Math.tan(Math.PI / 4 + rad / 2));
  return (1 - y / Math.PI) / 2 * geoWorldSize(zoom);
}

function geoXToLon(x, zoom) {
  return (x / geoWorldSize(zoom)) * 360 - 180;
}

function geoYToLat(y, zoom) {
  const n = Math.PI * (1 - (2 * y) / geoWorldSize(zoom));
  return (180 / Math.PI) * Math.atan(Math.sinh(n));
}

// geoViewport converts between screen pixels in the map element and
// world pixels at the current zoom.
function geoViewport(el) {
  const rect = el.getBoundingClientRect();
  const cx = geoLonToX(geoState.centerLon, geoState.zoom);
  const cy = geoLatToY(geoState.centerLat, geoState.zoom);
  return {
    width: rect.width,
    height: rect.height,
    originX: cx - rect.width / 2,
    originY: cy - rect.height / 2,
    toScreen(lon, lat) {
      return {
        x: geoLonToX(lon, geoState.zoom) - this.originX,
        y: geoLatToY(lat, geoState.zoom) - this.originY,
      };
    },
  };
}

// currentCaseId reads the case out of the current route, for the few
// places that build a cross-view link without having been handed one.
function currentCaseId() {
  return (window.location.hash.match(/^#\/cases\/([^/?]+)/) || [])[1] || "";
}

// geoFocusEvent is set by a "View on map" link so the map, once it
// loads, selects and centres the photo the analyst came from.
let geoFocusEvent = null;

document.addEventListener("click", (e) => {
  const link = e.target.closest("a[data-geo-focus]");
  if (link) geoFocusEvent = link.dataset.geoFocus || null;
});

// geoAfterLayout runs fn once the browser has had a chance to lay the
// page out.
//
// requestAnimationFrame alone is not enough: a frame callback does not
// fire while the tab is not being composited (backgrounded, or a
// non-visible embedded view), and the map then sat unrendered with a
// default 300x150 canvas until the tab was looked at again. A timeout
// still fires there, so whichever mechanism runs first wins and the
// other becomes a no-op.
function geoAfterLayout(fn) {
  let done = false;
  const run = () => {
    if (done) return;
    done = true;
    fn();
  };
  requestAnimationFrame(run);
  setTimeout(run, 0);
}

// ---------------- Tab ----------------

async function renderGeoMapTab(content, caseId) {
  content.innerHTML = `<p class="empty">Loading photo map...</p>`;

  if (geoState.caseId !== caseId) {
    geoState.caseId = caseId;
    geoState.filters = { country: "", collection: "", filename: "", from: "", to: "" };
    geoState.selected = null;
    geoState.zoom = 2;
    geoState.centerLon = 0;
    geoState.centerLat = 20;
    geoState.hasFitted = false;
  }

  let result;
  try {
    // The basemap is fetched once per session and reused: it is world
    // geography, identical for every case.
    const [photos, basemap] = await Promise.all([
      api(`/cases/${caseId}/geo/photos${geoQueryString()}`),
      geoState.basemap ? Promise.resolve(geoState.basemap) : api(`/geo/basemap`),
    ]);
    geoState.basemap = basemap;
    result = photos;
  } catch (e) {
    content.innerHTML = errorBox(e);
    return;
  }

  geoState.result = result;
  geoState.photos = result.photos || [];

  content.innerHTML = geoMapShell(result);
  wireGeoMap(content, caseId);

  // Fit and first paint after layout: both measure the map element, and
  // measuring it in the same turn that created it can read a width the
  // grid has not resolved yet.
  geoAfterLayout(() => {
    const live = document.querySelector(".geo-wrap");
    if (!live) return;
    if (geoState.photos.length > 0 && !geoState.hasFitted) {
      geoFitToPhotos(live);
      geoState.hasFitted = true;
    }

    // Arrived from a Timeline event's "View on map": select that exact
    // photo rather than leaving the analyst to find it again.
    if (geoFocusEvent) {
      const target = geoFocusEvent;
      geoFocusEvent = null;
      if (geoState.photos.some((p) => p.event_id === target)) {
        geoState.zoom = Math.max(geoState.zoom, 5);
        geoSelect(live, target, { center: true });
        return;
      }
    }
    geoRender(live);
  });


}

function geoQueryString() {
  const f = geoState.filters;
  const q = new URLSearchParams();
  if (f.country) q.set("country", f.country);
  if (f.collection) q.set("collection_id", f.collection);
  if (f.filename) q.set("filename", f.filename);
  if (f.from) q.set("from", f.from);
  if (f.to) q.set("to", f.to);
  const s = q.toString();
  return s ? `?${s}` : "";
}

function geoMapShell(result) {
  const total = result.total || 0;
  const withoutGPS = result.images_without_gps || 0;

  // The empty state must never be an empty map: a map with no markers
  // and no explanation reads as "nothing was found here", which is a
  // different claim from "no image in this case carries a coordinate".
  if (total === 0 && !geoAnyFilterActive()) {
    return `
      <section class="geo-wrap">
        ${geoIntro(result)}
        <div class="empty-panel">
          <h3>No geolocated photos found in this case.</h3>
          <p>No image in this case's imported evidence carries a usable EXIF GPS coordinate.</p>
          ${
            withoutGPS > 0
              ? `<p>${withoutGPS} image artifact${withoutGPS === 1 ? "" : "s"} ${
                  withoutGPS === 1 ? "was" : "were"
                } found and parsed, but ${
                  withoutGPS === 1 ? "it records" : "they record"
                } no coordinate. ${
                  withoutGPS === 1 ? "It is" : "They are"
                } in the Evidence and Timeline views; nothing is placed on the map at a guessed position.</p>`
              : ""
          }
        </div>
      </section>`;
  }

  return `
    <section class="geo-wrap">
      ${geoIntro(result)}
      ${geoFilterBar(result)}
      <div class="geo-layout">
        <div class="geo-map" id="geo-map" tabindex="0" role="application"
             aria-label="Map of photographs with EXIF GPS coordinates">
          <canvas id="geo-canvas"></canvas>
          <div class="geo-markers" id="geo-markers"></div>
          <div class="geo-controls">
            <button type="button" class="geo-btn" id="geo-zoom-in" aria-label="Zoom in">+</button>
            <button type="button" class="geo-btn" id="geo-zoom-out" aria-label="Zoom out">&minus;</button>
            <button type="button" class="geo-btn geo-btn-wide" id="geo-fit">Fit</button>
          </div>
          <div class="geo-attrib" id="geo-attrib"></div>
        </div>
        <aside class="geo-side" id="geo-side"></aside>
      </div>
    </section>`;
}

function geoIntro(result) {
  const total = result.total || 0;
  const withoutGPS = result.images_without_gps || 0;
  return `
    <div class="geo-intro">
      <h2>Photo Map</h2>
      <p class="geo-lede">
        ${total} image${total === 1 ? "" : "s"} with an EXIF GPS coordinate${
          withoutGPS > 0
            ? ` &middot; ${withoutGPS} image${withoutGPS === 1 ? "" : "s"} in this case record${
                withoutGPS === 1 ? "s" : ""
              } no coordinate and ${withoutGPS === 1 ? "is" : "are"} not shown`
            : ""
        }
      </p>
      <p class="geo-note">${esc(result.note || "")}</p>
    </div>`;
}

function geoAnyFilterActive() {
  const f = geoState.filters;
  return Boolean(f.country || f.collection || f.filename || f.from || f.to);
}

function geoFilterBar(result) {
  const countries = result.countries || [];
  const opt = (v, label, sel) =>
    `<option value="${esc(v)}"${sel === v ? " selected" : ""}>${esc(label)}</option>`;
  const f = geoState.filters;

  return `
    <div class="geo-filters">
      <label class="geo-field">
        <span>Country</span>
        <select id="geo-f-country">
          ${opt("", "All countries", f.country)}
          ${countries.map((c) => opt(c, c, f.country)).join("")}
        </select>
      </label>
      <label class="geo-field">
        <span>Filename</span>
        <input type="search" id="geo-f-filename" placeholder="contains..." value="${esc(f.filename)}">
      </label>
      <label class="geo-field">
        <span>From</span>
        <input type="text" id="geo-f-from" placeholder="YYYY-MM-DD" value="${esc(f.from)}">
      </label>
      <label class="geo-field">
        <span>To</span>
        <input type="text" id="geo-f-to" placeholder="YYYY-MM-DD" value="${esc(f.to)}">
      </label>
      <label class="geo-field">
        <span>Sort</span>
        <select id="geo-f-sort">
          ${opt("time", "Chronological", geoState.sort)}
          ${opt("filename", "Filename", geoState.sort)}
          ${opt("country", "Country", geoState.sort)}
        </select>
      </label>
      <button type="button" class="btn-secondary" id="geo-f-clear">Clear</button>
      <span class="geo-gps-only" title="Images without a coordinate are never placed on the map">
        Showing only images with GPS
      </span>
    </div>`;
}

// ---------------- Rendering ----------------

function geoRender(root) {
  const el = root.querySelector("#geo-map");
  if (!el) return;

  // A render is only as good as the measurement behind it. The first
  // one after mounting can land before the grid has resolved its
  // columns, which produced a 2px-wide canvas and markers projected off
  // the left edge -- and, because the markers were then outside a 2px
  // viewport, lazy-loaded thumbnails that never loaded at all.
  //
  // Rather than trust a suspicious rect, retry on the next frame. The
  // ResizeObserver below is the steady-state mechanism; this is what
  // stops a bad first measurement from being baked in before it runs.
  const rect = el.getBoundingClientRect();
  if (rect.width < 50 || rect.height < 50) {
    if (!geoState.pendingFrame) {
      geoState.pendingFrame = true;
      geoAfterLayout(() => {
        geoState.pendingFrame = false;
        const live = document.querySelector(".geo-wrap");
        if (live) geoRender(live);
      });
    }
    return;
  }

  geoDrawBasemap(el);
  geoDrawMarkers(el);
  geoRenderSide(root);
  const attrib = root.querySelector("#geo-attrib");
  if (attrib && geoState.basemap && geoState.basemap.dataset) {
    const d = geoState.basemap.dataset;
    attrib.textContent = `${d.source || "boundaries"} v${d.version || "?"} - drawn offline`;
    attrib.title = geoState.basemap.note || "";
  }
}

// geoDrawBasemap paints the country outlines to the canvas.
//
// Canvas rather than SVG or DOM: 1,100 rings is far more path data than
// is comfortable as elements, and it repaints on every pan frame.
function geoDrawBasemap(el) {
  const canvas = el.querySelector("#geo-canvas");
  if (!canvas || !geoState.basemap) return;

  const rect = el.getBoundingClientRect();
  const dpr = window.devicePixelRatio || 1;
  const w = Math.max(1, Math.round(rect.width));
  const h = Math.max(1, Math.round(rect.height));
  if (canvas.width !== w * dpr || canvas.height !== h * dpr) {
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    canvas.style.width = `${w}px`;
    canvas.style.height = `${h}px`;
  }

  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);

  const css = getComputedStyle(document.documentElement);
  const sea = css.getPropertyValue("--geo-sea").trim() || "#0f1720";
  const land = css.getPropertyValue("--geo-land").trim() || "#1d2a35";
  const line = css.getPropertyValue("--geo-outline").trim() || "#3a5064";

  ctx.fillStyle = sea;
  ctx.fillRect(0, 0, w, h);

  const vp = geoViewport(el);
  const world = geoWorldSize(geoState.zoom);

  ctx.fillStyle = land;
  ctx.strokeStyle = line;
  ctx.lineWidth = 1;

  for (const ring of geoState.basemap.rings || []) {
    // Two passes, offset by one world width, so a ring is drawn on
    // whichever copy of the world is currently on screen. Without this
    // the map goes blank when panned past the antimeridian.
    for (const shift of [0, -world, world]) {
      let started = false;
      let anyVisible = false;
      ctx.beginPath();
      for (let i = 0; i < ring.length; i += 2) {
        const x = geoLonToX(ring[i], geoState.zoom) - vp.originX + shift;
        const y = geoLatToY(ring[i + 1], geoState.zoom) - vp.originY;
        if (x > -200 && x < w + 200 && y > -200 && y < h + 200) anyVisible = true;
        if (!started) {
          ctx.moveTo(x, y);
          started = true;
        } else {
          ctx.lineTo(x, y);
        }
      }
      if (!anyVisible) {
        continue;
      }
      ctx.closePath();
      ctx.fill();
      ctx.stroke();
    }
  }
}

// geoCluster groups photos that would overlap on screen into one marker.
//
// A grid in SCREEN space, not in degrees: what matters is whether two
// markers collide at the current zoom, and a degree is a different
// distance at different latitudes.
function geoCluster(el) {
  const vp = geoViewport(el);
  const cells = new Map();

  for (const p of geoState.photos) {
    const pt = vp.toScreen(p.longitude, p.latitude);
    // Off-screen photos are still clustered, so a cluster count is the
    // true count and not "the ones that happened to be visible".
    const key = `${Math.floor(pt.x / GEO_CLUSTER_CELL_PX)}:${Math.floor(pt.y / GEO_CLUSTER_CELL_PX)}`;
    let c = cells.get(key);
    if (!c) {
      c = { photos: [], x: 0, y: 0 };
      cells.set(key, c);
    }
    c.photos.push(p);
    c.x += pt.x;
    c.y += pt.y;
  }

  const out = [];
  for (const c of cells.values()) {
    out.push({
      photos: c.photos,
      x: c.x / c.photos.length,
      y: c.y / c.photos.length,
    });
  }
  return out;
}

function geoDrawMarkers(el) {
  const host = el.querySelector("#geo-markers");
  if (!host) return;

  const rect = el.getBoundingClientRect();
  const clusters = geoCluster(el);
  const parts = [];

  for (const c of clusters) {
    // Only markers on (or near) the screen become DOM. A case with
    // thousands of photos still produces a handful of elements.
    if (c.x < -120 || c.x > rect.width + 120 || c.y < -120 || c.y > rect.height + 120) continue;

    if (c.photos.length === 1) {
      const p = c.photos[0];
      geoPreloadThumb(p);
      const sel = geoState.selected && geoState.selected.event_id === p.event_id;
      parts.push(`
        <button type="button" class="geo-marker${sel ? " selected" : ""}"
                style="left:${c.x}px;top:${c.y}px"
                data-event-id="${esc(p.event_id)}"
                title="${esc(p.filename)}">
          <span class="geo-marker-img">${geoThumbTag(p)}</span>
          <span class="geo-marker-tail" aria-hidden="true"></span>
        </button>`);
    } else {
      // Only the cluster's lead image is fetched -- a cluster of two
      // hundred photos costs one preview, not two hundred.
      const lead = c.photos[0];
      geoPreloadThumb(lead);
      parts.push(`
        <button type="button" class="geo-marker geo-cluster"
                style="left:${c.x}px;top:${c.y}px"
                data-cluster="${esc(c.photos.map((p) => p.event_id).join(","))}"
                title="${c.photos.length} photos here - click to zoom in">
          <span class="geo-marker-img">${geoThumbTag(lead)}
            <span class="geo-cluster-count">${c.photos.length}</span>
          </span>
          <span class="geo-marker-tail" aria-hidden="true"></span>
        </button>`);
    }
  }
  host.innerHTML = parts.join("");
}

// geoThumbCache remembers which thumbnails have been requested, and
// whether each one loaded.
//
// It exists because markers are rebuilt from scratch on every pan and
// zoom frame. An <img loading="lazy"> in that markup is destroyed and
// recreated before the browser ever gets round to fetching it, so the
// previews simply never appeared -- which is exactly what happened
// before this cache was added.
//
// Fetching stays LAZY in the sense that matters forensically and for
// performance: a thumbnail is requested only for a photo whose marker is
// actually on screen (markers are clustered and viewport-culled before
// any of this runs), and only once per session. A case with ten thousand
// photographs never generates ten thousand previews; it generates the
// handful the analyst has actually looked at.
const geoThumbCache = new Map(); // source_file_id -> "loading" | "ok" | "failed"

function geoThumbURL(sourceFileID) {
  return `/api/cases/${encodeURIComponent(geoState.caseId)}/images/${encodeURIComponent(
    sourceFileID
  )}/thumbnail`;
}

// geoPreloadThumb warms the browser cache for one photo, then repaints
// the markers once so the newly available image is drawn. The repaint is
// deferred to a frame so a screenful arriving at once costs one repaint
// rather than one per image.
function geoPreloadThumb(p) {
  if (!p.available || geoThumbCache.has(p.source_file_id)) return;
  geoThumbCache.set(p.source_file_id, "loading");

  const img = new Image();
  img.decoding = "async";
  const settle = (state) => {
    geoThumbCache.set(p.source_file_id, state);
    if (geoState.repaintFrame) return;
    geoState.repaintFrame = true;
    geoAfterLayout(() => {
      geoState.repaintFrame = false;
      const live = document.querySelector(".geo-wrap");
      if (live) geoRender(live);
    });
  };
  img.onload = () => settle("ok");
  // A preview that cannot be produced is a displayable fact, not a
  // failure to hide: the marker keeps its place and says so.
  img.onerror = () => settle("failed");
  img.src = geoThumbURL(p.source_file_id);
}

// geoThumbTag renders a marker's preview from whatever the cache knows.
// An image that has not loaded yet, failed, or has no servable bytes all
// render as a labelled placeholder rather than a browser broken-image
// icon.
function geoThumbTag(p) {
  if (!p.available) {
    return `<span class="geo-thumb-missing" title="image bytes unavailable">!</span>`;
  }
  const state = geoThumbCache.get(p.source_file_id);
  if (state === "ok") {
    return `<img src="${esc(geoThumbURL(p.source_file_id))}" alt="" decoding="async">`;
  }
  if (state === "failed") {
    return `<span class="geo-thumb-missing" title="preview unavailable">!</span>`;
  }
  return `<span class="geo-thumb-pending" aria-hidden="true"></span>`;
}

// ---------------- Side panel (the photo card) ----------------

function geoRenderSide(root) {
  const side = root.querySelector("#geo-side");
  if (!side) return;

  if (!geoState.selected) {
    const n = geoState.photos.length;
    side.innerHTML = `
      <div class="geo-card geo-card-empty">
        <h3>${n} photo${n === 1 ? "" : "s"} on the map</h3>
        <p>Select a marker to see the image, its EXIF metadata and its provenance.</p>
        ${geoSortedList()}
      </div>`;
    return;
  }

  const p = geoState.selected;
  const caseId = geoState.caseId;
  const thumb = p.available
    ? `<img class="geo-card-thumb" src="/api/cases/${encodeURIComponent(caseId)}/images/${encodeURIComponent(
        p.source_file_id
      )}/thumbnail" alt="Preview of ${esc(p.filename)}" loading="lazy">`
    : `<div class="geo-card-thumb geo-card-thumb-missing">image unavailable</div>`;

  const row = (label, value, opts) =>
    value
      ? `<div class="cred-field"><span class="cred-label">${esc(label)}</span>
           <span class="cred-value">${detailCell(value, opts)}</span></div>`
      : "";

  side.innerHTML = `
    <div class="geo-card">
      <button type="button" class="geo-card-close" id="geo-card-close" aria-label="Close">&times;</button>
      ${thumb}
      <h3 class="geo-card-name">${esc(p.filename)}</h3>

      <div class="img-section">Observed &mdash; stored in the file</div>
      ${row("GPS", `${p.latitude}, ${p.longitude}`)}
      ${row("As stored", [p.latitude_raw, p.longitude_raw].filter(Boolean).join(" / "))}
      ${row("EXIF taken", p.exif_taken)}
      ${row("Camera", [p.camera_make, p.camera_model].filter(Boolean).join(" "))}
      ${row("Dimensions", p.image_dimensions)}

      <div class="img-section">Derived &mdash; computed by Tracefall</div>
      ${row("Country", p.country || "unavailable")}
      ${row("Country code", p.country_iso)}
      ${row("Confidence", p.country_confidence)}
      ${row("Coordinate precision", p.coordinate_precision)}

      <div class="img-section">Evidence</div>
      ${row("Source path", p.path)}
      ${row("Collection", p.collection_label || p.collection_id)}
      ${row("Evidence SHA-256", p.sha256)}
      ${row("Event time", p.timestamp ? fmtTime(p.timestamp) : NO_TIMESTAMP_LABEL)}
      ${p.unavailable_reason ? `<p class="cred-note geo-warn">${esc(p.unavailable_reason)}</p>` : ""}

      <div class="geo-card-actions">
        <button type="button" class="btn-primary" id="geo-view-image"${p.available ? "" : " disabled"}>View image</button>
        <button type="button" class="btn-secondary" id="geo-view-meta">Show metadata</button>
        <a class="btn-secondary" href="#/cases/${esc(caseId)}/evidence">View evidence</a>
        <a class="btn-secondary" href="#/cases/${esc(caseId)}/summary?event=${encodeURIComponent(
          p.event_id
        )}">View timeline event</a>
      </div>
      <p class="cred-note">The position is what this image CONTAINS. The country is derived from that
      coordinate by Tracefall and is not stored in the image.</p>
    </div>`;
}

// geoSortedList is the "many photos" fallback: a plain list, ordered the
// way the analyst asked. It exists because a map is bad at answering
// "what have I got", and because photos with no timestamp must still be
// reachable without being given an invented position in a sequence.
function geoSortedList() {
  const sorted = geoSortPhotos(geoState.photos.slice());
  if (sorted.length === 0) return "";
  const untimed = sorted.filter((p) => !p.timestamp).length;
  return `
    <ol class="geo-list">
      ${sorted
        .map(
          (p) => `<li><button type="button" class="geo-list-item" data-event-id="${esc(p.event_id)}">
            <span class="geo-list-name">${esc(p.filename)}</span>
            <span class="geo-list-meta">${esc(p.country || "country unavailable")} &middot; ${
            p.timestamp ? esc(fmtTime(p.timestamp)) : NO_TIMESTAMP_LABEL
          }</span>
          </button></li>`
        )
        .join("")}
    </ol>
    ${
      untimed > 0
        ? `<p class="cred-note">${untimed} photo${untimed === 1 ? " has" : "s have"} no recorded time.
           ${untimed === 1 ? "It is" : "They are"} listed after the timed ones, in filename order &mdash;
           not placed in a sequence the evidence does not support.</p>`
        : ""
    }`;
}

function geoSortPhotos(list) {
  const byName = (a, b) => (a.filename || "").localeCompare(b.filename || "");
  switch (geoState.sort) {
    case "filename":
      return list.sort(byName);
    case "country":
      return list.sort((a, b) => (a.country || "").localeCompare(b.country || "") || byName(a, b));
    default:
      // Chronological, with the untimed after -- never interleaved into
      // an order the evidence does not establish.
      return list.sort((a, b) => {
        if (a.timestamp && b.timestamp) return a.timestamp.localeCompare(b.timestamp) || byName(a, b);
        if (a.timestamp) return -1;
        if (b.timestamp) return 1;
        return byName(a, b);
      });
  }
}

// ---------------- Interaction ----------------

function wireGeoMap(root, caseId) {
  const el = root.querySelector("#geo-map");
  if (!el) return;

  const rerender = () => geoRender(root);

  // Pan.
  el.addEventListener("pointerdown", (e) => {
    if (e.target.closest(".geo-marker") || e.target.closest(".geo-controls")) return;
    el.setPointerCapture(e.pointerId);
    geoState.dragging = { x: e.clientX, y: e.clientY, moved: false };
    el.classList.add("dragging");
  });
  el.addEventListener("pointermove", (e) => {
    if (!geoState.dragging) return;
    const dx = e.clientX - geoState.dragging.x;
    const dy = e.clientY - geoState.dragging.y;
    if (Math.abs(dx) + Math.abs(dy) > 2) geoState.dragging.moved = true;
    geoState.dragging.x = e.clientX;
    geoState.dragging.y = e.clientY;

    const z = geoState.zoom;
    const cx = geoLonToX(geoState.centerLon, z) - dx;
    const cy = geoLatToY(geoState.centerLat, z) - dy;
    geoState.centerLon = geoXToLon(cx, z);
    geoState.centerLat = geoYToLat(Math.max(0, Math.min(geoWorldSize(z), cy)), z);
    rerender();
  });
  const endDrag = (e) => {
    if (!geoState.dragging) return;
    geoState.dragging = null;
    el.classList.remove("dragging");
    if (e && e.pointerId !== undefined && el.hasPointerCapture(e.pointerId)) {
      el.releasePointerCapture(e.pointerId);
    }
  };
  el.addEventListener("pointerup", endDrag);
  el.addEventListener("pointercancel", endDrag);

  // Zoom, anchored on the cursor so the point under it stays put.
  el.addEventListener(
    "wheel",
    (e) => {
      e.preventDefault();
      geoZoomAt(el, e.deltaY < 0 ? 0.5 : -0.5, e.clientX, e.clientY);
      rerender();
    },
    { passive: false }
  );

  root.querySelector("#geo-zoom-in")?.addEventListener("click", () => {
    geoZoomAt(el, 1);
    rerender();
  });
  root.querySelector("#geo-zoom-out")?.addEventListener("click", () => {
    geoZoomAt(el, -1);
    rerender();
  });
  root.querySelector("#geo-fit")?.addEventListener("click", () => {
    geoFitToPhotos(root);
    rerender();
  });

  // Keyboard: the map is focusable, so it must be operable without a
  // pointer.
  el.addEventListener("keydown", (e) => {
    const step = 60;
    const z = geoState.zoom;
    let dx = 0;
    let dy = 0;
    switch (e.key) {
      case "ArrowLeft": dx = -step; break;
      case "ArrowRight": dx = step; break;
      case "ArrowUp": dy = -step; break;
      case "ArrowDown": dy = step; break;
      case "+": case "=": geoZoomAt(el, 1); rerender(); e.preventDefault(); return;
      case "-": geoZoomAt(el, -1); rerender(); e.preventDefault(); return;
      default: return;
    }
    e.preventDefault();
    geoState.centerLon = geoXToLon(geoLonToX(geoState.centerLon, z) + dx, z);
    geoState.centerLat = geoYToLat(geoLatToY(geoState.centerLat, z) + dy, z);
    rerender();
  });

  // Markers.
  root.querySelector("#geo-markers")?.addEventListener("click", (e) => {
    const marker = e.target.closest(".geo-marker");
    if (!marker) return;
    if (marker.dataset.cluster) {
      geoZoomToCluster(root, marker.dataset.cluster.split(","));
      return;
    }
    geoSelect(root, marker.dataset.eventId);
  });

  // The side list.
  root.querySelector("#geo-side")?.addEventListener("click", (e) => {
    const item = e.target.closest(".geo-list-item");
    if (item) {
      geoSelect(root, item.dataset.eventId, { center: true });
      return;
    }
    if (e.target.closest("#geo-card-close")) {
      geoState.selected = null;
      geoRender(root);
      return;
    }
    if (e.target.closest("#geo-view-image")) {
      geoOpenLightbox(geoState.selected);
      return;
    }
    if (e.target.closest("#geo-view-meta")) {
      geoOpenMetadata(geoState.selected);
    }
  });

  // Filters.
  const reload = () => renderGeoMapTab(root, caseId);
  const bind = (id, key, evt) =>
    root.querySelector(id)?.addEventListener(evt, (e) => {
      geoState.filters[key] = e.target.value.trim();
      reload();
    });
  bind("#geo-f-country", "country", "change");
  bind("#geo-f-from", "from", "change");
  bind("#geo-f-to", "to", "change");
  root.querySelector("#geo-f-filename")?.addEventListener("change", (e) => {
    geoState.filters.filename = e.target.value.trim();
    reload();
  });
  root.querySelector("#geo-f-sort")?.addEventListener("change", (e) => {
    geoState.sort = e.target.value;
    geoRenderSide(root);
  });
  root.querySelector("#geo-f-clear")?.addEventListener("click", () => {
    geoState.filters = { country: "", collection: "", filename: "", from: "", to: "" };
    reload();
  });

  // The canvas must follow the element's size.
  if (window.ResizeObserver && !geoState.observer) {
    geoState.observer = new ResizeObserver(() => {
      const live = document.getElementById("geo-map");
      if (live) geoRender(live.closest(".geo-wrap") || document);
    });
  }
  if (geoState.observer) {
    geoState.observer.disconnect();
    geoState.observer.observe(el);
  }
}

function geoZoomAt(el, delta, clientX, clientY) {
  const before = geoState.zoom;
  const next = Math.max(GEO_MAP_MIN_ZOOM, Math.min(GEO_MAP_MAX_ZOOM, before + delta));
  if (next === before) return;

  if (clientX === undefined) {
    geoState.zoom = next;
    return;
  }
  // Keep the geographic point under the cursor fixed across the zoom.
  const rect = el.getBoundingClientRect();
  const px = clientX - rect.left;
  const py = clientY - rect.top;
  const vp = geoViewport(el);
  const lon = geoXToLon(vp.originX + px, before);
  const lat = geoYToLat(vp.originY + py, before);

  geoState.zoom = next;
  const nx = geoLonToX(lon, next) - px + rect.width / 2;
  const ny = geoLatToY(lat, next) - py + rect.height / 2;
  geoState.centerLon = geoXToLon(nx, next);
  geoState.centerLat = geoYToLat(ny, next);
}

function geoFitToPhotos(root) {
  const el = (root.querySelector ? root.querySelector("#geo-map") : null) || document.getElementById("geo-map");
  if (!el || geoState.photos.length === 0) return;

  let minLon = 180;
  let maxLon = -180;
  let minLat = 90;
  let maxLat = -90;
  for (const p of geoState.photos) {
    minLon = Math.min(minLon, p.longitude);
    maxLon = Math.max(maxLon, p.longitude);
    minLat = Math.min(minLat, p.latitude);
    maxLat = Math.max(maxLat, p.latitude);
  }
  geoState.centerLon = (minLon + maxLon) / 2;
  geoState.centerLat = (minLat + maxLat) / 2;

  const rect = el.getBoundingClientRect();
  // Find the largest zoom at which every photo still fits, with margin
  // for the marker artwork itself.
  let best = GEO_MAP_MIN_ZOOM;
  for (let z = GEO_MAP_MAX_ZOOM; z >= GEO_MAP_MIN_ZOOM; z -= 0.25) {
    const w = Math.abs(geoLonToX(maxLon, z) - geoLonToX(minLon, z));
    const h = Math.abs(geoLatToY(minLat, z) - geoLatToY(maxLat, z));
    if (w < rect.width - 160 && h < rect.height - 160) {
      best = z;
      break;
    }
  }
  geoState.zoom = best;
}

function geoZoomToCluster(root, eventIds) {
  const set = new Set(eventIds);
  const members = geoState.photos.filter((p) => set.has(p.event_id));
  if (members.length === 0) return;

  // Photos at IDENTICAL coordinates can never be separated by zooming.
  // Expanding the cluster into the side list is the honest answer --
  // zooming forever would look broken.
  const allSame = members.every(
    (p) => p.latitude === members[0].latitude && p.longitude === members[0].longitude
  );
  if (allSame || geoState.zoom >= GEO_MAP_MAX_ZOOM) {
    geoShowClusterMembers(root, members);
    return;
  }

  const saved = geoState.photos;
  geoState.photos = members;
  geoFitToPhotos(root);
  geoState.photos = saved;
  geoRender(root);
}

function geoShowClusterMembers(root, members) {
  const side = root.querySelector("#geo-side");
  if (!side) return;
  geoState.selected = null;
  side.innerHTML = `
    <div class="geo-card geo-card-empty">
      <h3>${members.length} photos at this location</h3>
      <p>These photographs record the same coordinate, so zooming cannot separate them.</p>
      <ol class="geo-list">
        ${members
          .map(
            (p) => `<li><button type="button" class="geo-list-item" data-event-id="${esc(p.event_id)}">
              <span class="geo-list-name">${esc(p.filename)}</span>
              <span class="geo-list-meta">${
                p.timestamp ? esc(fmtTime(p.timestamp)) : NO_TIMESTAMP_LABEL
              }</span>
            </button></li>`
          )
          .join("")}
      </ol>
    </div>`;
}

function geoSelect(root, eventId, opts) {
  const p = geoState.photos.find((x) => x.event_id === eventId);
  if (!p) return;
  geoState.selected = p;
  if (opts && opts.center) {
    geoState.centerLon = p.longitude;
    geoState.centerLat = p.latitude;
  }
  geoRender(root);
}

// ---------------- Lightbox ----------------
//
// The full-resolution evidence image, served from the authorized
// endpoint. It is displayed by the browser's own image pipeline -- no
// canvas, no re-encode, nothing that would decode a 50-megapixel file
// into a JavaScript buffer.

function geoOpenLightbox(p) {
  if (!p || !p.available) return;
  const caseId = geoState.caseId;
  const src = `/api/cases/${encodeURIComponent(caseId)}/images/${encodeURIComponent(
    p.source_file_id
  )}/content`;

  const host = document.createElement("div");
  host.className = "geo-lightbox";
  host.setAttribute("role", "dialog");
  host.setAttribute("aria-modal", "true");
  host.setAttribute("aria-label", `Image ${p.filename}`);
  host.innerHTML = `
    <div class="geo-lb-bar">
      <div class="geo-lb-meta">
        <strong>${esc(p.filename)}</strong>
        <span>GPS ${esc(String(p.latitude))}, ${esc(String(p.longitude))} <em>(observed)</em></span>
        <span>${esc(p.country || "country unavailable")} <em>(derived)</em></span>
        <span>${p.exif_taken ? esc(p.exif_taken) + " <em>(EXIF)</em>" : "no EXIF timestamp"}</span>
      </div>
      <div class="geo-lb-tools">
        <button type="button" class="geo-btn" data-lb="out" aria-label="Zoom out">&minus;</button>
        <button type="button" class="geo-btn geo-btn-wide" data-lb="fit">Fit</button>
        <button type="button" class="geo-btn geo-btn-wide" data-lb="full">100%</button>
        <button type="button" class="geo-btn" data-lb="in" aria-label="Zoom in">+</button>
        <button type="button" class="geo-btn geo-btn-wide" data-lb="close">Close</button>
      </div>
    </div>
    <div class="geo-lb-stage" id="geo-lb-stage">
      <p class="geo-lb-status" id="geo-lb-status">Loading image...</p>
      <img id="geo-lb-img" alt="${esc(p.filename)}" hidden>
    </div>
    <p class="geo-lb-foot">Original evidence bytes, served unmodified. SHA-256 ${esc(p.sha256 || "unknown")}</p>`;

  document.body.appendChild(host);
  document.body.classList.add("geo-lb-open");

  const img = host.querySelector("#geo-lb-img");
  const status = host.querySelector("#geo-lb-status");
  const stage = host.querySelector("#geo-lb-stage");
  const view = { scale: 1, fit: true, x: 0, y: 0, drag: null };

  const apply = () => {
    img.style.transform = view.fit
      ? ""
      : `translate(${view.x}px, ${view.y}px) scale(${view.scale})`;
    img.classList.toggle("fit", view.fit);
  };

  img.addEventListener("load", () => {
    status.hidden = true;
    img.hidden = false;
    apply();
  });
  img.addEventListener("error", () => {
    // A failure here must not lose the record: the metadata stays on
    // screen behind the lightbox, and the reason is stated.
    status.textContent =
      "This image's bytes could not be served. Its metadata and provenance are unaffected " +
      "and remain available in the Evidence and Timeline views.";
    status.classList.add("geo-warn");
  });
  img.src = src;

  const close = () => {
    host.remove();
    document.body.classList.remove("geo-lb-open");
    document.removeEventListener("keydown", onKey);
  };
  const onKey = (e) => {
    if (e.key === "Escape") close();
  };
  document.addEventListener("keydown", onKey);

  host.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-lb]");
    if (!btn) {
      if (e.target === host || e.target === stage) close();
      return;
    }
    switch (btn.dataset.lb) {
      case "close": close(); break;
      case "fit": view.fit = true; view.scale = 1; view.x = 0; view.y = 0; apply(); break;
      case "full": view.fit = false; view.scale = 1; view.x = 0; view.y = 0; apply(); break;
      case "in": view.fit = false; view.scale = Math.min(8, view.scale * 1.5); apply(); break;
      case "out": view.fit = false; view.scale = Math.max(0.1, view.scale / 1.5); apply(); break;
    }
  });

  // Pan when zoomed in.
  stage.addEventListener("pointerdown", (e) => {
    if (view.fit) return;
    view.drag = { x: e.clientX, y: e.clientY };
    stage.setPointerCapture(e.pointerId);
  });
  stage.addEventListener("pointermove", (e) => {
    if (!view.drag) return;
    view.x += e.clientX - view.drag.x;
    view.y += e.clientY - view.drag.y;
    view.drag = { x: e.clientX, y: e.clientY };
    apply();
  });
  const stop = () => (view.drag = null);
  stage.addEventListener("pointerup", stop);
  stage.addEventListener("pointercancel", stop);

  host.querySelector('[data-lb="close"]').focus();
}

// geoOpenMetadata reaches the FULL EXIF record by going to the event the
// image metadata parser produced -- the same event the Timeline shows.
// The map does not keep a second copy of the metadata to drift from.
function geoOpenMetadata(p) {
  if (!p) return;
  const target = p.metadata_event_id || p.event_id;
  window.location.hash = `#/cases/${geoState.caseId}/summary?event=${encodeURIComponent(target)}`;
}

// ---------------- Router ----------------

// Navigation is guarded: an in-app move away from a case with unsaved
// changes asks first. hashchange fires AFTER the hash has changed, so a
// cancelled navigation has to restore the previous hash -- suppressing
// the resulting second event with a flag, or it would re-ask forever.
let lastHash = window.location.hash;
let restoringHash = false;
window.addEventListener("hashchange", async () => {
  if (restoringHash) {
    restoringHash = false;
    return;
  }
  // A deletion in flight pins the route.
  //
  // The modal covers the page and the navigation behind it is
  // pointer-inert, which stops a mouse -- but not a keyboard activating
  // a focused link, and not the back button. Either would leave the
  // modal reporting a deletion while the app rendered some other view,
  // or navigate INTO the case currently being destroyed. The route is
  // simply held until the request resolves; nothing is asked of the
  // analyst, because there is no useful choice to offer while a
  // destructive operation is already running.
  if (deleteInFlight) {
    restoringHash = true;
    window.location.hash = lastHash;
    return;
  }
  const target = window.location.hash;
  if (caseGuard.check() && !sameCaseSection(lastHash, target)) {
    const proceed = await confirmLeave();
    if (!proceed) {
      restoringHash = true;
      window.location.hash = lastHash;
      return;
    }
  }
  lastHash = target;
  route();
});

// sameCaseSection reports whether two hashes are the same case, so
// moving BETWEEN sections of the case being edited does not prompt --
// the pending change is still on screen and still saveable.
function sameCaseSection(a, b) {
  const caseOf = (h) => (h.match(/^#\/cases\/([^/]+)/) || [])[1] || "";
  const ca = caseOf(a);
  return ca !== "" && ca === caseOf(b);
}
window.addEventListener("DOMContentLoaded", async () => {
  checkHealth();
  // The session is resolved BEFORE the first route render, so an
  // unauthenticated visitor never briefly sees a case list shell before
  // being sent to the login form.
  await loadSession();
  renderUserBar();
  if (authState.enabled && !authState.authenticated) {
    renderLogin(authState.setupRequired
      ? "No accounts exist yet. Sign in with the administrator account printed in the server's startup output."
      : "");
    return;
  }
  // A gated account goes straight to the change-password screen, on this
  // load and on every subsequent one until the change is made.
  if (authState.enabled && authState.mustChangePassword) {
    renderPasswordChange();
    return;
  }
  // Display settings load BEFORE the first render, so no timestamp is
  // ever painted in UTC and then silently repainted in another zone --
  // a flicker between two different readings of the same instant is
  // exactly the kind of thing that gets a time written down wrong.
  await loadDisplaySettings();
  renderTimezoneControl();
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
  if (hash === "/settings/integrations") {
    renderedCaseId = null;
    renderedTab = null;
    tabScroll.clear();
    caseGuard.reset();
    setSidebarOpen(false);
    renderIntegrationSettings();
    return;
  }
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
  // No case on screen: a stale guard must not block navigation.
  caseGuard.reset();
  renderCaseList();
}

// ---------------- Unsaved-changes guard (Phase 13) ----------------
//
// Case status and priority are pending until saved, so leaving the page
// can lose them. Two mechanisms are needed, because they protect
// different exits:
//
//   * In-app navigation (sidebar, All Cases, another case) is fully
//     under our control, so it gets a real three-way choice:
//     Save / Discard / Cancel.
//   * A browser reload, a closed tab or the back button cannot be
//     intercepted with a custom dialog -- browsers deliberately only
//     allow the native beforeunload prompt, with wording they control.
//     Pretending otherwise would be a guard that silently does nothing.
const caseGuard = {
  // check reports whether unsaved changes exist. Replaced by
  // wireCaseMetadataControls while a case is on screen.
  check: () => false,
  save: async () => true,
  discard: () => {},
  // reset is called when leaving a case, so a stale guard from a
  // previous case cannot block navigation in a new one.
  reset() {
    this.check = () => false;
    this.save = async () => true;
    this.discard = () => {};
  },
};

// confirmLeave asks what to do about pending changes.
//
// Returns true if navigation may continue. window.confirm is used
// rather than a bespoke modal because it is synchronous and cannot be
// missed; the three-way choice is expressed as two sequential questions
// so Cancel is always reachable.
async function confirmLeave() {
  if (!caseGuard.check()) return true;
  const save = window.confirm(
    "You have unsaved changes to this case's status or priority.\n\n" +
      "OK  - save them now and continue\n" +
      "Cancel - decide whether to discard them"
  );
  if (save) {
    const ok = await caseGuard.save();
    if (!ok) {
      window.alert("The changes could not be saved. You are still on the case, and your changes are intact.");
      return false;
    }
    return true;
  }
  const discard = window.confirm(
    "Discard your unsaved changes and leave?\n\n" +
      "OK  - discard them and continue\n" +
      "Cancel - stay here and keep them"
  );
  if (discard) {
    caseGuard.discard();
    return true;
  }
  return false; // stay put, changes intact
}

// The browser-native guard for reload / close / back. Browsers require
// preventDefault plus returnValue and show their OWN wording; no custom
// message is possible, which is why this is not used for in-app links.
window.addEventListener("beforeunload", (e) => {
  if (!caseGuard.check()) return;
  e.preventDefault();
  e.returnValue = "";
});

// refreshLifecycleLocks re-reads the server's authoritative view of what
// this case still permits, and applies it to the controls.
//
// Called after a save, because saving may have just contained or closed
// the case. The server is asked rather than the rule re-derived here:
// there must be exactly one source of truth for the locks, and it is the
// server that enforces them.
async function refreshLifecycleLocks(caseId) {
  try {
    const data = await api(`/cases/${caseId}`);
    applyLifecycleLocks(data);
  } catch (e) {
    /* a failed refresh leaves the controls as they were; the server
       still refuses anything it should refuse */
  }
}

// applyLifecycleLocks disables the controls a locked case forbids.
//
// This is presentation only. Every one of these operations is re-checked
// server-side (internal/api/lifecycle.go), so a user who re-enables a
// control in devtools still gets a 409.
function applyLifecycleLocks(data) {
  if (!data || !data.case) return;
  lifecycleState.evidenceMutable = data.evidence_mutable !== false;
  lifecycleState.priorityEditable = data.priority_editable !== false;
  lifecycleState.caseStatus = data.case.case_status;

  const prioritySel = document.getElementById("case-priority-select");
  if (prioritySel) {
    prioritySel.disabled = !lifecycleState.priorityEditable;
    prioritySel.title = lifecycleState.priorityEditable
      ? ""
      : "This case is closed. Reopen it to change its priority.";
  }
  const banner = document.getElementById("case-lock-banner");
  if (banner) banner.innerHTML = renderLockBanner();

  // The lock UI is split across the case chrome (this function) and the
  // tab body (applyTabLifecycleLocks). Both must be refreshed whenever
  // the lifecycle changes, or they disagree.
  //
  // They did: saving a status change called only this function, so the
  // header updated while the Evidence Collections panel kept rendering
  // the OLD banner -- a case saved from Contained to Investigating
  // showed "Investigating" at the top and "This case is contained" below
  // it. Driving both from one entry point is what makes that state
  // unreachable, rather than relying on every future caller to remember
  // the second one.
  applyTabLifecycleLocks();
}

// lifecycleState mirrors the server's answer for the case on screen.
const lifecycleState = { evidenceMutable: true, priorityEditable: true, caseStatus: "open" };

// renderLockBanner states the lock in words wherever evidence would
// otherwise appear editable.
function renderLockBanner() {
  if (lifecycleState.evidenceMutable) return "";
  return `<div class="lock-banner" role="status">
    <strong>Evidence is locked</strong>
    <div class="small">This case is <strong>${esc(lifecycleState.caseStatus)}</strong>, so its evidence set cannot be added to, imported or deleted.
    Reading, analysis, export and integrity verification all remain available.
    Set the status back to Open or Investigating to make changes.</div>
  </div>`;
}

// ---------------- Case list ----------------

function integrationSettingsLink(className = "", label = "Settings") {
  if (authState.enabled && authState.role !== "admin") return "";
  return `<a class="${esc(className)}" href="#/settings/integrations">${esc(label)}</a>`;
}

function renderVTIntegrationForm(st) {
  const managed = st.source === "environment";
  return `<section class="panel integration-settings" aria-labelledby="vt-integration-title">
    <h2 id="vt-integration-title">VirusTotal</h2>
    <p id="vt-key-state" role="status"><strong>${st.configured ? "Configured" : "Not configured"}</strong> · ${managed ? "Managed by server environment" : st.configured ? "Saved on this server" : "No API key saved"}</p>
    <p class="small muted">Global server setting. Saving a key sends no provider request and does not change any case's data policy. Case lookups still require permission in Outside services.</p>
    ${managed ? `<p class="external-notice">The active key comes from <code>TRACEFALL_VT_API_KEY</code>. Change or remove that environment variable and restart the server to manage the key here.</p>` : ""}
    <form id="vt-key-form" autocomplete="off">
      <label for="vt-key-input">${st.configured ? "Replace API key" : "API key"}</label>
      <div class="row integration-key-row">
        <input type="password" id="vt-key-input" autocomplete="new-password" spellcheck="false" autocapitalize="off" maxlength="64" minlength="64" pattern="[a-fA-F0-9]{64}" placeholder="Paste your 64-character VirusTotal API key" required ${st.editable ? "" : "disabled"} aria-describedby="vt-key-storage" />
        <button class="btn-primary" id="vt-key-save" type="submit" ${st.editable ? "" : "disabled"}>Save key</button>
        <button class="danger" id="vt-key-remove" type="button" ${st.editable && st.configured ? "" : "disabled"}>Remove key</button>
      </div>
    </form>
    <p class="small muted" id="vt-key-storage">Saved keys are not returned to this page, stored in the case database, or included in reports. Storage is an owner-only server file (0600 in a 0700 directory), <strong>not encrypted</strong>: the server's OS account and administrators can read it. Protect server backups too. Remove does not erase backups or old filesystem snapshots.</p>
    ${!st.editable && !managed ? `<p class="field-error-box">Credential storage is unavailable. Check the server configuration.</p>` : ""}
    <hr>
    <h3>Test connection</h3>
    <p class="small">Uses the saved key, sends one fixed public EICAR test-file hash to VirusTotal and consumes one API request. It sends <strong>no case data</strong>, uploads no file, and shares the same rate and daily/monthly limits as case lookups. Free-tier keys are for non-commercial use under VirusTotal's terms.</p>
    <p class="small"><label><input id="vt-test-ack" type="checkbox" ${st.configured ? "" : "disabled"}> I authorize this external connection test and its quota usage.</label></p>
    <button id="vt-key-test" type="button" class="secondary" disabled>Test connection</button>
    <p id="vt-settings-msg" class="small" role="status" aria-live="polite"></p>
  </section>`;
}

async function renderChatGPTIntegration(root) {
  const content = root.querySelector("#chatgpt-settings-content");
  let st, busy = false, timer;
  const endpoint = "/admin/integrations/chatgpt";
  const pending = () => ["authorizing", "waiting"].includes(st?.state);
  const refresh = async (force = false) => {
    if (!root.isConnected) return;
    try {
      const next = await api(endpoint);
      if (!root.isConnected) return;
      const changed = JSON.stringify(next) !== JSON.stringify(st);
      st = next;
      if (force || changed) mount();
      if (pending()) timer = setTimeout(refresh, 1500);
    } catch (e) {
      if (root.isConnected) content.textContent = "Could not load ChatGPT settings: " + e.message;
    }
  };
  const act = async (method, suffix, body) => {
    if (busy) return;
    busy = true; clearTimeout(timer); sync();
    const msg = content.querySelector("#chatgpt-message");
    msg.textContent = suffix === "/verify" ? "Sending the fixed synthetic request… this may use account quota." : "Updating isolated server integration…";
    try {
      await api(endpoint + suffix, { method, ...(body ? { body: JSON.stringify(body) } : {}) });
      if (!root.isConnected) return;
      busy = false; await refresh(true);
    } catch (e) {
      if (!root.isConnected) return;
      busy = false;
      await refresh(true);
      const next = content.querySelector("#chatgpt-message");
      if (next) { next.textContent = e.message || "Operation failed."; next.className = "field-error-box"; }
    } finally { busy = false; if (root.isConnected) sync(); }
  };
  const sync = () => {
    if (!st || !content.querySelector("#chatgpt-authorize")) return;
    const blocked = busy || st.busy;
    content.querySelector("#chatgpt-authorize").disabled = blocked || !st.available;
    content.querySelector("#chatgpt-cancel").disabled = busy || !pending();
    content.querySelector("#chatgpt-disconnect").disabled = blocked || !st.available || st.state === "not_connected";
    content.querySelector("#chatgpt-provider").disabled = blocked || st.environment_managed;
    content.querySelector("#chatgpt-provider-save").disabled = blocked || st.environment_managed;
    const ack = content.querySelector("#chatgpt-verify-ack");
    ack.disabled = blocked || st.state !== "signed_in";
    content.querySelector("#chatgpt-verify").disabled = blocked || st.state !== "signed_in" || !ack.checked;
  };
  const mount = () => {
    const labels = {not_connected:"Not connected", authorizing:"Preparing official authorization…", waiting:"Waiting for authorization", signed_in:"Signed in", cancelled:"Authorization cancelled", failed:"Authorization/status failed", expired:"Authorization expired"};
    const code = st.state === "waiting" && st.authorization_url === "https://auth.openai.com/codex/device" && /^[A-Z0-9]{4}-[A-Z0-9]{4,6}$/.test(st.user_code || "");
    content.innerHTML = `<section class="panel integration-settings" aria-labelledby="chatgpt-title">
      <h2 id="chatgpt-title">ChatGPT / Codex</h2>
      <p id="chatgpt-state" role="status"><strong>${labels[st.state] || "Status unavailable"}</strong>${st.request_verified ? " · Request verified" : " · Request not verified"}</p>
      <p class="small">Uses the official Codex CLI device authorization. Sign in only on OpenAI's page. Tracefall has no password or token form. The server uses a dedicated Codex home; your personal Codex and Hermes sessions are not used or disconnected.</p>
      ${code ? `<div class="external-notice"><p><a id="chatgpt-official-link" href="https://auth.openai.com/codex/device" target="_blank" rel="noopener noreferrer">Open official OpenAI authorization page</a></p><p>Enter this one-time code: <strong id="chatgpt-user-code">${esc(st.user_code)}</strong></p><p class="small">Expires by ${esc(st.expires_at)}. Continue only if you started this authorization here. Cancel if someone else gave you the code.</p></div>` : ""}
      ${["failed", "expired", "cancelled"].includes(st.state) ? `<p class="field-error-box">${st.state === "expired" ? "The authorization deadline passed. Start again for a fresh code." : st.state === "cancelled" ? "The authorization process stopped. No code is retained." : "The CLI could not confirm authorization. Check the official CLI installation and network access, then retry. Raw CLI output is never shown."}</p>` : ""}
      <div class="row"><button id="chatgpt-authorize" type="button">${st.state === "signed_in" ? "Authorize again" : "Authorize ChatGPT"}</button><button id="chatgpt-cancel" class="secondary" type="button">Cancel authorization</button><button id="chatgpt-disconnect" class="danger" type="button">Disconnect</button></div>
      ${!st.available ? `<p class="field-error-box">Official Codex CLI or isolated integration storage is unavailable on this server. Ask the server administrator to install/configure it.</p>` : ""}
      <p class="small muted">Signed in means only that <code>codex login status</code> reports a ChatGPT session. It does not prove token freshness, plan/model access, or a successful request. Authorize never sends case data or a model request.</p>
      <h3>AI summary provider</h3>
      <p class="small">Active selection: <strong id="chatgpt-effective-provider">${esc(st.effective_provider)}</strong>. Authorization alone does not select Codex. Each case still requires its egress policy and a fresh per-request acknowledgement.</p>
      ${st.environment_managed ? `<p class="external-notice"><code>TRACEFALL_LLM_PROVIDER</code> overrides saved preferences. Change it in the server environment and restart to enable UI selection. Account authorization is separate from this override.</p>` : ""}
      <label for="chatgpt-provider">Use for AI summaries</label>
      <div class="row"><select id="chatgpt-provider">${[["none","Disabled"],["openai-compatible","API provider (server environment)"],["codex-cli","ChatGPT via Codex CLI"]].map(([v,label]) => `<option value="${v}" ${(st.preference || st.effective_provider) === v ? "selected" : ""}>${label}</option>`).join("")}</select><button id="chatgpt-provider-save" class="secondary" type="button">Save provider</button></div>
      <p class="small muted">API credentials and model remain configured on the server. Selection sends no request and grants no case egress permission.</p>
      <h3>Verify one synthetic request</h3>
      <p class="small">Sends one fixed synthetic prompt to OpenAI through this isolated Codex session. <strong>No case data</strong> is sent. May consume account quota and is subject to account limits. A successful response marks only this request as verified; it does not verify future summaries or privacy/data-control settings.</p>
      <p class="small"><label><input id="chatgpt-verify-ack" type="checkbox"> I authorize this external synthetic request and its quota usage.</label></p>
      <button id="chatgpt-verify" class="secondary" type="button" disabled>Verify request</button>
      <details><summary>Credential storage and provider privacy</summary><p class="small">The official CLI owns its credentials under the server data directory's <code>.integrations/codex</code>, outside cases, reports and database exports. Owner-only storage is <strong>not encryption</strong>. Administrators and server backups may retain credentials. Disconnect does not erase backups or snapshots. Verification is reset on authorization, disconnect, and server restart.</p><p class="small">${esc("This request goes to OpenAI through your ChatGPT account. This program cannot inspect your data-control settings. Check the provider's current terms and settings before authorizing case requests.")}</p></details>
      <p id="chatgpt-message" class="small" role="status" aria-live="polite"></p>
    </section>`;
    content.querySelector("#chatgpt-authorize").onclick = () => act("POST", "/authorize");
    content.querySelector("#chatgpt-cancel").onclick = () => act("POST", "/cancel");
    content.querySelector("#chatgpt-disconnect").onclick = () => {
      if (window.confirm("Disconnect the Tracefall ChatGPT session? This removes only its isolated CLI sign-in. Personal Codex/Hermes sessions and stored case drafts are unchanged. Backups are not erased.")) act("DELETE", "");
    };
    content.querySelector("#chatgpt-provider-save").onclick = () => act("PUT", "", {provider:content.querySelector("#chatgpt-provider").value});
    content.querySelector("#chatgpt-verify-ack").onchange = sync;
    content.querySelector("#chatgpt-verify").onclick = () => { if (content.querySelector("#chatgpt-verify-ack").checked) act("POST", "/verify", {acknowledge:true}); };
    sync();
  };
  await refresh();
}

async function renderIntegrationSettings() {
  const app = document.getElementById("app");
  app.innerHTML = `<div id="integration-settings-root"><p><a href="#/">All Cases</a> / Settings / Integrations</p><h1>Integrations</h1><div id="chatgpt-settings-content"></div><div id="vt-settings-content">Loading configuration…</div></div>`;
  const root = document.getElementById("integration-settings-root");
  const content = root.querySelector("#vt-settings-content");
  if (authState.enabled && authState.role !== "admin") {
    content.textContent = "Only an administrator can manage server integrations.";
    return;
  }
  try {
    renderChatGPTIntegration(root);
    let st = await api("/admin/integrations/virustotal");
    if (!root.isConnected) return;
    const mount = () => {
      content.innerHTML = renderVTIntegrationForm(st);
      const form = root.querySelector("#vt-key-form");
      const input = root.querySelector("#vt-key-input");
      const save = root.querySelector("#vt-key-save");
      const remove = root.querySelector("#vt-key-remove");
      const test = root.querySelector("#vt-key-test");
      const ack = root.querySelector("#vt-test-ack");
      const msg = root.querySelector("#vt-settings-msg");
      let busy = false;
      const sync = () => {
        input.disabled = busy || !st.editable;
        save.disabled = busy || !st.editable;
        remove.disabled = busy || !st.editable || !st.configured;
        ack.disabled = busy || !st.configured;
        test.disabled = busy || !st.configured || !ack.checked || input.value.length > 0;
      };
      ack.addEventListener("change", sync);
      input.addEventListener("input", sync);
      const act = async (method, suffix, body) => {
        if (busy) return;
        busy = true; sync();
        msg.textContent = suffix ? "Testing connection… rate limiting may delay this request." : "Updating server configuration…";
        msg.className = "small";
        try {
          const result = await api("/admin/integrations/virustotal" + suffix, { method, ...(body ? { body: JSON.stringify(body) } : {}) });
          const next = await api("/admin/integrations/virustotal");
          if (!root.isConnected) return;
          st = next;
          mount();
          root.querySelector("#vt-settings-msg").textContent = suffix ? result.message : method === "DELETE" ? "Key removed. Stored case results are unchanged." : "Key saved and active. No restart needed. No provider request was sent.";
        } catch (e) {
          if (!root.isConnected) return;
          msg.textContent = e.message || "The operation failed.";
          msg.className = "small field-error-box";
        } finally {
          busy = false;
          if (form.isConnected) sync();
        }
      };
      form.addEventListener("submit", (e) => {
        e.preventDefault();
        if (busy || !form.reportValidity()) return;
        const key = input.value.trim();
        input.value = "";
        act("PUT", "", { api_key: key });
      });
      remove.addEventListener("click", () => {
        if (!window.confirm("Remove the saved VirusTotal key? Future lookups will be disabled. Stored case results are kept.")) return;
        input.value = "";
        act("DELETE", "");
      });
      test.addEventListener("click", () => {
        if (!ack.checked || input.value || busy) return;
        act("POST", "/test", { acknowledge: true });
      });
      sync();
    };
    mount();
  } catch (e) {
    if (root.isConnected) content.textContent = "Could not load integration settings: " + (e.message || String(e));
  }
}

async function renderCaseList() {
  app.innerHTML = `
    <div class="panel new-case-panel">
      <h2>New case</h2>
      <div class="new-case-form">
        <div class="field">
          <label for="new-case-name">Name</label>
          <div class="input-wrap">
            <input id="new-case-name" placeholder="e.g. WKSTN-042 Phishing Triage" />
            <span id="new-case-name-icon" class="input-error-icon hidden">!</span>
          </div>
          <div id="new-case-error"></div>
        </div>
        <div class="field">
          <label for="new-case-desc">Description</label>
          <input id="new-case-desc" placeholder="optional" />
        </div>
      </div>
      <p class="field-info-note">Case names must be unique (case-insensitive, trimmed of leading/trailing spaces).</p>
      <div class="new-case-actions">
        <button id="create-case-btn">Create case</button>
      </div>
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
          <div class="case-card-info">
            <span class="case-card-name">${esc(c.name)}</span>
            ${c.description ? `<div class="muted small case-card-meta">${esc(c.description)}</div>` : ""}
            <div class="muted small mono case-card-meta">${esc(c.id)} &middot; created ${fmtTime(c.created_at)}</div>
          </div>
          <div class="case-card-col">${caseWorkflowBadge(c.case_status)}</div>
          <div class="case-card-col">${casePriorityBadge(c.priority)}</div>
          <div class="case-card-col">${analysisStateBadge(c)}</div>
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
    // Suppressed entirely for a non-admin: the bar's only action is a
    // delete, which the server would refuse.
    if (selected.length === 0 || !canDelete()) {
      bulkBar.innerHTML = "";
      return;
    }
    bulkBar.innerHTML = `
      <div class="bulk-action-bar">
        <span>${selected.length} case(s) selected</span>
        <button type="button" class="danger" id="case-delete-selected-btn">Delete Selected (${selected.length})</button>
      </div>`;
    document.getElementById("case-delete-selected-btn").addEventListener("click", (ev) =>
      confirmAndDeleteCases(selected, undefined, ev.currentTarget));
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

// ---------------- Case deletion progress ----------------
//
// Deletion is SYNCHRONOUS and, on this hardware, fast: the database work
// is one transaction (27 ms at 1,000 events, 2.4 s at 100,000) and the
// evidence directory removal is 127 ms for 8,000 files. A whole-case
// delete therefore takes roughly a tenth of a second to a few seconds.
//
// # Why there is no percentage, and no per-table stage
//
// Two separate reasons, and both are about honesty rather than effort:
//
//   * The server reports no position. It returns once, when everything
//     is gone. Any number rendered here would be invented, so the bar is
//     indeterminate -- it says "working", never "how far".
//
//   * The obvious stages cannot be claimed. "Removing events" and
//     "Removing findings" are separate DELETE statements, but they run
//     inside ONE transaction that can still roll back. Reporting
//     "events removed" before the commit would announce a completed
//     stage that may never have happened, which is exactly what must not
//     be done with a destructive operation.
//
// So what this panel shows is what is genuinely known: that deletion is
// running, what it is removing (from counts the case already loaded),
// and how long it has been going. Elapsed time is measured, not
// estimated, and is never presented as progress toward a total.

// DELETION_STAGE_LABELS mirrors DeletionStageLabels in
// internal/api/deleteprogress.go. The server sends its own label too;
// this is the fallback so a stage can never render as a raw identifier.
const DELETION_STAGE_LABELS = {
  preparing: "Preparing deletion",
  removing_records: "Removing case records",
  removing_evidence_files: "Removing evidence files",
  complete: "Complete",
  failed: "Failed",
};

// deletionCountsNote states what the committed transaction actually
// removed, from the row counts the database reported. Every number here
// is confirmed: it is read back after the commit, so nothing shown can
// still be rolled back.
function deletionCountsNote(c) {
  const parts = [];
  const add = (n, one, many) => {
    if (n > 0) parts.push(`${Number(n).toLocaleString()} ${n === 1 ? one : many}`);
  };
  add(c.collections, "collection", "collections");
  add(c.source_files, "evidence file", "evidence files");
  add(c.events, "event", "events");
  add(c.findings, "finding", "findings");
  add(c.correlations, "correlation", "correlations");
  if (parts.length === 0) return "no records to remove";
  return parts.join(" \u00b7 ");
}

const deletionProgress = {
  host: null,
  timer: null,
  pollTimer: null,
  startedAt: 0,

  // open mounts the modal panel. It is modal on purpose: it covers the
  // application, so a stray click cannot start another action or make
  // the case look navigable-away-from while its deletion is still
  // running (requirement 10). Nothing here closes on Escape or on a
  // backdrop click while the request is in flight.
  open(title, detail) {
    this.close();
    this.startedAt = Date.now();

    const host = document.createElement("div");
    host.className = "deletion-overlay";
    host.setAttribute("role", "alertdialog");
    host.setAttribute("aria-modal", "true");
    host.setAttribute("aria-labelledby", "deletion-title");
    host.setAttribute("aria-describedby", "deletion-detail");
    host.innerHTML = `
      <div class="deletion-panel" id="deletion-panel">
        <div class="deletion-head">
          <span class="deletion-spinner" aria-hidden="true"></span>
          <h2 id="deletion-title">${esc(title)}</h2>
        </div>
        <div class="deletion-activity" role="progressbar"
             aria-valuetext="in progress" aria-label="Deletion in progress"></div>
        <p class="deletion-lede">Deletion is in progress. Please keep this tab open until it finishes.</p>
        <ol class="deletion-stages" id="deletion-stages" aria-live="polite"></ol>
        <div class="deletion-summary" id="deletion-summary">${detail}</div>
        <p class="deletion-elapsed muted small" id="deletion-elapsed" aria-live="off"></p>
      </div>`;
    document.body.appendChild(host);
    document.body.classList.add("deletion-open");
    this.host = host;

    // Elapsed time is the one number here, and it is measured. It is
    // deliberately not styled as progress: a case with a large evidence
    // tree simply takes longer, and saying so beats a bar that stalls.
    const elapsed = host.querySelector("#deletion-elapsed");
    const tick = () => {
      const s = Math.floor((Date.now() - this.startedAt) / 1000);
      elapsed.textContent = s < 1 ? "" : `Elapsed ${s}s`;
    };
    tick();
    this.timer = window.setInterval(tick, 1000);

    // Focus moves into the dialog so a screen reader announces it and a
    // keyboard user is not left on a button that is now behind a modal.
    host.querySelector("#deletion-panel").setAttribute("tabindex", "-1");
    host.querySelector("#deletion-panel").focus({ preventScroll: true });
  },

  // track polls the server for the stages a deletion has actually
  // reached. Single-case deletion only: the bulk endpoint deletes cases
  // one at a time and publishes no combined progress, so claiming a
  // stage there would be inventing one.
  track(caseId) {
    if (!caseId) return;
    this.stopTracking();

    // Polling is deliberately frugal. Before the server has registered
    // the deletion the endpoint answers 404, and a 250ms poll through a
    // long deletion filled the console and the network log with a
    // hundred of them for no added information. So: a slow poll until
    // the first real answer, a fast one after it, and a full stop once
    // the server says the deletion is done -- there is nothing further
    // to learn after that.
    const fast = 250;
    const slow = 1000;
    let seen = false;
    let interval = slow;

    const schedule = (ms) => {
      window.clearInterval(this.pollTimer);
      interval = ms;
      this.pollTimer = window.setInterval(poll, ms);
    };

    const poll = async () => {
      try {
        const p = await api(`/cases/${caseId}/deletion-progress`);
        if (!seen) {
          seen = true;
          schedule(fast);
        }
        this.renderStages(p);
        if (p.done) {
          // The server has finished. The request's own resolution is
          // what closes the panel; nothing more can be learned here.
          this.stopTracking();
        }
      } catch {
        // 404 until the server registers the deletion, and again once
        // the record expires. Neither is an error worth showing: the
        // request itself is what reports success or failure.
        if (seen) this.stopTracking();
      }
    };

    poll();
    this.pollTimer = window.setInterval(poll, interval);
  },

  stopTracking() {
    if (this.pollTimer) {
      window.clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
  },

  // renderStages draws only what the backend has confirmed.
  //
  // A stage is ticked when the server says it is past it -- never when
  // the UI guesses it should be. Row counts appear against "Removing
  // case records" only once that transaction has COMMITTED, which is the
  // first moment any record can truthfully be called deleted.
  renderStages(p) {
    const host = this.host && this.host.querySelector("#deletion-stages");
    if (!host || !p) return;

    const order = ["preparing", "removing_records", "removing_evidence_files", "complete"];
    const current = order.indexOf(p.stage);
    const failedAt = p.stage === "failed";

    const rows = order.slice(0, 3).map((stage, i) => {
      let state = "pending";
      let note = "";
      if (failedAt) {
        // A failed deletion still shows what it had confirmed. Nothing
        // beyond that is marked either way.
        if (stage === "removing_records" && p.records_confirmed) state = "done";
        else if (stage === "preparing") state = "done";
      } else if (p.done) {
        state = "done";
      } else if (i < current) {
        state = "done";
      } else if (i === current) {
        state = "active";
      }

      if (stage === "removing_records" && p.records_confirmed && p.records_removed) {
        state = "done";
        note = deletionCountsNote(p.records_removed);
      }
      if (stage === "removing_evidence_files" && p.evidence_files_removed) state = "done";

      const mark = state === "done" ? "&#10003;" : state === "active" ? "&#8226;" : "";
      return `<li class="deletion-stage ${state}">
        <span class="deletion-stage-mark" aria-hidden="true">${mark}</span>
        <span class="deletion-stage-name">${esc(DELETION_STAGE_LABELS[stage] || stage)}</span>
        ${note ? `<span class="deletion-stage-note">${esc(note)}</span>` : ""}
      </li>`;
    });
    host.innerHTML = rows.join("");
  },

  // fail converts the panel in place into an error state. The running
  // state is stopped, and the word "Deleted" never appears: a failed
  // deletion has not deleted anything it is willing to claim.
  fail(message, onClose) {
    if (!this.host) return;
    this.stopTracking();
    window.clearInterval(this.timer);
    this.timer = null;

    const panel = this.host.querySelector(".deletion-panel");
    panel.classList.add("failed");
    panel.innerHTML = `
      <div class="deletion-head">
        <span class="deletion-fail-mark" aria-hidden="true">!</span>
        <h2 id="deletion-title">Deletion failed</h2>
      </div>
      <p class="deletion-detail" id="deletion-detail">${esc(message)}</p>
      <p class="deletion-note small">The case has not been reported as deleted. Some of its
      records or files may already have been removed &mdash; reopen the case to see its
      current state, or repeat the deletion to finish it.</p>
      <div class="deletion-actions">
        <button type="button" class="secondary small" id="deletion-dismiss">Close</button>
      </div>`;
    panel.querySelector("#deletion-dismiss").addEventListener("click", () => {
      this.close();
      if (onClose) onClose();
    });
    panel.querySelector("#deletion-dismiss").focus({ preventScroll: true });
  },

  close() {
    this.stopTracking();
    if (this.timer) {
      window.clearInterval(this.timer);
      this.timer = null;
    }
    if (this.host) {
      this.host.remove();
      this.host = null;
    }
    document.body.classList.remove("deletion-open");
  },
};

// deletionSummaryHTML lists what is about to be removed, as a table
// rather than a sentence.
//
// The prose version ("Removing 1 collection, 7,074 evidence files, 2,319
// events, 1,023 findings and 35 correlations...") put six numbers in one
// run-on line, which is the hardest possible shape to read at the moment
// an analyst most wants to check them.
//
// Every figure comes from the summary the case page has ALREADY loaded.
// Nothing is fetched or estimated for this panel, and a count that is
// not available is omitted rather than shown as zero-by-default.
function deletionSummaryHTML(ids, evidence) {
  if (ids.length !== 1) {
    return `<p class="deletion-summary-note">Removing ${fmtCount(ids.length)} cases and all of their
      evidence, events and analysis.</p>`;
  }

  const loaded =
    overviewData && overviewData.c && overviewData.c.id === ids[0] ? overviewData.summary : null;
  if (!loaded) {
    return `<p class="deletion-summary-note">Removing this case's evidence, events and analysis.</p>`;
  }

  // Order matches how the case itself is built up: evidence first, then
  // what was derived from it.
  const rows = [
    ["Collections", loaded.collections],
    ["Evidence files", loaded.source_files],
    ["Events", loaded.events],
    ["Findings", loaded.findings],
    ["Correlations", loaded.correlations],
    ["ATT&CK techniques", loaded.technique_count],
    ["Investigations", loaded.investigations],
  ].filter(([, n]) => Number(n) > 0);

  if (rows.length === 0) {
    return `<p class="deletion-summary-note">This case holds no evidence, events or analysis.</p>`;
  }

  const table = rows
    .map(
      ([label, n]) => `<div class="deletion-row">
        <span class="deletion-row-label">${esc(label)}</span>
        <span class="deletion-row-value">${esc(fmtCount(n))}</span>
      </div>`
    )
    .join("");

  // The on-disk figure, and only what is true of THIS case.
  //
  // A size is a size: nothing derives a position from it.
  //
  // Three distinct answers, because they are three different facts. A
  // measured zero is not "unknown" -- it means Tracefall stores none of
  // this case's evidence itself, which is exactly what a local-path
  // collection looks like: it points at the investigator's own folder,
  // and deletion never touches it. Saying "evidence files are also being
  // removed" there would claim a deletion that will not happen.
  let disk;
  if (evidence && evidence.measured && evidence.files > 0) {
    disk = `<p class="deletion-summary-note">
      Evidence on disk: ${esc(fmtCount(evidence.files))} files &middot; ${esc(fmtBytes(evidence.bytes))}
    </p>`;
  } else if (evidence && evidence.measured) {
    disk = `<p class="deletion-summary-note">
      No evidence files are stored by Tracefall for this case, so none are removed from disk.
      Evidence you ingested from a local folder is left where it is.
    </p>`;
  } else {
    disk = `<p class="deletion-summary-note">Evidence files stored by Tracefall are also being removed.</p>`;
  }

  return `<div class="deletion-table">${table}</div>${disk}`;
}

// deletionNavGuard warns before a reload or tab close while a deletion
// is running.
//
// It cannot stop the request -- that is on the server and will finish
// either way -- but leaving the page mid-deletion loses the only
// indication of whether it succeeded, and a browser warning is the one
// mechanism available for that. In-app navigation needs no handler: the
// panel is modal and covers the sidebar.
const deletionNavGuard = {
  handler: null,
  arm() {
    if (this.handler) return;
    this.handler = (e) => {
      e.preventDefault();
      // Browsers show their own wording; returnValue is what enables it.
      e.returnValue = "";
      return "";
    };
    window.addEventListener("beforeunload", this.handler);
  },
  disarm() {
    if (!this.handler) return;
    window.removeEventListener("beforeunload", this.handler);
    this.handler = null;
  },
};

// confirmAndDeleteCases requires explicit confirmation (never a silent
// destructive action -- see requirement 13) before permanently deleting
// one or more cases and everything associated with them. onSuccess
// defaults to reloading the current page (right for the case list, where
// "the current page" is still valid afterward); the case detail page
// passes its own onSuccess to navigate back to the list instead, since
// its own case no longer exists to reload.
// confirmAndDeleteCases warns, deletes, and does not pretend to be
// finished before the server says it is.
//
// Deletion is SYNCHRONOUS: the request returns only after every row and
// the case's evidence directory are gone. So the honest UI is an
// in-flight state held until the response arrives -- not an optimistic
// navigation, and not a progress percentage. The server does not report
// how far through a deletion it is, so any number shown here would be
// invented; an indeterminate "Deleting..." is the truthful shape.
//
// The button is disabled for the duration. Without that, a second click
// on a large case fires a second DELETE while the first is still
// running, and the second one fails with "not found" -- an error message
// about an operation that is in fact succeeding.
async function confirmAndDeleteCases(ids, onSuccess, trigger) {
  const title = ids.length === 1 ? "Delete Case?" : `Delete ${ids.length} Cases?`;
  // The warning states exactly what goes and exactly what stays. It is
  // checked against the implementation by a test -- a deletion warning
  // that overstates or understates what it destroys is worse than none.
  const what =
    ids.length === 1
      ? "This permanently deletes this case and everything belonging to it:"
      : `This permanently deletes the ${ids.length} selected cases and everything belonging to them:`;
  const detail =
    `${what}\n\n` +
    "  \u2022 every evidence collection, and its files on disk\n" +
    "  \u2022 the original uploaded archive or disk image\n" +
    "  \u2022 every discovered and imported source file record\n" +
    "  \u2022 every parsed event, observation and raw evidence record\n" +
    "  \u2022 every finding, correlation, investigation and ATT&CK mapping\n" +
    "  \u2022 notes, tags, analyst status, analysis runs and the case audit history\n\n" +
    "Evidence you ingested from a local folder is NOT deleted: Tracefall only " +
    "removes storage it owns. The system security log is also kept, so the record " +
    "that this case existed and was deleted survives.\n\n" +
    "This cannot be undone.";
  // Measured BEFORE the confirmation is shown, so the walk never runs
  // during the deletion itself and cannot race the removal it would be
  // measuring. A failure here is not worth surfacing: the summary simply
  // says that evidence files are being removed, without a size.
  let evidence = null;
  if (ids.length === 1) {
    try {
      evidence = await api(`/cases/${ids[0]}/evidence-size`);
    } catch {
      evidence = null;
    }
  }

  if (!window.confirm(`${title}\n\n${detail}`)) return;

  const restore = beginDeleting(trigger, ids.length);
  if (!restore.started) return; // a deletion is already running

  // The summary is built BEFORE the request, while the case's own counts
  // are still loaded and still true.
  deletionProgress.open(
    ids.length === 1 ? "Deleting case\u2026" : `Deleting ${ids.length} cases\u2026`,
    deletionSummaryHTML(ids, evidence)
  );
  // Real stages, polled from the server, for a single-case deletion. A
  // bulk delete removes cases one at a time and publishes no combined
  // progress, so it stays on the indeterminate state rather than being
  // given a stage list it cannot substantiate.
  if (ids.length === 1) deletionProgress.track(ids[0]);
  deletionNavGuard.arm();

  const stop = () => {
    deletionNavGuard.disarm();
    restore();
  };

  try {
    if (ids.length === 1) {
      await api(`/cases/${ids[0]}`, { method: "DELETE" });
    } else {
      // A bulk delete answers 200 even when some cases failed: the
      // result carries a Failed map (see Service.DeleteCases). Treating
      // the 200 alone as success reported "deleted" for cases that are
      // still there, which is the one thing a deletion UI must never do.
      const res = await api(`/cases`, {
        method: "DELETE",
        body: JSON.stringify({ case_ids: ids }),
      });
      const failed = (res && res.failed) || {};
      const failedIDs = Object.keys(failed);
      if (failedIDs.length > 0) {
        const deleted = (res && res.deleted_case_ids) || [];
        stop();
        deletionProgress.fail(
          `${deleted.length} of ${ids.length} cases were deleted. ` +
            `${failedIDs.length} could not be: ` +
            failedIDs.map((id) => `${id} (${failed[id]})`).join("; "),
          () => window.location.reload()
        );
        return;
      }
    }

    // Drop the cached case payload before navigating. It is overwritten
    // on the next case open and the deleted case can no longer be
    // fetched anyway, so nothing could actually resurrect it -- but a
    // deleted case's data sitting in a module variable is not a thing to
    // leave to that argument.
    overviewData = null;
    renderedCaseId = null;
    currentCollections = [];
    // Only now. The server has finished; nothing before this point
    // claims completion, and the panel is torn down as the view it was
    // covering is replaced.
    stop();
    deletionProgress.close();
    (onSuccess || (() => window.location.reload()))();
  } catch (e) {
    stop();
    deletionProgress.fail(e.message || String(e));
  }
}

// beginDeleting disables every delete control and blocks a second
// attempt. Returns the undo, for the failure path -- on success the view
// is replaced, so nothing is restored.
//
// It deliberately does NOT relabel or animate the button.
//
// It used to: the trigger became "Deleting case..." with a sweeping
// underline, which put a second live status indicator on screen
// underneath the modal that was already reporting the same thing. Two
// indicators for one operation is worse than one -- an analyst has to
// work out whether they are showing the same deletion, and a button
// that animates behind a backdrop reads as something still interactive.
// The modal is the single authoritative deletion status; the button
// behind it is simply disabled, keeping its own label.
function beginDeleting(trigger, count) {
  // The returned function carries `started`, so the caller can tell a
  // real start from a refused duplicate. Without it a second click
  // opened a second progress panel over the first and then tore both
  // down on one response.
  if (deleteInFlight) {
    const noop = () => {};
    noop.started = false;
    return noop;
  }
  deleteInFlight = true;

  // Every delete control is disabled, including the one that was
  // clicked, so the block cannot be walked around by clicking a
  // different button for the same case.
  const others = [
    ...document.querySelectorAll("#delete-case-btn, #case-delete-selected-btn, .delete-collection-btn"),
  ];
  const btn = trigger instanceof HTMLElement ? trigger : null;
  if (btn && !others.includes(btn)) others.push(btn);
  others.forEach((b) => (b.disabled = true));

  // Everything else on the case is inert too, so nothing underneath can
  // be operated while its case is being removed.
  document.querySelectorAll(".case-header-actions, .sidenav").forEach((el) => {
    el.classList.add("deletion-inert");
  });

  const restore = () => {
    deleteInFlight = false;
    others.forEach((b) => (b.disabled = false));
    document.querySelectorAll(".deletion-inert").forEach((el) => {
      el.classList.remove("deletion-inert");
    });
  };
  restore.started = true;
  return restore;
}

// deleteInFlight guards against a second delete being started while one
// is still running. Deletion is synchronous and can take seconds on a
// large case; a second request would fail with "not found" and report an
// error for an operation that was actually succeeding.
let deleteInFlight = false;

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
  // Invalidated analysis is not stale analysis: stale means results
  // still describe evidence the case holds, and after a deletion it
  // holds none of it. The backend decides -- see Summary.AnalysisInvalidated.
  const invalidated = !!summary.analysis_invalidated;
  const staleAnalysis =
    !invalidated && c.status !== "analyzed" && (summary.findings > 0 || summary.correlations > 0);

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
        ${renderCaseHeader(caseId, c, summary, staleAnalysis, invalidated)}
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
  // Apply the server's authoritative lock state to the controls as soon
  // as the case renders, not only after a save.
  applyLifecycleLocks(data);
  // Absent for a non-admin: the control is not rendered at all.
  document.getElementById("delete-case-btn")?.addEventListener("click", (ev) =>
    confirmAndDeleteCases(
      [caseId],
      () => {
        window.location.hash = "#/";
      },
      ev.currentTarget
    )
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
  // Phase 21. Placed after the analysis views and before the audit
  // trail: it is a way of LOOKING at evidence, like the Timeline, not a
  // record of what was done to the case.
  { key: "geomap", label: "Photo Map" },
  // Outside services sits before the audit trail: what it does is recorded there.
  { key: "external", label: "Outside services" },
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
          ${integrationSettingsLink("sidenav-item")}
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

// renderCaseStateBadges is the case's state, at a glance, in the header.
//
// Three questions an analyst asks before anything else -- where is this
// case in the workflow, how urgent is it, and can I trust what is on
// screen -- previously required reading three separate places: a badge
// for the engine status, and two dropdowns further down for workflow
// status and priority. Answering them now takes one look.
//
// These badges are DISPLAY ONLY. Editing still happens through the
// selects below, which remain the single place state is changed, so
// there is exactly one control per piece of state and no ambiguity
// about which one is authoritative.
function renderCaseStateBadges(c, staleAnalysis, invalidated) {
  return `
    <div class="case-state-badges" role="group" aria-label="Case state">
      ${caseWorkflowBadge(c.case_status)}
      ${casePriorityBadge(c.priority)}
      ${analysisStateBadge(c, staleAnalysis, invalidated)}
    </div>`;
}

// caseWorkflowBadge shows the ANALYST workflow state (open /
// investigating / contained / closed). Deliberately not the engine
// status: the two are different axes and conflating them has been a
// standing bug risk in this codebase -- see statusBadge's own note.
function caseWorkflowBadge(caseStatus) {
  const st = caseStatus || "open";
  const locked = st === "contained" || st === "closed";
  const title = locked
    ? `Case is ${st}: its evidence set is locked and cannot be added to, imported or deleted.`
    : `Case is ${st}: evidence can still be added, imported and deleted.`;
  return `<span class="badge case-state case-state-${esc(st)}" title="${esc(title)}">${esc(st.toUpperCase())}</span>`;
}

// casePriorityBadge shows triage priority, styled with the SAME
// vocabulary as artifact priority elsewhere and deliberately apart from
// finding severity -- an analyst's urgency judgement is not a detection
// verdict.
function casePriorityBadge(priority) {
  const p = priority || "medium";
  return `<span class="badge prio prio-${esc(p)}" title="Analyst triage priority: ${esc(p)}">${esc(p.toUpperCase())}</span>`;
}

// analysisStateBadge answers "can I trust what is on screen?".
//
// Three distinct states, never collapsed: analysis has never been run,
// analysis is current, or analysis exists but the evidence has changed
// underneath it. The third is the dangerous one -- results that look
// authoritative but describe evidence that is no longer what the case
// holds -- so it is the one that gets the warning styling.
// The case LIST has no summary to compute staleAnalysis from -- /api/cases
// returns bare cases -- so when the flag is not supplied it is derived
// from fields the case itself carries: an analysis timestamp plus an
// engine status that has since moved off "analyzed" means evidence
// changed after the last run. That is the same fact the detail page's
// flag encodes, read from data the list already has, so the two views
// agree without widening the API.
function analysisStateBadge(c, staleAnalysis, invalidated) {
  const stale = staleAnalysis === undefined ? !!c.analyzed_at && c.status !== "analyzed" : staleAnalysis;
  // Invalidated outranks everything. A case whose evidence was deleted
  // has no valid analysis at all, so it is neither stale (which means
  // results still describe evidence that EXISTS) nor never-analyzed
  // (which would deny that analysis ever ran).
  if (invalidated) {
    return `<span class="badge analysis-state analysis-never"
                  title="The evidence this case's analysis was derived from has been deleted, so there is no valid analysis for the evidence the case now holds. The previous run is retained in the case history, marked invalidated.">NOT ANALYZED</span>`;
  }
  if (stale) {
    return `<span class="badge analysis-state analysis-stale"
                  title="Findings, correlations, investigations and ATT&amp;CK results were produced before the evidence last changed. Re-run analysis before treating them as current.">ANALYSIS STALE</span>`;
  }
  if (c.status === "analyzed") {
    return `<span class="badge analysis-state analysis-current"
                  title="Analysis is current for the evidence this case holds${c.analyzed_at ? ", last run " + esc(fmtTime(c.analyzed_at)) : ""}.">ANALYZED</span>`;
  }
  return `<span class="badge analysis-state analysis-never"
                title="Analysis has never been run for this case.">NEVER ANALYZED</span>`;
}

// renderCaseHeader is the always-visible case identity band.
//
// Two rows by design (section 15): identity and actions on top,
// metadata below. Both wrap rather than overflow, so a narrow viewport
// stacks them instead of introducing a horizontal scrollbar -- and
// nothing is hidden to achieve that, because case status and priority
// are forensic context, not decoration.
function renderCaseHeader(caseId, c, summary, staleAnalysis, invalidated) {
  return `
    <header class="case-header">
      <div class="case-header-top">
        <div class="case-identity">
          <h1>${esc(c.name)}</h1>
          ${c.description ? `<div class="muted small">${esc(c.description)}</div>` : ""}
          <div class="muted small mono case-id">${esc(c.id)}</div>
        </div>
        <div class="case-header-actions">
          ${renderCaseStateBadges(c, staleAnalysis, invalidated)}
          <div class="dropdown">
            <button type="button" class="secondary small" id="export-case-btn"
                    aria-haspopup="true" aria-expanded="false" aria-controls="export-menu">Export &#9662;</button>
            <div id="export-menu" class="dropdown-menu hidden" role="menu" aria-labelledby="export-case-btn">
              <a role="menuitem" href="/api/cases/${caseId}/export" target="_blank" rel="noopener">Case JSON</a>
              <a role="menuitem" href="/api/cases/${caseId}/export/timeline.csv" target="_blank" rel="noopener">Timeline CSV</a>
              <a role="menuitem" href="/api/cases/${caseId}/export/findings.csv" target="_blank" rel="noopener">Findings CSV</a>
              <a role="menuitem" href="/api/cases/${caseId}/report.html" target="_blank" rel="noopener">Forensic report (HTML)</a>
              <a role="menuitem" href="/api/cases/${caseId}/report.pdf" target="_blank" rel="noopener">Forensic report (PDF)</a>
              <a role="menuitem" href="/api/cases/${caseId}/report.zip">Report bundle (ZIP + hash manifest)</a>
            </div>
          </div>
          ${canDelete() ? `<button type="button" class="danger small" id="delete-case-btn">Delete Case</button>` : ""}
        </div>
      </div>

      <div class="case-meta">
        <div class="case-meta-edit-label muted small">Edit case state</div>
        <div class="case-meta-edit">
          <div class="case-meta-fields">
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
          </div>
        </div>
        <dl class="case-meta-facts">
          <div class="case-fact">
            <dt class="muted small">Created</dt>
            <dd class="small">${esc(fmtTime(c.created_at))}</dd>
          </div>
          <div class="case-fact">
            <dt class="muted small">Last analyzed</dt>
            <dd class="small">${c.analyzed_at ? esc(fmtTime(c.analyzed_at)) : "Never analyzed"}</dd>
          </div>
        </dl>
      </div>
      <div id="case-save-bar" hidden></div>
      <div id="case-metadata-error"></div>
      <div id="case-lock-banner"></div>
      ${
        invalidated
          ? `<div class="stale-banner">
        <strong>Analysis invalidated: its evidence was deleted</strong>
        <div>The evidence this case's findings, correlations, investigations and ATT&amp;CK results were derived from has been deleted, so none of them is current and none is shown. The previous run is retained in this case's history, marked invalidated, and can still be inspected there. Re-run analysis to produce results for the evidence the case holds now.</div>
      </div>`
          : staleAnalysis
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
      <div id="tab-lock-banner"></div>
      <div id="add-evidence-form" class="add-evidence-form hidden">
        <h3>Upload evidence</h3>
        <p class="muted small">Upload a disk image (raw/DD, E01, VHD, VHDX or VMDK), an AD1 logical image, a ZIP of a KAPE collection, or a memory image for Volatility analysis. Disk readers support NTFS, FAT/exFAT and ext2/3/4. Formats are checked from their contents, not just their extension. By default, supported artifacts are imported and analysed automatically. Unsupported files, missing dependencies and parse failures are reported; a successful upload does not mean every artifact was analysed.</p>
        <div class="row">
          <input type="file" id="upload-file" accept=".zip,.ad1,.e01,.dd,.raw,.img,.001,.vhd,.vhdx,.vmdk,.vmem,.mem,.dmp,.dump,.lime,application/zip" />
          <button id="upload-btn">Upload Evidence</button>
        </div>
        <label class="small" for="upload-auto-analyze"><input type="checkbox" id="upload-auto-analyze" checked /> Automatically import all supported files and run analysis after upload</label>
        <div id="upload-error"></div>
        <div id="upload-progress"></div>

        <details style="margin-top:16px">
          <summary class="muted small" style="cursor:pointer">Advanced: ingest from a local path instead</summary>
          <p class="muted small">For evidence already on the Tracefall server, enter an allowed directory or image path. VHD/VHDX and VMDK images with companion files should be imported from a directory containing all required files. The server must allow access to that location.</p>
          <div class="row">
            <div style="flex:1"><input id="ingest-path" placeholder="/path/to/evidence or /path/to/image.vhdx" /></div>
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
      case "geomap":
        await renderGeoMapTab(content, caseId);
        break;
      case "external":
        await renderExternalTab(content, caseId);
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
  // Controls that live INSIDE the tab body -- "+ Add Evidence" is the
  // one that matters -- are created after the case chrome, so the lock
  // has to be re-applied once the body exists. Without this the button
  // is offered on a locked case and can only fail with a 409.
  applyTabLifecycleLocks();
}

// applyTabLifecycleLocks hides evidence-mutating controls inside the
// current tab body. Presentation only: the server refuses these
// operations regardless (internal/api/lifecycle.go).
function applyTabLifecycleLocks() {
  const locked = !lifecycleState.evidenceMutable;

  const addBtn = document.getElementById("add-evidence-btn");
  if (addBtn) addBtn.hidden = locked;

  // Every branch below is SYMMETRIC -- it restores the control when the
  // case is mutable, not only hides it when locked. The hiding used to
  // be one-way, which was invisible while this only ever ran on a
  // freshly rendered tab (whose controls start visible) but leaves a
  // reopened case permanently stripped now that it also runs against an
  // already-rendered one.
  const form = document.getElementById("add-evidence-form");
  if (form && locked) form.classList.add("hidden");

  document.querySelectorAll(".evidence-file-delete-btn").forEach((b) => (b.hidden = locked));

  const host = document.getElementById("tab-lock-banner");
  if (host) host.innerHTML = renderLockBanner();
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
  // The "already wired" marker is keyed by a SANITIZED prefix.
  //
  // dataset property names become data-* attributes, and a name
  // containing "-" followed by a lowercase letter is rejected with a
  // SyntaxError. A prefix carrying a collection UUID therefore threw for
  // some UUIDs and not others, depending purely on whether a hyphen in
  // the id happened to be followed by a letter -- which made the failure
  // look intermittent. Stripping non-alphanumerics removes the class of
  // bug rather than the one id that exposed it.
  const key = `pagerWired${String(prefix).replace(/[^A-Za-z0-9]/g, "")}`;
  if (!container || container.dataset[key]) return;
  container.dataset[key] = "1";

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
    card.addEventListener("click", async (event) => {
      // The whole card is the expand/collapse target, so any control
      // INSIDE it -- pager buttons, the page-size and status selects, the
      // integrity copy/expand controls -- would otherwise bubble up and
      // collapse the panel the analyst is working in. Paging the file
      // list closed the collection on every click.
      //
      // Ignoring clicks that originate from an interactive element covers
      // the controls added since as well as those present today, rather
      // than each new control having to remember to stop propagation.
      if (event.target.closest("button, select, input, textarea, a, label, .pager")) return;

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
            <div><span class="muted small">Evidence integrity (SHA-512)</span>${integrityHashCell(cd.integrity_sha512)}</div>
            <div><span class="muted small">Hosts observed</span><div class="small">${cd.hosts_observed && cd.hosts_observed.length ? esc(cd.hosts_observed.join(", ")) : "Unknown"}</div></div>
            <div><span class="muted small">Event time range</span><div class="small">${cd.earliest_event ? esc(fmtTime(cd.earliest_event)) + " &rarr; " + esc(fmtTime(cd.latest_event)) : "Unknown"}${cd.undated_events ? `<div class="muted small" title="These events are real observations, but their artifact records no time, so they fall outside the range above rather than being placed on it.">+ ${cd.undated_events} event(s) with no timestamp</div>` : ""}</div></div>
          </div>
          ${renderIntegrityVerifyPanel(caseId, cd)}
          ${renderDeleteCollectionControl(cd)}
          <div class="muted small" style="margin-top:8px">Parser coverage</div>
          ${
            cd.parser_coverage && cd.parser_coverage.length
              ? `<div class="table-wrap"><table><thead><tr><th>Parser</th><th>Artifact type</th><th>Files</th><th>Events</th></tr></thead><tbody>
                  ${cd.parser_coverage.map((p) => `<tr><td class="mono small">${esc(p.parser)}</td><td class="small">${esc(artifactLabel(p.artifact_type))}</td><td class="small">${p.file_count}</td><td class="small">${p.event_count}</td></tr>`).join("")}
                 </tbody></table></div>`
              : `<p class="empty">Unknown -- no files imported from this collection yet.</p>`
          }
          <div class="muted small" style="margin-top:8px">Per-file integrity</div>
          <div id="${integrityTablePagerHost(cd.collection_id)}">${
            cd.file_count > 0
              ? ""
              : `<p class="empty">No files recorded in this collection.${
                  cd.ingestion_status === "failed"
                    ? " This collection was left behind by a discovery that failed before it finished cataloging (an older Tracefall version); it holds no evidence and cannot be imported."
                    : ""
                }</p>`
          }</div>
        `;
        detail.dataset.loaded = "1";
        wireIntegrityHash(detail);
        mountIntegrityTable(detail, caseId, cd.collection_id, cd.file_count);
        wireIntegrityVerify(caseId, card.dataset.collection, detail);
        wireDeleteCollection(caseId, cd, detail);
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
  const saveBar = document.getElementById("case-save-bar");

  // Phase 13: changing a dropdown no longer saves.
  //
  // Previously each 'change' fired a PATCH immediately, so a mis-click
  // closed a case -- and closing a case now freezes its evidence, which
  // makes an accidental save a real problem rather than a cosmetic one.
  // Changes accumulate as PENDING state until the analyst saves them.
  const baseline = { case_status: statusSel.value, priority: prioritySel.value };

  const pending = () => {
    const p = {};
    if (statusSel.value !== baseline.case_status) p.case_status = statusSel.value;
    if (prioritySel.value !== baseline.priority) p.priority = prioritySel.value;
    return p;
  };
  const hasPending = () => Object.keys(pending()).length > 0;

  // Registered so the router and the browser can both ask whether it is
  // safe to leave -- see caseGuard.
  caseGuard.check = hasPending;
  caseGuard.save = () => saveNow();
  caseGuard.discard = () => {
    statusSel.value = baseline.case_status;
    prioritySel.value = baseline.priority;
    render();
  };

  function render() {
    const p = pending();
    const dirty = Object.keys(p).length > 0;
    saveBar.hidden = !dirty;
    if (!dirty) {
      saveBar.innerHTML = "";
      return;
    }
    const parts = [];
    if (p.case_status) parts.push(`status \u2192 <strong>${esc(p.case_status)}</strong>`);
    if (p.priority) parts.push(`priority \u2192 <strong>${esc(p.priority)}</strong>`);
    saveBar.innerHTML = `
      <div class="save-bar" role="status">
        <span class="small">Unsaved changes: ${parts.join(" &middot; ")}</span>
        <span class="save-bar-actions">
          <button type="button" class="secondary small" id="case-discard-btn">Discard</button>
          <button type="button" class="small" id="case-save-btn">Save changes</button>
        </span>
      </div>`;
    document.getElementById("case-save-btn").addEventListener("click", () => saveNow());
    document.getElementById("case-discard-btn").addEventListener("click", () => caseGuard.discard());
  }

  // saveNow persists the whole pending update in ONE request, so status
  // and priority land together or not at all. Returns true on success so
  // the navigation guard can decide whether to proceed.
  async function saveNow() {
    const patch = pending();
    if (Object.keys(patch).length === 0) return true;
    errBox.innerHTML = "";
    const btn = document.getElementById("case-save-btn");
    if (btn) {
      btn.disabled = true;
      btn.textContent = "Saving...";
    }
    try {
      await api(`/cases/${caseId}`, { method: "PATCH", body: JSON.stringify(patch) });
      // The saved values become the new baseline only on success.
      baseline.case_status = statusSel.value;
      baseline.priority = prioritySel.value;
      render();
      // The lifecycle locks may have just changed, so re-read the
      // server's authoritative view rather than inferring it here.
      await refreshLifecycleLocks(caseId);
      return true;
    } catch (e) {
      // On failure the pending values are KEPT: the analyst's unsaved
      // work is not discarded because the server said no.
      errBox.innerHTML = errorBox(e);
      if (btn) {
        btn.disabled = false;
        btn.textContent = "Save changes";
      }
      return false;
    }
  }

  statusSel.addEventListener("change", render);
  prioritySel.addEventListener("change", render);
  render();

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
      await api(`/cases/${caseId}/notes/${btn.dataset.id}`, { method: "DELETE" });
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

// ---------------------------------------------------------------------
// Outside services: how much of the case may leave the server, and the
// VirusTotal hash lookups that level allows.
//
// Nothing here is needed for analysis. The level starts at "none". The page
// sends nothing by itself: a lookup starts only from the button, and the
// server refuses it unless the case's level allows file hashes out.
// ---------------------------------------------------------------------
// The summary section of the Outside services tab. Plain strings in, HTML out;
// every value that came from the server or from a model is escaped.
function externalCitation(kind, id, context = {}) {
  if (kind === "enrichment") {
    if (!id || (!!context.reviewID === !!context.runID)) return `<span class="small">Stored VirusTotal source unavailable: frozen snapshot context not recorded.</span>`;
    const binding = context.reviewID ? `data-review-id="${esc(context.reviewID)}"` : `data-run-id="${esc(context.runID)}"`;
    return `<button type="button" class="source-link" data-source-kind="enrichment" data-source-id="${esc(id)}" ${binding} title="Open stored VirusTotal source: ${esc(id)}">stored VT ${esc(String(id).slice(0,12))}</button>`;
  }
  if (!["finding", "event", "correlation", "coverage"].includes(kind)) return `<span class="small">Unsupported source reference: ${esc(kind)} ${esc(id)}</span>`;
  return `<button type="button" class="source-link" data-source-kind="${kind}" data-source-id="${esc(id)}" title="Open ${kind}: ${esc(id)}">${kind} ${esc(String(id).slice(0, 12))}</button>`;
}

// Stored VT is secondary context, never primary event/success coverage.
function renderStoredVTCoverage(c) {
  const n = key => c?.vt_recorded === true && Number.isSafeInteger(c?.[key]) && c[key] >= 0 ? String(c[key]) : "not recorded";
  return `<p class="small stored-vt-coverage"><strong>Stored VirusTotal context:</strong> total ${n("vt_total")} · included ${n("vt_included")} · omitted ${n("vt_omitted")} · invalid ${n("vt_invalid")} · unlinked ${n("vt_unlinked")}. Packet context is separate from primary event coverage; do not sum repeated VT rows across packets. Older results without metadata are not recorded, not zero.</p>`;
}

function renderStoredVTSource(data) {
  const d = data && typeof data === "object" ? data : {};
  const n = key => Number.isSafeInteger(d[key]) && d[key] >= 0 ? String(d[key]) : "not recorded";
  const statuses = {found:"Found at lookup time",not_found:"Not known to VirusTotal at lookup time",error:"Stored lookup error; no usable opinion",unusable:"Stored result unusable; no usable opinion"};
  // Fixed labels only: no provider errors, JSON, names or free-text labels.
  const counts = ["malicious","suspicious","harmless","undetected","timeout","failure","type_unsupported","engines"];
  const events = Array.isArray(d.source_event_ids) ? d.source_event_ids.filter(id => typeof id === "string" && id) : [];
  return `<div class="stored-vt-source"><p><strong>Outside opinion at lookup time — not primary evidence.</strong> Stored results only; no VirusTotal call and no VT key required to inspect. Zero detections and not_found are not proof of safety.</p>
    <p>${Object.hasOwn(statuses,d.status) ? statuses[d.status] : "Status not recorded; no usable opinion"}. Recorded time: ${esc(typeof d.fetched_at === "string" && d.fetched_at.trim() ? d.fetched_at : "time not recorded")}.</p>
    <p>Frozen review/run snapshot. This is not the current live VT tab; later lookups never replace this citation.</p>
    <p>Local hash (${esc(d.indicator_type || "not recorded")}): <span class="mono">${esc(d.indicator || "not recorded")}</span></p>
    ${d.verdicts_recorded === true && d.status === "found" ? `<p>Recorded verdict counts: ${counts.map(key=>`${key}: ${n(key)}`).join(" · ")}</p>` : "<p>Verdicts not recorded; no counts inferred.</p>"}
    <h3>Verified same-snapshot source events</h3><div class="source-links">${events.map(id=>externalCitation("event",id)).join(" ") || "No verified source event references recorded."}</div>
    <p class="small">Lookup age and case-source freshness are different: a source change can stale a review even when a VT lookup is recent; an older lookup is still only the opinion recorded at that time. No age threshold or safety conclusion is inferred.</p></div>`;
}

// The dialog lives outside the refreshed status cards. Reading a source must
// not be interrupted by a background lookup finishing.
function wireExternalCitations(root, caseId) {
  root.querySelectorAll(".source-link").forEach((button) => {
    button.addEventListener("click", async () => {
      const kind = button.dataset.sourceKind;
      const id = button.dataset.sourceId;
      const dialog = document.createElement("dialog");
      dialog.className = "external-source-dialog";
      dialog.setAttribute("aria-label", `${kind} source`);
      dialog.innerHTML = `<div class="row between"><h2>${esc(kind)} source</h2><button type="button" class="btn-secondary" autofocus>Close</button></div>
        <p class="mono small source-id">${esc(id)}</p><div class="external-source-body" role="status">Loading source…</div>`;
      document.body.appendChild(dialog);
      dialog.querySelector("button").addEventListener("click", () => dialog.close());
      dialog.addEventListener("close", () => {
        dialog.remove();
        // A status refresh may have replaced the original citation button.
        const target = button.isConnected ? button : Array.from(document.querySelectorAll("#ext-root .source-link")).find((el) => el.dataset.sourceKind === kind && el.dataset.sourceId === id && el.dataset.reviewId === button.dataset.reviewId && el.dataset.runId === button.dataset.runId);
        if (target) target.focus({ preventScroll: true });
      }, { once: true });
      dialog.showModal();
      const body = dialog.querySelector(".external-source-body");
      if (kind === "enrichment") {
        // Resolve only the frozen snapshot named by the rendered citation.
        const reviewID = button.dataset.reviewId, runID = button.dataset.runId;
        if (!id || (!!reviewID === !!runID)) {
          body.textContent = "Frozen stored VirusTotal source unavailable: snapshot context not recorded.";
          return;
        }
        try {
          const snapshot = runID ? `batches/${encodeURIComponent(runID)}` : encodeURIComponent(reviewID);
          const data = await api(`/cases/${encodeURIComponent(caseId)}/enrich/case-review/${snapshot}/virustotal/${encodeURIComponent(id)}`);
          if (!dialog.isConnected) return;
          body.innerHTML = `<p class="small source-id">Case ${esc(caseId)} · frozen ${runID ? "batch run" : "single review"} ${esc(runID || reviewID)}</p>` + renderStoredVTSource(data);
          wireExternalCitations(body, caseId);
        } catch (_) {
          if (dialog.isConnected) body.textContent = "Frozen stored VirusTotal source unavailable. It may be missing from this snapshot or unusable. No current lookup was substituted; inspection makes no provider request.";
        }
      } else if (kind === "event") {
        await loadProvenanceInto(caseId, id, body);
      } else if (kind === "correlation" || kind === "coverage") {
        try {
          if (kind === "correlation") {
            const correlations = await api(`/cases/${caseId}/correlations`);
            if (!dialog.isConnected) return;
            const c = correlations.find(x => x.correlation_id === id);
            if (!c) throw Error("Correlation is missing from the current case results.");
            body.innerHTML = `<h3>${esc(c.title)}</h3><p>${esc(c.description || "")}</p><p class="small muted">Current deterministic correlation, not AI evidence. Citation order alone is not temporal order.</p><div class="source-links">${(c.event_ids || []).map(eid => externalCitation("event",eid)).join(" ") || "No supporting references recorded."}</div>`;
            wireExternalCitations(body,caseId);
          } else {
            const data = id === "selection" ? (await api(`/cases/${caseId}/enrich/case-review`)).latest?.coverage : await api(`/cases/${caseId}/sources/${encodeURIComponent(id)}/provenance`);
            if (!dialog.isConnected) return;
            if (!data) throw Error("Coverage record is unavailable.");
            body.innerHTML = `<p class="small">${id === "selection" ? "Recorded selection coverage for the latest bounded request." : "Current source provenance and parse coverage; it may have changed since the review."} Not raw-image coverage. Not recorded is not complete.</p><pre class="small" style="white-space:pre-wrap;overflow-wrap:anywhere"></pre>`;
            body.querySelector("pre").textContent=JSON.stringify(data,null,2);
          }
        } catch(e) { body.textContent="Source unavailable: "+(e.message || String(e)); }
      } else {
        try {
          const finding = await api(`/cases/${caseId}/findings/${encodeURIComponent(id)}`);
          if (!dialog.isConnected) return;
          body.innerHTML = `<h3>${esc(finding.title)}</h3><p>${esc(finding.description || "")}</p>
            ${renderSeverityExplanation(finding.severity_explanation)}
            <h3>Supporting events</h3><div class="source-links">${(finding.supporting_event_ids || []).map((eid) => externalCitation("event", eid)).join(" ") || "No supporting event references recorded."}</div>`;
          wireExternalCitations(body, caseId);
          mountFindingProvenance(body, caseId, id);
        } catch (e) {
          body.textContent = "Source unavailable: " + (e.message || String(e));
        }
      }
    });
  });
}

// Parsed-case batches keep their own DOM and selected identity. Poll only that
// frozen run and one small metadata page, never reconstruct the whole case.
function mountBatchReview(card, caseId, provider) {
  const root = document.createElement("details");
  root.id = "batch-review";
  root.dataset.caseId = caseId;
  root.className = "external-details batch-review";
  const ranges = {requests:[8,1,8],input_bytes:[1280000,4096,1280000],output_bytes:[131072,1024,131072],per_request_seconds:[120,1,120],overall_seconds:[900,1,900],concurrency:[1,1,1],retries:[0,0,0]};
  root.innerHTML = `<summary>Parsed-case batch review · optional bounded snapshot</summary>
    <p>Build a local plan, inspect its packets, then deliberately start. No navigation, planning, inspection or polling calls a model. Provider login and privacy receipts are not case egress permission or run consent.</p>
    <p class="small">Stored VirusTotal results may be included as secondary context in packets and synthesis. Stored results only: opening, planning and review never call VirusTotal; no VT key required. Hash-only permission for VT does not authorize LLM transmission. Current model egress permission and per-run approval still apply. VT is an outside opinion at lookup time, not primary evidence; zero detections and not_found are not proof of safety. Plans are frozen; later lookups do not replace old citations.</p>
    <p class="small">Frozen parsed snapshot, not raw-image completeness or forensic correctness. Successful means structurally validated commentary, not that every included event was semantically examined. Repeated context is not extra coverage. GET does not certify freshness; Start rechecks source, provider and policy. No automatic retry or resume after restart.</p>
    <form id="br-budget"><fieldset><legend>Hard-bounded run budget</legend><div class="batch-budget">${Object.entries(ranges).map(([key,[value,min,max]])=>`<label>${key.replaceAll("_"," ")} (${min}–${max}) <input id="br-${key}" name="${key}" type="number" min="${min}" max="${max}" step="1" value="${value}" required ${min===max ? "readonly" : ""}></label>`).join("")}</div>
    <label><input type="checkbox" name="synthesis" id="br-synthesis" checked> Request separate synthesis (reserves one request and 160000 input bytes)</label></fieldset>
    <p class="small">Sequential concurrency 1; retries 0. Budgets limit local admission, retained output and deadlines, not provider billing or computation. Output can be truncated or withheld without successful coverage. No dollar/token estimate. Each local plan retains sensitive frozen records and consumes disk; backups are not securely erased.</p>
    <button id="br-build" class="secondary" type="submit">Build batch plan</button></form>
    <p id="br-message" role="status" class="small"></p>
    <details id="br-history"><summary>Prior-run history (10 per page)</summary><div id="br-history-list"></div><button id="br-history-prev" class="secondary" type="button">Previous runs</button> <button id="br-history-next" class="secondary" type="button">Next runs</button></details>
    <div id="br-plan"></div>`;
  card.appendChild(root);
  const base = `/cases/${caseId}/enrich/case-review/batches`;
  let plan = null, context = structuredClone(provider), busy = false, loaded = false, generation = 0, timer, after = -1, historyOffset = 0;
  const q = s => root.querySelector(s);
  const live = () => root.isConnected;
  const message = (text, bad=false) => { if(live()){q("#br-message").textContent=text; q("#br-message").classList.toggle("field-error-box",bad);} };
  const binding = p => JSON.stringify([p?.id,p?.plan_key,p?.provider_binding,p?.privacy_contract,p?.egress_level,p?.destination,p?.model,p?.local]);
  const allowed = () => plan && context.configured && (plan.local || (context.allowed && context.egress_level === "pseudonymized")) && context.destination === plan.destination && context.model === plan.model && context.local === plan.local && context.privacy_contract === plan.privacy_contract && context.egress_level === plan.egress_level;
  const invalidate = () => { const ack=q("#br-ack"); if(ack)ack.checked=false; sync(); };
  const sync = () => {
    q("#br-build").disabled=busy;
    const start=q("#br-start"), stop=q("#br-stop");
    if(start)start.disabled=busy || plan.state!=="planned" || !allowed() || (!plan.local && !q("#br-ack")?.checked);
    if(stop)stop.disabled=busy || plan.state!=="running";
  };
  root.updateProvider = next => {
    if(JSON.stringify([context.destination,context.model,context.local,context.egress_level,context.privacy_contract,context.configured,context.allowed]) !== JSON.stringify([next.destination,next.model,next.local,next.egress_level,next.privacy_contract,next.configured,next.allowed])) invalidate();
    context=structuredClone(next); sync(); schedule();
  };
  const showPlan = p => {
    const changed = binding(plan)!==binding(p);
    plan=p;
    if(changed) {
      generation++; after=-1;
      q("#br-plan").innerHTML=`<h4>Inspected run <span id="br-run-id" class="mono"></span></h4><div id="br-status" role="status"></div>
        <p class="small">Provider terms and data controls apply. <a href="#/settings/integrations">Provider setup</a> is independent of this case's policy. ${p.local ? "Local provider; no external acknowledgement required." : "External provider: current pseudonymized case permission and deliberate approval of this exact plan are required."}</p>
        ${p.local ? "" : '<label><input id="br-ack" type="checkbox"> I inspected this plan, its sanitized packets and provider terms and authorize this run only.</label>'}
        <p><button id="br-start" type="button">Start batch review</button> <button id="br-stop" type="button" class="secondary">Stop batch review</button> <button id="br-refresh" type="button" class="secondary">Refresh inspected run</button></p>
        <h4>Initial packets (10 per page)</h4><div id="br-packets"></div><p><button id="br-packets-first" class="secondary" type="button">First packets</button> <button id="br-packets-next" class="secondary" type="button">Next packets</button></p><h4>Separate synthesis — model prose, not new evidence</h4><div id="br-synthesis-result"></div>`;
      q("#br-run-id").textContent=p.id;
      q("#br-ack")?.addEventListener("change",sync);
      q("#br-refresh").onclick=()=>refresh().catch(e=>message(e.message,true));
      q("#br-start").onclick=()=>operation(async()=>{
        const result=await api(`${base}/${encodeURIComponent(plan.id)}/start`,{method:"POST",body:JSON.stringify({plan_key:plan.plan_key,acknowledge:!!q("#br-ack")?.checked})});
        if(!live())return; invalidate(); showPlan(result); await packets();
      });
      q("#br-stop").onclick=()=>operation(async()=>{await api(`${base}/${encodeURIComponent(plan.id)}/cancel`,{method:"POST",body:"{}"});if(live()){invalidate();await refresh();}});
      q("#br-packets-first").onclick=()=>{after=-1;packets().catch(e=>message(e.message,true));};
      q("#br-packets-next").onclick=()=>{after=Number(q("#br-packets-next").dataset.after);packets().catch(e=>message(e.message,true));};
    }
    const n=v=>esc(v??"not recorded"), c=p.snapshot?.coverage||{}, progress=p.progress||{};
    q("#br-status").innerHTML=`<p><strong>${n(p.state)}</strong> · ${n(p.reason||"No recorded reason")} ${p.input_incomplete ? " · Incomplete input / partial work" : ""}</p>
      <p class="small">${n(p.destination)} · ${n(p.model)} · privacy contract ${n(p.privacy_contract)}. Frozen ${n(p.created_at)}; GET is not a freshness check.</p>
      <p class="small">Frozen budget: requests ${n(p.budget?.requests)} · input bytes ${n(p.budget?.input_bytes)} · output bytes ${n(p.budget?.output_bytes)} · per-request seconds ${n(p.budget?.per_request_seconds)} · overall seconds ${n(p.budget?.overall_seconds)} · concurrency ${n(p.budget?.concurrency)} · retries ${n(p.budget?.retries)}. Editing the form above affects only the next Build plan, not this inspected run.</p>
      <p>Eligible ${n(p.eligible_events)} / planned primary events ${n(p.planned_events)}. Total initial batches ${n(p.total_batches)} / enabled ${n(p.enabled_batches)}.</p>
      <p>Successful ${n(progress.succeeded)} · failed ${n(progress.failed)} · cancelled ${n(progress.cancelled)} · interrupted ${n(progress.interrupted)} · unreviewed ${n(progress.unreviewed)} · ready (subset of unreviewed) ${n(progress.ready)} · sending ${n(progress.sending)}.</p>
      <p>Primary reviewed events ${n(progress.primary_reviewed_events)} · distinct successful events ${n(progress.distinct_successful_events)}. Neither count proves semantic examination; synthesis adds no event coverage.</p>
      <p class="small">Requests attempted ${n(progress.requests_attempted)} · input bytes admitted ${n(progress.input_bytes_admitted)} · output bytes retained ${n(progress.output_bytes_retained)}. Attempts are durable admission, not proof of delivery or billing.</p>
      <p class="small">Whole catalog: ${n(c.sources_imported)} imported, ${n(c.sources_failed)} failed, ${n(c.sources_unsupported)} unsupported, ${n(c.sources_not_imported)} not imported. Parse gaps ${n(p.snapshot?.source_parse_gaps)}; parse coverage not recorded ${n(c.parse_coverage_not_recorded)}; undated ${n(c.undated_total)}. These totals remain applicable when sampled source details are omitted.</p>
      <p class="small">Findings included ${n(p.findings_included)} / omitted ${n(p.findings_omitted)}; correlations included ${n(p.correlations_included)} / omitted ${n(p.correlations_omitted)}.</p>
      <p class="small">Distinct stored VT included ${p.vt_recorded === true ? n(p.vt_included) : "not recorded"} / omitted ${p.vt_recorded === true ? n(p.vt_omitted) : "not recorded"} across this plan. Not primary or successful event coverage.</p>${renderStoredVTCoverage({...c,vt_recorded:c.vt_recorded === true && p.vt_recorded === true,vt_included:p.vt_included,vt_omitted:p.vt_omitted})}
      <p class="small">Synthesis ${n(p.synthesis_state||"not prepared")} · omitted sentences ${n(p.synthesis_omitted_sentences)} · unsynthesized successful batches ${n(p.unsynthesized_batches)}. Reservation: ${p.budget?.synthesis ? "one request + 160000 input bytes" : "disabled"}; output/time remaining and a newly prepared privacy namespace can still prevent synthesis. Omitted, failed or budget-exhausted work is not whole-case completion.</p>`;
    sync(); schedule();
  };
  const operation = async fn => {if(busy)return;busy=true;sync();message("Working locally or awaiting explicit operation…");try{await fn();if(live())message("Operation completed; inspect recorded state below.");}catch(e){if(live()){invalidate();message(e.message||String(e),true);}}finally{busy=false;if(live())sync();}};
  const schedule = () => {clearTimeout(timer);if(plan?.state==="running")timer=setTimeout(()=>{if(live())refresh().catch(e=>{message(e.message,true);schedule();});},2000);};
  const refresh = async () => {
    if(!plan)return;
    const id=plan.id, epoch=generation;
    const p=await api(`${base}/${encodeURIComponent(id)}`);
    if(!live()||generation!==epoch||plan.id!==id)return;
    showPlan(p); await packets();
  };
  // Packet rendering and exact payload inspection are independent of whole-case loads.
  const packets = async () => {
    const id=plan.id, epoch=generation, cursor=after;
    const page=await api(`${base}/${encodeURIComponent(id)}/packets?after=${cursor}&limit=10`);
    if(!live()||epoch!==generation||plan.id!==id||cursor!==after)return;
    const paint = (container, items) => {
      // Remove the empty-state text when a prepared packet becomes available.
      for(const node of [...container.childNodes])if(node.nodeType===Node.TEXT_NODE)node.remove();
      const wanted=new Set(items.map(p=>String(p.seq)));
      for(const node of [...container.children])if(!wanted.has(node.dataset.seq))node.remove();
      for(const packet of items){
        let node=[...container.children].find(n=>n.dataset.seq===String(packet.seq));
        if(!node){
          node=document.createElement("details");node.className="batch-packet";node.dataset.seq=packet.seq;
          node.innerHTML=`<summary></summary><p class="batch-packet-identity small"></p><div class="batch-packet-status small"></div>
            <button class="secondary batch-payload-button" type="button">Inspect exact sanitized payload / hash</button><pre class="batch-payload small" tabindex="0" hidden></pre>
            <details class="batch-coverage"><summary>This packet's coverage and primary / context references</summary><pre class="small"></pre><div class="batch-originals source-links"></div></details>
            <div class="batch-commentary"></div><details class="batch-raw"><summary>Untrusted raw provider answer — text only, not evidence</summary><pre class="small"></pre></details>`;
          container.appendChild(node);
          node.querySelector(".batch-payload-button").onclick=async()=>{
            const button=node.querySelector(".batch-payload-button");button.disabled=true;
            try{
              const data=await api(`${base}/${encodeURIComponent(id)}/packets/${packet.seq}/payload`);
              if(!live()||epoch!==generation||!node.isConnected)return;
              const box=node.querySelector(".batch-payload");
              box.textContent=`${data.attempted ? "Attempted: durable admission, not delivery proof" : "Frozen pre-send: NOT a transmission receipt"}\nState: ${data.state}\nPrivacy receipt: ${JSON.stringify(data.privacy)}\nA privacy check is not separate permission.\nDestination: ${data.payload.destination} · Model: ${data.payload.model}\nSHA-256 (system + NUL + user): ${data.payload.sha256}\n\nSYSTEM\n${data.payload.system}\n\nUSER\n${data.payload.user}`;
              box.hidden=false;
            }catch(e){message("Payload unavailable: "+(e.message||String(e)),true);}finally{if(node.isConnected)button.disabled=false;}
          };
        }
        if(node.dataset.record===JSON.stringify(packet))continue;
        node.dataset.record=JSON.stringify(packet);
        node.querySelector("summary").textContent=`Packet ${packet.seq} · ${packet.kind} · ${packet.state}`;
        node.querySelector(".batch-packet-identity").textContent=`Namespace: ${packet.namespace||"not prepared"}. Aliases and pseudonyms are local to this namespace, never merge equal-looking tokens. Offset ${packet.offset}; primary events ${packet.primary_events}; event/context references ${(packet.event_ids||[]).length}.`;
        node.querySelector(".batch-packet-status").textContent=`Privacy receipt: ${packet.privacy?.status||"not recorded"} · ${packet.privacy?.contract||"not recorded"}; ${packet.privacy?.payload_bytes||0} payload bytes. Not consent or anonymity. ${packet.error||""} Rejected lines ${packet.rejected||0}; rejection reasons ${JSON.stringify(packet.reasons||{})}. ${packet.actual_model ? "Reported model: "+packet.actual_model : ""} ${packet.prompt_tokens||packet.completion_tokens ? "Reported tokens in "+(packet.prompt_tokens??"unknown")+", out "+(packet.completion_tokens??"unknown") : "Usage not reported."} ${packet.omitted_source_batches?.length ? "Synthesis omitted source batches: "+packet.omitted_source_batches.join(", ") : ""}`;
        node.querySelector(".batch-coverage pre").textContent=JSON.stringify(packet.coverage ?? "not recorded",null,2);
        let vtCoverage=node.querySelector(".batch-vt-coverage");
        if(!vtCoverage){vtCoverage=document.createElement("div");vtCoverage.className="batch-vt-coverage";node.querySelector(".batch-coverage pre").before(vtCoverage);}
        vtCoverage.innerHTML=renderStoredVTCoverage(packet.coverage);
        node.querySelector(".batch-originals").innerHTML=`<p>Original same-case references: ${packet.kind==="event" ? "event membership is primary" : "events are supporting context, not additional primary event coverage"}.</p>`+
          ["event","finding","correlation"].map(kind=>(packet[kind+"_ids"]||[]).map(ref=>externalCitation(kind,ref)).join(" ")).join(" ");
        wireExternalCitations(node.querySelector(".batch-originals"),caseId);
        const commentary=node.querySelector(".batch-commentary");
        commentary.innerHTML=`<p><strong>Validated commentary — not evidence; anchoring is not truth.</strong></p>`+(packet.sentences?.length ? renderReviewClaimGroups(packet.sentences, (kind,ref)=>kind==="coverage"&&ref==="selection" ? '<button type="button" class="source-link batch-selection">coverage selection (this packet)</button>' : externalCitation(kind,ref,{runID:id})) : `<p>No usable commentary recorded for this packet (${esc(packet.state)}).</p>`);
        commentary.querySelectorAll(".batch-selection").forEach(b=>{
          // Deliberately bypass legacy latest-review coverage resolution.
          b.classList.remove("source-link");b.onclick=()=>{
            const d=document.createElement("dialog");d.className="external-source-dialog";d.setAttribute("aria-label","Batch packet coverage");
            d.innerHTML='<h2>This packet’s frozen coverage</h2><p class="batch-coverage-id"></p><pre></pre><button type="button" class="secondary">Close</button>';
            d.querySelector(".batch-coverage-id").textContent=`Run ${id}; packet ${packet.seq}; namespace ${packet.namespace}. Not raw-image coverage; do not sum repeated context.`;
            d.querySelector("pre").textContent=JSON.stringify(packet.coverage,null,2);d.querySelector("button").onclick=()=>d.close();d.addEventListener("close",()=>{d.remove();if(b.isConnected)b.focus({preventScroll:true});},{once:true});document.body.appendChild(d);d.showModal();
          };
        });
        wireExternalCitations(commentary,caseId);
        node.querySelector(".batch-raw pre").textContent=packet.raw_answer||"No raw provider answer recorded.";
      }
    };
    paint(q("#br-packets"),page.packets.filter(p=>p.kind!=="synthesis"));
    const synthesis=page.packets.filter(p=>p.kind==="synthesis");
    if(!synthesis.length && plan.synthesis_state && !["disabled","omitted"].includes(plan.synthesis_state)){
      const s=await api(`${base}/${encodeURIComponent(id)}/packets?after=${plan.total_batches-1}&limit=1`);
      if(!live()||epoch!==generation||cursor!==after)return;
      synthesis.push(...s.packets.filter(p=>p.kind==="synthesis"));
    }
    paint(q("#br-synthesis-result"),synthesis);
    if(!synthesis.length)q("#br-synthesis-result").textContent=`Synthesis ${plan.synthesis_state||"not prepared"}. No new evidence; only retained validated original citations may be used.`;
    q("#br-packets-next").disabled=page.packets.filter(p=>p.kind!=="synthesis").length<10;
    q("#br-packets-next").dataset.after=page.packets.at(-1)?.seq ?? cursor;
  };
  const history = async () => {
    const offset=historyOffset;
    const h=await api(`${base}/history?offset=${offset}&limit=10`);
    if(!live()||offset!==historyOffset)return;
    const list=q("#br-history-list"); list.innerHTML=`<p class="small">${h.total} retained plans; inspecting a history entry never resumes it.</p>`;
    for(const p of h.plans){const b=document.createElement("button");b.type="button";b.className="secondary";b.textContent=`${p.id} · ${p.state} · ${p.created_at}`;b.onclick=()=>operation(async()=>{invalidate();showPlan(p);await packets();});list.appendChild(b);}
    q("#br-history-prev").disabled=offset===0;q("#br-history-next").disabled=!h.has_more;
  };
  q("#br-history").ontoggle=()=>{if(q("#br-history").open)history().catch(e=>message(e.message,true));};
  q("#br-history-prev").onclick=()=>{historyOffset=Math.max(0,historyOffset-10);history().catch(e=>message(e.message,true));};
  q("#br-history-next").onclick=()=>{historyOffset+=10;history().catch(e=>message(e.message,true));};
  q("#br-budget").onsubmit=e=>{e.preventDefault();operation(async()=>{
    const budget={}; for(const key of Object.keys(ranges))budget[key]=Number(q(`[name="${key}"]`).value);budget.synthesis=q("#br-synthesis").checked;
    invalidate();const p=await api(`${base}/plan`,{method:"POST",body:JSON.stringify({budget})});if(!live())return;showPlan(p);await packets();message("Plan built locally; zero model requests. Inspect and approve before starting.");
  });};
  root.addEventListener("toggle",()=>{if(root.open&&!loaded){loaded=true;operation(async()=>{const p=await api(base);if(!live())return;if(p.id){showPlan(p);await packets();}else message("No plan yet. Build locally; nothing will be sent.");});}});
  return root;
}

// Case Review types are supplied by the backend, never inferred from prose.
// Summary deliberately does not use this renderer.
function renderReviewClaimGroups(sentences, citation = externalCitation) {
  const types = [
    ["observation", "Observations", "Check the cited records; an AI label is not a verified observation."],
    ["possible_conflict", "Possible conflicts", "Tentative conflict; compare the cited records before drawing a conclusion."],
    ["hypothesis", "Hypotheses", "Unconfirmed explanations, not detector findings."],
    ["gap", "Gaps", "Missing or limited information is not proof of absence."],
    ["next_check", "Suggested checks", "Recommendations only; no action has been executed."],
    ["unclassified", "Unclassified / not type-checked", "Missing or unknown type, including older results. Not retrospectively classified."]
  ];
  const groups = new Map(types.map(([kind]) => [kind, []]));
  for (const sentence of sentences || []) {
    const kind = groups.has(sentence.kind) ? sentence.kind : "unclassified";
    groups.get(kind).push(sentence);
  }
  return `<div class="review-claim-groups"><p class="small review-claim-legend"><strong>AI-labelled categories — not truth-validated.</strong> Observations need citation checks; possible conflicts are tentative; hypotheses are unconfirmed; gaps are not proof of absence; suggested checks are recommendations, not executed actions. Labels do not change findings, severity or evidence.</p>` + types.map(([kind, label, caution]) => {
    const items = groups.get(kind);
    if (!items.length) return "";
    return `<section class="review-claim-group" data-claim-kind="${kind}"><h5>${label} <span class="review-claim-count">(${items.length})</span></h5><p class="small muted">${caution}</p><ol>${items.map(s => `<li>${esc(s.text)} <span class="source-links">${(s.cites || []).map(c => citation(c.kind, c.id)).join(" ")}</span></li>`).join("")}</ol></section>`;
  }).join("") + `</div>`;
}

function renderCaseReviewSection(rv) {
  const running = rv.run?.state === "running";
  const l = rv.latest;
  const coverage = (c) => { const n = key => Number.isSafeInteger(c?.[key]) && c[key] >= 0 ? String(c[key]) : "not recorded"; return c ? `<p class="small review-coverage"><strong>Bounded partial selection:</strong> ${n("events_included")} of ${n("events_total")} parsed events included; ${n("events_omitted")} omitted. ${n("findings_included")} of ${n("findings_total")} findings (${n("findings_omitted")} omitted); ${n("correlations_included")} of ${n("correlations_total")} correlations (${n("correlations_omitted")} omitted); ${n("sources_included")} of ${n("sources_total")} source coverage records (${n("sources_omitted")} omitted). ${n("undated_total")} undated events in the case. Missing supporting references: ${n("missing_supporting_refs")}; available supporting events omitted: ${n("supporting_refs_omitted")}; unflagged observations included: ${n("unflagged_included")}; source parse coverage not recorded: ${n("parse_coverage_not_recorded")}. Global source statuses: ${n("sources_imported")} imported, ${n("sources_failed")} parse failures, ${n("sources_unsupported")} unsupported, ${n("sources_not_imported")} supported but not imported. Command lines omitted by the body guard: ${n("command_lines_omitted")}.</p>` : ""; };
  let why = !rv.configured ? "Set up a provider in Settings → Integrations." : !rv.allowed ? "Choose pseudonymized egress for an external destination." : rv.events === 0 ? "No parsed events are available." : running ? "A bounded review is running." : "Inspect a preview before starting.";
  return `<h3>AI Case Review <span class="external-optional">Optional · bounded</span></h3>
    <p class="small"><strong>Optional AI commentary, not a finding or evidence.</strong> A single request reviews selected parsed findings, correlations, supporting events, context and unflagged observations. It never changes findings or severity.</p>
    <p class="small muted">Not exhaustive case analysis; no raw-image coverage. Use the separate parsed-case batch section below to plan multiple bounded requests. Unknown or tied times do not establish order; unknown hosts are acquisition-scoped. Validation checks references, entities and numbers, not semantic truth.</p>
    <p class="small">Stored VirusTotal context is optional secondary context. Stored results only: opening, previewing, planning and review never call VirusTotal; no VT key required. VT is an outside opinion at lookup time, not primary evidence. Zero detections and not_found are not proof of safety. Lookup age differs from case-source freshness; no age threshold is inferred. Frozen citations never substitute a later live lookup.</p>
    <p class="small">Destination: ${rv.configured ? `${esc(rv.destination)} · ${esc(rv.model)} · ${rv.local ? "local model; nothing leaves this machine" : "another machine"}` : `<a href="#/settings/integrations">Settings → Integrations</a>`}.</p>
    <p id="rv-caps" class="small"><strong>1. Evidence selection — request caps:</strong> 25 findings · 25 correlations · 120 parsed events · 60 source coverage records · 160000 payload bytes. One request, always limited in scope.</p>
    <details id="rv-selection" class="external-details"><summary>How evidence is selected</summary>
      <p class="small">Half the event capacity is reserved for deterministic acquisition/source/type/identity/time-knownness strata beyond primary references. ID ordering is only a selection tie-break, never evidence of temporal order. Provenance identifies the primary observation, not every recollection.</p>
    </details>
    <p id="rv-privacy-status" class="small" role="status"><strong>2. Privacy preparation:</strong> Not checked for a current preview. A privacy check is not permission to transmit.</p>
    <details id="rv-privacy" class="external-details"><summary>Privacy contract and limitations</summary>
      <p class="small">Stored VT numeric verdicts, status, lookup time and linked references can be part of the sanitized model context; hashes remain tokenized for the model. Raw hashes in the source dialog are local only. No raw provider JSON, error text or free-text labels. Hash-only VT permission does not authorize LLM transmission: retain model egress permission, this exact preview and per-request acknowledgement (or per-run approval for batches).</p>
      <p class="small">Only allowlisted normalized fields and numeric parse coverage are used. Names, addresses and hashes become stable tokens; secrets are removed. Bounded normalized command lines are secret-redacted; recognizable SQL/cookie bodies are omitted and counted. Original partial/local time readings stay labelled, never treated as UTC. No raw file bodies, SQL statements, cookies, notes, case names, evidence names, server paths or raw parser errors. URL userinfo, query strings and fragments are removed before tokenization. Recognized request bodies and private-key blocks are excluded. These are pattern-based protections, not a guarantee that arbitrary text contains no sensitive information. Pseudonymized does not mean anonymous. Missing parse coverage means not recorded, not complete.</p>
    </details>
    <p id="rv-permission" class="small"><strong>3. Transmission permission:</strong> Provider login is not consent. ${!rv.configured ? "No provider is active." : rv.local ? "Local destination; explicitly starting is still required. No external acknowledgement is needed." : rv.allowed ? "Case policy permits pseudonymized facts, but each external request still requires the current preview and your acknowledgement." : "Case policy blocks external case facts. A successful privacy check cannot override it."} Choosing a policy or inspecting a preview never starts a request. Revocation cancels an in-flight external review where possible; bytes already delivered cannot be recalled.</p>
    ${rv.configured && !rv.local ? `<p class="external-notice small"><strong>Before sending:</strong> ${esc(rv.notice || "Check this provider's terms and data controls.")}</p><p class="small"><label><input type="checkbox" id="rv-ack"> I reviewed the preview and provider terms and authorize this one bounded request.</label></p>` : ""}
    <p><button type="button" class="secondary" id="rv-preview" ${running || rv.events === 0 ? "disabled" : ""}>Inspect pre-send preview</button>
    <button type="button" id="rv-start" disabled>Start bounded review</button>
    <button type="button" class="secondary" id="rv-cancel" ${running ? "" : "hidden"}>Stop review</button></p>
    <p id="rv-why" class="small muted">${esc(why)}</p><p id="rv-msg" class="small" role="status"></p>
    <div id="rv-plan" hidden></div><pre id="rv-preview-box" hidden tabindex="0" aria-label="Pre-send bounded review payload" class="small" style="white-space:pre-wrap;overflow-wrap:anywhere;max-height:24em;overflow:auto"></pre>
    ${rv.run ? `<p class="small">Last bounded request: <strong>${esc(rv.run.state)}</strong> ${esc(rv.run.reason || "")}</p>` : ""}
    ${l ? `<div class="review-commentary"><p><strong>Optional AI commentary — not evidence or a new finding.</strong></p>
      ${l.stale ? `<p class="field-error-box">Stale: relevant parsed events, correlations, findings, source coverage or stored VirusTotal context changed since this request. This does not measure the age or freshness of the outside opinion.</p>` : ""}
      <p class="small">Privacy preparation at this attempt: ${l.privacy ? `${esc(l.privacy.status)} · ${esc(l.privacy.contract)} · ${esc(l.privacy.payload_bytes)} payload bytes. A local check, not proof of anonymity.` : "not recorded (older result)."}</p>
      ${coverage(l.coverage)}${renderStoredVTCoverage(l.coverage)}
      <p class="small">${esc(l.created_at)} · ${esc(l.destination)} · ${esc(l.model)}${l.prompt_tokens || l.completion_tokens ? ` · ${l.prompt_tokens} tokens in, ${l.completion_tokens} out` : ""}</p>
      ${l.status === "ok" ? renderReviewClaimGroups(l.sentences,(kind,id)=>externalCitation(kind,id,{reviewID:l.id})) : `<p>No usable commentary: ${esc(l.error || "request failed or interrupted")}. The request payload is recorded separately.</p>`}
      <p class="small">${l.rejected || 0} line(s) rejected. Anchoring validation does not prove truth. Read every claim against its references.</p>
      <button type="button" class="secondary" id="rv-payload">Show exactly what was sent</button>
      <pre id="rv-payload-box" data-hash="${esc(l.payload_sha256)}" hidden tabindex="0" aria-label="Exact bounded review payload" class="small" style="white-space:pre-wrap;overflow-wrap:anywhere;max-height:24em;overflow:auto"></pre></div>` : `<p class="empty">No bounded case review has been requested.</p>`}`;
}

function wireCaseReviewSection(content, caseId, rv, say) {
  const card = content.querySelector("#external-review");
  if (!card) return;
  const start = card.querySelector("#rv-start"), ack = card.querySelector("#rv-ack");
  const sync = () => { start.disabled = !rv.configured || !rv.allowed || rv.events === 0 || rv.run?.state === "running" || !card.dataset.previewHash || card.dataset.privacyContract !== rv.privacy_contract || (!rv.local && !ack?.checked); };
  if (ack) ack.addEventListener("change",sync);
  card.addEventListener("review-state-restored",sync);
  const invalidatePreview = () => {
    delete card.dataset.previewHash; delete card.dataset.privacyContract;
    if (ack) ack.checked = false;
    card.querySelector("#rv-preview-box").hidden = true;
    card.querySelector("#rv-plan").hidden = true;
    card.querySelector("#rv-privacy-status").textContent = "2. Privacy preparation: not checked for a current preview; no transmission permission granted.";
    sync();
  };
  card.querySelector("#rv-preview").addEventListener("click",async () => {
    invalidatePreview();
    try {
      const p = await api(`/cases/${caseId}/enrich/case-review/preview`);
      if (!card.isConnected) return;
      const bytes = new TextEncoder().encode(p.system + p.user).length;
      if (!p.privacy || p.privacy.status !== "checked" || p.privacy.contract !== rv.privacy_contract || p.privacy.requires_separate_permission !== true || p.privacy.payload_bytes !== bytes || !p.preview_key) throw Error("A current privacy-preparation receipt is required; refresh and inspect again.");
      if (p.destination !== rv.destination || p.model !== rv.model || p.local !== rv.local || p.egress_level !== rv.egress_level || p.source_fingerprint !== rv.source_fingerprint) throw Error("The preview privacy/provider/policy/input context changed; refresh before authorizing.");
      card.dataset.privacyContract = p.privacy.contract;
      card.querySelector("#rv-privacy-status").textContent = `2. Privacy preparation: checked locally (${p.privacy.contract}, ${bytes} payload bytes). Pattern-based checks, not anonymity or permission to transmit.`;
      card.dataset.previewHash = p.preview_key;
      card.dataset.fingerprint = p.source_fingerprint;
      const box = card.querySelector("#rv-preview-box");
      box.textContent = `Destination: ${p.destination} · Model: ${p.model}\nPayload SHA-256: ${p.sha256}\n\n${p.system}\n\n${p.user}`; box.hidden = false;
      const plan = card.querySelector("#rv-plan"); plan.innerHTML = '<p>Actual selection and coverage (not exhaustive); stored VT only, no lookup or model call on preview.</p>' + renderStoredVTCoverage(p.coverage) + '<pre class="small"></pre>'; plan.querySelector("pre").textContent = JSON.stringify(p.coverage ?? "not recorded"); plan.hidden = false;
      if (ack) ack.checked = false;
      card.querySelector("#rv-why").textContent = "Preview built locally; nothing sent. Starting recomputes and refuses a changed payload.";
      sync();
    } catch(e) { if (!card.isConnected) return; invalidatePreview(); say("rv-msg",e.message || String(e),true); }
  });
  start.addEventListener("click",async () => {
    start.disabled = true;
    try {
      await api(`/cases/${caseId}/enrich/case-review`,{method:"POST",body:JSON.stringify({acknowledge:!!ack?.checked,preview_key:card.dataset.previewHash})});
      if (card.isConnected) await renderExternalTab(content,caseId);
    } catch(e) { if (!card.isConnected) return; invalidatePreview(); say("rv-msg",e.message || String(e),true); }
  });
  card.querySelector("#rv-cancel").addEventListener("click",async () => {
    try { await api(`/cases/${caseId}/enrich/case-review/cancel`,{method:"POST",body:"{}"}); if(card.isConnected)await renderExternalTab(content,caseId); }
    catch(e) { say("rv-msg",e.message || String(e),true); }
  });
  card.querySelector("#rv-payload")?.addEventListener("click",async () => {
    try { const p=await api(`/cases/${caseId}/enrich/case-review/payload`); if(!card.isConnected)return; const box=card.querySelector("#rv-payload-box"); if(box.dataset.hash!==p.sha256)throw Error("Latest review changed; refresh before inspecting it.");box.textContent=`Destination: ${p.destination} · Model: ${p.model}\nSHA-256: ${p.sha256}\n\n${p.system}\n\n${p.user}`;box.hidden=false; }
    catch(e) { say("rv-msg",e.message || String(e),true); }
  });
  sync();
}

function renderNarrativeSection(nv) {
  const run = nv.run;
  const running = run && run.state === "running";
  let why = "";
  if (!nv.configured) why = "No language model is configured. Open Settings → Integrations to authorize ChatGPT/Codex and select a provider, or configure the server API provider.";
  else if (!nv.allowed) why = "This case's level does not allow facts to be sent to another machine. Choose \"pseudonymized\" above.";
  else if (nv.findings === 0) why = "The case has no findings yet: run the analysis first.";
  else if (running) why = "A summary is being drafted.";
  const where = nv.configured
    ? nv.local
      ? `a model on this machine (<span class="mono">${esc(nv.destination)}</span>, ${esc(nv.model)}): nothing leaves it`
      : `<span class="mono">${esc(nv.destination)}</span>, model ${esc(nv.model)}: another machine`
    : "not configured";
  const l = nv.latest;
  let latest = `<p class="empty">No summary has been requested for this case.</p>`;
  if (l) {
    const items = (l.sentences || [])
      .map((x) => {
        const cites = (x.cites || []).map((c) => externalCitation(c.kind, c.id)).join(" ");
        return `<li>${esc(x.text)} <span class="source-links">${cites}</span></li>`;
      })
      .join("");
    const reasons = l.reasons ? Object.entries(l.reasons).map(([k, v]) => `${esc(k)} (${v})`).join("; ") : "";
    latest = `
      <div class="narrative-draft" style="border:1px solid var(--border, #334);padding:var(--space-3);border-radius:6px">
        <p class="small"><strong>Draft written by a language model: not a finding, not evidence.</strong>
          ${esc(fmtTime(l.created_at))} &middot; ${l.local ? "ran on this machine" : "sent to " + esc(l.destination)} &middot; ${esc(l.model)}
          ${l.prompt_tokens || l.completion_tokens ? ` &middot; ${l.prompt_tokens} tokens in, ${l.completion_tokens} out` : ""}</p>
        ${l.stale ? `<p><strong>The findings changed after this draft was written.</strong> Draft it again.</p>` : ""}
        ${
          l.status === "ok"
            ? `<p class="small muted">Each sentence cites what it relies on. That, the names and the numbers were checked by program;
                <strong>whether it is true was not</strong>. Read it against the cited findings and events.</p>
               <ol>${items}</ol>
               ${l.rejected ? `<p class="small muted">${l.rejected} line(s) of the answer were dropped by validation: ${reasons}.</p>` : ""}`
            : `<p>The request produced no usable draft${l.error ? ` (${esc(l.error)})` : ""}. Case facts were still sent; see exactly what below.</p>`
        }
        <p class="small mono muted" style="word-break:break-all">SHA-256 of what was sent: ${esc(l.payload_sha256)}</p>
        <p><button type="button" class="btn-secondary" id="nv-payload">Show exactly what was sent</button></p>
        <pre id="nv-payload-box" data-hash="${esc(l.payload_sha256)}" tabindex="0" aria-label="Exact payload sent to the model" class="small" hidden style="white-space:pre-wrap;max-height:24em;overflow:auto"></pre>
      </div>`;
  }
  return `
    <h3>AI summary <span class="external-optional">Optional</span></h3>
    <p class="small muted">Optional. A model drafts a short summary of the findings; the findings themselves never come from it.
      Where it goes: ${where}.</p>
    ${!nv.configured ? `<details id="nv-setup" class="external-details"><summary>Set up a language model</summary>
      <p><strong>API provider:</strong> set <code>TRACEFALL_LLM_API_KEY</code> and <code>TRACEFALL_LLM_MODEL</code> on the server; optionally set <code>TRACEFALL_LLM_BASE_URL</code>.</p>
      <p><strong>ChatGPT account:</strong> <a href="#/settings/integrations">Open Settings → Integrations</a> to authorize the official Codex CLI in isolated server storage and select <code>codex-cli</code>. Explicit <code>TRACEFALL_LLM_PROVIDER</code> overrides UI provider preferences. Authorizing sends no model request; case summaries still require their egress policy and per-request acknowledgement.</p>
      </details>` : ""}
    <details id="nv-privacy" class="external-details"><summary>What leaves this server?</summary>
    <p class="small"><strong>What is sent:</strong> finding titles, rules, severities, ATT&amp;CK ids, times, and for the events they cite:
      type, process names, command lines, paths and addresses, with every name, address, identifier and hash replaced by a token
      only this server can reverse, and secrets removed. <strong>Never sent:</strong> file contents, SQL statements, cookies, the case name or
      description, notes, evidence file names. Times, process names and the shape of the activity are sent as they are. Pseudonymized does not mean anonymous.</p>
    </details>
    ${
      nv.configured && !nv.local
        ? `${nv.notice ? `<p class="external-notice small"><strong>Before sending:</strong> ${esc(nv.notice)}</p>` : ""}
           <p class="small"><label><input type="checkbox" id="nv-ack"> I have reviewed what will be sent and this provider's terms, and authorize this request
             (some providers may use it to train models).</label></p>`
        : ""
    }
    <p>
      <button type="button" class="btn-primary" id="nv-start" disabled>Draft summary</button>
      <button type="button" class="btn-secondary" id="nv-cancel" ${running ? "" : "hidden"}>Stop</button>
      ${why ? `<span class="muted small" style="margin-left:var(--space-2)">${esc(why)}</span>` : ""}
    </p>
    <p id="nv-msg" class="small" role="status"></p>
    ${run ? `<p class="small">Last request: <strong>${esc(run.state)}</strong>${run.reason ? " &middot; " + esc(run.reason) : ""}</p>` : ""}
    ${latest}`;
}

function wireNarrativeSection(content, caseId, nv, say) {
  const start = document.getElementById("nv-start");
  if (!start) return;
  const ack = document.getElementById("nv-ack");
  const running = nv.run && nv.run.state === "running";
  const ready = () => nv.configured && nv.allowed && nv.findings > 0 && !running && (nv.local || (ack && ack.checked));
  const sync = () => (start.disabled = !ready());
  sync();
  if (ack) ack.addEventListener("change", sync);
  start.addEventListener("click", async () => {
    start.disabled = true;
    try {
      await api(`/cases/${caseId}/enrich/narrative`, { method: "POST", body: JSON.stringify({ acknowledge: !!(ack && ack.checked) }) });
      await renderExternalTab(content, caseId);
    } catch (e) {
      say("nv-msg", e.message || String(e), true);
      sync();
    }
  });
  const cancel = document.getElementById("nv-cancel");
  if (cancel)
    cancel.addEventListener("click", async () => {
      try {
        await api(`/cases/${caseId}/enrich/narrative/cancel`, { method: "POST", body: "{}" });
        await renderExternalTab(content, caseId);
      } catch (e) {
        say("nv-msg", e.message || String(e), true);
      }
    });
  const show = document.getElementById("nv-payload");
  if (show)
    show.addEventListener("click", async () => {
      const box = document.getElementById("nv-payload-box");
      try {
        const p = await api(`/cases/${caseId}/enrich/narrative/payload`);
        box.textContent = `To: ${p.destination}   Model: ${p.model}   Sent: ${p.sent_at}\nSHA-256: ${p.sha256}\n\n--- instructions ---\n${p.system}\n\n--- facts ---\n${p.user}`;
        box.hidden = false;
      } catch (e) {
        say("nv-msg", e.message || String(e), true);
      }
    });
}

// Capture at response time, not request time: the analyst may interact while
// status is loading. Consent never follows a different provider or policy.
function captureExternalState(root, consentKey) {
  if (!root || root.dataset.consentKey !== consentKey) return null;
  const box = root.querySelector("#nv-payload-box");
  const active = document.activeElement;
  const review = root.querySelector("#external-review");
  const reviewPreview = root.querySelector("#rv-preview-box");
  const reviewPayload = root.querySelector("#rv-payload-box");
  return {
    review: review ? { privacyContract: review.dataset.privacyContract, privacyText: review.querySelector("#rv-privacy-status")?.textContent, ack: !!root.querySelector("#rv-ack")?.checked, hash: review.dataset.previewHash, fingerprint: review.dataset.fingerprint, preview: reviewPreview && !reviewPreview.hidden ? reviewPreview.textContent : null, plan: root.querySelector("#rv-plan")?.textContent, payload: reviewPayload && !reviewPayload.hidden ? {hash:reviewPayload.dataset.hash,text:reviewPayload.textContent,scrollTop:reviewPayload.scrollTop} : null, scrollTop:reviewPreview?.scrollTop } : null,
    ack: !!root.querySelector("#nv-ack")?.checked,
    openDetails: Array.from(root.querySelectorAll("details[id]")).filter((d) => d.open).map((d) => d.id),
    payload: box && !box.hidden ? { hash: box.dataset.hash, text: box.textContent, scrollTop: box.scrollTop } : null,
    focusId: root.contains(active) ? active.id : "",
    focusSource: root.contains(active) && active.dataset?.sourceId ? { kind: active.dataset.sourceKind, id: active.dataset.sourceId } : null,
  };
}

function restoreExternalState(root, state) {
  if (!state) return;
  const ack = root.querySelector("#nv-ack");
  if (ack) { ack.checked = state.ack; ack.dispatchEvent(new Event("change")); }
  root.querySelectorAll("details[id]").forEach((d) => { d.open = state.openDetails.includes(d.id); });
  const box = root.querySelector("#nv-payload-box");
  if (box && state.payload && box.dataset.hash === state.payload.hash) {
    box.textContent = state.payload.text;
    box.hidden = false;
    box.scrollTop = state.payload.scrollTop;
  }
  const review = root.querySelector("#external-review");
  const rv = state.review;
  if (review && rv) {
    if (rv.hash && rv.privacyContract && rv.privacyContract === root.dataset.reviewPrivacyContract && rv.fingerprint === root.dataset.reviewFingerprint && rv.preview) {
      review.dataset.previewHash=rv.hash; review.dataset.fingerprint=rv.fingerprint; review.dataset.privacyContract=rv.privacyContract;
      review.querySelector("#rv-privacy-status").textContent=rv.privacyText;
      const preview=review.querySelector("#rv-preview-box");preview.textContent=rv.preview;preview.hidden=false;preview.scrollTop=rv.scrollTop || 0;
      const plan=review.querySelector("#rv-plan");plan.textContent=rv.plan;plan.hidden=false;
      const reviewAck=review.querySelector("#rv-ack");if(reviewAck){reviewAck.checked=rv.ack;reviewAck.dispatchEvent(new Event("change"));}
      review.dispatchEvent(new Event("review-state-restored"));
      review.querySelector("#rv-why").textContent="Preview built locally; nothing sent. Starting recomputes and refuses a changed payload.";
    }
    const sent=review.querySelector("#rv-payload-box");
    if (sent && rv.payload && sent.dataset.hash===rv.payload.hash) {sent.textContent=rv.payload.text;sent.hidden=false;sent.scrollTop=rv.payload.scrollTop;}
  }
  let focused = state.focusId ? Array.from(root.querySelectorAll("[id]")).find((el) => el.id === state.focusId) : null;
  if (!focused && state.focusSource) focused = Array.from(root.querySelectorAll(".source-link")).find((el) => el.dataset.sourceKind === state.focusSource.kind && el.dataset.sourceId === state.focusSource.id);
  if (focused && !focused.disabled) focused.focus({ preventScroll: true });
}

async function renderExternalTab(content, caseId, refresh) {
  // A refresh while a run is going keeps the page as it is until the new one
  // is ready: no "Loading..." flash, and the scroll position stays.
  const previousRoot = document.getElementById("ext-root");
  const previousBatch = previousRoot?.querySelector("#batch-review");
  const batchRoot = previousBatch?.dataset.caseId === String(caseId) ? previousBatch : null;
  const initialPlaceholder = refresh ? null : document.createElement("p");
  if (initialPlaceholder) { initialPlaceholder.className="empty"; initialPlaceholder.textContent="Loading..."; content.replaceChildren(initialPlaceholder); }
  const [eg, vt, nv, rv] = await Promise.all([
    api(`/cases/${caseId}/egress`),
    api(`/cases/${caseId}/enrich/virustotal`),
    api(`/cases/${caseId}/enrich/narrative`),
    api(`/cases/${caseId}/enrich/case-review`),
  ]);
  // A response from a page we left must not repaint the next tab.
  if (!content.isConnected || (refresh ? document.getElementById("ext-root") !== previousRoot : content.firstElementChild !== initialPlaceholder)) return;
  const batchFocus = batchRoot?.contains(document.activeElement) ? document.activeElement : null;
  const consentKey = JSON.stringify([caseId, eg.level, nv.destination, nv.model, nv.local, rv.destination, rv.model, rv.local, rv.egress_level, rv.privacy_contract]);
  const state = refresh ? captureExternalState(previousRoot, consentKey) : null;
  const st = vt.status;
  const run = st.run;
  const running = run && run.state === "running";
  const nrun = nv.run;
  const nRunning = nrun && nrun.state === "running";
  const canStart = st.allowed && st.configured && !running && st.pending > 0 && st.remaining > 0;

  const options = eg.options
    .map(
      (o) => `<label class="egress-option" style="display:block;margin:var(--space-2) 0;${o.selectable ? "" : "opacity:.55;"}">
        <input type="radio" name="egress-level" value="${esc(o.level)}"
               ${o.level === eg.level ? "checked" : ""} ${o.selectable ? "" : "disabled"}>
        <strong>${esc(o.level)}</strong>${o.selectable ? "" : " <span class=\"muted small\">(reserved, not available)</span>"}
        <div class="muted small" style="margin-left:1.5em">${esc(o.description)}</div>
      </label>`
    )
    .join("");

  let why = "";
  if (!st.configured) why = "VirusTotal is not configured. Open Settings → Integrations to save an API key (administrator access).";
  else if (!st.allowed) why = "This case's level does not allow file hashes to leave the server.";
  else if (running) why = "A lookup is running.";
  else if (st.candidates === 0) why = "No file hashes were found in this case's events.";
  else if (st.pending === 0) why = "Every hash has already been answered.";
  else if (st.remaining <= 0)
    why = st.monthly_limit - st.monthly_used <= st.daily_limit - st.daily_used
      ? "The monthly request allowance is used up."
      : "The daily request allowance is used up.";

  const runLine = run
    ? `<p class="small">Last run: <strong>${esc(run.state)}</strong> &middot; ${run.done} of ${run.total} done
         (${run.found} known, ${run.not_found} not known, ${run.errors} errors)${run.reason ? " &middot; " + esc(run.reason) : ""}</p>`
    : "";

  const rows = (vt.results || [])
    .slice()
    .sort((a, b) => {
      const sc = (r) => (r.status === "error" ? -2 : r.result && r.result.found ? r.result.malicious + r.result.suspicious : -1);
      return sc(b) - sc(a) || a.indicator.localeCompare(b.indicator);
    })
    .map((r) => {
      let verdict;
      if (r.status === "error") verdict = `no answer (${esc(r.error)})`;
      else if (!r.result || !r.result.found) verdict = "not known to VirusTotal";
      else {
        const x = r.result;
        const engines = x.malicious + x.suspicious + x.harmless + x.undetected;
        verdict = `${x.malicious + x.suspicious} of ${engines} engines flagged it`;
        if (x.threat_label) verdict += `<div class="muted small">${esc(x.threat_label)}</div>`;
      }
      return `<tr>
        <td data-label="Hash" class="mono small" style="word-break:break-all">${esc(r.indicator_type)}<br>${esc(r.indicator)}</td>
        <td data-label="VirusTotal answer" class="small">${verdict}</td>
        <td data-label="Seen in events" class="small source-links">${(r.source_event_ids || []).slice(0, 3).map((id) => externalCitation("event", id)).join(" ")}
          ${(r.source_event_ids || []).length > 3 ? `<details id="vt-sources-${esc(r.indicator_type)}-${esc(r.indicator)}"><summary>${r.source_event_ids.length - 3} more supporting events</summary>${r.source_event_ids.slice(3).map((id) => externalCitation("event", id)).join(" ")}</details>` : ""}</td>
        <td data-label="Checked" class="mono small">${esc(fmtTime(r.fetched_at))}</td>
      </tr>`;
    })
    .join("");

  const scrollY = window.scrollY;
  content.innerHTML = `
    <div id="ext-root">
      <h2>Outside services</h2>
      <p class="muted small">Analysis never needs these. What is sent is decided here, per case, and every change and every
        transmission is written to the audit history.</p>

      <div class="external-grid">
      <section class="panel external-card" id="external-policy" aria-labelledby="external-policy-title">
      <h3 id="external-policy-title">Data policy</h3>
      <p class="small muted">Per case. Changing permission does not start a lookup or send facts.</p>
      <div id="egress-options">${options}</div>
      <p id="egress-msg" class="small" role="status"></p>

      </section>
      <section class="panel external-card" id="external-vt" aria-labelledby="external-vt-title">
      <h3 id="external-vt-title">VirusTotal <span class="external-optional">Optional · hashes only</span></h3>
      <p class="small">${integrationSettingsLink("", "Configure VirusTotal in Settings → Integrations")}</p>
      <p class="small">${st.candidates} file hash(es) in this case's events &middot; ${st.already_answered} answered &middot; ${st.pending} waiting.
        </p><details id="vt-allowance" class="external-details"><summary>Quota and estimated duration</summary><p class="small">Free-key allowance: ${st.daily_used} of ${st.daily_limit} used in the last 24 hours, ${st.monthly_used} of ${st.monthly_limit} this calendar month (UTC). Lookups are spaced to stay under
        4 per minute, so ${st.pending} hash(es) take about ${Math.ceil((st.pending * 15.5) / 60)} minute(s).</p></details>
      <p class="small muted">Only the hash is sent: no file, file name, path, host, user or case detail. VirusTotal's answer is an
        outside opinion, not evidence: it is kept apart from the findings and never changes one.
        &ldquo;Not known&rdquo; means VirusTotal has not been given that file, not that it is safe.</p>
      <p>
        <button type="button" class="btn-primary" id="vt-start" ${canStart ? "" : "disabled"}>Look up hashes</button>
        <button type="button" class="btn-secondary" id="vt-cancel" ${running ? "" : "hidden"}>Stop</button>
        ${canStart ? "" : `<span class="muted small" style="margin-left:var(--space-2)">${esc(why)}</span>`}
      </p>
      <p id="vt-msg" class="small" role="status"></p>
      ${runLine}
      ${
        rows
          ? `<div class="table-wrap"><table class="data-table">
              <thead><tr><th>Hash</th><th>VirusTotal answer</th><th>Seen in events</th><th>Checked (${esc(tzLabel())})</th></tr></thead>
              <tbody>${rows}</tbody></table></div>`
          : `<p class="empty">No VirusTotal answers stored for this case.</p>`
      }
      </section>
      <section class="panel external-card" id="external-llm" aria-label="AI summary">
      ${renderNarrativeSection(nv)}
      </section>
      <section class="panel external-card" id="external-review" aria-label="AI Case Review">
      ${renderCaseReviewSection(rv)}
      </section>
      </div>
    </div>`;

  if (refresh) window.scrollTo(0, scrollY);
  const root = document.getElementById("ext-root");
  root.dataset.consentKey = consentKey;
  root.dataset.reviewFingerprint = rv.source_fingerprint || "";
  root.dataset.reviewPrivacyContract = rv.privacy_contract || "";
  const say = (id, text, bad) => {
    const el = document.getElementById(id);
    if (!el) return;
    if (bad) el.innerHTML = `<span class="field-error-box">${esc(text)}</span>`;
    else el.textContent = text;
  };

  document.querySelectorAll('input[name="egress-level"]').forEach((r) =>
    r.addEventListener("change", async () => {
      try {
        await api(`/cases/${caseId}/egress`, { method: "PUT", body: JSON.stringify({ level: r.value }) });
        await renderExternalTab(content, caseId);
      } catch (e) {
        say("egress-msg", e.message || String(e), true);
      }
    })
  );
  const start = document.getElementById("vt-start");
  if (start)
    start.addEventListener("click", async () => {
      start.disabled = true;
      try {
        await api(`/cases/${caseId}/enrich/virustotal`, { method: "POST", body: "{}" });
        await renderExternalTab(content, caseId);
      } catch (e) {
        say("vt-msg", e.message || String(e), true);
        start.disabled = false;
      }
    });
  const cancel = document.getElementById("vt-cancel");
  if (cancel)
    cancel.addEventListener("click", async () => {
      try {
        await api(`/cases/${caseId}/enrich/virustotal/cancel`, { method: "POST", body: "{}" });
        await renderExternalTab(content, caseId);
      } catch (e) {
        say("vt-msg", e.message || String(e), true);
      }
    });

  wireNarrativeSection(content, caseId, nv, say);
  wireCaseReviewSection(content, caseId, rv, say);
  wireExternalCitations(root, caseId);
  restoreExternalState(root, state);
  const batchCard = root.querySelector("#external-review");
  if (batchRoot) {
    batchCard.appendChild(batchRoot);
    batchRoot.updateProvider(rv);
    if(batchFocus && !batchFocus.disabled)batchFocus.focus({preventScroll:true});
  } else mountBatchReview(batchCard, caseId, rv);

  // While a run is going, refresh. Stop as soon as the analyst leaves the
  // page: the root this render created is no longer the one on screen.
  if (running || nRunning || rv.run?.state === "running") {
    setTimeout(() => {
      if (document.getElementById("ext-root") === root) renderExternalTab(content, caseId, true).catch(() => {});
    }, 3000);
  }
}

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
      <thead><tr><th>Time (${esc(tzLabel())})</th><th>Action</th><th>Actor</th><th>Target</th><th>Summary</th></tr></thead>
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

  // A pipeline job outlives the page: if one is queued or running for
  // this case, show it again instead of leaving the analyst guessing.
  resumePipelineIfActive(caseId).catch(() => {});

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
      if (document.getElementById("upload-auto-analyze")?.checked) {
        // Automatic mode runs on the SERVER: the file is sent in
        // resumable chunks, then a persisted pipeline job discovers,
        // imports and analyzes it. Closing the tab, losing the network
        // or restarting the server does not lose the work.
        const uploadId = await uploadResumable(caseId, file, (p) => {
          stage = { phase: "uploading", loaded: p.loaded, total: p.total, lengthComputable: true };
          paint();
        });
        await runServerPipeline(caseId, progress, { upload_id: uploadId });
        return;
      }
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

// ---------------- resumable upload and server pipeline ----------------

// UPLOAD_CHUNK_BYTES is how much of a file travels in one request. Small
// enough that a failed chunk costs little to resend, large enough that
// per-request overhead is negligible on a multi-gigabyte image. The server
// accepts up to 64 MiB per chunk.
const UPLOAD_CHUNK_BYTES = 8 * 1024 * 1024;
const UPLOAD_MAX_RETRIES = 6;

function uploadStorageKey(caseId, file) {
  return `tracefall.upload.${caseId}.${file.name}.${file.size}.${file.lastModified}`;
}

const sleepMs = (ms) => new Promise((r) => setTimeout(r, ms));

// uploadResumable sends file to the server in chunks and returns the
// upload id once every byte is confirmed.
//
// It never reads the whole file: each chunk is a Blob slice. The server's
// "received" count is the only source of truth for where to continue, so
// after a dropped connection, a 409, a server restart or even a page
// reload followed by choosing the SAME file again (same name, size and
// modification time), the upload carries on from the bytes the server
// really holds rather than from what this page believes it sent.
async function uploadResumable(caseId, file, onProgress) {
  const key = uploadStorageKey(caseId, file);
  const base = `/cases/${caseId}/uploads`;
  let session = null;

  const saved = localStorage.getItem(key);
  if (saved) {
    try {
      const s = await api(`${base}/${saved}`);
      if (s.status === "open" && s.size === file.size) session = s;
    } catch (_) {
      /* stale or unknown: start over */
    }
    if (!session) localStorage.removeItem(key);
  }
  if (!session) {
    session = await api(base, { method: "POST", body: JSON.stringify({ filename: file.name, size: file.size }) });
    localStorage.setItem(key, session.upload_id);
  }

  const id = session.upload_id;
  let offset = session.received || 0;
  if (onProgress) onProgress({ loaded: offset, total: file.size });

  let failures = 0;
  while (offset < file.size) {
    const end = Math.min(offset + UPLOAD_CHUNK_BYTES, file.size);
    try {
      const headers = { "Content-Type": "application/octet-stream", "Upload-Offset": String(offset), "X-Tracefall-Client": "dashboard" };
      const t = csrfToken();
      if (t) headers["X-Tracefall-CSRF"] = t;
      const res = await fetch(`/api${base}/${id}`, { method: "PUT", headers, body: file.slice(offset, end) });
      const body = await res.json().catch(() => null);
      if (res.status === 409 && body && typeof body.received === "number") {
        // Our idea of the offset was wrong (a retry that actually landed,
        // or a restart). Adopt the server's.
        offset = body.received;
        if (++failures > UPLOAD_MAX_RETRIES) throw new Error("The server and browser could not agree on the upload offset");
        continue;
      }
      if (!res.ok) {
        if (res.status >= 400 && res.status < 500) throw apiError(res, body);
        throw new Error((body && body.error) || `server error ${res.status}`);
      }
      offset = body.received;
      failures = 0;
      if (onProgress) onProgress({ loaded: offset, total: file.size });
    } catch (e) {
      // A 4xx other than 409 is a refusal, not a glitch: retrying cannot help.
      if (e && e.status >= 400 && e.status < 500) throw e;
      if (++failures > UPLOAD_MAX_RETRIES) throw new Error(`Upload failed after ${UPLOAD_MAX_RETRIES} retries: ${e.message || e}`);
      await sleepMs(Math.min(1000 * 2 ** (failures - 1), 15000)); // retry with backoff
      try {
        // Resynchronize before sending anything again.
        offset = (await api(`${base}/${id}`)).received;
      } catch (_) {
        /* still unreachable: the next loop iteration retries */
      }
    }
  }

  await api(`${base}/${id}/complete`, { method: "POST" });
  localStorage.removeItem(key);
  return id;
}

const PIPELINE_STAGE_LABELS = {
  queued: "Waiting in the queue",
  discover: "Inspecting the upload and cataloging its contents",
  import: "Importing every supported file",
  analyze: "Running deterministic detection and correlation",
};

function pipelineJobKey(caseId) {
  return `tracefall.job.${caseId}`;
}

function renderPipelinePanel(job, note) {
  const label = PIPELINE_STAGE_LABELS[job.stage] || job.stage;
  const prog = job.progress || {};
  const counts =
    prog.files_imported != null
      ? `<p class="small muted">${fmtCount(prog.files_imported || 0)} file(s) imported${prog.files_failed ? `, ${fmtCount(prog.files_failed)} failed to parse` : ""}.</p>`
      : "";
  return `<div class="panel import-progress">
    <h3>${esc(label)}</h3>
    <p class="small muted">This runs on the server. You can close this page; progress is kept and shown again when you return.${job.attempts > 1 ? " The job was resumed after an interruption." : ""}</p>
    <div class="progress-track indeterminate" role="progressbar" aria-valuetext="in progress"><div class="progress-fill"></div></div>
    ${counts}
    ${note ? `<p class="small muted">${esc(note)}</p>` : ""}
    <button type="button" class="secondary small" id="pipeline-cancel-btn" ${job.cancel_requested ? "disabled" : ""}>${job.cancel_requested ? "Cancelling..." : "Cancel"}</button>
  </div>`;
}

function renderPipelineOutcome(job) {
  const r = job.result || {};
  const cont = `<div style="margin-top:12px"><button id="import-continue-btn">Continue to case dashboard</button></div>`;
  if (job.status === "succeeded") {
    const analysis = r.analyzed
      ? `<p class="small">Analysis completed across the case: ${fmtCount(r.findings || 0)} finding(s) and ${fmtCount(r.correlations || 0)} correlation(s). Review the timeline and findings on the case dashboard.</p>`
      : `<p class="small muted">Analysis was not requested for this job.</p>`;
    return `<div class="panel" style="background:var(--bg-panel); margin-top:12px; margin-bottom:0">
      <h3>Import and analysis complete</h3>
      ${analysis}
      ${uploadStep(`${fmtCount(r.files_imported || 0)} file(s) imported`, true)}
      ${r.files_skipped ? uploadStep(`${fmtCount(r.files_skipped)} file(s) skipped`, true) : ""}
      ${r.files_failed ? `<p class="small" style="color:var(--high)">${fmtCount(r.files_failed)} supported file(s) failed to parse -- not the same as unsupported evidence. Per-file reasons are in the Evidence tab.</p>` : ""}
      ${uploadStep(`${fmtCount(r.events || 0)} event(s) in the case`, true)}
      ${job.attempts > 1 ? `<p class="small muted">The job was resumed after an interruption; it continued from its last checkpoint.</p>` : ""}
      ${cont}
    </div>`;
  }
  const title = job.status === "cancelled" ? "Pipeline cancelled" : "Pipeline failed";
  const detail =
    job.status === "cancelled"
      ? "Stopped at the analyst's request. Anything already imported is valid evidence."
      : job.error || "The pipeline failed.";
  return `<div class="panel" style="background:var(--bg-panel); margin-top:12px; margin-bottom:0">
    <h3>${title}</h3>
    <div class="error-box">${esc(detail)}</div>
    <p class="small muted">The uploaded staging file is removed when a job ends; to retry, upload the file again.</p>
    ${cont}
  </div>`;
}

// runServerPipeline starts (or, given an existing job, re-attaches to) a
// server-side ingest job and follows it until it ends.
//
// The job id is kept in localStorage so a reloaded page can find it, but
// the SERVER is the source of truth: resumePipelineIfActive asks it. Poll
// failures are tolerated for a minute, because a restarting server is
// exactly the situation this exists to survive.
async function runServerPipeline(caseId, container, params, existingJob) {
  let job = existingJob || (await api(`/cases/${caseId}/pipeline/jobs`, { method: "POST", body: JSON.stringify(params) }));
  localStorage.setItem(pipelineJobKey(caseId), job.job_id);
  const path = `/cases/${caseId}/pipeline/jobs/${job.job_id}`;

  let note = "";
  let misses = 0;
  for (;;) {
    if (job.status === "succeeded" || job.status === "failed" || job.status === "cancelled") break;
    container.innerHTML = renderPipelinePanel(job, note);
    const cancel = container.querySelector("#pipeline-cancel-btn");
    if (cancel) {
      cancel.addEventListener("click", async () => {
        cancel.disabled = true;
        try {
          await api(`${path}/cancel`, { method: "POST" });
        } catch (e) {
          note = e.message || String(e);
        }
      });
    }
    await sleepMs(1000);
    try {
      job = await api(path);
      misses = 0;
      note = "";
    } catch (e) {
      if (e && e.status >= 400 && e.status < 500 && e.status !== 401) throw e;
      if (++misses > 60) throw new Error("Lost contact with the server while the job was running. The job is kept; reload this page to check on it.");
      note = "Waiting for the server to respond...";
    }
  }

  localStorage.removeItem(pipelineJobKey(caseId));
  container.innerHTML = renderPipelineOutcome(job);
  const cont = container.querySelector("#import-continue-btn");
  if (cont) cont.addEventListener("click", () => window.location.reload());
  return job;
}

// resumePipelineIfActive re-attaches the evidence tab to a job that is
// still queued or running, e.g. after the page was reloaded.
async function resumePipelineIfActive(caseId) {
  const jobs = await api(`/cases/${caseId}/pipeline/jobs`);
  const active = (jobs || []).find((j) => j.status === "queued" || j.status === "running");
  if (!active) {
    localStorage.removeItem(pipelineJobKey(caseId));
    return;
  }
  const host = document.getElementById("upload-progress");
  const form = document.getElementById("add-evidence-form");
  const addBtn = document.getElementById("add-evidence-btn");
  if (!host) return;
  if (form) form.classList.remove("hidden");
  if (addBtn) addBtn.textContent = "Cancel";
  await runServerPipeline(caseId, host, null, active);
}

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
    <td class="ev-priority">${priorityBadge(f.priority, f.priority_reason)}</td>
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
      ${priorityBadge(f.priority, f.priority_reason)}
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
  const tip = f.unsupported_reason || f.note;
  return `<span class="badge status${status === "failed" ? " critical" : ""}"${
    tip ? ` title="${esc(tip)}"` : ""
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
      ${row("Why this priority", f.priority_reason)}
      ${row("Status", EVIDENCE_STATUS_LABELS[evidenceStatusValue(f)] || f.import_status)}
      ${row("Classification", capabilityClassification(f))}
      ${row("Note", f.note)}
      ${row("Size", fmtBytes(f.size_bytes))}
      ${row("SHA-256", f.sha256)}
      ${row("Embedded hash (from container)", f.embedded_hash)}
      ${row("Source collection", collectionLabel(f.collection_id))}
      ${row("Events imported", f.event_count ? String(f.event_count) : "")}
      ${row("Parser coverage", parseCoverageText(f.parse_coverage))}
    </div>
    ${renderCapabilityBoundary(f)}`;
}

// capabilityClassification names WHICH kind of "not supported" this is.
//
// "Known artifact, parser unavailable" and "unrecognized" are different
// investigative facts: the first tells an analyst to reach for another
// tool on a file they now have identified, the second tells them
// Tracefall could not identify it at all. NTFS $MFT is the case that
// matters -- it is recognized, high priority, and unparsed.
function capabilityClassification(f) {
  if (f.supported) return "Supported \u2014 a parser exists for this artifact";
  if (f.recognized) return "Known artifact, parser unavailable";
  return "Unrecognized \u2014 not identified as a known forensic artifact";
}

// renderCapabilityBoundary shows exactly what Tracefall can and cannot
// read for this file's artifact family.
//
// A one-line reason ("Tracefall parses Chromium History and Firefox
// places.sqlite only. Internet Explorer/Edge Legacy WebCacheV01.dat is
// an ESE database, and cookie/cache stores are not parsed.") was
// technically accurate and still left an analyst to work out, from a
// sentence, whether their Chrome history was covered. The support
// boundary is a boundary; showing it as two lists makes it readable at
// a glance instead of parseable on a second reading.
//
// Nothing here asserts support -- both lists come from the capability
// registry, which derives support from the live parser registry.
function renderCapabilityBoundary(f) {
  if (!f.unsupported_reason && !(f.not_parsed || []).length && !(f.parsed_instead || []).length) return "";
  const list = (items) => `<ul class="capability-list">${items.map((i) => `<li>${esc(i)}</li>`).join("")}</ul>`;
  const notParsed = f.not_parsed || [];
  const parsed = f.parsed_instead || [];
  return `
    <div class="capability-boundary">
      ${f.unsupported_reason ? `<p class="muted small ev-detail-reason">${esc(f.unsupported_reason)}</p>` : ""}
      ${
        notParsed.length
          ? `<div class="capability-group">
               <div class="capability-heading not-supported">Not currently supported</div>
               ${list(notParsed)}
             </div>`
          : ""
      }
      ${
        parsed.length
          ? `<div class="capability-group">
               <div class="capability-heading supported">Supported in this family</div>
               ${list(parsed)}
             </div>`
          : ""
      }
    </div>`;
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
      <p class="muted small coverage-note">
        <strong>Supported + Unsupported = ${fmtCount(cov.discovered)} discovered.</strong>
        The second group breaks down the ${fmtCount(cov.supported)} <em>supported</em> files only &mdash; an unsupported
        file is never a candidate for import, so it appears in the first group and not the second.
        Adding across the two groups double-counts.
      </p>
      <div class="coverage-totals">
        <div class="coverage-stat coverage-total" title="Every file found inside this source or image. Both breakdowns beside it account for all of them, separately.">
          <div class="n">${fmtCount(cov.discovered)}</div><div class="l">Discovered</div></div>

        <div class="coverage-axis" role="group" aria-label="By capability">
          <div class="coverage-axis-label">Can Tracefall parse it?</div>
          <div class="coverage-axis-stats">
            <div class="coverage-stat" title="Files whose format Tracefall has a parser for. Supported is NOT the same as imported -- a supported file still has to be selected and parsed.">
              <div class="n ok">${fmtCount(cov.supported)}</div><div class="l">Supported</div></div>
            <div class="coverage-stat" title="Files Tracefall has no parser for. They stay in the collection's inventory: evidence you may need to examine another way, not broken files.">
              <div class="n muted">${fmtCount(cov.unsupported)}</div><div class="l">Unsupported</div></div>
          </div>
        </div>

        <div class="coverage-axis" role="group" aria-label="By import state">
          <div class="coverage-axis-label">What happened to the supported files?</div>
          <div class="coverage-axis-stats">
            <div class="coverage-stat" title="Supported files selected and successfully parsed into this case. Only these contribute events to the analysis.">
              <div class="n ok">${fmtCount(cov.imported)}</div><div class="l">Imported</div></div>
            <div class="coverage-stat" title="Supported files not yet selected for import. Unsupported files are not counted here -- they cannot be imported at all.">
              <div class="n muted">${fmtCount(cov.not_imported)}</div><div class="l">Not imported</div></div>
            <div class="coverage-stat" title="Files identical by SHA-256 to another file already in this collection, so they were not imported twice.">
              <div class="n muted">${fmtCount(cov.duplicates)}</div><div class="l">Duplicates</div></div>
            <div class="coverage-stat" title="Supported files that WERE selected for import but whose parser failed. Not the same as unsupported: Tracefall recognized the artifact and could not read this particular file.">
              <div class="n ${cov.parse_failed ? "bad" : "muted"}">${fmtCount(cov.parse_failed)}</div><div class="l">Parse failed</div></div>
          </div>
        </div>
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
    <td class="small">${priorityBadge(b.priority, b.priority_reason)}</td>
    <td class="small num">${fmtCount(b.files)}</td>
    <td class="small num">${b.supported ? fmtCount(b.supported_files) : "0"}</td>
    <td class="small muted ev-note">${esc(b.reason || b.note || "")}${
      b.priority_reason
        ? `<div class="ev-note-why">${esc(PRIORITY_LABELS[b.priority] || b.priority || "Unknown")}: ${esc(b.priority_reason)}</div>`
        : ""
    }</td>
  </tr>`;
}

// priorityBadge renders forensic triage priority. Deliberately styled
// apart from finding severity: they are different judgements and must
// never be read as the same thing. A HIGH-priority artifact Tracefall
// cannot parse is normal and worth saying out loud.
// A row without a priority still gets a badge. An empty cell reads as
// "no opinion", which is indistinguishable from "nobody looked" -- and
// the point of the priority column is that every artifact carries a
// forensic judgement, whether or not Tracefall can parse it.
//
// why, when present, becomes the badge's tooltip: the rationale behind
// the level, available wherever the badge appears.
function priorityBadge(p, why) {
  const level = p || "unknown";
  const tip = why ? ` title="${esc(why)}"` : "";
  return `<span class="badge prio prio-${esc(level)}"${tip}>${esc(PRIORITY_LABELS[level] || level)}</span>`;
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

  pagerFor(prefix, { scope: collectionId, sizes: [10, 25, 50, 100, 250], defaultSize: 10 });

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
    updateRecommendedCount(page);
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

  // updateRecommendedCount keeps the button's number equal to the set it
  // would actually select, as the filter changes.
  function updateRecommendedCount(page) {
    const el = container.querySelector("#ev-recommended-count");
    if (el) el.textContent = fmtCount(page.recommended_total || 0);
    const btn = container.querySelector("#ev-select-recommended");
    // With nothing recommended under this filter the button could only
    // clear the selection, which is not what it says it does.
    if (btn) btn.disabled = (page.recommended_total || 0) === 0;
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
      // Scoped to the CURRENT filter, and REPLACING the selection.
      //
      // It previously added to whatever was already selected, using an
      // unfiltered query: with 242 files already selected, "Select
      // recommended (240)" added 240 mostly-overlapping ids and left 242
      // selected -- a number describing neither the action nor its
      // result. "Recommended" is the recommended subset of the MATCHING
      // files, so selecting it must yield exactly that set.
      const q = queryParams();
      q.set("recommended", "true");
      const res = await api(`/cases/${caseId}/evidence/${collectionId}/files/ids?${q}`);
      selected.clear();
      (res.ids || []).forEach((id) => selected.add(id));
      bulk = { signature: filterSignature(), count: selected.size, mode: "recommended" };
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

  const jobId = started.job_id;

  // Cancellation is requested at most once per click but is safe to
  // request repeatedly -- the server treats a second cancel as a no-op
  // (see Service.CancelImport). The local flag exists only to flip the
  // button into "Cancelling..." immediately, so the analyst gets
  // feedback in the same frame rather than waiting for the next poll.
  let cancelRequested = false;
  async function requestCancel(btn) {
    cancelRequested = true;
    if (btn) {
      btn.disabled = true;
      btn.textContent = "Cancelling...";
    }
    try {
      await api(`/cases/${caseId}/import-jobs/${jobId}/cancel`, { method: "POST" });
    } catch (e) {
      // A failed cancel must not leave the UI claiming it worked. The
      // import is still running, so re-enable the button and say so.
      cancelRequested = false;
      if (btn) {
        btn.disabled = false;
        btn.textContent = "Cancel import";
      }
      const err = progressHost.querySelector(".import-cancel-error");
      if (err) err.textContent = "Could not cancel the import: " + (e.message || e);
    }
  }

  // paint re-renders progress and re-attaches the Cancel handler, since
  // the panel's markup is replaced on every poll.
  function paint(p) {
    progressHost.innerHTML = renderImportProgress(p, cancelRequested);
    const btn = progressHost.querySelector("#import-cancel-btn");
    if (btn) btn.addEventListener("click", () => requestCancel(btn));
  }

  paint({ phase: "preparing", files_total: ids.length, percent: 0 });

  // Poll at a human cadence: fast enough to feel live, slow enough not to
  // spend the browser's time on requests instead of rendering.
  for (;;) {
    await sleep(400);
    const p = await api(`/cases/${caseId}/import-jobs/${jobId}`);
    paint(p);
    if (!p.done) continue;

    if (p.phase === "failed") {
      throw new Error(p.error || "the import failed");
    }
    // Cancelled is a normal terminal state, not a failure: the files
    // that were imported are valid evidence and the result describes
    // exactly what happened.
    progressHost.innerHTML = "";
    container.querySelector("#import-result").innerHTML = renderImportResults(p.result || {}, p.phase === "cancelled");
    const cont = container.querySelector("#import-continue-btn");
    if (cont) cont.addEventListener("click", () => window.location.reload());
    wireParseFailureToggle(container, (p.result || {}).parse_failures);
    return p;
  }
}

const IMPORT_PHASE_LABELS = {
  queued: "Waiting for another import to finish",
  preparing: "Preparing",
  parsing: "Parsing files",
  enriching: "Resolving hosts",
  persisting: "Saving evidence",
  finalizing: "Finalizing",
  complete: "Complete",
  failed: "Failed",
  cancelled: "Cancelled",
};

function renderImportProgress(p, cancelRequested) {
  const pct = typeof p.percent === "number" ? p.percent : -1;
  const indeterminate = pct < 0;
  return `
    <div class="panel import-progress" style="background:var(--bg-panel); margin-top:var(--space-3); margin-bottom:0">
      <div class="row between">
        <h3>Importing evidence</h3>
        ${
          p.done
            ? ""
            : `<button type="button" class="danger small" id="import-cancel-btn"
                       ${cancelRequested || p.cancel_requested ? "disabled" : ""}>${
                cancelRequested || p.cancel_requested ? "Cancelling..." : "Cancel import"
              }</button>`
        }
      </div>
      <div class="small">${esc(IMPORT_PHASE_LABELS[p.phase] || p.phase || "Working")}</div>
      ${
        cancelRequested || p.cancel_requested
          ? `<div class="small muted">Stopping at the next safe point. Files already imported stay imported; files not yet processed are left untouched.</div>`
          : ""
      }
      <div class="small critical import-cancel-error"></div>
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

// wireParseFailureToggle makes the parse-error list expandable, and
// pages it.
//
// A large import can fail on hundreds of files (233 in the case that
// prompted this). Rendering all of them put hundreds of rows into the
// DOM at once and made the panel unreadable -- every one still has to be
// INSPECTABLE, which is why they are paged rather than truncated.
//
// The rows are built on demand from the failures already in memory: the
// import response carried them, so paging costs no request.
function wireParseFailureToggle(container, failures) {
  const btn = container.querySelector("#view-parse-errors-btn");
  const panel = container.querySelector("#parse-errors-panel");
  if (!btn || !panel) return;

  const all = failures || [];
  pagerFor(PARSE_ERROR_PAGER, { scope: "parse-errors", sizes: [10, 25, 50, 100], defaultSize: 10 });

  // Identical failures are summarized rather than repeated.
  //
  // A single unsupported format produces one row per file: 233
  // MAM-compressed Prefetch files yield 233 rows of the same sentence,
  // which buries the fact that there is really only ONE problem. The
  // groups say what went wrong and how many files it affected; the
  // per-file list stays available inside each group, so nothing is lost.
  const groups = groupParseFailures(all);

  const render = () => {
    const page = paginate(PARSE_ERROR_PAGER, all);
    panel.innerHTML = `
      ${renderParseFailureGroups(groups)}
      <div class="muted small" style="margin-top:var(--space-3)">Every affected file</div>
      <div class="table-wrap"><table class="data-table">
        <thead><tr><th>File</th><th>Artifact type</th><th>State</th><th>Stage</th><th>Problem</th><th>Events kept</th></tr></thead>
        <tbody>${page.items.map(parseFailureRow).join("")}</tbody>
      </table></div>
      ${renderPager(PARSE_ERROR_PAGER, page, { noun: "parse errors", label: "Parse error pagination" })}`;
  };

  wirePager(PARSE_ERROR_PAGER, panel, render);
  btn.addEventListener("click", () => {
    panel.hidden = !panel.hidden;
    btn.textContent = panel.hidden ? "View parse errors" : "Hide parse errors";
    // Rendered on first open rather than up front, so an import whose
    // errors are never inspected never builds the rows at all.
    if (!panel.hidden && !panel.dataset.rendered) {
      panel.dataset.rendered = "1";
      render();
    }
  });
}

// PARSE_CATEGORY_LABELS name the STATE a file ended in, so the six that
// matter are never rendered alike.
//
// The distinction is the point. "This artifact is not one Tracefall
// reads", "this artifact is fine and its compression is not implemented",
// "this file was catalogued as the wrong thing", "this file is damaged"
// and "this file is empty" lead to four different next steps and one
// non-step, and reporting them all as "parse error" told an analyst
// nothing about which they were looking at.
const PARSE_CATEGORY_LABELS = {
  unsupported_format: "Unsupported artifact",
  unsupported_compression: "Unsupported compression",
  misclassified: "Misclassified",
  corrupt_or_truncated: "Corrupt or truncated",
  empty: "Empty file",
  limit_exceeded: "Safety limit reached",
  unreadable: "Could not be read",
  optional_reader_unavailable: "Optional reader not available",
  internal_error: "Internal error",
};

// PARSE_CATEGORY_NOTE says, in one line, what the state means for the
// EVIDENCE -- which is the question an analyst is actually asking.
const PARSE_CATEGORY_NOTE = {
  unsupported_format: "The file is intact. Tracefall does not read this artifact.",
  unsupported_compression: "The artifact is present and supported; its container's compression is not implemented.",
  misclassified: "The file is intact. It is not the artifact it was cataloged as.",
  corrupt_or_truncated: "The evidence itself is damaged.",
  empty: "The file has no content. Nothing to parse, and nothing is wrong with it.",
  limit_exceeded: "The file exceeded a safety ceiling and was not parsed.",
  unreadable: "The file could not be read from storage.",
  optional_reader_unavailable: "The file is intact but was NOT analyzed: an optional reader is not set up on this server. Treat it as not examined, not as empty.",
  internal_error: "Tracefall failed unexpectedly on this file.",
};

function parseCategoryLabel(c) {
  return PARSE_CATEGORY_LABELS[c] || c || "Unknown";
}

// groupParseFailures collapses identical failures into one entry each.
//
// Keyed on (artifact type, stage, message): two files that failed the
// same way for the same reason are one problem reported twice, and an
// analyst deciding what to do needs the problem, not the repetition.
// Ordered most-affected-first so the biggest gap reads first.
function groupParseFailures(failures) {
  const byKey = new Map();
  for (const f of failures) {
    const key = `${f.artifact_type}\u0000${f.stage}\u0000${f.message}`;
    const g = byKey.get(key);
    if (g) {
      g.count++;
      g.files.push(f.filename || f.path);
      continue;
    }
    byKey.set(key, {
      artifactType: f.artifact_type,
      stage: f.stage,
      message: f.message,
      category: f.category,
      count: 1,
      files: [f.filename || f.path],
    });
  }
  return [...byKey.values()].sort((a, b) => b.count - a.count);
}

function renderParseFailureGroups(groups) {
  if (!groups.length) return "";
  // One group is not a summary of anything -- it would just restate the
  // table below it.
  if (groups.length === 1 && groups[0].count === 1) return "";

  return `
    <div class="muted small">What went wrong</div>
    <div class="parse-error-groups">
      ${groups
        .map(
          (g) => `<details class="parse-error-group">
            <summary>
              <strong>${fmtCount(g.count)} file(s)</strong>
              <span class="small">${esc(artifactLabel(g.artifactType))}</span>
              <span class="parse-category parse-category-${esc(g.category || "unknown")}">${esc(parseCategoryLabel(g.category))}</span>
              <span class="muted small">&middot; ${esc(PARSE_STAGE_LABELS[g.stage] || g.stage)}</span>
            </summary>
            <p class="small parse-error-note">${esc(PARSE_CATEGORY_NOTE[g.category] || "")}</p>
            <p class="small parse-error-message">${esc(g.message)}</p>
            <div class="muted small parse-error-files">${g.files.slice(0, 200).map(esc).join(", ")}${
              g.files.length > 200 ? ` and ${fmtCount(g.files.length - 200)} more` : ""
            }</div>
          </details>`
        )
        .join("")}
    </div>`;
}

// PARSE_ERROR_PAGER is scoped to the parse-error panel, so paging it
// never disturbs the evidence pager on the same screen.
const PARSE_ERROR_PAGER = "pe";

function parseFailureRow(f) {
  return `<tr>
    <td class="mono small" title="${esc(f.path)}">${esc(f.filename || f.path)}</td>
    <td class="small">${esc(artifactLabel(f.artifact_type))}</td>
    <td class="small"><span class="parse-category parse-category-${esc(f.category || "unknown")}">${esc(parseCategoryLabel(f.category))}</span></td>
    <td class="small">${esc(PARSE_STAGE_LABELS[f.stage] || f.stage)}</td>
    <td class="small">${esc(f.message)}</td>
    <td class="small">${f.partial_events ? "partial" : "none"}</td>
  </tr>`;
}

// renderParseFailures lists the files that were selected and supported
// but could not be parsed. This is deliberately separate from
// "unsupported": an unsupported file is one Tracefall was never able to
// read, while a parse failure is evidence that SHOULD have been readable
// and was not -- which is a finding about the evidence itself.
function renderParseFailures(failures) {
  if (!failures || !failures.length) return "";
  // The panel starts EMPTY: its rows are built by wireParseFailureToggle
  // when it is first opened, one page at a time. The count is stated up
  // front so the scale of the problem is visible without expanding.
  return `
    <div style="margin-top:var(--space-3)">
      <button type="button" class="secondary small" id="view-parse-errors-btn"
              aria-expanded="false" aria-controls="parse-errors-panel">View parse errors</button>
      <div id="parse-errors-panel" hidden style="margin-top:var(--space-2)"></div>
    </div>`;
}

const PARSE_STAGE_LABELS = {
  extract: "Extracting from container",
  parse: "Parsing",
};

// renderImportSkips breaks the skipped files down BY REASON.
//
// "N file(s) skipped (already imported/unsupported/duplicate)" told the
// analyst a number and then three possible explanations for it, leaving
// them to guess which applied. The reasons are genuinely different --
// "no parser available" is a capability gap, "duplicate content" is a
// deduplication decision, "already imported" is a no-op -- and the
// server already reports which one applied per file, so there is no
// reason to collapse them.
function renderImportSkips(skips) {
  const byReason = new Map();
  for (const s of skips) {
    const reason = s.reason || "skipped";
    byReason.set(reason, (byReason.get(reason) || 0) + 1);
  }
  const rows = Array.from(byReason.entries())
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([reason, n]) => `<li>${fmtCount(n)} &times; ${esc(reason)}</li>`)
    .join("");
  return `
    <div class="small muted">
      ${fmtCount(skips.length)} file(s) skipped &mdash; not imported, and not a parse failure:
      <ul class="import-skip-reasons">${rows}</ul>
    </div>`;
}

// renderImportResults shows what the import endpoint actually parsed --
// how many files were imported, how many events (new vs. already known
// from another collection), plus a button to continue into the case
// dashboard.
function renderImportResults(res, cancelled, analysisOutcome = null) {
  const wasCancelled = cancelled || res.cancelled;
  return `
    <div class="panel" style="background:var(--bg-panel); margin-top:12px; margin-bottom:0">
      <h3>${wasCancelled ? "Import cancelled" : analysisOutcome ? "Import and analysis complete" : "Import complete"}</h3>
      ${
        analysisOutcome
          ? analysisOutcome.error
            ? `<p class="small critical">Import finished, but automatic analysis failed: ${esc(analysisOutcome.error)}. The imported evidence is retained; run analysis from the case dashboard.</p>`
            : `<p class="small">Analysis completed across the case: ${fmtCount(analysisOutcome.findings)} finding(s) and ${fmtCount(analysisOutcome.correlations)} correlation(s). Review the full timeline and findings on the case dashboard.</p>`
          : ""
      }
      ${
        wasCancelled
          ? `<p class="small muted import-cancel-note">
               Stopped at the analyst's request. The files imported before the stop are
               valid evidence. Nothing else was written, so the remaining files are exactly
               as they were and can simply be imported again.
             </p>`
          : ""
      }
      ${uploadStep(`${(res.imported || []).length} file(s) imported`, true)}
      ${
        wasCancelled
          ? uploadStep(
              `${fmtCount(res.unprocessed || 0)} file(s) not processed \u2014 still available to import, not a parse failure`,
              true
            )
          : ""
      }
      ${uploadStep(`${fmtCount(res.event_count)} event(s) parsed (${fmtCount(res.new_event_count)} new, ${fmtCount(res.duplicate_event_count)} already known from another collection)`, true)}
      ${res.skipped && res.skipped.length ? renderImportSkips(res.skipped) : ""}
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

// ---------------- Forensic timeline tab (Phase 14) ----------------
//
// The analyst-facing view of NORMALIZED EVENTS -- the layer between the
// evidence that was collected and the findings a detection drew from it.
// It is deliberately not the Findings page: most events here will never
// be cited by any detection, and being able to search those is the whole
// point. An event with no finding is an ordinary observation, not a
// negative result.
//
// # Why this queries the server
//
// It previously fetched the entire timeline, plus every finding and
// every correlation, and filtered the lot in JavaScript. That is
// workable for a few thousand events and untenable for the evidence
// Tracefall now parses: one $MFT alone can contribute hundreds of
// thousands. The browser held the whole case in memory and re-scanned it
// on every keystroke.
//
// So filtering, searching, ordering and paging all happen in the
// database (see store/eventquery.go), and the browser receives one page.
// The filter vocabularies come from the server too, derived from the
// events the case actually holds -- so a dropdown never offers a choice
// that cannot return anything.
//
// # Timezone
//
// Date bounds are entered as wall-clock readings in the DISPLAY
// timezone (readDateTime / wallTimeToInstant) and sent as absolute
// instants. The server never has to guess what the analyst meant, and
// the window queried is the same window they are reading on screen.

// TIMELINE_SEARCH_FIELDS are the forensic fields a search term can be
// aimed at. The empty value is "any field": the documented free-text
// surface (see docs/forensic-search.md), which is what an analyst who
// does not yet know where a string lives should be using.
//
// Each named option maps to the API's own parameter of the same name, so
// what the analyst picks is exactly what the server searches.
const TIMELINE_SEARCH_FIELDS = [
  { value: "", label: "Any field" },
  { value: "filename", label: "Filename" },
  { value: "path", label: "Path" },
  { value: "url", label: "URL" },
  { value: "domain", label: "Domain / host" },
  { value: "ip", label: "IP address" },
  { value: "command_line", label: "Command line" },
  { value: "original_path", label: "Deleted original path" },
];

async function renderTimelineTab(content, caseId, collections) {
  content.innerHTML = `<p class="empty">Loading timeline...</p>`;

  let facets;
  try {
    facets = await api(`/cases/${caseId}/events/facets`);
  } catch (e) {
    content.innerHTML = errorBox(e);
    return;
  }

  if (!facets.total_events) {
    content.innerHTML = `<p class="empty">No events yet. Add evidence and import it first.</p>
      <p class="muted small">Some artifacts are evidence without being timeline events -- an NTFS $LogFile
      records no timestamps, and a browser cache index is a container rather than a cached response. Those
      appear under Evidence with what was read from them.</p>`;
    return;
  }

  // ATT&CK options come from the findings this case has, which is a
  // small bounded list -- unlike events, it is safe to fetch whole.
  let techniqueIds = [];
  try {
    const findings = await api(`/cases/${caseId}/findings`);
    techniqueIds = Array.from(new Set((findings || []).flatMap((f) => f.attack_techniques || []))).sort();
  } catch {
    techniqueIds = [];
  }

  content.innerHTML = `
    <div class="row between tl-head">
      <h2 id="timeline-heading">Forensic timeline</h2>
      <div class="tl-meta small muted" id="tl-meta"></div>
    </div>
    <p class="muted small tl-explain">Normalized events parsed from this case's evidence. An event is an
      observation, not a detection &mdash; most events are never cited by a finding.</p>
    <div id="tl-filters"></div>
    <div id="tl-body" aria-live="polite"></div>
    <div id="tl-pager"></div>`;

  const prefix = "tl";
  pagerFor(prefix, { scope: caseId, sizes: [10, 25, 50, 100], defaultSize: 10 });

  document.getElementById("tl-filters").innerHTML = renderFilterBar(prefix, {
    scope: caseId,
    search: "Search events...",
    searchFields: TIMELINE_SEARCH_FIELDS,
    // A request per keystroke is not free here, unlike the old in-memory
    // filtering this replaced.
    searchDebounceMs: 300,
    severity: true,
    artifact: (facets.artifact_types || []).map((o) => ({ value: o.value, label: o.label })),
    eventType: (facets.event_types || []).map((o) => ({ value: o.value, label: o.label })),
    host: filterOptions(facets.hosts || []),
    user: filterOptions(facets.users || []),
    process: filterOptions(facets.processes || []),
    technique: filterOptions(techniqueIds),
    collection: filterOptions(facets.collections || [], (id) => collectionLabel(id)),
    timeRange: true,
  });

  let inFlight = 0;

  // timelineQuery translates the filter bar into the API's parameters.
  // Every value is sent as a separate parameter so each is individually
  // escaped, and repeated parameters form the OR-set the server expects.
  function timelineQuery() {
    const f = readFilterBar(prefix);
    const st = pagerStates.get(prefix);
    const q = new URLSearchParams();

    const term = (f.qRaw || "").trim();
    if (term) q.set(f.qField || "q", term);

    const addAll = (param, set) => {
      if (!set) return;
      set.forEach((v) => q.append(param, v));
    };
    addAll("artifact_type", f.artifact);
    addAll("event_type", f.eventType);
    addAll("host", f.host);
    addAll("user", f.user);
    addAll("process", f.process);
    addAll("collection", f.collection);
    addAll("severity", f.severity);
    addAll("technique", f.technique);

    // Absolute instants, already resolved out of the display timezone.
    if (f.from) q.set("from", f.from.toISOString());
    if (f.to) q.set("to", f.to.toISOString());

    q.set("page", String(st.page));
    q.set("page_size", String(st.pageSize));
    return q;
  }

  async function load() {
    const token = ++inFlight;
    const body = document.getElementById("tl-body");
    body.setAttribute("aria-busy", "true");
    let page;
    try {
      page = await api(`/cases/${caseId}/events?${timelineQuery()}`);
    } catch (e) {
      // A slower earlier request must never overwrite a newer answer.
      if (token !== inFlight) return;
      body.removeAttribute("aria-busy");
      body.innerHTML = errorBox(e);
      return;
    }
    if (token !== inFlight) return;
    body.removeAttribute("aria-busy");
    renderTimelinePage(caseId, page);
  }

  wireFilterBar(prefix, () => {
    // Any change to the result set returns to page 1: staying on page 7
    // of a two-page result shows an empty screen that reads as "nothing
    // matched".
    resetPage(prefix);
    load();
  });
  wirePager(prefix, content, load);
  load();
}

// renderTimelinePage draws one server page of the forensic timeline.
function renderTimelinePage(caseId, page) {
  const body = document.getElementById("tl-body");
  const pagerHost = document.getElementById("tl-pager");
  const meta = document.getElementById("tl-meta");

  if (meta) {
    // The zone every timestamp below is rendered in, stated on the view
    // itself. A timeline whose zone the reader has to remember is a
    // timeline that gets misread.
    const range = page.range && page.range.from
      ? ` &middot; ${esc(fmtRangeSummary(page.range))}`
      : "";
    meta.innerHTML = `Times shown in <strong>${esc(tzLabel())}</strong>${range}`;
  }

  // The note goes ABOVE the results, whether or not there are any: the
  // case an analyst most needs it in is the one where a partial date
  // returned nothing and looked like a bug.
  const scopeNote = renderSearchScopeNote((readFilterBar("tl") || {}).qRaw);

  if (!page.items.length) {
    // Two different situations, two different sentences. "No events
    // match" and "this case has no events" send an analyst to entirely
    // different next steps, and a bare empty table says neither.
    body.innerHTML = scopeNote + (page.filtered
      ? `<p class="empty">No events match the current filters.
           This case holds ${fmtCount(page.total_in_case)} event(s) in total.</p>`
      : `<p class="empty">No events in this case yet.</p>`);
    pagerHost.innerHTML = "";
    return;
  }

  body.innerHTML = scopeNote + `
    <div class="table-wrap"><table class="data-table wide">
      <thead><tr>
        <th>Time (${esc(tzLabel())})</th><th>Artifact</th><th>Event type</th><th>Host</th><th>User</th>
        <th>Process</th><th>Detail</th><th>Finding</th><th>ATT&amp;CK</th><th>Collection</th>
      </tr></thead>
      <tbody>
        ${page.items.map((e) => timelineRow(e)).join("")}
      </tbody>
    </table></div>`;

  pagerHost.innerHTML = renderPager("tl", {
    page: page.page,
    pageSize: page.page_size,
    total: page.total,
    totalPages: page.total_pages,
    from: page.total === 0 ? 0 : (page.page - 1) * page.page_size + 1,
    to: (page.page - 1) * page.page_size + page.items.length,
  }, { noun: "events", label: "Timeline pagination" });

  wireDetailCells(body);
  wireTimelineRowClicks(caseId, body);
}

// partialDateTerm reports when a search term looks like a DATE but is
// not a complete one, so the timeline can say what it actually did.
//
// This exists because of a specific, repeated confusion. Typing "2021"
// into the search box returns results -- on one real case, 43 of them --
// and they look like time filtering. They are not: the term matched the
// literal string "2021" inside file paths, URLs and page titles. Typing
// the more precise "2021-04" then returns NOTHING, because no field
// happens to contain that string, which reads as the search being
// broken when it is doing exactly what a text search does.
//
// A COMPLETE date or timestamp is handled as a moment (see the server's
// searchTermMoment) and needs no warning. Only the partial forms do.
function partialDateTerm(term) {
  const t = (term || "").trim();
  if (!t) return "";
  // Complete forms are resolved as moments; nothing to explain.
  if (/^\d{4}-\d{2}-\d{2}([ T]\d{2}:\d{2}(:\d{2})?)?$/.test(t)) return "";
  // A bare year, a year-month, or a truncated date.
  if (/^\d{4}$/.test(t) || /^\d{4}-\d{1,2}$/.test(t) || /^\d{4}-\d{1,2}-\d{1}$/.test(t)) return t;
  return "";
}

// renderSearchScopeNote explains a text-only date-ish search, and points
// at the control that does filter by time.
function renderSearchScopeNote(term) {
  const partial = partialDateTerm(term);
  if (!partial) return "";
  return `<p class="tl-hint" role="note">
    <strong>${esc(partial)}</strong> is being searched as <strong>text</strong>, not as a time.
    Any results below contain that string in a path, URL, title or other field &mdash; they are
    not selected by when the event happened. To filter by time, use
    <strong>Date range</strong>, which supports a full date and time down to the second.
  </p>`;
}

// fmtRangeSummary states the window actually queried, in the display
// zone, so the analyst can check the conversion rather than trust it.
function fmtRangeSummary(range) {
  const from = range.from ? fmtTime(range.from) : "";
  const to = range.to ? fmtTime(range.to) : "";
  if (from && to) return `${from} to ${to}`;
  return from ? `from ${from}` : `to ${to}`;
}

// timelineRow renders one server-supplied event.
//
// The finding, ATT&CK and chain columns are driven by the REFERENCES the
// server attached (e.findings / e.correlations), not by a client-side
// join against every finding in the case. An empty findings list renders
// as an empty cell, never as a dash or a zero -- there is nothing absent
// to report.
function timelineRow(e) {
  const findings = e.findings || [];
  const sev = maxSeverity(findings.map((f) => f.severity));
  const techniques = Array.from(new Set(findings.flatMap((f) => f.attack_techniques || []))).sort();
  const hasChain = (e.correlations || []).some((c) => c.correlation_type === "activity_chain");
  return `<tr class="timeline-row" data-event="${esc(e.id)}" tabindex="0">
    <td class="mono small nowrap">${eventTimeCell(e)}</td>
    <td class="small nowrap">${esc(e.artifact_label || e.artifact_type)}</td>
    <td class="small nowrap">${esc(e.event_type)}${hasChain ? ' <span class="badge conf chain-badge" title="Part of a reconstructed activity chain">chain</span>' : ""}</td>
    <td class="mono small nowrap">${esc(e.host)}</td>
    <td class="mono small nowrap">${esc(e.user)}</td>
    <td class="mono small nowrap">${esc(e.process_name)}</td>
    <td class="mono small detail-td">${detailCell(eventDetailValue(e))}</td>
    <td class="small nowrap">${sev ? severityBadge(sev) : ""}</td>
    <td class="small">${techChips(techniques)}</td>
    <td class="small nowrap">${collectionBadge(e.collection_id)}</td>
  </tr>
  <tr class="raw-row" data-for="${esc(e.id)}" style="display:none">
    <td colspan="10"><div class="evidence-box"></div></td>
  </tr>`;
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
  body.innerHTML = scopeNote + `
    <div class="table-wrap"><table class="data-table wide">
      <thead><tr>
        <th>Time (${esc(tzLabel())})</th><th>Category</th><th>Type</th><th>Host</th><th>User</th>
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
    // An account/credential record gets a labelled panel above the raw
    // record: it is the ONE place the NTLM hash is shown, and the place
    // it can be copied from exactly.
    const panel =
      credentialPanel(prov.event) ||
      shellBagPanel(prov.event) ||
      filezillaPanel(prov.event) ||
      imageGeoPanel(prov.event);
    if (panel) {
      box.innerHTML = panel + `<pre class="provenance-text"></pre>`;
      box.querySelector(".provenance-text").textContent = renderProvenanceText(prov);
      wireDetailCells(box);
    } else {
      box.textContent = renderProvenanceText(prov);
    }
    box.dataset.loaded = "1";
  } catch (e) {
    box.textContent = "Error loading evidence: " + (e.message || e);
  }
}

// credentialPanel renders the account/credential fields of a Windows SAM
// event, and returns "" for every other event.
//
// This is the ONLY view that shows an NTLM hash. It is not in the
// timeline row, not in the Detail column, and not in any search index --
// see internal/store/eventquery.go's named-key allowlist. It is shown
// truncated with a reveal control, and Copy always carries the complete
// 32 characters whatever the display is showing.
//
// The wording is as deliberate as the placement. An NTLM hash is a
// PASSWORD HASH: not a password, not reversible into one, and not
// something Tracefall attempts to crack. An analyst reading this panel
// under time pressure must not be able to come away with the wrong idea
// about what they are looking at.
// hashStateLabel turns a non-decoded hash status into what the analyst
// should read, and says whether the underlying material exists.
//
// The distinction the whole function exists for: "no hash is stored"
// and "the hash is stored and encrypted" must never render the same.
function hashStateLabel(x) {
  switch (x.ntlm_hash_status) {
    case "encrypted_system_hive_missing":
      return { value: "Encrypted \u2014 SYSTEM hive required", encrypted: true };
    case "encrypted_system_hive_unusable":
      return { value: "Encrypted \u2014 SYSTEM hive could not be used", encrypted: true };
    case "encrypted_data_unavailable":
      return { value: "Encrypted \u2014 hash material could not be read", encrypted: true };
    case "unsupported":
      return { value: "Encrypted \u2014 unsupported format", encrypted: true };
    case "not_stored":
      return { value: "No hash stored for this account", encrypted: false };
    default:
      return { value: "Not available (" + (x.ntlm_hash_status || "unknown") + ")", encrypted: false };
  }
}

// shellBagPanel shows the reconstructed navigation chain for a ShellBags
// event, and returns "" for every other event.
//
// A ShellBags entry means little on its own: what it establishes is
// where a folder SAT, which is a statement about its ancestors. The
// Detail column shows the reconstructed path; this panel shows the chain
// that produced it, level by level, so an analyst can see which levels
// are recorded names and which are gaps -- and read a source folder off
// the evidence instead of inferring it from a leaf.
function shellBagPanel(ev) {
  const x = (ev && ev.extra) || {};
  if (!ev || ev.event_type !== "shellbag_navigation") return "";

  const path = x.reconstructed_path || "";
  const levels = path ? path.split("\\") : [];
  const complete = x.path_complete !== "false";

  const chain = levels
    .map((seg, i) => {
      const undecoded = seg === "(undecoded)";
      const last = i === levels.length - 1;
      return `<li class="sb-level${undecoded ? " sb-undecoded" : ""}${last ? " sb-leaf" : ""}">
        <span class="sb-depth">${i}</span>
        <span class="sb-name">${esc(undecoded ? "not decoded" : seg)}</span>
      </li>`;
    })
    .join("");

  const rows = [];
  const add = (label, value, opts) => {
    if (!value) return;
    rows.push(`<div class="cred-field"><span class="cred-label">${esc(label)}</span>
      <span class="cred-value">${detailCell(value, opts)}</span></div>`);
  };
  add("Reconstructed path", path);
  add("Parent folder", x.parent_name);
  add("Parent path", x.parent_path);
  add("BagMRU node", x.shellbag_node);
  add("Parent BagMRU key", x.parent_registry_key);
  add("Shell item type", x.shell_item_kind + (x.shell_item_type_hex ? ` (${x.shell_item_type_hex})` : ""));
  if (x.shell_item_name_source) add("Name source", x.shell_item_name_source);
  if (x.shell_item_recovered_strings) add("Strings in this item", x.shell_item_recovered_strings);
  if (x.registry_last_write) add("BagMRU last write", x.registry_last_write);

  return `<div class="cred-panel sb-panel">
    <h4>Explorer navigation &mdash; reconstructed hierarchy</h4>
    <ol class="sb-chain">${chain}</ol>
    ${
      complete
        ? ""
        : `<p class="cred-note sb-warn">${esc(x.path_limitation || "")}</p>`
    }
    ${rows.join("")}
    <p class="cred-note">${esc(x.evidence_meaning || "")}</p>
    <p class="cred-note">${esc(x.timestamp_meaning || "")}</p>
  </div>`;
}

// filezillaPanel renders a FileZilla entry as the connection record it
// is, with the address question -- "is there an IPv4 here?" -- answered
// explicitly either way rather than left to be inferred from a missing
// field.
//
// There is no password row and there is no way to add one: the value is
// never carried out of internal/filezilla, so the event this renders
// does not contain it.
function filezillaPanel(ev) {
  const x = (ev && ev.extra) || {};
  if (!ev || ev.event_type !== "filezilla_server_entry") return "";

  const rows = [];
  const add = (label, value, opts) => {
    if (value === undefined || value === null || value === "") return;
    rows.push(`<div class="cred-field"><span class="cred-label">${esc(label)}</span>
      <span class="cred-value">${detailCell(value, opts)}</span></div>`);
  };

  if (x.server_ipv4) add("Server (IPv4)", x.server_ipv4);
  else if (x.server_ipv6) add("Server (IPv6)", x.server_ipv6);
  else if (x.server_hostname) add("Server (hostname)", x.server_hostname);
  else add("Server", x.server_host);

  add("Address type", x.server_address_type);
  if (x.ipv4_availability) add("IPv4 availability", x.ipv4_availability);
  add("Protocol", x.protocol + (x.protocol_code ? ` (code ${x.protocol_code})` : ""));
  if (x.protocol_note) add("Protocol note", x.protocol_note);
  add("Port", x.server_port || x.server_port_raw);
  add("Username", x.server_username);
  add("Account", x.server_account);
  add("Site name", x.site_name);
  add("Site comment", x.site_comment);
  add("Remote directory", x.remote_directory);
  add("Local directory", x.local_directory);
  add("Logon type", x.logon_type || x.logon_type_code);
  add("Transfer mode", x.transfer_mode);
  add("Stored password", x.password_present === "true" ? "present - not extracted" : "none stored");
  if (x.password_storage) add("Password storage", x.password_storage);
  add("Source", x.source_file);
  add("FileZilla version", x.filezilla_version);
  if (x.parse_warnings) add("Parse warnings", x.parse_warnings);

  return `<div class="cred-panel fz-panel">
    <h4>FileZilla server entry</h4>
    ${rows.join("")}
    ${x.password_present === "true" ? `<p class="cred-note">${esc(x.password_handling || "")}</p>` : ""}
    <p class="cred-note">${esc(x.evidence_meaning || "")}</p>
    <p class="cred-note">${esc(x.timestamp_basis || x.timestamp_meaning || "")}</p>
  </div>`;
}

// imageGeoPanel renders an image's embedded location with OBSERVED and
// DERIVED kept visually apart.
//
// The split is the whole point of the panel. The raw sexagesimal
// components and the hemisphere letters are what the file holds; the
// decimal coordinate is arithmetic on them; the country is a lookup
// Tracefall performed against a bundled dataset and is not in the image
// at all. Presenting the country beside the coordinate without saying
// which of them the image actually recorded is the misreading this
// layout exists to prevent.
function imageGeoPanel(ev) {
  const x = (ev && ev.extra) || {};
  if (!ev) return "";
  const isGPS = ev.event_type === "image_gps_recorded";
  if (!isGPS && ev.event_type !== "image_metadata_recorded") return "";

  const rows = [];
  const add = (label, value, opts) => {
    if (value === undefined || value === null || value === "") return;
    rows.push(`<div class="cred-field"><span class="cred-label">${esc(label)}</span>
      <span class="cred-value">${detailCell(value, opts)}</span></div>`);
  };

  const section = (title) =>
    rows.push(`<div class="img-section">${esc(title)}</div>`);

  section("Observed - stored in the file");
  add("Image", x.image_file);
  add("Format", x.image_format);
  add("Dimensions", x.image_dimensions);
  if (x.dimensions_disagree) add("Dimensions note", x.dimensions_disagree);
  add("Make", x.camera_make);
  add("Model", x.camera_model);
  add("Writing software", x.writing_software);
  add("Body serial", x.camera_body_serial);
  add("Lens", x.lens_model);

  for (const tag of ["datetimeoriginal", "datetimedigitized", "datetime"]) {
    const v = x["exif_" + tag];
    if (!v) continue;
    add(`EXIF ${tag === "datetime" ? "ModifyDate" : tag === "datetimeoriginal" ? "DateTimeOriginal" : "DateTimeDigitized"}`, v);
    add("  meaning", x["exif_" + tag + "_meaning"]);
  }
  if (x.exif_present === "false") add("EXIF", x.exif_note);

  if (isGPS) {
    add("GPS latitude (as stored)", x.gps_latitude_raw);
    add("GPS longitude (as stored)", x.gps_longitude_raw);
    add("EXIF components", x.gps_components_observed);
    if (x.gps_altitude) add("Altitude", x.gps_altitude);
    if (x.gps_time_raw) add("GPS fix time", `${x.gps_date_raw || ""} ${x.gps_time_raw}`.trim());

    section("Derived - computed by Tracefall, not stored in the file");
    add("Decimal coordinate", x.gps_coordinates);
    add("Derivation", x.gps_decimal_derivation);
    if (x.gps_precision) add("Coordinate precision", x.gps_precision);
    if (x.gps_precision_note) add("Precision note", x.gps_precision_note);
    add("Country", x.country || "unavailable");
    if (x.country_iso_a2) add("Country code", `${x.country_iso_a2}${x.country_iso_a3 ? " / " + x.country_iso_a3 : ""}`);
    if (x.country_status) add("Country status", x.country_status);
    if (x.country_confidence) add("Country confidence", x.country_confidence);
    if (x.country_confidence_note) add("Confidence note", x.country_confidence_note);
    if (x.country_nearest_land) add("Nearest land", x.country_nearest_land);
    add("Geolocation method", x.geolocation_method);
    add("Dataset", x.geolocation_dataset);
    if (x.geolocation_dataset_source) add("Dataset source", x.geolocation_dataset_source);
    if (x.geolocation_dataset_license) add("Dataset license", x.geolocation_dataset_license);
  }

  if (x.parse_warnings) add("Parse warnings", x.parse_warnings);

  // Phase 21: the reverse of the map's "View timeline event". Both
  // directions address the SAME event -- there is no second record for
  // the map to point at.
  const onMap = isGPS && currentCaseId()
    ? `<p class="img-map-link"><a class="btn-secondary" href="#/cases/${esc(currentCaseId())}/geomap"
         data-geo-focus="${esc(ev.id || "")}">View on map</a></p>`
    : "";

  return `<div class="cred-panel img-panel">
    <h4>${isGPS ? "Image location &mdash; EXIF GPS" : "Image metadata &mdash; EXIF"}</h4>
    ${onMap}
    ${rows.join("")}
    ${isGPS ? `<p class="cred-note">${esc(x.country_derivation || "")}</p>` : ""}
    ${isGPS ? `<p class="cred-note">${esc(x.gps_observation_note || "")}</p>` : ""}
    <p class="cred-note">${esc(x.evidence_meaning || "")}</p>
    <p class="cred-note">${esc(x.timestamp_meaning || "")}</p>
  </div>`;
}

function credentialPanel(ev) {
  const x = (ev && ev.extra) || {};
  if (!ev || ev.event_type !== "sam_local_account") return "";

  const rows = [];
  const add = (label, value, opts) => {
    if (value === undefined || value === null || value === "") return;
    rows.push(`<div class="cred-field"><span class="cred-label">${esc(label)}</span>
      <span class="cred-value">${detailCell(value, opts)}</span></div>`);
  };

  add("Account", x.account_name);
  add("RID", x.rid);
  if (x.account_full_name) add("Full name", x.account_full_name);
  add("Scope", x.account_scope);
  if (x.account_control) add("Account control", x.account_control);
  if (x.account_disabled) add("Disabled", x.account_disabled);

  if (x.ntlm_hash) {
    // truncateAt is short on purpose: the whole value is one click away
    // and one click to the clipboard, and a hash does not need to sit
    // fully rendered on screen to be usable evidence.
    rows.push(`<div class="cred-field cred-hash"><span class="cred-label">NTLM hash</span>
      <span class="cred-value">${detailCell(x.ntlm_hash, { truncateAt: 8, revealLabel: "Reveal hash" })}</span></div>`);
    add("Hash status", "decoded");
    rows.push(`<p class="cred-note">${esc(x.ntlm_hash_meaning || "")}</p>`);
  } else {
    // WORDING MATTERS HERE. An encrypted hash is not a missing one.
    //
    // "not available" told an analyst the same thing for an account
    // with no password and for an account whose hash is sitting in the
    // evidence needing one more file to read. Those are different
    // findings and they lead to different next steps, so they get
    // different words -- and the encrypted cases say plainly that the
    // hash material EXISTS.
    const state = hashStateLabel(x);
    rows.push(`<div class="cred-field cred-hash"><span class="cred-label">NTLM hash</span>
      <span class="cred-value ${state.encrypted ? "cred-encrypted" : "cred-unavailable"}">${esc(state.value)}</span></div>`);
    add("Hash status", x.ntlm_hash_status || "unknown");
    rows.push(`<p class="cred-note">${esc(x.ntlm_hash_unavailable_reason || "")}</p>`);
  }

  // The account's own timestamps, each labelled with what it is. None of
  // them is this event's time -- the event has none.
  const times = [
    ["Last logon", x.last_logon],
    ["Password last set", x.password_last_set],
    ["Last incorrect password", x.last_incorrect_password],
    ["Account expires", x.account_expires],
  ].filter(([, v]) => v);
  if (times.length) {
    rows.push(`<div class="cred-times">` +
      times.map(([l, v]) => `<div class="cred-field"><span class="cred-label">${esc(l)}</span>
        <span class="cred-value">${esc(v)}</span></div>`).join("") +
      `</div>`);
  }

  // The boot key is the SECOND piece of evidence a decoded hash stands
  // on. Named on the event so provenance is complete: "decoded" without
  // saying decoded USING WHAT is half a record.
  if (x.boot_key_source) {
    add("Boot key source", x.boot_key_source + (x.boot_key_control_set ? ` (${x.boot_key_control_set})` : ""));
  } else if (x.boot_key_status && x.boot_key_status !== "derived") {
    add("Boot key source", "none available");
  }

  return `<div class="cred-panel">
    <h4>Windows local account &mdash; credential evidence</h4>
    ${rows.join("")}
    <p class="cred-note">${esc(x.evidence_meaning || "")}</p>
    <p class="cred-note">${esc(x.timestamp_basis || "")}</p>
  </div>`;
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

// fetchEventsById returns {id: event} for the events the ids name. The findings
// and correlations tabs used to download the whole timeline to look these up,
// which on a 363,000 event case was 482 MB for the browser and about 2 GB of
// memory on the server, every time the tab opened. This asks only for what is
// cited, in requests of at most 1000 ids, four at a time.
async function fetchEventsById(caseId, ids) {
  const unique = [...new Set((ids || []).filter(Boolean))];
  const CHUNK = 1000;
  const PARALLEL = 4;
  const chunks = [];
  for (let i = 0; i < unique.length; i += CHUNK) chunks.push(unique.slice(i, i + CHUNK));
  const byId = {};
  let next = 0;
  async function worker() {
    while (next < chunks.length) {
      const chunk = chunks[next++];
      const events = await api(`/cases/${caseId}/events/lookup`, {
        method: "POST",
        body: JSON.stringify({ ids: chunk }),
      });
      for (const e of events) byId[e.id] = e;
    }
  }
  await Promise.all(Array.from({ length: Math.min(PARALLEL, chunks.length) }, worker));
  return byId;
}

async function renderFindingsTab(content, caseId) {
  content.innerHTML = `<p class="empty">Loading findings...</p>`;
  const [findings, correlations, statuses] = await Promise.all([
    api(`/cases/${caseId}/findings`),
    api(`/cases/${caseId}/correlations`).catch(() => []),
    api(`/cases/${caseId}/analyst-status`).catch(() => []),
  ]);
  const statusIdx = buildStatusIndex(statuses);
  if (findings.length === 0) {
    content.innerHTML = `<p class="empty">No findings yet. Run analysis first.</p>`;
    return;
  }
  const eventsById = await fetchEventsById(caseId, findings.flatMap((f) => f.supporting_event_ids || []))
    .catch(() => ({}));
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
  pagerFor("fd", { scope: caseId, sizes: [10, 25, 50, 100], defaultSize: 10 });

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

// integrityTablePagerHost names the container the per-file integrity
// table is paged into, scoped per collection so two expanded collections
// page independently.
function integrityTablePagerHost(collectionID) {
  return `integrity-files-${collectionID}`;
}

// mountIntegrityTable pages the per-file integrity table from the server.
//
// The table lists EVERY file in the collection -- discovered as well as
// imported -- because its purpose is the recorded SHA-256 of each file,
// which exists whether or not the file was parsed. On a disk image that is
// tens of thousands of rows. The collection detail does not carry the file
// list (on a 45,618-file image it was 37.8 MB), so each page is requested
// from /evidence/{id}/files, which is the same paged endpoint the Evidence
// tab already uses.
function mountIntegrityTable(root, caseId, collectionID, total) {
  const host = root.querySelector(`#${CSS.escape(integrityTablePagerHost(collectionID))}`);
  if (!host || !total) return;

  const prefix = `intg${collectionID}`;
  pagerFor(prefix, { scope: collectionID, sizes: [10, 25, 50, 100, 250], defaultSize: 10 });

  // Only the newest page request may paint. A click made while an earlier
  // page is still loading must not be overwritten when that page arrives.
  let latest = 0;
  const render = async () => {
    const st = pagerStates.get(prefix);
    const ticket = ++latest;
    let res;
    try {
      res = await api(`/cases/${caseId}/evidence/${collectionID}/files?page=${st.page}&page_size=${st.pageSize}`);
    } catch (err) {
      if (ticket === latest) {
        host.innerHTML = `<p class="empty">Could not load this page of files: ${esc(err.message || String(err))}</p>`;
      }
      return;
    }
    if (ticket !== latest) return;
    st.page = res.page; // the server clamps an out-of-range page
    const items = res.items || [];
    const start = (res.page - 1) * res.page_size;
    const page = {
      items,
      page: res.page,
      pageSize: res.page_size,
      total: res.total,
      totalPages: res.total_pages,
      from: res.total === 0 ? 0 : start + 1,
      to: start + items.length,
    };
    host.innerHTML = `
      <div class="table-wrap"><table class="data-table">
        <thead><tr><th>Filename</th><th>SHA-256</th><th>Size</th><th>Discovered</th><th>Imported</th><th>Status</th><th>Events</th></tr></thead>
        <tbody>${page.items.map(integrityFileRow).join("")}</tbody>
      </table></div>
      ${renderPager(prefix, page, { noun: "files", label: "Per-file integrity pagination" })}`;
  };
  wirePager(prefix, host, render);
  render();
}

function integrityFileRow(sf) {
  return `<tr>
    <td class="mono small">${esc(sf.original_filename)}</td>
    <td class="mono small">${sha256Cell(sf, "Unknown")}</td>
    <td class="small">${fmtBytes(sf.size_bytes)}</td>
    <td class="small">${esc(fmtTime(sf.discovered_at))}</td>
    <td class="small">${sf.imported_at ? esc(fmtTime(sf.imported_at)) : "-"}</td>
    <td class="small">${esc(sf.import_status)}</td>
    <td class="small">${sf.event_count || "-"}</td>
  </tr>`;
}

// wireIntegrityHash makes the copy and expand controls work. Copying
// goes through the SAME copyText helper the Detail column uses, so
// there is one clipboard implementation to reason about and both
// controls behave identically over plain HTTP on a LAN -- which is
// exactly how Tracefall is normally reached.
//
// The hash keeps one extra step the Detail column does not need: if the
// clipboard is unreachable entirely, the digest is expanded in place
// and SELECTED, so Ctrl+C still yields the complete value. That is a
// fallback for a failure, not a claim of success -- the button says so.
function wireIntegrityHash(root) {
  root.querySelectorAll(".copy-hash").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      e.stopPropagation();
      const ok = await copyText(btn.dataset.hash);
      if (!ok) {
        // Rather than tell the investigator to press Ctrl+C with
        // nothing selected, expand the hash in place and select it.
        const code = setHashExpanded(btn.parentElement, true);
        const range = document.createRange();
        range.selectNodeContents(code);
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
      }
      const original = btn.textContent;
      btn.textContent = ok ? "Copied" : "Copy failed - press Ctrl+C";
      btn.classList.toggle("copy-ok", ok);
      btn.classList.toggle("copy-failed", !ok);
      setTimeout(() => {
        btn.textContent = original;
        btn.classList.remove("copy-ok", "copy-failed");
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

// ---------------- Provenance views (Phase 11) ----------------
//
// These answer "what evidence is this standing on?" by walking
// relationships that already existed -- finding -> supporting events ->
// source files -> collection -> evidence hash. Nothing here invents a
// link: an unresolved step is shown as unresolved.

async function mountFindingProvenance(detail, caseId, findingId) {
  const host = document.createElement("div");
  host.className = "provenance";
  host.innerHTML = `<h4>Evidence provenance</h4><p class="muted small">Loading provenance...</p>`;
  detail.appendChild(host);
  try {
    const p = await api(`/cases/${caseId}/findings/${findingId}/provenance`);
    host.innerHTML = `<h4>Evidence provenance</h4>${renderFindingProvenance(p)}`;
    wireIntegrityHash(host);
  } catch (e) {
    host.innerHTML = `<h4>Evidence provenance</h4>${errorBox(e)}`;
  }
}

function renderFindingProvenance(p) {
  // The gap between referenced and resolved events is itself
  // provenance: it means evidence this finding rests on has since been
  // deleted, which an analyst must not have to infer from a smaller
  // number than they expected.
  const missing = p.supporting_event_count - p.resolved_event_count;
  const eventLine =
    `${fmtCount(p.resolved_event_count)} supporting event(s)` +
    (missing > 0 ? ` <span class="prov-badge-deleted">${fmtCount(missing)} no longer present</span>` : "") +
    (p.timestampless_event_count
      ? ` <span class="muted small">&middot; ${fmtCount(p.timestampless_event_count)} with no timestamp</span>`
      : "");

  const files = p.source_files.length
    ? p.source_files
        .map(
          (f) => `<div class="prov-file">
            <span class="mono small ${f.deleted ? "prov-deleted" : ""}" title="${esc(f.path)}">${esc(f.original_filename || f.path)}</span>
            ${f.deleted ? `<span class="prov-badge-deleted">Deleted</span>` : ""}
            ${f.parser ? `<span class="muted small">${esc(f.parser)}</span>` : ""}
          </div>`
        )
        .join("")
    : `<span class="muted small">No source file could be resolved for this finding's events.</span>`;

  const collections = p.collections.length
    ? p.collections.map(renderProvenanceCollection).join("")
    : `<span class="muted small">No evidence collection could be resolved.</span>`;

  return `
    <div class="prov-chain">
      <div class="prov-step">
        <div class="prov-label">Finding</div>
        <div class="prov-value">${esc(p.title)} <span class="muted small mono">${esc(p.rule_id)}</span></div>
      </div>
      <div class="prov-step">
        <div class="prov-label">Supporting events</div>
        <div class="prov-value">${eventLine}</div>
      </div>
      <div class="prov-step">
        <div class="prov-label">Source files (${fmtCount(p.source_files.length)})</div>
        <div class="prov-value">${files}</div>
      </div>
      <div class="prov-step">
        <div class="prov-label">Evidence</div>
        <div class="prov-value">${collections}</div>
      </div>
      <div class="prov-step">
        <div class="prov-label">Produced by</div>
        <div class="prov-value">${renderAnalysisRunRef(p)}</div>
      </div>
    </div>`;
}

// renderAnalysisRunRef states which analysis produced a finding, or says
// plainly that the finding predates run tracking. It never invents a
// run: "legacy" is the correct answer, not a placeholder id.
function renderAnalysisRunRef(p) {
  if (!p.analysis_run_available || !p.analysis_run) {
    return `<span class="prov-badge-legacy">Legacy</span> <span class="muted small">This finding predates analysis-run tracking, so the run that produced it was never recorded.</span>`;
  }
  const r = p.analysis_run;
  return `<span class="mono small">${esc(r.analysis_run_id)}</span>
    <div class="muted small">${esc(fmtTime(r.completed_at || r.started_at))}${r.tool_version ? " &middot; " + esc(r.tool_version) : ""}</div>`;
}

// evidenceDisplayName names an evidence object for a provenance chain.
//
// For an upload this is the filename. For a local-path collection
// Collection.OriginalFilename is the absolute path the ANALYST typed,
// which Tracefall has always displayed verbatim in the evidence list --
// but a full server path is noise in a provenance chain and unreadable
// at narrow widths, so the chain shows the last segment with the whole
// value on hover. Nothing is hidden that the evidence list does not
// already show in full.
function evidenceDisplayName(c) {
  const raw = c.original_filename || "";
  if (!raw) return collectionLabel(c.collection_id);
  const parts = raw.split(/[\\/]/).filter(Boolean);
  return parts.length ? parts[parts.length - 1] : raw;
}

function renderProvenanceCollection(c) {
  return `<div class="prov-collection">
    <div class="small" title="${esc(c.original_filename || "")}">${esc(evidenceDisplayName(c))}
      <span class="muted small">&middot; ${esc(SOURCE_TYPE_LABELS[c.source_type] || c.source_type)}</span></div>
    <div class="muted small">Imported ${esc(fmtTime(c.imported_at))}</div>
    ${
      c.integrity_recorded
        ? `<div class="muted small" style="margin-top:4px">Evidence integrity (SHA-512)</div>${integrityHashCell(c.integrity_sha512)}`
        : `<div class="muted small">${esc(LEGACY_UNAVAILABLE)}: no integrity digest was recorded for this collection.</div>`
    }
  </div>`;
}

// toggleSourceFileProvenance shows what one source file produced.
//
// The counts come from the server, which derives them by counting real
// relationships at read time. They are deliberately NOT read from a
// stored counter: a counter drifts from the truth after evidence
// deletion or re-analysis, and a provenance figure that can be wrong is
// worse than one that costs a query.
async function toggleSourceFileProvenance(caseId, btn) {
  const host = btn.closest(".evidence-file-row").querySelector(".evidence-file-provenance");
  if (!host.hidden) {
    host.hidden = true;
    btn.setAttribute("aria-expanded", "false");
    btn.textContent = "Provenance";
    return;
  }
  host.hidden = false;
  btn.setAttribute("aria-expanded", "true");
  btn.textContent = "Hide";
  if (host.dataset.loaded) return;

  host.innerHTML = `<p class="muted small">Loading provenance...</p>`;
  try {
    const p = await api(`/cases/${caseId}/sources/${btn.dataset.id}/provenance`);
    host.innerHTML = renderSourceFileProvenance(p);
    host.dataset.loaded = "1";
    wireIntegrityHash(host);
  } catch (e) {
    host.innerHTML = errorBox(e);
  }
}

function renderSourceFileProvenance(p) {
  const sf = p.source_file;
  const row = (label, value) =>
    value ? `<div class="prov-step"><div class="prov-label">${label}</div><div class="prov-value">${value}</div></div>` : "";

  return `<div class="prov-chain">
    ${row("File", `<span class="mono small ${sf.deleted ? "prov-deleted" : ""}">${esc(sf.original_filename)}</span>
       ${sf.deleted ? `<span class="prov-badge-deleted">Deleted</span>` : ""}`)}
    ${row("Path in evidence", `<span class="mono small">${esc(sf.path)}</span>`)}
    ${row("Artifact type", esc(artifactLabel(sf.artifact_type)))}
    ${row("Parser", sf.parser ? `<span class="mono small">${esc(sf.parser)}</span>` : `<span class="muted small">${esc(LEGACY_UNAVAILABLE)}</span>`)}
    ${row("Status", esc(SOURCE_FILE_STATUS_LABELS[sf.import_status] || sf.import_status))}
    ${row("Parser coverage", esc(parseCoverageText(sf.parse_coverage)))}
    ${row("Imported", sf.imported_at ? esc(fmtTime(sf.imported_at)) : `<span class="muted small">Not recorded</span>`)}
    ${sf.deleted ? row("Deleted", esc(fmtTime(sf.deleted_at))) : ""}
    ${row("File hash (SHA-256)", sf.sha256 ? `<span class="mono small">${esc(sf.sha256)}</span>` : `<span class="muted small">Not recorded</span>`)}
    ${row("Produced", `Used by <strong>${fmtCount(p.event_count)}</strong> event(s) &middot; contributed to <strong>${fmtCount(p.finding_count)}</strong> finding(s)
       ${noEventNote(sf, p.event_count)}`)}
    ${p.collection ? row("Evidence", renderProvenanceCollection(p.collection)) : ""}
  </div>
  ${renderSourceFileRecords(p)}`;
}

// noEventNote explains a successfully imported file that contributed no
// timeline events, so "0 event(s)" is never read as a silent failure.
// A file that FAILED carries the parse-error status instead, and says so
// on its own row -- this note is only for the honest case where the
// artifact genuinely records nothing datable (an NTFS $LogFile, a
// Chromium Simple Cache entry, whose format holds no timestamp). The
// evidence itself is still stored and still hashed; what it lacks is a
// point on a clock.
function parseCoverageText(c) {
 if (!c) return "Coverage not recorded";
 return `read=${c.records_read} mapped=${c.mapped} unmapped=${c.unmapped} undated=${c.undated} records_failed=${c.records_failed} chunks_failed=${c.chunks_failed} capped=${!!c.limit_reached}${(c.notes || []).length ? "; " + c.notes.join("; ") : ""}`;
}

function noEventNote(sf, eventCount) {
  if (eventCount !== 0 || sf.import_status !== "imported") return "";
  if (sf.parse_coverage) return `<div class="muted small">Parsed successfully; ${esc(parseCoverageText(sf.parse_coverage))}. Unmapped records were not analyzed; zero mapped events is not evidence of no activity.</div>`;
  return `<div class="muted small" style="margin-top:4px">Parsed successfully. No normalized events were produced. Coverage was not recorded; inspect the source and any structured records before concluding that no activity occurred.</div>`;
}

// renderSourceFileRecords shows what a file parsed to when it produced
// records with NO event.
//
// A record attached to an event is already reachable by opening that
// event. A record with none -- an NTFS $LogFile's transaction metadata,
// a browser-cache container, a Recycle Bin $R file's recovered content
// and hash -- had nowhere to be seen, so a real forensic record was
// stored and never shown. Rendered only in that case, so a file with
// events is not given a second, redundant copy of what its rows already
// say.
function renderSourceFileRecords(p) {
  const records = p.raw_evidence || [];
  if (!records.length || p.event_count > 0) return "";
  return `
    <details class="prov-records">
      <summary class="muted small" style="cursor:pointer">
        Parsed record${records.length === 1 ? "" : "s"} (${fmtCount(records.length)})${
          p.raw_evidence_truncated ? " -- showing the first " + fmtCount(records.length) : ""
        }
      </summary>
      ${records
        .map(
          (r) => `<div class="prov-record">
            <div class="muted small mono">${esc(r.source_reference || "")}</div>
            <div class="evidence-box">${esc(prettyJSON(r.raw))}</div>
          </div>`
        )
        .join("")}
    </details>`;
}

// prettyJSON re-indents a stored record for reading, and returns it
// untouched when it is not JSON -- a raw CSV line is evidence too.
function prettyJSON(raw) {
  try {
    return JSON.stringify(JSON.parse(raw), null, 2);
  } catch {
    return raw;
  }
}

// LEGACY_UNAVAILABLE is the one wording used everywhere a record
// predates the provenance being captured, so the distinction between
// "unknown" and "absent" reads the same on every screen.
const LEGACY_UNAVAILABLE = "Legacy - provenance unavailable";

// renderDeleteCollectionControl offers collection-level deletion.
//
// Hidden entirely when the case's evidence is locked. That is a
// convenience, not the control: the server refuses the request on a
// contained or closed case regardless of what the page renders.
function renderDeleteCollectionControl(cd) {
  if (!lifecycleState.evidenceMutable) return "";
  return `
    <div class="collection-danger">
      <button type="button" class="danger small delete-collection-btn"
              data-collection="${esc(cd.collection_id)}">Delete collection</button>
      <span class="muted small">Removes this collection and everything discovered inside it.</span>
    </div>`;
}

// wireDeleteCollection confirms, then deletes.
//
// The confirmation states what will actually go -- the collection's
// name, what it holds, and the consequence for the analysis -- because
// this is the most destructive action in the application and a generic
// "are you sure?" gives an analyst nothing to check their intent
// against.
function wireDeleteCollection(caseId, cd, root) {
  const btn = root.querySelector(".delete-collection-btn");
  if (!btn) return;

  btn.addEventListener("click", async (e) => {
    e.stopPropagation(); // never toggle the card open/closed

    const name = cd.original_filename || collectionLabel(cd.collection_id);
    // The same modal and the same warning as deleting individual files:
    // deleting a collection IS deleting evidence, and the consequence
    // for the analysis is identical.
    const ok = await confirmDestructive({
      title: "Delete Evidence?",
      message: EVIDENCE_DELETION_WARNING,
      details:
        `Collection "${name}" (${SOURCE_TYPE_LABELS[cd.source_type] || cd.source_type}): ` +
        `${fmtCount(cd.file_count)} discovered file(s), ${fmtCount(cd.imported_file_count)} imported, ` +
        `${fmtCount(cd.parsed_event_count)} event(s) parsed. Events also observed in another ` +
        `collection are kept and re-attributed to that collection.`,
      confirmLabel: "Delete Evidence",
    });
    if (!ok) return;

    // Deletion is SYNCHRONOUS: the request returns only once every row
    // and the collection's directory are gone, so "Deleting..." is held
    // until the response arrives and nothing here claims completion
    // early. A pending collection of several thousand discovered files
    // is the slow case -- every one of them is a catalog row.
    const original = btn.textContent;
    const host = root.querySelector(".collection-danger");
    const previousError = host ? host.querySelector(".error-box") : null;
    if (previousError) previousError.remove(); // don't stack failures

    btn.disabled = true;
    btn.textContent = "Deleting...";

    let deleted = false;
    try {
      await api(`/cases/${caseId}/collections/${cd.collection_id}`, { method: "DELETE" });
      deleted = true;
    } catch (err) {
      if (host) host.insertAdjacentHTML("beforeend", errorBox(err));
    } finally {
      // Restored on BOTH paths, and in a finally so it cannot be skipped.
      //
      // On success the card is about to be replaced by the re-render, so
      // this is invisible. It is here for the case that is not: if the
      // response arrives and anything afterwards throws -- a failed
      // re-render, a transport error surfacing late -- the control would
      // otherwise sit on "Deleting..." for the rest of the session,
      // looking like a deletion that never finished when in fact it had.
      btn.disabled = false;
      btn.textContent = original;
    }

    if (deleted) {
      // A full re-render is right here: the collection is gone, so its
      // card, the case counters and the stale-analysis banner all have
      // to be rebuilt from the server's new answer rather than patched.
      renderedCaseId = null;
      route();
    }
  });
}

// ---------------- Integrity verification (Phase 11) ----------------
//
// Phase 10A RECORDED a SHA-512 of each collection's original evidence.
// This is where an investigator re-checks it: has the evidence changed
// since Tracefall first saw it?
//
// The recorded digest is a historical fact and is never rewritten by a
// check. What the panel shows is a comparison, and it distinguishes
// three outcomes rather than two -- verified, mismatch, and "could not
// be checked" -- because not knowing is not the same as knowing the
// evidence changed.

function renderIntegrityVerifyPanel(caseId, cd) {
  if (!cd.integrity_sha512) {
    // Nothing to verify against. Say why, rather than offering a button
    // that could only ever report a non-answer.
    return `<div class="integrity-verify">
      <p class="muted small">Integrity verification is unavailable for this collection: it was ingested before Tracefall recorded integrity digests, so there is no original digest to compare against.</p>
    </div>`;
  }
  return `<div class="integrity-verify">
    <button type="button" class="secondary small verify-integrity-btn"
            aria-describedby="verify-result-${esc(cd.collection_id)}">Verify Integrity</button>
    <div class="verify-result" id="verify-result-${esc(cd.collection_id)}" role="status" aria-live="polite"></div>
  </div>`;
}

function wireIntegrityVerify(caseId, collectionId, root) {
  const btn = root.querySelector(".verify-integrity-btn");
  if (!btn) return;
  const result = root.querySelector(".verify-result");

  btn.addEventListener("click", async (e) => {
    // The panel lives inside the collection card, whose own click
    // handler toggles the card open/closed.
    e.stopPropagation();
    const original = btn.textContent;
    btn.disabled = true;
    btn.textContent = "Verifying...";
    // Real work, not a fake bar: re-hashing a large evidence object
    // genuinely takes time, and the honest thing to show is that it is
    // in progress, not an invented percentage.
    result.innerHTML = `<p class="muted small">Recomputing SHA-512 over the original evidence...</p>`;
    try {
      const res = await api(`/cases/${caseId}/evidence/${collectionId}/verify-integrity`, { method: "POST" });
      result.innerHTML = renderIntegrityResult(res);
      wireIntegrityHash(result);
    } catch (err) {
      result.innerHTML = errorBox(err);
    } finally {
      btn.disabled = false;
      btn.textContent = original;
    }
  });
}

// renderIntegrityResult states the outcome in words first, then the
// evidence for it.
//
// The status is carried by text and an icon, never by colour alone --
// a red/green swap would be the only signal for a reader who cannot
// distinguish them, on a result that matters.
function renderIntegrityResult(res) {
  const when = `<div class="muted small">Checked ${esc(fmtTime(res.verified_at))} &middot; ${esc(res.tool_version || "")}${
    res.duration_ms ? ` &middot; ${fmtCount(res.duration_ms)} ms` : ""
  }</div>`;

  if (res.status === "verified") {
    return `<div class="verify-box verify-ok">
      <div class="verify-head"><span aria-hidden="true">&#10003;</span> <strong>INTEGRITY VERIFIED</strong></div>
      <div class="small">The evidence hashes exactly as it did when Tracefall received it.</div>
      <div class="muted small">Covered: ${esc(res.evidence_kind || "evidence")}</div>
      ${integrityHashCell(res.recorded_sha512)}
      ${when}
    </div>`;
  }
  if (res.status === "mismatch") {
    return `<div class="verify-box verify-bad">
      <div class="verify-head"><span aria-hidden="true">&#9888;</span> <strong>INTEGRITY MISMATCH</strong></div>
      <div class="small">The evidence does not hash as it did when Tracefall received it. It has changed on disk since ingestion.</div>
      <div class="muted small">Covered: ${esc(res.evidence_kind || "evidence")}</div>
      <div class="verify-digest">
        <div class="muted small">Recorded at ingestion</div>
        ${integrityHashCell(res.recorded_sha512)}
      </div>
      <div class="verify-digest">
        <div class="muted small">Computed now</div>
        ${integrityHashCell(res.computed_sha512)}
      </div>
      ${when}
    </div>`;
  }
  return `<div class="verify-box verify-unknown">
    <div class="verify-head"><span aria-hidden="true">&#9432;</span> <strong>NOT VERIFIED</strong></div>
    <div class="small">${esc(res.reason || "This collection's integrity could not be checked.")}</div>
    ${res.recorded_sha512 ? `<div class="verify-digest"><div class="muted small">Recorded at ingestion (unchanged)</div>${integrityHashCell(res.recorded_sha512)}</div>` : ""}
    ${when}
  </div>`;
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
    // Provenance is loaded separately and appended, so a provenance
    // failure can never blank the supporting-evidence table the analyst
    // came here to read.
    mountFindingProvenance(detail, caseId, findingId);
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
  pagerFor("iv", { scope: caseId, sizes: [10, 25, 50, 100], defaultSize: 10 });

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
    others.forEach((c) => container.appendChild(renderCorrelationCard(c, eventsById, eventFindingIdx, caseId)));
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
  // Phase 14: the same web host seen in two independent browser
  // artifacts. A link between sources, not a narrative chain.
  web_resource: "Web resource correlation",
  // An estimate of how far one machine's clock is from the capture's.
  clock_skew: "Clock offset",
  // A file delivered over HTTP in a capture, then named on a host.
  web_to_host: "Web delivery to host",
  // One machine in the case reaching another.
  host_relation: "Host-to-host relation",
};

// renderCorrelationsTab splits correlations into activity chains (a
// reconstructed narrative sequence, rendered as a visual step flow --
// see renderActivityChain) and everything else (process/entity/temporal
// relationships, still shown as compact cards, same as before -- they
// describe a link between events, not a story with a beginning and end).
async function renderCorrelationsTab(content, caseId) {
  content.innerHTML = `<p class="empty">Loading correlated activity...</p>`;
  const [corrs, findings] = await Promise.all([
    api(`/cases/${caseId}/correlations`),
    api(`/cases/${caseId}/findings`).catch(() => []),
  ]);
  if (corrs.length === 0) {
    content.innerHTML = `<p class="empty">No correlations yet. Run analysis first.</p>`;
    return;
  }
  const eventsById = await fetchEventsById(caseId, corrs.flatMap((c) => c.event_ids || []))
    .catch(() => ({}));
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
    others.forEach((c) => container.appendChild(renderCorrelationCard(c, eventsById, eventFindingIdx, caseId)));
  }
}

function renderCorrelationCard(c, eventsById, eventFindingIdx, caseId) {
  const collIds = new Set(c.event_ids.map((id) => eventsById[id] && eventsById[id].collection_id).filter(Boolean));
  const collectionsLine = collIds.size > 1 ? `<div class="muted small" style="margin-top:6px">Spans ${[...collIds].map(collectionLabel).join(", ")}</div>` : "";
  const card = h(`
    <div class="finding-card" style="cursor:default">
      <div class="row between">
        <span class="badge conf">${esc(CORR_LABELS[c.correlation_type] || c.correlation_type)}</span>
        <span class="muted small" title="Underlying events in this reconstructed correlation">${fmtCount(c.event_ids.length)} underlying event(s)</span>
      </div>
      <div class="finding-title">${esc(c.title)}</div>
      <div class="finding-desc">${esc(c.description)}</div>
      <div class="muted small correlation-span">${esc(fmtTime(c.first_seen))} &rarr; ${esc(fmtTime(c.last_seen))}</div>
      ${collectionsLine}
      <div class="correlation-detail-host"></div>
    </div>`);
  mountCorrelationEventDetail(card.querySelector(".correlation-detail-host"), c, eventsById, eventFindingIdx, caseId);
  return card;
}

// ---------------- correlation event drill-down ----------------
//
// A correlation card used to state a number and stop: "Activity burst on
// DESKTOP-0J3S8C2 (60 events)" with no way to see any of the 60. That is
// not a finding an investigator can act on or defend -- the whole point
// of a correlation is the events underneath it.
//
// The events are resolved from c.event_ids against the timeline already
// fetched for this tab. Nothing is re-requested and no event data is
// duplicated into the correlation: the correlation stores references,
// and this follows them.

// correlationEventsFor resolves a correlation's event IDs to events, in
// a DETERMINISTIC order.
//
// Activity chains keep c.event_ids order exactly: that sequence IS the
// reconstructed narrative, built and order-locked on the Go side (see
// internal/correlate/activity_chain.go and
// TestBuildActivityChains_FullNarrative). Re-sorting it here would
// silently rewrite the story.
//
// Every other correlation type is ordered chronologically by the event's
// own timestamp, with the event ID as a tiebreak so events sharing an
// instant -- common in a burst -- still order identically on every
// render.
function correlationEventsFor(c, eventsById) {
  const resolved = c.event_ids.map((id) => eventsById[id]).filter(Boolean);
  const missing = c.event_ids.length - resolved.length;
  if (isChainCorrelationType(c.correlation_type)) {
    return { events: resolved, missing, ordering: "narrative" };
  }
  const ordered = [...resolved].sort((a, b) => {
    const at = new Date(a.timestamp).getTime();
    const bt = new Date(b.timestamp).getTime();
    if (at !== bt) return at - bt;
    return String(a.id).localeCompare(String(b.id));
  });
  return { events: ordered, missing, ordering: "chronological" };
}

// correlationPagerPrefix builds a pager key unique to one correlation.
// Non-alphanumerics are stripped because the prefix is also used as a
// dataset key, and a hyphenated UUID is not a valid one.
function correlationPagerPrefix(correlationID) {
  return "corr" + String(correlationID).replace(/[^A-Za-z0-9]/g, "");
}

// mountCorrelationEventDetail adds the expandable, paginated event list.
//
// Collapsed by default and paginated when open: 60 event rows unfurling
// inside a card is the "unreadable wall of text" this is meant to
// replace, and a case can hold correlations far larger than 60.
function mountCorrelationEventDetail(host, c, eventsById, eventFindingIdx, caseId) {
  if (!host) return;
  const { events, missing, ordering } = correlationEventsFor(c, eventsById);
  const total = c.event_ids.length;

  if (total === 0) {
    // A correlation with no events is not expandable, and says so rather
    // than offering an empty panel.
    host.innerHTML = `<p class="muted small">This correlation references no events.</p>`;
    return;
  }

  const detailId = `corr-events-${esc(c.correlation_id)}`;
  host.innerHTML = `
    <button type="button" class="secondary small corr-toggle" aria-expanded="false" aria-controls="${detailId}">
      View ${fmtCount(total)} underlying event${total === 1 ? "" : "s"}
    </button>
    <div class="correlation-events" id="${detailId}" hidden></div>`;

  const panel = host.querySelector(".correlation-events");
  const toggle = host.querySelector(".corr-toggle");
  const prefix = correlationPagerPrefix(c.correlation_id);

  function render() {
    // Small correlations do not need a pager; large ones must have one.
    const paged = events.length > 10 ? paginate(prefix, events) : null;
    const shown = paged ? paged.items : events;
    panel.innerHTML = `
      <p class="muted small corr-ordering">
        ${fmtCount(total)} event(s) in this ${isChainCorrelationType(c.correlation_type) ? "activity chain" : "correlation"},
        shown in ${ordering === "narrative" ? "reconstructed sequence" : "chronological"} order.
        ${missing ? `<strong>${fmtCount(missing)} event(s) could not be resolved and are not shown.</strong>` : ""}
      </p>
      <div class="table-wrap"><table class="data-table wide">
        <thead><tr>
          <th>Time (${esc(tzLabel())})</th><th>Category</th><th>Type</th><th>Host</th><th>User</th>
          <th>Process</th><th>Parent</th><th>PID</th><th>PPID</th><th>Detail</th>
          <th>Finding</th><th>ATT&amp;CK</th><th>Source</th><th>Collection</th>
        </tr></thead>
        <tbody>${shown.map((e) => rowForEvent(e, (eventFindingIdx || {})[e.id], [c])).join("")}</tbody>
      </table></div>
      ${paged ? renderPager(prefix, paged, { noun: "events", label: "Correlation event pagination" }) : ""}`;
    wireDetailCells(panel);
    if (caseId) wireTimelineRowClicks(caseId, panel);
    if (paged) wirePager(prefix, panel, render);
  }

  toggle.addEventListener("click", () => {
    const open = !panel.hidden;
    if (open) {
      panel.hidden = true;
      toggle.setAttribute("aria-expanded", "false");
      toggle.textContent = `View ${fmtCount(total)} underlying event${total === 1 ? "" : "s"}`;
      return;
    }
    // The pager is created on first open, scoped to this correlation so
    // paging one card never moves another.
    if (events.length > 10) {
      pagerFor(prefix, { sizes: [10, 25, 50, 100], defaultSize: 25, scope: c.correlation_id });
    }
    panel.hidden = false;
    toggle.setAttribute("aria-expanded", "true");
    toggle.textContent = "Hide events";
    render();
  });
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

  // A long chain is drawn as its first steps plus a paginated table of
  // every event, rather than as sixty stacked nodes. The step flow is
  // the readable summary; the table is where the chain is actually
  // INSPECTED. Both show the same events in the same recorded order.
  const shown = steps.length > CHAIN_INLINE_STEPS ? steps.slice(0, CHAIN_INLINE_STEPS) : steps;
  shown.forEach((e, i) => {
    if (i > 0) flow.appendChild(h(`<div class="chain-connector">&darr;</div>`));
    flow.appendChild(renderChainNode(caseId, e, eventFindingIdx[e.id] || []));
  });
  if (steps.length > CHAIN_INLINE_STEPS) {
    flow.appendChild(
      h(`<p class="muted small chain-truncation-note">
           Showing the first ${CHAIN_INLINE_STEPS} of ${fmtCount(steps.length)} steps in sequence.
           Every event in this chain is listed below, in the same order.
         </p>`)
    );
  }

  // The drill-down is present on every chain, not only long ones: the
  // step flow names each step but does not carry the full forensic
  // detail (PID, parent, command line, source evidence) that the table
  // does.
  const detailHost = h(`<div class="correlation-detail-host"></div>`);
  wrap.appendChild(detailHost);
  mountCorrelationEventDetail(detailHost, c, eventsById, eventFindingIdx, caseId);
  return wrap;
}

// CHAIN_INLINE_STEPS bounds how many chain nodes are drawn as the visual
// flow. Beyond this the flow stops being a narrative anyone can read and
// becomes the wall of text the drill-down exists to replace.
const CHAIN_INLINE_STEPS = 12;

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
  pagerFor(prefix, { scope: col.collection_id, sizes: [10, 25, 50, 100, 250], defaultSize: 10 });

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
        <button type="button" class="secondary small evidence-file-prov-btn" data-id="${esc(f.id)}"
                aria-expanded="false" aria-label="Show provenance for ${esc(f.original_filename)}">Provenance</button>
        ${canDelete() ? `<button type="button" class="small danger evidence-file-delete-btn" data-id="${esc(f.id)}" data-name="${esc(f.original_filename)}">Delete</button>` : ""}
      </span>
      <div class="evidence-file-provenance" hidden></div>
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
    // Suppressed for a non-admin, as above.
    if (selected.length === 0 || !canDelete()) {
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
    if (btn) {
      confirmAndDeleteEvidence(caseId, [btn.dataset.id]);
      return;
    }
    const provBtn = e.target.closest(".evidence-file-prov-btn");
    if (provBtn) toggleSourceFileProvenance(caseId, provBtn);
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
// confirmDestructive shows a modal and resolves true only if the user
// chooses the confirming action.
//
// window.confirm cannot express this: its buttons are OK/Cancel and
// cannot be named, so a destructive action would be confirmed by a
// button that does not say what it does. A native <dialog> gives the
// focus trap, the Escape key and the backdrop for free, so the only
// thing built here is the content and the promise.
//
// details is optional supplementary text -- counts, names -- shown under
// the main message in a quieter style. The main message is never
// abbreviated to make room for it.
function confirmDestructive({ title, message, details, confirmLabel, cancelLabel = "Cancel" }) {
  return new Promise((resolve) => {
    const dlg = document.createElement("dialog");
    dlg.className = "confirm-modal";
    dlg.setAttribute("aria-labelledby", "confirm-modal-title");
    dlg.innerHTML = `
      <h2 id="confirm-modal-title">${esc(title)}</h2>
      <p class="confirm-modal-message">${esc(message)}</p>
      ${details ? `<div class="confirm-modal-details">${esc(details)}</div>` : ""}
      <div class="confirm-modal-actions">
        <button type="button" class="secondary" data-choice="cancel">${esc(cancelLabel)}</button>
        <button type="button" class="danger" data-choice="confirm">${esc(confirmLabel)}</button>
      </div>`;

    let settled = false;
    const finish = (ok) => {
      if (settled) return;
      settled = true;
      dlg.close();
      dlg.remove();
      resolve(ok);
    };
    dlg.addEventListener("click", (e) => {
      const choice = e.target.closest("[data-choice]");
      if (choice) finish(choice.dataset.choice === "confirm");
    });
    // Escape and the backdrop both mean cancel -- the safe outcome is
    // the one a stray keypress lands on.
    dlg.addEventListener("cancel", (e) => {
      e.preventDefault();
      finish(false);
    });

    document.body.appendChild(dlg);
    dlg.showModal();
    // Focus starts on Cancel, so Enter never confirms a deletion the
    // user has not read.
    dlg.querySelector('[data-choice="cancel"]').focus();
  });
}

// EVIDENCE_DELETION_WARNING is the one wording every evidence-deletion
// path uses. Deleting evidence does not merely make analysis stale -- it
// INVALIDATES it, because the results were derived from evidence that
// will no longer exist, and the backend removes them from every current
// view (see Service.invalidateAnalysisAfterDeletion).
const EVIDENCE_DELETION_WARNING =
  "Deleting this evidence will invalidate the current analysis results derived from it, " +
  "including findings, investigations, correlations, activity chains, and ATT&CK mappings. " +
  "This action cannot be undone.";

async function confirmAndDeleteEvidence(caseId, ids) {
  const ok = await confirmDestructive({
    title: "Delete Evidence?",
    message: EVIDENCE_DELETION_WARNING,
    details:
      `${fmtCount(ids.length)} evidence file(s) selected. Events observed only in these files are ` +
      `removed with them; events also observed elsewhere are kept and re-attributed to the ` +
      `collection that still holds them.`,
    confirmLabel: "Delete Evidence",
  });
  if (!ok) return;
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
