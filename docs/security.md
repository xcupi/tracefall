# Security model

What Tracefall protects, how, and where that protection stops.

Referenced by `internal/model.AuditEvent` and
[deployment.md](deployment.md).

---

## Two deployment modes

Tracefall runs in exactly one of two modes, decided by the bind address.
The unsafe combination is **refused at startup**, not warned about.

| Mode | Bind | Authentication |
|---|---|---|
| Single operator | loopback | optional, off by default |
| Shared / LAN | non-loopback | **required** |

See [deployment.md](deployment.md) for configuration.

---

## Authentication

Local accounts, server-side sessions, cookie transport. No external
identity provider — a DFIR deployment is usually one small team on an
isolated network, where an OIDC dependency is a liability rather than a
feature.

### Passwords

Hashed with **PBKDF2-HMAC-SHA256, 600,000 iterations**, a 16-byte
per-user random salt, and a 32-byte derived key. The stored form is
self-describing (`pbkdf2-sha256$600000$salt$key`) so a future build can
verify an old hash and upgrade it on the next successful login without a
flag day.

PBKDF2 rather than argon2id/bcrypt/scrypt because those live in
`golang.org/x/crypto`, which Tracefall does not depend on. PBKDF2
entered the Go standard library in 1.24 and is an approved password KDF
(RFC 8018, NIST SP 800-132). **It is memory-cheap, which is a real
weakness against a GPU attacker** — accepted deliberately in exchange for
a zero-dependency credential path in a tool that must build and audit as
a closed set. If Tracefall ever vendors `x/crypto` for another reason,
argon2id is the upgrade.

Minimum length is 12 characters. There are deliberately **no composition
rules** (mixed case, symbols, rotation): they push people toward
predictable passwords, and NIST SP 800-63B recommends length instead.

Verification is constant-time. An unknown username still costs a full
password verification against a dummy hash, so login timing does not
reveal which accounts exist.

### Sessions

- 256-bit tokens from `crypto/rand`.
- The database stores only **SHA-256 of the token**. A stolen database
  yields no usable cookies. (Plain SHA-256 is correct here: the token is
  uniform randomness, so there is no low-entropy secret to stretch, and
  a slow hash on every request would be self-inflicted DoS.)
- Server-side, so **logout actually revokes**. A self-contained signed
  token would stay valid until expiry no matter what the server decided,
  and for a tool holding evidence "revoke that session now" is worth
  more than statelessness.
- Expiry is enforced in the SQL `WHERE` clause, so an expired row cannot
  be returned even if a caller forgets to check.
- Changing a password or disabling an account **drops that user's
  sessions** in the same transaction.

### Cookies

| Cookie | HttpOnly | SameSite | Purpose |
|---|---|---|---|
| `tracefall_session` | **yes** | Lax | the session token |
| `tracefall_csrf` | no (by design) | Lax | double-submit CSRF token |

The CSRF cookie is deliberately readable by script: the dashboard must
echo it back in `X-Tracefall-CSRF` for the double-submit check. Its only
power is to prove same-origin, and a cross-site attacker cannot read it.

`Secure` is opt-in via `TRACEFALL_SECURE_COOKIES` because Tracefall
speaks plain HTTP; setting it without TLS makes login fail silently.

### Request source checks (all modes)

Before authentication and routing, every request is checked in
`rejectRequest` (`internal/api/middleware.go`). A refused request gets
`403 request refused: <reason>` and is logged, never handled.

- **Host (no-auth mode only).** The `Host` header must name loopback
  (`localhost`, `127.0.0.1`, `::1`, with or without a port). This blocks DNS
  rebinding, where a hostile page points its own hostname at 127.0.0.1 and
  reads same-origin responses. Authentication mode does not need this rule:
  the session cookie is scoped to the hostname the analyst logged in with, so
  a rebound hostname never carries it.
- **Origin (writes).** When the browser sends `Origin`, its host must equal
  the request `Host`. `null` is refused. A cross-origin POST always carries
  `Origin`, so this stops it.
- **Sec-Fetch-Site (writes).** `cross-site` is refused.
- **X-Tracefall-Client (writes).** Every non-GET request must carry this
  header. The dashboard sends `dashboard`; CLI clients must send any non-empty
  value. A browser cannot add a custom header to a cross-origin request
  without a CORS preflight, and Tracefall never answers a preflight, so a
  foreign page cannot forge it. This is the control that protects no-auth
  mode, which has no CSRF token.

Known limits of these checks:

- A reverse proxy that rewrites `Host` will fail the Origin match. Configure
  the proxy to pass `Host` through, or it will refuse dashboard writes.
- A non-browser client on the same machine can send any header it likes.
  These checks defend against web pages, not local processes. Anything that
  can already run code on the analyst's machine can read the evidence
  directly.
- In LAN mode (`TRACEFALL_HOST` non-loopback) authentication is mandatory,
  so the Host rule is off by design and the session cookie carries the
  protection instead.

### CSV exports and spreadsheet formulas

Every cell of the timeline and findings CSV is passed through `csvSafeRow`
(`internal/api/export.go`). A cell beginning with `=`, `+`, `-`, `@`, tab or
CR gets a leading single quote, so Excel or LibreOffice shows it as text
instead of running it. Evidence fields are attacker-controlled, so this
matters for a forensic export. The same writers feed the report bundle, so
the manifest hashes still match the downloaded files.

### First-run bootstrap

On a first start with authentication enabled and an empty users table,
Tracefall creates one administrator named **`tracefall`** with a password
from `crypto/rand` (24 bytes, ~192 bits, base64url) and prints it once.

The account is created with `must_change_password = 1`. It may
authenticate, read its own session, change its password and log out —
**nothing else**, enforced in the middleware every request passes
through. A printed credential can persist in terminal scrollback, a
screenshot or a CI log, so it is an enrolment credential, not a working
one. Changing it clears the gate, replaces the hash and invalidates every
session for the account in one transaction; a no-op "change" to the same
password is refused, since that would satisfy the gate while leaving the
displayed credential in force.

The decision to print is made from **persisted state** (the users table
is empty), not an in-memory flag or a marker file, so repeated restarts
never regenerate, reprint or overwrite anything.

`TRACEFALL_ADMIN_PASSWORD` supplies the password instead for unattended
provisioning. That path is **not** gated: the operator chose the value,
Tracefall never displayed it, and forcing a change would break the
automation the variable exists for. It is also never echoed.

There is deliberately **no administrative password-reset CLI**. Recovery
for a forgotten sole-admin password is a documented gap — see
"What this does not protect against".

### Login throttling

10 failed attempts per username in 15 minutes. Held **in memory**, not
in the database: throttling state is operational rather than forensic,
must not survive a restart, must not be exported with a case, and must
not add a write to the single SQLite connection per failed guess — which
would make the throttle its own denial-of-service vector.

---

## Authorization

Two roles. Every extra role multiplies the (role × endpoint) states to
reason about, and the distinction that matters in a DFIR team is between
people who analyse evidence and people who may **destroy** it.

| | analyst | admin |
|---|---|---|
| View cases, timeline, findings, investigations, provenance | ✅ | ✅ |
| Create cases, ingest/import evidence, analyze | ✅ | ✅ |
| Notes, tags, analyst workflow state | ✅ | ✅ |
| Export, verify integrity | ✅ | ✅ |
| **Delete** cases / evidence (single or bulk) | ❌ | ✅ |
| Manage users | ❌ | ✅ |
| View the security log | ❌ | ✅ |

Admin is a **superset** of analyst.

### Enforcement is middleware, not per-handler

Every API request passes through one `withSecurity` wrapper that
resolves the principal, checks CSRF, and checks the role. A route added
later inherits the protection by default; a forgotten check **denies**
rather than opens.

The rule itself is deliberately blunt: **every `DELETE` is admin-only**,
and everything under `/api/admin/` is admin-only. Deletion is the
privilege boundary because it is the only action that destroys forensic
material.

UI hiding is **not** the control. The dashboard hides destructive
buttons from analysts as a convenience, and the server re-checks the
role on every request regardless of what the UI chose to render.

### Public routes

An explicit allow-list, not a prefix rule: `/api/healthz`,
`/api/auth/login`, `/api/auth/session`. Nothing else is reachable
unauthenticated when authentication is on.

---

## Case isolation

Every case-scoped route verifies that the object belongs to the case in
the URL — collections, source files, findings, notes.

Phase 12 fixed one gap: `PATCH`/`DELETE /api/notes/{noteID}` took a bare
note id with **no case in the route and no ownership predicate in the
store** (`UPDATE notes ... WHERE id = ?`). Any caller who knew or guessed
a note id could edit or delete a note in any case. The route is now
`/api/cases/{id}/notes/{noteID}` and the case is part of the SQL
predicate, so a foreign id matches no row — reported identically to an
unknown id, so the API cannot be used to probe which ids exist.

---

## Audit and the security log

Two logs, deliberately separate.

| | `audit_log` | `security_log` |
|---|---|---|
| Records | what happened **to a case** | who used **the system** |
| Scope | one case (`case_id` NOT NULL, FK to `cases`) | system-wide |
| In case export | yes | **no** |
| Examples | evidence imported, analysis completed, integrity verified | login, logout, access denied, user created |

They are separate for two reasons. Structurally, `audit_log.case_id` is
`NOT NULL REFERENCES cases(id)`, so a login — which belongs to no case —
cannot be stored there at all; the foreign key rejects it. Semantically,
account administration should not travel inside every case export.

**Actor** is now the authenticated username instead of the generic
`local-user`. In single-operator mode it remains `local-user`, which is
the honest value when there is no authentication. A failed login for an
unknown username records `unauthenticated` — never an invented name.

Both logs are **append-only from the application layer**: the store
exposes only create, there is no update or per-row delete, and no route
accepts a mutation. Tests assert both.

### Case deletion

Deleting a case removes that case's entire `audit_log`, because those
rows are part of the case. The deletion itself is therefore recorded in
the **`security_log`**, which is system-wide and survives: action
`case_deleted`, with the acting username, the case id and the case name.

That is the one record of the case that outlives it, and it is
deliberate — "this case existed and this person destroyed it" is exactly
the kind of fact a security log is for. It contains no evidence, no
event data and no findings.

Deletion is admin-only (every `DELETE` is; see the role table above) and
requires a valid CSRF token like any other state-changing request.

### Never logged

Passwords, password hashes, session tokens, CSRF tokens, uploaded file
contents, raw evidence. A test asserts none of these appear in any audit
or security entry.

---

## HTTP security headers

| Header | Value | Why here |
|---|---|---|
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'; …; frame-ancestors 'none'` | one same-origin bundle, no external resource of any kind |
| `X-Content-Type-Options` | `nosniff` | evidence bytes must never be sniffed into something executable |
| `X-Frame-Options` | `DENY` | the dashboard must not be framed to clickjack a delete button |
| `Referrer-Policy` | `no-referrer` | a case id in a URL must not travel to any external site |
| `Cache-Control` (API) | `no-store` | API responses carry evidence and must not sit in a shared cache |

`script-src` has **no** `'unsafe-inline'`, so an injected `<script>` is
blocked outright. `style-src` does include it, only because the existing
dashboard sets inline style attributes.

---

## What this does not protect against

Being precise about the limits is part of the model.

- **Transport.** Tracefall speaks plain HTTP. Anyone who can see the
  network can read sessions and evidence. Terminate TLS in front of it.
- **A malicious authenticated analyst.** Any analyst can read every case
  and export it. There is no per-case access control — the model is
  "everyone on this team may see this team's cases".
- **Database theft.** Passwords and session tokens are hashed, but
  evidence, findings and the audit log are stored in plaintext SQLite.
  Use disk encryption.
- **Deleting a case still destroys its audit log**, unchanged from
  earlier phases. See "Retention" below.
- **A compromised host.** Tracefall reads evidence from local disk as
  the user running it; root on that host defeats everything here.
- **Rate limiting beyond login.** Only authentication is throttled.
- **No administrative password recovery.** If the only admin password is
  lost there is no reset command; recovery means starting from a new
  database. A `tracefall admin reset-password` subcommand is the obvious
  future addition, deliberately not built here to avoid a CLI
  administration subsystem for one requirement.

### Retention: a deliberate non-change

Deleting a case removes its `audit_log` rows along with it. Making audit
history outlive its case is a **retention architecture** decision — where
orphaned records live, how long, who may purge them, and how that
interacts with legal deletion obligations — not a one-line change.
Phase 12 deliberately did not implement it. The security log is
unaffected: it is system-wide and survives case deletion, so *"admin
deleted case X"* remains recorded even when case X is gone.
