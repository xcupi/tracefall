# Deployment: access control, LAN access, uploads

Tracefall runs in one of exactly two supported modes. Which one you get
is determined by the address you bind to, and the unsafe combination is
**refused at startup** rather than warned about.

| Mode | Bind | Authentication | Who can reach it |
|---|---|---|---|
| **Single operator** | loopback (`127.0.0.1`, `localhost`, `::1`) | optional, off by default | only processes on that machine |
| **Shared / LAN** | any non-loopback address | **required** | anyone who can route to the port |

Binding to a non-loopback address **without** authentication does not
start:

```
tracefall: refusing to start: Tracefall is configured to listen on a
non-loopback address with authentication disabled.
```

Before Phase 12 that configuration started and logged a warning, which
meant one mis-set environment variable published every case, all
evidence, the full audit log and every destructive endpoint to the
network. A warning in a log nobody reads is not a control.

## Configuration

All of these can be set as an environment variable or a CLI flag; an
explicit flag wins over the environment variable, which wins over the
built-in default. See `internal/config` for the implementation.

| Flag | Env var | Default | Meaning |
|---|---|---|---|
| `-host` | `TRACEFALL_HOST` | `127.0.0.1` | listen host/IP |
| `-port` | `TRACEFALL_PORT` | `8080` | listen port |
| `-db` | `TRACEFALL_DB` | `tracefall.db` | SQLite database file path |
| `-data-dir` | `TRACEFALL_DATA_DIR` | `./data` | root directory for uploaded/extracted case evidence |
| `-max-upload-mb` | `TRACEFALL_MAX_UPLOAD_MB` | `2048` (2 GiB) | maximum accepted upload size |
| `-auth` | `TRACEFALL_AUTH` | `false` | require username/password. **Mandatory for any non-loopback bind.** |
| `-session-ttl-minutes` | `TRACEFALL_SESSION_TTL_MINUTES` | `720` (12 h) | how long one login stays valid |
| `-secure-cookies` | `TRACEFALL_SECURE_COOKIES` | `false` | mark session cookies `Secure`. Only behind HTTPS -- **breaks login over plain HTTP** |
| (env only) | `TRACEFALL_ADMIN_PASSWORD` | *(generated)* | password for the bootstrap `admin` account, first start only |
| (env only) | `TRACEFALL_EVIDENCE_ROOTS` | *(unset)* | folders the server may read for path-based ingest, separated like `PATH` (`:` on Linux). Unset: path ingest is refused, except in local no-auth loopback mode, where any path is accepted. See `docs/security.md`, *Server-path ingest* |

`TRACEFALL_AUTH` accepts `1/true/yes/on/enabled` and their negatives.
`TRACEFALL_ADMIN_PASSWORD` is environment-only, deliberately: a flag
would put the password in the process table.

The default (`127.0.0.1`) is deliberately loopback-only, matching "safe
by default." This is a change from Tracefall's very first version, where
the default `:8080` address bound to all interfaces without anyone
intending that.

## Single-operator mode (default)

```bash
go run ./cmd/tracefall
```

Binds `127.0.0.1:8080`, no authentication, nothing to configure. The
dashboard shows *"Local operator · no authentication"* so the mode is
never ambiguous. This is unchanged from earlier phases.

## Shared / LAN mode

```bash
TRACEFALL_AUTH=on TRACEFALL_HOST=0.0.0.0 ./tracefall
```

On the **first** start with authentication enabled and no accounts,
Tracefall creates a `tracefall` administrator and prints its password
once:

```
==================================================
 Tracefall First-Run Setup
==================================================

Administrator account created.

Username: tracefall
Password: eQ1RGGmtEERC18PGhtftrbS9EOs7S__s

IMPORTANT:
This password is displayed only once.
Sign in and change the password immediately.

==================================================
```

That account is **gated behind a mandatory password change**: it can
sign in and change its password, and nothing else, until it does. The
password was displayed in plaintext on a terminal, where it can survive
in scrollback, a screenshot or a CI log, so it is treated as a
short-lived enrolment credential rather than a working one. The gate is
enforced by the server, not the UI, so it cannot be skipped by calling
the API directly.

Whether the credential is printed is decided by **persisted state** —
"the users table is empty" — so restarting never regenerates, reprints
or overwrites anything.

The password is generated from `crypto/rand`, printed to stdout only,
and never written to the structured log or the audit trail. It is
generated rather than defaulted because a well-known default credential
on a forensic tool is worse than no authentication: it looks secure.

Set `TRACEFALL_ADMIN_PASSWORD` instead for unattended provisioning.

Then sign in and create per-analyst accounts under **admin → users**
(`POST /api/admin/users`). Do not share the `admin` account: the audit
trail records the username that acted, and a shared account makes every
entry say the same thing.

### Transport is still plain HTTP

Authentication controls *who* may act. It does nothing about *who can
read the traffic*. Tracefall speaks plain HTTP and does not terminate
TLS. On a shared network, put it behind a reverse proxy that does
(nginx, Caddy, a corporate ingress) and set `TRACEFALL_SECURE_COOKIES=1`
so session cookies are marked `Secure`.

Setting `TRACEFALL_SECURE_COOKIES=1` **without** TLS makes login fail
silently -- the browser accepts the cookie and refuses to send it back.
That is why it is opt-in rather than inferred.

From another machine on the same LAN, open
`http://<the-host-machine's-LAN-IP>:8080`.

### Firewall requirements

The host running Tracefall needs to allow **inbound TCP** on whatever
port you configured (`8080` by default) from the LAN segment your other
machine is on. How to do that depends on the host OS:

- **Linux (ufw)**: `sudo ufw allow 8080/tcp` (or scope it to a subnet:
  `sudo ufw allow from 192.168.1.0/24 to any port 8080 proto tcp`)
- **Linux (firewalld)**: `sudo firewall-cmd --add-port=8080/tcp --permanent && sudo firewall-cmd --reload`
- **macOS**: System Settings → Network → Firewall → Options, allow
  incoming connections for the `tracefall` binary
- **Windows**: `netsh advfirewall firewall add rule name="Tracefall" dir=in action=allow protocol=TCP localport=8080`,
  or add a rule via Windows Defender Firewall's GUI

No outbound rules are needed -- Tracefall makes no outbound network
calls in this phase (no telemetry, no update checks, no threat intel
lookups).

### What LAN mode does *not* add

Binding to `0.0.0.0` makes Tracefall reachable, not authenticated.
**There is still no login, no access control, and no encryption
(plain HTTP)** in this phase. Anyone who can reach the configured
host:port -- including anyone else on the same Wi-Fi/LAN segment -- can
create cases, upload evidence, and read findings. Do not run Tracefall
on a network you don't trust, and:

- **Never** port-forward this to the public internet.
- **Never** put it directly on a network shared with untrusted devices
  (e.g. a guest Wi-Fi network).
- If you need it reachable outside a trusted LAN, put a reverse proxy
  with real authentication (and TLS) in front of it -- Tracefall itself
  doesn't provide either yet (see ARCHITECTURE.md's Phase 2 list, which
  includes authentication).

## Uploaded evidence: the security model

An uploaded KAPE package is untrusted input: it was collected on a
(possibly compromised) machine, and Tracefall has no reason to trust its
contents beyond "this is data to parse, never code to run." The upload
pipeline (`POST /cases/{id}/upload`, `internal/api.Service.UploadCase`,
`internal/archive`) applies several independent layers of protection:

1. **HTTP body size cap.** `http.MaxBytesReader` rejects a request body
   larger than `-max-upload-mb` before any of it is parsed or written to
   disk (413 Payload Too Large).
2. **Format validation.** The uploaded file must open as a well-formed
   ZIP (`archive.ErrInvalidArchive` if not) before anything is extracted.
3. **Path safety.** Every entry's name is checked for absolute paths
   (both `/foo` and `C:\foo` styles) and `..` path-traversal (Zip Slip)
   before it's joined onto the destination directory, and the resolved
   path is independently re-verified to stay inside that directory as a
   second check. See `internal/archive.safeJoin`.
4. **No symlinks.** Any entry whose stored mode marks it a symlink is
   rejected outright -- Tracefall never creates a real filesystem
   symlink from archive content, and never treats archive content as
   something that could plausibly be "followed."
5. **Zip-bomb protection.** Extraction enforces a maximum entry count, a
   maximum per-file uncompressed size, a maximum total uncompressed
   size, and a maximum compression ratio for files above a size floor --
   and the per-file cap is enforced against bytes actually decompressed,
   not just the (attacker-controlled) size the zip header declares.
6. **Fail closed.** Any single unsafe or over-limit entry aborts
   extraction of the *entire* archive -- a crafted archive is rejected as
   a whole, never partially trusted.
7. **Never executable.** Extracted files are always written with fixed
   `0644`/`0755` permissions, ignoring whatever mode bits the archive
   itself declared. Nothing Tracefall extracts is ever executed --
   ingestion only ever *reads* file contents through the artifact
   parsers in `internal/parsers`.
8. **Isolated, cleaned-up storage, per collection.** A case can hold
   more than one evidence collection (see docs/data-model.md), and each
   one gets its own subtree:

   ```
   <data-dir>/cases/<case-id>/collections/<collection-id>/upload.zip
   <data-dir>/cases/<case-id>/collections/<collection-id>/evidence/
   <data-dir>/cases/<case-id>/collections/<collection-id>/metadata.json
   ```

   (`internal/casefiles`). A failed or partial upload/extraction removes
   only *that collection's* directory -- never a sibling collection's,
   even one already successfully ingested into the same case -- so no
   partial or untrusted state lingers on disk and the case is left ready
   for the next attempt without any risk to evidence already in hand.
   `metadata.json` is a best-effort, human-readable copy of the
   collection's database record (source type, timestamps, file/event
   counts) written alongside the evidence itself, so the collection's
   provenance travels with it even if the folder is copied or archived
   independently of Tracefall's database.

Full details and the exact defaults (file count, size, and ratio limits)
are documented in `internal/archive`'s package comment and
`archive.DefaultLimits`.

A file that isn't one of the four supported artifact formats (EvtxECmd
CSV, PECmd CSV, RECmd CSV, Scheduled Task XML) is not a security
concern -- it's simply extracted and then reported as unsupported by
`internal/ingest.Walk`, exactly as an unrecognized file in a local-path
ingest already was in Phase 1. Ingestion never fails because of files it
doesn't know how to parse; it only fails if the archive itself is
malformed or unsafe.
