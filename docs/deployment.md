# Deployment: LAN access, uploads, and their security model

Phase 1.5 adds two things beyond running Tracefall on `localhost` for
yourself: making the server reachable from other machines on your LAN,
and accepting a KAPE evidence package as a browser upload instead of a
local filesystem path. Both are still explicitly **local/LAN tools with
no authentication** -- this document is about what protections exist and
where the boundary of that protection stops.

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

The default (`127.0.0.1`) is deliberately loopback-only, matching "safe
by default." This is a change from Tracefall's very first version, where
the default `:8080` address bound to all interfaces without anyone
intending that.

## Enabling LAN access

```bash
TRACEFALL_HOST=0.0.0.0 TRACEFALL_PORT=8080 go run ./cmd/tracefall
```

or, built as a binary:

```bash
go build -o tracefall ./cmd/tracefall
./tracefall -host 0.0.0.0 -port 8080
```

Tracefall logs a startup warning whenever it binds to a non-loopback
host, and the startup banner still prints a `localhost` URL for
convenience even though the process is listening on every interface.
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
