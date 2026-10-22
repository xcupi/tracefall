# Container and Grafana evidence

Status: parsers for Docker's own files and for Grafana are being added. This page
says where the evidence lives for each way Docker can run on a Windows server,
what Tracefall reads, and what it does not. Statements marked **verified** were
checked against files a real engine wrote in the validation lab; everything else
is documented behaviour and has not been checked here.

## Which kind of container is it

Ask the server owner, or read it from the disk:

| What you find | Meaning |
|---|---|
| `C:\ProgramData\docker\` with `containers\` and `windowsfilter\` | Docker Engine running **Windows containers**. |
| `C:\ProgramData\DockerDesktop\` or `%LOCALAPPDATA%\Docker\` | **Docker Desktop**, normally Linux containers inside a WSL2 or Hyper-V virtual disk. |
| A Hyper-V virtual machine (a `.vhdx`) running Linux | **Linux containers** inside a VM. The container data is inside the VM's disk, not on the Windows volume. |
| `containerd` or `podman` data directories | Not Docker Engine; layout differs (see "Not covered"). |

Grafana is, as far as is publicly documented, distributed as a Linux container
image. A Grafana container on a Windows server therefore most likely runs as a
Linux container, which means the evidence is inside a virtual disk. Confirm this
from the server before assuming it.

## Where the evidence is

### Linux containers (verified layout, Docker 29, json-file log driver)

On the Linux side (a VM, a WSL2 distribution, or a Linux host):

| Path | What it holds | Read by Tracefall |
|---|---|---|
| `/var/lib/docker/containers/ID/ID-json.log` | stdout and stderr of the container with the engine's own UTC timestamp | yes |
| `/var/lib/docker/containers/ID/config.v2.json` | image, command, state, start and stop times, environment (names and values), mounts | yes (environment values are never shown) |
| `/var/lib/docker/containers/ID/hostconfig.json` | privileges, host mounts, published ports, capabilities | yes |
| `/var/lib/docker/volumes/NAME/_data` | named volumes (Grafana's `/var/lib/grafana` when mounted) | files inside are read like any other file |
| `/var/lib/docker/overlay2/` or the containerd snapshot store | image layers and the container's writable layer | not interpreted as layers; files can be read from a mounted tree |

ID is the 64-hex-character container id.

### Windows containers (documented layout, not verified against a real engine)

The same Docker code writes the same JSON files, under
`C:\ProgramData\docker\containers\ID\`. Layers live in
`C:\ProgramData\docker\windowsfilter\`. Tracefall's parser for the JSON files is
written to accept this path, and is tested only on synthetic files built from the
documented format. Treat results from a Windows engine as unverified until a
real sample has been compared against the engine's own `docker inspect`.

### Grafana's own files

| File | Where | What it proves |
|---|---|---|
| Console log | inside the container's JSON log (default in the official image) | requests Grafana chose to log, with status and client address |
| `grafana.log` | `/var/log/grafana/` when file logging is on | same, as a plain file |
| `grafana.db` | `/var/lib/grafana/` (a volume, or the writable layer) | users, service-account tokens, data sources, recent login attempts, sessions |

Findings from the validation lab (Grafana 11.3.0, verified):

- **The default log is thin.** Only some requests are logged. A failed login
  appears as an anonymous `401` on `/login`; **the name that was tried is not
  logged.** Successful actions such as creating a user or a data source did not
  appear as application messages.
- **`login_attempt` is incomplete.** It holds attempts against accounts that
  exist (three for `admin`) and none for a name that does not (four for a
  non-existent name left no row). Rows are pruned over time.
- **`last_seen_at` has a sentinel.** A user who never logged in carries a
  `last_seen_at` ten years before `created`. It is not a login time.
- **Secrets are stored, not shown.** A data source's password is stored encrypted
  (`secure_json_data`); Tracefall reports that a secret exists and never decodes or
  prints it. The container's environment often holds the admin password in the
  clear (`GF_SECURITY_ADMIN_PASSWORD` in the lab); Tracefall lists variable names
  only.
- **Timestamps.** The Docker log and Grafana's `t=` are UTC instants. `grafana.db`
  timestamps are stored as UTC by Grafana and matched the container log in the
  lab.

## How to collect

Prefer the disk. Stop-the-world is not needed for the files above.

1. **Image the server's disk** (E01 or raw) as for any Windows server. That
   captures `C:\ProgramData\docker` for Windows containers and the virtual disks
   for Linux containers.
2. **Linux containers in a virtual disk:** Tracefall does not read `VHD`/`VHDX`
   (see `disk-images.md`). Convert or mount the virtual disk outside Tracefall
   (for example convert to raw with `qemu-img convert`), then ingest the raw image
   or the extracted `/var/lib/docker` and Grafana files.
3. **If the machine is live** and you must read through Docker, keep it
   read-only: `docker inspect ID`, `docker logs --timestamps ID`,
   `docker diff ID`. Record the exact commands and hash the output. These are
   secondary evidence, produced by the engine at collection time.
4. **Do not** start, stop, restart or `docker exec` into the container if you can
   avoid it: stopping changes state timestamps and can rotate logs.
5. **Memory:** a memory image of the host (or the VM) can show processes inside
   containers; it is read by the existing memory analysis, not by the container
   parsers.

## What Tracefall does with it

- Container JSON log lines become `container_log` events; lines that are Grafana
  requests become `web_request` events, so the existing web-attack rules apply.
- Container configuration and host configuration become one event each, with the
  risky settings (privileged, Docker socket mount, host PID or network, wide port
  publication, secrets in environment variable names) tagged.
- `grafana.db` rows become user, token, data-source, login-attempt and session
  events.
- Nothing here reads inside a container's filesystem layers or reconstructs what
  ran in a container; that comes from the files listed above, or from the memory
  image.

## Not covered

- containerd's own metadata store, Podman and CRI-O layouts.
- Docker's `local` log driver (binary), `journald`, and remote log drivers; only
  the default `json-file` driver is read.
- Overlay layer interpretation (whiteouts, layer diffing).
- Windows containers' layer store.
- VHD, VHDX and VMDK virtual disks.
- Kubernetes.
