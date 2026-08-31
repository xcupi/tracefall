# Native Windows artifact samples (EVTX + Registry hive)

**100% synthetic.** Every byte here was fabricated to exercise
Tracefall's Phase 9 native artifact ingestion, exactly as
[`testdata/synthetic_case`](../synthetic_case) and
[`testdata/ad1_samples`](../ad1_samples) do for the KAPE CSV and AD1
paths. No real hostname, username, SID, IP address, file path, or event
from any real machine appears in any of these files.

The invented cast is the same one the rest of Tracefall's fixtures use:

| Field | Value |
|---|---|
| Host | `WKSTN-042` (and `SRV-FS01` as a logon target) |
| User | `jdoe`, `svc-backup` |
| IP addresses | `198.51.100.23`, `203.0.113.77`, `10.0.0.5` — all IANA-reserved documentation/private ranges |
| Domain | `updates.example.test` — the reserved `.test` TLD |
| Payload | `C:\Users\jdoe\AppData\Local\Temp\update.exe` |

## Files

| File | What it is |
|---|---|
| `Security.evtx` | Valid EVTX. Four failed logons (4625), a success (4624), a privileged logon (4672), explicit-credential use (4648), and a service install (7045). |
| `Sysmon.evtx` | Valid EVTX. Sysmon 11 (file create), 1 (process create), 22 (DNS), 3 (network connect), 13 (registry set to a Run key). |
| `SYSTEM` | Valid REGF hive. Machine name `WKSTN-042` under `ControlSet001\Control\ComputerName`, plus a service `ImagePath` in a user-writable directory. |
| `SOFTWARE` | Valid REGF hive. One of each remaining persistence location: Run, Winlogon `Userinit`, IFEO `Debugger`, `AppInit_DLLs`. |
| `NTUSER.DAT` | Valid REGF hive. Per-user `Run` and `RunOnce` entries. |
| `Broken.evtx` | **Deliberately damaged**: a valid EVTX whose first chunk fails its CRC. Exercises partial recovery — the reader must skip that chunk, keep the rest, and report the failure. |
| `Truncated.dat` | **Deliberately damaged**: a hive cut off at 2500 bytes, before its bins data. Must be rejected cleanly. |

Together the two event logs and three hives tell one story an
investigator can follow end to end: a password spray succeeds, the
account gains privileges, a payload is written to `%TEMP%` and executed,
it resolves a domain and connects out, and it persists four different
ways.

## These are generated, not hand-maintained

They are written by
[`internal/nativegen`](../../internal/nativegen), which drives the same
pure-Go *writers* the unit tests use —
[`internal/evtx/evtxgen`](../../internal/evtx/evtxgen) and
[`internal/regf/regfgen`](../../internal/regf/regfgen). So there is one
source of truth for what these fixtures contain, rather than opaque
binaries that could silently drift from what the readers expect.

Regenerate them with:

```bash
go test ./internal/nativegen -run TestGenerateSamples -write-samples
```

The output is deterministic: regenerating produces byte-identical files.

## "Real" means structurally real

These were not produced by Windows or by FTK Imager — Tracefall has no
such tool in this environment. They are real in the sense that matters
for testing a parser: real `ElfFile`/`ElfChnk` framing with correct
CRC32s, real BinXML templates with substitution arrays, real `regf` base
blocks with `hbin` cells, `nk`/`vk` records and `lf` subkey lists. Every
structure [`internal/evtx`](../../internal/evtx) and
[`internal/regf`](../../internal/regf) parse is present and correct,
including the ones that must be *rejected*.

The limits of that are stated honestly in
[`docs/native-artifacts.md`](../../docs/native-artifacts.md): these
fixtures do not cover every provider-specific quirk a decade-old
production Security.evtx might contain, and validation against real
evidence remains future work.
