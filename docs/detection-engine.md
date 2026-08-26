# Detection engine

`internal/detect` is Tracefall's deterministic detection engine. Every
rule is a pure function of a case's normalized events — no network calls,
no LLM, no randomness, no wall-clock dependence in the *logic* (only in
each finding's `created_at` timestamp). Running `detect.Run` twice on
identical evidence always produces the same set of findings, in the same
order. This is a hard requirement, not a preference: it's what makes
Tracefall's output reproducible and defensible in an investigation.

## The `Rule` interface

```go
type Rule interface {
	ID() string
	Evaluate(events []model.Event) []model.Finding
}
```

A rule receives the case's full, timestamp-sorted event list and returns
zero or more findings. `detect.Run` calls every registered rule (see
`detect.All()`), assigns IDs, and sorts the combined result by
`first_seen` (rule ID as tiebreaker) so output ordering is stable.

## Evidence requirement

Every `Finding` carries `SupportingEvents []string` — the event IDs it's
based on — and this is **never empty**. `internal/detect/rule.go`'s
`newFinding` constructor derives `first_seen`/`last_seen` directly from
the supporting events passed in, so it's structurally difficult to
produce an unsupported finding.

## Severity and confidence philosophy

**A single weak indicator is never reported as a verdict.** Where a
rule's signal is inherently weak in isolation — one registry Run key, one
scheduled task — its finding is worded as an *observation*
("persistence mechanism observed") at low-to-medium confidence, not an
accusation. Stronger claims require corroborating evidence, which is
exactly what makes a finding's severity/confidence go up (e.g. a Run key
pointing into `%AppData%\Temp` instead of `Program Files`), or is what
the correlation engine surfaces separately as a linkage between multiple
findings/events (see [correlation-engine.md](correlation-engine.md)).

`confidence` on a `Finding` is intentionally a coarse enum
(`low`/`medium`/`high`), not a float — a float would imply a precision
the underlying heuristics don't have. (This is a different concept from
`Event.Confidence`, which is a *parser's* confidence in field-extraction
fidelity — see [data-model.md](data-model.md).)

## The fifteen rules

All thresholds below are named constants in `internal/detect/rules.go`
and easy to retune. Rules 1–7 are from Phase 1; rules 8–15 were added in
Phase 4 ("Expand Windows DFIR Triage Coverage") — see that section below
for the artifact coverage that feeds them.

### 1. `office-spawns-powershell`

Fires once per `process_create` event whose parent process is a common
Office application (Word, Excel, PowerPoint, Publisher, Outlook, OneNote,
Acrobat) and whose own process is a PowerShell host. Severity `high`,
confidence `medium`. Maps to **T1059.001** (PowerShell) and **T1204.002**
(User Execution: Malicious File).

### 2. `powershell-encoded-command`

Fires on any PowerShell `process_create` command line or `4104`
script-block event whose text matches one or more of seven suspicious
indicator patterns (encoded-command flag, `FromBase64String`, hidden
window style, no-profile execution, a network-download cmdlet,
`Invoke-Expression`/`IEX`, execution-policy bypass). Severity escalates
to `high` at 2+ matched indicators; the finding's description lists
exactly which indicators matched, by name. Maps to **T1059.001** and
**T1027** (Obfuscated Files or Information).

### 3. `new-registry-run-key`

Fires once per `registry_run_key_set` event. Severity/confidence starts
at `low`; escalates to `high`/`medium` if the Run key's target executable
path is under a user-writable/non-standard directory (`%AppData%`,
`%Temp%`, `%ProgramData%`, `Users\Public`, `Downloads`). Maps to
**T1547.001** (Registry Run Keys / Startup Folder).

### 4. `new-scheduled-task`

Fires once per `scheduled_task_created` event. Same severity escalation
logic as above, plus escalation when the task's action invokes a known
scripting host/LOLBin (`wscript`, `cscript`, `mshta`, `regsvr32`,
`rundll32`, `certutil`, `bitsadmin`, `cmd`, or a PowerShell host). Maps to
**T1053.005** (Scheduled Task).

### 5. `suspicious-process-chain`

Fires when a PowerShell host or `cmd.exe` spawns a child process whose
path is under a suspicious directory, or which is itself a known
scripting host/LOLBin. Severity `high`, confidence `medium`. Maps to
**T1059** and **T1059.001**.

### 6. `brute-force-then-success`

Groups `logon_failure` events by `(host, user)`, forms contiguous bursts
where consecutive failures are no more than 10 minutes apart, and fires
when a burst reaches at least 3 failures **and** is followed by a
`logon_success` for the same `(host, user)` within 30 minutes of the last
failure. All failures in the burst plus the success event become the
finding's supporting evidence. Severity `high`, confidence `high` (a
multi-event temporal+entity pattern, not a single weak indicator). Maps
to **T1110** (Brute Force) and **T1078** (Valid Accounts).

### 7. `execution-persistence-temporal`

For each persistence event (`registry_run_key_set` or
`scheduled_task_created`), looks for the *single best* prior execution of
the same target executable — preferring an authoritative
`process_create` (Security 4688) match over a `prefetch_execution` match
— on the same host within 15 minutes. One finding per persistence event
(not one per matching execution event, which would otherwise
double/triple-count when both a 4688 and a Prefetch record exist for the
same binary — see the `bestExecutionMatch` helper). Severity `critical`,
confidence `high`: execution immediately followed by persistence for the
*same* binary is a strong, hard-to-explain-away pattern. Maps to
**T1547.001** or **T1053.005** depending on the mechanism, plus
**T1059.001** when the executing process was a PowerShell host.

## Phase 4 additions

Phase 4 expanded artifact coverage (see `docs/data-model.md`'s "Phase 4
artifact coverage" section for the new Event IDs/Sysmon events/fields
this feeds from) and added eight new rules. Every new rule follows the
same philosophy as rules 1–7 above: a single weak indicator is reported
as an observation at low severity/confidence, never a verdict, and
severity only escalates with real corroboration (a suspicious path, a
matched command-line indicator, or a second finding/correlation).

### 8. `office-spawns-script-interpreter`

The non-PowerShell sibling of rule 1: fires when an Office application
spawns `cmd.exe`, `wscript.exe`, `cscript.exe`, or `mshta.exe`. The ATT&CK
sub-technique is chosen from real evidence, never the process name alone
— `cmd.exe` → **T1059.003**, `mshta.exe` → **T1218.005** (both
unambiguous), and `wscript.exe`/`cscript.exe` are inspected for a
`.vbs`/`.js`/`.jse` file argument to choose **T1059.005** vs **T1059.007**;
if that's inconclusive, only the parent **T1059** is used rather than
guessing. Severity `high`, confidence `medium`; also maps **T1204.002**.

### 9. `suspicious-parent-child-lineage`

Extends rule 5's PowerShell/`cmd.exe`-parent check to three more parent
processes with atypical child-spawning behavior: `services.exe` spawning
a suspicious-path or script-host child (`high`, since a legitimate
service host runs a signed binary from `Program Files`/`System32`),
`explorer.exe` spawning a script interpreter (`low` alone — a user
opening a script is routine — escalating to `medium` only with a
corroborating suspicious path or command-line indicator), and
`svchost.exe` directly spawning any child process at all (`medium` alone,
`high` if corroborated — `svchost.exe` hosts DLL services and does not
normally fork children). Maps to **T1059**.

### 10. `service-persistence`

Fires once per `service_install` event (System 7045). Same
low→high-on-suspicious-path/script-host escalation as rules 3/4. Maps to
**T1543.003** (Windows Service).

### 11. `registry-persistence-extended`

Fires once per `registry_persistence` event (Winlogon Shell/Userinit,
IFEO Debugger hijack, AppInit_DLLs, or a service's `ImagePath`, as
classified by `internal/parsers/regpersist`). Winlogon and IFEO start at
`medium` even without a suspicious path (these locations have essentially
no legitimate everyday use for most software, unlike a Run key), escalating
to `high` with one. Maps to **T1547.004** (Winlogon Helper DLL),
**T1546.012** (IFEO Injection), **T1547.001** (AppInit_DLLs — still an
autostart-adjacent mechanism), or **T1543.003** (service `ImagePath`),
depending on which location matched.

### 12. `explicit-credential-use`

Fires once per `logon_explicit_credentials` event (4648). Always `low`
severity/confidence alone — RunAs, mapped drives, and scheduled "run as"
accounts all generate 4648 constantly as routine administration.
Escalation is left entirely to corroboration: see the `credential_chain`
correlation in `docs/correlation-engine.md`. Maps to **T1078**.

### 13. `privileged-logon-observed`

Fires once per `privileged_logon` event (4672). Always `low` alone, for
the same reason as rule 12 — administrator-equivalent logons are routine.
Maps to **T1078**.

### 14. `network-after-execution`

Fires when a scripting-interpreter/LOLBin process (or a process running
from a suspicious path) makes a network connection within 5 minutes of
its own `process_create` event. Severity is `medium` by default,
escalating to `high` only with a suspicious path or a matched
command-line indicator (reusing rule 2's `indicatorsIn`) — **the
destination IP/hostname and port are never inspected and play no role in
severity**, deliberately, per this phase's explicit "do not use
simplistic 'non-standard port = malicious'" instruction; only the
executing process's own behavior is judged. Maps to **T1071**, plus
**T1059.001** when the process is PowerShell.

### 15. `remote-logon-observed`

Fires on a `logon_success` event whose `logon_type` Extra field is `"10"`
(RemoteInteractive/RDP) — the one Windows LogonType value specific enough
to map to a concrete protocol. `LogonType 3` ("Network") is deliberately
*not* mapped to any `T1021.x` sub-technique, since it's shared by SMB,
WinRM, and many other protocols and can't be disambiguated from the
LogonType field alone. Always `low` — RDP administration is routine in
most environments. Maps to **T1021.001** (Remote Desktop Protocol).

### Extended: `execution-persistence-temporal` (rule 7)

Phase 4 broadened this rule's persistence-event set to also include
`registry_persistence` and `service_install` (previously only
`registry_run_key_set` and `scheduled_task_created`) — the mechanism name
and ATT&CK technique used in the finding text now come from the
`persistenceMechanism` helper, which switches on the persistence event's
type and (for `registry_persistence`) its `registry_persistence_type`
Extra field.

## Adding a rule

1. Add a new unexported type in `internal/detect/rules.go` implementing
   `Rule` (`ID() string`, `Evaluate([]model.Event) []model.Finding`).
2. Register it in `detect.All()`.
3. Use `newFinding(...)` to construct findings — it enforces the
   supporting-evidence and UTC-timestamp conventions.
4. If the rule needs a shared process/path classification (Office app,
   PowerShell host, suspicious path, ...), add it to `internal/procclass`
   rather than duplicating a literal list — `internal/correlate` shares
   that package too, and duplicated classification lists drift.
5. Reference ATT&CK technique IDs that exist in `internal/attck`'s
   registry (add new ones there first if needed — `attck.Resolve` silently
   skips unknown IDs rather than erroring, so a typo'd ID fails silently;
   test for the exact IDs you expect).
6. Add a test in `internal/detect/rules_test.go` covering both the
   trigger case and at least one case that must *not* fire.
