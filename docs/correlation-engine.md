# Correlation engine

`internal/correlate` is Tracefall's deterministic correlation engine. It
builds explicit relationships between normalized events. Like detection,
it is a pure function of the case's events — same input, same output,
every time — and it runs independently of `internal/detect`: correlation
doesn't require or depend on findings, so it stays useful for exploring
relationships the fixed detection rule set didn't happen to flag.

**The engine never invents an event or a relationship the evidence
doesn't support.** Every correlation is either a direct evidence match
(the same executable name appearing in two records) or an explicitly
defined, documented heuristic with a named time window. If a step in a
narrative isn't backed by an actual event, it's simply absent from the
correlation — never filled in with an assumption.

## The four correlation types

### `process_chain`

Links a `process_create` event to the `process_create` event of its
recorded parent. Windows Security 4688 already carries the parent
process's image name directly (`ParentProcessName`), so this is a lookup
against other process-create events on the same host with that name —
not a PID-tree walk. The match picks the *nearest preceding* instance of
the parent process, within a 2-hour window, so a stale process name
reused hours later on a busy host isn't matched incorrectly
(`nearestPreceding` in `internal/correlate/process_chain.go`).

### `entity`

Groups events that reference the same normalized executable name on the
same host **across two or more distinct artifact types** — e.g. a binary
that shows up in a `process_create` event (Windows Event Log), a
`prefetch_execution` record (Prefetch), and a `registry_run_key_set`
event (Registry). The two-artifact-type minimum
(`entityMinArtifactTypes`) exists because a name appearing in only one
artifact is just an event, not a cross-artifact linkage — this
correlation type specifically exists to surface the kind of independent,
multi-source corroboration that turns a single weak indicator into a
well-supported one.

### `temporal`

Clusters each host's events into "bursts of activity" — consecutive
events with no gap larger than 10 minutes (`temporalGap`) — and reports a
burst only if it has at least 3 events (`temporalMinEvents`) spanning at
least 2 distinct artifact types (`temporalMinArtifacts`). This is
deliberately the weakest, most general correlation type: it asserts
"these events happened close together," nothing about causation.

### `activity_chain`

Reconstructs the specific narrative from the product brief — logon →
Office → PowerShell → payload → persistence → outbound network — as far
as the evidence actually supports it, per host, starting from every
`office-spawns-powershell`-style pivot point (an Office app's
`process_create` event followed by a PowerShell `process_create` event
naming it as parent):

1. **Logon** — the most recent `logon_success` for the same
   `(host, user)` before the pivot, within 2 hours.
2. **Office execution** — the Office application's own `process_create`
   event.
3. **PowerShell execution** — the pivot event itself.
4. **Payload execution** — a `process_create` event whose parent is the
   PowerShell process, if one exists.
5. **Persistence** — a `registry_run_key_set` or `scheduled_task_created`
   event referencing the payload (or, if there was no payload step, the
   PowerShell process itself), within 2 hours after the pivot.
6. **Network** — a `network_connection` event from that same executable,
   within 2 hours after the pivot.

Each step is looked up independently and only included if found; a chain
is reported only if it has **at least 3** evidenced steps (the trivial
2-step Office→PowerShell pivot alone is already covered by the
`office-spawns-powershell` detection rule, so reporting it again here
would be redundant noise, not a new finding). Because Phase 1 has no
browser/download artifact parser, a chain will never claim a browser or
download step — it simply starts wherever the earliest evidenced step
is, which in practice is the logon or the Office execution.

See `internal/correlate/activity_chain.go`'s `latestBefore`,
`findProcessCreate`, `findChild`, `findPersistence`, and `findNetwork`
helpers for the exact matching logic behind each step.

## Adding a new correlation heuristic

1. Add a new `BuildXxx(caseID string, events []model.Event) []model.Correlation`
   function in its own file under `internal/correlate/`.
2. Register it in `correlate.Run`.
3. Give it a named constant for any time window or threshold, with a
   comment explaining the reasoning (see the existing files for the
   pattern) — a correlation heuristic without an explained threshold is
   hard for a future maintainer (or investigator) to trust or retune.
4. If it needs process/path classification, use `internal/procclass`
   rather than duplicating a list (the same package `internal/detect`
   uses, so both engines classify a process the same way).
5. Add tests in `internal/correlate/correlate_test.go` covering both a
   case where the correlation fires and a case with insufficient
   evidence where it must not.
