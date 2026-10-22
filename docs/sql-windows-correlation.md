# Evidence-linked SQL / Windows correlations

## Status and scope

Two deterministic relationship types are registered in `correlate.Run` / `RunFrom`:

- `sql_client_connection`: one recorded SQL client-connection GUID, an independently sourced Windows/client diagnostic record, and a Windows process-creation/lifetime record.
- `sql_os_execution`: a literal SQL OS-command request, an identified server `sqlservr.exe` lifetime, and an actual Windows process-create record with matching command content and parent identity.

These are **correlations, not causal or maliciousness findings**. A request or permission check is not an execution event. No detection rules are added. Generic UI type fallback remains usable; no model/parser/normalization/dedup/artifact changes are required here.

The implementation is `internal/correlate/sql_to_windows_rules.go`: the requested name ending `_windows.go` would be selected only for GOOS=windows and silently excluded on Linux forensic-analysis hosts.

Validation is synthetic input through the actual `Run` filtered-source path, plus focused builder/filter parity. This does not validate a SQL reader, an existing client diagnostic parser, real SQL Audit/XE field fidelity, real Windows lifetime extraction, or real-evidence end-to-end operation. The diagnostic schema below is an **explicit integration contract**, not a claim that a reader already emits it. Existing parsers must not be relabelled merely to satisfy a join.

## Input contract and identity trust boundary

Every cited record needs nonempty event ID, case ID equal to the requested case, collection ID, established Host, source-file ID, source reference and its own known timestamp. Memory-analysis artifacts and `timestamp_basis=memory_snapshot` are excluded. Host must come from the collection's evidence, not from SQL `client_hostname`, an examiner path, DNS guessing, or case-wide inheritance. No cross-collection join is attempted, even for recollections or established same-machine observations.

SQL pairs are exact:

| ArtifactType | EventType |
|---|---|
| `mssql_extended_events` | `mssql_xe_event` |
| `mssql_audit` | `mssql_audit_event` |

`mssql_errorlog` and `mssql_agent_log` can provide investigation context, but **cannot substitute for those SQL records or establish a Windows execution edge**. This change does not consume core logs as process/instance proof.

SQL `Extra` fields consumed: `sql_instance`, `sql_client_connection_id`, `sql_server_pid`, `sql_statement`, `sql_outcome`. The reader's other fields (`sql_session_id`, `sql_client_pid`, `sql_client_hostname`, `sql_client_ip`, `sql_action`, `sql_outcome_basis`, `sql_activity_id`, `sql_activity_sequence`) remain immutable context; none is silently converted to a process identifier or success/causation claim.

### Exact client connection relationship

The client diagnostic must independently identify its Windows process and carry:

- EventType `mssql_client_diagnostic`, ArtifactType `windows_sql_client_diagnostic`;
- Host = the collected **client** machine, PID = the diagnostic emitter's observed Windows PID;
- `Extra.process_guid` = that process's recorded GUID;
- `Extra.sql_client_connection_id` = the driver diagnostic's actual connection ID, not a generic UUID;
- `Extra.sql_server_host` and `Extra.sql_instance` = the independently identified server role and instance, exactly matching SQL Host/instance. The adapter must not derive these from SQL client-supplied hostname/app/PID fields; a connection-string hostname alone is not authenticated host identity.

The SQL record is on the **server** host. Its source file must differ from the diagnostic source file; relabelling the same SQL file is not independent corroboration. The diagnostic's process-create record must be a Windows event-log process create, in the client host/case/collection, with equal PID and ProcessGuid. Both trace timestamps must fall strictly inside that process's recorded start/end lifetime. No relative ordering of client and SQL trace records is narrated.

Connection IDs and process GUIDs are separate schema fields. Accepted GUID text is exactly the standard unbraced 8-4-4-4-12 hexadecimal shape, nonzero; comparison ignores hexadecimal case but never trims or repairs malformed identifiers. Definition UUIDs, audit UUIDs, ProcessGuid, activity GUIDs, SQL sessions and bare client PIDs are not connection IDs. There must be exactly one client diagnostic for the connection within the case/collection; multiple diagnostic rows, even for the same process under distinct event IDs, conservatively abstain. This is intentionally stricter than aggregating a multi-record driver trace.

Activity-only joins are **not implemented**, even with equal GUID/sequence strings. Sequence/transfer provenance must first be demonstrably preserved by both readers before a future implementation can safely use it. Missing connection ID does not fall back to an activity ID.

### SQL request / Windows process relationship

The SQL record must name `Extra.sql_server_pid` as the exact canonical positive decimal Windows PID. It is never `sql_client_pid` or SPID/session ID. A Windows process-create record on the same server Host/case/collection must name `sqlservr.exe`, that PID and the same nonempty `Extra.sql_instance`. Instance attribution on the Windows record must be independently established by an adapter/enrichment source; this rule never infers it from a bare PID, a file name or an arbitrary SQL statement.

The parent needs its own process start timestamp and RFC3339Nano `Extra.exit_time`. Both SQL timestamp and child creation must lie strictly inside that bounded lifetime. At both instants any overlapping, tied, unbounded or undated competing process with the same scoped PID or ProcessGuid blocks the relationship. Nonoverlapping, fully bounded historical PID reuse does not by itself block it. Memory snapshot processes cannot supply identity.

The child must be a real Windows event-log process create on that same server/case/collection, with a positive different PID and either:

- recorded PPID equal to the server PID, with a uniquely bounded parent lifetime; or
- a valid nonzero `Extra.parent_process_guid` equal to the parent's recorded ProcessGuid.

A recorded contradictory PPID, GUID or parent name blocks the relationship; a matching GUID never overrides a conflicting PPID. Missing PPID **and** GUID abstains. SQL and child must have different source files.

Only one literal invocation is understood: `EXEC [master..|sys.|dbo.]xp_cmdshell [N]'literal' [;]` (the prefix, N and semicolon are optional; SQL keywords are case-insensitive). SQL doubled single quotes are decoded; otherwise command bytes are preserved exactly. Variables, comments, quoted/bracketed identifiers, multiple statements, SQL Agent job names, statement mentions, arbitrary batches, `EXECUTE` spelling and other launch mechanisms are not interpreted.

The child must name `cmd.exe` with CommandLine **exactly** `cmd.exe /c ` plus that decoded literal, including command case and whitespace. Full-path/quoted shells, alternate switches and equivalent shell commands are deliberately not normalized. SQL timestamp must strictly precede child creation by at most five seconds. This is a consistency ceiling, not a proximity-based identity rule or a claim about completion time. Tied timestamps do not establish order. Competing matching SQL requests or child process creates produce no edge rather than choosing the nearest event.

Understood non-denial `sql_outcome` values are empty, `unknown`, `permission_allowed`, `allowed`, `success`, `succeeded`. Every other value, including denied/failed outcomes and unrecognized vocabulary, abstains. These values are never narrated as operation completion: in particular Audit permission success remains only a permission check, regardless of `sql_outcome_basis`. A positive edge still requires the independent Windows process create. New reader outcome vocabularies require explicit review.

## Determinism, provenance and privacy

Repeated delivery of an identical event ID and record is collapsed locally, without changing model dedup behavior. Conflicting versions of any relevant event ID block this builder's output. Relevant inputs are SQL events, the explicit diagnostic event type and process creates; unrelated event types do not affect the result. Unique input records are sorted by ID before matching. Citations use fixed roles: parent/client-process, SQL record, diagnostic/child. `Run` derives stable correlation IDs from those citations. Caller slices/maps and raw evidence remain untouched.

Descriptions deliberately contain **no command or SQL statement content at all**. This omission policy is stronger than best-effort pattern redaction and cannot leak an unrecognized credential syntax copied from those fields. It does not redact the immutable source records or attachments; authorized analysts inspect the cited evidence for full content. Titles are fixed strings too.

## Deliberate false negatives / abstention gates

Expect no edge for missing case/collection/established host/instance/provenance, unknown times, absent lifetime ends, source aliasing, malformed/zero/braced GUIDs, diagnostic schema gaps, missing serverPID, lifetime contradictions, parent ambiguity, conflicting PPID/GUID/name, denied or unrecognized outcomes, multiple matching requests/children, any unsupported SQL/shell syntax, delay beyond five seconds, or activity-only/endpoint/IP/name/session/time-only evidence. Cross-host trace clock uncertainty is not estimated or corrected here: adapters must preserve correct timestamp bases; uncertain/undated local readings must not be promoted to instants. No source absence is evidence that activity never occurred.

These strict gates mean native process-create records without a separately established exit time/instance, and SQL traces without the server process identity, generally cannot produce an execution edge. This implementation does not fill those missing fields. The client diagnostic adapter and trustworthy lifetime/instance enrichment remain parent-integration prerequisites, not hidden substitutes in this correlator.

## Verification

Feature slices were run RED (assertion failure in a compiling package) then GREEN: strong client connection, identity gates, ambiguity/duplicate stability, strong OS execution, execution gates, GUID parent with PPID contradiction, lifetime contradictions and declared-input parity. Privacy/immutability, activity-only abstention and OS duplicate/reversed-input checks exercise the shared paths as additional regressions.

Focused commands:

```
go test ./internal/correlate -count=1
go test -race ./internal/correlate -count=1
go vet ./internal/correlate
```

No full suite, network acquisition, real samples or SQL/server starts are required or claimed by these checks.

## Authoritative semantics

- Microsoft, [Data tracing in ADO.NET](https://learn.microsoft.com/en-us/sql/connect/ado-net/data-tracing?view=sql-server-ver17): client connection ID tracing between client and server; capture requirements and limits.
- Microsoft, [Accessing diagnostic information in the Extended Events log](https://learn.microsoft.com/en-us/sql/relational-databases/native-client/features/accessing-diagnostic-information-in-the-extended-events-log?view=sql-server-ver15): diagnostic connection IDs and activity identity/sequence context, not interchangeable UUIDs.
- Microsoft, [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon): process creation, ProcessGuid for process correlation despite PID reuse, process termination and separately configured network connection telemetry. Sysmon ProcessGuid is not SQL ClientConnectionID.
- Microsoft, [sys.fn_get_audit_file](https://learn.microsoft.com/en-us/sql/relational-databases/system-functions/sys-fn-get-audit-file-transact-sql?view=sql-server-ver17) and [SQL Server Audit records](https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-records?view=sql-server-ver17): session/connection fields vary by platform/version; for non-login events `succeeded` describes a permission check, not operation completion or OS effects.

Design was cross-checked against the offline reader research report's “Safe deterministic SQL → Windows joins” section. Research feasibility is separate from production reader acceptance and from this synthetic correlator validation.
