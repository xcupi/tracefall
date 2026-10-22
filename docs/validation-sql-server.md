# SQL Server validation against engine-produced evidence

This records what was checked against files written by a real SQL Server engine,
what that check found, and what it did **not** cover. The numbers below were read
from tool output in the validation session.

## Evidence

A SQL Server 2022 Developer instance (16.0.4305.5, Linux container, UTC) was
started with SQL Agent enabled, and a scripted sequence of actions was run
through `sqlcmd` while the actions were logged on the client side as ground
truth: 12 failed logins from one client against three account names (5, 4 and 3
attempts), a login creation, a sysadmin role change, `sp_configure` calls,
attempts to use `xp_cmdshell`, a database and a backup, a Server Audit and an
Extended Events session writing to files, an Agent job with a CmdExec step, a
divide-by-zero error, and two log cycles. The engine's files were then copied out
unchanged (SHA-256 recorded) and imported with the built binary.

Files produced: `errorlog` plus three rotations, `sqlagent.out`,
`sqlagentstartup.log`, a Server Audit file, three `.xel` files (the default
`system_health`, the in-memory-OLTP engine file and the session created for the
test) and the default trace `log.trc`.

## Results

| Check | Result |
|---|---|
| Text logs imported (`errorlog`, 2 rotations with content, `sqlagent.out`) | 343 events: 283 `sql_message`, 47 `sql_agent_message`, 13 `sql_login_failed` |
| Failed logins by account name | attacker-style names 5 / 4 / 3 exactly as scripted; the 13th is a login attempt by the harness's own readiness polling while the engine started |
| Audit export from `sys.fn_get_audit_file` (25 rows) | 25 events, all dated (audit `event_time` is documented UTC) |
| XE exports from `sys.fn_xe_file_target_read_file` (123 + 45 events) | 168 events |
| Files not supported | `log.trc` (default trace, binary), `sqlagentstartup.log` (113 bytes of banner), the empty `errorlog.3` |
| Agent job | `sp_start_job` reported "started successfully"; the Agent log records the request (message 177) and then `Status: Failed` (message 208). A start request is not a success |
| `xp_cmdshell` | not supported by the Linux engine; the engine log records `blocked access to procedure` for each attempt. The enabled-and-executed path was therefore **not** exercised |

## Native binary files (offline reader configured)

The reader was run inside its mandatory sandbox against files copied unchanged
from the engine, and each result was compared with the engine's own reading of
the **same file**:

| File | Tracefall (binary) | Engine reading |
|---|---|---|
| Server Audit `.sqlaudit` | 25 events | 25 rows from `sys.fn_get_audit_file` |
| Extended Events session `.xel` | 123 events | 123 |
| `system_health` `.xel` (complete file) | 124 events | 124 |
| in-memory-OLTP engine `.xel` | 0 events | 0 |

For the audit file the comparison was field by field, 25 rows x 11 fields (time,
succeeded, action, principal, client address, application, database, object,
session, instance, statement): identical. Statement text differs only in line
endings (`\r\n` in the binary; the export path normalises to `\n`).
These checks are pinned by SHA-256 in `internal/parsers/mssqlxe/real_engine_test.go`
and skip unless their `TRACEFALL_REAL_MSSQL_*` variables are set.

Observations worth knowing:

- A **partial copy** of a live `.xel` (taken while the engine was still writing:
  127 KB of what became a 479 KB file) read as `complete` with **0 events**. The
  reader cannot know the file is a prefix. Collect XE files after the session is
  stopped or rolled over, and treat a zero-event `.xel` as "nothing in what was
  collected", not "nothing happened".
- Native audit stays labelled `experimental`: this is one engine version, one
  platform, one file, 25 rows. It is verified for that, not for every audit
  action, SQL Server version or Windows.

## Defects this found (all fixed, each with a regression test)

1. **No SQL detection existed.** Twelve failed logins from one client produced no
   finding. Rules were added (see `docs/detection-engine.md`).
2. **Unconfigured optional reader looked like damaged evidence.** `.xel` and
   `.sqlaudit` files failed as `internal_error` / "The file could not be parsed".
   They now fail as `optional_reader_unavailable`, which says the file is intact,
   was not analyzed, and names the settings.
3. **Audit outcome mislabelled.** The handling of user-defined audit events treated every row
   as one, because real rows always carry `user_defined_event_id`
   (value 0). Login failures and successes were relabelled as caller-supplied. The
   check is now on the `UDAU` action only. The synthetic test had used a single
   `UDAU` row and could not see this; the real row shape did.
4. **Padded action codes.** `action_id` is a space-padded `varchar(4)`; the padding is
   trimmed.
5. **Credential redaction did not cover SQL.** `WITH PASSWORD =`, `@rmtpassword`,
   connection-string `Password=`/`Pwd=`, and `sqlcmd -P` passed through
   `cmdsem.Redact` unchanged. They are now masked.
6. **Reports showed no SQL evidence fields.** A finding citing a SQL event rendered
   only a timestamp. Login, client, outcome, instance, action and statement
   (redacted) now appear.

## Not verified

- **Windows SQL Server.** The engine here ran on Linux. Windows ERRORLOG encoding
  (the Linux `errorlog` was ASCII with CRLF while `sqlagent.out` was UTF-16LE with a
  BOM), `MSSQL$instance` providers writing to the Application log, Windows
  authentication and `xp_cmdshell` effects are covered by synthetic tests only.
- **Licensing of the offline reader.** It uses a proprietary Microsoft package
  that Tracefall does not redistribute; licence clearance remains a deployment
  decision (see `tools/mssql-xe-reader/README.md`).
- **Default trace (`.trc`), `.mdf`/`.ldf`, transaction reconstruction.** Not read.
- **Time basis of `errorlog`.** The text log has no zone, so its events stay
  undated (local reading preserved). The engine writes its own `UTC adjustment`
  line at the start of the log; it is not used to derive a UTC value yet.
- **Localized messages**, other SQL Server versions, SQL Agent history tables.
- A single run on one engine version is not a version matrix.
