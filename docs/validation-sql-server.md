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
- **Native binary `.xel` / `.sqlaudit` decoding.** The offline reader needs a
  separately licensed Microsoft package and was not configured in this validation.
  The binary files above were checked only through the exports a running engine
  produces from them, which also means the *absence of a reader* was the thing
  observed for the binaries. Native `.sqlaudit` decoding remains unverified.
- **Default trace (`.trc`), `.mdf`/`.ldf`, transaction reconstruction.** Not read.
- **Time basis of `errorlog`.** The text log has no zone, so its events stay
  undated (local reading preserved). The engine writes its own `UTC adjustment`
  line at the start of the log; it is not used to derive a UTC value yet.
- **Localized messages**, other SQL Server versions, SQL Agent history tables.
- A single run on one engine version is not a version matrix.
