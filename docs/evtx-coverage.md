# EVTX coverage: what is mapped, what is not, and why

Every Windows event record reaches Tracefall through one table,
`internal/parsers/winevent`. The raw `.evtx` reader (`internal/parsers/evtx`)
and the EvtxECmd CSV parser (`internal/parsers/evtxcsv`) both call it, so a
mapping added there is gained by both and gives the same fields and the same
dedup identity from either source.

A record with no mapping is **dropped but counted**: each source file stores
`parse_coverage` (records read, mapped, unmapped, and a bounded
per-`(provider, channel, EventID)` census). **Unmapped is not benign.** It
means Tracefall has no verified layout or no analytic value for that record
kind today, nothing more.

An ID is claimed only under its exact provider **and** channel. The same
number under another provider or channel is "handled, not mapped" and the event
is left untouched. A record that does not carry the minimum fields to be
useful (for example no task name, no service name) is not mapped either.

## Mapped families (G02 tranche 1)

All of these are observations a log wrote. None names an actor unless the
record does, and none is a verdict. Each event carries `evidence_meaning` and
`limitations` in `Extra`, and the exact `event_provider` / `event_channel`.

| Provider / channel | EventID | Event type | Means | Does NOT mean |
| --- | --- | --- | --- | --- |
| Microsoft-Windows-Windows Defender / `.../Operational` | 5007 | `antimalware_configuration_change` | A Defender setting changed and the **registry path** inside Old/New Value is a security-relevant one (see rule below). | Who changed it, how, that protection is now reduced, or that the change was unauthorized. |
| same | 5004 | `antimalware_configuration_change` | A real-time protection feature configuration changed: `feature_name`, `configuration`, `feature_id` as recorded. | Enabled or disabled (the value is not interpreted), who changed it. |
| same | 1013 | `antimalware_history_deleted` | Defender deleted its stored detection history (`history_deleted_time_recorded`, user, domain, SID as recorded). | A deliberate attempt to hide evidence (Defender also purges automatically), which detections were removed, an actor. |
| Microsoft-Windows-WMI-Activity / `.../Operational` | 5860 | `wmi_activity` | A temporary event consumer started: namespace, query (bounded, redacted), client process id, machine, user. | That an event matched, that any action ran, persistence, intent. |
| same | 5858 | `wmi_activity` | A WMI client operation failed: operation id, operation text (bounded, redacted), component, result code, client process id. | What the operation was for, that it succeeded elsewhere, intent. |
| Microsoft-Windows-TaskScheduler / `.../Operational` | 107, 108, 110, 119 | `scheduled_task_launch` | The scheduler recorded launching an instance of the task because of a time trigger (107), an event trigger (108), for a user (110), or a user's logon (119). | That the task's action ran or succeeded (see 100/129/200/201/202), or an actor. |
| same | 322 | `scheduled_task_launch` | The scheduler did **not** launch the task because an instance was already running. `existing_instance_id` is the instance that was already running. | Any run. |
| System / `Service Control Manager` | 7031 | `service_message` | A service terminated unexpectedly: `service_name`, `termination_count`, `corrective_action_delay_ms`, `recovery_action_code`, `recovery_action`. | An attack, an actor, a cause, that the recovery action worked. |
| same | 7024 | `service_message` | A service terminated with an error: `service_name`, `service_error_ref` (a message-table reference such as `%%1234`, kept as recorded). | Same as 7031. |
| Microsoft-Windows-SMBServer / `.../Security` | 551 | `smb_security_event` | The SMB server rejected a session authentication: client address/name, user, session id, status, translated status, SPN, reason code. | A logon, a valid account, password guessing, intent. |
| same | 1009 | `smb_security_event` | The SMB server denied anonymous access to the client. | A logon, what the client wanted, intent. |
| Security / `Microsoft-Windows-Security-Auditing` | 4703 | `token_right_adjusted` | Privileges in the target account's token were enabled/disabled by the process shown. | Privilege escalation or misuse; routine for services. |
| same | 4689 | `process_exit` | A process with this ID and image path exited, with its exit status. Carries the same `pid`, `logon_id` and `process_path` keys as a 4688 so a reader can match them. | When it started, which creation it belongs to (no join is made; process ids are reused). |
| Microsoft-Windows-PowerShell / `.../Operational` | 4100 | `powershell_pipeline_error` | An error was raised while a pipeline executed; host, command, script and error text (bounded, redacted). | A command that ran, script content, intent. |

Sources for the meanings (Microsoft wording, retrieved while this was built):

- Task Scheduler event table
  `learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd363625(v=ws.10)`:
  107 "Task Scheduler launched the "%2" instance of task "%1" due to a time trigger.";
  108 "...The task was triggered by an event trigger."; 110 "...instance of task "%1" for user "%3" .";
  119 "Task Scheduler launched the "%3" instance of task "%1" due to user "%2" logon.";
  322 "Task Scheduler did not launch task "%1" because instance "%2" of the same task is already running."
  The observed field order (110: `TaskName`, `InstanceId`, `UserContext`; 119: `TaskName`, `UserName`,
  `InstanceId`) matches the placeholders.
- Service Control Manager
  `learn.microsoft.com/es-mx/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc756361(v=ws.10)`:
  7031 "The %1 service terminated unexpectedly. It has done this %2 time(s). The following corrective action
  will be taken in %3 milliseconds: %5."; 7024 "The %1 service terminated with service-specific error %2."
  Real records add `param4` (the recovery action code, beside its text in `param5`); in 7024 `param2`
  is a `%%NNNN` message-table reference.
- Defender
  `learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus`:
  5007 "The antimalware platform configuration changed." (Old value / New value); 5004 "The real-time
  protection configuration changed." (Feature, Configuration); 1013 "The antimalware platform deleted history
  of malware and other potentially unwanted software." (Time, User).
- SMB server `learn.microsoft.com/en-us/answers/questions/937522` (event text quoted by users):
  551 "SMB Session Authentication Failure"; 1009 "The server denied anonymous access to the client."
- Security `learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4703`
  (token privileges enabled or disabled) and `.../event-4689` ("every time a process has exited").
- WMI-Activity 5858: the user-posted message text in
  `learn.microsoft.com/en-us/archive/msdn-technet-forums/d0b5dd30-d53c-4641-9df3-400d5f41f1eb`
  ("Id = ...; ClientMachine = ...; User = ...; ClientProcessId = ...; Component = ...; Operation = ...;
  ResultCode = ...; PossibleCause = ..."). 5860's meaning rests on the record's own element name
  `Operation_TemporaryEssStarted` and its fields; no Microsoft page was found that documents it.

### Defender 5007: which changes are mapped

5007 is very frequent and almost all of it is the platform writing its own bookkeeping. A 5007 is mapped
only when the registry-value **path** (the text before ` = `) of Old Value or New Value is, under one of
the Defender roots (`HKLM\SOFTWARE\Microsoft\Windows Defender\`,
`HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\`, or the platform's `Default\`), one of:

- an entry under `Exclusions\Paths\`, `Exclusions\Extensions\`, `Exclusions\Processes\`,
  `Exclusions\IpAddresses\`, or the policy values `Policy Manager\ExcludedPaths/Extensions/Processes`
  (what Defender is told not to inspect);
- an explicit toggle: `DisableAntiSpyware`, `DisableAntiVirus`, `DisableRoutinelyTakingAction`,
  `Real-Time Protection\Disable{RealtimeMonitoring,BehaviorMonitoring,OnAccessProtection,IOAVProtection,ScriptScanning,RawWriteNotification}`,
  `SpyNet\{SpynetReporting,SubmitSamplesConsent,DisableBlockAtFirstSeen}`, `MpEnablePus`, `PUAProtection`,
  `Features\TamperProtection`.

It is an exact list, not "any value named Disable*": engine-internal flags with such names (for example under
`NIS\Consumers\`) are written by the platform. The data after ` = ` and any name in a foreign key never decides
relevance. Old/New Value are stored bounded (512 bytes, `*_truncated` when cut) and redacted.
The old/new data is kept without interpretation; the rule says "this setting changed", not "protection is off".

## Deliberately unmapped

| What | Why |
| --- | --- |
| Security 5156, 5157, 5158 (Filtering Platform) | Tens of thousands of rows in one log; needs an aggregation design, not one event per row. |
| Security 4656, 4658, 4690 | Handle operations: very high volume, no standalone meaning. |
| DistributedCOM 10016, 10010, 10028 | Permission/activation noise. |
| Defender 1000, 1001, 1150, 1151, 2000, 2010 | Scan, health and signature-update housekeeping. |
| Defender 5007 (anything not in the rule above) | Platform bookkeeping; counted, not mapped. |
| WMI-Activity 5857 | "Provider loaded": routine. |
| Windows Error Reporting 1001, SQL Server Integration Services 12288/12289, storage drivers, FailoverClustering, GroupPolicy, VDS, LsaSrv | Out of scope of this tranche. |
| PowerShell 8196, 12039, 40961, 40962, 53504 | Lifecycle noise. |

## Deferred (no verified layout)

| What | Why |
| --- | --- |
| SMBClient 31010, 31002 (provider `Microsoft-Windows-SMBClient`, channel `Microsoft-Windows-SmbClient/Security`) | The only SMB client log available held no record of either ID (its only record kind was 31001, 32 records), so there was no real layout to check. Published event text exists but a layout from memory is not mapped. |
| Defender 5001, 5010, 5012, 5861 | No real record in the available logs. |
| Defender 5007 exclusion/toggle positive branch | The rule is implemented and tested on constructed records, but **no real 5007 in the available log matched it**, so it has not been checked on a real positive. |

## Verification performed

Against 10 real native logs (read-only, hashed before and after; the same hashes) and an independent decoder
(python-evtx, walking every physical chunk because one log was not closed cleanly and its header under-counts
chunks):

- Record census: the reader and the independent decoder agree on all 193,467 records in 268
  `(provider, channel, EventID)` kinds, 0 differences.
- Mapped records before / after this change: 99,703 / 111,703 of 193,467 (unmapped 93,764 / 81,764,
  48.5% / 42.3%). The 12,000 newly mapped records are exactly: 107 ×1,320; 108 ×9; 110 ×101; 119 ×129;
  322 ×6,223; 551 ×415; 1009 ×355; 5004 ×8; 1013 ×198; 5860 ×12; 5858 ×82; 7031 ×289; 7024 ×288;
  4703 ×1,988; 4689 ×336; 4100 ×247. Each equals the independent count of that ID.
  5007: 4,242 records, 0 mapped; an independently written rule also finds 0 security-relevant paths.
- Field comparison, up to 20 sampled records per ID (all of them where fewer exist): every decoded Data value
  equals the independent decoder's value, 0 mismatches. Differences in rendering that were reconciled by
  rule: hex numbers without zero padding, GUID letter case, binary values as hex vs base64, whitespace layout
  of multi-line text.
- Still unmapped, top of the list (kind: unmapped records): Security 5156: 22,575; PowerShell 8196: 12,016;
  PowerShell 12039: 12,016; Defender 1151: 6,056; Defender 1150: 5,802; Defender 5007: 4,242;
  DistributedCOM 10016: 4,056; Security 4658: 1,894; WMI 5857: 1,629; DistributedCOM 10010: 1,509;
  Security 4656: 1,151; Security 4690: 947; PowerShell 53504: 691; PowerShell 40961: 676;
  PowerShell 40962: 673.
- Compiled binary through the isolated import worker on a staged copy of those 10 logs, in a disposable data
  dir on a loopback port: discovered 10 files, imported, analyzed, read back sources/coverage/findings/
  correlations through the API, restarted the server and read back identical results, requested `report.html`;
  the server was killed and the port confirmed closed. A base-commit binary on the same files gave the same
  249 findings with identical supporting-event identities (by dedup hash) and the same 2,277 correlations.
  None of the new event types is cited by any finding or correlation.
- Unit/behaviour tests: positive and negative fixtures per ID (wrong provider, wrong channel, under-specified
  record, absent versus recorded empty/dash/zero), native/CSV parity of fields and dedup hash, dedup
  distinctness and recollection collapse, and pinned historical hashes of existing Windows events computed
  with the base commit's code. Mutation checks (provider gate removed, 5007 rule inverted or widened,
  positional index shifted, dedup field dropped, redaction removed, ...) are caught by a test. An independent reviewer ran 55 further mutations: 47 were killed, 1 was an invalid build, and 7 survivors exposed 6 missing tests (three dedup-identity fields, WMI 5858 operation redaction, and the 1013 and 5860 limitation wording); those tests were added afterwards.
- Real-record test: `TestRealG02Coverage` in `internal/parsers/evtx` is skipped unless
  `TRACEFALL_REAL_EVTX_DIR` is set; with `TRACEFALL_REAL_PY_CENSUS` and `TRACEFALL_REAL_PY_SAMPLES` it prints
  counts and field names only.

## Not verified

- No real EvtxECmd CSV export was available for these IDs. CSV parity is tested with constructed rows in the
  `Key: Value; ...` PayloadData shape; how EvtxECmd flattens UserData families (WMI, SMB) and the multi-line
  PowerShell ContextInfo is not confirmed. The reader renders GUID letter case differently from the independent
  decoder; the CSV path may differ again, which could make one record count twice across sources.
- The 5007 positive branch, SMB 551 with a status other than the ones present, and IPv6 SMB client addresses
  were exercised on constructed records only.
- The 4689/4688 field alignment was checked on constructed records; the 4688 session id may differ from the
  4689 one (the 4688 field is the creator's session), so a real pairing must not require equal `logon_id`.
- No detection rule consumes the new event types. Entity and temporal correlation builders read every
  event, so a case with the new events can place them in those correlations; none was produced in the
  examined set.
