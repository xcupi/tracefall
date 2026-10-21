# Windows record identity and Task Scheduler clock correction

## Migration

Windows Event Log identities now include the source channel and recorded Windows
record number, source IP, command/script content, and explicit normalized
account/domain/session/group/script-fragment attributes. Task identities also
retain the Task Scheduler namespace and original local registration reading.
These changes are restricted to `windows_event_log` and `scheduled_task` artifacts;
unrelated artifact identity logic is unchanged. Historical prefetch and packet
capture hashes are pinned in the model tests.

**Reimport old evidence into a fresh case.** Existing representative rows cannot
reconstruct events previously lost to deduplication, and rehashing them cannot
recover those records. Mixing old and new identity versions in an existing case
is not a migration. There is no automatic database rewrite in this change.

`RecordNumber` in EvtxECmd CSV means the original Windows `EventRecordID`, not the
CSV row position. Decimal formatting is canonicalized, and export row order,
file path, collection identity and recovery notes are not source-record identity.
A source which omits/invalidates that number remains unknown; no number or source
instance is invented. Native/CSV parity requires equivalent recorded identity and
semantic fields. A lossy export without the Windows number cannot reliably match
a numbered native record, or distinguish otherwise identical records. Channel,
host, timestamp and semantic content scope the record number; no fictitious
log-generation identifier is inferred after log resets.

## Task clock and meaning

- A zone-less XML RegistrationInfo/Date remains undated. Its original reading,
  fractional precision and `task_registration_local_zone_unknown` basis survive
  in Extra. No examiner clock, file mtime, collection clock or assumed UTC is used.
- A date with `Z` or an explicit offset remains a true instant, normalized to UTC.
- Missing and invalid dates retain an undated task configuration, with a named
  basis and original text where present.
- Native extensionless task files under Tasks directories are discovered. Full
  decoded XML is retained as raw evidence; action and principal XML is retained
  alongside the compatible first-Exec/first-principal summary, including other
  Exec actions, working directories, group/logon details and COM handlers.
- `evidence_kind=task_configuration` and `evidence_meaning` explicitly say this is
  configuration, not execution evidence. The existing scheduled-task-create
  event classification is retained for compatibility; neither the file nor its
  author-supplied Date proves an execution or a verified creation time.

Timestamp callsite audit: scheduledtasks now uses `normalize.XMLTimestamp`.
Remaining `normalize.Timestamp` parser callers are EvtxECmd, PECmd (LastRun and
additional run times), and RECmd (key LastWrite), all UTC-by-contract EZ Tools
exports. Those formats and existing timestamp behavior are deliberately unchanged.
The new source-clock contract test covers zoned and zone-less UTC exports beside
local XML readings.

## Actual TDD results

All evidence here is synthetic with neutral identities. No real raw evidence was
used. Worktree base: `8b72d82`; branch: `fix/windows-identity-time`.

The following assertion failures were observed **before their corresponding
production fixes** (full logs retained in the scratch directory):

| RED log | Observed failure |
| --- | --- |
| `windows-identity-red.log` | Persisted two 4625 records at equal time/user/host collapsed to `map[203.0.113.1:1]` instead of both source IPs. |
| `windows-semantic-red.log` | Domain, session, record number, channel, account/group object, script block/fragment and script text distinctions collapsed. |
| `windows-parity-red.log` | Native/CSV parity exposed the missing CSV Windows record number, before adding canonical RecordNumber propagation. |
| `task-time-red.log` | Zone-less readings acquired invented UTC instants; absent/invalid dates emitted zero configurations. |
| `task-configuration-red.log` | Extensionless names were not detected; action/principal details were lost; non-task XML emitted a task. |
| `task-identity-red.log` | Distinct Task Scheduler namespace objects with equal commands collapsed, both undated and explicitly zoned. |
| `task-local-identity-red.log` | Distinct original local registration readings collapsed after removing the invented UTC instant. |

An initial test compile typo was corrected before accepting the persisted-import
RED result. The recollection fixture uses a different packaging note to avoid the
intentional whole-package duplicate rejection. An existing cross-source fixture
incorrectly labeled native record 5 as CSV RecordNumber 1; it is now correctly
labeled 5, not weakened to ignore the Windows record number.

Final GREEN commands (all exited 0):

```sh
go test ./internal/model ./internal/normalize ./internal/parsers/scheduledtasks ./internal/parsers/winevent ./internal/parsers/evtx ./internal/parsers/evtxcsv ./internal/parsers/recmd ./internal/parsers/pecmd -count=1
go test ./internal/api -run '^(TestWindowsIdentity_|TestTaskTime_|TestNative_CrossSourceDoesNotDoubleCount$)' -count=1 -v
go vet ./internal/model ./internal/normalize ./internal/parsers/scheduledtasks ./internal/parsers/winevent ./internal/parsers/evtxcsv
```

Final output: every listed parser/model/normalize package returned `ok`; all three
focused API tests passed (`ok tracefall/internal/api 7.384s`); vet emitted no
findings. Final logs: `identity-time-targeted-green.log`,
`identity-time-import-green.log`, `identity-time-vet.log` under the parent scratch
directory. The persisted Windows test verifies two source IP representatives,
positive duplicate controls within a file/across native and CSV/across collections,
and distinct raw evidence/observation provenance. The native task import verifies
three extensionless configurations: absent date and local date remain undated;
explicit-zone Date remains dated.

No full suite was run. Correlate/detect, EVTX coverage contracts, Windows server
mapping, and the main report were not changed. No real-EVTX fidelity claim is made
by these synthetic identity tests.
