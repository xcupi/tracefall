# Invocation-evidence finding selection

This policy applies only to `suspicious-process-chain`, `new-scheduled-task`
and `powershell-encoded-command`. It changes lead selection and priority, not
parsing, event retention, correlation identity or analyst adjudication.

## Recorded parent relationships

CMD self-nesting and nesting within the PowerShell host family are not selected
by ancestry alone, even when the child interpreter path is writable. They are
not classified as benign or authorized either. A self-nested child remains a
high/medium review lead when its command supplies independent encoded + hidden,
or dynamic expression + download/Base64-conversion invocation evidence.

The recognized CMD wrapper is a direct `/c` or `/k` PowerShell invocation, with
optional `/d`. Other distinct-child gates are unchanged. Descriptions state a
recorded parent relationship and do not assert payload success or actor intent.
This rule retains fixed high severity / medium confidence for selected leads.

## Scheduled task configuration

A task definition is observed configuration, not proof of actor creation,
execution or successful malicious persistence. Its registration date is
**author-recorded**, not independently verified. Unknown dates remain unknown.

Routine configuration stays on the timeline without a per-task finding. An
interpreter name, a task namespace, a system directory, or ProgramData alone
neither establishes hostility nor supplies an allowlist. Selection considers
the normalized command action, requiring agreement with its process identity:

| Action evidence | Severity / confidence |
| --- | --- |
| No-profile / execution-policy bypass only | low / low |
| Encoded, hidden, direct download or dynamic-expression invocation | medium / medium |
| Temp/AppData/Public/Downloads action target alone | medium / low |
| Hidden + writable action target | high / medium |
| Encoded + hidden; dynamic expression + download/decode | high / medium |
| Remote script/loader action | high / medium |

Remote target selection is restricted to direct script/loader invocations
(mshta, wscript, cscript, rundll32, regsvr32), not arbitrary URLs in data
arguments. A PowerShell `-File` target is read only from launch options; text
after `-Command`, encoded content, or the first `-File` is not another target.
Missing, COM-only or otherwise unsupported normalized actions are retained as
evidence without a finding, not certified safe. XML action parsing is unchanged.

The finding/catalog title is now **Scheduled Task action review**. Its rule ID
and ATT&CK mapping remain unchanged.

## PowerShell invocation indicators

Process records require both a PowerShell process identity and a matching
recorded executable invocation. PowerShell script-block events carry their own
artifact context. Options are matched as launch tokens, before command/script
arguments; `-encoding` is not `-enc`. Supported encoded forms are `-e`, `-ec`,
`-enc`, and `-EncodedCommand`. Hidden window forms include `-w hidden`, `-w 1`,
and `-WindowStyle hidden`.

The selector blanks quoted literal data and line/block comments before matching
invocation constructs. It does not interpret the script. A search for the words
IEX, DownloadString or encoded options is not itself execution of those forms.
Base64 conversion, WebClient construction and web API requests alone are not
selected. A DownloadString/DownloadFile method invocation remains a lead; a web
request cmdlet additionally requires a dynamic-expression invocation.

- No-profile and policy-bypass options, alone or together: **low / low**.
- Encoded, hidden, download or dynamic invocation: **medium / medium**.
- Encoded + hidden, or dynamic + download/decode: **high / medium**.

Repeated tokens do not count as independent corroboration. Encoded payloads are
**not decoded or executed** and are never assumed benign. A record does not
prove a command completed, downloaded code ran, or activity was authorized.
Command-derived descriptions use `cmdsem.Redact` before truncation.

## Contracts and historical decisions

Only these three rules use the new selectors. Shared `procclass` and the legacy
indicator helper used by other rules are unchanged. The old task-only substring
predicate was retired. Inputs remain process creation, PowerShell script blocks
and scheduled-task configuration, as appropriate. Tests compare full versus
declared-filter evaluation and exercise `RunFrom`, shuffled input and tied or
unrecorded times. The affected event-level outputs use time/ID tie-breaks.

Single findings retain IDs derived from case, rule and supporting events, even
when their title, description or priority changes. Reanalysis can remove IDs
from current results. Existing decisions on retained IDs still apply; removal
is not an analyst clearance. Preserve historical analysis/exports when reviewing
changed classifications. No decision migration or backfill was added.

Investigation facets remain ancestry/execution, scripting and persistence
mechanism review, respectively. No grouping/scoring, static UI category or
ATT&CK registry changes were needed. API tests verify investigation readback and
that reports carry the task-configuration and execution-limit caveats.

## Verification and limits

Tests use neutral synthetic commands, no network requests or payload execution.
Paired controls cover self-nesting versus independent hostile invocation,
renamed routine tasks versus suspicious actions in a stock-looking namespace,
system-directory hostile actions, unknown encoded content, missing context,
literal/comment searches, web API calls, and credential-safe finding/report
text. The old undated-task test now uses a selecting action; the writable-target
control explicitly expects a medium/low lead instead of path-only high.

The selector is deliberately lexical, not a complete PowerShell/CMD grammar or
data-flow analysis. It does not resolve arbitrary aliases, dynamic command
construction, interpolation, all here-string forms, additional wrapper levels,
or every executable/loader syntax. Separate constructs in one recorded script
are not proof of a shared executed data flow. Unselected events remain available
for investigation. These limitations are not evidence of benignness.

Focused validation commands (use an explicit scratch `GOCACHE`, `GOPROXY=off`):

```text
go test ./internal/detect ./internal/investigate ./internal/correlate ./internal/procclass ./internal/cmdsem ./internal/report ./internal/artifacts -count=1 -timeout 10m
go test ./internal/api -run 'TestAnalyze_|TestScenarioF_PowerShellDownload|TestReport_|TestUI_' -count=1 -timeout 15m
go test -race ./internal/detect ./internal/investigate ./internal/correlate ./internal/cmdsem -count=1 -timeout 10m
go test -race ./internal/api -run 'TestAnalyze_InvocationNoiseControlsAndReport|TestReport_NewEvidenceDetailsAreReadableAndCommandsAreRedacted' -count=1 -timeout 5m
go build ./...
go vet ./...
git diff --check
```

Private software proof compares frozen-baseline and candidate binaries against
the same normalized SQLite snapshot, with ordered event/observation hashes and
stable-event-set deltas. It does not establish native-reader fidelity, whole-case
examination completeness or false-positive accuracy. Full-suite integration and
independent review remain separate gates; this work does not merge or publish.
