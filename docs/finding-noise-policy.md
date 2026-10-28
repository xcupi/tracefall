# Conservative invocation finding priority

Applies only to `suspicious-process-chain`, `new-scheduled-task` and
`powershell-encoded-command`. Changes priority and derived descriptions, not
parsing, raw event retention, correlation identity or analyst adjudication.

## Classification contract

A bounded lexical selector is not an interpreter. Failure to recognize a form
is **uncertainty, not proof of benignness**. The selector distinguishes:

1. **Selected evidence:** affirmative supported invocation/target labels, whose
   priority is calibrated independently below.
2. **Known context:** supported literal/comment/script-argument boundaries or
   routine configuration. Task observations remain low/low findings; known
   PowerShell quoted data/comments and `-File` arguments do not by themselves
   select that rule.
3. **Uncertain:** unsupported syntax, missing host-option values, mismatching
   recorded invocation identity, incomplete lexical quoting/comments, here-string
   forms or indirect/call-operator forms. If the original baseline PowerShell
   keyword predicate matched, preserve a low/low keyword lead with an explicit
   uncertainty reason. Independently recognized stronger indicators retain their
   priority; uncertainty never upgrades a keyword to execution evidence.

This is the authorized conservative redesign, replacing the earlier drop-on-no-
selector policy. More low-priority context is intentional, not evidence that
those commands were malicious. No-profile/bypass combinations, repetition and
Base64 conversion alone are not independent hostile evidence. No baseline
keyword and no supported positive behavior means no new PowerShell finding.
An unquoted search keyword can conservatively remain low/low; no claim of
execution is made. Known quoted search data and comments remain negative controls.

## Decision matrix

| Evidence | Severity / confidence |
| --- | --- |
| Interpreter self-nesting alone (including missing command) | low / low |
| Task configuration, routine/unknown/missing normalized action | low / low |
| No-profile/bypass alone; uncertain baseline keyword lead | low / low |
| Known encoded payload, hidden option, download/dynamic invocation | medium / medium |
| Task mshta/rundll32 `javascript:` or `vbscript:` action target | medium / medium |
| Task Temp/AppData/Public/Downloads executed action target alone | medium / low |
| Encoded + hidden; dynamic + download/Base64 conversion | high / medium |
| Task hidden + writable target; remote supported loader target | high / medium |
| Existing distinct-child script-host/non-standard-path ancestry gate | high / medium |

A task definition is an observed configuration, not proof of actor creation,
execution or malicious persistence. Task-file registration dates are author-
recorded, not independently verified. Missing normalized action is named as
missing; neither target nor intent is invented. A task name, system directory or
ProgramData neither proves hostility nor grants an allowlist.

CMD→CMD is retained at low/low without stronger evidence. PowerShell-family
self-nesting also retains low/low. This family treatment can add leads compared
with the frozen baseline; it must not be described as merely retaining all old
PowerShell→PowerShell results. Strong nested invocation raises priority, not
proof of outcome. Existing distinct-child gates remain unchanged.

## Supported forms and boundaries

- PowerShell host identity accepts bare names and quoted/unquoted paths using
  backslash or forward slash. Launch options stop at `-File`/implicit script
  arguments or `-Command` text; data arguments are not host switches.
- Encoded aliases `-e`, `-ec`, `-enc`, `-EncodedCommand`, plus unique
  `-encodedc...` prefixes; window `-w`/`-wi...`; policy `-ep`/`-ex...`; command
  `-c`/`-com...` are recognized. These are bounded explicit parameter families,
  not arbitrary prefix guessing. Colon-value forms are recognized. An encoded
  payload remains opaque; flag order does not create independent corroboration.
- Recognized host metadata options consume a value. Unknown switches/missing
  values stop scanning, preserving uncertainty rather than scanning their data.
- Script-block records recognize one nested unquoted PowerShell host at a
  lexical command position. Quoted/commented host names and search arguments
  are not nested launches. This supported behavior can add previously unselected
  script leads; it is not advertised as baseline parity.
- Task action and normalized process identity must agree for positive target
  evidence. WSH selects its first script after supported switches; mshta and
  rundll32 select their first loader target. Their inline active-code schemes
  are affirmative medium/medium leads, not just fallback. Subsequent literal
  arguments do not become inline actions.
- Regsvr32's DLL is independent of its `/i:` argument; the install target is
  assessed as a loader target only with scrobj.dll. URL/UNC data supplied to an
  unrelated DLL does not earn remote-loader priority.
- Task `cmd /c` or `/k` (optional `/d`) supports one direct command position,
  including the outer quoting form. PowerShell `-Command path.ps1` and
  `-c "& 'path.ps1'"` select the first script target. `Write-Output path.ps1`
  and later script arguments do not become executable targets.
- Literal/comment masking preserves token boundaries and backtick escapes.
  `foo#bar`/`foo<#bar#>` are not comments. Here-strings and incomplete lexical
  forms are not certified data by a failed selector; baseline keyword leads
  remain uncertain.

No command, script, decoder or payload is executed by these selectors or tests.
Separate constructs in one script are not proof of executed shared data flow.
Arbitrary aliases, dynamic construction, interpolation, arbitrary wrappers and
complete PowerShell/CMD/loader grammars remain unsupported. The fallback is a
baseline-retention policy, not universal detection of unknown syntax.

## Derived-output privacy and identity

`cmdsem.Redact` masks HTTP(S) URL userinfo in command-derived output before
truncation, including percent-encoded user/password characters. The URL host,
path and query remain; ordinary emails and path/query `@` are not userinfo.
Stored `Event.CommandLine` is unchanged. The common helper remains best-effort
known-shape redaction, not a guarantee that sensitive attachments are sanitized.

One finding per affected rule/event is deterministic (time then event ID).
Single findings keep IDs derived from case, rule and supporting events even
when title, prose or priority changes. Existing analyst decisions on retained
IDs remain applicable; removed literal-data findings are not analyst clearance.
The catalog titles are **Scheduled Task action review** and **PowerShell
command/script review**. Rule IDs and ATT&CK mappings are unchanged.

## Verification scope

Tests explicitly update earlier no-finding task and self-nesting expectations
for the approved low/low retention policy; strong positive expectations are
kept, and data-only task arguments must not earn target/invocation priority.
Tests exercise direct/filtered inputs, RunFrom, deterministic output, stable
IDs, the three supported-form regressions and finding/report redaction while
checking stored synthetic commands remain unchanged.

Private compiled proof uses the same immutable normalized SQLite snapshot and
one sequentially reused working database, never a second extracted-evidence
copy. Ordered event and observation row digests must match before and after.
Persisted finding deltas use rule + event set, not title. Reports and
investigations are read back through API, with no provider/IOC transmission.
These are software and priority-change proofs, not native-reader fidelity,
whole-case completeness or false-positive accuracy measurements. Full-suite
integration and independent review are separate parent gates; no main merge
or push is performed here.

Syntax references: [Windows PowerShell host](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1),
[pwsh host](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_pwsh?view=powershell-7.5),
[PowerShell comment boundaries](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_comments?view=powershell-7.5),
[WSH](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wscript),
[regsvr32](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/regsvr32),
[rundll32](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/rundll32).
These document syntax, not the outcome of any recorded command.
