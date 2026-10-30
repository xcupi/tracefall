# Task Scheduler evidence context

Two deterministic, context-only correlations are available in the Correlations API and ordinary correlation cards. They do not generate findings, merge investigations, add ATT&CK techniques, increase source diversity/corroboration, or change investigation assessments. Context events remain individually available in the timeline and source drill-down.

## Recorded instance context

`task_instance_context` requires at least two distinct normalized Task Scheduler Operational records (100, 102, 200, 201, 202) carrying the same literal valid dashed instance GUID, a validated host, case and nonempty acquisition. GUID braces and letter case are comparison-only; source fields remain unchanged. Provider, channel, event ID, action and normalized outcome must agree with the shared normalizer. Memory/snapshot records, empty/duplicate actual event IDs and conflicting recorded task names or user contexts are excluded. Repeated task-level starts or completions cause abstention because separate episodes cannot safely be distinguished. Multiple action observations remain separate counts.

There is no arbitrary duration limit for a recorded instance identity. Partial lifecycles are retained: action start plus reported failure needs no invented task start. 201 records action completion, not program success; 102 does not establish that all actions succeeded; 202 reports action failure independently of the result-code spelling or its absence. A missing record is not proof a step did not occur. Contradictory names are compared case-insensitively without trimming source literals. Undated observations can share identity but have no temporal placement. Windows use known timestamps only; an all-undated group retains zero bounds and an explicit unknown-time caveat. Stable presentation order is not causal ordering.

129 has no instance identifier and is never added to an instance group by task name or proximity. Configuration records (106/140/141/142) are not execution observations.

## Recorded process context

`task_process_context` associates a normalized 129 with one observed process creation only when the actual payload `process_id` is a complete positive Windows PID (decimal or `0x` hexadecimal), and the literal full target path agrees case/slash-insensitively with the process creation's `ProcessPath`. EnginePID, basename, task name and timing alone are never identities. Both endpoints must be dated, nonmemory, within two seconds in either direction, and in the same validated case/host/nonempty acquisition. A tie or negative local interleaving does not imply causal order.

This conservative implementation abstains on **any observed competing creation of that PID in the acquisition**, even outside the two-second window, instead of choosing the nearest record or asserting a historical unique lifetime. Conflicting recorded process GUIDs and incompatible or malformed exit bounds also block the association. Unknown exits and unobserved PID reuse remain explicit limitations.

Paths are not expanded, unquoted, dot-cleaned, short-name-resolved or symlink-resolved. Drive-absolute and UNC paths are supported. Uncertain command/argument values, environment variables, dot segments, wildcard/alias syntax and unknown executable extensions are excluded; the bounded target set is `.exe`, `.com`, `.cmd`, `.bat`. This can omit legitimate context, but does not convert uncertain strings into process identity. No action text, command, user or raw result code is copied into derived prose.

## Identity and assessment boundaries

The engine adds only the scheduled-task execution type to its filtered typed inputs. Case-wide identity metadata continues to stream into compact distinct tuples, including unrelated event types and contradictory metadata. Actual endpoint-ID uniqueness is counted from references, not from synthetic identity projections. No `Load(All)` or all-case full-event retention is introduced. The investigation layer excludes both context types before grouping and before retaining context-only narrative members. Raw timeline observations, independent detections and genuine existing correlations keep their existing behavior.

Synthetic normalization, store, HTTP and restart checks are software regression proof only, not independent native EVTX fidelity or large-case resource acceptance. Native candidate validation, independent review and the serial full suite remain separate integration gates.
