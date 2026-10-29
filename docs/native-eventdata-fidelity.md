# Native EventData ResultCode fidelity

The native EVTX reader preserves the decoded string of the exact payload field
`ResultCode`. This applies to named `<Data Name="ResultCode">` entries and
`<ResultCode>` leaves in EventData/UserData, including the existing recursive
flattening path. It is independent of provider, channel, host and event ID.
A missing field remains missing; a recorded empty string remains present.
Whitespace (including Unicode whitespace, tabs and line breaks), malformed
numeric-looking strings, leading zeroes and dash tokens are not normalized by
this field's extraction policy.

This is a narrow field policy, not a blanket change to payload extraction.
Other named fields, positional Data/Binary values, System extraction, timestamp
precision, provider/channel representation and record identity keep their
existing behavior. Classic PowerShell positional consumers keep their trimming
contract. Matching the field name is exact, not a new case-insensitive alias
policy. Duplicate names and depth limits retain the existing flattening rules.

“Decoded string” does not mean the original BinXML bytes or XML serialization.
Native typed numeric substitutions continue to use the reader's existing
stringification (for example UInt32 as decimal); no original decimal/hex text is
invented for a value that was stored as a binary integer. XML entity syntax is
not recorded token syntax. The original EVTX remains the byte-level source.

## Mapping boundary

RawEvidence's resolved `event_data.ResultCode` now retains this decoded literal
for all records that the parser maps. Unmapped records remain counted rather
than acquiring a new mapping. The shared Task Scheduler Event 202 mapper copies
recorded ResultCode presence and literal text to `extra.result_code`. Its
`outcome=failure` comes from the scheduler event definition, never from numeric
interpretation: a zero, padded, malformed, missing or empty code does not turn
that failure into success or establish payload execution/effects.

The Event 201 completion path also copies ResultCode with explicit presence and
literal text, without `setExtra` trimming or empty/dash omission. Its
`action=task_action_completed` and `outcome=observed` remain unchanged: completion
is a scheduler observation, not proof of a successful program outcome. Zero,
nonzero, missing and malformed codes are retained without numeric interpretation
or new status inference. Only ResultCode changes on this path; all other field
policies and existing record semantics are unchanged.

CSV production is unchanged and explicitly deferred. CSV maps are normalized
export values, not original XML/BinXML string literals. Neither lost export
whitespace nor an original XML spelling can be reconstructed from those maps.
Do not claim arbitrary native/CSV literal parity across that boundary.

## Validation scope

Regression tests exercise actual generated native BinXML string substitutions
through parser/raw evidence and the shared mapping, including Unicode/control
padding, empty/missing, malformed numeric and XML-sensitive characters. The
same reader helper's named/nested EventData and UserData shapes are checked
separately with decoded-node unit tests, not presented as independent native
file certificates. A native UInt32 substitution checks existing decimal
stringification; Security records carrying ResultCode do not gain new mapping
semantics. A compiling Go-overlay old-trim mutation must fail a literal
assertion without changing tracked source bytes.

Acceptance proof is retained outside the repository. The reader-fix baseline
`cf688c2` retains its selected-source worker comparison, full raw/normalized
hash-row parity and 113 Event 202 failures. That existing native census/import
was not repeated for this mapper-only follow-up. It is not a new whole-source
independent-reader census or a whole-case completeness claim.

The follow-up closes native Event 201/202 ResultCode fidelity for the tested
matrix: 22 synthetic native records through raw evidence, shared normalization,
a compiled isolated worker and a fresh persisted HTTP import. Controls include
missing versus present empty, dash, Unicode/control padding, malformed strings,
zero/leading zeroes and actual UInt32 substitutions with unchanged decimal
stringification. Production detection/correlation negative controls add no
program-success, payload-execution or maliciousness conclusions. Existing
provider/channel, other scheduler records and classic PowerShell tests remain
green. Shared Input tests and representable native/CSV adapter tests prove
semantic parity, not recovery of literals already lost by CSV formatting.
A compiling old-`setExtra` overlay must fail literal assertions; inherited strict
201 empty/padded overlays must pass without weakening their assertions.

Targeted tests, races, scoped vet and builds are separate from parent independent
review of the whole `ed04145..final` reader-plus-mapper range before merge. The
full suite, a new whole-case import, arbitrary EventData literal fidelity and
CSV original XML/BinXML fidelity are NOT VERIFIED by this vertical slice.
