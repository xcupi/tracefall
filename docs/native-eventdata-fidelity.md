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

The existing Event 201 completion path still passes ResultCode through shared
`setExtra`, which trims whitespace and omits empty/dash tokens. Native raw 201
fidelity is repaired here, but normalized 201 literal fidelity is NOT repaired.
A separate narrowly authorized shared-mapper change with presence/literal guard
tests is required to close that downstream gate. This reader patch must not be
represented as full native-to-normalized fidelity for Event 201.

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

Acceptance proof is retained outside the repository. A fresh compiled isolated
worker comparison on one existing selected working source checks complete raw
and normalized hash-row parity with retained reference output. It is not a
new whole-source independent-reader census or a whole-case completeness claim.
A fresh tiny compiled HTTP import checks persisted Event 202 Unicode/control
padding against the native string and an independent reader. Targeted tests,
races, vet and builds are separate from parent independent review and the full
suite; neither the full suite nor a new whole-case import is part of this fix.
