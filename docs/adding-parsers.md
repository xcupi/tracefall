# Adding a new artifact parser

Tracefall's parser architecture is designed so that adding support for a
new KAPE artifact never requires changing ingestion, normalization's
shared helpers, detection, correlation, storage, or the API. This
document walks through the interface and how to add one.

## The `ArtifactParser` interface

Defined in [`internal/parsers/parser.go`](../internal/parsers/parser.go):

```go
type ArtifactParser interface {
	Name() string                        // e.g. "evtxcsv@1"
	ArtifactType() string                // a model.Artifact* constant
	Detect(relPath string) bool          // filename/path pattern match
	Parse(absPath string) (ParseResult, error)
}

type ParseResult struct {
	Events []model.Event       // CaseID/SourceFileID/ID left blank -- ingestion fills them in
	Raw    []model.RawEvidence // Raw[i] is the untouched source record for Events[i]
}
```

`internal/ingest.Registry()` returns the ordered list of known parsers.
`internal/ingest.Walk` walks the evidence directory, and for each file,
tries each registered parser's `Detect` in order (first match wins) and
calls its `Parse` if matched. Unmatched files are recorded in
`Result.Skipped`, not treated as an error — a real KAPE package routinely
contains far more files than Tracefall has parsers for.

## Existing parsers, as a reference

| Package | Artifact | Format consumed | Why |
|---|---|---|---|
| `internal/parsers/evtxcsv` | Windows Event Logs (Security 4624/4625/4688, PowerShell 4104, Sysmon Network Connect 3) | EvtxECmd CSV | see ARCHITECTURE.md's "why CSV, not raw binary formats" |
| `internal/parsers/pecmd` | Prefetch | PECmd CSV | same |
| `internal/parsers/recmd` | Registry Run keys | RECmd batch CSV | same |
| `internal/parsers/scheduledtasks` | Scheduled Tasks | raw Task Scheduler XML (UTF-16LE) | KAPE collects this directly; simple enough to parse natively |

`evtxcsv` is the most instructive example of the "one parser, several
event types" pattern: EvtxECmd's CSV shape is identical regardless of
channel/EventID, so one parser dispatches on `(Channel, EventId)` inside
`toEvent` to produce different `model.Event` shapes. Extending coverage
to another channel/EventID pair already-parsed by EvtxECmd (e.g. Sysmon
Process Create, Event ID 1) is a new `case` in that switch, not a new
parser package.

## Step by step: adding a new parser

1. **Create a package** under `internal/parsers/<name>/`.
2. **Pick a `Name()`** of the form `<tool>@<version>`, e.g. `amcache@1`.
   Bump the version suffix if you ever change what fields a given input
   shape produces — it's stored on every `Event`/`SourceFile` for
   provenance, and an investigator (or a future you) may need to know
   "was this event produced before or after the parser's field mapping
   changed."
3. **Pick or add a `model.ArtifactType`** constant in `internal/model/model.go`
   if this is a genuinely new artifact type.
4. **Write `Detect`**. Match on filename/path patterns, following the
   existing parsers' convention (case-insensitive, checking the tool
   name and file extension). Don't content-sniff — KAPE/EZ Tools output
   naming is predictable and documented, and content-sniffing is slower
   and easier to get subtly wrong across encodings.
5. **Write `Parse`**. Read the file, and for each record:
   - Parse the timestamp with `normalize.Timestamp` — if it fails, skip
     the record rather than fabricating a time (an unplaceable event
     would corrupt the timeline and any temporal correlation).
   - Map artifact-specific fields to `model.Event`'s common fields
     (`process_name` via `normalize.ProcessName` for a bare path, or
     `normalize.ExecutableFromCommandLine` for a string that may include
     arguments — see [data-model.md](data-model.md) for the distinction and
     the regression it exists to prevent).
   - Put anything that doesn't have a first-class `Event` field into
     `Extra`, with a short, documented snake_case key.
   - Set `ArtifactType`, `Parser`, and a `Confidence` reflecting how much
     you trust the field mapping (`1.0` for an unambiguous field like a
     registry value; lower, with a comment explaining why, for something
     like Prefetch's `LastRun`, which only approximates actual execution
     time).
   - Append the exact original record (JSON-encoded) to `ParseResult.Raw`,
     index-aligned with `ParseResult.Events` — this is what makes the
     provenance chain (see [data-model.md](data-model.md)) work; never
     skip it.
6. **Register it** in `internal/ingest.Registry()`.
7. **Write tests** in `<name>_test.go`: at least one `Detect` test with
   both a matching and non-matching path, and one `Parse` test against a
   small inline fixture asserting the resulting `Event` fields. See
   `internal/parsers/evtxcsv/evtxcsv_test.go` for the fullest example,
   including a regression test for a real bug this codebase hit (a raw
   Windows path containing spaces, like `C:\Program Files\...`, must not
   be naively space-split when extracting the executable name).
8. **If you're adding a genuinely new binary format parser** (raw
   `.evtx`, raw Prefetch, a raw registry hive) instead of consuming a
   companion tool's CSV, keep the binary-decoding logic isolated inside
   that parser package — nothing else in Tracefall should need to know
   the raw format exists. `internal/parsers/scheduledtasks`'s UTF-16
   decoding (`decodeUTF16`) is the existing example of self-contained
   binary/encoding handling inside a parser package.

## Regenerating or extending the synthetic test dataset

`testdata/synthetic_case` is a hand-built, **clearly synthetic — not
real** — evidence package resembling KAPE + `!EZParser` output, covering
a representative attack-like sequence (phishing document → Office →
PowerShell → payload → persistence via both a registry Run key and a
scheduled task → outbound connection), plus an unrelated brute-force
sub-plot. It exists so the full pipeline can be exercised without a real
forensic image, and the same ingestion/parsing/detection/correlation code
path processes it exactly as it would real evidence — nothing in the
pipeline branches on "is this synthetic."

If you add a new parser and want to extend the synthetic dataset to cover
it, add the new source file(s) under `testdata/synthetic_case/<Tool>/`
following the existing files' shape, and extend
`internal/ingest.TestWalk_SyntheticCase` and
`internal/api.TestEndToEnd_SyntheticCase`'s assertions (source file
count, event count) to match. Keep the dataset's own internal narrative
consistent (same host, same timestamps for a given step) if the new
artifact type ties into the existing attack-chain story — that's what
lets `internal/correlate`'s activity-chain reconstruction keep working
end-to-end.
