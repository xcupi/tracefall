// Package parsers defines the contract every artifact parser implements.
// Ingestion (internal/ingest) depends only on this interface, never on a
// concrete parser -- adding support for a new KAPE artifact means writing
// a new package that satisfies ArtifactParser and registering it in
// internal/ingest's detector table. Nothing else in the system changes.
package parsers

import "tracefall/internal/model"

// ParseResult is what a parser hands back to ingestion: normalized events
// paired 1:1 with the raw record they came from. CaseID, SourceFileID, and
// ID fields are intentionally left blank -- ingestion assigns them, since
// a parser doesn't know what case it's running in.
type ParseResult struct {
	Events []model.Event
	Raw    []model.RawEvidence // Raw[i] is the untouched source record for Events[i]
}

// ArtifactParser turns one artifact source file into normalized events.
// Implementations must not depend on anything in internal/detect,
// internal/correlate, or internal/api -- parsing is strictly upstream of
// analysis.
type ArtifactParser interface {
	// Name identifies the parser and its version, e.g. "evtxcsv@1". Stored
	// on every Event and SourceFile for provenance.
	Name() string

	// ArtifactType is the model.Artifact* constant this parser produces.
	ArtifactType() string

	// Detect reports whether relPath (forward-slash, relative to the
	// evidence root) looks like a file this parser handles. Detection is
	// filename/path based, not content-sniffing -- KAPE and its EZ Tools
	// companions use predictable output naming conventions.
	Detect(relPath string) bool

	// Parse reads absPath and returns normalized events. It must not
	// mutate global state and must be safe to call concurrently with
	// other parsers running on other files.
	Parse(absPath string) (ParseResult, error)
}

// SniffLength is how many leading bytes of a file discovery reads and
// offers to a ContentDetector. It only ever needs to cover a format's
// magic number, so it is deliberately tiny -- discovery must stay cheap
// enough to run over an entire triage collection.
const SniffLength = 512

// ContentDetector is an OPTIONAL extra a parser may implement when its
// artifact is identified by what the file contains rather than by what
// it is called.
//
// The EZ Tools CSV parsers are correctly filename-driven: KAPE names its
// output predictably, and a "*_EvtxECmd_Output.csv" is one by
// construction. Native Windows artifacts are the opposite case. A
// registry hive is routinely named SYSTEM, ntuser.dat, UsrClass.dat, or
// nothing recognizable at all after being copied out of a triage image,
// while a file called Security.evtx may turn out to be a renamed ZIP.
// Trusting the name there would both miss real evidence and misclassify
// files an attacker gets to name.
//
// Discovery consults Detect first and DetectContent second, so a parser
// can support both, and content detection never overrides a filename
// match that already succeeded.
type ContentDetector interface {
	// DetectContent reports whether header -- the first SniffLength
	// bytes of the file, or the whole file if it is shorter -- is this
	// parser's artifact. It must not assume a minimum length.
	DetectContent(header []byte) bool
}
