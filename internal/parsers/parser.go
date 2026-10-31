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
	Coverage *model.ParseCoverage `json:",omitempty"`
	Events   []model.Event
	Raw      []model.RawEvidence // Raw[i] is the untouched source record for Events[i]
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

// ParseContext carries COLLECTION-scoped facts a parser may need that
// its own file cannot supply.
//
// It exists because parsing is otherwise strictly file-local, and one
// artifact genuinely is not: a SAM hive's NT hashes are encrypted under
// a key that lives in a DIFFERENT file, the SYSTEM hive. Reading that
// key is not something the SAM parser can do from the SAM.
//
// The first attempt at this looked for a SYSTEM hive next to the SAM on
// disk. That works for a directory of already-extracted files and fails
// for an AD1 image, because AD1 entries are materialized one at a time
// immediately before each is parsed -- so when the SAM is parsed, the
// SYSTEM hive beside it in the image has not been written yet. The
// lookup was racing the extraction order and losing. Collection-scoped
// context removes the race: the key is derived once, before any file is
// parsed, and handed to the parse.
//
// The zero value is valid and means "no context available", which every
// parser must handle -- a SAM parsed with no context still reports every
// account, with its hashes marked encrypted and the reason stated.
type ParseContext struct {
	// EvidenceRoot and BundleFiles admit explicit collection-scoped companion
	// sources. A parser must not infer filesystem siblings from EvidencePath.
	EvidenceRoot string
	BundleFiles  []BundleFile

	// EvidencePath is the path relative to the collection evidence root,
	// forward-slash (the same value as SourceFile.Path). User/profile
	// attribution must use this rather than the server's absolute path.
	EvidencePath string

	// BootKey is the machine boot key derived from this collection's
	// SYSTEM hive, or nil when none was available.
	BootKey []byte
	// BootKeySource is the evidence path of the SYSTEM hive the key came
	// from, and BootKeySHA256 its hash. Both travel onto the events so
	// provenance can name the cryptographic dependency exactly, rather
	// than leaving "it was decoded somehow" as the record.
	BootKeySource string
	BootKeySHA256 string
	// BootKeyStatus and BootKeyReason explain a missing key in terms an
	// analyst can act on: "collect the SYSTEM hive" and "the SYSTEM hive
	// you collected is damaged" are different next steps.
	BootKeyStatus string
	BootKeyReason string
	// BootKeyControlSet is the numbered control set the key was read
	// from -- a SYSTEM hive holds more than one, and which was live is
	// part of saying where the key came from.
	BootKeyControlSet int

	// TimeBasis is the host time zone recorded by this collection's SYSTEM
	// hive, or nil when none was recorded. Parsers that read local-time
	// values (registry shell items) convert them only when it is set.
	TimeBasis *TimeBasis
}

// BundleFile links a canonical repository role to its admitted stored path
// and source catalog identity. Original names and stored names may differ.
type BundleFile struct{ Role, Path, SourceFileID, SHA256 string }

// TimeBasis is a host time zone as one fixed offset: UTC = local +
// ActiveBiasMinutes. Source names the hive and value it came from, so a
// converted value can say where its offset was read.
type TimeBasis struct {
	ActiveBiasMinutes int
	Source            string
}

// ContextualParser is an OPTIONAL interface for a parser that can use
// collection-scoped context. A parser that does not implement it is
// called through Parse exactly as before -- this adds a capability, it
// does not change the contract.
type ContextualParser interface {
	// ParseWithContext behaves as Parse, additionally using whatever
	// ctx supplies. It must produce the same result as Parse when ctx
	// is the zero value.
	ParseWithContext(absPath string, ctx ParseContext) (ParseResult, error)
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

// ContentConfirmer is an OPTIONAL extra for a parser whose Detect
// matches on a filename that is not, on its own, proof.
//
// A parser that implements it is asked to CONFIRM a name match against
// the file's first SniffLength bytes before discovery hands it the file.
// A parser that does not implement it is unaffected: its name match
// still stands alone, which is right for the EZ Tools CSVs, whose
// filenames are produced by the tool itself.
//
// It exists for the native Windows hives. "SAM", "SYSTEM" and
// "NTUSER.DAT" are ordinary words as well as hive names, and a file
// carrying one of them that is not a hive was previously claimed,
// counted as supported evidence, and then failed at import -- telling an
// analyst a hive was corrupt when no hive was ever there. A refused
// confirmation returns the file to content-based detection, and if
// nothing claims it there it is reported as unrecognized, which is what
// it is.
type ContentConfirmer interface {
	// ConfirmContent reports whether header is consistent with this
	// parser's artifact. It must not assume a minimum length.
	ConfirmContent(header []byte) bool
}

// PathScopedDetector is an OPTIONAL extra for a parser whose CONTENT
// detector is broad enough that where a file lives is part of deciding
// what it is.
//
// It is ContentConfirmer's mirror image. ContentConfirmer exists because
// a filename match can be wrong and the bytes must agree; this exists
// because a CONTENT match can be right about the format and still wrong
// about the artifact.
//
// The case that produced it: a JPEG signature says "this is a picture"
// and nothing more, so an image parser detecting on it claims every JPEG
// in a collection -- including the 84 cached response bodies sitting
// inside a Chromium cache directory, which are already correctly
// catalogued as browser-cache evidence. They really are JPEGs; they are
// not standalone images, and reclassifying them lost the cache context
// that made them meaningful. A parser whose detector cannot tell those
// apart from the file's bytes alone says so here.
//
// A parser that does not implement it is unaffected: its content
// detector is consulted for every file, exactly as before.
type PathScopedDetector interface {
	// DetectPath reports whether relPath (forward-slash, relative to the
	// evidence root) is a location this parser's CONTENT detection
	// should be consulted for at all. Returning false skips
	// DetectContent for that file, leaving it to whatever else claims or
	// recognizes it.
	//
	// It is not a filename match: returning true means "ask the bytes",
	// never "this is the artifact".
	DetectPath(relPath string) bool
}

// EventArtifactTypeSource is an OPTIONAL interface for a parser whose
// events carry artifact types beyond its own ArtifactType().
//
// Almost every parser reads one kind of file and emits one kind of
// event, so for them the file's artifact type and their events' are the
// same thing. A container is different: an NTUSER.DAT is a registry
// hive, and it also holds UserAssist entries and a ShellBags tree, which
// are distinct artifacts with distinct forensic meaning. Discovery
// assigns one parser per file, so those structures must be read by the
// parser that claims the hive -- but their EVENTS should still be
// filterable, labelled and counted as what they are.
//
// Implementing this tells the capability registry that those types are
// supported, so they get real labels and priorities instead of being
// classified as unrecognized. It changes nothing about how a FILE is
// classified.
type EventArtifactTypeSource interface {
	// EventArtifactTypes returns the additional artifact types this
	// parser's events may carry. Every value must be a model.Artifact*
	// constant.
	EventArtifactTypes() []string
}
