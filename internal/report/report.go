// Package report renders a deterministic forensic report from already
// computed case data.
//
// # What this package is
//
// A pure function from Data to bytes. It imports nothing from the store,
// the API or the parsers, so a report can only say what the caller
// passed in; there is no code path by which it could query, infer or
// embellish. The same Data always renders to the same bytes.
//
// # What it is not
//
// It is not an analysis step and it contains no LLM. Every sentence it
// emits is either a fixed template string or a value taken from Data.
// Any future AI-assisted narrative must be added as a separate, labelled
// section supplied by the caller, never generated here.
//
// # Integrity
//
// A report is only useful as evidence if a reader can tell it has not
// been altered. Manifest records the SHA-256 of the rendered HTML and of
// every attachment; Verify re-checks a delivered bundle against it. A
// manifest is not a signature: it proves the files match the manifest,
// not who made it. See the Limitations the report itself prints.
package report

// Count is a labelled number, used for ordered breakdowns. Slices of
// Count are used instead of maps so that rendering order is fixed.
type Count struct {
	Name string
	N    int
}

// Meta identifies the report and the case.
type Meta struct {
	Title       string
	CaseID      string
	CaseName    string
	Description string
	CaseStatus  string
	Priority    string
	CreatedAt   string
	AnalyzedAt  string
	GeneratedAt string
	// GeneratedBy is the system account that requested the report. It is
	// NOT a verified examiner identity; the report says so.
	GeneratedBy string
	ToolName    string
	ToolVersion string
	// TimeBasis states what every timestamp in the report means.
	TimeBasis string
}

// Evidence is one evidence collection and the hashes recorded for it.
type Evidence struct {
	Label        string
	SourceType   string
	OriginalName string
	SHA256       string
	SHA512       string
	// HashKind says WHAT the digests cover (uploaded bytes, ordered AD1
	// segments, directory fingerprint).
	HashKind    string
	Status      string
	Files       int
	Supported   int
	Unsupported int
	Imported    int
	Events      int
	// Integrity is the outcome of the most recent re-verification, or a
	// statement that none has been run.
	Integrity string
	// Image is set for a disk-image collection: what the container said
	// about its own acquisition, how it checked out, and what is inside.
	Image *ImageInfo
}

// KV is an ordered label/value pair.
type KV struct{ Key, Value string }

// ImagePartition is one partition-table entry of a disk image.
type ImagePartition struct {
	Index int
	Type  string
	Name  string
	FS    string
	Start uint64 // first sector
	Size  string
}

// ImageVolume is one NTFS volume found in a disk image.
type ImageVolume struct {
	Prefix       string
	Label        string
	FilesInUse   int
	Deleted      int
	Cataloged    int
	NotCataloged int
	Corrupt      int
}

// ImageInfo describes a disk image's container, verification and layout.
type ImageInfo struct {
	Format       string
	Segments     int
	Size         string
	Acquisition  []KV
	StoredMD5    string
	StoredSHA1   string
	ComputedMD5  string
	ComputedSHA1 string
	// Verification states, in words, whether the decoded image matched the
	// hashes recorded at acquisition -- including when there were none.
	Verification string
	Partitioning string
	Partitions   []ImagePartition
	Volumes      []ImageVolume
	Notes        []string
}

// RunInfo is one analysis run.
type RunInfo struct {
	ID           string
	Started      string
	Completed    string
	Status       string
	ToolVersion  string
	Events       int
	Findings     int
	Correlations int
	Invalidated  string
}

// Analysis describes the analysis the findings come from.
type Analysis struct {
	// Current is true only when the findings describe the evidence the
	// case holds now. When false the report prints a prominent warning.
	Current bool
	Note    string
	Runs    []RunInfo
}

// Summary is the case-level rollup.
type Summary struct {
	Collections    int
	SourceFiles    int
	ImportedFiles  int
	Events         int
	Findings       int
	Correlations   int
	Investigations int
	Techniques     int
	Severity       []Count
}

// Technique is a resolved ATT&CK technique.
type Technique struct {
	ID     string
	Name   string
	Tactic string
}

// EventRef is a reference to one event, with enough to find it again.
type EventRef struct {
	ID       string
	Time     string
	Type     string
	Artifact string
	Summary  string
	Source   string
	Ref      string
}

// Finding is one detection result and the evidence it stands on.
type Finding struct {
	Number        string
	ID            string
	Title         string
	Severity      string
	Confidence    string
	RuleID        string
	Description   string
	Techniques    []Technique
	FirstSeen     string
	LastSeen      string
	ReviewStatus  string
	ReviewNote    string
	Notes         []string
	Why           []string
	Escalated     bool
	EventCount    int
	Events        []EventRef
	EventsOmitted int
}

// Investigation is a grouped, scored story built from findings.
type Investigation struct {
	Title        string
	Category     string
	Severity     string
	Confidence   string
	Score        int
	Start        string
	End          string
	Hosts        string
	Users        string
	FindingCount int
	Summary      string
	Rationale    []string
	ReviewStatus string
}

// Timeline summarizes the case timeline. The full timeline is an
// attachment, not part of the body.
type Timeline struct {
	Total        int
	Dated        int
	Undated      int
	Earliest     string
	Latest       string
	ByArtifact   []Count
	PeriodUnit   string
	ByPeriod     []Count
	Key          []EventRef
	KeyOmitted   int
	KeyTotalNote string
}

// CoverageRow is one artifact class in the case.
type CoverageRow struct {
	Type      string
	Family    string
	Priority  string
	Supported bool
	Files     int
	Imported  int
	Note      string
}

// Coverage states what was and was not analyzed.
type Coverage struct {
	Discovered    int
	Supported     int
	Unsupported   int
	Duplicates    int
	Imported      int
	ParseFailed   int
	ByType        []CoverageRow
	Failed        []string
	FailedOmitted int
}

// Attachment is a file delivered with the report and hashed in the
// manifest.
type Attachment struct {
	Name        string
	Description string
	SHA256      string
	Bytes       int64
	Rows        int
}

// RuleInfo documents a detection rule that fired in this case.
type RuleInfo struct {
	ID       string
	Title    string
	Detects  string
	Basis    string
	Base     string
	Max      string
	Fired    int
	TechList string
}

// AuditEntry is one audit trail record.
type AuditEntry struct {
	Time    string
	Actor   string
	Action  string
	Summary string
}

// Data is everything a report contains.
type Data struct {
	Meta           Meta
	Summary        Summary
	Analysis       Analysis
	Evidence       []Evidence
	Investigations []Investigation
	Findings       []Finding
	Timeline       Timeline
	Coverage       Coverage
	Attachments    []Attachment
	Rules          []RuleInfo
	Audit          []AuditEntry
	AuditOmitted   int
	// Limitations are case-specific caveats the caller computed (stale
	// analysis, parse failures...). Fixed caveats live in the template.
	Limitations []string
}
