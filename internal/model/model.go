// Package model defines Tracefall's core domain types shared across every
// layer of the pipeline: ingestion, parsers, normalization, detection,
// correlation, ATT&CK mapping, storage, and the API. Keeping these types in
// one dependency-free package is what lets parsers stay ignorant of
// detection logic and the UI stay ignorant of forensic analysis.
package model

import "time"

// Case is an investigation container. All ingested evidence, events,
// findings, and correlations are scoped to exactly one case.
type Case struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Status      string    `json:"status"` // created | ingested | analyzed
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Case status values. Status reflects the case's evidence set as a
// whole, not any single collection: it moves to Ingested every time a
// new Collection finishes ingesting (including the first), and to
// Analyzed once analysis has run against the current full evidence set.
// Adding another collection after Analyzed moves it back to Ingested --
// a signal that the analysis is now stale and should be re-run.
const (
	CaseStatusCreated  = "created"
	CaseStatusIngested = "ingested"
	CaseStatusAnalyzed = "analyzed"
)

// Collection is one independent evidence-gathering event ingested into a
// case -- e.g. one KAPE ZIP uploaded at a point in time, or one
// local-path ingest. A Case can contain many Collections (INC-001 might
// have a morning triage, an afternoon follow-up triage, and evidence
// added later in the investigation); Tracefall's timeline, findings, and
// correlations always operate across every Collection in the case, never
// just the most recent one. See docs/data-model.md.
type Collection struct {
	ID                   string    `json:"collection_id"`
	CaseID               string    `json:"case_id"`
	CreatedAt            time.Time `json:"created_at"`
	SourceType           string    `json:"source_type"`
	OriginalFilename     string    `json:"original_filename,omitempty"` // uploaded ZIP's filename, or the given local path
	ArchiveHash          string    `json:"archive_hash,omitempty"`      // SHA-256 of the uploaded archive, or a deterministic content fingerprint for local-path ingest; used to reject duplicate evidence within a case
	EvidenceDirectory    string    `json:"evidence_directory"`          // where this collection's extracted evidence lives on disk
	IngestionStatus      string    `json:"ingestion_status"`
	FileCount            int       `json:"file_count"`
	SupportedFileCount   int       `json:"supported_file_count"`
	UnsupportedFileCount int       `json:"unsupported_file_count"`
	ParsedEventCount     int       `json:"parsed_event_count"`
}

// Collection source types.
const (
	SourceTypeUpload    = "kape_upload" // browser-uploaded ZIP
	SourceTypeLocalPath = "local_path"  // ingested from a directory already on disk
	SourceTypeLegacy    = "legacy"      // synthesized for evidence ingested before collections existed (see internal/store/migrate.go)
)

// Collection ingestion status values.
const (
	CollectionStatusPending  = "pending"
	CollectionStatusIngested = "ingested"
	CollectionStatusFailed   = "failed"
)

// SourceFile records one file that was ingested as part of one of a
// case's evidence collections, and which parser handled it. This is the
// first link in the provenance chain: Finding -> Event -> SourceFile.
type SourceFile struct {
	ID           string    `json:"id"`
	CaseID       string    `json:"case_id"`
	CollectionID string    `json:"collection_id"`
	Path         string    `json:"path"` // path relative to the collection's evidence root
	ArtifactType string    `json:"artifact_type"`
	Parser       string    `json:"parser"` // parser name@version that handled this file
	RowCount     int       `json:"row_count"`
	SHA256       string    `json:"sha256"`
	IngestedAt   time.Time `json:"ingested_at"`
}

// Artifact types recognized in Phase 1. New artifact types are added here
// and in internal/ingest's detector table -- nothing else needs to change.
const (
	ArtifactWindowsEventLog = "windows_event_log" // EvtxECmd CSV output
	ArtifactPrefetch        = "prefetch"          // PECmd CSV output
	ArtifactRegistryRunKey  = "registry_run_key"  // RECmd batch CSV output
	ArtifactScheduledTask   = "scheduled_task"    // raw Task Scheduler XML
)

// Event types recognized in Phase 1. EventType is the normalized,
// artifact-agnostic vocabulary that the detection engine reasons over --
// deliberately smaller than the set of Windows Event IDs or artifact
// formats it's derived from.
const (
	EventLogonSuccess        = "logon_success"
	EventLogonFailure        = "logon_failure"
	EventProcessCreate       = "process_create"
	EventPowerShellScript    = "powershell_script_block"
	EventPrefetchExecution   = "prefetch_execution"
	EventRegistryRunKey      = "registry_run_key_set"
	EventScheduledTaskCreate = "scheduled_task_created"
	EventNetworkConnection   = "network_connection"
)

// Event is Tracefall's normalized evidence record. Every parser emits
// Events; nothing downstream (detection, correlation, API, UI) ever looks
// at a parser-specific format again. Fields that don't apply to a given
// event are left zero-valued -- e.g. a logon event has no CommandLine, a
// registry event has no PID.
//
// Fields not common enough to earn a first-class column live in Extra,
// keyed by a short snake_case name (e.g. "logon_type", "encoded_command",
// "task_name"). This keeps the common schema small and stable while still
// preserving artifact-specific detail for rules and investigators that
// need it.
type Event struct {
	ID        string    `json:"id"`
	CaseID    string    `json:"case_id"`
	Timestamp time.Time `json:"timestamp"` // always normalized to UTC

	Host string `json:"host,omitempty"`
	User string `json:"user,omitempty"`

	EventType string `json:"event_type"`
	Provider  string `json:"provider,omitempty"` // e.g. "Security", "Microsoft-Windows-PowerShell/Operational"
	EventID   int    `json:"event_id,omitempty"` // Windows Event ID, where applicable

	ProcessName       string `json:"process_name,omitempty"`
	ProcessPath       string `json:"process_path,omitempty"`
	ParentProcessName string `json:"parent_process,omitempty"`
	ParentProcessPath string `json:"parent_process_path,omitempty"`
	PID               int64  `json:"pid,omitempty"`
	PPID              int64  `json:"ppid,omitempty"`
	CommandLine       string `json:"command_line,omitempty"`

	FilePath     string `json:"file_path,omitempty"`
	RegistryPath string `json:"registry_path,omitempty"`

	NetworkSource   string `json:"network_source,omitempty"`
	NetworkDest     string `json:"network_dest,omitempty"`
	NetworkDestPort int    `json:"network_dest_port,omitempty"`

	// Provenance -- how to trace this event back to raw evidence. These
	// fields describe the collection this event was FIRST observed in;
	// if the same real-world event was also observed in a later
	// collection (e.g. a re-run KAPE triage recollecting the same
	// Windows Event Log records), that is never a second Event row --
	// see DedupHash and EventObservation below -- so these fields alone
	// don't tell the full story for an event with more than one
	// observation. Callers that need the complete list use
	// store.ListEventObservations(eventID).
	ArtifactType    string `json:"artifact_type"`
	CollectionID    string `json:"collection_id"`
	SourceFileID    string `json:"source_file_id"`
	SourceReference string `json:"source_reference,omitempty"` // e.g. row number within the source file
	Parser          string `json:"parser"`                     // parser name@version

	// Confidence is the parser's confidence in the fidelity of the
	// extracted fields (not a detection confidence -- that lives on
	// Finding). 1.0 means the field mapping is unambiguous.
	Confidence float64 `json:"confidence"`

	// RawEvidenceID references the pristine, unmodified source row/record
	// this event was normalized from, so an investigator can always drill
	// down to ground truth. Like the provenance fields above, this is the
	// first observation's raw record specifically.
	RawEvidenceID string `json:"raw_evidence_id,omitempty"`

	// DedupHash identifies this event's real-world identity across
	// collections -- see DedupHash() below. Two normalized events with
	// the same hash are treated as the same underlying observation and
	// collapsed into one Event row (with an EventObservation recorded
	// per collection they actually appeared in), rather than stored as
	// duplicates.
	DedupHash string `json:"dedup_hash,omitempty"`

	Extra map[string]string `json:"extra,omitempty"`
}

// EventObservation records that a (deduplicated) Event was observed in
// one specific collection, via one specific source file and raw record.
// An event with two observations (one per collection) was independently
// collected twice -- e.g. the same Windows Event Log record present in
// both an 08:00 and a 14:00 KAPE triage of the same host -- and
// deduplication must never discard that fact: it's the direct evidence
// behind an "Observed in: Collection #1, Collection #2" display.
type EventObservation struct {
	ID              string `json:"id"`
	EventID         string `json:"event_id"`
	CaseID          string `json:"case_id"`
	CollectionID    string `json:"collection_id"`
	SourceFileID    string `json:"source_file_id"`
	RawEvidenceID   string `json:"raw_evidence_id,omitempty"`
	SourceReference string `json:"source_reference,omitempty"`
}

// RawEvidence preserves the original record a parser read, untouched, so
// normalization is always auditable and reversible.
type RawEvidence struct {
	ID              string `json:"id"`
	CaseID          string `json:"case_id"`
	SourceFileID    string `json:"source_file_id"`
	SourceReference string `json:"source_reference,omitempty"`
	Raw             string `json:"raw"` // original row/record, e.g. as JSON or the raw CSV line
}

// Severity levels for findings.
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Confidence levels for findings. Deliberately coarse (not a float) so
// rule authors aren't tempted to fabricate false precision.
const (
	ConfidenceLow    = "low"
	ConfidenceMedium = "medium"
	ConfidenceHigh   = "high"
)

// Finding is the output of one detection rule firing once. It is always
// backed by concrete SupportingEventIDs -- Tracefall does not produce
// findings without evidence.
type Finding struct {
	ID               string    `json:"finding_id"`
	CaseID           string    `json:"case_id"`
	RuleID           string    `json:"detection_rule"`
	Title            string    `json:"title"`
	Severity         string    `json:"severity"`
	Confidence       string    `json:"confidence"`
	Description      string    `json:"description"`
	SupportingEvents []string  `json:"supporting_event_ids"`
	Techniques       []string  `json:"attack_techniques"` // ATT&CK technique IDs, e.g. "T1059.001"
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
	CreatedAt        time.Time `json:"created_at"`
}

// Correlation types.
const (
	CorrelationTemporal      = "temporal"
	CorrelationEntity        = "entity"
	CorrelationProcessChain  = "process_chain"
	CorrelationActivityChain = "activity_chain"
)

// Correlation is a deterministic relationship between two or more events,
// established by an explicit heuristic (never invented). A process-chain
// correlation might link a parent process to its child; an activity-chain
// correlation stitches several correlations into a narrative sequence such
// as document-open -> Office -> PowerShell -> persistence.
type Correlation struct {
	ID          string    `json:"correlation_id"`
	CaseID      string    `json:"case_id"`
	Type        string    `json:"correlation_type"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	EventIDs    []string  `json:"event_ids"` // ordered where sequence is meaningful
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}
