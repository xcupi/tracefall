// Package model defines Tracefall's core domain types shared across every
// layer of the pipeline: ingestion, parsers, normalization, detection,
// correlation, ATT&CK mapping, storage, and the API. Keeping these types in
// one dependency-free package is what lets parsers stay ignorant of
// detection logic and the UI stay ignorant of forensic analysis.
package model

import "time"

// Case is an investigation container. All ingested evidence, events,
// findings, and correlations are scoped to exactly one case.
//
// Case carries TWO independent status-like concepts, deliberately kept
// as separate fields rather than folded into one -- see Phase 6's
// docs/analyst-workflow.md for the full rationale:
//
//   - Status is the ANALYSIS lifecycle (created/ingested/analyzed --
//     unchanged since Phase 1): does the case's current evidence set
//     have up-to-date detection/correlation results?
//   - CaseStatus is the analyst's own INVESTIGATIVE workflow state
//     (open/investigating/contained/closed, added in Phase 6): where is
//     the human investigator in handling this case? This is never set
//     or changed by the deterministic engine -- only ever by an analyst
//     action (or CreateCase's default).
//
// A case can be "analyzed" (engine ran successfully) while its
// CaseStatus is "open" (analyst hasn't started working it yet), or
// "ingested" (evidence changed, stale) while CaseStatus is "closed" (an
// analyst added evidence to a closed case, which is allowed but doesn't
// reopen it automatically). The two are never conflated.
type Case struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Status      string    `json:"status"` // created | ingested | analyzed -- see doc comment above
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`

	// AnalyzedAt is when AnalyzeCase last completed successfully for
	// this case (nil if never analyzed) -- distinct from UpdatedAt
	// (touched by ANY case change, including a pure metadata edit that
	// has nothing to do with analysis) and from CreatedAt. This is what
	// lets the UI show "analyzed 3 collections / 42 events ago at 14:02
	// UTC" precisely, and what distinguishes "never analyzed" from
	// "analyzed before, now stale" even though both currently show
	// Status == ingested.
	//
	// A *time.Time, not time.Time: encoding/json's `omitempty` does NOT
	// treat a zero-valued time.Time (0001-01-01T00:00:00Z) as "empty" --
	// omitempty's emptiness check is reflect.Value.IsZero-adjacent for
	// basic kinds only, and a struct is never considered empty by it. A
	// plain time.Time field here would have serialized the zero value
	// literally instead of omitting it, which is exactly the bug this
	// pointer avoids.
	AnalyzedAt *time.Time `json:"analyzed_at,omitempty"`

	// CaseStatus is the analyst's investigative workflow state -- see
	// the CaseWorkflow* constants. Defaults to CaseWorkflowOpen on
	// creation; changed only by an explicit analyst action
	// (Service.UpdateCaseMetadata), never by analysis.
	CaseStatus string `json:"case_status"`
	// Priority is the analyst's own triage priority -- see the
	// CasePriority* constants. Purely descriptive; nothing in the
	// deterministic engine reads or sets it.
	Priority string `json:"priority"`
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

// CaseWorkflow* are Case.CaseStatus's values (Phase 6) -- the analyst's
// own investigative-progress state, entirely independent of Status
// above. A small, fixed set matching how a human triage workflow
// actually progresses; Tracefall never infers or auto-transitions these
// from evidence/analysis activity.
const (
	CaseWorkflowOpen          = "open"
	CaseWorkflowInvestigating = "investigating"
	CaseWorkflowContained     = "contained"
	CaseWorkflowClosed        = "closed"
)

// CasePriority* are Case.Priority's values (Phase 6) -- an analyst's own
// triage priority, purely descriptive.
const (
	CasePriorityLow      = "low"
	CasePriorityMedium   = "medium"
	CasePriorityHigh     = "high"
	CasePriorityCritical = "critical"
)

// Collection is one independent evidence-gathering event ingested into a
// case -- e.g. one KAPE ZIP uploaded at a point in time, or one
// local-path ingest. A Case can contain many Collections (INC-001 might
// have a morning triage, an afternoon follow-up triage, and evidence
// added later in the investigation); Tracefall's timeline, findings, and
// correlations always operate across every Collection in the case, never
// just the most recent one. See docs/data-model.md.
type Collection struct {
	ID               string    `json:"collection_id"`
	CaseID           string    `json:"case_id"`
	CreatedAt        time.Time `json:"created_at"`
	SourceType       string    `json:"source_type"`
	OriginalFilename string    `json:"original_filename,omitempty"` // uploaded ZIP's filename, or the given local path
	ArchiveHash      string    `json:"archive_hash,omitempty"`      // SHA-256 of the uploaded archive, or a deterministic content fingerprint for local-path ingest; used to reject duplicate evidence within a case
	// IntegritySHA512 is the SHA-512 of the ORIGINAL evidence object, for
	// forensic integrity rather than for deduplication: the exact
	// uploaded bytes for a ZIP or AD1, or the deterministic content
	// fingerprint defined in docs/evidence-integrity.md for a local
	// directory. It is computed before anything is extracted or
	// transformed, and is immutable once the collection exists.
	//
	// Deliberately SEPARATE from ArchiveHash: that one is load-bearing
	// for duplicate detection (see idx_collections_case_archive_hash) and
	// changing its algorithm would change which evidence counts as a
	// duplicate. This field adds integrity evidence without touching that.
	IntegritySHA512      string `json:"integrity_sha512,omitempty"`
	EvidenceDirectory    string `json:"evidence_directory"` // where this collection's extracted evidence lives on disk
	IngestionStatus      string `json:"ingestion_status"`
	FileCount            int    `json:"file_count"`             // active (non-deleted) files discovered, supported + unsupported
	SupportedFileCount   int    `json:"supported_file_count"`   // of those, how many a parser recognizes (available to import, whether or not yet imported)
	UnsupportedFileCount int    `json:"unsupported_file_count"` // of those, how many no parser recognizes
	ImportedFileCount    int    `json:"imported_file_count"`    // of the supported files, how many have actually been imported
	ParsedEventCount     int    `json:"parsed_event_count"`     // total events produced by imported files
}

// Collection source types.
const (
	SourceTypeUpload    = "kape_upload" // browser-uploaded ZIP
	SourceTypeLocalPath = "local_path"  // ingested from a directory already on disk
	SourceTypeLegacy    = "legacy"      // synthesized for evidence ingested before collections existed (see internal/store/migrate.go)
	// SourceTypeAD1 is an AccessData Logical Image (AD1) forensic
	// container -- see internal/ad1 and docs/ad1-ingestion.md. Unlike
	// the other source types above, this describes the CONTAINER FORMAT,
	// not how it arrived (an AD1 can reach Tracefall via browser upload
	// or local-path ingest identically -- see docs/ad1-ingestion.md's
	// "Why SourceType is format, not delivery mechanism" section for why
	// that distinction stops being meaningful for AD1 and isn't tracked
	// separately).
	SourceTypeAD1 = "ad1_image"
)

// Collection ingestion status values.
const (
	CollectionStatusPending  = "pending"
	CollectionStatusIngested = "ingested"
	// CollectionStatusFailed is LEGACY and is never written any more.
	// Discovery used to create a collection before cataloging it and
	// mark it "failed" if cataloging then failed, leaving a permanent
	// zero-file collection that was not evidence and could never become
	// evidence. Discovery is now atomic (see
	// internal/store.Store.CreateCollectionWithSourceFiles): a failed
	// discovery creates nothing. The constant remains because databases
	// written by earlier versions still contain such rows -- they are
	// read, rendered as a clearly-labelled dead end, and deliberately
	// never advanced to "ingested" (see Service.recomputeCollectionCounts).
	CollectionStatusFailed = "failed"
)

// SourceFile is one individual evidence file discovered inside a
// collection -- the unit an investigator now selects, imports, inspects,
// and deletes independently (see docs/data-model.md's "Evidence file
// model" section). This is the first link in the provenance chain:
// Finding -> Event -> SourceFile.
//
// A file's life cycle is discovery, then (optionally) import:
// upload/path-ingest catalogs every file in the package as a SourceFile
// row the moment it's discovered -- before anything is parsed -- with
// ImportStatus SourceFileDiscovered (or SourceFileUnsupported /
// SourceFileDuplicate if it's not something an investigator can choose
// to import). Only once an investigator selects specific discovered
// files and imports them does a file gain events and move to
// SourceFileImported (or SourceFileFailed if parsing itself failed).
type SourceFile struct {
	ID               string `json:"id"`
	CaseID           string `json:"case_id"`
	CollectionID     string `json:"collection_id"`
	OriginalFilename string `json:"original_filename"` // basename as it appeared in the package
	Path             string `json:"path"`              // path relative to the collection's evidence root
	ArtifactType     string `json:"artifact_type,omitempty"`
	Parser           string `json:"parser,omitempty"` // parser name@version that would/did handle this file
	Supported        bool   `json:"supported"`        // a parser was detected for this file, whether or not it has been imported
	SizeBytes        int64  `json:"size_bytes"`
	SHA256           string `json:"sha256"` // Tracefall's own SHA-256, computed once the file is actually imported (see EmbeddedHash for what's known before that)
	// EmbeddedHash is a hash the SOURCE CONTAINER reported for this file
	// -- currently only populated for SourceTypeAD1 (from FTK Imager's
	// own MD5/SHA1 acquisition-time hashing, when it was enabled),
	// format "algo:hexdigest" (e.g. "sha1:abcd..."), empty if unknown.
	// This is a hash Tracefall *observed being claimed*, not one it
	// independently verified -- kept in its own field, never merged into
	// SHA256, so the UI can show both side by side and an investigator
	// can tell which is which. See docs/ad1-ingestion.md.
	EmbeddedHash string     `json:"embedded_hash,omitempty"`
	ImportStatus string     `json:"import_status"`
	EventCount   int        `json:"event_count"` // 0 until imported
	DiscoveredAt time.Time  `json:"discovered_at"`
	ImportedAt   *time.Time `json:"imported_at,omitempty"`
	DeletedAt    *time.Time `json:"deleted_at,omitempty"` // soft-delete marker; nil while the file is active evidence
}

// SourceFile import status values -- see SourceFile's doc comment for
// the life cycle these form.
const (
	SourceFileDiscovered  = "discovered"  // cataloged, supported, not yet selected for import
	SourceFileImported    = "imported"    // selected and successfully parsed into events
	SourceFileUnsupported = "unsupported" // cataloged, but no parser recognizes it -- cannot be imported
	SourceFileDuplicate   = "duplicate"   // cataloged, but its content (by SHA-256) already exists elsewhere in this same collection -- cannot be imported (a different collection may legitimately re-observe the same file; see docs/data-model.md)
	SourceFileFailed      = "failed"      // selected for import, but its parser returned an error
)

// Artifact types recognized in Phase 1. New artifact types are added here
// and in internal/ingest's detector table -- nothing else needs to change.
const (
	ArtifactWindowsEventLog = "windows_event_log" // EvtxECmd CSV output
	ArtifactPrefetch        = "prefetch"          // PECmd CSV output
	ArtifactRegistryRunKey  = "registry_run_key"  // RECmd batch CSV output
	// ArtifactRegistryHive is a raw REGF hive read natively
	// (internal/parsers/registry). Deliberately distinct from
	// ArtifactRegistryRunKey: artifact type is part of an event's
	// identity (see Event.ComputeDedupHash), so a hive snapshot and a
	// RECmd CSV export of that same hive stay separately attributable
	// rather than silently collapsing into one another.
	ArtifactRegistryHive = "registry_hive"
	// ArtifactPowerShellHistory is a PowerShell ConsoleHost_history.txt
	// file. It records commands in order but NO timestamps, which is why
	// events from it carry a zero Timestamp -- see
	// docs/evidence-triage.md and Event.ComputeDedupHash's zero-time rule.
	ArtifactPowerShellHistory = "powershell_history"
	// ArtifactBrowserHistory is a browser history database. The exact
	// formats supported are listed in docs/evidence-triage.md; the
	// artifact type does not imply every browser is readable.
	ArtifactBrowserHistory = "browser_history"
	ArtifactScheduledTask  = "scheduled_task" // raw Task Scheduler XML
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

// Event types added in Phase 4 ("Expand Windows DFIR Triage Coverage").
// Each one earns its place by feeding a specific detection rule or
// correlation added in the same phase -- see internal/detect and
// internal/correlate -- rather than being coverage for its own sake.
const (
	// EventLogonExplicitCreds is Security 4648 (a logon was attempted
	// using explicit credentials) -- the classic "runas"/lateral-movement
	// signal, and step one of the credential-abuse correlation.
	EventLogonExplicitCreds = "logon_explicit_credentials"
	// EventPrivilegedLogon is Security 4672 (special privileges assigned
	// to a new logon) -- an administrator-equivalent logon indicator.
	EventPrivilegedLogon = "privileged_logon"
	// EventKerberosTGTRequest is Security 4768 (a Kerberos
	// Ticket-Granting-Ticket was requested).
	EventKerberosTGTRequest = "kerberos_tgt_request"
	// EventKerberosServiceTicket is Security 4769 (a Kerberos service
	// ticket was requested).
	EventKerberosServiceTicket = "kerberos_service_ticket_request"
	// EventNTLMAuth is Security 4776 (the domain controller attempted to
	// validate credentials for an NTLM logon).
	EventNTLMAuth = "ntlm_authentication"
	// EventServiceInstall is System 7045 (a new service was installed on
	// the system), reported by the Service Control Manager provider --
	// the classic service-persistence/service-execution signal.
	EventServiceInstall = "service_install"
	// EventFileCreate is Sysmon Event ID 11 (FileCreate) -- a process
	// wrote a file, most useful for observing a payload being dropped to
	// disk before it's executed.
	EventFileCreate = "file_create"
	// EventRegistryPersistence is a registry persistence location other
	// than a Run/RunOnce key -- Winlogon Shell/Userinit, IFEO Debugger
	// hijacking, AppInit_DLLs, or a service's ImagePath -- classified by
	// internal/parsers/regpersist and reported identically whether the
	// evidence came from an RECmd hive snapshot or a real-time Sysmon
	// registry event. Run/RunOnce keys keep using EventRegistryRunKey
	// (unchanged from Phase 1) so existing behavior/tests are undisturbed.
	EventRegistryPersistence = "registry_persistence"
	// EventRegistryKeyLastWrite records that a registry key carried a
	// particular last-write timestamp -- an observation, not an action.
	// The hive records only that the key was written at that moment; it
	// does not say by whom, or that it was created then, so the event
	// type is named for exactly what the evidence supports. No detection
	// rule consumes it: it exists for timeline visibility and provenance.
	EventRegistryKeyLastWrite = "registry_key_last_write"
	// EventPowerShellHistoryCommand is one command recovered from a
	// PowerShell console history file. Deliberately distinct from
	// EventPowerShellScript (script-block logging), because that artifact
	// carries an execution timestamp and this one does not: a history
	// entry proves a command was TYPED, not when it ran, or whether it
	// ran at all.
	EventPowerShellHistoryCommand = "powershell_history_command"
	// EventBrowserVisit is one recorded page visit from a browser history
	// database.
	EventBrowserVisit = "browser_visit"
	// EventDNSQuery is Sysmon Event ID 22 (DNSEvent) -- a process resolved
	// a domain name.
	EventDNSQuery = "dns_query"
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
	// CorrelationCredentialChain (Phase 4) links a credential-related
	// event sequence: repeated failed logons into a success, or explicit
	// credential use into the privileged activity that followed it. See
	// internal/correlate/credential_chain.go.
	CorrelationCredentialChain = "credential_chain"
	// CorrelationServiceChain (Phase 4) links a service installation to
	// the service process actually starting, and onward to any network
	// connection that process made. See internal/correlate/service_chain.go.
	CorrelationServiceChain = "service_chain"
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
