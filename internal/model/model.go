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
// "ingested" (evidence changed, stale) while CaseStatus is "closed".
// The two are never conflated.
//
// Phase 13 gave CaseStatus teeth: it now governs whether the case's
// EVIDENCE may still be changed. Adding evidence to a contained or
// closed case used to be permitted; it no longer is (see
// EvidenceMutable). Reading, analysing, exporting and investigating a
// locked case all remain fully available -- immutability of the evidence
// set and readability of the investigation are separate concerns.
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

// EvidenceMutable reports whether a case's collected evidence may still
// be added to, imported, or deleted.
//
// The lifecycle divides in two at CONTAINMENT, which is the point an
// investigator declares the evidence set complete:
//
//	open, investigating -> evidence is still being gathered: mutable
//	contained, closed   -> the evidence set is settled: immutable
//
// This is deliberately NOT a statement about the investigation. A
// contained or closed case stays fully readable, analysable, exportable
// and investigable; only the SET OF COLLECTED EVIDENCE is frozen. An
// unknown status is treated as immutable, so a value this build does not
// recognize fails closed rather than silently permitting a mutation.
func EvidenceMutable(caseStatus string) bool {
	return caseStatus == CaseWorkflowOpen || caseStatus == CaseWorkflowInvestigating
}

// PriorityEditable reports whether a case's analyst triage priority may
// still be changed.
//
// Priority has a DIFFERENT lifecycle from evidence: it stays editable
// through containment, because triage urgency is a judgement about the
// investigation rather than a property of the evidence, and an
// investigator may well re-rank a contained case while writing it up.
// Only closing the case freezes it.
func PriorityEditable(caseStatus string) bool {
	return caseStatus != CaseWorkflowClosed
}

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
	// SourceTypeDiskImage is a whole-disk or whole-volume forensic image
	// (raw/dd or E01/EWF) holding NTFS file systems. Like an AD1, it is
	// cataloged without extracting anything; the artifacts the analyst
	// selects are read out of the image at import time. The collection's
	// ArchiveHash covers the container file(s) exactly as received.
	SourceTypeDiskImage = "disk_image"
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
	// ArtifactMFT is the NTFS Master File Table. One artifact type for
	// the table, not one per filesystem object: the $MFT is the evidence
	// file, and its records are that file's contents.
	ArtifactMFT = "ntfs_mft"
	// ArtifactUsnJournal is the NTFS USN change journal ($UsnJrnl:$J).
	ArtifactUsnJournal = "ntfs_usnjrnl"
	// ArtifactLogFile is the NTFS transaction log ($LogFile).
	ArtifactLogFile = "ntfs_logfile"
	// ArtifactBrowserCache is a browser HTTP cache entry.
	//
	// Deliberately SEPARATE from ArtifactBrowserHistory. History is
	// navigation evidence -- the user went somewhere. Cache is response
	// evidence -- the browser received and stored something, usually a
	// subresource nobody chose to load. Sharing one artifact type would
	// let the two be read as the same claim.
	ArtifactBrowserCache = "browser_cache"
	// ArtifactBrowserCacheIndex is a browser cache CONTAINER file: a
	// Chromium blockfile "index" or a Firefox cache1 "_CACHE_MAP_".
	//
	// Separate from ArtifactBrowserCache because it is a different kind
	// of evidence, not a different format of the same kind. A container
	// holds addresses and hashes -- how many entries the cache has, how
	// big it is, when it was created -- and no cache keys, so it yields
	// no URLs and no timeline events. Labelling one "browser cache
	// entry" would promise an analyst URLs that are not in the file.
	ArtifactBrowserCacheIndex = "browser_cache_index"

	// Recognition-only browser-cache classes.
	//
	// These are NOT parser outputs and no parser produces them. They are
	// what discovery concluded a file IS, structurally, when no parser
	// claimed it -- so triage can say "auxiliary payload file, its
	// metadata is in data_1" instead of filing every unclaimed file in a
	// cache directory under one message.
	//
	// A file carrying one of these types is never Supported: recognizing
	// something is not the same as being able to parse it, and the
	// supported count must keep meaning "Tracefall can turn this into
	// forensic records".
	//
	// The auxiliary classes. Three, not one: an analyst told "auxiliary
	// file" learns nothing actionable, while "rankings, and the times in
	// it cannot be attributed to a URL" and "payload blocks, the
	// metadata is in data_1" each say where to look next.
	//
	// ArtifactBrowserCacheRankings is a blockfile rankings file (data_0):
	// LRU nodes carrying use times but no cache key.
	ArtifactBrowserCacheRankings = "browser_cache_rankings"
	// ArtifactBrowserCachePayload is a blockfile payload block file
	// (data_2 / data_3): stream content whose describing metadata is in
	// the data_1 entry record that addresses it.
	ArtifactBrowserCachePayload = "browser_cache_payload"
	// ArtifactBrowserCacheBody is a cached response body written to its
	// own file (f_######), likewise described by a data_1 entry record.
	ArtifactBrowserCacheBody = "browser_cache_body"
	// ArtifactBrowserCacheAuxiliary is the generic auxiliary class, used
	// where the specific kind is not established.
	ArtifactBrowserCacheAuxiliary = "browser_cache_auxiliary"
	// ArtifactBrowserCacheState covers a cache's bookkeeping: journals,
	// lock files, temporary indexes. Not evidence of a cached resource
	// and not a parse failure -- a cache simply has housekeeping files.
	ArtifactBrowserCacheState = "browser_cache_state"
	// ArtifactBrowserCacheVariant is a browser-cache structure Tracefall
	// DOES read, in a version or state this build does not decode. It is
	// the one recognition class that may still hold recoverable forensic
	// data, and it is triaged accordingly.
	ArtifactBrowserCacheVariant = "browser_cache_variant"
	// ArtifactBrowserCacheUnknown is the honest fallback: the file is in
	// a browser cache directory and its bytes settled nothing.
	ArtifactBrowserCacheUnknown = "browser_cache_unknown"

	// ArtifactLNK is a Windows shortcut (.lnk).
	//
	// A shortcut is REFERENCE evidence: it records where a target was,
	// how big it was, and the target's own timestamps as they stood when
	// the shortcut was last written -- often the only surviving
	// description of a file that has since been deleted.
	//
	// It is not execution evidence. Windows writes shortcuts for files
	// that were merely opened, saved or listed in a dialog. Nothing that
	// consumes this artifact type may treat it as a run.
	ArtifactLNK = "windows_lnk"
	// ArtifactRecycleBin is a Windows Recycle Bin $I metadata record: the
	// original path, original size and deletion time of a deleted file.
	//
	// Deliberately distinct from the paired $R file, which holds the
	// content and which Tracefall does not read. An $I record proves a
	// file was sent to the Recycle Bin at a recorded time; it says
	// nothing about the content's current availability.
	ArtifactRecycleBin = "recycle_bin_metadata"
	// ArtifactRecycleBinContent is the $R half of a Recycle Bin pair: the
	// CONTENT of a deleted file.
	//
	// Deliberately distinct from ArtifactRecycleBin. The two halves are
	// different evidence answering different questions -- the $I says
	// WHAT was deleted and WHEN, the $R holds WHAT IT WAS -- and an
	// analyst has to be able to tell a metadata record from recovered
	// content at a glance. Sharing one artifact type would also make a
	// pair look like two copies of the same thing.
	//
	// A $R file carries no metadata of its own. Every identifying fact
	// on a record of this type is attributed to the paired $I record it
	// came from; see internal/parsers/recyclebincontent.
	ArtifactRecycleBinContent = "recycle_bin_content"
	// ArtifactJumpListAutomatic is a *.automaticDestinations-ms Jump
	// List: an OLE compound file whose numbered streams hold embedded
	// shortcuts, beside a DestList recording the most-recently-used
	// order, an access count and a last-recorded access time per entry.
	//
	// A Jump List entry proves that an application HOLDS A REFERENCE to
	// a target. It is not proof of execution: Windows records items
	// opened, saved, previewed or merely reached through a dialog.
	ArtifactJumpListAutomatic = "jumplist_automatic"
	// ArtifactJumpListCustom is a *.customDestinations-ms Jump List: a
	// different container entirely -- embedded shortcuts written back to
	// back, supplied by the application for its own task and pinned
	// categories.
	//
	// Kept distinct from the automatic list because the two carry
	// different evidence: a custom list has no DestList, so it records
	// no access times or ordering, and an analyst must not read one as
	// though it did.
	ArtifactJumpListCustom = "jumplist_custom"

	// ArtifactUserAssist is a Windows UserAssist entry, read out of an
	// NTUSER.DAT hive.
	//
	// A SEPARATE artifact type from ArtifactRegistryHive even though the
	// evidence FILE is a hive, because the two answer different
	// questions. The source file stays classified as a registry hive --
	// that is what was collected and hashed. An EVENT, though, is what an
	// analyst filters a timeline by, and "UserAssist" tells them what the
	// observation is; "registry hive" tells them only where it was
	// stored. See docs/windows-artifacts.md.
	ArtifactUserAssist = "userassist"
	// ArtifactShellBags is a Windows ShellBags (BagMRU) entry, read out
	// of an NTUSER.DAT or UsrClass.dat hive. Separate from
	// ArtifactRegistryHive for the same reason as ArtifactUserAssist.
	ArtifactShellBags = "shellbags"

	// ArtifactAmcache is a Windows Amcache entry, read out of
	// Amcache.hve. Separate from ArtifactRegistryHive for the same
	// reason as ArtifactUserAssist: the FILE is a hive, but the analyst
	// filters a timeline by what the observation IS.
	ArtifactAmcache = "amcache"
	// ArtifactRecentDocs is a Windows RecentDocs MRU entry: a document
	// name Explorer recorded as recently opened.
	ArtifactRecentDocs = "recent_docs"
	// ArtifactRunMRU is a Windows Run-dialog MRU entry.
	ArtifactRunMRU = "run_mru"
	// ArtifactTypedPaths is a path typed into the Explorer address bar.
	ArtifactTypedPaths = "typed_paths"
	// ArtifactOpenSaveMRU is an Open/Save common-dialog MRU entry.
	ArtifactOpenSaveMRU = "opensave_mru"
	// ArtifactMUICache is a MUICache application display-name entry.
	ArtifactMUICache = "muicache"

	// ArtifactSAM is a Windows local account record read out of a SAM
	// hive. Separate from ArtifactRegistryHive for the same reason as
	// ArtifactUserAssist -- the FILE is a hive, but what the analyst is
	// looking at is the local account database, and it is the one
	// artifact in this family that can carry credential material.
	//
	// An analyst who filters the timeline to "Windows SAM" wants the
	// accounts, not every persistence key that happened to be in the
	// same file.
	ArtifactSAM = "sam_account"

	// ArtifactUnsupportedBrowserDB is a browser-related SQLite database
	// Tracefall recognizes but does not parse -- cookies, saved logins,
	// favicons, autofill, media state, quota bookkeeping.
	//
	// It exists so those files stop being catalogued as browser history.
	// A browser profile holds a dozen databases and exactly one of them
	// is history; claiming all of them and failing the rest at import
	// reported 25 files of intact evidence as broken. Recognized is not
	// parsed: nothing is extracted from these, and the catalog says so.
	ArtifactUnsupportedBrowserDB = "unsupported_browser_artifact"

	// ArtifactRegistryTransactionLog is a registry transaction log --
	// SAM.LOG1, SYSTEM.LOG2 and the rest.
	//
	// A REGF file, sharing the hive signature, with a different base
	// block file type and no key tree. Classifying it as a hive
	// catalogued 20 of them in one image and failed every one with "this
	// is a registry transaction log, not a hive": true, and discovered
	// far too late to be useful. The file type is in the first 512
	// bytes, so the distinction belongs at classification time.
	ArtifactRegistryTransactionLog = "registry_transaction_log"
	// ArtifactActivitiesCache is a Windows Timeline activity record from
	// ActivitiesCache.db.
	ArtifactActivitiesCache = "activities_cache"
	// ArtifactBrowserDownload is a browser download record. Deliberately
	// SEPARATE from ArtifactBrowserHistory: a download and a page visit
	// are different claims about different actions, and merging them
	// would let "this file arrived" read as "this page was viewed".
	ArtifactBrowserDownload = "browser_download"

	ArtifactScheduledTask = "scheduled_task" // raw Task Scheduler XML

	// ArtifactFileZillaServer is a server entry from a FileZilla
	// connection file -- recentservers.xml or the Site Manager's
	// sitemanager.xml.
	//
	// A CONFIGURATION record, kept apart from every network artifact for
	// that reason. It says the client held this host, port, protocol and
	// username; it does not say a connection was made at any time, that
	// one succeeded, or that anything was transferred.
	ArtifactFileZillaServer = "filezilla_server"

	// ArtifactImageMetadata is metadata embedded in an image file --
	// EXIF, and the JPEG frame header.
	//
	// This is ordinary file CONTENT. A camera writes it and so does every
	// editor and exporter downstream, so it identifies what CLAIMED to
	// produce the image rather than establishing that it did.
	ArtifactImageMetadata = "image_metadata"

	// ArtifactImageGPS is a geographic coordinate embedded in an image's
	// EXIF GPS block.
	//
	// Deliberately SEPARATE from ArtifactImageMetadata: a position is a
	// much stronger claim than a camera model, it is the one EXIF field
	// an analyst filters a case down to, and merging the two would bury
	// it among thousands of images that carry no location at all.
	ArtifactImageGPS = "image_gps"
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

	// Filesystem events, from NTFS $MFT records (Phase 15).
	//
	// FOUR SEPARATE TYPES, not one "filesystem" event with a timestamp
	// field. NTFS records four independent times per file and they mean
	// different things: when it came into existence, when its contents
	// were last written, when its MFT record last changed, and when it
	// was last read. Collapsing them would make "created" and "accessed"
	// indistinguishable on a timeline, which is precisely the
	// distinction an examiner is looking for.
	//
	// These describe the FILESYSTEM's own record of a file. They assert
	// nothing about who acted or what ran -- NTFS records neither -- and
	// nothing downstream may infer a user or a process from them.
	EventFilesystemCreated  = "filesystem_created"
	EventFilesystemModified = "filesystem_modified"
	EventFilesystemChanged  = "filesystem_changed"
	EventFilesystemAccessed = "filesystem_accessed"

	// USN change journal events (Phase 16).
	//
	// Separate from the filesystem_* types above because they come from
	// a DIFFERENT SOURCE with different guarantees. An $MFT event is the
	// current state of a file's metadata; a USN event is a historical
	// record that the volume observed a change -- including for files
	// that no longer exist. An examiner must be able to tell which they
	// are reading, so the two vocabularies never merge.
	//
	// One event per USN record, typed by the most significant reason bit
	// present. The complete raw reason mask travels with every event, so
	// the translation can always be checked against what the journal
	// actually said.
	EventUsnCreate         = "usnjrnl_create"
	EventUsnDelete         = "usnjrnl_delete"
	EventUsnModify         = "usnjrnl_modify"
	EventUsnRename         = "usnjrnl_rename"
	EventUsnMetadataChange = "usnjrnl_metadata_change"

	// EventBrowserCacheEntry is a resource the browser cached (Phase 14).
	//
	// ONE event type, not several. The cache formats Tracefall reads
	// record a single meaningful time per entry -- when it was last
	// fetched -- so a second event type would either duplicate that
	// observation or need a timestamp the cache does not store.
	//
	// This event asserts that the browser HELD a cached copy of a
	// resource at a recorded time. It asserts nothing about the user:
	// not that they navigated to it, saw it, clicked it, downloaded it
	// or ran it. Most cache entries are subresources fetched
	// automatically by a page.
	EventBrowserCacheEntry = "browser_cache_entry"

	// LNK target metadata (Phase 17). THREE event types, one per
	// timestamp the shortcut records, mirroring how the $MFT's four
	// timestamps are handled: each is a distinct observation about the
	// TARGET FILE, and collapsing them would discard two of the three.
	//
	// Every one of these describes the target's own MACE time as it
	// stood when the shortcut was last written. None of them is a launch
	// of the target, and none may be read as one -- see ArtifactLNK.
	EventLnkTargetCreated  = "lnk_target_created"
	EventLnkTargetModified = "lnk_target_modified"
	EventLnkTargetAccessed = "lnk_target_accessed"

	// Jump List entries (phase 21). TWO event types, because the two
	// timestamps a Jump List can supply mean different things and must
	// never be collapsed:
	//
	// EventJumpListEntryAccess is the Jump List's OWN timestamp -- when
	// the application last recorded reaching the item, from the DestList.
	// It is the closest thing the artifact has to a moment of use, and it
	// is still not proof of execution: an item is recorded when opened,
	// saved, previewed, or reached through a dialog.
	EventJumpListEntryAccess = "jumplist_entry_access"
	// EventJumpListTargetMetadata is a TARGET FILE timestamp carried by
	// the embedded shortcut -- the target's own creation, write or access
	// time as it stood when the shortcut was written. It describes the
	// file, not any use of it, exactly as the standalone LNK events do.
	EventJumpListTargetMetadata = "jumplist_target_metadata"

	// EventRecycleBinDeletion is the moment a file was moved to the
	// Recycle Bin, from an $I metadata record.
	//
	// It is NOT the file's last-write time, not its creation time, and
	// not evidence that anything ran. One event type, because an $I
	// record carries exactly one timestamp.
	EventRecycleBinDeletion = "recyclebin_deletion"

	// EventUserAssistActivity is one UserAssist entry.
	//
	// Named "activity", not "execution", and that is the whole point.
	// UserAssist counts launches Explorer performed -- from the Start
	// menu, the desktop, a shortcut. A program run from a script, a
	// service or a command prompt never appears, so the absence of an
	// entry proves nothing, and the presence of one is evidence that this
	// USER's shell launched the item, not that a process was created at
	// the recorded instant. Security 4688 is what records that.
	EventUserAssistActivity = "userassist_activity"

	// EventShellBagNavigation is one reconstructed ShellBags entry:
	// Explorer recorded a folder.
	//
	// Not "file opened" and not "folder opened at time T". The registry
	// key's last-write time is when Explorer last updated that node of
	// the BagMRU tree; the shell item's own DOS timestamps are local-time
	// wall-clock readings with no timezone and are reported as metadata
	// rather than placed on the timeline. See internal/shellbag.
	EventShellBagNavigation = "shellbag_navigation"

	// EventAmcacheApplication is one Amcache entry.
	//
	// "Application", not "execution". Amcache records that Windows'
	// application-compatibility machinery CATALOGUED a binary -- which
	// happens on installation, on inventory scans and on execution
	// alike. It is application-presence evidence with strong identifying
	// metadata (path, SHA-1, publisher, size), not a process-creation
	// record. Security 4688 is what records that.
	EventAmcacheApplication = "amcache_application"

	// EventSAMLocalAccount is one Windows LOCAL ACCOUNT record read from
	// a SAM hive: the account's name, its RID, its account-control
	// flags, its stored timestamps, and -- when the SYSTEM hive's boot
	// key was also present -- its NTLM PASSWORD HASH.
	//
	// What this event is NOT, deliberately and in every case:
	//
	//   - not a logon. An account existing is not an authentication.
	//     Security 4624/4625 record those.
	//   - not a password change. The record carries a
	//     "password last set" timestamp, which is reported AS THAT and
	//     is not the event's own time.
	//   - not persistence, and not execution. Nothing here ran.
	//   - not a finding. A local account having a password hash is what
	//     a Windows machine looks like; it is evidence, and calling it
	//     an alert would bury the real ones.
	//
	// The event carries NO TIMESTAMP of its own. A SAM record does not
	// say when it was written, and the hive's or the file's modification
	// time would be a different fact wearing this event's clothes. The
	// account's own timestamps travel as explicitly-labelled fields.
	//
	// The NTLM value is a PASSWORD HASH. It is not a password, it is not
	// reversible into one, and Tracefall does not attempt to recover
	// one. See internal/sam.
	EventSAMLocalAccount = "sam_local_account"

	// EventRecentDocument is one RecentDocs MRU entry: Explorer recorded
	// a document as recently opened. The key's last-write time dates the
	// MOST RECENT entry only -- see internal/parsers/registry.
	EventRecentDocument = "recent_document"

	// EventRunMRUCommand is one Run-dialog MRU entry: a command was
	// TYPED into the Run dialog and accepted. Not proof it executed
	// successfully, and not a process-creation record.
	EventRunMRUCommand = "run_mru_command"

	// EventTypedPath is one Explorer address-bar entry: a path was typed
	// there. Not proof the path was opened, and certainly not that
	// anything was executed.
	EventTypedPath = "typed_path"

	// EventOpenSaveMRU is one Open/Save common-dialog MRU entry: a file
	// was selected in an open or save dialog.
	EventOpenSaveMRU = "opensave_mru"

	// EventMUICacheEntry is one MUICache entry: Windows cached an
	// application's display name. Presence evidence only -- the shell
	// caches these on enumeration, not just on launch.
	EventMUICacheEntry = "muicache_entry"

	// EventActivityRecorded is one Windows Timeline activity.
	//
	// "Recorded", not "executed": the Activities provider logs
	// application and document focus, and an activity row is not a
	// process-creation record.
	EventActivityRecorded = "activity_recorded"

	// EventBrowserDownload is one browser download record: the browser
	// retrieved a resource to a local path. Downloaded is not opened and
	// is not executed.
	EventBrowserDownload = "browser_download"

	// EventLogoff is a Windows logoff record (Security 4634/4647). It
	// bounds a session that EventLogonSuccess opened, which is what makes
	// "who was at this machine, and when" answerable rather than
	// open-ended.
	EventLogoff = "logoff"

	// EventFileZillaServerEntry is one server entry held by a FileZilla
	// client. It carries NO TIMESTAMP: neither recentservers.xml nor
	// sitemanager.xml records when an entry was created or used, and the
	// file's own mtime describes the file rather than the entry.
	//
	// It is not a network connection, not a logon, and not a transfer.
	// The strongest reading recentservers.xml supports is that a
	// connection to this host was ATTEMPTED from this user's profile.
	EventFileZillaServerEntry = "filezilla_server_entry"

	// EventImageMetadataRecorded is the metadata one image file carries.
	// Its time, when it has one, is the EXIF DateTimeOriginal -- when the
	// exposure was recorded according to the writing device's own clock.
	// It is never a filesystem timestamp.
	EventImageMetadataRecorded = "image_metadata_recorded"

	// EventImageGPSRecorded is a coordinate an image's EXIF GPS block
	// recorded. The position is OBSERVED in the file; any country derived
	// from it is DERIVED, and the event keeps the two apart.
	EventImageGPSRecorded = "image_gps_recorded"
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

	// AnalysisRunID attributes this finding to the AnalysisRun that
	// produced it (Phase 11).
	//
	// EMPTY means the finding predates run tracking. It is reported as
	// legacy, never backfilled: an analysis run that was never recorded
	// cannot be reconstructed, and stamping a historical finding with a
	// plausible-looking run id would fabricate provenance. Detection
	// itself is unaffected -- this field is set at persist time and is
	// not an input to any rule.
	AnalysisRunID string `json:"analysis_run_id,omitempty"`
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
	// CorrelationWebResource (Phase 14) links the SAME web host as it
	// appears in independent browser artifacts -- a recorded visit in
	// browser history and a stored response in the browser cache. It is
	// corroboration between sources, not a verdict: see
	// internal/correlate/web_resource.go for what it does and does not
	// claim.
	CorrelationWebResource = "web_resource"
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

	// AnalysisRunID attributes this correlation to the AnalysisRun that
	// produced it, exactly as Finding.AnalysisRunID does.
	//
	// It exists so a correlation can be excluded from current results
	// when its run is invalidated -- a correlation is derived from a set
	// of events, and when those events are deleted it describes evidence
	// the case no longer holds. Empty for rows written before the field
	// existed; such rows are reported as legacy, never retrofitted to an
	// invented run.
	AnalysisRunID string `json:"analysis_run_id,omitempty"`
}
