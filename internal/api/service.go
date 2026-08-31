// Package api is Tracefall's HTTP surface: a thin Service that
// orchestrates ingest -> store -> detect -> correlate -> attck for the
// case lifecycle, plus handlers that expose it as JSON. The service layer
// contains no forensic analysis logic itself -- it only sequences calls
// into the layers that do (internal/ingest, internal/detect,
// internal/correlate, internal/attck) and persists results via
// internal/store. Keeping that logic out of the HTTP handlers is what
// lets internal/web stay a dumb JSON consumer, never a place forensic
// decisions get made.
//
// A case can contain many evidence Collections (see internal/model.Collection);
// timeline, findings, correlations, and ATT&CK coverage always operate
// across every collection in the case, never just one. That's mostly
// "free": internal/detect and internal/correlate have always taken the
// case's full event list, not a per-collection one -- the work this
// package does is ingesting more than one collection into that list
// correctly, deduplicating real re-observations of the same event
// without losing per-collection provenance. See deduplicate() below and
// docs/data-model.md.
package api

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"tracefall/internal/ad1"
	"tracefall/internal/archive"
	"tracefall/internal/attck"
	"tracefall/internal/casefiles"
	"tracefall/internal/correlate"
	"tracefall/internal/detect"
	"tracefall/internal/evtx"
	"tracefall/internal/ingest"
	"tracefall/internal/investigate"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
	"tracefall/internal/regf"
	"tracefall/internal/store"
)

var (
	ErrCaseNotFound       = errors.New("case not found")
	ErrNotIngested        = errors.New("case has no ingested evidence yet")
	ErrCollectionNotFound = errors.New("evidence collection not found")
	// ErrCaseNameRequired means the case name was empty after trimming
	// leading/trailing whitespace (see CreateCase's normalization).
	ErrCaseNameRequired = errors.New("name is required")
	// ErrDuplicateCase means a case with this name (trimmed and
	// case-insensitively compared -- see docs/data-model.md's "Case name
	// uniqueness" section) already exists. Wrapped by *DuplicateCaseError,
	// which identifies that case -- match this sentinel with errors.Is
	// for status-code dispatch, or use errors.As to get the structured
	// detail.
	ErrDuplicateCase = errors.New("a case with this name already exists")
	// ErrUploadTooLarge means the uploaded archive exceeded the
	// configured maximum upload size before it could even be validated.
	ErrUploadTooLarge = errors.New("uploaded file exceeds the maximum upload size")
	// ErrDuplicateEvidence means the archive/source hash being added
	// already belongs to another collection in the same case. Wrapped by
	// *DuplicateEvidenceError, which identifies that collection -- match
	// this sentinel with errors.Is for status-code dispatch, or use
	// errors.As to get the structured detail. See docs/data-model.md's
	// "Deduplication" section for how this differs from event-level dedup.
	ErrDuplicateEvidence = errors.New("evidence already exists in this case")
	// ErrUnsupportedEvidence means the uploaded/local-path input was
	// recognized as a format Tracefall knows about (currently: AD1) but
	// can't actually be processed -- encrypted, an unsupported version,
	// corrupt/structurally invalid, or (upload only) segmented with only
	// one segment provided. Always wraps a more specific underlying
	// error (see internal/ad1's sentinels) via %w; never used for "this
	// isn't a recognized format at all" (that case falls through to the
	// existing ZIP path's own ErrInvalidArchive instead -- see
	// DiscoverEvidenceFromUpload).
	ErrUnsupportedEvidence = errors.New("evidence package format is not supported")
	// ErrEvidencePathNotFound means the local filesystem path an
	// investigator typed into Add Evidence doesn't exist, or the server
	// can't read it. Distinct from ErrUnsupportedEvidence (the path
	// exists but Tracefall can't process what's in it) because the
	// remedy is different: check the path, not the evidence.
	ErrEvidencePathNotFound = errors.New("evidence path does not exist or is not readable")
	// ErrNoEvidenceFound means the evidence source was read successfully
	// but contained no files at all -- an empty directory, an empty
	// archive, an AD1 with no entries. There is nothing to catalog, so
	// no collection is created; a collection with zero files is not a
	// useful thing for an investigator to be left holding.
	ErrNoEvidenceFound = errors.New("no evidence files were found in this location")
	// ErrInvalidAD1 means the input WAS recognized as an AD1 forensic
	// image (by magic bytes, see ad1.Sniff) but cannot be read --
	// corrupt, truncated, structurally invalid, encrypted, or an
	// unsupported version. Separate from ErrUnsupportedEvidence, which
	// means "this isn't a format Tracefall reads at all": an analyst
	// handed a broken AD1 needs to know their IMAGE is the problem, not
	// that they picked the wrong kind of file. Always wraps internal/ad1's
	// own sentinel, which names the specific defect.
	ErrInvalidAD1 = errors.New("the AD1 forensic image is invalid or cannot be read")
)

// DuplicateEvidenceError reports that a collection with the same
// archive/source hash already exists in the case, identifying it so the
// caller (API response, dashboard) can tell the investigator exactly
// which existing collection their upload/ingest duplicates.
type DuplicateEvidenceError struct {
	CollectionID    string
	CollectionLabel string // e.g. "Collection #1", numbered by upload order
}

func (e *DuplicateEvidenceError) Error() string {
	return fmt.Sprintf("%s: this evidence package has already been added to this case as %s", ErrDuplicateEvidence, e.CollectionLabel)
}

func (e *DuplicateEvidenceError) Unwrap() error { return ErrDuplicateEvidence }

// DuplicateCaseError reports that a case with the same name (trimmed,
// case-insensitive) already exists, identifying it so the caller (API
// response, dashboard) can tell the investigator exactly which existing
// case their chosen name duplicates.
type DuplicateCaseError struct {
	CaseID   string
	CaseName string // the existing case's stored name (trimmed, original casing)
}

func (e *DuplicateCaseError) Error() string {
	return fmt.Sprintf("%s: %q is already in use", ErrDuplicateCase, e.CaseName)
}

func (e *DuplicateCaseError) Unwrap() error { return ErrDuplicateCase }

type Service struct {
	store *store.Store
	files *casefiles.Store
	// extractLimits bounds ZIP extraction (file count, per-file/total
	// size, compression ratio) -- see internal/archive. Defaults to
	// archive.DefaultLimits; overridable for tests.
	extractLimits archive.Limits
	// ad1Limits bounds AD1 cataloging/extraction (entries visited, name/
	// metadata/path lengths, per-file decompressed size) -- see
	// internal/ad1. Defaults to ad1.DefaultLimits; overridable for tests.
	ad1Limits ad1.Limits
	// jobs tracks running background imports. In-memory only and never
	// consulted by the synchronous import path -- see importjob.go for
	// why job state must not live in the database.
	jobs *importJobs
}

func NewService(s *store.Store, files *casefiles.Store) *Service {
	return &Service{store: s, files: files, extractLimits: archive.DefaultLimits, ad1Limits: ad1.DefaultLimits, jobs: newImportJobs()}
}

// ---------- Cases ----------

// CreateCase adds a new case, normalizing and enforcing name uniqueness
// per docs/data-model.md's "Case name uniqueness" section: name is
// trimmed of leading/trailing whitespace before storing (so "Foo" and
// " Foo " collide), and uniqueness itself is also case-insensitive (so
// "Foo" and "foo" collide) -- matching how idx_cases_name_unique
// compares names at the database level.
//
// Duplicate detection is two-layered, the same pattern as
// checkDuplicateEvidence/commitDiscovery below: a
// SELECT-based pre-check here avoids the common case ever reaching the
// database with a doomed INSERT, and the (case_id-less, case-wide)
// idx_cases_name_unique index is the race-safe backstop for two
// concurrent requests that both pass the pre-check before either has
// inserted -- store.CreateCase translates that constraint violation to
// store.ErrDuplicateCase, which is re-resolved to a DuplicateCaseError
// identifying whichever case actually won the race.
func (s *Service) CreateCase(name, description string) (model.Case, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return model.Case{}, ErrCaseNameRequired
	}
	if err := s.checkDuplicateCase(name); err != nil {
		return model.Case{}, err
	}

	now := time.Now().UTC()
	c := model.Case{
		ID:          uuid.NewString(),
		Name:        name,
		Description: description,
		Status:      model.CaseStatusCreated,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	c.CaseStatus = model.CaseWorkflowOpen
	c.Priority = model.CasePriorityMedium
	if err := s.store.CreateCase(c); err != nil {
		if errors.Is(err, store.ErrDuplicateCase) {
			if existing, found, ferr := s.store.FindCaseByName(name); ferr == nil && found {
				return model.Case{}, &DuplicateCaseError{CaseID: existing.ID, CaseName: existing.Name}
			}
			return model.Case{}, ErrDuplicateCase
		}
		return model.Case{}, fmt.Errorf("creating case: %w", err)
	}
	s.audit(c.ID, model.AuditCaseCreated, model.TargetCase, c.ID, fmt.Sprintf("Case %q created", name))
	return c, nil
}

// audit records one action in the case's audit trail (Phase 6). Failures
// to write the audit event are deliberately NOT propagated as an error
// from the calling operation -- e.g. a note being saved successfully
// must not fail the whole request just because the secondary audit-log
// insert failed. Audit logging is a best-effort record of what happened,
// never a gate on whether the primary action succeeds. See
// docs/analyst-workflow.md's "Audit log" section.
func (s *Service) audit(caseID, action, targetType, targetID, summary string) {
	_ = s.store.CreateAuditEvent(model.AuditEvent{
		ID:         uuid.NewString(),
		CaseID:     caseID,
		Timestamp:  time.Now().UTC(),
		Action:     action,
		Actor:      model.ActorLocalUser,
		TargetType: targetType,
		TargetID:   targetID,
		Summary:    summary,
	})
}

func (s *Service) checkDuplicateCase(name string) error {
	existing, found, err := s.store.FindCaseByName(name)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	return &DuplicateCaseError{CaseID: existing.ID, CaseName: existing.Name}
}

func (s *Service) ListCases() ([]model.Case, error) {
	return s.store.ListCases()
}

func (s *Service) GetCase(id string) (model.Case, error) {
	c, err := s.store.GetCase(id)
	if err != nil {
		return model.Case{}, ErrCaseNotFound
	}
	return c, nil
}

// Summary is the case-level rollup the dashboard's overview panel and
// GET /cases/{id} are built from. Every count here spans the case's
// entire evidence set (all collections), consistent with findings,
// correlations, and the timeline never being scoped to just one upload.
type Summary struct {
	Collections int `json:"collections"`
	// SourceFiles is every active (non-deleted) cataloged file, imported
	// or not -- see internal/model.SourceFile's discovered/imported life
	// cycle. ImportedSourceFiles is the subset an investigator actually
	// selected and that produced events; the two differ whenever a
	// collection has files still sitting as merely "discovered".
	SourceFiles         int            `json:"source_files"`
	ImportedSourceFiles int            `json:"imported_source_files"`
	Events              int            `json:"events"`
	Findings            int            `json:"findings"`
	Correlations        int            `json:"correlations"`
	SeverityCounts      map[string]int `json:"severity_counts"`
	TechniqueCount      int            `json:"technique_count"`
	// Investigations/InvestigationSeverityCounts (Phase 5) are the
	// case-overview rollup of internal/investigate's grouped, scored
	// investigations -- computed here from the same
	// events/findings/correlations CaseSummary already loaded, at no
	// extra store cost.
	Investigations              int            `json:"investigations"`
	InvestigationSeverityCounts map[string]int `json:"investigation_severity_counts"`
}

func (s *Service) CaseSummary(id string) (Summary, error) {
	collections, err := s.store.ListCollections(id)
	if err != nil {
		return Summary{}, err
	}
	sources, err := s.store.ListSourceFiles(id)
	if err != nil {
		return Summary{}, err
	}
	events, err := s.store.ListEvents(id)
	if err != nil {
		return Summary{}, err
	}
	findings, err := s.store.ListFindings(id)
	if err != nil {
		return Summary{}, err
	}
	correlations, err := s.store.ListCorrelations(id)
	if err != nil {
		return Summary{}, err
	}

	sevCounts := map[string]int{model.SeverityCritical: 0, model.SeverityHigh: 0, model.SeverityMedium: 0, model.SeverityLow: 0}
	techniques := map[string]bool{}
	for _, f := range findings {
		sevCounts[f.Severity]++
		for _, t := range f.Techniques {
			techniques[t] = true
		}
	}
	imported := 0
	for _, sf := range sources {
		if sf.ImportStatus == model.SourceFileImported {
			imported++
		}
	}

	investigations := investigate.Run(id, events, findings, correlations)
	invSevCounts := map[string]int{model.SeverityCritical: 0, model.SeverityHigh: 0, model.SeverityMedium: 0, model.SeverityLow: 0}
	for _, inv := range investigations {
		invSevCounts[inv.Severity]++
	}

	return Summary{
		Collections:                 len(collections),
		SourceFiles:                 len(sources),
		ImportedSourceFiles:         imported,
		Events:                      len(events),
		Findings:                    len(findings),
		Correlations:                len(correlations),
		SeverityCounts:              sevCounts,
		TechniqueCount:              len(techniques),
		Investigations:              len(investigations),
		InvestigationSeverityCounts: invSevCounts,
	}, nil
}

// ---------- Evidence collections ----------

func (s *Service) ListCollections(caseID string) ([]model.Collection, error) {
	return s.store.ListCollections(caseID)
}

// CollectionDetail is one collection plus the source files it produced,
// for GET /cases/{id}/evidence/{collectionId}.
// ParserCoverage is one (parser, artifact type) pair actually
// represented in a collection, with how many source files and events it
// produced -- Phase 6's "parser coverage" collection-metadata
// requirement. Computed at read time from SourceFiles already loaded for
// CollectionDetail, never a separate stored field.
type ParserCoverage struct {
	Parser       string `json:"parser"`
	ArtifactType string `json:"artifact_type"`
	FileCount    int    `json:"file_count"`
	EventCount   int    `json:"event_count"`
}

// CollectionDetail is a Collection plus everything Phase 6 section 4
// requires be visible about it -- most of it (ID, archive hash,
// acquisition time, source type, file counts) is already on
// model.Collection directly; HostsObserved/EarliestEvent/LatestEvent/
// ParserCoverage are computed here at read time from the collection's
// actual imported events, never invented or estimated. A collection with
// no imported events yet (still all "discovered") has nil
// Earliest/LatestEvent and an empty HostsObserved -- the frontend shows
// "Unknown" for these rather than Tracefall guessing.
type CollectionDetail struct {
	model.Collection
	SourceFiles    []TriagedSourceFile `json:"source_files"`
	Coverage       Coverage            `json:"coverage"`
	HostsObserved  []string            `json:"hosts_observed"`
	EarliestEvent  *time.Time          `json:"earliest_event,omitempty"`
	LatestEvent    *time.Time          `json:"latest_event,omitempty"`
	ParserCoverage []ParserCoverage    `json:"parser_coverage"`
}

func (s *Service) CollectionDetail(caseID, collectionID string) (CollectionDetail, error) {
	c, err := s.store.GetCollection(collectionID)
	if err != nil || c.CaseID != caseID {
		return CollectionDetail{}, ErrCollectionNotFound
	}
	sources, err := s.store.ListSourceFilesByCollection(collectionID)
	if err != nil {
		return CollectionDetail{}, err
	}
	events, err := s.store.ListEventsByCollection(collectionID)
	if err != nil {
		return CollectionDetail{}, err
	}

	hostSet := map[string]bool{}
	var earliest, latest *time.Time
	for _, e := range events {
		if e.Host != "" {
			hostSet[e.Host] = true
		}
		ts := e.Timestamp
		if earliest == nil || ts.Before(*earliest) {
			t := ts
			earliest = &t
		}
		if latest == nil || ts.After(*latest) {
			t := ts
			latest = &t
		}
	}
	hosts := make([]string, 0, len(hostSet))
	for h := range hostSet {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	type coverageKey struct{ parser, artifactType string }
	coverage := map[coverageKey]*ParserCoverage{}
	var coverageOrder []coverageKey
	for _, sf := range sources {
		if sf.ImportStatus != model.SourceFileImported {
			continue
		}
		k := coverageKey{sf.Parser, sf.ArtifactType}
		entry, ok := coverage[k]
		if !ok {
			entry = &ParserCoverage{Parser: sf.Parser, ArtifactType: sf.ArtifactType}
			coverage[k] = entry
			coverageOrder = append(coverageOrder, k)
		}
		entry.FileCount++
		entry.EventCount += sf.EventCount
	}
	parserCoverage := make([]ParserCoverage, 0, len(coverageOrder))
	for _, k := range coverageOrder {
		parserCoverage = append(parserCoverage, *coverage[k])
	}

	triaged := triageAll(sources)
	return CollectionDetail{
		Collection:     c,
		SourceFiles:    triaged,
		Coverage:       computeCoverage(triaged),
		HostsObserved:  hosts,
		EarliestEvent:  earliest,
		LatestEvent:    latest,
		ParserCoverage: parserCoverage,
	}, nil
}

// ---------- Adding evidence: discover, then import ----------
//
// Adding evidence is two explicit steps, not one (see docs/data-model.md's
// "Evidence selection workflow" section): DiscoverEvidenceFromUpload/Path
// safely extracts (for an upload) or reads (for a local path) every file
// in the package and catalogs each one as a model.SourceFile -- supported
// or not -- without parsing anything. Nothing becomes evidence (no
// events, no findings possible) until ImportEvidence is called with the
// specific file IDs an investigator selected. This lets an investigator
// choose exactly which files matter before Tracefall does any parsing
// work on them, rather than every supported file in a package being
// ingested automatically.

// DiscoverResult is returned from starting to add evidence to a case --
// the collection now exists and every file in it has been cataloged, but
// none of it has been parsed yet. See ImportEvidence.
type DiscoverResult struct {
	Collection model.Collection `json:"collection"`
	// SourceFiles is every file discovered, whatever its status, each
	// carrying its triage classification (artifact class, forensic
	// priority, and -- when unsupported -- why). The classification is
	// computed at read time from the capability registry, never stored;
	// see triage.go.
	SourceFiles      []TriagedSourceFile `json:"source_files"`
	DiscoveredCount  int                 `json:"discovered_count"`
	SupportedCount   int                 `json:"supported_count"`
	UnsupportedCount int                 `json:"unsupported_count"`
	DuplicateCount   int                 `json:"duplicate_count"` // supported, but identical (by SHA-256) to another file discovered in this same batch
	// Coverage summarizes the whole catalog -- what it holds, what
	// Tracefall can parse, and what it will ignore. This is what makes a
	// 7,000-file image comprehensible at a glance.
	Coverage Coverage `json:"coverage"`
	// Upload-only archive-level facts the UI shows as upload/extraction
	// progress; zero for a local-path discovery.
	UploadSizeBytes int64 `json:"upload_size_bytes,omitempty"`
	ExtractedFiles  int   `json:"extracted_files,omitempty"`
	ExtractedBytes  int64 `json:"extracted_bytes,omitempty"`
}

// DiscoverEvidenceFromPath catalogs evidence directly from a local
// filesystem directory as a new collection in caseID -- kept for
// local/scripted use (e.g. the bundled synthetic dataset). For a
// browser-uploaded KAPE ZIP, see DiscoverEvidenceFromUpload. A case
// accepts any number of collections: each call adds another one rather
// than being rejected outright -- unless it's the *same* evidence (by
// deterministic directory fingerprint, see hashDirectory) as a
// collection already in this case, in which case it's rejected with
// *DuplicateEvidenceError before anything is cataloged.
func (s *Service) DiscoverEvidenceFromPath(caseID, path string) (DiscoverResult, error) {
	if _, err := s.GetCase(caseID); err != nil {
		return DiscoverResult{}, err
	}

	// path may point at a single AD1 file instead of a KAPE-style
	// directory -- sniffed (magic bytes, not the .ad1 extension alone;
	// see ad1.Sniff) only when it's a regular file, so this never changes
	// behavior for the existing directory-ingest case below.
	if info, statErr := os.Stat(path); statErr == nil && !info.IsDir() {
		if isAD1, isEncrypted, sniffErr := sniffStagedFile(path); sniffErr == nil && isAD1 {
			if isEncrypted {
				return DiscoverResult{}, fmt.Errorf("%w: %v", ErrInvalidAD1, ad1.ErrEncrypted)
			}
			return s.discoverAD1FromPath(caseID, path)
		}
	}

	// Check the path before fingerprinting it, so the common mistake --
	// a typo, or a path relative to the investigator's shell rather than
	// the server's working directory -- produces "evidence path does not
	// exist" rather than a walk error dressed up as an internal failure.
	if info, statErr := os.Stat(path); statErr != nil {
		return DiscoverResult{}, fmt.Errorf("%w: %s", ErrEvidencePathNotFound, path)
	} else if !info.IsDir() {
		// A regular file that reached here already failed the AD1 sniff
		// above, so it is a format Tracefall has no reader for.
		return DiscoverResult{}, fmt.Errorf("%w: %s is a file, not an evidence directory", ErrUnsupportedEvidence, path)
	}

	hash, err := hashDirectory(path)
	if err != nil {
		if classified := classifyPathError(err, path); classified != nil {
			return DiscoverResult{}, classified
		}
		return DiscoverResult{}, fmt.Errorf("fingerprinting evidence directory: %w", err)
	}
	if err := s.checkDuplicateEvidence(caseID, hash); err != nil {
		return DiscoverResult{}, err
	}

	// The collection is described here but not created here:
	// catalogEvidenceDirectory commits it together with its catalog, or
	// not at all (see commitDiscovery).
	collection := model.Collection{
		ID: uuid.NewString(), CaseID: caseID, CreatedAt: time.Now().UTC(),
		SourceType: model.SourceTypeLocalPath, OriginalFilename: path, EvidenceDirectory: path,
		ArchiveHash: hash, IngestionStatus: model.CollectionStatusPending,
	}
	res, err := s.catalogEvidenceDirectory(caseID, collection, path)
	if err != nil {
		return DiscoverResult{}, err
	}
	s.audit(caseID, model.AuditEvidenceDiscovered, model.TargetCollection, collection.ID,
		fmt.Sprintf("Evidence discovered from local path %q: %d file(s), %d supported", path, res.DiscoveredCount, res.SupportedCount))
	return res, nil
}

// DiscoverEvidenceFromUpload accepts an uploaded KAPE package as a ZIP
// archive (or, detected by content -- see ad1.Sniff -- an AD1 forensic
// image) read from zipData, and catalogs it into caseID as a new
// evidence collection:
//
//	stage + hash the upload (before anything else exists)
//	-> reject as a duplicate if this case already has a collection with the same hash
//	-> save the original archive (preserved, untouched, for provenance)
//	-> validate + safely extract it (internal/archive) [ZIP] / catalog it without extracting (internal/ad1) [AD1]
//	-> discover and classify every extracted file (internal/ingest.Discover) -- not parsed yet
//	-> store the catalog
//
// filename is the investigator's own name for the uploaded file (e.g.
// "DiskDrigger.ad1") -- display-only, used for an AD1 collection's
// OriginalFilename (see discoverAD1Upload); the ZIP path doesn't
// currently surface it anywhere, matching its pre-existing behavior.
//
// The upload is treated as untrusted input throughout: see
// internal/archive's and internal/ad1's doc comments for the specific
// protections applied. Any failure at any step removes everything
// written to disk for this collection specifically (never touching any
// other collection already in the case) and marks it failed, so the case
// itself is never left corrupted and the caller can simply try adding
// evidence again. Nothing is parsed here -- see ImportEvidence.
func (s *Service) DiscoverEvidenceFromUpload(caseID string, zipData io.Reader, filename string) (DiscoverResult, error) {
	if _, err := s.GetCase(caseID); err != nil {
		return DiscoverResult{}, err
	}

	// Hash before creating any collection or extracting -- staged outside
	// any collection's own directory, since we don't yet know whether
	// this upload will be rejected as a duplicate.
	stagingPath, uploadSize, archiveHash, err := s.stageUpload(caseID, zipData)
	if err != nil {
		return DiscoverResult{}, err
	}
	stagingClaimed := false
	defer func() {
		if !stagingClaimed {
			_ = os.Remove(stagingPath)
		}
	}()

	if err := s.checkDuplicateEvidence(caseID, archiveHash); err != nil {
		return DiscoverResult{}, err
	}

	// Format detection happens on the already-staged file (magic bytes
	// only -- see ad1.Sniff), not the original io.Reader, so it costs
	// nothing extra and never consumes zipData twice. An AD1 upload is
	// handed off entirely to discoverAD1Upload, which owns staging's
	// cleanup from here (see its own stagingClaimed handling) -- see
	// docs/ad1-ingestion.md for why AD1 needs a different commit step
	// (no upfront extraction) than the ZIP path below.
	if isAD1, isEncrypted, sniffErr := sniffStagedFile(stagingPath); sniffErr == nil && isAD1 {
		if isEncrypted {
			return DiscoverResult{}, fmt.Errorf("%w: %v", ErrInvalidAD1, ad1.ErrEncrypted)
		}
		return s.discoverAD1Upload(caseID, stagingPath, &stagingClaimed, uploadSize, archiveHash, filename)
	}

	collectionID := uuid.NewString()
	evidenceDir := s.files.EvidenceDir(caseID, collectionID)
	collection := model.Collection{
		ID: collectionID, CaseID: caseID, CreatedAt: time.Now().UTC(),
		SourceType: model.SourceTypeUpload, ArchiveHash: archiveHash, EvidenceDirectory: evidenceDir,
		IngestionStatus: model.CollectionStatusPending,
	}

	// The collection's directory has to exist before the archive can be
	// extracted into it, but the collection ROW does not: it is committed
	// only once the catalog is complete (see catalogEvidenceDirectory).
	// A failure anywhere below therefore removes the directory and leaves
	// the database exactly as it was -- no failed collection, no orphan
	// source files.
	if err := s.files.EnsureCollectionDir(caseID, collectionID); err != nil {
		return DiscoverResult{}, fmt.Errorf("preparing collection storage: %w", err)
	}

	succeeded := false
	defer func() {
		if !succeeded {
			_ = s.files.RemoveCollectionDir(caseID, collectionID)
		}
	}()

	uploadPath := s.files.UploadPath(caseID, collectionID)
	if err := os.Rename(stagingPath, uploadPath); err != nil {
		return DiscoverResult{}, fmt.Errorf("finalizing uploaded archive: %w", err)
	}
	stagingClaimed = true // ownership transferred to the collection dir; its own cleanup (above) covers it from here

	extractRes, err := archive.ExtractFile(uploadPath, evidenceDir, s.extractLimits)
	if err != nil {
		return DiscoverResult{}, err
	}

	res, err := s.catalogEvidenceDirectory(caseID, collection, evidenceDir)
	if err != nil {
		return DiscoverResult{}, err
	}
	res.UploadSizeBytes = uploadSize
	res.ExtractedFiles = extractRes.FilesExtracted
	res.ExtractedBytes = extractRes.TotalBytes

	_ = s.files.WriteMetadata(caseID, collectionID, res.Collection) // best-effort; DB remains authoritative

	succeeded = true
	s.audit(caseID, model.AuditEvidenceDiscovered, model.TargetCollection, collectionID,
		fmt.Sprintf("Evidence discovered from uploaded archive: %d file(s), %d supported", res.DiscoveredCount, res.SupportedCount))
	return res, nil
}

// catalogEvidenceDirectory runs internal/ingest.Discover against dir,
// classifies each file (unsupported / duplicate-within-this-batch /
// selectable), persists the catalog, and updates the collection's
// discovery counts. It does not parse anything or touch the case's
// status -- a collection with files merely discovered, not yet imported,
// has produced no events, so there is nothing yet that would make prior
// analysis stale. Shared by DiscoverEvidenceFromPath and
// DiscoverEvidenceFromUpload.
func (s *Service) catalogEvidenceDirectory(caseID string, collection model.Collection, dir string) (DiscoverResult, error) {
	collectionID := collection.ID
	discovered, err := ingest.Discover(dir, ingest.Registry())
	if err != nil {
		// A path that vanished (or was never readable) between the
		// duplicate check and here is the investigator's problem to fix,
		// not an internal failure -- classify it so the handler can say
		// so with a 4xx instead of "internal error".
		// Only the base name is echoed: for an upload, dir is a
		// server-internal extraction directory, and this message reaches
		// the browser. The wrapped error still carries the full path to
		// the server log.
		if classified := classifyPathError(err, filepath.Base(dir)); classified != nil {
			return DiscoverResult{}, classified
		}
		return DiscoverResult{}, fmt.Errorf("discovering evidence: %w", err)
	}
	if len(discovered) == 0 {
		return DiscoverResult{}, ErrNoEvidenceFound
	}

	now := time.Now().UTC()
	seenHashes := map[string]bool{}
	sourceFiles := make([]model.SourceFile, 0, len(discovered))
	var supported, unsupported, duplicate int
	for _, f := range discovered {
		sf := model.SourceFile{
			ID: uuid.NewString(), CaseID: caseID, CollectionID: collectionID,
			OriginalFilename: f.OriginalName, Path: f.Path, ArtifactType: f.ArtifactType, Parser: f.Parser,
			Supported: f.Supported, SizeBytes: f.SizeBytes, SHA256: f.SHA256, DiscoveredAt: now,
		}
		switch {
		case !f.Supported:
			sf.ImportStatus = model.SourceFileUnsupported
			unsupported++
		case f.SHA256 != "" && seenHashes[f.SHA256]:
			// Identical content already discovered earlier in this same
			// batch -- not blocked across collections (see
			// docs/data-model.md's "Evidence file model" section), only
			// within one, where it would mean the same file appeared
			// twice in one package.
			sf.ImportStatus = model.SourceFileDuplicate
			duplicate++
			supported++
		default:
			sf.ImportStatus = model.SourceFileDiscovered
			supported++
		}
		if f.Supported && f.SHA256 != "" {
			seenHashes[f.SHA256] = true
		}
		sourceFiles = append(sourceFiles, sf)
	}

	// Nothing has been written yet: every failure above returned before
	// touching the database, so an unreadable/empty/unusable evidence
	// source leaves no collection and no orphan source_file rows behind.
	// Only now, with a complete catalog in hand, is any of it committed.
	collection.IngestionStatus = model.CollectionStatusPending
	collection.FileCount = len(sourceFiles)
	collection.SupportedFileCount = supported
	collection.UnsupportedFileCount = unsupported
	full, err := s.commitDiscovery(collection, sourceFiles)
	if err != nil {
		return DiscoverResult{}, err
	}

	triaged := triageAll(sourceFiles)
	return DiscoverResult{
		Collection: full, SourceFiles: triaged, Coverage: computeCoverage(triaged),
		DiscoveredCount: len(sourceFiles), SupportedCount: supported, UnsupportedCount: unsupported, DuplicateCount: duplicate,
	}, nil
}

// commitDiscovery atomically creates a fully-cataloged collection and
// reloads it as the database now holds it. A (case_id, archive_hash)
// collision here -- two identical uploads racing past checkDuplicateEvidence
// -- becomes a *DuplicateEvidenceError naming the collection that won,
// exactly as it did when the collection was inserted up front, except
// that the loser no longer leaves a half-built collection behind.
func (s *Service) commitDiscovery(collection model.Collection, sourceFiles []model.SourceFile) (model.Collection, error) {
	err := s.store.CreateCollectionWithSourceFiles(collection, sourceFiles)
	if errors.Is(err, store.ErrDuplicateCollection) {
		if existing, found, ferr := s.store.FindCollectionByHash(collection.CaseID, collection.ArchiveHash); ferr == nil && found {
			return model.Collection{}, s.duplicateEvidenceError(collection.CaseID, existing)
		}
		return model.Collection{}, ErrDuplicateEvidence
	}
	if err != nil {
		return model.Collection{}, fmt.Errorf("saving discovered evidence: %w", err)
	}
	full, err := s.store.GetCollection(collection.ID)
	if err != nil {
		return model.Collection{}, fmt.Errorf("reloading collection: %w", err)
	}
	return full, nil
}

// ---------- Importing selected evidence ----------

// ImportSkip explains why one requested source file ID was not imported.
type ImportSkip struct {
	SourceFileID string `json:"source_file_id"`
	Reason       string `json:"reason"`
}

// ImportResult is returned from selecting specific discovered files and
// importing them -- the point at which they actually become evidence.
type ImportResult struct {
	Collection model.Collection   `json:"collection"`
	Imported   []model.SourceFile `json:"imported"`
	// EventCount is how many records the imported files parsed to,
	// including ones that turned out to already be known (see
	// DuplicateEventCount).
	EventCount          int          `json:"event_count"`
	NewEventCount       int          `json:"new_event_count"`
	DuplicateEventCount int          `json:"duplicate_event_count"`
	Skipped             []ImportSkip `json:"skipped,omitempty"`
	// Errors is the pre-existing one-line-per-failure list, retained so
	// existing consumers keep working. ParseFailures carries the same
	// failures structured, which is what the dashboard renders.
	Errors []string `json:"errors,omitempty"`
	// ParseFailures describes each file that was SELECTED and SUPPORTED
	// but could not be parsed. This is deliberately distinct from
	// Skipped (files that were never eligible: unsupported, duplicate,
	// already imported) -- conflating "Tracefall has no parser for this"
	// with "this file is broken" would misrepresent the evidence.
	ParseFailures []ParseFailure `json:"parse_failures,omitempty"`
}

// Parse failure categories. Coarse on purpose: an investigator needs to
// know whether to re-collect the evidence, ignore it, or report a bug --
// not which function returned the error.
const (
	ParseFailureCorrupt     = "corrupt_or_truncated" // the evidence itself is damaged
	ParseFailureUnreadable  = "unreadable"           // could not be read from storage
	ParseFailureLimit       = "limit_exceeded"       // hit a safety ceiling
	ParseFailureUnsupported = "unsupported_format"   // recognized container, unusable contents
	ParseFailureInternal    = "internal_error"       // anything else
)

// Parse stages, matching where in the import a failure actually happened.
const (
	ParseStageExtract = "extract" // materializing an AD1 entry before parsing
	ParseStageParse   = "parse"   // the artifact parser itself
)

// ParseFailure describes one file that could not be parsed, in terms
// safe to show a user: no stack traces, no absolute server paths, no
// internal identifiers beyond the ones the client already holds.
type ParseFailure struct {
	SourceFileID string `json:"source_file_id"`
	// Path is relative to the evidence root, exactly as the catalog
	// shows it -- never an absolute path on the server.
	Path         string `json:"path"`
	Filename     string `json:"filename"`
	ArtifactType string `json:"artifact_type,omitempty"`
	Parser       string `json:"parser,omitempty"`
	Stage        string `json:"stage"`
	Category     string `json:"category"`
	// Message is a sanitized, human-readable explanation.
	Message string `json:"message"`
	// PartialEvents records whether any events from this file were
	// persisted before it failed. Parsing completes fully or not at all
	// before anything is written (see the three-phase import), so this is
	// always false today -- it is reported explicitly rather than left to
	// be assumed, because "did this file half-land in my evidence?" is a
	// question an investigator must never have to guess at.
	PartialEvents bool `json:"partial_events"`
}

// ImportEvidence parses exactly the requested source files (each must
// already be cataloged in this collection with status
// SourceFileDiscovered -- see DiscoverEvidenceFromPath/Upload) and turns
// them into evidence: events, deduplicated against the rest of the case
// exactly the way a whole-directory ingest always has (see deduplicate),
// with full provenance preserved. Files not selected are left exactly as
// they were, still available to import later. An ID that doesn't resolve
// to an importable file in this collection (not found, already imported,
// unsupported, a duplicate, deleted) is reported in Skipped rather than
// failing the whole request -- a partial selection succeeding partially
// is more useful than an all-or-nothing rejection.
func (s *Service) ImportEvidence(caseID, collectionID string, sourceFileIDs []string) (ImportResult, error) {
	// nil sink: identical behavior to before progress reporting existed.
	// There is one implementation of importing, called two ways -- see
	// importjob.go for the background variant.
	return s.importEvidence(caseID, collectionID, sourceFileIDs, nil)
}

func (s *Service) importEvidence(caseID, collectionID string, sourceFileIDs []string, prog *progressSink) (ImportResult, error) {
	prog.phase(PhasePreparing)
	if _, err := s.GetCase(caseID); err != nil {
		return ImportResult{}, err
	}
	collection, err := s.store.GetCollection(collectionID)
	if err != nil || collection.CaseID != caseID {
		return ImportResult{}, ErrCollectionNotFound
	}

	registry := ingest.Registry()
	// make(...,0,...), never `var imported []model.SourceFile`: no
	// `omitempty` on ImportResult.Imported, and internal/web/static/app.js's
	// renderImportResults reads res.imported.length unconditionally -- if
	// every requested file were skipped or failed (0 actually imported),
	// a nil slice here would serialize as JSON `null` and crash that
	// render, the same bug class as the two fixed just above in
	// Investigation(). skipped/errs don't need this: their JSON fields
	// do have `omitempty`, and the frontend already checks them for
	// truthiness before reading .length.
	imported := make([]model.SourceFile, 0, len(sourceFileIDs))
	var skipped []ImportSkip
	var errs []string
	var failures []ParseFailure
	var totalNew, totalDup int

	// Phase 1: parse every selected file, persisting nothing yet. Host
	// resolution (phase 2) needs the whole batch in hand before any event
	// is written -- see enrichBatchHosts -- because Host feeds
	// ComputeDedupHash, so an event saved with an unresolved host would
	// be saved under the wrong dedup identity. Per-file skips and parse
	// failures are recorded exactly as before and don't abort the batch.
	pending := make([]pendingImport, 0, len(sourceFileIDs))
	prog.phase(PhaseParsing)
	prog.setTotal(len(sourceFileIDs))
	for _, id := range sourceFileIDs {
		sf, err := s.store.GetSourceFile(id)
		if err != nil || sf.CaseID != caseID || sf.CollectionID != collectionID {
			skipped = append(skipped, ImportSkip{SourceFileID: id, Reason: "not found in this collection"})
			prog.fileParsed(0, true)
			continue
		}
		if sf.DeletedAt != nil {
			skipped = append(skipped, ImportSkip{SourceFileID: id, Reason: "deleted"})
			prog.fileParsed(0, true)
			continue
		}
		if sf.ImportStatus != model.SourceFileDiscovered {
			skipped = append(skipped, ImportSkip{SourceFileID: id, Reason: "already " + sf.ImportStatus})
			prog.fileParsed(0, true)
			continue
		}

		prog.startFile(sf.Path)

		p := findParserFor(registry, sf.Parser)
		if p == nil {
			_ = s.store.MarkSourceFileFailed(id)
			skipped = append(skipped, ImportSkip{SourceFileID: id, Reason: "no parser available"})
			prog.fileParsed(0, true)
			continue
		}

		if collection.SourceType == model.SourceTypeAD1 {
			// AD1 entries aren't extracted during discovery (see
			// catalogAD1) -- materialize exactly this one selected
			// entry's bytes under EvidenceDirectory now, immediately
			// before ParseFile reads them below exactly as it does for
			// every other collection type. This also computes and
			// records Tracefall's own SHA-256 for the file, which isn't
			// known until this point (see extractAD1Entry's doc comment).
			if err := s.extractAD1Entry(caseID, collectionID, sf); err != nil {
				_ = s.store.MarkSourceFileFailed(id)
				errs = append(errs, fmt.Sprintf("%s: %v", sf.Path, err))
				failures = append(failures, parseFailure(sf, ParseStageExtract, err))
				prog.fileParsed(0, true)
				continue
			}
		}

		parsed, err := ingest.ParseFile(caseID, collectionID, id, collection.EvidenceDirectory, sf.Path, p)
		if err != nil {
			_ = s.store.MarkSourceFileFailed(id)
			errs = append(errs, fmt.Sprintf("%s: %v", sf.Path, err))
			failures = append(failures, parseFailure(sf, ParseStageParse, err))
			prog.fileParsed(0, true)
			continue
		}
		pending = append(pending, pendingImport{sourceFile: sf, events: parsed.Events, raw: parsed.Raw})
		prog.fileParsed(len(parsed.Events), false)
	}

	// Phase 2: resolve every blank host against the complete batch plus
	// the case's existing evidence, once, before anything is written.
	prog.phase(PhaseEnriching)
	if err := s.enrichBatchHosts(caseID, collectionID, pending); err != nil {
		return ImportResult{}, fmt.Errorf("enriching event hosts: %w", err)
	}

	// Phase 3: persist. Still strictly one file at a time, in the order
	// requested, so deduplicate() keeps seeing each file's events against
	// everything already saved -- including earlier files from this same
	// batch -- exactly as it always has.
	prog.phase(PhasePersisting)
	for _, pf := range pending {
		sf := pf.sourceFile
		id := sf.ID
		prog.startFile(sf.Path)

		if err := s.store.SaveRawEvidence(pf.raw); err != nil {
			return ImportResult{}, fmt.Errorf("saving raw evidence: %w", err)
		}
		newEvents, observations, err := s.deduplicate(caseID, collectionID, pf.events, pf.raw)
		if err != nil {
			return ImportResult{}, fmt.Errorf("deduplicating events: %w", err)
		}
		if err := s.store.SaveEvents(newEvents); err != nil {
			return ImportResult{}, fmt.Errorf("saving events: %w", err)
		}
		if err := s.store.SaveEventObservations(observations); err != nil {
			return ImportResult{}, fmt.Errorf("saving event observations: %w", err)
		}

		applied, err := s.store.MarkSourceFileImported(id, len(pf.events), time.Now().UTC())
		if errors.Is(err, store.ErrDuplicateSourceFile) {
			// This file's content is byte-identical to another file
			// already imported into this same collection -- the events
			// saved above are harmlessly redundant (deduplicate already
			// collapsed them against whatever the earlier file
			// contributed), so this is a normal per-file outcome, not a
			// failure: skip just this one and continue with the rest of
			// the batch. ZIP/local-path collections normally never reach
			// here at all (their discovery-time SHA-256 already flags
			// same-content files as SourceFileDuplicate before either is
			// selectable -- see catalogEvidenceDirectory); an AD1
			// collection can, since its own discovery-time dedup only
			// catches this when AD1 itself recorded a hash (see
			// catalogAD1's doc comment) -- so this path exists
			// specifically to keep that weaker guarantee from turning
			// into a request-aborting error instead of a per-file skip.
			skipped = append(skipped, ImportSkip{SourceFileID: id, Reason: "duplicate content already imported in this collection"})
			prog.filePersisted(0, len(pf.events))
			continue
		}
		if err != nil {
			return ImportResult{}, fmt.Errorf("marking file imported: %w", err)
		}
		if !applied {
			// Lost a race with a concurrent import of the same file ID --
			// the events/observations above are harmlessly redundant
			// (deduplicate already collapses them against whatever the
			// winner just saved) and this file is already evidence.
			skipped = append(skipped, ImportSkip{SourceFileID: id, Reason: "already imported"})
			prog.filePersisted(0, len(pf.events))
			continue
		}

		refreshed, err := s.store.GetSourceFile(id)
		if err != nil {
			return ImportResult{}, fmt.Errorf("reloading imported file: %w", err)
		}
		imported = append(imported, refreshed)
		totalNew += len(newEvents)
		totalDup += len(pf.events) - len(newEvents)
		prog.filePersisted(len(newEvents), len(pf.events)-len(newEvents))
	}

	prog.phase(PhaseFinalizing)
	if len(imported) > 0 {
		if err := s.recomputeCollectionCounts(collectionID); err != nil {
			return ImportResult{}, fmt.Errorf("recomputing collection counts: %w", err)
		}
		// A case with at least one imported file always moves to
		// "ingested" -- including when it was already "analyzed":
		// importing more evidence makes the prior analysis stale, and
		// this is the signal the dashboard uses to prompt re-running it.
		if err := s.store.UpdateCaseStatus(caseID, model.CaseStatusIngested); err != nil {
			return ImportResult{}, fmt.Errorf("updating case status: %w", err)
		}
	}
	full, err := s.store.GetCollection(collectionID)
	if err != nil {
		return ImportResult{}, fmt.Errorf("reloading collection: %w", err)
	}

	if len(imported) > 0 {
		s.audit(caseID, model.AuditEvidenceImported, model.TargetCollection, collectionID,
			fmt.Sprintf("%d file(s) imported, %d new event(s), %d already-known", len(imported), totalNew, totalDup))
	}

	return ImportResult{
		Collection: full, Imported: imported,
		EventCount: totalNew + totalDup, NewEventCount: totalNew, DuplicateEventCount: totalDup,
		Skipped: skipped, Errors: errs, ParseFailures: failures,
	}, nil
}

// findParserFor returns the registry entry whose Name() matches
// parserName -- ImportEvidence trusts the parser a file was classified
// under at discovery time (stored on the SourceFile row) rather than
// re-running detection against every file's path again.
func findParserFor(registry []parsers.ArtifactParser, parserName string) parsers.ArtifactParser {
	for _, p := range registry {
		if p.Name() == parserName {
			return p
		}
	}
	return nil
}

// recomputeCollectionCounts recalculates a collection's discovery/import
// rollup from its current active (non-deleted) source files -- called
// after import and after evidence deletion, so these counts are always
// derived fresh from what's actually there rather than hand-adjusted
// incrementally (which would drift if a step were ever missed).
func (s *Service) recomputeCollectionCounts(collectionID string) error {
	collection, err := s.store.GetCollection(collectionID)
	if err != nil {
		return err
	}
	files, err := s.store.ListSourceFilesByCollection(collectionID)
	if err != nil {
		return err
	}
	var supported, unsupported, imported, events int
	for _, f := range files {
		if f.Supported {
			supported++
		} else {
			unsupported++
		}
		if f.ImportStatus == model.SourceFileImported {
			imported++
			events += f.EventCount
		}
	}
	collection.FileCount = len(files)
	collection.SupportedFileCount = supported
	collection.UnsupportedFileCount = unsupported
	collection.ImportedFileCount = imported
	collection.ParsedEventCount = events
	// A collection with at least one imported file has produced actual
	// evidence -- "ingested" (see model.CollectionStatusIngested), same
	// meaning it always had, just now reached via import instead of a
	// single discover-and-parse step. Never advances a "failed"
	// collection, and deleting evidence back down to zero imported files
	// deliberately leaves the status as-is rather than reverting it --
	// the case-level status (see DeleteSourceFiles) is what signals
	// staleness/emptiness system-wide.
	if imported > 0 && collection.IngestionStatus != model.CollectionStatusFailed {
		collection.IngestionStatus = model.CollectionStatusIngested
	}
	return s.store.UpdateCollection(collection)
}

// deduplicate matches each newly-parsed event against every event
// already known in the case -- across every prior collection, not just
// this one -- by internal/model.Event.ComputeDedupHash(). A match means
// the same real-world event was independently observed again (e.g. the
// same Windows Event Log record present in two KAPE triages of the same
// host taken hours apart): no new Event row is created for it, but an
// EventObservation recording *this* collection's copy of it always is,
// so provenance is never lost -- see internal/model.EventObservation's
// doc comment. Matches are checked first against events parsed earlier
// in this same batch (in case one file's records overlap another's
// within a single collection), then against the store.
func (s *Service) deduplicate(caseID, collectionID string, events []model.Event, raw []model.RawEvidence) ([]model.Event, []model.EventObservation, error) {
	newEvents := make([]model.Event, 0, len(events))
	observations := make([]model.EventObservation, 0, len(events))
	canonicalID := make(map[string]string, len(events)) // dedup hash -> event ID, within this batch

	for i, ev := range events {
		hash := ev.ComputeDedupHash()
		ev.DedupHash = hash

		eventID, ok := canonicalID[hash]
		if !ok {
			existing, found, err := s.store.FindEventByDedupHash(caseID, hash)
			if err != nil {
				return nil, nil, err
			}
			if found {
				eventID = existing.ID
			} else {
				eventID = ev.ID
				newEvents = append(newEvents, ev)
			}
			canonicalID[hash] = eventID
		}

		var rawEvidenceID string
		if i < len(raw) {
			rawEvidenceID = raw[i].ID
		}
		observations = append(observations, model.EventObservation{
			ID: uuid.NewString(), EventID: eventID, CaseID: caseID, CollectionID: collectionID,
			SourceFileID: ev.SourceFileID, RawEvidenceID: rawEvidenceID, SourceReference: ev.SourceReference,
		})
	}
	return newEvents, observations, nil
}

// Host enrichment lives in hostenrich.go (Service.enrichBatchHosts),
// called once per import batch from ImportEvidence's phase 2 -- see that
// file for why it can't be done per file.

// ---------- Duplicate evidence detection ----------
//
// A case must not accept the same evidence package twice as two separate
// collections -- see docs/data-model.md's "Duplicate evidence" section.
// The check is exact-hash equality only (no content-level/semantic
// fingerprinting): two independently-built ZIPs of identical files can
// still hash differently because ZIP metadata differs, and that's an
// accepted limitation of this phase, not a bug.

// checkDuplicateEvidence looks for an existing collection in caseID with
// the given hash and, if found, returns a *DuplicateEvidenceError
// identifying it. This is the fast pre-check: called before any
// collection row is created, before any archive is extracted, and before
// any local-path directory is walked by internal/ingest, so a duplicate
// is rejected without doing any of that work. It is not by itself
// sufficient against a concurrent duplicate request -- see
// commitDiscovery for the race-safe backstop.
// classifyPathError turns a filesystem failure into ErrEvidencePathNotFound
// when the cause is a missing or unreadable path, or returns nil when the
// error is something else and the caller should treat it as internal.
//
// It deliberately uses errors.Is against the fs sentinels rather than
// type-asserting *fs.PathError: the error arrives wrapped -- os.Open's
// *fs.PathError, wrapped again by filepath.WalkDir, wrapped again by
// ingest.Discover -- and errors.Is unwraps all of it to reach the
// underlying syscall errno. Matching on the concrete type, or on a
// string, would miss exactly the cases this exists to catch.
//
// "does not exist" and "is not readable" share one message on purpose:
// an investigator can act on both the same way (check the path, check
// permissions), and distinguishing them would leak whether a path the
// server can see exists -- see Phase 4's note on not exposing server
// filesystem details.
func classifyPathError(err error, subject string) error {
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) {
		return fmt.Errorf("%w: %s", ErrEvidencePathNotFound, subject)
	}
	return nil
}

func (s *Service) checkDuplicateEvidence(caseID, hash string) error {
	if hash == "" {
		return nil
	}
	existing, found, err := s.store.FindCollectionByHash(caseID, hash)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	return s.duplicateEvidenceError(caseID, existing)
}

// duplicateEvidenceError builds a *DuplicateEvidenceError labeling
// existing by its position in the case's collection list ("Collection
// #1", ...) -- the same numbering the dashboard uses -- so the message
// identifies the existing collection the way an investigator already
// sees it, not by an opaque ID. Falls back to a generic label rather
// than failing outright if the list can't be loaded, since this is only
// ever building an error message, not doing anything load-bearing.
func (s *Service) duplicateEvidenceError(caseID string, existing model.Collection) error {
	label := "an earlier collection in this case"
	if all, err := s.store.ListCollections(caseID); err == nil {
		for i, c := range all {
			if c.ID == existing.ID {
				label = fmt.Sprintf("Collection #%d", i+1)
				break
			}
		}
	}
	return &DuplicateEvidenceError{CollectionID: existing.ID, CollectionLabel: label}
}

// stageUpload copies zipData to a temporary file inside the case's own
// directory (so the later os.Rename into the collection's final location
// is same-filesystem and therefore atomic) and hashes it in the same
// pass, so the archive is fully preserved on disk -- "preserve original
// evidence" -- and hashed in one write, without needing a second read
// pass the way computing the hash after the fact would. The caller
// removes the staged file if it turns out to be a duplicate or the
// upload is otherwise abandoned; on success ownership transfers to the
// collection directory via os.Rename.
func (s *Service) stageUpload(caseID string, zipData io.Reader) (path string, size int64, hash string, err error) {
	caseDir := s.files.CaseDir(caseID)
	if err := os.MkdirAll(caseDir, 0o755); err != nil {
		return "", 0, "", fmt.Errorf("preparing case storage: %w", err)
	}
	f, err := os.CreateTemp(caseDir, "upload-*.zip.tmp")
	if err != nil {
		return "", 0, "", fmt.Errorf("staging uploaded archive: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), zipData)
	if err != nil {
		_ = os.Remove(f.Name())
		return "", 0, "", fmt.Errorf("saving uploaded archive: %w", err)
	}
	return f.Name(), n, hex.EncodeToString(h.Sum(nil)), nil
}

// hashDirectory computes a deterministic SHA-256 fingerprint of a local
// evidence directory for duplicate detection on the local-path ingestion
// path (AddEvidenceFromPath), which -- unlike an uploaded ZIP -- has no
// single archive of bytes to hash directly. The fingerprint is built
// from each regular file's path relative to root plus its content, not
// directory metadata (mtimes, permissions): two copies of the same
// evidence produce the same fingerprint regardless of how or when they
// were copied to disk. filepath.WalkDir visits entries in lexical order,
// which is what makes this deterministic across runs without an explicit
// sort step.
func hashDirectory(root string) (string, error) {
	h := sha256.New()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		// A NUL byte can't appear in a valid path component, so this
		// can't be confused with a path or content that happens to
		// contain the same bytes as another entry's boundary.
		io.WriteString(h, filepath.ToSlash(rel))
		h.Write([]byte{0})

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		_, err = io.Copy(h, f)
		f.Close()
		if err != nil {
			return err
		}
		h.Write([]byte{0})
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("hashing %s: %w", root, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ---------- Evidence deletion ----------
//
// Deleting a source file must never leave stale findings pointing at
// evidence that no longer exists, and must never lose an event that's
// still supported by another observation -- see
// docs/data-model.md's "Evidence deletion" section. Both are handled by
// composing existing, already-tested mechanisms rather than new
// detection/correlation logic: deleteSourceFileEvidence removes exactly
// the observations/events this deletion actually invalidates (keeping
// anything still independently observed elsewhere), and marking the case
// "ingested" (never "analyzed") after a deletion means stale
// findings/correlations are never shown as current -- the existing
// AnalyzeCase, unchanged, recomputes them from scratch, the same way it
// already does after new evidence is added.

// DeletedEvidenceResult summarizes what deleting one or more source
// files actually did, so the API/UI response is a clear, honest account
// of the change rather than a bare "ok".
type DeletedEvidenceResult struct {
	DeletedSourceFiles []string     `json:"deleted_source_file_ids"`
	EventsRemoved      int          `json:"events_removed"`  // events with no remaining observation -- deleted entirely
	EventsRetained     int          `json:"events_retained"` // events that lost this observation but survive via another
	Skipped            []ImportSkip `json:"skipped,omitempty"`
}

// DeleteSourceFile removes exactly one evidence file from a case. See
// DeleteSourceFiles.
func (s *Service) DeleteSourceFile(caseID, sourceFileID string) (DeletedEvidenceResult, error) {
	return s.DeleteSourceFiles(caseID, []string{sourceFileID})
}

// DeleteSourceFiles removes one or more evidence files from a case:
// their EventObservations are removed, any Event left with no
// observations at all (nothing else in the case ever observed it) is
// deleted entirely, any Event that survives via another observation has
// its own denormalized provenance re-pointed if it was pointing at the
// file being removed, their raw evidence records are removed, the files
// themselves are soft-deleted (and their on-disk copy removed, for
// uploaded evidence Tracefall owns -- never for a local-path collection,
// which points at the investigator's own files), and affected
// collections' counts are recalculated from what's actually left.
//
// This never touches findings/correlations/ATT&CK mappings/the timeline
// directly -- it only changes what events exist. The case is marked
// "ingested" (or "created", if that removed the case's last event)
// afterward so the dashboard prompts a re-run rather than continuing to
// show analysis based on evidence that's now gone; internal/detect and
// internal/correlate, unchanged, recompute everything correctly the next
// time AnalyzeCase runs, because they've always operated on the case's
// complete current event list, never a delta.
func (s *Service) DeleteSourceFiles(caseID string, sourceFileIDs []string) (DeletedEvidenceResult, error) {
	if _, err := s.GetCase(caseID); err != nil {
		return DeletedEvidenceResult{}, err
	}

	res := DeletedEvidenceResult{}
	touchedCollections := map[string]bool{}
	for _, id := range sourceFileIDs {
		sf, err := s.store.GetSourceFile(id)
		if err != nil || sf.CaseID != caseID {
			res.Skipped = append(res.Skipped, ImportSkip{SourceFileID: id, Reason: "not found in this case"})
			continue
		}
		if sf.DeletedAt != nil {
			res.Skipped = append(res.Skipped, ImportSkip{SourceFileID: id, Reason: "already deleted"})
			continue
		}

		removed, retained, err := s.deleteSourceFileEvidence(sf)
		if err != nil {
			return DeletedEvidenceResult{}, fmt.Errorf("deleting source file %s: %w", id, err)
		}
		res.EventsRemoved += removed
		res.EventsRetained += retained
		res.DeletedSourceFiles = append(res.DeletedSourceFiles, id)
		touchedCollections[sf.CollectionID] = true

		if collection, cerr := s.store.GetCollection(sf.CollectionID); cerr == nil &&
			(collection.SourceType == model.SourceTypeUpload || collection.SourceType == model.SourceTypeAD1) {
			// Only for evidence Tracefall itself extracted and owns. A
			// local-path (non-AD1) collection's EvidenceDirectory is
			// wherever the investigator's own evidence already lives on
			// disk -- Tracefall must never delete files out from under
			// them. An AD1 collection's EvidenceDirectory, regardless of
			// whether the AD1 itself arrived by upload or local path, is
			// always Tracefall's own lazily-populated extraction
			// destination (see catalogAD1/extractAD1Entry) -- the
			// original AD1 container is never touched by this, only the
			// one extracted copy of this specific deleted file.
			_ = s.files.RemoveEvidenceFile(caseID, sf.CollectionID, sf.Path)
		}
	}

	for collectionID := range touchedCollections {
		if err := s.recomputeCollectionCounts(collectionID); err != nil {
			return DeletedEvidenceResult{}, fmt.Errorf("recomputing collection counts: %w", err)
		}
	}

	if len(res.DeletedSourceFiles) > 0 {
		remaining, err := s.store.ListEvents(caseID)
		if err != nil {
			return DeletedEvidenceResult{}, fmt.Errorf("checking remaining events: %w", err)
		}
		status := model.CaseStatusIngested
		if len(remaining) == 0 {
			status = model.CaseStatusCreated
		}
		if err := s.store.UpdateCaseStatus(caseID, status); err != nil {
			return DeletedEvidenceResult{}, fmt.Errorf("updating case status: %w", err)
		}
	}
	if len(res.DeletedSourceFiles) > 0 {
		s.audit(caseID, model.AuditEvidenceDeleted, model.TargetSourceFile, "",
			fmt.Sprintf("%d source file(s) deleted (%d events removed, %d retained via another observation)",
				len(res.DeletedSourceFiles), res.EventsRemoved, res.EventsRetained))
	}
	return res, nil
}

// deleteSourceFileEvidence removes sf's contribution to the case's
// events: each of its EventObservations is deleted; if that was an
// event's last observation, the event itself is deleted (nothing
// supports it anymore -- see docs/data-model.md's "Event dedup +
// evidence deletion" section); otherwise the event survives, and if its
// own denormalized provenance (Event.SourceFileID etc. -- see
// model.Event's doc comment) pointed at this file specifically, it's
// re-pointed at one of the observations that still exists so nothing
// dangles.
func (s *Service) deleteSourceFileEvidence(sf model.SourceFile) (removedEvents, retainedEvents int, err error) {
	observations, err := s.store.ListEventObservationsBySourceFile(sf.ID)
	if err != nil {
		return 0, 0, err
	}

	for _, obs := range observations {
		if err := s.store.DeleteEventObservation(obs.ID); err != nil {
			return 0, 0, err
		}
		remaining, err := s.store.ListEventObservations(obs.EventID)
		if err != nil {
			return 0, 0, err
		}
		if len(remaining) == 0 {
			if err := s.store.DeleteEvent(obs.EventID); err != nil {
				return 0, 0, err
			}
			removedEvents++
			continue
		}
		retainedEvents++

		ev, err := s.store.GetEvent(obs.EventID)
		if err != nil {
			return 0, 0, err
		}
		if ev.SourceFileID != sf.ID {
			continue // this event's own provenance already points elsewhere
		}
		next := remaining[0]
		artifactType, parserName := ev.ArtifactType, ev.Parser
		if nextFile, ferr := s.store.GetSourceFile(next.SourceFileID); ferr == nil {
			artifactType, parserName = nextFile.ArtifactType, nextFile.Parser
		}
		if err := s.store.RepointEventProvenance(ev.ID, next.CollectionID, next.SourceFileID, next.RawEvidenceID, next.SourceReference, artifactType, parserName); err != nil {
			return 0, 0, err
		}
	}

	if err := s.store.DeleteRawEvidenceBySourceFile(sf.ID); err != nil {
		return 0, 0, err
	}
	if err := s.store.SoftDeleteSourceFile(sf.ID, time.Now().UTC()); err != nil {
		return 0, 0, err
	}
	return removedEvents, retainedEvents, nil
}

// ---------- Case deletion ----------

// DeleteCase permanently removes a case and every piece of data
// associated with it -- evidence, events, observations, findings,
// correlations, ATT&CK mappings (implicit in findings), derived
// analysis, and the case's on-disk evidence directory -- see
// store.DeleteCase for the exact, ordered, transactional set of DB
// deletes and internal/casefiles.Store.RemoveCaseDir for the filesystem
// cleanup. Irreversible; the API/UI layer is responsible for requiring
// explicit confirmation before calling this.
func (s *Service) DeleteCase(caseID string) error {
	if _, err := s.GetCase(caseID); err != nil {
		return err
	}
	if err := s.store.DeleteCase(caseID); err != nil {
		return fmt.Errorf("deleting case: %w", err)
	}
	if err := s.files.RemoveCaseDir(caseID); err != nil {
		return fmt.Errorf("removing case files: %w", err)
	}
	return nil
}

// BulkDeleteCasesResult reports exactly which of the requested cases
// were deleted and which failed (and why), rather than an all-or-nothing
// result -- each case is deleted independently and transactionally (see
// store.DeleteCase), so one failing (e.g. an already-deleted or unknown
// ID) never blocks or reverts the others.
type BulkDeleteCasesResult struct {
	Deleted []string          `json:"deleted_case_ids"`
	Failed  map[string]string `json:"failed,omitempty"` // case ID -> error message
}

// DeleteCases deletes multiple cases, continuing past any individual
// failure so the caller gets a complete, accurate picture of what
// happened across the whole batch.
func (s *Service) DeleteCases(caseIDs []string) BulkDeleteCasesResult {
	res := BulkDeleteCasesResult{Failed: map[string]string{}}
	for _, id := range caseIDs {
		if err := s.DeleteCase(id); err != nil {
			res.Failed[id] = err.Error()
			continue
		}
		res.Deleted = append(res.Deleted, id)
	}
	return res
}

// ---------- Analyze ----------

// AnalyzeResultSummary is returned from POST /cases/{id}/analyze.
type AnalyzeResultSummary struct {
	Findings     []model.Finding     `json:"findings"`
	Correlations []model.Correlation `json:"correlations"`
}

// AnalyzeCase runs the deterministic detection and correlation engines
// over a case's stored events -- every event from every collection, so a
// relationship between evidence in collection 1 and collection 2 is
// found exactly when the deterministic rules would find it within a
// single collection (internal/detect and internal/correlate don't know
// or care that "collection" is a concept; they always operated on the
// case's full event list, even before collections existed). It is
// idempotent: prior findings and correlations are cleared first, so
// running it twice on unchanged evidence produces the same result rather
// than accumulating duplicates, and running it again after a new
// collection is added recomputes findings/correlations across the
// complete, updated evidence set rather than appending to stale ones.
func (s *Service) AnalyzeCase(caseID string) (AnalyzeResultSummary, error) {
	c, err := s.GetCase(caseID)
	if err != nil {
		return AnalyzeResultSummary{}, err
	}
	if c.Status == model.CaseStatusCreated {
		return AnalyzeResultSummary{}, ErrNotIngested
	}

	s.audit(caseID, model.AuditAnalysisStarted, model.TargetCase, caseID, "Analysis started")

	events, err := s.store.ListEvents(caseID)
	if err != nil {
		s.audit(caseID, model.AuditAnalysisFailed, model.TargetCase, caseID, "Analysis failed: "+err.Error())
		return AnalyzeResultSummary{}, fmt.Errorf("loading events: %w", err)
	}

	findings := detect.Run(caseID, events)
	correlations := correlate.Run(caseID, events)

	// ReplaceAnalysis is one atomic transaction (clear + save + mark
	// analyzed) -- see its doc comment in internal/store/store.go. If it
	// fails for any reason, the case's PREVIOUS findings/correlations/
	// status are left completely untouched (the transaction rolls back),
	// satisfying Phase 6's "if analysis fails, preserve the previous
	// valid results" requirement without needing a separate persisted
	// "analysis failed" state: the case's Status/AnalyzedAt simply still
	// reflect the last successful analysis, and this error return is
	// exactly what tells the caller the CURRENT attempt didn't succeed.
	if err := s.store.ReplaceAnalysis(caseID, findings, correlations); err != nil {
		s.audit(caseID, model.AuditAnalysisFailed, model.TargetCase, caseID, "Analysis failed: "+err.Error())
		return AnalyzeResultSummary{}, fmt.Errorf("saving analysis results: %w", err)
	}

	s.audit(caseID, model.AuditAnalysisCompleted, model.TargetCase, caseID,
		fmt.Sprintf("Analysis completed: %d finding(s), %d correlation(s)", len(findings), len(correlations)))
	return AnalyzeResultSummary{Findings: findings, Correlations: correlations}, nil
}

// ---------- Read views ----------

// Timeline returns a case's unified timeline across every collection,
// chronologically. If collectionID is non-empty, it's filtered to just
// that collection's events (by their first observation -- see
// store.ListEventsByCollection).
func (s *Service) Timeline(caseID, collectionID string) ([]model.Event, error) {
	if collectionID != "" {
		return s.store.ListEventsByCollection(collectionID)
	}
	return s.store.ListEvents(caseID)
}

func (s *Service) Findings(caseID string) ([]model.Finding, error) {
	return s.store.ListFindings(caseID)
}

// FindingDetail is a finding with its supporting events resolved inline,
// so the UI's "click a finding, see its evidence" flow is one request.
// Each event's CollectionID indicates which collection it was first
// observed in, letting the UI label cross-collection supporting evidence
// even though findings themselves are case-level, not collection-scoped.
type FindingDetail struct {
	model.Finding
	SupportingEventDetails []model.Event     `json:"supporting_event_details"`
	TechniqueDetails       []attck.Technique `json:"technique_details"`
	// Explanation says WHY this finding carries the severity and
	// confidence it does, from the producing rule's declared reasoning
	// plus facts counted from the supporting events above. It never
	// changes those levels -- see explain.go.
	Explanation SeverityExplanation `json:"severity_explanation"`
}

func (s *Service) Finding(caseID, findingID string) (FindingDetail, error) {
	f, err := s.store.GetFinding(findingID)
	if err != nil || f.CaseID != caseID {
		return FindingDetail{}, fmt.Errorf("finding not found")
	}
	events, err := s.store.GetEvents(f.SupportingEvents)
	if err != nil {
		return FindingDetail{}, err
	}
	return FindingDetail{
		Finding:                f,
		SupportingEventDetails: events,
		TechniqueDetails:       attck.Resolve(f.Techniques),
		Explanation:            explainFinding(f, events),
	}, nil
}

func (s *Service) Correlations(caseID string) ([]model.Correlation, error) {
	return s.store.ListCorrelations(caseID)
}

// AttackTechnique pairs one ATT&CK technique with the findings in this
// case that map to it, so /cases/{id}/attack shows exactly which
// techniques this case has evidence for, not the full static registry.
type AttackTechnique struct {
	attck.Technique
	Findings []model.Finding `json:"findings"`
}

func (s *Service) AttackSummary(caseID string) ([]AttackTechnique, error) {
	findings, err := s.store.ListFindings(caseID)
	if err != nil {
		return nil, err
	}

	byTechnique := map[string][]model.Finding{}
	var order []string
	for _, f := range findings {
		for _, t := range f.Techniques {
			if _, seen := byTechnique[t]; !seen {
				order = append(order, t)
			}
			byTechnique[t] = append(byTechnique[t], f)
		}
	}

	out := make([]AttackTechnique, 0, len(order))
	for _, id := range order {
		tech, ok := attck.Lookup(id)
		if !ok {
			continue
		}
		out = append(out, AttackTechnique{Technique: tech, Findings: byTechnique[id]})
	}
	return out, nil
}

// Sources lists every source file across every collection in the case
// (was, in Phase 1.5, the meaning of GET /cases/{id}/evidence -- that
// path now lists collections instead, since "evidence" primarily means
// "evidence collections" from the UI's perspective now; see
// docs/data-model.md for the full endpoint rename).
func (s *Service) Sources(caseID string) ([]TriagedSourceFile, error) {
	files, err := s.store.ListSourceFiles(caseID)
	if err != nil {
		return nil, err
	}
	return triageAll(files), nil
}

// EventProvenance is the full chain for one event: the normalized event,
// the raw record its first observation came from, the source file that
// raw record was read from, and -- since deduplication can mean an event
// was observed in more than one collection -- every collection it was
// actually observed in. Finding -> Event -> RawEvidence -> SourceFile,
// plus Event -> [Collection] for "Observed in: Collection #1, Collection #2".
type EventProvenance struct {
	Event        model.Event              `json:"event"`
	RawEvidence  model.RawEvidence        `json:"raw_evidence"`
	SourceFile   model.SourceFile         `json:"source_file"`
	Observations []model.EventObservation `json:"observations"`
}

func (s *Service) EventProvenance(caseID, eventID string) (EventProvenance, error) {
	ev, err := s.store.GetEvent(eventID)
	if err != nil || ev.CaseID != caseID {
		return EventProvenance{}, fmt.Errorf("event not found")
	}
	raw, err := s.store.GetRawEvidence(ev.RawEvidenceID)
	if err != nil {
		return EventProvenance{}, fmt.Errorf("raw evidence not found: %w", err)
	}
	sources, err := s.store.ListSourceFiles(caseID)
	if err != nil {
		return EventProvenance{}, err
	}
	var sf model.SourceFile
	for _, f := range sources {
		if f.ID == ev.SourceFileID {
			sf = f
			break
		}
	}
	observations, err := s.store.ListEventObservations(eventID)
	if err != nil {
		return EventProvenance{}, err
	}
	return EventProvenance{Event: ev, RawEvidence: raw, SourceFile: sf, Observations: observations}, nil
}

// ---------------- Investigations (Phase 5) ----------------
//
// Investigations are never persisted -- see internal/investigate's doc
// comment for why. Investigations/Investigation below always recompute
// from whatever Findings/Correlations/Events are currently stored, which
// AnalyzeCase already keeps authoritative via store.ReplaceAnalysis (one
// atomic transaction). This means deleting evidence and re-running
// analysis can never leave a stale investigation behind, and it needed
// no new database table or migration: the same "compute on read from
// existing store queries" pattern CaseSummary, AttackSummary, and
// Finding (detail) already use above.

// Investigations returns caseID's current investigation-level
// assessment: every Finding grouped into a coherent investigative story
// with a deterministic risk score, confidence, and narrative. See
// internal/investigate for the grouping/scoring/narrative algorithms.
func (s *Service) Investigations(caseID string) ([]model.Investigation, error) {
	events, err := s.store.ListEvents(caseID)
	if err != nil {
		return nil, fmt.Errorf("loading events: %w", err)
	}
	findings, err := s.store.ListFindings(caseID)
	if err != nil {
		return nil, fmt.Errorf("loading findings: %w", err)
	}
	correlations, err := s.store.ListCorrelations(caseID)
	if err != nil {
		return nil, fmt.Errorf("loading correlations: %w", err)
	}
	return investigate.Run(caseID, events, findings, correlations), nil
}

// InvestigationAttackTechnique pairs one ATT&CK technique with exactly
// the findings/events within THIS investigation that support it -- the
// "Tactic -> Techniques -> Supporting Findings -> Supporting Events"
// view, scoped to one investigation rather than the whole case (compare
// AttackTechnique/AttackSummary, which is case-wide).
type InvestigationAttackTechnique struct {
	attck.Technique
	FindingIDs []string `json:"finding_ids"`
	EventIDs   []string `json:"event_ids"`
}

// InvestigationTacticGroup is one MITRE tactic and the techniques within
// this investigation that map to it, mirroring the case-wide ATT&CK
// tab's tactic-grouped layout (internal/web/static/app.js's
// renderAttackTab/CANONICAL_TACTICS) at investigation scope.
type InvestigationTacticGroup struct {
	Tactic     string                         `json:"tactic"`
	Techniques []InvestigationAttackTechnique `json:"techniques"`
}

// InvestigationDetail is an Investigation with its referenced
// events/findings/correlations/techniques resolved inline -- the same
// "one request, fully drillable" shape FindingDetail already provides
// for a single finding, scaled up to an investigation's typically-small
// handful of findings. It never duplicates data: every resolved record
// here is the exact same Event/Finding/Correlation the Timeline/Findings/
// Activity Chains tabs already show, just filtered to this
// investigation's ID references.
type InvestigationDetail struct {
	model.Investigation
	EventDetails       []model.Event              `json:"event_details"`
	FindingDetails     []model.Finding            `json:"finding_details"`
	CorrelationDetails []model.Correlation        `json:"correlation_details"`
	TechniqueDetails   []attck.Technique          `json:"technique_details"`
	AttackBreakdown    []InvestigationTacticGroup `json:"attack_breakdown"`
}

// Investigation returns one investigation's full detail. Since
// investigations aren't persisted and carry no independent identity
// beyond their current finding membership, this recomputes the whole
// case's investigation set and picks out the one matching
// investigationID -- see internal/investigate's stableID, which is what
// makes that ID still match between this call and an earlier
// Investigations() call as long as the underlying findings haven't
// changed.
func (s *Service) Investigation(caseID, investigationID string) (InvestigationDetail, error) {
	all, err := s.Investigations(caseID)
	if err != nil {
		return InvestigationDetail{}, err
	}
	var inv model.Investigation
	found := false
	for _, i := range all {
		if i.ID == investigationID {
			inv, found = i, true
			break
		}
	}
	if !found {
		return InvestigationDetail{}, fmt.Errorf("investigation not found")
	}

	events, err := s.store.GetEvents(inv.EventIDs)
	if err != nil {
		return InvestigationDetail{}, err
	}
	// make(...,0,...), never `var findings []model.Finding`: the JSON
	// response's finding_details field has no `omitempty` (see
	// InvestigationDetail), so a nil slice here would serialize as `null`
	// instead of `[]` -- see correlations' identical fix below for why
	// that's not just a style nit, it crashes internal/web/static/app.js.
	findings := make([]model.Finding, 0, len(inv.FindingIDs))
	for _, id := range inv.FindingIDs {
		f, err := s.store.GetFinding(id)
		if err != nil {
			return InvestigationDetail{}, err
		}
		findings = append(findings, f)
	}
	// No store.GetCorrelation exists (correlations are always listed
	// case-wide, never fetched singly elsewhere either) -- filter the
	// case's correlation list down to this investigation's IDs rather
	// than adding a new store method for a lookup Investigation() is the
	// only caller of.
	allCorrelations, err := s.store.ListCorrelations(caseID)
	if err != nil {
		return InvestigationDetail{}, err
	}
	wantCorr := make(map[string]bool, len(inv.CorrelationIDs))
	for _, id := range inv.CorrelationIDs {
		wantCorr[id] = true
	}
	// make(...,0,...), never `var correlations []model.Correlation`: an
	// investigation built from a single standalone finding with no chain/
	// entity/temporal correlation at all (a real, valid case -- e.g. one
	// isolated persistence artifact with nothing else to correlate it
	// against) has CorrelationIDs == nil, and a `var` slice here would
	// stay nil too, serializing as JSON `null` for correlation_details
	// (no `omitempty` on that field -- see InvestigationDetail). The
	// frontend calls .filter() on it unconditionally
	// (internal/web/static/app.js's renderInvestigationDetail), so a null
	// there crashed the whole investigation detail page -- found via
	// Phase 7 AD1 browser verification (a standalone registry-run-key
	// finding with nothing to correlate against was the first real
	// scenario to hit this). Same bug class, same fix, as
	// internal/investigate/score.go's sortedUniqueStrings from Phase 6.
	correlations := make([]model.Correlation, 0, len(inv.CorrelationIDs))
	for _, c := range allCorrelations {
		if wantCorr[c.ID] {
			correlations = append(correlations, c)
		}
	}

	return InvestigationDetail{
		Investigation:      inv,
		EventDetails:       events,
		FindingDetails:     findings,
		CorrelationDetails: correlations,
		TechniqueDetails:   attck.Resolve(inv.Techniques),
		AttackBreakdown:    buildAttackBreakdown(inv, findings),
	}, nil
}

// buildAttackBreakdown groups an investigation's techniques by MITRE
// tactic, each with exactly the finding/event IDs (within this
// investigation) that support it -- never assigning a technique this
// investigation's own findings don't already carry (internal/attck is
// the only place technique metadata is defined; this only groups IDs
// findings already reference).
func buildAttackBreakdown(inv model.Investigation, findings []model.Finding) []InvestigationTacticGroup {
	type techAgg struct {
		findingIDs map[string]bool
		eventIDs   map[string]bool
	}
	byTechnique := map[string]*techAgg{}
	var techOrder []string
	for _, f := range findings {
		for _, t := range f.Techniques {
			agg, ok := byTechnique[t]
			if !ok {
				agg = &techAgg{findingIDs: map[string]bool{}, eventIDs: map[string]bool{}}
				byTechnique[t] = agg
				techOrder = append(techOrder, t)
			}
			agg.findingIDs[f.ID] = true
			for _, e := range f.SupportingEvents {
				agg.eventIDs[e] = true
			}
		}
	}

	byTactic := map[string][]InvestigationAttackTechnique{}
	var tacticOrder []string
	for _, id := range techOrder {
		tech, ok := attck.Lookup(id)
		if !ok {
			continue
		}
		agg := byTechnique[id]
		findingIDs := make([]string, 0, len(agg.findingIDs))
		for id := range agg.findingIDs {
			findingIDs = append(findingIDs, id)
		}
		eventIDs := make([]string, 0, len(agg.eventIDs))
		for id := range agg.eventIDs {
			eventIDs = append(eventIDs, id)
		}
		sort.Strings(findingIDs)
		sort.Strings(eventIDs)
		entry := InvestigationAttackTechnique{Technique: tech, FindingIDs: findingIDs, EventIDs: eventIDs}
		for _, tactic := range splitTacticString(tech.Tactic) {
			if _, seen := byTactic[tactic]; !seen {
				tacticOrder = append(tacticOrder, tactic)
			}
			byTactic[tactic] = append(byTactic[tactic], entry)
		}
	}

	out := make([]InvestigationTacticGroup, 0, len(tacticOrder))
	for _, tactic := range tacticOrder {
		out = append(out, InvestigationTacticGroup{Tactic: tactic, Techniques: byTactic[tactic]})
	}
	return out
}

// splitTacticString turns attck.Technique's comma-joined Tactic string
// (e.g. "Persistence, Privilege Escalation") into a list -- a technique
// can genuinely belong to more than one MITRE tactic.
func splitTacticString(tacticStr string) []string {
	var out []string
	for _, s := range strings.Split(tacticStr, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// parseFailure turns a parser error into a structured, user-safe report.
//
// The raw error is deliberately NOT passed through: a parser error can
// embed the absolute path it was reading, which is server filesystem
// information the browser has no business seeing. The category is
// derived from the sentinel errors the readers already define, so the
// classification tracks what the code actually returns rather than
// matching on message text.
func parseFailure(sf model.SourceFile, stage string, err error) ParseFailure {
	category, message := classifyParseError(err)
	return ParseFailure{
		SourceFileID: sf.ID,
		Path:         sf.Path,
		Filename:     sf.OriginalFilename,
		ArtifactType: sf.ArtifactType,
		Parser:       sf.Parser,
		Stage:        stage,
		Category:     category,
		Message:      message,
		// Import parses every file completely before persisting anything
		// (see the three-phase structure above), so a file that failed to
		// parse contributed no events at all.
		PartialEvents: false,
	}
}

func classifyParseError(err error) (category, message string) {
	switch {
	case errors.Is(err, evtx.ErrCorrupt), errors.Is(err, regf.ErrCorrupt), errors.Is(err, ad1.ErrCorrupt):
		return ParseFailureCorrupt, "The file is corrupt, truncated, or structurally invalid, so it could not be parsed."
	case errors.Is(err, evtx.ErrNotEVTX):
		return ParseFailureUnsupported, "This file is not a Windows Event Log despite being cataloged as one."
	case errors.Is(err, regf.ErrNotHive):
		return ParseFailureUnsupported, "This file is not a registry hive despite being cataloged as one."
	case errors.Is(err, evtx.ErrLimitExceeded), errors.Is(err, regf.ErrLimitExceeded), errors.Is(err, ad1.ErrLimitExceeded):
		return ParseFailureLimit, "The file exceeds a safety limit (size, record count, or nesting depth) and was not parsed."
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, fs.ErrPermission):
		return ParseFailureUnreadable, "The file could not be read from evidence storage."
	default:
		return ParseFailureInternal, "The file could not be parsed."
	}
}
