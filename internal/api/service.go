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
	"time"

	"github.com/google/uuid"

	"tracefall/internal/archive"
	"tracefall/internal/attck"
	"tracefall/internal/casefiles"
	"tracefall/internal/correlate"
	"tracefall/internal/detect"
	"tracefall/internal/ingest"
	"tracefall/internal/model"
	"tracefall/internal/store"
)

var (
	ErrCaseNotFound       = errors.New("case not found")
	ErrNotIngested        = errors.New("case has no ingested evidence yet")
	ErrCollectionNotFound = errors.New("evidence collection not found")
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

type Service struct {
	store *store.Store
	files *casefiles.Store
	// extractLimits bounds ZIP extraction (file count, per-file/total
	// size, compression ratio) -- see internal/archive. Defaults to
	// archive.DefaultLimits; overridable for tests.
	extractLimits archive.Limits
}

func NewService(s *store.Store, files *casefiles.Store) *Service {
	return &Service{store: s, files: files, extractLimits: archive.DefaultLimits}
}

// ---------- Cases ----------

func (s *Service) CreateCase(name, description string) (model.Case, error) {
	now := time.Now().UTC()
	c := model.Case{
		ID:          uuid.NewString(),
		Name:        name,
		Description: description,
		Status:      model.CaseStatusCreated,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.store.CreateCase(c); err != nil {
		return model.Case{}, fmt.Errorf("creating case: %w", err)
	}
	return c, nil
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
	Collections    int            `json:"collections"`
	SourceFiles    int            `json:"source_files"`
	Events         int            `json:"events"`
	Findings       int            `json:"findings"`
	Correlations   int            `json:"correlations"`
	SeverityCounts map[string]int `json:"severity_counts"`
	TechniqueCount int            `json:"technique_count"`
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

	return Summary{
		Collections:    len(collections),
		SourceFiles:    len(sources),
		Events:         len(events),
		Findings:       len(findings),
		Correlations:   len(correlations),
		SeverityCounts: sevCounts,
		TechniqueCount: len(techniques),
	}, nil
}

// ---------- Evidence collections ----------

func (s *Service) ListCollections(caseID string) ([]model.Collection, error) {
	return s.store.ListCollections(caseID)
}

// CollectionDetail is one collection plus the source files it produced,
// for GET /cases/{id}/evidence/{collectionId}.
type CollectionDetail struct {
	model.Collection
	SourceFiles []model.SourceFile `json:"source_files"`
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
	return CollectionDetail{Collection: c, SourceFiles: sources}, nil
}

// ---------- Adding evidence ----------

// IngestResultSummary is returned from adding one evidence collection to
// a case -- a machine-checkable summary of what was discovered and
// parsed, not the full event list (fetch that from the timeline
// endpoint, which spans every collection).
type IngestResultSummary struct {
	Collection model.Collection `json:"collection"`
	// SourceFiles are the files parsed from THIS collection specifically.
	SourceFiles []model.SourceFile `json:"source_files"`
	// EventCount is how many records this collection's supported
	// artifacts parsed to, including ones that turned out to already be
	// known (see DuplicateEventCount) -- i.e. this collection's own
	// parsed_event_count.
	EventCount int `json:"event_count"`
	// NewEventCount is how many of those were genuinely new to the case;
	// DuplicateEventCount is how many matched an event already known
	// from an earlier collection (by internal/model.Event.ComputeDedupHash)
	// and were recorded as an additional observation rather than a
	// second Event row. NewEventCount + DuplicateEventCount == EventCount.
	NewEventCount       int      `json:"new_event_count"`
	DuplicateEventCount int      `json:"duplicate_event_count"`
	Skipped             []string `json:"skipped_files"`
	Errors              []string `json:"errors"`
}

// AddEvidenceFromPath ingests evidence directly from a local filesystem
// directory as a new collection in caseID -- the original Phase 1 flow,
// kept for local/scripted use (e.g. the bundled synthetic dataset). For
// a browser-uploaded KAPE ZIP, see AddEvidenceFromUpload. A case accepts
// any number of collections: each call adds another one rather than
// being rejected outright -- unless it's the *same* evidence (by
// deterministic directory fingerprint, see hashDirectory) as a
// collection already in this case, in which case it's rejected with
// *DuplicateEvidenceError before anything is parsed or ingested.
func (s *Service) AddEvidenceFromPath(caseID, path string) (IngestResultSummary, error) {
	if _, err := s.GetCase(caseID); err != nil {
		return IngestResultSummary{}, err
	}

	hash, err := hashDirectory(path)
	if err != nil {
		return IngestResultSummary{}, fmt.Errorf("fingerprinting evidence directory: %w", err)
	}
	if err := s.checkDuplicateEvidence(caseID, hash); err != nil {
		return IngestResultSummary{}, err
	}

	collection := model.Collection{
		ID: uuid.NewString(), CaseID: caseID, CreatedAt: time.Now().UTC(),
		SourceType: model.SourceTypeLocalPath, OriginalFilename: path, EvidenceDirectory: path,
		ArchiveHash: hash, IngestionStatus: model.CollectionStatusPending,
	}
	if err := s.createCollectionOrDuplicateError(collection); err != nil {
		return IngestResultSummary{}, err
	}

	res, err := s.ingestFromDirectory(caseID, collection.ID, path)
	if err != nil {
		_ = s.store.UpdateCollection(model.Collection{ID: collection.ID, IngestionStatus: model.CollectionStatusFailed})
		return IngestResultSummary{}, err
	}
	return res, nil
}

// UploadResultSummary is returned from POST /cases/{id}/evidence -- an
// IngestResultSummary plus a few archive-level facts the UI shows as
// upload/extraction progress.
type UploadResultSummary struct {
	IngestResultSummary
	UploadSizeBytes int64 `json:"upload_size_bytes"`
	ExtractedFiles  int   `json:"extracted_files"`
	ExtractedBytes  int64 `json:"extracted_bytes"`
}

// AddEvidenceFromUpload accepts an uploaded KAPE package as a ZIP
// archive read from zipData, and adds it to caseID as a new evidence
// collection:
//
//	stage + hash the upload (before anything else exists)
//	-> reject as a duplicate if this case already has a collection with the same hash
//	-> save the original archive (preserved, untouched, for provenance)
//	-> validate + safely extract it (internal/archive)
//	-> discover + parse + normalize supported artifacts (internal/ingest, unchanged)
//	-> deduplicate events against every event already in the case
//	-> store
//
// The archive is treated as untrusted input throughout: see
// internal/archive's doc comment for the specific protections applied
// during extraction. Any failure at any step removes everything written
// to disk for this collection specifically (never touching any other
// collection already in the case) and marks it failed, so the case
// itself is never left corrupted and the caller can simply try adding
// evidence again.
func (s *Service) AddEvidenceFromUpload(caseID string, zipData io.Reader) (UploadResultSummary, error) {
	if _, err := s.GetCase(caseID); err != nil {
		return UploadResultSummary{}, err
	}

	// Hash before creating any collection, extracting, or parsing --
	// staged outside any collection's own directory, since we don't yet
	// know whether this upload will be rejected as a duplicate.
	stagingPath, uploadSize, archiveHash, err := s.stageUpload(caseID, zipData)
	if err != nil {
		return UploadResultSummary{}, err
	}
	stagingClaimed := false
	defer func() {
		if !stagingClaimed {
			_ = os.Remove(stagingPath)
		}
	}()

	if err := s.checkDuplicateEvidence(caseID, archiveHash); err != nil {
		return UploadResultSummary{}, err
	}

	collectionID := uuid.NewString()
	evidenceDir := s.files.EvidenceDir(caseID, collectionID)
	collection := model.Collection{
		ID: collectionID, CaseID: caseID, CreatedAt: time.Now().UTC(),
		SourceType: model.SourceTypeUpload, ArchiveHash: archiveHash, EvidenceDirectory: evidenceDir,
		IngestionStatus: model.CollectionStatusPending,
	}
	if err := s.createCollectionOrDuplicateError(collection); err != nil {
		return UploadResultSummary{}, err
	}

	if err := s.files.EnsureCollectionDir(caseID, collectionID); err != nil {
		_ = s.store.UpdateCollection(model.Collection{ID: collectionID, IngestionStatus: model.CollectionStatusFailed})
		return UploadResultSummary{}, fmt.Errorf("preparing collection storage: %w", err)
	}

	succeeded := false
	defer func() {
		if !succeeded {
			_ = s.files.RemoveCollectionDir(caseID, collectionID)
			_ = s.store.UpdateCollection(model.Collection{ID: collectionID, IngestionStatus: model.CollectionStatusFailed})
		}
	}()

	uploadPath := s.files.UploadPath(caseID, collectionID)
	if err := os.Rename(stagingPath, uploadPath); err != nil {
		return UploadResultSummary{}, fmt.Errorf("finalizing uploaded archive: %w", err)
	}
	stagingClaimed = true // ownership transferred to the collection dir; its own cleanup (above) covers it from here

	extractRes, err := archive.ExtractFile(uploadPath, evidenceDir, s.extractLimits)
	if err != nil {
		return UploadResultSummary{}, err
	}

	ingestRes, err := s.ingestFromDirectory(caseID, collectionID, evidenceDir)
	if err != nil {
		return UploadResultSummary{}, err
	}

	_ = s.files.WriteMetadata(caseID, collectionID, ingestRes.Collection) // best-effort; DB remains authoritative

	succeeded = true
	return UploadResultSummary{
		IngestResultSummary: ingestRes,
		UploadSizeBytes:     uploadSize,
		ExtractedFiles:      extractRes.FilesExtracted,
		ExtractedBytes:      extractRes.TotalBytes,
	}, nil
}

// ingestFromDirectory runs the discover/parse/normalize pipeline
// (internal/ingest.Walk, unchanged) against dir for one collection,
// deduplicates the result against the rest of the case's evidence, and
// persists everything. Shared by both AddEvidenceFromPath and
// AddEvidenceFromUpload so there is exactly one place that pipeline is
// invoked and exactly one place deduplication happens.
func (s *Service) ingestFromDirectory(caseID, collectionID, dir string) (IngestResultSummary, error) {
	res, err := ingest.Walk(caseID, collectionID, dir, ingest.Registry())
	if err != nil {
		return IngestResultSummary{}, fmt.Errorf("ingest: %w", err)
	}
	if err := s.enrichMissingHosts(caseID, res.Events); err != nil {
		return IngestResultSummary{}, fmt.Errorf("enriching event hosts: %w", err)
	}

	if err := s.store.SaveSourceFiles(res.SourceFiles); err != nil {
		return IngestResultSummary{}, fmt.Errorf("saving source files: %w", err)
	}
	if err := s.store.SaveRawEvidence(res.Raw); err != nil {
		return IngestResultSummary{}, fmt.Errorf("saving raw evidence: %w", err)
	}

	newEvents, observations, err := s.deduplicate(caseID, collectionID, res.Events, res.Raw)
	if err != nil {
		return IngestResultSummary{}, fmt.Errorf("deduplicating events: %w", err)
	}
	if err := s.store.SaveEvents(newEvents); err != nil {
		return IngestResultSummary{}, fmt.Errorf("saving events: %w", err)
	}
	if err := s.store.SaveEventObservations(observations); err != nil {
		return IngestResultSummary{}, fmt.Errorf("saving event observations: %w", err)
	}

	collection := model.Collection{
		ID: collectionID, IngestionStatus: model.CollectionStatusIngested,
		FileCount:            len(res.SourceFiles) + len(res.Skipped),
		SupportedFileCount:   len(res.SourceFiles),
		UnsupportedFileCount: len(res.Skipped),
		ParsedEventCount:     len(res.Events),
	}
	if err := s.store.UpdateCollection(collection); err != nil {
		return IngestResultSummary{}, fmt.Errorf("updating collection: %w", err)
	}
	full, err := s.store.GetCollection(collectionID)
	if err != nil {
		return IngestResultSummary{}, fmt.Errorf("reloading collection: %w", err)
	}

	// A case with at least one ingested collection always moves to
	// "ingested" -- including when it was already "analyzed": adding
	// evidence makes the prior analysis stale, and this is the signal
	// the dashboard uses to prompt re-running it.
	if err := s.store.UpdateCaseStatus(caseID, model.CaseStatusIngested); err != nil {
		return IngestResultSummary{}, fmt.Errorf("updating case status: %w", err)
	}

	errs := make([]string, len(res.Errors))
	for i, e := range res.Errors {
		errs[i] = fmt.Sprintf("%s: %v", e.Path, e.Err)
	}

	return IngestResultSummary{
		Collection:          full,
		SourceFiles:         res.SourceFiles,
		EventCount:          len(res.Events),
		NewEventCount:       len(newEvents),
		DuplicateEventCount: len(res.Events) - len(newEvents),
		Skipped:             res.Skipped,
		Errors:              errs,
	}, nil
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

// enrichMissingHosts fills in Host, in place, for any event in events
// that's still blank after internal/ingest.Walk's own per-collection
// backfill. That per-collection backfill (see ingest.backfillHost) only
// has that one collection's own events to learn a dominant host from --
// which fails completely for a collection whose artifact types never
// carry a hostname natively at all (e.g. a follow-up collection
// containing only a registry export and Task Scheduler XML, neither of
// which records a computer name). Left blank, those events would match
// each other by their shared emptiness in host-scoped correlation
// (internal/correlate) instead of by real evidence, and would fail to
// match events from an *earlier* collection that does carry a real host
// -- exactly the case this phase adds: a case's evidence increasingly
// arrives across more than one collection over time. This borrows the
// dominant host already established elsewhere in the case as a
// second-pass fallback; if the case has no host information at all yet
// either, it's a no-op, same as ingest.backfillHost's own behavior.
func (s *Service) enrichMissingHosts(caseID string, events []model.Event) error {
	hasBlank := false
	for _, e := range events {
		if e.Host == "" {
			hasBlank = true
			break
		}
	}
	if !hasBlank {
		return nil
	}

	existing, err := s.store.ListEvents(caseID)
	if err != nil {
		return err
	}
	counts := map[string]int{}
	for _, e := range existing {
		if e.Host != "" {
			counts[e.Host]++
		}
	}
	if len(counts) == 0 {
		return nil
	}
	var dominant string
	best := -1
	for host, n := range counts {
		if n > best || (n == best && host < dominant) {
			dominant, best = host, n
		}
	}
	for i := range events {
		if events[i].Host == "" {
			events[i].Host = dominant
		}
	}
	return nil
}

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
// createCollectionOrDuplicateError for the race-safe backstop.
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

// createCollectionOrDuplicateError inserts collection, translating a
// database-level (case_id, archive_hash) uniqueness violation --
// store.ErrDuplicateCollection, from schema.go's
// idx_collections_case_archive_hash -- into a *DuplicateEvidenceError
// identifying whichever collection won the race. This is what makes
// duplicate detection safe against two concurrent requests both passing
// checkDuplicateEvidence's SELECT before either has inserted: only one
// INSERT can succeed, and the loser gets a clean duplicate error here
// instead of a raw constraint-violation error or, worse, a second
// collection.
func (s *Service) createCollectionOrDuplicateError(collection model.Collection) error {
	err := s.store.SaveCollection(collection)
	if err == nil {
		return nil
	}
	if errors.Is(err, store.ErrDuplicateCollection) {
		if existing, found, ferr := s.store.FindCollectionByHash(collection.CaseID, collection.ArchiveHash); ferr == nil && found {
			return s.duplicateEvidenceError(collection.CaseID, existing)
		}
		return ErrDuplicateEvidence
	}
	return fmt.Errorf("creating collection: %w", err)
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

	events, err := s.store.ListEvents(caseID)
	if err != nil {
		return AnalyzeResultSummary{}, fmt.Errorf("loading events: %w", err)
	}

	findings := detect.Run(caseID, events)
	correlations := correlate.Run(caseID, events)

	if err := s.store.ClearAnalysis(caseID); err != nil {
		return AnalyzeResultSummary{}, fmt.Errorf("clearing prior analysis: %w", err)
	}
	if err := s.store.SaveFindings(findings); err != nil {
		return AnalyzeResultSummary{}, fmt.Errorf("saving findings: %w", err)
	}
	if err := s.store.SaveCorrelations(correlations); err != nil {
		return AnalyzeResultSummary{}, fmt.Errorf("saving correlations: %w", err)
	}
	if err := s.store.UpdateCaseStatus(caseID, model.CaseStatusAnalyzed); err != nil {
		return AnalyzeResultSummary{}, fmt.Errorf("updating case status: %w", err)
	}

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
func (s *Service) Sources(caseID string) ([]model.SourceFile, error) {
	return s.store.ListSourceFiles(caseID)
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
