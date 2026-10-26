// Package store is Tracefall's persistence layer: a thin wrapper over
// SQLite (via the pure-Go modernc.org/sqlite driver, so no cgo/system
// SQLite dependency is required to build or run Tracefall). SQLite is a
// deliberate MVP choice -- see docs/data-model.md for the migration path
// to PostgreSQL when multi-user/concurrent-write access is needed.
//
// No layer above store (detect, correlate, api) does its own SQL; they
// all go through the typed methods here.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"tracefall/internal/model"
)

// ErrDuplicateCollection means an INSERT into collections violated the
// (case_id, archive_hash) uniqueness constraint (see schema.go's
// idx_collections_case_archive_hash) -- the database-level backstop
// against two concurrent requests both passing a SELECT-based duplicate
// check before either has inserted. Callers should look up the
// collection that already holds this hash (FindCollectionByHash) to
// report which one it duplicates.
var ErrDuplicateCollection = errors.New("a collection with this archive/source hash already exists in this case")

// ErrDuplicateCase means an INSERT into cases violated the
// idx_cases_name_unique uniqueness constraint (see schema's comment by
// that index) -- the database-level backstop against two concurrent
// requests both passing a SELECT-based duplicate check before either has
// inserted. Callers should look up the case that already holds this name
// (FindCaseByName) to report which one it duplicates.
var ErrDuplicateCase = errors.New("a case with this name already exists")

// isUniqueConstraintViolation reports whether err came from violating a
// SQLite UNIQUE constraint/index. Matched by message substring (the
// stable part of modernc.org/sqlite's error text -- e.g. "UNIQUE
// constraint failed: t.a, t.b") rather than a driver-specific error type,
// so this package's only dependency on the driver's error shape is this
// one string, in this one place.
func isUniqueConstraintViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

type Store struct {
	sourceTx            *sql.Tx // private source-transaction view only
	db                  *sql.DB
	reviewFingerprintMu sync.Mutex
	reviewFingerprints  map[string]reviewFingerprintCache
}

// Open opens (creating if necessary) the SQLite database at path and
// ensures the schema exists.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	// SQLite handles one writer at a time; a single connection avoids
	// SQLITE_BUSY errors under Tracefall's modest concurrency needs.
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: applying schema: %w", err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: migrating schema: %w", err)
	}
	if _, err := db.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: enabling foreign keys: %w", err)
	}
	s := &Store{db: db}
	if err := s.RecoverReviewBatches(); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: recovering interrupted batch reviews: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

const timeLayout = "2006-01-02T15:04:05.000000000Z"

func fmtTime(t time.Time) string { return t.UTC().Format(timeLayout) }

func parseTime(s string) time.Time {
	t, _ := time.Parse(timeLayout, s)
	return t
}

// ---------- Cases ----------

const caseCols = `id, name, description, status, created_at, updated_at, case_status, priority, analyzed_at`

// scanCase scans one row shaped like caseCols. analyzed_at may be empty
// (never analyzed), which leaves Case.AnalyzedAt nil so its `omitempty`
// JSON tag hides it entirely rather than serializing a misleading
// zero-ish timestamp.
//
// It also enforces one invariant every reader depends on: a case
// reporting Status == analyzed always carries the AnalyzedAt timestamp
// of the run that produced that status. ReplaceAnalysis -- the only
// writer of CaseStatusAnalyzed -- sets both in one statement, so a row
// written by the current code can never violate this. A row migrated in
// from before analyzed_at existed can: migrate.go deliberately does not
// invent a timestamp for those (see its comment), leaving status =
// 'analyzed' beside an empty analyzed_at. Reported verbatim, that made
// the dashboard state self-contradictory -- an ANALYZED badge directly
// above "Last analyzed: Never analyzed".
//
// Reconciled here, at the single point every Case is materialized, so
// GetCase/ListCases/FindCaseByName/exports all agree: without a recorded
// run time there is nothing to attest that the stored results reflect
// the current evidence, which is exactly what CaseStatusIngested already
// means ("evidence present, analysis not up to date -- re-run it"). The
// findings themselves are untouched and still readable; re-running
// analysis restores the analyzed status along with a real timestamp.
//
// Deliberately a read-time projection, not an UPDATE: the stored row is
// left exactly as acquired, so nothing is rewritten under the
// investigator, and a future migration could still backfill these rows
// from an authoritative source if one ever exists. Only Status (the
// engine lifecycle) is affected -- CaseStatus, the analyst's own
// workflow state, is never touched by this or anything else here.
func scanCase(row interface{ Scan(...any) error }) (model.Case, error) {
	var c model.Case
	var created, updated, analyzedAt string
	err := row.Scan(&c.ID, &c.Name, &c.Description, &c.Status, &created, &updated, &c.CaseStatus, &c.Priority, &analyzedAt)
	if err != nil {
		return model.Case{}, err
	}
	c.CreatedAt, c.UpdatedAt = parseTime(created), parseTime(updated)
	if analyzedAt != "" {
		t := parseTime(analyzedAt)
		c.AnalyzedAt = &t
	}
	if c.Status == model.CaseStatusAnalyzed && c.AnalyzedAt == nil {
		c.Status = model.CaseStatusIngested
	}
	return c, nil
}

func (s *Store) CreateCase(c model.Case) error {
	caseStatus, priority := c.CaseStatus, c.Priority
	if caseStatus == "" {
		caseStatus = model.CaseWorkflowOpen
	}
	if priority == "" {
		priority = model.CasePriorityMedium
	}
	_, err := s.db.Exec(
		`INSERT INTO cases (id, name, description, status, created_at, updated_at, case_status, priority, analyzed_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, '')`,
		c.ID, c.Name, c.Description, c.Status, fmtTime(c.CreatedAt), fmtTime(c.UpdatedAt), caseStatus, priority,
	)
	if isUniqueConstraintViolation(err) {
		return ErrDuplicateCase
	}
	return err
}

// FindCaseByName looks up a case by name, compared the same way
// idx_cases_name_unique enforces uniqueness: trimmed of leading/trailing
// whitespace and case-insensitively (see docs/data-model.md's "Case name
// uniqueness" section). Returns found=false if no case has that name.
func (s *Store) FindCaseByName(name string) (model.Case, bool, error) {
	row := s.db.QueryRow(`SELECT `+caseCols+` FROM cases WHERE LOWER(TRIM(name)) = LOWER(TRIM(?)) LIMIT 1`, name)
	c, err := scanCase(row)
	if err == sql.ErrNoRows {
		return model.Case{}, false, nil
	}
	if err != nil {
		return model.Case{}, false, err
	}
	return c, true, nil
}

func (s *Store) UpdateCaseStatus(id, status string) error {
	_, err := s.db.Exec(`UPDATE cases SET status = ?, updated_at = ? WHERE id = ?`,
		status, fmtTime(time.Now()), id)
	return err
}

// CaseMetadataUpdate is the set of analyst-editable case fields
// (Service.UpdateCaseMetadata) -- deliberately NOT including Status
// (the analysis lifecycle, only ever set by AnalyzeCase/evidence
// changes) or CreatedAt/AnalyzedAt (both system-set). A nil field means
// "leave unchanged", letting a caller update just one of
// name/description/case_status/priority without needing the others.
type CaseMetadataUpdate struct {
	Name        *string
	Description *string
	CaseStatus  *string
	Priority    *string
}

// UpdateCaseMetadata applies a partial update to a case's analyst-facing
// metadata. Name uniqueness (case-insensitive, trimmed) is enforced the
// same way CreateCase's does, via the same idx_cases_name_unique
// database constraint -- isUniqueConstraintViolation translates a
// collision to ErrDuplicateCase identically.
func (s *Store) UpdateCaseMetadata(id string, u CaseMetadataUpdate) error {
	c, err := s.GetCase(id)
	if err != nil {
		return err
	}
	if u.Name != nil {
		c.Name = *u.Name
	}
	if u.Description != nil {
		c.Description = *u.Description
	}
	if u.CaseStatus != nil {
		c.CaseStatus = *u.CaseStatus
	}
	if u.Priority != nil {
		c.Priority = *u.Priority
	}
	_, err = s.db.Exec(`UPDATE cases SET name = ?, description = ?, case_status = ?, priority = ?, updated_at = ? WHERE id = ?`,
		c.Name, c.Description, c.CaseStatus, c.Priority, fmtTime(time.Now()), id)
	if isUniqueConstraintViolation(err) {
		return ErrDuplicateCase
	}
	return err
}

func (s *Store) GetCase(id string) (model.Case, error) {
	row := s.db.QueryRow(`SELECT `+caseCols+` FROM cases WHERE id = ?`, id)
	return scanCase(row)
}

func (s *Store) ListCases() ([]model.Case, error) {
	rows, err := s.db.Query(`SELECT ` + caseCols + ` FROM cases ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.Case
	for rows.Next() {
		c, err := scanCase(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ---------- Collections ----------

const collectionCols = `id, case_id, created_at, source_type, original_filename, archive_hash, integrity_sha512, evidence_directory, ingestion_status, file_count, supported_file_count, unsupported_file_count, imported_file_count, parsed_event_count, tz_recorded, tz_key_name, tz_active_bias_minutes, tz_value_used, tz_control_set, tz_source, tz_reason`

func scanCollection(row interface{ Scan(...any) error }) (model.Collection, error) {
	var c model.Collection
	var createdAt string
	err := row.Scan(&c.ID, &c.CaseID, &createdAt, &c.SourceType, &c.OriginalFilename, &c.ArchiveHash,
		&c.IntegritySHA512, &c.EvidenceDirectory, &c.IngestionStatus, &c.FileCount, &c.SupportedFileCount,
		&c.UnsupportedFileCount, &c.ImportedFileCount, &c.ParsedEventCount,
		&c.TimeZone.Recorded, &c.TimeZone.KeyName, &c.TimeZone.ActiveBiasMinutes, &c.TimeZone.ValueUsed,
		&c.TimeZone.ControlSet, &c.TimeZone.Source, &c.TimeZone.Reason)
	if err != nil {
		return model.Collection{}, err
	}
	c.CreatedAt = parseTime(createdAt)
	return c, nil
}

// SetCollectionTimeZone records the host time zone a collection's SYSTEM hive
// gave, or the reason it gave none. It is written once per import of a
// collection; a later import with the same hive writes the same value.
func (s *Store) SetCollectionTimeZone(collectionID string, tz model.TimeZoneBasis) error {
	_, err := s.db.Exec(`UPDATE collections SET tz_recorded = ?, tz_key_name = ?, tz_active_bias_minutes = ?,
		tz_value_used = ?, tz_control_set = ?, tz_source = ?, tz_reason = ? WHERE id = ?`,
		tz.Recorded, tz.KeyName, tz.ActiveBiasMinutes, tz.ValueUsed, tz.ControlSet, tz.Source, tz.Reason, collectionID)
	return err
}

// SaveCollection inserts a new collection. If c.ArchiveHash is non-empty
// and another collection in the same case already has it, this returns
// ErrDuplicateCollection (see idx_collections_case_archive_hash in
// schema.go) instead of creating a second row.
func (s *Store) SaveCollection(c model.Collection) error {
	return insertCollection(s.db, c)
}

// execer is the subset of *sql.DB and *sql.Tx that the insert helpers
// below need, so one statement definition serves both a standalone
// write and a write enrolled in a larger transaction.
type execer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

func insertCollection(db execer, c model.Collection) error {
	// The insert names its own columns. collectionCols (what reads select)
	// grows with new fields; the insert must not silently follow it. Time
	// zone fields are written later, by SetCollectionTimeZone.
	_, err := db.Exec(`INSERT INTO collections (id, case_id, created_at, source_type, original_filename, archive_hash, integrity_sha512, evidence_directory, ingestion_status, file_count, supported_file_count, unsupported_file_count, imported_file_count, parsed_event_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.CaseID, fmtTime(c.CreatedAt), c.SourceType, c.OriginalFilename, c.ArchiveHash,
		c.IntegritySHA512, c.EvidenceDirectory, c.IngestionStatus, c.FileCount, c.SupportedFileCount,
		c.UnsupportedFileCount, c.ImportedFileCount, c.ParsedEventCount)
	if isUniqueConstraintViolation(err) {
		return ErrDuplicateCollection
	}
	return err
}

// CreateCollectionWithSourceFiles inserts a collection and its complete
// discovery catalog in ONE transaction: either the collection and every
// one of its source_file rows exist, or nothing does.
//
// Discovery used to insert the collection first and catalog afterwards,
// which meant any failure while cataloging (an unreadable directory, a
// corrupt AD1, a database error) left behind a permanent collection with
// status "failed" and zero files -- a row that is not evidence, cannot
// become evidence, and has to be explained to an investigator who never
// successfully added anything. Committing both together removes that
// state from the data model rather than teaching the UI to render it.
//
// A duplicate (case_id, archive_hash) still surfaces as
// ErrDuplicateCollection, from the same unique index as before, so the
// race two concurrent identical uploads can lose is unchanged -- except
// that the loser now leaves no rows at all.
func (s *Store) CreateCollectionWithSourceFiles(c model.Collection, files []model.SourceFile) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := insertCollection(tx, c); err != nil {
		return err
	}
	for _, f := range files {
		if err := insertSourceFile(tx, f); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// UpdateCollection overwrites a collection's MUTABLE fields (status and
// counts) only. It deliberately cannot touch archive_hash or
// integrity_sha512: an evidence integrity hash that could be rewritten
// after the fact would not be integrity evidence at all, so the column
// is simply absent from this statement -- see docs/evidence-integrity.md.
//
// Original doc: overwrites a collection's mutable fields (status and
// counts) -- called both when a discovery/import pass finishes and
// whenever evidence deletion changes what a collection actually
// contains (see Service.recomputeCollectionCounts).
func (s *Store) UpdateCollection(c model.Collection) error {
	_, err := s.db.Exec(`UPDATE collections SET ingestion_status = ?, file_count = ?, supported_file_count = ?,
		unsupported_file_count = ?, imported_file_count = ?, parsed_event_count = ? WHERE id = ?`,
		c.IngestionStatus, c.FileCount, c.SupportedFileCount, c.UnsupportedFileCount, c.ImportedFileCount, c.ParsedEventCount, c.ID)
	return err
}

func (s *Store) GetCollection(id string) (model.Collection, error) {
	row := s.db.QueryRow(`SELECT `+collectionCols+` FROM collections WHERE id = ?`, id)
	return scanCollection(row)
}

// ListCollections returns a case's collections in the order they were
// added -- the basis of "Collection #1", "Collection #2", ... display
// numbering, which is assigned by position, not stored.
func (s *Store) ListCollections(caseID string) ([]model.Collection, error) {
	rows, err := s.db.Query(`SELECT `+collectionCols+` FROM collections WHERE case_id = ? ORDER BY created_at ASC`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// make(...,0), not `var`: these rows are served straight out to the
	// JSON API, where a nil slice becomes `null` and the dashboard's
	// .map/.filter/.join on it throws. An empty result must serialize
	// as [].
	out := make([]model.Collection, 0)
	for rows.Next() {
		c, err := scanCollection(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// FindCollectionByHash looks up an existing collection in caseID with
// the given archive/source hash, for deduplicating a new upload/ingest
// against evidence already added to the case. Returns found=false, not
// an error, when there's no match. hash == "" always reports not found,
// since an empty hash never uniquely identifies anything (see
// idx_collections_case_archive_hash in schema.go).
func (s *Store) FindCollectionByHash(caseID, hash string) (model.Collection, bool, error) {
	if hash == "" {
		return model.Collection{}, false, nil
	}
	row := s.db.QueryRow(`SELECT `+collectionCols+` FROM collections WHERE case_id = ? AND archive_hash = ? LIMIT 1`, caseID, hash)
	c, err := scanCollection(row)
	if err == sql.ErrNoRows {
		return model.Collection{}, false, nil
	}
	if err != nil {
		return model.Collection{}, false, err
	}
	return c, true, nil
}

// ---------- Source files ----------

// ErrDuplicateSourceFile means an UPDATE that would mark a source file
// imported instead violated the (collection_id, sha256) uniqueness
// constraint (idx_source_files_collection_sha256_active in schema.go) --
// the race-safe backstop behind Service's discovery-time in-batch
// duplicate detection. See that index's comment in migrate.go for why
// this is scoped to one collection, not the whole case.
var ErrDuplicateSourceFile = errors.New("a file with this content has already been imported into this collection")

// SaveSourceFiles inserts freshly-discovered source file rows -- called
// once per discovery pass, before any of them are necessarily selected
// for import. See model.SourceFile's doc comment for the
// discovered -> imported life cycle.
func (s *Store) SaveSourceFiles(files []model.SourceFile) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, f := range files {
		if err := insertSourceFile(tx, f); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func insertSourceFile(db execer, f model.SourceFile) error {
	_, err := db.Exec(`INSERT INTO source_files (id, case_id, collection_id, original_filename, path, artifact_type, parser, supported, size_bytes, sha256, embedded_hash, import_status, event_count, discovered_at, imported_at, deleted_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID, f.CaseID, f.CollectionID, f.OriginalFilename, f.Path, f.ArtifactType, f.Parser,
		boolToInt(f.Supported), f.SizeBytes, f.SHA256, f.EmbeddedHash, f.ImportStatus, f.EventCount, fmtTime(f.DiscoveredAt),
		fmtOptionalTime(f.ImportedAt), fmtOptionalTime(f.DeletedAt))
	return err
}

const sourceFileCols = `id, case_id, collection_id, original_filename, path, artifact_type, parser, supported, size_bytes, sha256, embedded_hash, import_status, event_count, discovered_at, imported_at, deleted_at, parse_coverage_json`

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// fmtOptionalTime formats t, or "" if t is nil -- the on-disk
// representation of "not set yet" for imported_at/deleted_at, matching
// the rest of this package's empty-string-means-unset convention (e.g.
// collections.archive_hash).
func fmtOptionalTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return fmtTime(*t)
}

func scanSourceFile(row interface{ Scan(...any) error }) (model.SourceFile, error) {
	var f model.SourceFile
	var supported int
	var discovered, imported, deleted, coverage string
	err := row.Scan(&f.ID, &f.CaseID, &f.CollectionID, &f.OriginalFilename, &f.Path, &f.ArtifactType, &f.Parser,
		&supported, &f.SizeBytes, &f.SHA256, &f.EmbeddedHash, &f.ImportStatus, &f.EventCount, &discovered, &imported, &deleted, &coverage)
	if err != nil {
		return model.SourceFile{}, err
	}
	if coverage != "" {
		if err := json.Unmarshal([]byte(coverage), &f.ParseCoverage); err != nil {
			return model.SourceFile{}, fmt.Errorf("decoding parse coverage: %w", err)
		}
	}
	f.Supported = supported != 0
	f.DiscoveredAt = parseTime(discovered)
	if imported != "" {
		t := parseTime(imported)
		f.ImportedAt = &t
	}
	if deleted != "" {
		t := parseTime(deleted)
		f.DeletedAt = &t
	}
	return f, nil
}

// ListSourceFiles returns every active (non-deleted) source file across
// a case -- every collection, imported or merely discovered.
func (s *Store) ListSourceFiles(caseID string) ([]model.SourceFile, error) {
	rows, err := s.db.Query(`SELECT `+sourceFileCols+` FROM source_files WHERE case_id = ? AND deleted_at = '' ORDER BY path`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// make(...,0), not `var`: these rows are served straight out to the
	// JSON API, where a nil slice becomes `null` and the dashboard's
	// .map/.filter/.join on it throws. An empty result must serialize
	// as [].
	out := make([]model.SourceFile, 0)
	for rows.Next() {
		f, err := scanSourceFile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// ListSourceFilesByCollection returns just one collection's active
// source files, e.g. for the collection-detail API/UI view.
func (s *Store) ListSourceFilesByCollection(collectionID string) ([]model.SourceFile, error) {
	rows, err := s.db.Query(`SELECT `+sourceFileCols+` FROM source_files WHERE collection_id = ? AND deleted_at = '' ORDER BY path`, collectionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// make(...,0), not `var`: these rows are served straight out to the
	// JSON API, where a nil slice becomes `null` and the dashboard's
	// .map/.filter/.join on it throws. An empty result must serialize
	// as [].
	out := make([]model.SourceFile, 0)
	for rows.Next() {
		f, err := scanSourceFile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// GetSourceFile fetches one source file by ID regardless of its
// import/deleted status -- callers that need to distinguish those states
// (e.g. to reject importing an already-deleted file) check the returned
// fields themselves.
func (s *Store) GetSourceFile(id string) (model.SourceFile, error) {
	row := s.db.QueryRow(`SELECT `+sourceFileCols+` FROM source_files WHERE id = ?`, id)
	return scanSourceFile(row)
}

// GetSourceFiles fetches multiple source files by ID, skipping any ID
// that doesn't exist (callers that need to detect a missing ID compare
// len(result) against len(ids) themselves) -- used by bulk evidence
// deletion to resolve a batch of selected IDs in one place.
func (s *Store) GetSourceFiles(ids []string) ([]model.SourceFile, error) {
	out := make([]model.SourceFile, 0, len(ids))
	for _, id := range ids {
		f, err := s.GetSourceFile(id)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// MarkSourceFileImported transitions a source file from "discovered" to
// "imported" now that it's been successfully parsed. The WHERE clause
// (import_status = 'discovered') makes this an idempotent, race-safe
// compare-and-swap: applied reports whether this call actually won that
// transition -- false means another concurrent import request already
// claimed this file, and the caller should treat it as already handled
// rather than importing it a second time. A uniqueness violation (two
// different, concurrently-imported files racing to claim the same
// content hash within this collection) is translated to
// ErrDuplicateSourceFile.
// SetSourceFileSHA256 records Tracefall's own, independently-computed
// SHA-256 for a source file. Used by the AD1 import adapter (see
// internal/api's ImportEvidence), which -- unlike a ZIP/local-path
// collection, where every file's SHA-256 is already known at discovery
// time from a cheap disk read -- can't afford to decompress every AD1
// entry just to hash it during discovery (see internal/ad1's package doc
// comment and docs/ad1-ingestion.md), so the hash becomes available only
// once a selected file is actually extracted and imported.
func (s *Store) SetSourceFileSHA256(id, sha256 string) error {
	_, err := s.db.Exec(`UPDATE source_files SET sha256 = ? WHERE id = ?`, sha256, id)
	return err
}

func (s *Store) MarkSourceFileImported(id string, eventCount int, importedAt time.Time, coverage ...*model.ParseCoverage) (applied bool, err error) {
	diagnostic := ""
	if len(coverage) > 0 && coverage[0] != nil {
		b, e := json.Marshal(coverage[0])
		if e != nil {
			return false, e
		}
		diagnostic = string(b)
	}
	res, err := s.sourceExecutor().Exec(`UPDATE source_files SET import_status = ?, event_count = ?, imported_at = ?, parse_coverage_json = ?
 WHERE id = ? AND import_status = ?`,
		model.SourceFileImported, eventCount, fmtTime(importedAt), diagnostic, id, model.SourceFileDiscovered)
	if isUniqueConstraintViolation(err) {
		return false, ErrDuplicateSourceFile
	}
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// RetryFailedSource permits an explicit retry only when no evidence from the
// failed attempt exists. Old non-atomic failed imports must be repaired in a
// fresh case, not silently combined with a second attempt. The state and row
// absence checks are one statement, so a stale caller cannot revive admission.
func (s *Store) RetryFailedSource(id string) (bool, error) {
	res, err := s.db.Exec(`UPDATE source_files SET import_status = ?, event_count = 0, imported_at = '', parse_coverage_json = ''
 WHERE id = ? AND import_status = ?
 AND NOT EXISTS (SELECT 1 FROM raw_evidence WHERE source_file_id = ?)
 AND NOT EXISTS (SELECT 1 FROM event_observations WHERE source_file_id = ?)
 AND NOT EXISTS (SELECT 1 FROM events WHERE source_file_id = ?)`, model.SourceFileDiscovered, id, model.SourceFileFailed, id, id, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// MarkSourceFileFailed records that a selected file failed, keeping it visible.
func (s *Store) MarkSourceFileFailed(id string) error {
	_, err := s.db.Exec(`UPDATE source_files SET import_status = ? WHERE id = ?`, model.SourceFileFailed, id)
	return err
}

// SoftDeleteSourceFile marks a source file removed as of deletedAt
// without deleting the row -- see model.SourceFile.DeletedAt's doc
// comment. Active listings (ListSourceFiles, ListSourceFilesByCollection)
// exclude it from here on; its physical evidence file removal is the
// caller's responsibility (internal/casefiles), since this package has
// no filesystem knowledge.
func (s *Store) SoftDeleteSourceFile(id string, deletedAt time.Time) error {
	_, err := s.db.Exec(`UPDATE source_files SET deleted_at = ? WHERE id = ?`, fmtTime(deletedAt), id)
	return err
}

// ---------- Raw evidence ----------

func (s *Store) SaveRawEvidence(items []model.RawEvidence) error {
	tx, err := s.beginSourceWrite()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT INTO raw_evidence (id, case_id, source_file_id, source_reference, raw) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, r := range items {
		if _, err := stmt.Exec(r.ID, r.CaseID, r.SourceFileID, r.SourceReference, r.Raw); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) GetRawEvidence(id string) (model.RawEvidence, error) {
	row := s.db.QueryRow(`SELECT id, case_id, source_file_id, source_reference, raw FROM raw_evidence WHERE id = ?`, id)
	var r model.RawEvidence
	if err := row.Scan(&r.ID, &r.CaseID, &r.SourceFileID, &r.SourceReference, &r.Raw); err != nil {
		return model.RawEvidence{}, err
	}
	return r, nil
}

// ---------- Events ----------

func (s *Store) SaveEvents(events []model.Event) error {
	tx, err := s.beginSourceWrite()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT INTO events (
		id, case_id, collection_id, timestamp, host, user, event_type, provider, event_id,
		process_name, process_path, parent_process, parent_process_path, pid, ppid, command_line,
		file_path, registry_path, network_source, network_dest, network_dest_port,
		artifact_type, source_file_id, source_reference, parser, confidence, raw_evidence_id, dedup_hash, extra_json
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, e := range events {
		extraJSON, err := json.Marshal(e.Extra)
		if err != nil {
			return err
		}
		if _, err := stmt.Exec(
			e.ID, e.CaseID, e.CollectionID, fmtTime(e.Timestamp), e.Host, e.User, e.EventType, e.Provider, e.EventID,
			e.ProcessName, e.ProcessPath, e.ParentProcessName, e.ParentProcessPath, e.PID, e.PPID, e.CommandLine,
			e.FilePath, e.RegistryPath, e.NetworkSource, e.NetworkDest, e.NetworkDestPort,
			e.ArtifactType, e.SourceFileID, e.SourceReference, e.Parser, e.Confidence, e.RawEvidenceID, e.DedupHash, string(extraJSON),
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

const eventCols = `id, case_id, collection_id, timestamp, host, user, event_type, provider, event_id,
	process_name, process_path, parent_process, parent_process_path, pid, ppid, command_line,
	file_path, registry_path, network_source, network_dest, network_dest_port,
	artifact_type, source_file_id, source_reference, parser, confidence, raw_evidence_id, dedup_hash, extra_json`

func scanEvent(row interface{ Scan(...any) error }) (model.Event, error) {
	e, extraJSON, err := scanEventRaw(row)
	if err != nil {
		return model.Event{}, err
	}
	e.Extra = map[string]string{}
	_ = json.Unmarshal([]byte(extraJSON), &e.Extra)
	return e, nil
}

// scanEventRaw reads one event row but leaves its extra_json undecoded. The
// caller decodes it only when it needs the event's Extra map.
func scanEventRaw(row interface{ Scan(...any) error }) (model.Event, string, error) {
	var e model.Event
	var ts, extraJSON string
	err := row.Scan(
		&e.ID, &e.CaseID, &e.CollectionID, &ts, &e.Host, &e.User, &e.EventType, &e.Provider, &e.EventID,
		&e.ProcessName, &e.ProcessPath, &e.ParentProcessName, &e.ParentProcessPath, &e.PID, &e.PPID, &e.CommandLine,
		&e.FilePath, &e.RegistryPath, &e.NetworkSource, &e.NetworkDest, &e.NetworkDestPort,
		&e.ArtifactType, &e.SourceFileID, &e.SourceReference, &e.Parser, &e.Confidence, &e.RawEvidenceID, &e.DedupHash, &extraJSON,
	)
	if err != nil {
		return model.Event{}, "", err
	}
	e.Timestamp = parseTime(ts)
	return e, extraJSON, nil
}

// FindEventByDedupHash looks up an existing event in caseID with the
// given DedupHash, for deduplicating a newly-parsed event against
// everything already in the case (across every collection). Returns
// found=false, not an error, when there's no match.
func (s *Store) FindEventByDedupHash(caseID, hash string) (model.Event, bool, error) {
	if hash == "" {
		return model.Event{}, false, nil
	}
	row := s.sourceExecutor().QueryRow(`SELECT `+eventCols+` FROM events WHERE case_id = ? AND dedup_hash = ? LIMIT 1`, caseID, hash)
	e, err := scanEvent(row)
	if err == sql.ErrNoRows {
		return model.Event{}, false, nil
	}
	if err != nil {
		return model.Event{}, false, err
	}
	return e, true, nil
}

// ListEvents returns every event for a case ordered chronologically --
// the basis of the unified timeline.
func (s *Store) ListEvents(caseID string) ([]model.Event, error) {
	rows, err := s.db.Query(`SELECT `+eventCols+` FROM events WHERE case_id = ? ORDER BY timestamp ASC`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.Event
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) GetEvent(id string) (model.Event, error) {
	row := s.db.QueryRow(`SELECT `+eventCols+` FROM events WHERE id = ?`, id)
	return scanEvent(row)
}

func (s *Store) GetEvents(ids []string) ([]model.Event, error) {
	out := make([]model.Event, 0, len(ids))
	for _, id := range ids {
		e, err := s.GetEvent(id)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// ListEventsByCollection returns just the events first observed in one
// collection, chronologically -- used for per-collection filtered
// timeline views. Note this only reflects events whose *primary*
// (first) observation was this collection; an event also re-observed in
// this collection via deduplication but first seen in an earlier one is
// not included here -- see ListEventObservationsByCollection for that.
func (s *Store) ListEventsByCollection(collectionID string) ([]model.Event, error) {
	rows, err := s.db.Query(`SELECT `+eventCols+` FROM events WHERE collection_id = ? ORDER BY timestamp ASC`, collectionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.Event
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// CollectionEventSummary is what a collection's detail reports about its
// events, computed in the database rather than by loading every event.
type CollectionEventSummary struct {
	Hosts    []string   // distinct non-empty hosts, sorted
	Earliest *time.Time // earliest dated event; nil when none is dated
	Latest   *time.Time // latest dated event; nil when none is dated
	Undated  int        // events whose artifact records no time (zero timestamp)
}

// SummarizeCollectionEvents answers the detail's event questions with two
// aggregate queries. Timestamps are stored in one fixed-width UTC layout
// (timeLayout), so MIN and MAX over the text are the chronological bounds.
// The zero timestamp is Tracefall's "no time recorded" encoding and is never
// a bound: it is counted as undated, as ListEventsByCollection's callers
// have always been told.
func (s *Store) SummarizeCollectionEvents(collectionID string) (CollectionEventSummary, error) {
	var out CollectionEventSummary
	zero := fmtTime(time.Time{})

	var undated int
	var lo, hi *string
	if err := s.db.QueryRow(
		`SELECT COUNT(CASE WHEN timestamp = ? THEN 1 END),
		        MIN(CASE WHEN timestamp <> ? THEN timestamp END),
		        MAX(CASE WHEN timestamp <> ? THEN timestamp END)
		   FROM events WHERE collection_id = ?`,
		zero, zero, zero, collectionID,
	).Scan(&undated, &lo, &hi); err != nil {
		return out, fmt.Errorf("store: collection event bounds: %w", err)
	}
	out.Undated = undated
	if lo != nil {
		t := parseTime(*lo)
		out.Earliest = &t
	}
	if hi != nil {
		t := parseTime(*hi)
		out.Latest = &t
	}

	rows, err := s.db.Query(
		`SELECT DISTINCT host FROM events WHERE collection_id = ? AND host <> '' ORDER BY host`,
		collectionID)
	if err != nil {
		return out, fmt.Errorf("store: collection hosts: %w", err)
	}
	defer rows.Close()
	out.Hosts = []string{}
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return out, err
		}
		out.Hosts = append(out.Hosts, h)
	}
	return out, rows.Err()
}

// DeleteEvent removes one event row entirely -- only valid once its last
// EventObservation has also been removed (see
// Service.deleteSourceFileEvidence), since an Event with no observations
// left has no evidence supporting it at all.
func (s *Store) DeleteEvent(id string) error {
	_, err := s.db.Exec(`DELETE FROM events WHERE id = ?`, id)
	return err
}

// RepointEventProvenance updates an Event's own denormalized provenance
// fields (which describe its *first* observation only -- see
// model.Event's doc comment) to point at a different, still-existing
// observation. Needed when the observation an event's provenance
// currently points to is the one being deleted, but the event itself
// survives because it has other observations left -- without this, the
// event's SourceFileID/RawEvidenceID would dangle, pointing at rows that
// no longer exist. See Service.deleteSourceFileEvidence.
func (s *Store) RepointEventProvenance(eventID, collectionID, sourceFileID, rawEvidenceID, sourceReference, artifactType, parser string) error {
	_, err := s.db.Exec(`UPDATE events SET collection_id = ?, source_file_id = ?, raw_evidence_id = ?,
		source_reference = ?, artifact_type = ?, parser = ? WHERE id = ?`,
		collectionID, sourceFileID, rawEvidenceID, sourceReference, artifactType, parser, eventID)
	return err
}

// DeleteRawEvidenceBySourceFile removes every raw evidence record read
// from one source file -- safe once every event/observation that could
// have referenced it has already been deleted or repointed elsewhere
// (see Service.deleteSourceFileEvidence, which does so in that order).
// ListRawEvidenceBySourceFile returns the raw records one evidence file
// produced, newest-insertion-order, bounded by limit.
//
// It exists because a parser may produce records with NO event -- an
// NTFS $LogFile, a browser-cache container, a Recycle Bin $R file whose
// content is the evidence itself. Those records were previously reachable
// only through an event that, by definition, does not exist for them, so
// a perfectly good forensic record was stored and never shown.
func (s *Store) ListRawEvidenceBySourceFile(sourceFileID string, limit int) ([]model.RawEvidence, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(
		`SELECT id, case_id, source_file_id, source_reference, raw
		 FROM raw_evidence WHERE source_file_id = ? ORDER BY rowid LIMIT ?`, sourceFileID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]model.RawEvidence, 0)
	for rows.Next() {
		var r model.RawEvidence
		if err := rows.Scan(&r.ID, &r.CaseID, &r.SourceFileID, &r.SourceReference, &r.Raw); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) DeleteRawEvidenceBySourceFile(sourceFileID string) error {
	_, err := s.db.Exec(`DELETE FROM raw_evidence WHERE source_file_id = ?`, sourceFileID)
	return err
}

// ---------- Event observations ----------

func (s *Store) SaveEventObservations(observations []model.EventObservation) error {
	tx, err := s.beginSourceWrite()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT INTO event_observations
		(id, event_id, case_id, collection_id, source_file_id, raw_evidence_id, source_reference)
		VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, o := range observations {
		if _, err := stmt.Exec(o.ID, o.EventID, o.CaseID, o.CollectionID, o.SourceFileID, o.RawEvidenceID, o.SourceReference); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func scanObservation(row interface{ Scan(...any) error }) (model.EventObservation, error) {
	var o model.EventObservation
	err := row.Scan(&o.ID, &o.EventID, &o.CaseID, &o.CollectionID, &o.SourceFileID, &o.RawEvidenceID, &o.SourceReference)
	return o, err
}

const observationCols = `id, event_id, case_id, collection_id, source_file_id, raw_evidence_id, source_reference`

// ListEventObservations returns every collection an event was observed
// in, oldest first -- the data behind an "Observed in: Collection #1,
// Collection #2" display. An event that has never been deduplicated
// still has exactly one observation (recorded at ingest time regardless
// of whether a match was found), so this is always non-empty for a
// valid event ID.
func (s *Store) ListEventObservations(eventID string) ([]model.EventObservation, error) {
	rows, err := s.db.Query(`SELECT `+observationCols+` FROM event_observations WHERE event_id = ? ORDER BY id`, eventID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.EventObservation
	for rows.Next() {
		o, err := scanObservation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// ListEventObservationsBySourceFile returns every observation that came
// from one specific source file -- one row per event that file
// contributed to, regardless of whether that event turned out to be
// canonical or a dedup match against an event first seen elsewhere. This
// is the starting point for deleting a source file's evidence: see
// Service.deleteSourceFileEvidence.
func (s *Store) ListEventObservationsBySourceFile(sourceFileID string) ([]model.EventObservation, error) {
	rows, err := s.db.Query(`SELECT `+observationCols+` FROM event_observations WHERE source_file_id = ? ORDER BY id`, sourceFileID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.EventObservation
	for rows.Next() {
		o, err := scanObservation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// DeleteEventObservation removes one observation row -- the first step
// in removing a source file's contribution to an event (see
// Service.deleteSourceFileEvidence): once an event's last observation is
// gone, the event itself has no remaining evidence and is deleted too;
// until then, it survives (still supported by its other observations).
func (s *Store) DeleteEventObservation(id string) error {
	_, err := s.db.Exec(`DELETE FROM event_observations WHERE id = ?`, id)
	return err
}

// ---------- Findings ----------

// ClearAnalysis removes all findings and correlations for a case so
// re-running detection/correlation is idempotent and reproducible rather
// than accumulating duplicate findings on every /analyze call.
func (s *Store) ClearAnalysis(caseID string) error {
	if _, err := s.db.Exec(`DELETE FROM findings WHERE case_id = ?`, caseID); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM correlations WHERE case_id = ?`, caseID)
	return err
}

// ReplaceAnalysis atomically replaces a case's findings and correlations
// with a freshly computed set, and marks the case analyzed -- all in one
// transaction. This is Phase 6's fix for a real correctness gap:
// AnalyzeCase previously called ClearAnalysis, SaveFindings,
// SaveCorrelations, and UpdateCaseStatus as four SEPARATE transactions,
// so a failure between the clear and the save (a disk error, a crash)
// left the case with its analysis wiped and nothing valid to replace it
// -- silently destroying the previous, still-valid results. With
// everything in one transaction, ANY failure rolls back to exactly the
// state before the call: the case's prior findings/correlations/status
// are left completely untouched, and the caller (Service.AnalyzeCase)
// can report the failure without ever having damaged what was there
// before. See docs/analyst-workflow.md's "Analysis state" section.
func (s *Store) ReplaceAnalysis(caseID string, findings []model.Finding, correlations []model.Correlation) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Clears every finding and correlation for the case, invalidated ones
	// included. Finding and correlation IDs are CONTENT-DERIVED
	// (model.StableID): the same finding recomputed after a deletion has
	// the same primary key as the retained one, so old and new rows
	// cannot coexist. Retaining them would make re-analysis fail on a
	// key collision -- which is why the retained historical record is
	// the analysis RUN, not its output. See Store.InvalidateAnalysis.
	if _, err := tx.Exec(`DELETE FROM findings WHERE case_id = ?`, caseID); err != nil {
		return fmt.Errorf("clearing prior findings: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM correlations WHERE case_id = ?`, caseID); err != nil {
		return fmt.Errorf("clearing prior correlations: %w", err)
	}

	findingStmt, err := tx.Prepare(`INSERT INTO findings
		(id, case_id, rule_id, title, severity, confidence, description, supporting_events_json, techniques_json, first_seen, last_seen, created_at, analysis_run_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer findingStmt.Close()
	for _, f := range findings {
		supJSON, _ := json.Marshal(f.SupportingEvents)
		techJSON, _ := json.Marshal(f.Techniques)
		if _, err := findingStmt.Exec(f.ID, f.CaseID, f.RuleID, f.Title, f.Severity, f.Confidence, f.Description,
			string(supJSON), string(techJSON), fmtTime(f.FirstSeen), fmtTime(f.LastSeen), fmtTime(f.CreatedAt),
			f.AnalysisRunID); err != nil {
			return fmt.Errorf("saving finding: %w", err)
		}
	}

	corrStmt, err := tx.Prepare(`INSERT INTO correlations
		(id, case_id, type, title, description, event_ids_json, first_seen, last_seen, analysis_run_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer corrStmt.Close()
	for _, c := range correlations {
		idsJSON, _ := json.Marshal(c.EventIDs)
		if _, err := corrStmt.Exec(c.ID, c.CaseID, c.Type, c.Title, c.Description, string(idsJSON),
			fmtTime(c.FirstSeen), fmtTime(c.LastSeen), c.AnalysisRunID); err != nil {
			return fmt.Errorf("saving correlation: %w", err)
		}
	}

	now := fmtTime(time.Now())
	if _, err := tx.Exec(`UPDATE cases SET status = ?, analyzed_at = ?, updated_at = ? WHERE id = ?`,
		model.CaseStatusAnalyzed, now, now, caseID); err != nil {
		return fmt.Errorf("updating case status: %w", err)
	}

	return tx.Commit()
}

func (s *Store) SaveFindings(findings []model.Finding) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT INTO findings
		(id, case_id, rule_id, title, severity, confidence, description, supporting_events_json, techniques_json, first_seen, last_seen, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, f := range findings {
		supJSON, _ := json.Marshal(f.SupportingEvents)
		techJSON, _ := json.Marshal(f.Techniques)
		if _, err := stmt.Exec(f.ID, f.CaseID, f.RuleID, f.Title, f.Severity, f.Confidence, f.Description,
			string(supJSON), string(techJSON), fmtTime(f.FirstSeen), fmtTime(f.LastSeen), fmtTime(f.CreatedAt)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func scanFinding(row interface{ Scan(...any) error }) (model.Finding, error) {
	var f model.Finding
	var supJSON, techJSON, first, last, created string
	err := row.Scan(&f.ID, &f.CaseID, &f.RuleID, &f.Title, &f.Severity, &f.Confidence, &f.Description,
		&supJSON, &techJSON, &first, &last, &created, &f.AnalysisRunID)
	if err != nil {
		return model.Finding{}, err
	}
	_ = json.Unmarshal([]byte(supJSON), &f.SupportingEvents)
	_ = json.Unmarshal([]byte(techJSON), &f.Techniques)
	f.FirstSeen, f.LastSeen, f.CreatedAt = parseTime(first), parseTime(last), parseTime(created)
	return f, nil
}

const findingCols = `id, case_id, rule_id, title, severity, confidence, description, supporting_events_json, techniques_json, first_seen, last_seen, created_at, analysis_run_id`

// currentAnalysisFilter excludes rows produced by an invalidated run.
//
// InvalidateAnalysis already removes those rows, so in a consistent
// database this filter matches everything. It is kept as the enforcement
// point anyway: it makes "no result from an invalidated run is ever
// current" an invariant of the QUERY rather than of one write path, so a
// row that survives a partial failure, an older database, or some future
// code path that forgets, still cannot be presented as a current result.
//
// This is the enforcement point for the whole invalidation lifecycle. It
// lives in the QUERY, not in a caller, because every current view --
// summary counts, findings, correlations, investigations, activity
// chains, ATT&CK coverage -- reads through these two list methods. A
// rule applied anywhere higher could be forgotten by the next view
// somebody adds, and the failure mode is a case reporting findings for
// evidence it no longer holds.
//
// Legacy rows carrying no run id are excluded once ANY run for the case
// has been invalidated. Such a row predates run attribution, so it
// cannot be tied to a surviving run -- and leaving it visible would be
// exactly the orphaned "current" finding this exists to prevent.
const currentAnalysisFilter = `
	AND analysis_run_id NOT IN (
		SELECT id FROM analysis_runs WHERE case_id = ? AND status = 'invalidated'
	)
	AND NOT (
		analysis_run_id = '' AND EXISTS (
			SELECT 1 FROM analysis_runs WHERE case_id = ? AND status = 'invalidated'
		)
	)`

// ListFindings returns a case's CURRENT findings: those still describing
// the evidence the case holds. Findings from an invalidated run are
// retained in the database and excluded here -- see
// ListFindingsIncludingInvalidated for the audit view.
func (s *Store) ListFindings(caseID string) ([]model.Finding, error) {
	rows, err := s.db.Query(`SELECT `+findingCols+` FROM findings WHERE case_id = ?`+
		currentAnalysisFilter+` ORDER BY first_seen ASC`, caseID, caseID, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// ListFindingsIncludingInvalidated returns every finding a case has ever
// retained, including those from invalidated runs.
//
// For audit and export only. Nothing that presents CURRENT results may
// call it: the whole point of the distinction is that an invalidated
// finding is history, not a result.
func (s *Store) ListFindingsIncludingInvalidated(caseID string) ([]model.Finding, error) {
	rows, err := s.db.Query(`SELECT `+findingCols+` FROM findings WHERE case_id = ? ORDER BY first_seen ASC`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) GetFinding(id string) (model.Finding, error) {
	row := s.db.QueryRow(`SELECT `+findingCols+` FROM findings WHERE id = ?`, id)
	return scanFinding(row)
}

// ---------- Correlations ----------

func (s *Store) SaveCorrelations(correlations []model.Correlation) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT INTO correlations
		(id, case_id, type, title, description, event_ids_json, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, c := range correlations {
		idsJSON, _ := json.Marshal(c.EventIDs)
		if _, err := stmt.Exec(c.ID, c.CaseID, c.Type, c.Title, c.Description, string(idsJSON), fmtTime(c.FirstSeen), fmtTime(c.LastSeen)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

const correlationCols = `id, case_id, type, title, description, event_ids_json, first_seen, last_seen, analysis_run_id`

func scanCorrelations(rows *sql.Rows) ([]model.Correlation, error) {
	defer rows.Close()
	var out []model.Correlation
	for rows.Next() {
		var c model.Correlation
		var idsJSON, first, last string
		if err := rows.Scan(&c.ID, &c.CaseID, &c.Type, &c.Title, &c.Description, &idsJSON,
			&first, &last, &c.AnalysisRunID); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(idsJSON), &c.EventIDs)
		c.FirstSeen, c.LastSeen = parseTime(first), parseTime(last)
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListCorrelations returns a case's CURRENT correlations. Correlations
// from an invalidated run are retained and excluded, exactly as findings
// are -- a correlation describes a set of events, and when those events
// are deleted it no longer describes anything the case holds.
func (s *Store) ListCorrelations(caseID string) ([]model.Correlation, error) {
	rows, err := s.db.Query(`SELECT `+correlationCols+` FROM correlations WHERE case_id = ?`+
		currentAnalysisFilter+` ORDER BY first_seen ASC`, caseID, caseID, caseID)
	if err != nil {
		return nil, err
	}
	return scanCorrelations(rows)
}

// ListCorrelationsIncludingInvalidated is the audit counterpart of
// ListFindingsIncludingInvalidated.
func (s *Store) ListCorrelationsIncludingInvalidated(caseID string) ([]model.Correlation, error) {
	rows, err := s.db.Query(`SELECT `+correlationCols+` FROM correlations WHERE case_id = ? ORDER BY first_seen ASC`, caseID)
	if err != nil {
		return nil, err
	}
	return scanCorrelations(rows)
}

// InvalidateAnalysis marks a case's completed analysis runs as no longer
// describing its evidence, and reports what stopped being current.
//
// Nothing is deleted. The runs, their findings and their correlations
// are all retained: an investigator must be able to see that analysis
// WAS run, what it produced, and that the evidence behind it was
// subsequently removed. What changes is that none of it is returned by a
// current-results query ever again.
//
// Idempotent: a run already invalidated keeps its original timestamp and
// reason, because the first invalidation is the one that describes what
// happened.
func (s *Store) InvalidateAnalysis(caseID string, at time.Time, reason string) (runs, findings, correlations int, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, 0, 0, err
	}
	defer tx.Rollback()

	// Count first: after the update these rows are no longer current, so
	// the counts have to be taken while they still are.
	if err := tx.QueryRow(`SELECT COUNT(*) FROM analysis_runs WHERE case_id = ? AND status = ?`,
		caseID, model.AnalysisRunCompleted).Scan(&runs); err != nil {
		return 0, 0, 0, err
	}
	if err := tx.QueryRow(`SELECT COUNT(*) FROM findings WHERE case_id = ?`, caseID).Scan(&findings); err != nil {
		return 0, 0, 0, err
	}
	if err := tx.QueryRow(`SELECT COUNT(*) FROM correlations WHERE case_id = ?`, caseID).Scan(&correlations); err != nil {
		return 0, 0, 0, err
	}

	if _, err := tx.Exec(`UPDATE analysis_runs
		SET status = ?, invalidated_at = ?, invalidation_reason = ?
		WHERE case_id = ? AND status = ?`,
		model.AnalysisRunInvalidated, fmtTime(at), reason, caseID, model.AnalysisRunCompleted); err != nil {
		return 0, 0, 0, fmt.Errorf("invalidating analysis runs: %w", err)
	}

	// The RUN is the retained historical record; its output is removed.
	//
	// This is the one place the "retain everything" instinct has to give
	// way to the schema: finding and correlation IDs are content-derived
	// (model.StableID), so a finding recomputed after the deletion
	// collides with the retained copy of itself on the primary key, and
	// re-analysis fails outright. Keeping the rows would therefore trade
	// a working re-analysis for an audit trail -- and the audit trail is
	// not lost: the invalidated run row records which run it was, when
	// it ran, on which build, how many findings and correlations it
	// produced, when it was invalidated and why. That is what
	// ListAnalysisRuns and the case's audit log both surface.
	if _, err := tx.Exec(`DELETE FROM findings WHERE case_id = ?`, caseID); err != nil {
		return 0, 0, 0, fmt.Errorf("removing invalidated findings: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM correlations WHERE case_id = ?`, caseID); err != nil {
		return 0, 0, 0, fmt.Errorf("removing invalidated correlations: %w", err)
	}

	// A case whose analysis has been invalidated has no valid analysis
	// for its current evidence, so it is no longer "analyzed" and has no
	// analysis timestamp. The run history retains when it happened; the
	// case must not keep claiming a current result it does not have.
	if _, err := tx.Exec(`UPDATE cases SET analyzed_at = '', updated_at = ? WHERE id = ?`,
		fmtTime(at), caseID); err != nil {
		return 0, 0, 0, fmt.Errorf("clearing case analysis timestamp: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, 0, 0, err
	}
	return runs, findings, correlations, nil
}

// AnalysisInvalidatedWithoutReplacement reports the specific state that
// makes a case "not analyzed" rather than "never analyzed": its analysis
// was invalidated by an evidence deletion and nothing has replaced it.
//
// It is deliberately NOT "has this case ever had an invalidation". An
// invalidated run is retained forever, so that question stays true for
// the rest of the case's life -- and a case re-analyzed after a deletion
// has a perfectly current analysis that must not be labelled otherwise.
// Invalidation marks every completed run, so "an invalidated run exists
// and no completed one does" is exactly the state with no valid result.
func (s *Store) AnalysisInvalidatedWithoutReplacement(caseID string) (bool, error) {
	var invalidated, completed int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM analysis_runs WHERE case_id = ? AND status = ?`,
		caseID, model.AnalysisRunInvalidated).Scan(&invalidated); err != nil {
		return false, err
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM analysis_runs WHERE case_id = ? AND status = ?`,
		caseID, model.AnalysisRunCompleted).Scan(&completed); err != nil {
		return false, err
	}
	return invalidated > 0 && completed == 0, nil
}

// ---------- Case deletion ----------

// DeleteCase permanently removes a case and every row anywhere in the
// database that belongs to it -- collections, source files, raw
// evidence, events, event observations, findings, correlations,
// analyst workflow state, analysis runs, and finally the case row
// itself -- in dependency order, inside one
// transaction, so a failure partway through leaves the database exactly
// as it was rather than an orphaned partial deletion. Foreign keys are
// enforced (PRAGMA foreign_keys = ON, set in Open()) with no ON DELETE
// CASCADE declared anywhere in schema.go, deliberately: an explicit,
// ordered delete here is auditable and easy to reason about, rather than
// relying on cascade semantics to get the order right implicitly.
//
// This does not touch the case's on-disk evidence directory --
// Service.DeleteCase does that separately via internal/casefiles, since
// this package has no filesystem knowledge.
// DeletedCaseCounts is how many rows of each kind a case deletion
// actually removed, as the database reported them.
//
// These are not estimates and not pre-counts: each field is the
// RowsAffected of the statement that removed it, read back after the
// transaction COMMITTED. Before the commit none of it is true, and
// after the commit all of it is -- which is exactly the granularity at
// which case deletion can be honestly reported.
//
// It costs nothing to collect: sql.Result is already returned by every
// Exec, so no counting query is added for it.
type DeletedCaseCounts struct {
	Collections       int64 `json:"collections"`
	SourceFiles       int64 `json:"source_files"`
	Events            int64 `json:"events"`
	EventObservations int64 `json:"event_observations"`
	RawEvidence       int64 `json:"raw_evidence"`
	Findings          int64 `json:"findings"`
	Correlations      int64 `json:"correlations"`
	Notes             int64 `json:"notes"`
	Tags              int64 `json:"tags"`
	AnalystStatus     int64 `json:"analyst_status"`
	AuditLog          int64 `json:"audit_log"`
	AnalysisRuns      int64 `json:"analysis_runs"`
}

// DeleteCase removes a case and everything belonging to it. See
// DeleteCaseWithCounts, which it delegates to; the counts are discarded
// for callers that do not need them.
func (s *Store) DeleteCase(caseID string) error {
	_, err := s.DeleteCaseWithCounts(caseID)
	return err
}

// DeleteCaseWithCounts is DeleteCase, additionally reporting what it
// removed.
func (s *Store) DeleteCaseWithCounts(caseID string) (DeletedCaseCounts, error) {
	var counts DeletedCaseCounts
	// Each statement's row count is routed to the field it belongs to.
	// A table with no destination here is still deleted -- the count is
	// simply not surfaced.
	into := map[string]*int64{
		`DELETE FROM event_observations WHERE case_id = ?`: &counts.EventObservations,
		`DELETE FROM raw_evidence WHERE case_id = ?`:       &counts.RawEvidence,
		`DELETE FROM events WHERE case_id = ?`:             &counts.Events,
		`DELETE FROM findings WHERE case_id = ?`:           &counts.Findings,
		`DELETE FROM correlations WHERE case_id = ?`:       &counts.Correlations,
		`DELETE FROM source_files WHERE case_id = ?`:       &counts.SourceFiles,
		`DELETE FROM collections WHERE case_id = ?`:        &counts.Collections,
		`DELETE FROM notes WHERE case_id = ?`:              &counts.Notes,
		`DELETE FROM tags WHERE case_id = ?`:               &counts.Tags,
		`DELETE FROM analyst_status WHERE case_id = ?`:     &counts.AnalystStatus,
		`DELETE FROM audit_log WHERE case_id = ?`:          &counts.AuditLog,
		`DELETE FROM analysis_runs WHERE case_id = ?`:      &counts.AnalysisRuns,
	}

	tx, err := s.db.Begin()
	if err != nil {
		return DeletedCaseCounts{}, err
	}
	defer tx.Rollback()

	stmts := []string{
		`DELETE FROM event_observations WHERE case_id = ?`,
		`DELETE FROM raw_evidence WHERE case_id = ?`,
		`DELETE FROM events WHERE case_id = ?`,
		`DELETE FROM findings WHERE case_id = ?`,
		`DELETE FROM correlations WHERE case_id = ?`,
		`DELETE FROM source_files WHERE case_id = ?`,
		`DELETE FROM collections WHERE case_id = ?`,
		// Phase 6: analyst workflow state is scoped to exactly one case
		// and has no independent life of its own once that case is gone
		// (unlike evidence deletion within a live case, which
		// deliberately preserves notes -- see model.Note's doc comment).
		// A whole-case delete is the one case where notes/tags/status/
		// audit history are removed along with everything else.
		`DELETE FROM notes WHERE case_id = ?`,
		`DELETE FROM tags WHERE case_id = ?`,
		`DELETE FROM analyst_status WHERE case_id = ?`,
		`DELETE FROM audit_log WHERE case_id = ?`,
		// Phase 11. Analysis runs describe work done ON this case and
		// have no meaning without it, so they go with it -- the same
		// whole-case rule the audit log above follows. Deleting evidence
		// from a LIVE case does not touch runs; only deleting the case
		// itself does.
		`DELETE FROM analysis_runs WHERE case_id = ?`,
		// Roadmap item 2: pipeline jobs and upload sessions are
		// operational state about work on this case, and go with it.
		`DELETE FROM pipeline_jobs WHERE case_id = ?`,
		`DELETE FROM upload_sessions WHERE case_id = ?`,
		// Outside services' answers about this case's indicators, and the
		// egress level chosen for it, have no meaning without the case.
		`DELETE FROM enrichments WHERE case_id = ?`,
		`DELETE FROM narratives WHERE case_id = ?`,
		`DELETE FROM review_batch_packets WHERE case_id = ?`,
		`DELETE FROM review_batch_members WHERE case_id = ?`,
		`DELETE FROM review_batch_runs WHERE case_id = ?`,
		`DELETE FROM case_reviews WHERE case_id = ?`,
		`DELETE FROM app_settings WHERE key = 'egress:' || ?`,
		`DELETE FROM cases WHERE id = ?`,
	}
	for _, stmt := range stmts {
		res, err := tx.Exec(stmt, caseID)
		if err != nil {
			return DeletedCaseCounts{}, fmt.Errorf("%s: %w", stmt, err)
		}
		if field, ok := into[stmt]; ok {
			if n, err := res.RowsAffected(); err == nil {
				*field = n
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return DeletedCaseCounts{}, err
	}
	// Only now are the counts true. Returning them before the commit
	// would describe rows that could still have rolled back.
	return counts, nil
}

// ---------------- Analysis runs (Phase 11) ----------------
//
// A run row is written when analysis starts and updated exactly once
// when it finishes. That is the only mutation: a completed or failed
// run is never rewritten afterwards, so the record of what happened
// stays fixed even though the findings it produced can be replaced by a
// later run.

const analysisRunCols = `id, case_id, started_at, completed_at, status, tool_version, event_count, finding_count, correlation_count, error, invalidated_at, invalidation_reason`

func scanAnalysisRun(row interface{ Scan(...any) error }) (model.AnalysisRun, error) {
	var r model.AnalysisRun
	var started, completed, invalidated string
	err := row.Scan(&r.ID, &r.CaseID, &started, &completed, &r.Status, &r.ToolVersion,
		&r.EventCount, &r.FindingCount, &r.CorrelationCount, &r.Error,
		&invalidated, &r.InvalidationReason)
	if err != nil {
		return model.AnalysisRun{}, err
	}
	r.StartedAt = parseTime(started)
	// Empty string means "not finished", which must stay nil rather than
	// becoming a zero time -- a zero CompletedAt would render as a real
	// date and claim the run ended in year 1.
	if completed != "" {
		t := parseTime(completed)
		r.CompletedAt = &t
	}
	if invalidated != "" {
		t := parseTime(invalidated)
		r.InvalidatedAt = &t
	}
	return r, nil
}

// CreateAnalysisRun records a run that has just started.
func (s *Store) CreateAnalysisRun(r model.AnalysisRun) error {
	_, err := s.db.Exec(`INSERT INTO analysis_runs (`+analysisRunCols+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.CaseID, fmtTime(r.StartedAt), fmtOptionalTime(r.CompletedAt), r.Status, r.ToolVersion,
		r.EventCount, r.FindingCount, r.CorrelationCount, r.Error,
		fmtOptionalTime(r.InvalidatedAt), r.InvalidationReason)
	return err
}

// FinishAnalysisRun records a run's outcome.
//
// It updates ONLY the completion fields, and only for a run still
// marked running -- so a finished run cannot be reopened or rewritten
// by a later call, whatever the caller intends.
func (s *Store) FinishAnalysisRun(id, status string, completedAt time.Time, eventCount, findingCount, correlationCount int, errMsg string) error {
	_, err := s.db.Exec(`UPDATE analysis_runs
		SET completed_at = ?, status = ?, event_count = ?, finding_count = ?, correlation_count = ?, error = ?
		WHERE id = ? AND status = ?`,
		fmtTime(completedAt), status, eventCount, findingCount, correlationCount, errMsg,
		id, model.AnalysisRunRunning)
	return err
}

// GetAnalysisRun returns one run by ID.
func (s *Store) GetAnalysisRun(id string) (model.AnalysisRun, error) {
	return scanAnalysisRun(s.db.QueryRow(`SELECT `+analysisRunCols+` FROM analysis_runs WHERE id = ?`, id))
}

// ListAnalysisRuns returns a case's runs, most recent first.
func (s *Store) ListAnalysisRuns(caseID string) ([]model.AnalysisRun, error) {
	rows, err := s.db.Query(`SELECT `+analysisRunCols+` FROM analysis_runs WHERE case_id = ? ORDER BY started_at DESC`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]model.AnalysisRun, 0)
	for rows.Next() {
		r, err := scanAnalysisRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListSourceFilesIncludingDeleted returns every source file for a case,
// including soft-deleted ones.
//
// The ordinary ListSourceFiles filters deleted rows out, which is right
// for the working views: deleted evidence should not appear in a catalog
// an analyst selects from. Provenance is the exception. A finding can
// still reference an event whose source file was later deleted, and a
// provenance view that silently dropped that link would imply the
// evidence never existed rather than that it was removed.
func (s *Store) ListSourceFilesIncludingDeleted(caseID string) ([]model.SourceFile, error) {
	rows, err := s.db.Query(`SELECT `+sourceFileCols+` FROM source_files WHERE case_id = ? ORDER BY path`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]model.SourceFile, 0)
	for rows.Next() {
		f, err := scanSourceFile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// ClearIntegrityForTest blanks a collection's recorded SHA-512 so tests
// can exercise the pre-Phase-10A "no digest recorded" path against a
// real database row.
//
// It exists only for that: production code must never clear a recorded
// digest, because the digest is the historical fact integrity
// verification checks against. Named ForTest so no call site can adopt
// it by accident.
func (s *Store) ClearIntegrityForTest(collectionID string) error {
	_, err := s.db.Exec(`UPDATE collections SET integrity_sha512 = '' WHERE id = ?`, collectionID)
	return err
}

// ClearFindingRunIDsForTest blanks a case's finding run attributions so
// tests can exercise the legacy "provenance unavailable" path against
// real rows written before analysis runs were recorded.
//
// Test-only, for the same reason as ClearIntegrityForTest: production
// code must never erase a finding's provenance.
func (s *Store) ClearFindingRunIDsForTest(caseID string) error {
	_, err := s.db.Exec(`UPDATE findings SET analysis_run_id = '' WHERE case_id = ?`, caseID)
	return err
}

// DeleteCollection permanently removes one collection and every row that
// belongs to it, in dependency order, inside a single transaction.
//
// It is the collection-scoped analogue of DeleteCase, and follows the
// same rule: an explicit ordered delete rather than ON DELETE CASCADE,
// because the order is then auditable and reviewable instead of implicit
// in the schema.
//
// Ordinary evidence deletion SOFT-deletes a source file, so Phase 11
// provenance can still report "this file existed and was removed".
// Deleting the whole collection is different: the object that provenance
// would point AT is going away, so leaving soft-deleted children behind
// would leave rows referencing a collection that no longer exists. Those
// rows are removed here.
//
// Callers are expected to have already run the normal evidence-deletion
// path for the collection's live files, which is what removes their
// events, re-points events still observed elsewhere, and marks the case
// for re-analysis. The statements below are what remains afterwards, and
// are written to be correct even if some of it is already gone.
// CollectionEventsAreSelfContained reports whether every event tied to
// this collection belongs to it alone.
//
// It exists to decide whether DeleteCollection's bulk statements are
// SAFE. Those statements delete `events WHERE collection_id = ?`
// wholesale, which is correct only when no other collection still
// observes one of them -- otherwise evidence that a second collection
// independently recorded would be destroyed along with this one.
//
// Two ways that can be untrue, and both are checked:
//
//   - an event attributed HERE is also observed by another collection
//     (deleting it would lose the other collection's observation), or
//   - an observation HERE belongs to an event attributed ELSEWHERE
//     (that event survives, with one fewer observation).
//
// The second case is handled correctly by the bulk statements on their
// own, but it is included so a true answer means "nothing about this
// collection's events involves any other collection" -- a condition a
// reader can check in one sentence, rather than a subtler rule that
// happens to hold.
func (s *Store) CollectionEventsAreSelfContained(collectionID string) (bool, error) {
	var sharedOut, sharedIn int
	err := s.db.QueryRow(`
		SELECT
			(SELECT COUNT(*) FROM events e
			   WHERE e.collection_id = ?
			     AND EXISTS (SELECT 1 FROM event_observations o
			                   WHERE o.event_id = e.id AND o.collection_id <> ?)),
			(SELECT COUNT(*) FROM event_observations o
			   WHERE o.collection_id = ?
			     AND EXISTS (SELECT 1 FROM events e
			                   WHERE e.id = o.event_id AND e.collection_id <> ?))`,
		collectionID, collectionID, collectionID, collectionID).Scan(&sharedOut, &sharedIn)
	if err != nil {
		return false, fmt.Errorf("store: checking whether collection %s shares events: %w", collectionID, err)
	}
	return sharedOut == 0 && sharedIn == 0, nil
}

// CountEventsByCollection counts the events attributed to one
// collection, without loading them.
func (s *Store) CountEventsByCollection(collectionID string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM events WHERE collection_id = ?`, collectionID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: counting events for collection %s: %w", collectionID, err)
	}
	return n, nil
}

// CountActiveSourceFilesByCollection counts a collection's live (not
// already soft-deleted) catalog rows, without loading them. A discovery
// pass writes one row per file it cataloged, supported or not, so this
// is in the thousands for a real triage image even when nothing was
// imported.
func (s *Store) CountActiveSourceFilesByCollection(collectionID string) (int, error) {
	var n int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM source_files WHERE collection_id = ? AND deleted_at = ''`,
		collectionID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: counting source files for collection %s: %w", collectionID, err)
	}
	return n, nil
}

// ListSourceFileIDsByCollectionArtifacts returns the IDs of a
// collection's live catalog rows whose artifact type is one of those
// given. Used to find the few files that may have a generated thumbnail,
// rather than attempting a removal for every file in the collection.
func (s *Store) ListSourceFileIDsByCollectionArtifacts(collectionID string, artifactTypes []string) ([]string, error) {
	if len(artifactTypes) == 0 {
		return nil, nil
	}
	args := make([]any, 0, len(artifactTypes)+1)
	args = append(args, collectionID)
	placeholders := make([]string, 0, len(artifactTypes))
	for _, t := range artifactTypes {
		placeholders = append(placeholders, "?")
		args = append(args, t)
	}
	rows, err := s.db.Query(
		`SELECT id FROM source_files WHERE collection_id = ? AND deleted_at = '' AND artifact_type IN (`+
			strings.Join(placeholders, ",")+`)`, args...)
	if err != nil {
		return nil, fmt.Errorf("store: listing source file ids for collection %s: %w", collectionID, err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (s *Store) DeleteCollection(collectionID string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmts := []string{
		`DELETE FROM event_observations WHERE collection_id = ?`,
		// Only events still attributed to THIS collection. An event that
		// survived because another collection observed it has already had
		// its provenance re-pointed there (see RepointEventProvenance) and
		// must not be removed.
		`DELETE FROM events WHERE collection_id = ?`,
		`DELETE FROM raw_evidence WHERE source_file_id IN (SELECT id FROM source_files WHERE collection_id = ?)`,
		`DELETE FROM source_files WHERE collection_id = ?`,
		`DELETE FROM collections WHERE id = ?`,
	}
	for _, stmt := range stmts {
		if _, err := tx.Exec(stmt, collectionID); err != nil {
			return fmt.Errorf("%s: %w", stmt, err)
		}
	}
	return tx.Commit()
}
