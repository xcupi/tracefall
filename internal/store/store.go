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
	db *sql.DB
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
	return &Store{db: db}, nil
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

const collectionCols = `id, case_id, created_at, source_type, original_filename, archive_hash, evidence_directory, ingestion_status, file_count, supported_file_count, unsupported_file_count, imported_file_count, parsed_event_count`

func scanCollection(row interface{ Scan(...any) error }) (model.Collection, error) {
	var c model.Collection
	var createdAt string
	err := row.Scan(&c.ID, &c.CaseID, &createdAt, &c.SourceType, &c.OriginalFilename, &c.ArchiveHash,
		&c.EvidenceDirectory, &c.IngestionStatus, &c.FileCount, &c.SupportedFileCount, &c.UnsupportedFileCount, &c.ImportedFileCount, &c.ParsedEventCount)
	if err != nil {
		return model.Collection{}, err
	}
	c.CreatedAt = parseTime(createdAt)
	return c, nil
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
	_, err := db.Exec(`INSERT INTO collections (`+collectionCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.CaseID, fmtTime(c.CreatedAt), c.SourceType, c.OriginalFilename, c.ArchiveHash,
		c.EvidenceDirectory, c.IngestionStatus, c.FileCount, c.SupportedFileCount, c.UnsupportedFileCount, c.ImportedFileCount, c.ParsedEventCount)
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

// UpdateCollection overwrites a collection's mutable fields (status and
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
	_, err := db.Exec(`INSERT INTO source_files (`+sourceFileCols+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID, f.CaseID, f.CollectionID, f.OriginalFilename, f.Path, f.ArtifactType, f.Parser,
		boolToInt(f.Supported), f.SizeBytes, f.SHA256, f.EmbeddedHash, f.ImportStatus, f.EventCount, fmtTime(f.DiscoveredAt),
		fmtOptionalTime(f.ImportedAt), fmtOptionalTime(f.DeletedAt))
	return err
}

const sourceFileCols = `id, case_id, collection_id, original_filename, path, artifact_type, parser, supported, size_bytes, sha256, embedded_hash, import_status, event_count, discovered_at, imported_at, deleted_at`

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
	var discovered, imported, deleted string
	err := row.Scan(&f.ID, &f.CaseID, &f.CollectionID, &f.OriginalFilename, &f.Path, &f.ArtifactType, &f.Parser,
		&supported, &f.SizeBytes, &f.SHA256, &f.EmbeddedHash, &f.ImportStatus, &f.EventCount, &discovered, &imported, &deleted)
	if err != nil {
		return model.SourceFile{}, err
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

func (s *Store) MarkSourceFileImported(id string, eventCount int, importedAt time.Time) (applied bool, err error) {
	res, err := s.db.Exec(`UPDATE source_files SET import_status = ?, event_count = ?, imported_at = ?
		WHERE id = ? AND import_status = ?`,
		model.SourceFileImported, eventCount, fmtTime(importedAt), id, model.SourceFileDiscovered)
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

// MarkSourceFileFailed records that a selected file's parser returned an
// error, so it stays visible in the evidence list as failed rather than
// silently vanishing.
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
	tx, err := s.db.Begin()
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
	tx, err := s.db.Begin()
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
	var e model.Event
	var ts, extraJSON string
	err := row.Scan(
		&e.ID, &e.CaseID, &e.CollectionID, &ts, &e.Host, &e.User, &e.EventType, &e.Provider, &e.EventID,
		&e.ProcessName, &e.ProcessPath, &e.ParentProcessName, &e.ParentProcessPath, &e.PID, &e.PPID, &e.CommandLine,
		&e.FilePath, &e.RegistryPath, &e.NetworkSource, &e.NetworkDest, &e.NetworkDestPort,
		&e.ArtifactType, &e.SourceFileID, &e.SourceReference, &e.Parser, &e.Confidence, &e.RawEvidenceID, &e.DedupHash, &extraJSON,
	)
	if err != nil {
		return model.Event{}, err
	}
	e.Timestamp = parseTime(ts)
	e.Extra = map[string]string{}
	_ = json.Unmarshal([]byte(extraJSON), &e.Extra)
	return e, nil
}

// FindEventByDedupHash looks up an existing event in caseID with the
// given DedupHash, for deduplicating a newly-parsed event against
// everything already in the case (across every collection). Returns
// found=false, not an error, when there's no match.
func (s *Store) FindEventByDedupHash(caseID, hash string) (model.Event, bool, error) {
	if hash == "" {
		return model.Event{}, false, nil
	}
	row := s.db.QueryRow(`SELECT `+eventCols+` FROM events WHERE case_id = ? AND dedup_hash = ? LIMIT 1`, caseID, hash)
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
func (s *Store) DeleteRawEvidenceBySourceFile(sourceFileID string) error {
	_, err := s.db.Exec(`DELETE FROM raw_evidence WHERE source_file_id = ?`, sourceFileID)
	return err
}

// ---------- Event observations ----------

func (s *Store) SaveEventObservations(observations []model.EventObservation) error {
	tx, err := s.db.Begin()
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

	if _, err := tx.Exec(`DELETE FROM findings WHERE case_id = ?`, caseID); err != nil {
		return fmt.Errorf("clearing prior findings: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM correlations WHERE case_id = ?`, caseID); err != nil {
		return fmt.Errorf("clearing prior correlations: %w", err)
	}

	findingStmt, err := tx.Prepare(`INSERT INTO findings
		(id, case_id, rule_id, title, severity, confidence, description, supporting_events_json, techniques_json, first_seen, last_seen, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer findingStmt.Close()
	for _, f := range findings {
		supJSON, _ := json.Marshal(f.SupportingEvents)
		techJSON, _ := json.Marshal(f.Techniques)
		if _, err := findingStmt.Exec(f.ID, f.CaseID, f.RuleID, f.Title, f.Severity, f.Confidence, f.Description,
			string(supJSON), string(techJSON), fmtTime(f.FirstSeen), fmtTime(f.LastSeen), fmtTime(f.CreatedAt)); err != nil {
			return fmt.Errorf("saving finding: %w", err)
		}
	}

	corrStmt, err := tx.Prepare(`INSERT INTO correlations
		(id, case_id, type, title, description, event_ids_json, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer corrStmt.Close()
	for _, c := range correlations {
		idsJSON, _ := json.Marshal(c.EventIDs)
		if _, err := corrStmt.Exec(c.ID, c.CaseID, c.Type, c.Title, c.Description, string(idsJSON), fmtTime(c.FirstSeen), fmtTime(c.LastSeen)); err != nil {
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
		&supJSON, &techJSON, &first, &last, &created)
	if err != nil {
		return model.Finding{}, err
	}
	_ = json.Unmarshal([]byte(supJSON), &f.SupportingEvents)
	_ = json.Unmarshal([]byte(techJSON), &f.Techniques)
	f.FirstSeen, f.LastSeen, f.CreatedAt = parseTime(first), parseTime(last), parseTime(created)
	return f, nil
}

const findingCols = `id, case_id, rule_id, title, severity, confidence, description, supporting_events_json, techniques_json, first_seen, last_seen, created_at`

func (s *Store) ListFindings(caseID string) ([]model.Finding, error) {
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

func (s *Store) ListCorrelations(caseID string) ([]model.Correlation, error) {
	rows, err := s.db.Query(`SELECT id, case_id, type, title, description, event_ids_json, first_seen, last_seen
		FROM correlations WHERE case_id = ? ORDER BY first_seen ASC`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.Correlation
	for rows.Next() {
		var c model.Correlation
		var idsJSON, first, last string
		if err := rows.Scan(&c.ID, &c.CaseID, &c.Type, &c.Title, &c.Description, &idsJSON, &first, &last); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(idsJSON), &c.EventIDs)
		c.FirstSeen, c.LastSeen = parseTime(first), parseTime(last)
		out = append(out, c)
	}
	return out, rows.Err()
}

// ---------- Case deletion ----------

// DeleteCase permanently removes a case and every row anywhere in the
// database that belongs to it -- collections, source files, raw
// evidence, events, event observations, findings, correlations, and
// finally the case row itself -- in dependency order, inside one
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
func (s *Store) DeleteCase(caseID string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
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
		`DELETE FROM cases WHERE id = ?`,
	}
	for _, stmt := range stmts {
		if _, err := tx.Exec(stmt, caseID); err != nil {
			return fmt.Errorf("%s: %w", stmt, err)
		}
	}
	return tx.Commit()
}
