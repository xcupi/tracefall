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

func (s *Store) CreateCase(c model.Case) error {
	_, err := s.db.Exec(
		`INSERT INTO cases (id, name, description, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		c.ID, c.Name, c.Description, c.Status, fmtTime(c.CreatedAt), fmtTime(c.UpdatedAt),
	)
	return err
}

func (s *Store) UpdateCaseStatus(id, status string) error {
	_, err := s.db.Exec(`UPDATE cases SET status = ?, updated_at = ? WHERE id = ?`,
		status, fmtTime(time.Now()), id)
	return err
}

func (s *Store) GetCase(id string) (model.Case, error) {
	row := s.db.QueryRow(`SELECT id, name, description, status, created_at, updated_at FROM cases WHERE id = ?`, id)
	var c model.Case
	var created, updated string
	if err := row.Scan(&c.ID, &c.Name, &c.Description, &c.Status, &created, &updated); err != nil {
		return model.Case{}, err
	}
	c.CreatedAt, c.UpdatedAt = parseTime(created), parseTime(updated)
	return c, nil
}

func (s *Store) ListCases() ([]model.Case, error) {
	rows, err := s.db.Query(`SELECT id, name, description, status, created_at, updated_at FROM cases ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.Case
	for rows.Next() {
		var c model.Case
		var created, updated string
		if err := rows.Scan(&c.ID, &c.Name, &c.Description, &c.Status, &created, &updated); err != nil {
			return nil, err
		}
		c.CreatedAt, c.UpdatedAt = parseTime(created), parseTime(updated)
		out = append(out, c)
	}
	return out, rows.Err()
}

// ---------- Collections ----------

const collectionCols = `id, case_id, created_at, source_type, original_filename, archive_hash, evidence_directory, ingestion_status, file_count, supported_file_count, unsupported_file_count, parsed_event_count`

func scanCollection(row interface{ Scan(...any) error }) (model.Collection, error) {
	var c model.Collection
	var createdAt string
	err := row.Scan(&c.ID, &c.CaseID, &createdAt, &c.SourceType, &c.OriginalFilename, &c.ArchiveHash,
		&c.EvidenceDirectory, &c.IngestionStatus, &c.FileCount, &c.SupportedFileCount, &c.UnsupportedFileCount, &c.ParsedEventCount)
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
	_, err := s.db.Exec(`INSERT INTO collections (`+collectionCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.CaseID, fmtTime(c.CreatedAt), c.SourceType, c.OriginalFilename, c.ArchiveHash,
		c.EvidenceDirectory, c.IngestionStatus, c.FileCount, c.SupportedFileCount, c.UnsupportedFileCount, c.ParsedEventCount)
	if isUniqueConstraintViolation(err) {
		return ErrDuplicateCollection
	}
	return err
}

// UpdateCollection overwrites a collection's mutable fields (status and
// counts) once ingestion of it has finished (successfully or not).
func (s *Store) UpdateCollection(c model.Collection) error {
	_, err := s.db.Exec(`UPDATE collections SET ingestion_status = ?, file_count = ?, supported_file_count = ?,
		unsupported_file_count = ?, parsed_event_count = ? WHERE id = ?`,
		c.IngestionStatus, c.FileCount, c.SupportedFileCount, c.UnsupportedFileCount, c.ParsedEventCount, c.ID)
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

	var out []model.Collection
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

func (s *Store) SaveSourceFiles(files []model.SourceFile) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT INTO source_files
		(id, case_id, collection_id, path, artifact_type, parser, row_count, sha256, ingested_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, f := range files {
		if _, err := stmt.Exec(f.ID, f.CaseID, f.CollectionID, f.Path, f.ArtifactType, f.Parser, f.RowCount, f.SHA256, fmtTime(f.IngestedAt)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

const sourceFileCols = `id, case_id, collection_id, path, artifact_type, parser, row_count, sha256, ingested_at`

func scanSourceFile(row interface{ Scan(...any) error }) (model.SourceFile, error) {
	var f model.SourceFile
	var ingested string
	err := row.Scan(&f.ID, &f.CaseID, &f.CollectionID, &f.Path, &f.ArtifactType, &f.Parser, &f.RowCount, &f.SHA256, &ingested)
	if err != nil {
		return model.SourceFile{}, err
	}
	f.IngestedAt = parseTime(ingested)
	return f, nil
}

func (s *Store) ListSourceFiles(caseID string) ([]model.SourceFile, error) {
	rows, err := s.db.Query(`SELECT `+sourceFileCols+` FROM source_files WHERE case_id = ? ORDER BY path`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.SourceFile
	for rows.Next() {
		f, err := scanSourceFile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// ListSourceFilesByCollection returns just one collection's source
// files, e.g. for the collection-detail API/UI view.
func (s *Store) ListSourceFilesByCollection(collectionID string) ([]model.SourceFile, error) {
	rows, err := s.db.Query(`SELECT `+sourceFileCols+` FROM source_files WHERE collection_id = ? ORDER BY path`, collectionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.SourceFile
	for rows.Next() {
		f, err := scanSourceFile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
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
