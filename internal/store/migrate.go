package store

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"tracefall/internal/model"
)

// migrate upgrades a database created under an earlier schema version
// (before evidence collections and event deduplication existed) in
// place, so old cases remain fully readable through the current,
// collection-aware API rather than erroring or silently losing data. It
// is safe to run on every startup: each step checks whether it has
// already been applied before doing anything.
//
// This intentionally is not a general migration framework (versioned
// migration files, up/down steps, etc.) -- Tracefall has had exactly one
// schema change that needed this treatment so far, and a framework for
// one migration would be pure speculation. If a second one is ever
// needed, that's the signal to build one; see docs/data-model.md.
func migrate(db *sql.DB) error {
	if err := addColumnIfMissing(db, "source_files", "collection_id", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return fmt.Errorf("migrating source_files: %w", err)
	}
	if err := addColumnIfMissing(db, "events", "collection_id", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return fmt.Errorf("migrating events (collection_id): %w", err)
	}
	if err := addColumnIfMissing(db, "events", "dedup_hash", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return fmt.Errorf("migrating events (dedup_hash): %w", err)
	}
	// These indexes reference columns that might have just been added by
	// the ALTER TABLE calls above (on a database old enough to have
	// needed them), so they can't live in the static schema string --
	// see schema.go's comments by idx_source_files_collection and
	// idx_events_case_dedup.
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_source_files_collection ON source_files(collection_id)`); err != nil {
		return fmt.Errorf("creating source_files collection index: %w", err)
	}
	// (collection_id, path) matches ListSourceFilesByCollection's WHERE
	// and ORDER BY together, so a collection's catalog is read out
	// already ordered.
	//
	// Phase 10B pages that catalog on the server, which means the query
	// runs on every page navigation rather than once per discovery. With
	// only the collection_id index, SQLite found the rows by index and
	// then SORTED them -- 56ms for a 7,074-file collection, on the single
	// write connection, every page. Ordering by index instead removes the
	// sort entirely. Purely additive: no column, statement or result
	// order changes.
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_source_files_collection_path ON source_files(collection_id, path)`); err != nil {
		return fmt.Errorf("creating source_files collection/path index: %w", err)
	}
	// Per-collection event queries (CollectionDetail's summary, and the
	// collection's event list) filter on events.collection_id. Without this
	// index every such query scans the whole events table; on a 363k-event
	// disk image that was the bulk of an 11-second collection detail. It
	// references a column the ALTER above may have just added, so it lives
	// here and not in the static schema (see the note by idx_events_case).
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_events_collection ON events(collection_id)`); err != nil {
		return fmt.Errorf("creating events collection index: %w", err)
	}
	// Streaming one collection's events page by page (pageEvents) orders by
	// (timestamp, id) within the collection; without this index each page
	// would sort the whole collection again.
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_events_collection_ts_id ON events(collection_id, timestamp, id)`); err != nil {
		return fmt.Errorf("creating events collection timeline index: %w", err)
	}
	// Phase 12 bootstrap refinement: gate an account behind a mandatory
	// password change. Existing accounts default to 0 -- a deployment
	// that already has users has already chosen their passwords, and
	// forcing every one of them to change on upgrade would be a
	// disruption this column does not need to cause.
	if err := addColumnIfMissing(db, "users", "must_change_password", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return fmt.Errorf("migrating users (must_change_password): %w", err)
	}
	// Phase 11: attribute a finding to the analysis run that produced it.
	// Added as a nullable-by-default column so every existing finding
	// keeps an EMPTY run id -- which is the honest answer for a finding
	// written before runs were recorded. Nothing is backfilled: inventing
	// a run id for a historical finding would fabricate provenance.
	if err := addColumnIfMissing(db, "findings", "analysis_run_id", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return fmt.Errorf("migrating findings (analysis_run_id): %w", err)
	}
	// Correlations gain the same run linkage findings already carry, so
	// an invalidated run's correlations can be excluded from current
	// results by the same rule. Existing rows keep an empty value and
	// are treated as legacy -- see Store.ListCorrelations.
	if err := addColumnIfMissing(db, "correlations", "analysis_run_id", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return fmt.Errorf("migrating correlations (analysis_run_id): %w", err)
	}
	// An analysis run can now be invalidated: its results stop being
	// current when the evidence they describe is deleted. Both columns
	// default to empty, which reads as "still current" for every run
	// recorded before the lifecycle existed.
	if err := addColumnIfMissing(db, "analysis_runs", "invalidated_at", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return fmt.Errorf("migrating analysis_runs (invalidated_at): %w", err)
	}
	if err := addColumnIfMissing(db, "analysis_runs", "invalidation_reason", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return fmt.Errorf("migrating analysis_runs (invalidation_reason): %w", err)
	}
	// Host time zone from the SYSTEM hive (internal/timezone). Empty until a
	// collection's import resolves it.
	for _, col := range []struct{ name, def string }{
		{"tz_recorded", "INTEGER NOT NULL DEFAULT 0"},
		{"tz_key_name", "TEXT NOT NULL DEFAULT ''"},
		{"tz_active_bias_minutes", "INTEGER NOT NULL DEFAULT 0"},
		{"tz_value_used", "TEXT NOT NULL DEFAULT ''"},
		{"tz_control_set", "TEXT NOT NULL DEFAULT ''"},
		{"tz_source", "TEXT NOT NULL DEFAULT ''"},
		{"tz_reason", "TEXT NOT NULL DEFAULT ''"},
	} {
		if err := addColumnIfMissing(db, "collections", col.name, col.def); err != nil {
			return fmt.Errorf("migrating collections (%s): %w", col.name, err)
		}
	}
	// Audit hash chain. A row written before the chain existed has an empty
	// entry_hash; VerifyAuditChain reports those as unchained, never as valid.
	if err := addColumnIfMissing(db, "audit_log", "prev_hash", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return fmt.Errorf("migrating audit_log (prev_hash): %w", err)
	}
	if err := addColumnIfMissing(db, "audit_log", "entry_hash", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return fmt.Errorf("migrating audit_log (entry_hash): %w", err)
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_events_case_dedup ON events(case_id, dedup_hash)`); err != nil {
		return fmt.Errorf("creating events dedup index: %w", err)
	}
	// Phase 14: idx_events_case_ts (case_id, timestamp) is now a strict
	// PREFIX of idx_events_case_ts_id (case_id, timestamp, id), which
	// schema.go creates. Keeping both would make every event insert
	// maintain two B-trees to answer one question, so the superseded one
	// is dropped here rather than left behind.
	//
	// Dropping an index is safe in a way that dropping a column is not:
	// no data lives in it, every query that used it is served by the
	// wider index, and re-running this on a database that has already
	// been migrated is a no-op. Deliberately the only DROP in this file.
	if _, err := db.Exec(`DROP INDEX IF EXISTS idx_events_case_ts`); err != nil {
		return fmt.Errorf("dropping superseded events timestamp index: %w", err)
	}
	if err := backfillLegacyCollections(db); err != nil {
		return fmt.Errorf("backfilling legacy collections: %w", err)
	}
	if err := backfillDedupHashes(db); err != nil {
		return fmt.Errorf("backfilling dedup hashes: %w", err)
	}
	if err := enforceCaseNameUniqueness(db); err != nil {
		return fmt.Errorf("enforcing case name uniqueness: %w", err)
	}
	if err := migrateSourceFilesToEvidenceModel(db); err != nil {
		return fmt.Errorf("migrating source_files to the evidence file model: %w", err)
	}
	if err := addColumnIfMissing(db, "collections", "imported_file_count", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return fmt.Errorf("migrating collections (imported_file_count): %w", err)
	}
	// Every pre-existing collection was ingested under the old
	// one-shot-import model, where every supported file discovered was
	// always immediately imported -- so its imported count is simply its
	// existing supported count. Only rows that still have the pre-upgrade
	// default (0) are touched, so this stays idempotent and never
	// overwrites a real imported_file_count computed by the current code.
	if _, err := db.Exec(`UPDATE collections SET imported_file_count = supported_file_count WHERE imported_file_count = 0 AND supported_file_count > 0`); err != nil {
		return fmt.Errorf("backfilling collections.imported_file_count: %w", err)
	}
	// Phase 6: analyst-workflow case fields. Existing cases default to
	// "open"/"medium" (the same defaults schema.go gives a freshly
	// created case) and an empty analyzed_at, which Service.GetCase's
	// JSON omits (omitempty) exactly as it would for a case that has
	// genuinely never been analyzed -- an old case that WAS analyzed
	// before this column existed simply can't have that historical
	// timestamp recovered, so it is deliberately left blank rather than
	// guessed at (e.g. backfilled from updated_at, which is touched by
	// far more than just analysis).
	if err := addColumnIfMissing(db, "cases", "case_status", "TEXT NOT NULL DEFAULT 'open'"); err != nil {
		return fmt.Errorf("migrating cases (case_status): %w", err)
	}
	if err := addColumnIfMissing(db, "cases", "priority", "TEXT NOT NULL DEFAULT 'medium'"); err != nil {
		return fmt.Errorf("migrating cases (priority): %w", err)
	}
	if err := addColumnIfMissing(db, "cases", "analyzed_at", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return fmt.Errorf("migrating cases (analyzed_at): %w", err)
	}
	// Phase 7: AD1 ingestion. Existing source_files rows (none of them
	// AD1-sourced, since this column didn't exist before Phase 7) default
	// to '' -- "no embedded hash reported," which is accurate: nothing
	// pre-Phase-7 ever had one.
	if err := addColumnIfMissing(db, "source_files", "embedded_hash", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return fmt.Errorf("migrating source_files (embedded_hash): %w", err)
	}
	// Phase 10A: forensic integrity hash on the evidence collection.
	// Existing collections predate it and get '' -- honestly "not
	// recorded" rather than a hash computed later over evidence that may
	// since have been extracted, which would not be integrity evidence.
	if err := addColumnIfMissing(db, "collections", "integrity_sha512", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return fmt.Errorf("migrating collections (integrity_sha512): %w", err)
	}
	// Must come last: it rebuilds source_files, so everything above that
	// reads or writes the retired columns has to have run already.
	if err := retireLegacySourceFileColumns(db); err != nil {
		return fmt.Errorf("retiring legacy source_files columns: %w", err)
	}
	return nil
}

// retireLegacySourceFileColumns rebuilds source_files without row_count
// and ingested_at, the two Phase 1 columns the evidence file model
// replaced (with event_count and discovered_at/imported_at).
//
// Every other migration in this file ADDS a column, which SQLite does
// with a cheap ALTER TABLE. These two need REMOVING, and that is the
// difference that made this necessary: both were declared NOT NULL with
// no DEFAULT, and the current INSERT (see store.go's sourceFileCols)
// does not list them, because on a database created by the current
// schema they do not exist. On an upgraded database they very much do,
// so every INSERT failed:
//
//	NOT NULL constraint failed: source_files.row_count
//
// which surfaced as a 500 on "Add Evidence" -- discovery could catalog
// the evidence but never commit it, so an upgraded install could not add
// evidence at all. backfillSourceFileEvidenceMetadata had already copied
// the DATA out of these columns years-equivalent earlier; what it could
// not do is retire the columns themselves, because SQLite has no DROP
// COLUMN in the version this project targets. Rebuilding the table is
// the supported way to do it.
//
// Idempotent, like the rest of this file: on a database that never had
// the legacy columns (anything created by the current schema) this is a
// no-op. Foreign keys are still off here -- Open turns them on only
// after migrate returns -- which is exactly the condition SQLite's
// table-rebuild procedure requires.
func retireLegacySourceFileColumns(db *sql.DB) error {
	legacy, err := hasAnyColumn(db, "source_files", "row_count", "ingested_at")
	if err != nil {
		return err
	}
	if !legacy {
		return nil // already canonical
	}

	// The rebuilt table's definition is deliberately identical to
	// schema.go's source_files, minus nothing and plus nothing --
	// TestMigrate_RebuiltSourceFilesMatchesFreshSchema compares the two
	// so this can never silently drift out of step with it.
	const canonical = `CREATE TABLE source_files_rebuilt (
	id                TEXT PRIMARY KEY,
	case_id           TEXT NOT NULL REFERENCES cases(id),
	collection_id     TEXT NOT NULL REFERENCES collections(id),
	original_filename TEXT NOT NULL DEFAULT '',
	path              TEXT NOT NULL,
	artifact_type     TEXT NOT NULL DEFAULT '',
	parser            TEXT NOT NULL DEFAULT '',
	supported         INTEGER NOT NULL DEFAULT 0,
	size_bytes        INTEGER NOT NULL DEFAULT 0,
	sha256            TEXT NOT NULL DEFAULT '',
	embedded_hash     TEXT NOT NULL DEFAULT '',
	import_status     TEXT NOT NULL DEFAULT 'discovered',
	event_count       INTEGER NOT NULL DEFAULT 0,
	discovered_at     TEXT NOT NULL,
	imported_at       TEXT NOT NULL DEFAULT '',
	deleted_at        TEXT NOT NULL DEFAULT ''
)`

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(canonical); err != nil {
		return fmt.Errorf("creating rebuilt table: %w", err)
	}
	// Column-for-column copy, no transformation: the data was already
	// migrated into these columns by backfillSourceFileEvidenceMetadata.
	// discovered_at is NOT NULL with no default, so a row that somehow
	// never got one becomes '' rather than failing the whole upgrade --
	// the same "empty means unset" convention the rest of the schema
	// uses, and the alternative would be refusing to start.
	if _, err := tx.Exec(`INSERT INTO source_files_rebuilt (` + sourceFileCols + `)
		SELECT id, case_id, collection_id, original_filename, path, artifact_type, parser,
		       supported, size_bytes, sha256, embedded_hash, import_status, event_count,
		       IFNULL(discovered_at, ''), IFNULL(imported_at, ''), IFNULL(deleted_at, '')
		FROM source_files`); err != nil {
		return fmt.Errorf("copying source files: %w", err)
	}
	if _, err := tx.Exec(`DROP TABLE source_files`); err != nil {
		return fmt.Errorf("dropping legacy table: %w", err)
	}
	if _, err := tx.Exec(`ALTER TABLE source_files_rebuilt RENAME TO source_files`); err != nil {
		return fmt.Errorf("renaming rebuilt table: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	// DROP TABLE took every index on the old table with it, so all three
	// are recreated here -- including the per-collection uniqueness index
	// whose conflict pre-check (enforceSourceFileUniquenessPerCollection)
	// has already run and passed against this same data.
	for _, stmt := range []string{
		`CREATE INDEX IF NOT EXISTS idx_source_files_case ON source_files(case_id)`,
		`CREATE INDEX IF NOT EXISTS idx_source_files_collection ON source_files(collection_id)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_source_files_collection_sha256_active
			ON source_files(collection_id, sha256) WHERE import_status = 'imported' AND deleted_at = ''`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("recreating source_files index: %w", err)
		}
	}
	return nil
}

// hasAnyColumn reports whether table has at least one of the named columns.
func hasAnyColumn(db *sql.DB, table string, columns ...string) (bool, error) {
	for _, c := range columns {
		exists, err := columnExists(db, table, c)
		if err != nil {
			return false, err
		}
		if exists {
			return true, nil
		}
	}
	return false, nil
}

// migrateSourceFilesToEvidenceModel adds the columns the evidence file
// model (discover -> select -> import, individual file deletion --
// see internal/model.SourceFile) needs beyond what Phase 1 had, backfills
// them for any pre-existing row, and creates the file-level duplicate
// index. Every step is idempotent, like the rest of this file.
func migrateSourceFilesToEvidenceModel(db *sql.DB) error {
	newColumns := []struct{ name, definition string }{
		{"original_filename", "TEXT NOT NULL DEFAULT ''"},
		{"supported", "INTEGER NOT NULL DEFAULT 0"},
		{"size_bytes", "INTEGER NOT NULL DEFAULT 0"},
		{"import_status", "TEXT NOT NULL DEFAULT ''"},
		{"event_count", "INTEGER NOT NULL DEFAULT 0"},
		{"discovered_at", "TEXT NOT NULL DEFAULT ''"},
		{"imported_at", "TEXT NOT NULL DEFAULT ''"},
		{"deleted_at", "TEXT NOT NULL DEFAULT ''"},
	}
	for _, c := range newColumns {
		if err := addColumnIfMissing(db, "source_files", c.name, c.definition); err != nil {
			return fmt.Errorf("adding %s: %w", c.name, err)
		}
	}

	if err := backfillSourceFileEvidenceMetadata(db); err != nil {
		return fmt.Errorf("backfilling evidence metadata: %w", err)
	}

	// File-level duplicate protection is deliberately scoped to one
	// collection (collection_id, sha256), not the whole case -- unlike
	// idx_collections_case_archive_hash and idx_cases_name_unique, the
	// same file legitimately reappears across *different* collections in
	// the same case all the time (e.g. Security.csv re-collected in a
	// follow-up KAPE triage hours later): that is exactly what
	// event-level DedupHash/EventObservation exists to handle, and this
	// index must not block it -- see docs/data-model.md's "Evidence file
	// model" section. Within a single collection, though, the same file
	// content appearing twice would mean something actually went wrong
	// (e.g. a retried import), so it's still worth guarding at the
	// database level, race-safely, the same way collection- and
	// case-level duplicates already are.
	if err := enforceSourceFileUniquenessPerCollection(db); err != nil {
		return fmt.Errorf("enforcing per-collection file uniqueness: %w", err)
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_source_files_collection ON source_files(collection_id)`); err != nil {
		return fmt.Errorf("creating source_files collection index: %w", err)
	}
	return nil
}

// backfillSourceFileEvidenceMetadata fills in the new evidence-file
// columns for any row that predates them (import_status = ”), from the
// data that already exists on that row: every pre-existing source_files
// row represents a file that was already fully imported under the old
// one-shot ingest model, so it becomes ImportStatus=imported,
// Supported=true, EventCount from the old row_count column, and
// discovered_at/imported_at from the old ingested_at timestamp.
// original_filename is derived from path since it was never stored
// separately before.
func backfillSourceFileEvidenceMetadata(db *sql.DB) error {
	hasOldColumns, err := columnExists(db, "source_files", "row_count")
	if err != nil {
		return err
	}
	if !hasOldColumns {
		return nil // fresh database: nothing predates the evidence file model
	}

	rows, err := db.Query(`SELECT id, path, row_count, ingested_at FROM source_files WHERE import_status = ''`)
	if err != nil {
		return err
	}
	type pending struct {
		id, filename, timestamp string
		eventCount              int
	}
	var updates []pending
	for rows.Next() {
		var id, path, ingestedAt string
		var rowCount int
		if err := rows.Scan(&id, &path, &rowCount, &ingestedAt); err != nil {
			rows.Close()
			return err
		}
		updates = append(updates, pending{id: id, filename: filepath.Base(path), timestamp: ingestedAt, eventCount: rowCount})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(updates) == 0 {
		return nil
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`UPDATE source_files SET
		original_filename = ?, supported = 1, import_status = ?, event_count = ?,
		discovered_at = ?, imported_at = ? WHERE id = ?`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, u := range updates {
		if _, err := stmt.Exec(u.filename, model.SourceFileImported, u.eventCount, u.timestamp, u.timestamp, u.id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// enforceSourceFileUniquenessPerCollection creates
// idx_source_files_collection_sha256_active after first checking that no
// existing (collection_id, sha256) pair among already-imported,
// non-deleted files would violate it -- the same safe-migration pattern
// enforceCaseNameUniqueness uses: refuse to silently proceed, report
// exactly which files collide, and let a human resolve it (the
// duplicate, if genuine, can simply be deleted through the normal
// evidence-deletion flow once Tracefall is back up) rather than picking
// one to delete automatically.
func enforceSourceFileUniquenessPerCollection(db *sql.DB) error {
	rows, err := db.Query(`
		SELECT collection_id, sha256, COUNT(*), GROUP_CONCAT(id, ', ')
		FROM source_files
		WHERE import_status = ? AND deleted_at = '' AND sha256 != ''
		GROUP BY collection_id, sha256
		HAVING COUNT(*) > 1`, model.SourceFileImported)
	if err != nil {
		return err
	}
	var conflicts []string
	for rows.Next() {
		var collectionID, sha string
		var count int
		var ids string
		if err := rows.Scan(&collectionID, &sha, &count, &ids); err != nil {
			rows.Close()
			return err
		}
		conflicts = append(conflicts, fmt.Sprintf("collection %s: sha256 %s is shared by %d files (ids: %s)", collectionID, sha, count, ids))
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(conflicts) > 0 {
		return fmt.Errorf(
			"%d duplicate evidence file(s) already exist within a single collection, so per-collection uniqueness cannot be enforced automatically -- "+
				"%s -- delete the duplicate file(s) by hand once Tracefall is running and restart "+
				"(Tracefall will not delete evidence automatically)",
			len(conflicts), strings.Join(conflicts, "; "))
	}

	_, err = db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_source_files_collection_sha256_active
		ON source_files(collection_id, sha256) WHERE import_status = 'imported' AND deleted_at = ''`)
	return err
}

func columnExists(db *sql.DB, table, column string) (bool, error) {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

func addColumnIfMissing(db *sql.DB, table, column, definition string) error {
	exists, err := columnExists(db, table, column)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	_, err = db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, definition))
	return err
}

// backfillLegacyCollections synthesizes one Collection (source_type
// "legacy") per case that has source_files/events predating collections
// (collection_id == ""), and points that evidence at it. Without this,
// pre-collection evidence would have no collection_id at all and
// couldn't be listed, displayed with a provenance label, or included in
// per-collection API responses.
func backfillLegacyCollections(db *sql.DB) error {
	rows, err := db.Query(`SELECT DISTINCT case_id FROM source_files WHERE collection_id = ''`)
	if err != nil {
		return err
	}
	var caseIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		caseIDs = append(caseIDs, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	for _, caseID := range caseIDs {
		if err := backfillLegacyCollectionForCase(db, caseID); err != nil {
			return err
		}
	}
	return nil
}

func backfillLegacyCollectionForCase(db *sql.DB, caseID string) error {
	var already int
	if err := db.QueryRow(`SELECT COUNT(*) FROM collections WHERE case_id = ? AND source_type = ?`,
		caseID, model.SourceTypeLegacy).Scan(&already); err != nil {
		return err
	}
	if already > 0 {
		return nil // already migrated in a previous Open()
	}

	var fileCount int
	var earliest sql.NullString
	if err := db.QueryRow(`SELECT COUNT(*), MIN(ingested_at) FROM source_files WHERE case_id = ? AND collection_id = ''`,
		caseID).Scan(&fileCount, &earliest); err != nil {
		return err
	}
	var eventCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE case_id = ? AND collection_id = ''`,
		caseID).Scan(&eventCount); err != nil {
		return err
	}

	createdAt := time.Now().UTC()
	if earliest.Valid {
		if t, err := time.Parse(timeLayout, earliest.String); err == nil {
			createdAt = t
		}
	}

	collectionID := uuid.NewString()
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec(`INSERT INTO collections
		(id, case_id, created_at, source_type, original_filename, archive_hash, evidence_directory, ingestion_status, file_count, supported_file_count, unsupported_file_count, parsed_event_count)
		VALUES (?, ?, ?, ?, '', '', '', ?, ?, ?, 0, ?)`,
		collectionID, caseID, fmtTime(createdAt), model.SourceTypeLegacy, model.CollectionStatusIngested,
		fileCount, fileCount, eventCount)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE source_files SET collection_id = ? WHERE case_id = ? AND collection_id = ''`, collectionID, caseID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE events SET collection_id = ? WHERE case_id = ? AND collection_id = ''`, collectionID, caseID); err != nil {
		return err
	}
	return tx.Commit()
}

// backfillDedupHashes computes and stores DedupHash for any event row
// that doesn't have one yet (pre-dedup legacy rows, or rows from a
// version of the schema that had the column but not this backfill).
// Events already stored as separate rows before deduplication existed
// are not retroactively merged -- only their hash is filled in, so
// deduplication works correctly going forward when a new collection is
// added to an old case.
func backfillDedupHashes(db *sql.DB) error {
	rows, err := db.Query(`SELECT ` + eventCols + ` FROM events WHERE dedup_hash = ''`)
	if err != nil {
		return err
	}
	type pending struct{ id, hash string }
	var updates []pending
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			rows.Close()
			return err
		}
		updates = append(updates, pending{id: e.ID, hash: e.ComputeDedupHash()})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(updates) == 0 {
		return nil
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`UPDATE events SET dedup_hash = ? WHERE id = ?`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, u := range updates {
		if _, err := stmt.Exec(u.hash, u.id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// enforceCaseNameUniqueness creates the case-insensitive,
// whitespace-trimmed unique index on cases.name (idx_cases_name_unique),
// after first checking that no existing data would violate it. It can't
// live in the static schema (like idx_collections_case_archive_hash
// does) because a database from before this constraint existed might
// already contain two cases with the same name -- and unlike the other
// migrations in this file, there is no safe automatic fix: silently
// deleting or merging either case would destroy investigation data, and
// silently renaming one would be an unrequested, opinionated change to
// case identity. So this refuses to create the index (and, since
// Open()/migrate() propagate the error, refuses to let Tracefall start)
// and instead reports exactly which case names collide, leaving a human
// to resolve it by hand (e.g. renaming one of the cases) before
// restarting. See docs/data-model.md's "Case name uniqueness" section.
func enforceCaseNameUniqueness(db *sql.DB) error {
	rows, err := db.Query(`
		SELECT LOWER(TRIM(name)), COUNT(*), GROUP_CONCAT(id, ', ')
		FROM cases
		GROUP BY LOWER(TRIM(name))
		HAVING COUNT(*) > 1`)
	if err != nil {
		return err
	}
	var conflicts []string
	for rows.Next() {
		var norm, ids string
		var count int
		if err := rows.Scan(&norm, &count, &ids); err != nil {
			rows.Close()
			return err
		}
		conflicts = append(conflicts, fmt.Sprintf("%q is used by %d cases (ids: %s)", norm, count, ids))
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(conflicts) > 0 {
		return fmt.Errorf(
			"%d duplicate case name(s) already exist, so uniqueness cannot be enforced automatically -- "+
				"%s -- case names are compared trimmed of whitespace and case-insensitively; "+
				"rename the conflicting case(s) by hand and restart Tracefall "+
				"(Tracefall will not delete or merge cases automatically)",
			len(conflicts), strings.Join(conflicts, "; "))
	}

	_, err = db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_cases_name_unique ON cases (LOWER(TRIM(name)))`)
	return err
}
