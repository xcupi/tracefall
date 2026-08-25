package store

import (
	"database/sql"
	"fmt"
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
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_events_case_dedup ON events(case_id, dedup_hash)`); err != nil {
		return fmt.Errorf("creating events dedup index: %w", err)
	}
	if err := backfillLegacyCollections(db); err != nil {
		return fmt.Errorf("backfilling legacy collections: %w", err)
	}
	if err := backfillDedupHashes(db); err != nil {
		return fmt.Errorf("backfilling dedup hashes: %w", err)
	}
	return nil
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
