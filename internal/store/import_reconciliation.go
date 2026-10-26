package store

import (
	"time"
	"tracefall/internal/model"
)

// ReconcileCollectionImports repairs the post-source-commit checkpoint even
// when this attempt imports nothing. Rollup and analysis invalidation commit
// together: a crash cannot consume the dirty rollup without staling analysis.
// An already reconciled collection is a no-op, preserving later analysis.
func (s *Store) ReconcileCollectionImports(caseID, collectionID string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var status string
	var oldFiles, oldSupported, oldUnsupported, oldImported, oldEvents int
	if err := tx.QueryRow(`SELECT ingestion_status,file_count,supported_file_count,unsupported_file_count,imported_file_count,parsed_event_count FROM collections WHERE id=? AND case_id=?`, collectionID, caseID).Scan(&status, &oldFiles, &oldSupported, &oldUnsupported, &oldImported, &oldEvents); err != nil {
		return err
	}
	var files, supported, imported, events int
	if err := tx.QueryRow(`SELECT count(*),coalesce(sum(supported != 0),0),coalesce(sum(import_status = ?),0),coalesce(sum(CASE WHEN import_status = ? THEN event_count ELSE 0 END),0) FROM source_files WHERE collection_id=? AND case_id=? AND deleted_at=''`, model.SourceFileImported, model.SourceFileImported, collectionID, caseID).Scan(&files, &supported, &imported, &events); err != nil {
		return err
	}
	next := status
	if imported > 0 && status != model.CollectionStatusFailed {
		next = model.CollectionStatusIngested
	}
	if oldFiles == files && oldSupported == supported && oldUnsupported == files-supported && oldImported == imported && oldEvents == events && status == next {
		return nil
	}
	if _, err := tx.Exec(`UPDATE collections SET ingestion_status=?,file_count=?,supported_file_count=?,unsupported_file_count=?,imported_file_count=?,parsed_event_count=? WHERE id=? AND case_id=?`, next, files, supported, files-supported, imported, events, collectionID, caseID); err != nil {
		return err
	}
	if imported > 0 {
		if _, err := tx.Exec(`UPDATE cases SET status=?,updated_at=? WHERE id=?`, model.CaseStatusIngested, fmtTime(time.Now()), caseID); err != nil {
			return err
		}
	}
	return tx.Commit()
}
