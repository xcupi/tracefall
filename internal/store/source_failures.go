package store

import "tracefall/internal/model"

// FailedSourceFileIDs is source metadata only, not events or raw evidence. It
// includes failures with historical partial rows: RetryFailedSource remains the
// atomic no-prior-evidence admission guard for any explicit retry.
func (s *Store) FailedSourceFileIDs(collectionID string) ([]string, error) {
	rows, err := s.db.Query(`SELECT id FROM source_files WHERE collection_id = ? AND import_status = ? AND deleted_at = '' ORDER BY id`, collectionID, model.SourceFileFailed)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Store) CountFailedSourceFiles(collectionID string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT count(*) FROM source_files WHERE collection_id = ? AND import_status = ? AND deleted_at = ''`, collectionID, model.SourceFileFailed).Scan(&n)
	return n, err
}
