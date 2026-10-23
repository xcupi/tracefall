package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"tracefall/internal/model"
	"tracefall/internal/narrative"
)

// CaseReview is separate from legacy Summary and its report appendix.
type CaseReview struct {
	Narrative   model.Narrative          `json:"narrative"`
	Coverage    narrative.ReviewCoverage `json:"coverage"`
	Fingerprint string                   `json:"source_fingerprint"`
}

func (s *Store) SaveCaseReview(r CaseReview) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO case_reviews (id,case_id,created_at,record_json) VALUES (?,?,?,?) ON CONFLICT(id) DO UPDATE SET record_json=excluded.record_json`, r.Narrative.ID, r.Narrative.CaseID, fmtTime(r.Narrative.CreatedAt), string(b))
	return err
}
func (s *Store) LatestCaseReview(caseID string) (CaseReview, bool, error) {
	var raw string
	err := s.db.QueryRow(`SELECT record_json FROM case_reviews WHERE case_id=? ORDER BY created_at DESC,id DESC LIMIT 1`, caseID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return CaseReview{}, false, nil
	}
	if err != nil {
		return CaseReview{}, false, err
	}
	var r CaseReview
	err = json.Unmarshal([]byte(raw), &r)
	return r, err == nil, err
}
