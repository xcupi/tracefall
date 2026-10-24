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
	FrozenVT    []narrative.ReviewVT     `json:"frozen_vt,omitempty"`
	Privacy     *narrative.ReviewPrivacy `json:"privacy,omitempty"`
	Narrative   model.Narrative          `json:"narrative"`
	Coverage    narrative.ReviewCoverage `json:"coverage"`
	Fingerprint string                   `json:"source_fingerprint"`
}

// CaseReviewVT reads only the attempted single-review snapshot. Old rows without
// frozen_vt are not recorded and resolve as unavailable, never live data.
func (s *Store) CaseReviewVT(caseID, reviewID, id string) (narrative.ReviewVT, error) {
	var raw string
	if err := s.db.QueryRow(`SELECT record_json FROM case_reviews WHERE case_id=? AND id=?`, caseID, reviewID).Scan(&raw); err != nil {
		return narrative.ReviewVT{}, err
	}
	var r CaseReview
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return narrative.ReviewVT{}, err
	}
	for _, v := range r.FrozenVT {
		if v.ID == id {
			return v, nil
		}
	}
	return narrative.ReviewVT{}, sql.ErrNoRows
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
