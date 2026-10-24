package store

import (
	"encoding/json"
	"errors"
)

func (s *Store) BatchHistory(caseID string, offset, limit int) ([]json.RawMessage, int, error) {
	if offset < 0 || limit < 1 || limit > 100 {
		return nil, 0, errors.New("invalid batch history pagination")
	}
	var total int
	if err := s.db.QueryRow(`SELECT count(*) FROM review_batch_runs WHERE case_id=?`, caseID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(`SELECT record_json,state FROM review_batch_runs WHERE case_id=? ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?`, caseID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []json.RawMessage{}
	for rows.Next() {
		var raw, state string
		if err := rows.Scan(&raw, &state); err != nil {
			return nil, 0, err
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(raw), &obj); err != nil {
			return nil, 0, err
		}
		obj["state"] = state
		b, err := json.Marshal(obj)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, b)
	}
	return out, total, rows.Err()
}
