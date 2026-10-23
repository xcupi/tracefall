package store

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"tracefall/internal/model"
)

// UpsertEnrichment stores one answer, replacing an earlier answer for the same
// indicator in the same case.
func (s *Store) UpsertEnrichment(e model.Enrichment) error {
	ids, err := json.Marshal(e.SourceEventIDs)
	if err != nil {
		return err
	}
	if e.ResultJSON == "" {
		e.ResultJSON = "{}"
	}
	_, err = s.db.Exec(`INSERT INTO enrichments (id, case_id, provider, indicator_type, indicator, status, result_json, error, fetched_at, source_event_ids)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(case_id, provider, indicator) DO UPDATE SET
			indicator_type = excluded.indicator_type, status = excluded.status, result_json = excluded.result_json,
			error = excluded.error, fetched_at = excluded.fetched_at, source_event_ids = excluded.source_event_ids`,
		e.ID, e.CaseID, e.Provider, e.IndicatorType, e.Indicator, e.Status, e.ResultJSON, e.Error, fmtTime(e.FetchedAt), string(ids))
	return err
}

// ListEnrichments returns a case's answers from one provider, by indicator.
func (s *Store) ListEnrichments(caseID, provider string) ([]model.Enrichment, error) {
	rows, err := s.db.Query(`SELECT id, case_id, provider, indicator_type, indicator, status, result_json, error, fetched_at, source_event_ids
		FROM enrichments WHERE case_id = ? AND provider = ? ORDER BY indicator`, caseID, provider)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Enrichment
	for rows.Next() {
		var e model.Enrichment
		var ts, ids string
		if err := rows.Scan(&e.ID, &e.CaseID, &e.Provider, &e.IndicatorType, &e.Indicator, &e.Status, &e.ResultJSON, &e.Error, &ts, &ids); err != nil {
			return nil, err
		}
		e.FetchedAt = parseTime(ts)
		_ = json.Unmarshal([]byte(ids), &e.SourceEventIDs)
		out = append(out, e)
	}
	return out, rows.Err()
}

// CountEnrichmentRequestsSince counts answers a provider gave, across all
// cases, since t. It is how a daily request limit is kept across restarts.
func (s *Store) CountEnrichmentRequestsSince(provider string, t time.Time) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM enrichments WHERE provider = ? AND fetched_at >= ?`, provider, fmtTime(t)).Scan(&n)
	return n, err
}

// HashField is one event field that holds a value under one of the named keys.
type HashField struct {
	EventID string
	Key     string
	Value   string
}

// EventFieldsByKey returns, for a case, every event Extra field whose key is
// one of keys EXACTLY. The keys are chosen by the caller from a fixed list; a
// substring match would sweep in fields such as "ntlm_hash" or
// "sql_record_sha256" that must never be treated as file hashes.
func (s *Store) EventFieldsByKey(caseID string, keys []string) ([]HashField, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	var conds []string
	args := []any{caseID}
	for _, k := range keys {
		conds = append(conds, `extra_json LIKE ?`)
		args = append(args, `%"`+k+`":%`)
	}
	rows, err := s.db.Query(`SELECT id, extra_json FROM events WHERE case_id = ? AND (`+strings.Join(conds, " OR ")+`) ORDER BY id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	want := map[string]bool{}
	for _, k := range keys {
		want[k] = true
	}
	var out []HashField
	for rows.Next() {
		var id, raw string
		if err := rows.Scan(&id, &raw); err != nil {
			return nil, err
		}
		var m map[string]string
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			continue
		}
		ks := make([]string, 0, len(m))
		for k := range m {
			if want[k] {
				ks = append(ks, k)
			}
		}
		sort.Strings(ks)
		for _, k := range ks {
			out = append(out, HashField{EventID: id, Key: k, Value: m[k]})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("event fields: %w", err)
	}
	return out, nil
}
