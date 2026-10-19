package store

import (
	"encoding/json"
	"fmt"
	"strings"

	"tracefall/internal/model"
)

// caseEvents reads a case's events for analysis. It is the store-backed
// model.EventSource: each call returns only what was asked for.
type caseEvents struct {
	s      *Store
	caseID string
}

// EventSourceFor returns the analysis source for one case.
func (s *Store) EventSourceFor(caseID string) model.EventSource {
	return caseEvents{s: s, caseID: caseID}
}

// Load selects by event type or artifact type through the case's indexes. An
// empty filter (neither All nor any name) selects nothing.
func (c caseEvents) Load(f model.EventFilter) ([]model.Event, error) {
	if f.All {
		return c.s.ListEvents(c.caseID)
	}
	if len(f.Types) == 0 && len(f.Artifacts) == 0 {
		return nil, nil
	}
	var clauses []string
	args := []any{c.caseID}
	if len(f.Types) > 0 {
		clauses = append(clauses, "event_type IN ("+placeholders(len(f.Types))+")")
		for _, t := range f.Types {
			args = append(args, t)
		}
	}
	if len(f.Artifacts) > 0 {
		clauses = append(clauses, "artifact_type IN ("+placeholders(len(f.Artifacts))+")")
		for _, a := range f.Artifacts {
			args = append(args, a)
		}
	}
	// Ordered as ListEvents orders, so a filtered consumer sees its events in
	// the same relative order a full load would give it.
	q := `SELECT ` + eventCols + ` FROM events WHERE case_id = ? AND (` + strings.Join(clauses, " OR ") + `) ORDER BY timestamp ASC, id ASC`
	rows, err := c.s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("loading filtered events: %w", err)
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

// Refs reads every event as an EventRef. It never builds the parsed Extra
// maps, which is where most of a full event's memory goes.
func (c caseEvents) Refs() ([]model.EventRef, error) {
	rows, err := c.s.db.Query(`SELECT id, host, process_name, artifact_type, timestamp FROM events WHERE case_id = ? ORDER BY timestamp ASC, id ASC`, c.caseID)
	if err != nil {
		return nil, fmt.Errorf("loading event references: %w", err)
	}
	defer rows.Close()
	var out []model.EventRef
	for rows.Next() {
		var r model.EventRef
		var ts string
		if err := rows.Scan(&r.ID, &r.Host, &r.ProcessName, &r.ArtifactType, &ts); err != nil {
			return nil, err
		}
		r.Timestamp = parseTime(ts)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ForEachEvent calls fn for every event of the case, ordered by timestamp,
// then ID, reading one row at a time. Use it where the consumer can work
// event by event (writing a file, counting); it never holds the case.
func (s *Store) ForEachEvent(caseID string, fn func(model.Event) error) error {
	rows, err := s.db.Query(`SELECT `+eventCols+` FROM events WHERE case_id = ? ORDER BY timestamp ASC, id ASC`, caseID)
	if err != nil {
		return fmt.Errorf("streaming events: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return err
		}
		if err := fn(e); err != nil {
			return err
		}
	}
	return rows.Err()
}

// ForEachEventLazy is ForEachEvent for consumers that need the parsed Extra
// map of only some event types. The map is decoded when needExtra reports true
// for an event's type; for the other events Extra is nil. Reading and decoding
// every row's JSON was most of the allocation of an investigation pass.
func (s *Store) ForEachEventLazy(caseID string, needExtra func(eventType string) bool, fn func(model.Event) error) error {
	rows, err := s.db.Query(`SELECT `+eventCols+` FROM events WHERE case_id = ? ORDER BY timestamp ASC, id ASC`, caseID)
	if err != nil {
		return fmt.Errorf("streaming events: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		e, extraJSON, err := scanEventRaw(rows)
		if err != nil {
			return err
		}
		if needExtra(e.EventType) {
			e.Extra = map[string]string{}
			_ = json.Unmarshal([]byte(extraJSON), &e.Extra)
		}
		if err := fn(e); err != nil {
			return err
		}
	}
	return rows.Err()
}
