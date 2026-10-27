package store

import (
	"database/sql"
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

// Each uses the existing paged reader; no case-wide full-event load.
func (c caseEvents) Each(needExtra func(string) bool, fn func(model.Event) error) error {
	return c.s.ForEachEventLazy(c.caseID, needExtra, fn)
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
	where := `(` + strings.Join(clauses, " OR ") + `)`
	if len(f.Names) > 0 {
		names := f.NamesLower()
		if len(names) == 0 {
			return nil, nil // names were asked for and none is usable: select nothing
		}
		var nc []string
		for _, n := range names {
			esc := likeEscape(n)
			nc = append(nc,
				`LOWER(file_path) LIKE ? ESCAPE '\'`, `LOWER(file_path) LIKE ? ESCAPE '\'`, `LOWER(file_path) = ?`,
				`LOWER(process_path) LIKE ? ESCAPE '\'`, `LOWER(process_path) LIKE ? ESCAPE '\'`, `LOWER(process_path) = ?`,
				`LOWER(process_name) = ?`)
			// A Windows separator is a backslash, which is also the escape
			// character here, so it is written doubled to mean itself.
			args = append(args, "%/"+esc, `%\\`+esc, n, "%/"+esc, `%\\`+esc, n, n)
		}
		where += ` AND (` + strings.Join(nc, " OR ") + `)`
	}
	if len(f.Within) > 0 {
		ph := make([]string, len(f.Within))
		for i, a := range f.Within {
			ph[i] = "?"
			args = append(args, a)
		}
		where += ` AND artifact_type IN (` + strings.Join(ph, ",") + `)`
	}
	// Ordered as ListEvents orders, so a filtered consumer sees its events in
	// the same relative order a full load would give it.
	q := `SELECT ` + eventCols + ` FROM events WHERE case_id = ? AND ` + where + ` ORDER BY timestamp ASC, id ASC`
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
	rows, err := c.s.db.Query(`SELECT id, collection_id, host, process_name, artifact_type, timestamp FROM events WHERE case_id = ? ORDER BY timestamp ASC, id ASC`, c.caseID)
	if err != nil {
		return nil, fmt.Errorf("loading event references: %w", err)
	}
	defer rows.Close()
	var out []model.EventRef
	for rows.Next() {
		var r model.EventRef
		var ts string
		if err := rows.Scan(&r.ID, &r.CollectionID, &r.Host, &r.ProcessName, &r.ArtifactType, &ts); err != nil {
			return nil, err
		}
		r.Timestamp = parseTime(ts)
		out = append(out, r)
	}
	return out, rows.Err()
}

// eventPageSize is how many events one query reads. A variable so tests can
// make the pages small enough to cross.
var eventPageSize = 2000

// tapRow remembers the id and the stored timestamp text of the row scanEventRaw
// just read, which are what the next page starts after. The columns are
// eventCols', in that order; the page test fails if that order ever changes.
type tapRow struct {
	rows   *sql.Rows
	ts, id string
}

func (t *tapRow) Scan(dest ...any) error {
	if err := t.rows.Scan(dest...); err != nil {
		return err
	}
	t.id = *(dest[0].(*string))
	t.ts = *(dest[3].(*string))
	return nil
}

// pageEvents reads the events whose scopeCol equals scope, ordered by timestamp
// then id, one page of eventPageSize rows per query, and calls fn for each.
//
// Each page is read in full and its cursor closed BEFORE fn is called. The
// store has one database connection, and a cursor held open while fn writes to
// a slow client would hold it, so one download read slowly would stop every
// other request. Between pages the connection is free.
//
// The next page starts after the last (timestamp, id) of the previous one, using
// the text exactly as stored, so the order is the one ORDER BY gives. Events
// written while a stream runs may or may not be seen by it, as with any two
// queries; a consumer that needs one instant reads while the case is locked.
func (s *Store) pageEvents(scopeCol, scope string, scan func(row interface{ Scan(...any) error }) (model.Event, error), fn func(model.Event) error) error {
	var afterTS, afterID string
	started := false
	for {
		q := `SELECT ` + eventCols + ` FROM events WHERE ` + scopeCol + ` = ?`
		args := []any{scope}
		if started {
			q += ` AND (timestamp, id) > (?, ?)`
			args = append(args, afterTS, afterID)
		}
		q += ` ORDER BY timestamp ASC, id ASC LIMIT ?`
		args = append(args, eventPageSize)

		rows, err := s.db.Query(q, args...)
		if err != nil {
			return fmt.Errorf("streaming events: %w", err)
		}
		tap := &tapRow{rows: rows}
		page := make([]model.Event, 0, 256)
		for rows.Next() {
			e, err := scan(tap)
			if err != nil {
				rows.Close()
				return err
			}
			page = append(page, e)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}

		for _, e := range page {
			if err := fn(e); err != nil {
				return err
			}
		}
		if len(page) < eventPageSize {
			return nil
		}
		afterTS, afterID, started = tap.ts, tap.id, true
	}
}

// ForEachEvent calls fn for every event of the case, ordered by timestamp,
// then ID. Use it where the consumer can work event by event (writing a file,
// counting); it never holds the case, and between pages it holds nothing.
func (s *Store) ForEachEvent(caseID string, fn func(model.Event) error) error {
	return s.pageEvents("case_id", caseID, scanEvent, fn)
}

// ForEachEventInCollection is ForEachEvent for the events first observed in one
// collection, ordered the same way.
func (s *Store) ForEachEventInCollection(collectionID string, fn func(model.Event) error) error {
	return s.pageEvents("collection_id", collectionID, scanEvent, fn)
}

// ForEachEventLazy is ForEachEvent for consumers that need the parsed Extra
// map of only some event types. The map is decoded when needExtra reports true
// for an event's type; for the other events Extra is nil. Reading and decoding
// every row's JSON was most of the allocation of an investigation pass.
func (s *Store) ForEachEventLazy(caseID string, needExtra func(eventType string) bool, fn func(model.Event) error) error {
	scan := func(row interface{ Scan(...any) error }) (model.Event, error) {
		e, extraJSON, err := scanEventRaw(row)
		if err != nil {
			return model.Event{}, err
		}
		if needExtra(e.EventType) {
			e.Extra = map[string]string{}
			_ = json.Unmarshal([]byte(extraJSON), &e.Extra)
		}
		return e, nil
	}
	return s.pageEvents("case_id", caseID, scan, fn)
}

// likeEscape escapes the characters LIKE treats specially, for use with
// ESCAPE '\'.
func likeEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}
