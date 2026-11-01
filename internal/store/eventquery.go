package store

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"tracefall/internal/model"
)

// Server-side forensic event search (Phase 14).
//
// # Why this exists
//
// ListEvents returns every event in a case. That was adequate while a
// case meant one KAPE triage of a handful of CSVs; it stopped being
// adequate the moment a single $MFT could contribute hundreds of
// thousands of rows. The dashboard was fetching the whole timeline and
// filtering it in JavaScript, which means the browser held the entire
// evidence set in memory, re-scanned it on every keystroke, and the
// server did a full table read to answer "show me one day in April".
//
// This file moves the question into the database, where the indexes
// are. The caller describes WHAT it wants; SearchEvents decides how to
// find it and returns exactly one page plus the true total.
//
// # The forensic constraints that shape it
//
//  1. A page is a VIEW, never a filter on what exists. Total always
//     reports every matching event, so a page boundary can never be
//     mistaken for the end of the evidence.
//
//  2. Ordering is deterministic. Paging through a non-deterministic
//     order shows one event twice and hides another -- for evidence
//     review that is a correctness bug, not a cosmetic one. Every query
//     therefore breaks ties on the primary key.
//
//  3. Every analyst-supplied value is a BOUND PARAMETER. Column and
//     direction choices come from fixed allow-lists in this file.
//     Nothing an analyst types is ever concatenated into SQL.
//
//  4. Time bounds are INSTANTS, already resolved to UTC by the caller.
//     This layer knows nothing about display timezones -- see
//     api/eventsearch.go, which is where a local calendar date is
//     turned into the pair of instants that bracket it.

// EventSort names the orderings the timeline offers. Both are total
// orders: the timestamp decides, and the id breaks ties.
type EventSort string

const (
	// EventSortTimeDesc is newest-first, the default for an
	// investigation ("what happened most recently?").
	EventSortTimeDesc EventSort = "time_desc"
	// EventSortTimeAsc is oldest-first, for reading a sequence forward.
	EventSortTimeAsc EventSort = "time_asc"
)

// orderClause maps a sort to SQL. Unknown values fall back to
// newest-first rather than being interpolated, so this can never become
// an injection point.
//
// The id tie-breaker runs in the SAME direction as the timestamp, and
// that detail is load-bearing. Either direction is equally deterministic
// -- both are total orders over (timestamp, id) -- but only a
// same-direction pair can be read straight off an ascending index:
// SQLite can walk idx_events_case_ts_id backwards to produce (timestamp
// DESC, id DESC), while a mixed (DESC, ASC) pair forces it to sort every
// matching row before returning ten. On a 200,000-event case that was
// the difference between 1.4ms and 155ms for a single page.
func (s EventSort) orderClause() string {
	if s == EventSortTimeAsc {
		return `ORDER BY timestamp ASC, id ASC`
	}
	return `ORDER BY timestamp DESC, id DESC`
}

// EventQuery describes one forensic timeline question.
//
// The zero value (with only CaseID set) means "every event in this
// case", which is what an analyst opening the timeline with no filters
// is asking for.
//
// Semantics, matching the rest of Tracefall's filtering: values WITHIN
// one OR-set are alternatives, and the separate constraints are AND'd.
// An empty set is "no constraint", never "match nothing".
type EventQuery struct {
	// CaseID scopes every query. It is required, and it is the only
	// reason an event from another case can never appear in a result --
	// see SearchEvents, which refuses an empty CaseID outright.
	CaseID string

	// Categorical OR-sets, each populated from a facet the analyst
	// picked out of a dropdown rather than typed.
	CollectionIDs []string
	ArtifactTypes []string
	EventTypes    []string
	Hosts         []string
	Users         []string
	Processes     []string

	// From/To bracket the timestamp, INCLUSIVE at both ends, as UTC
	// instants. A zero time means that end is unbounded.
	From time.Time
	To   time.Time

	// Field-scoped substring terms. Each is matched case-insensitively
	// against one documented set of columns -- see the fieldTerms table
	// below for exactly which, and docs/forensic-search.md for the
	// analyst-facing statement of the same thing.
	Filename     string
	Path         string
	URL          string
	Domain       string
	IP           string
	CommandLine  string
	OriginalPath string

	// Text is the free-text term, matched case-insensitively across the
	// documented normalized fields (freeTextColumns / freeTextJSONKeys).
	// It deliberately does not reach hashes, internal identifiers, or
	// provenance plumbing.
	Text string

	// TextTimeFrom/TextTimeTo widen a free-text match to also cover
	// events INSIDE this window, OR'd with the field match above.
	//
	// They exist because an analyst who types a timestamp into the
	// search box is searching for a moment, and every field the text
	// predicate reads is a string -- so the search returned nothing for
	// evidence that was present, and only the date picker could reach
	// it. Pasting a timestamp out of a report is the most natural way to
	// look for one, and answering it with "no events" was a retrieval
	// failure, not a true statement.
	//
	// The window is computed by the CALLER, because deciding what
	// "2021-04-29 18:17" means requires the display timezone and this
	// layer deliberately knows nothing about timezones (see the file
	// comment). Its width is the precision of what was typed: a bare
	// date covers that whole local day, a date and minute that minute,
	// a full timestamp that second.
	//
	// Zero on both means no time widening, which is the case for an
	// ordinary term like a filename.
	TextTimeFrom time.Time
	TextTimeTo   time.Time

	// FindingSeverities and FindingTechniques are the two filters that
	// reach ACROSS the layer boundary: they restrict to events that a
	// current finding cites, by that finding's severity or ATT&CK
	// technique.
	//
	// Named after the finding deliberately. An event has no severity and
	// no technique of its own -- those are conclusions a detection rule
	// drew -- and a filter called plain "severity" on an event view would
	// suggest otherwise. Selecting one narrows the timeline to the small
	// minority of events some detection has spoken about, which is a
	// legitimate question ("show me what the rules flagged, in timeline
	// context") as long as it is not mistaken for a property of the
	// evidence.
	FindingSeverities []string
	FindingTechniques []string

	Sort EventSort

	// Limit/Offset select the page. A Limit of 0 means "no limit", which
	// only internal callers with an already-bounded question should use.
	Limit  int
	Offset int
}

// freeTextColumns is the exact set of normalized columns free-text
// search reads. Stated as data, not as an inline SQL string, so the
// documented semantics and the implementation cannot drift apart -- the
// test TestSearchSemantics_FreeTextSearchesOnlyDocumentedFields asserts
// against this very list.
//
// Deliberately ABSENT, and each for a reason:
//
//   - id, case_id, collection_id, source_file_id, raw_evidence_id:
//     internal identifiers. An analyst searching "a1b2" wants a filename
//     or a URL fragment, not a row key that happens to contain it.
//   - dedup_hash: a hash. Searching it would let an unrelated term
//     collide with hex and return an event that has nothing to do with
//     the question.
//   - source_reference, confidence, pid, ppid: plumbing and numbers with
//     no free-text meaning.
var freeTextColumns = []string{
	"host",
	"user",
	"event_type",
	"artifact_type",
	"parser",
	"provider",
	"process_name",
	"process_path",
	"parent_process",
	"parent_process_path",
	"command_line",
	"file_path",
	"registry_path",
	"network_source",
	"network_dest",
}

// freeTextJSONKeys are the extra_json keys free-text search reads.
//
// These are read with json_extract on NAMED keys -- never a blind LIKE
// over the whole JSON blob. A blind match would hit key names, numeric
// internals, and any future field a parser adds, so an analyst could not
// state what their own search had covered.
//
// Every key here is one an investigator actually searches by, and each
// exists because the value has no typed column of its own:
//
//	url            the requested resource (browser history, browser cache)
//	page_title     the title of a visited page
//	original_path  a deleted file's path before deletion (Recycle Bin $I)
//	original_name  a deleted file's name before deletion
//	target_path    what a shortcut or Jump List entry points at
//	file_name      the filename an NTFS or USN record names
//	application    the application a Jump List belongs to
//	executable_name the executable a Prefetch record names
//	content_type   a cached response's MIME type
var freeTextJSONKeys = []string{
	"url",
	"page_title",
	"original_path",
	"original_name",
	"target_path",
	"file_name",
	"application",
	"executable_name",
	"content_type",
}

// fieldTerm binds one field-scoped search term to the columns and JSON
// keys it searches. Keeping them in one table is what lets the API layer
// and the documentation enumerate the same truth.
type fieldTerm struct {
	name     string
	value    func(EventQuery) string
	columns  []string
	jsonKeys []string
}

// fieldTerms is the field-scoped search surface.
//
// Filename is narrower than Path on purpose: an analyst who knows the
// name of a file and not where it lived should not have to wade through
// every event whose directory happens to contain the string.
var fieldTerms = []fieldTerm{
	{
		name:     "filename",
		value:    func(q EventQuery) string { return q.Filename },
		columns:  []string{"process_name", "parent_process"},
		jsonKeys: []string{"file_name", "original_name", "executable_name"},
	},
	{
		name:     "path",
		value:    func(q EventQuery) string { return q.Path },
		columns:  []string{"file_path", "process_path", "parent_process_path", "registry_path"},
		jsonKeys: []string{"original_path", "target_path"},
	},
	{
		name:     "url",
		value:    func(q EventQuery) string { return q.URL },
		jsonKeys: []string{"url"},
	},
	{
		// Domain reads network_dest, which is where both browser parsers
		// put the URL's host and where winevent puts a connection's
		// destination. It is a real normalized column, so this is not a
		// second-guess at parsing the URL here.
		name:    "domain",
		value:   func(q EventQuery) string { return q.Domain },
		columns: []string{"network_dest"},
	},
	{
		// An IP can be either end of a connection, so both are searched.
		name:    "ip",
		value:   func(q EventQuery) string { return q.IP },
		columns: []string{"network_source", "network_dest"},
	},
	{
		name:    "command_line",
		value:   func(q EventQuery) string { return q.CommandLine },
		columns: []string{"command_line"},
	},
	{
		// The deleted-file question: "was this path ever in the Recycle
		// Bin?" original_path/original_name are the $I record's own
		// values, never the $R filename -- see internal/recyclebin.
		name:     "original_path",
		value:    func(q EventQuery) string { return q.OriginalPath },
		jsonKeys: []string{"original_path", "original_name"},
	},
}

// eventWhere builds the WHERE clause and its bound arguments.
//
// Every value is appended to args and represented in the SQL only as a
// "?" placeholder. The only strings interpolated are column names drawn
// from the constant tables above.
func eventWhere(q EventQuery) (string, []any) {
	var clauses []string
	var args []any

	clauses = append(clauses, "case_id = ?")
	args = append(args, q.CaseID)

	// Categorical OR-sets.
	inSet := func(column string, values []string) {
		values = nonEmptyStrings(values)
		if len(values) == 0 {
			return
		}
		clauses = append(clauses, column+" IN ("+placeholders(len(values))+")")
		for _, v := range values {
			args = append(args, v)
		}
	}
	inSet("collection_id", q.CollectionIDs)
	inSet("artifact_type", q.ArtifactTypes)
	inSet("event_type", q.EventTypes)
	inSet("host", q.Hosts)
	inSet("user", q.Users)
	inSet("process_name", q.Processes)

	// Time bounds. Timestamps are stored in a fixed-width UTC layout
	// (see timeLayout), so a lexicographic comparison IS a chronological
	// one and the existing (case_id, timestamp) index applies.
	if !q.From.IsZero() {
		clauses = append(clauses, "timestamp >= ?")
		args = append(args, fmtTime(q.From))
	}
	if !q.To.IsZero() {
		clauses = append(clauses, "timestamp <= ?")
		args = append(args, fmtTime(q.To))
	}

	// Field-scoped substring terms.
	for _, ft := range fieldTerms {
		term := strings.TrimSpace(ft.value(q))
		if term == "" {
			continue
		}
		if sql, a := likeAcross(ft.columns, ft.jsonKeys, term); sql != "" {
			clauses = append(clauses, sql)
			args = append(args, a...)
		}
	}

	// Finding-derived filters. Both resolve through the findings table
	// under the SAME currentAnalysisFilter every other results query
	// uses, so an invalidated run can never bring events back into a
	// filtered timeline.
	if sev := nonEmptyStrings(q.FindingSeverities); len(sev) > 0 {
		clauses = append(clauses, `id IN (
			SELECT je.value FROM findings f, json_each(f.supporting_events_json) je
			WHERE f.case_id = ?`+currentAnalysisFilter+`
			  AND f.severity IN (`+placeholders(len(sev))+`))`)
		args = append(args, q.CaseID, q.CaseID, q.CaseID)
		for _, v := range sev {
			args = append(args, v)
		}
	}
	if tech := nonEmptyStrings(q.FindingTechniques); len(tech) > 0 {
		clauses = append(clauses, `id IN (
			SELECT je.value FROM findings f, json_each(f.supporting_events_json) je,
			                     json_each(f.techniques_json) jt
			WHERE f.case_id = ?`+currentAnalysisFilter+`
			  AND jt.value IN (`+placeholders(len(tech))+`))`)
		args = append(args, q.CaseID, q.CaseID, q.CaseID)
		for _, v := range tech {
			args = append(args, v)
		}
	}

	// Free text.
	if term := strings.TrimSpace(q.Text); term != "" {
		sql, a := likeAcross(freeTextColumns, freeTextJSONKeys, term)
		// A Windows Event ID is a forensic identifier an analyst really
		// does search by ("4624"), and it is a typed integer column
		// rather than text. It is matched only when the term is entirely
		// digits, so a textual search can never be diverted into a
		// numeric comparison. This is the one numeric field free text
		// reaches, and it is documented as such.
		if isAllDigits(term) {
			sql = "(" + sql + " OR event_id = ?)"
			a = append(a, term)
		}
		// A term the caller recognized as a moment also matches events
		// in that moment's window. OR'd rather than replacing the field
		// match, so a term that is both -- a URL containing a date, a
		// filename with one in it -- still finds the text as well.
		if !q.TextTimeFrom.IsZero() && !q.TextTimeTo.IsZero() {
			sql = "(" + sql + " OR (timestamp >= ? AND timestamp <= ?))"
			a = append(a, fmtTime(q.TextTimeFrom), fmtTime(q.TextTimeTo))
		}
		clauses = append(clauses, sql)
		args = append(args, a...)
	}

	return strings.Join(clauses, " AND "), args
}

// likeAcross builds "(col LIKE ? OR ... OR json_extract(extra_json,
// '$.key') LIKE ? OR ...)" for one term.
//
// LIKE with no ESCAPE is ASCII-case-insensitive in SQLite, which is the
// case-insensitivity the analyst-facing documentation promises. The
// term's own LIKE metacharacters are escaped so a path containing "_"
// -- which is most Windows paths that matter -- is matched literally
// instead of silently becoming a single-character wildcard.
func likeAcross(columns, jsonKeys []string, term string) (string, []any) {
	pattern := "%" + escapeLike(term) + "%"
	var parts []string
	var args []any
	for _, c := range columns {
		parts = append(parts, c+` LIKE ? ESCAPE '\'`)
		args = append(args, pattern)
	}
	for _, k := range jsonKeys {
		parts = append(parts, `json_extract(extra_json, '$.`+k+`') LIKE ? ESCAPE '\'`)
		args = append(args, pattern)
	}
	if len(parts) == 0 {
		return "", nil
	}
	return "(" + strings.Join(parts, " OR ") + ")", args
}

// escapeLike neutralizes LIKE's wildcards in an analyst-supplied term.
func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

func nonEmptyStrings(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// SearchEvents returns one page of matching events plus the TOTAL number
// of matches.
//
// The total is counted with the same WHERE clause rather than inferred
// from the page, because "showing 1-10 of 1,284" is a forensic
// statement: an investigator uses it to know whether they have seen the
// evidence, and a total that only counted the page would be a lie that
// looks like a fact.
func (s *Store) SearchEvents(q EventQuery) ([]model.Event, int, error) {
	// A query with no case scope would read across every case in the
	// database. Nothing in Tracefall wants that, so it is refused here
	// rather than defended against at each call site.
	if strings.TrimSpace(q.CaseID) == "" {
		return nil, 0, fmt.Errorf("store: event search requires a case")
	}

	where, args := eventWhere(q)

	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM events WHERE `+srcVisible("source_file_id")+` AND (`+where+`)`, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("store: counting events: %w", err)
	}

	sql := `SELECT ` + eventCols + ` FROM events WHERE ` + srcVisible("source_file_id") + ` AND (` + where + `) ` + q.Sort.orderClause()
	pageArgs := args
	if q.Limit > 0 {
		sql += ` LIMIT ? OFFSET ?`
		offset := q.Offset
		if offset < 0 {
			offset = 0
		}
		// Copy before appending: args is still referenced by the count
		// query above in some call orders, and appending to a shared
		// backing array is exactly the kind of aliasing bug that would
		// only show up under load.
		pageArgs = append(append([]any{}, args...), q.Limit, offset)
	}

	rows, err := s.db.Query(sql, pageArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("store: searching events: %w", err)
	}
	defer rows.Close()

	out := []model.Event{}
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// EventFacets are the distinct values a case's events actually carry,
// for building filter dropdowns.
//
// Derived from the stored events rather than from the artifact/event
// constant tables, so the timeline offers an analyst exactly the filters
// that can return something. Offering "Firefox History" as a choice in a
// case with no Firefox evidence wastes the analyst's attention and
// invites them to conclude that a zero result means the filter is
// broken.
type EventFacets struct {
	ArtifactTypes []string `json:"artifact_types"`
	EventTypes    []string `json:"event_types"`
	Hosts         []string `json:"hosts"`
	Users         []string `json:"users"`
	Processes     []string `json:"processes"`
	Collections   []string `json:"collections"`

	// Earliest/Latest bracket the case's real evidence, so the date
	// picker can say what range even exists. Zero when the case has no
	// timestamped events at all.
	Earliest time.Time `json:"earliest"`
	Latest   time.Time `json:"latest"`
}

// facetColumns is the fixed allow-list of columns EventFacets reads, in
// the order the single DISTINCT query selects them. Nothing here comes
// from a request.
var facetColumns = []string{"artifact_type", "event_type", "host", "user", "process_name", "collection_id"}

// EventFacets returns the distinct filterable values in one case.
//
// # Why this is one query and not six
//
// The obvious implementation is a SELECT DISTINCT per column. Measured
// on a 200,000-event case that cost ~930ms, because four of the six
// columns have no index and each therefore scans the case in full.
//
// Indexing them was the other obvious fix, and was rejected on measured
// evidence: four extra indexes raised the cost of importing 200,000
// events from 5.3s to 9.1s -- a 73% tax on the operation an analyst
// runs repeatedly with real evidence -- to save time on the one that
// happens once when a tab opens. Facet lists are not worth slowing
// ingestion down for.
//
// So the columns are read together and deduplicated as they stream.
// SQLite deduplicates the COMBINATIONS internally, so what crosses into
// Go is bounded by the number of distinct combinations rather than by
// the number of events, and the whole thing is one pass over the case.
func (s *Store) EventFacets(caseID string) (EventFacets, error) {
	var out EventFacets
	if strings.TrimSpace(caseID) == "" {
		return out, fmt.Errorf("store: event facets require a case")
	}

	// facetColumns is a package constant, never request input.
	rows, err := s.db.Query(
		`SELECT DISTINCT `+strings.Join(facetColumns, ", ")+` FROM events WHERE case_id = ? AND `+srcVisible("source_file_id"), caseID)
	if err != nil {
		return out, fmt.Errorf("store: event facets: %w", err)
	}
	seen := make([]map[string]bool, len(facetColumns))
	for i := range seen {
		seen[i] = map[string]bool{}
	}
	for rows.Next() {
		values := make([]string, len(facetColumns))
		targets := make([]any, len(facetColumns))
		for i := range values {
			targets[i] = &values[i]
		}
		if err := rows.Scan(targets...); err != nil {
			rows.Close()
			return out, err
		}
		for i, v := range values {
			// An empty value is the absence of the field, not a value the
			// analyst can usefully filter by, so it never becomes an
			// option. Events lacking it are still returned by every query
			// that does not constrain that field.
			if v != "" {
				seen[i][v] = true
			}
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}

	// Sorted here rather than by SQL: the query above cannot order six
	// independent columns at once, and sorting a few hundred strings in
	// Go is free next to the scan that produced them.
	sorted := func(m map[string]bool) []string {
		out := make([]string, 0, len(m))
		for v := range m {
			out = append(out, v)
		}
		sort.Strings(out)
		return out
	}
	out.ArtifactTypes = sorted(seen[0])
	out.EventTypes = sorted(seen[1])
	out.Hosts = sorted(seen[2])
	out.Users = sorted(seen[3])
	out.Processes = sorted(seen[4])
	out.Collections = sorted(seen[5])

	// The bounds ignore the zero timestamp, which is Tracefall's
	// encoding of "this artifact records no time" (see
	// model.Event.Timestamp) and is not a point on any calendar. Letting
	// it through would tell the analyst their evidence starts in year 1.
	row := s.db.QueryRow(
		`SELECT MIN(timestamp), MAX(timestamp) FROM events WHERE case_id = ? AND timestamp > ? AND `+srcVisible("source_file_id"),
		caseID, fmtTime(time.Time{}))
	var lo, hi *string
	if err := row.Scan(&lo, &hi); err != nil {
		return out, fmt.Errorf("store: event time bounds: %w", err)
	}
	if lo != nil {
		out.Earliest = parseTime(*lo)
	}
	if hi != nil {
		out.Latest = parseTime(*hi)
	}
	return out, nil
}

// CountEvents reports how many events a case holds, without reading any
// of them. Used where only the size matters (empty-state decisions,
// scale warnings) and loading rows to call len() would be waste.
func (s *Store) CountEvents(caseID string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM events WHERE case_id = ? AND `+srcVisible("source_file_id"), caseID).Scan(&n)
	return n, err
}

// FindingsForEvents returns the CURRENT findings whose supporting
// evidence includes any of the given events, keyed by event id.
//
// # Why this is a join and not a scan of every finding
//
// The timeline shows, on each row, whether that event is cited by a
// detection. Answering it by loading every finding in the case and
// indexing them in Go works, and is what the dashboard did while the
// whole timeline was client-side -- but it re-reads the entire finding
// set on every page navigation to annotate at most a hundred rows.
// json_each expands supporting_events_json into rows SQLite can match
// directly, so the database returns exactly the findings that are
// relevant to the page in front of the analyst.
//
// # Why "current" is load-bearing
//
// This applies the same currentAnalysisFilter every other
// results-presenting query applies. A finding belonging to an
// invalidated analysis run is history, not a result: if it were
// annotated onto a timeline row the analyst would be told that deleted
// evidence still supports a live detection. An event whose only findings
// were invalidated correctly comes back with none.
func (s *Store) FindingsForEvents(caseID string, eventIDs []string) (map[string][]model.Finding, error) {
	out := map[string][]model.Finding{}
	eventIDs = nonEmptyStrings(eventIDs)
	if strings.TrimSpace(caseID) == "" || len(eventIDs) == 0 {
		return out, nil
	}

	// je.value is the event id inside supporting_events_json, selected
	// alongside the finding so one pass builds the whole map.
	q := `SELECT je.value, ` + prefixCols(findingCols, "f") + `
		FROM findings f, json_each(f.supporting_events_json) je
		WHERE f.case_id = ?` + currentAnalysisFilter + `
		  AND je.value IN (` + placeholders(len(eventIDs)) + `)
		ORDER BY f.first_seen ASC, f.id ASC`

	args := []any{caseID, caseID, caseID}
	for _, id := range eventIDs {
		args = append(args, id)
	}

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: findings for events: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var eventID string
		f, err := scanFindingWithLead(rows, &eventID)
		if err != nil {
			return nil, err
		}
		out[eventID] = append(out[eventID], f)
	}
	return out, rows.Err()
}

// prefixCols qualifies a comma-separated column list with a table alias,
// so a shared column constant can be reused inside a join without being
// duplicated (and drifting).
func prefixCols(cols, alias string) string {
	parts := strings.Split(cols, ",")
	for i, p := range parts {
		parts[i] = alias + "." + strings.TrimSpace(p)
	}
	return strings.Join(parts, ", ")
}

// scanFindingWithLead scans one row shaped as (lead, findingCols).
//
// The lead column is the event id json_each produced, which is what
// makes the result a map rather than a list. Written out rather than
// wrapping scanFinding because database/sql has no way to scan "the
// rest of the row" into an existing scanner.
func scanFindingWithLead(row interface{ Scan(...any) error }, lead *string) (model.Finding, error) {
	var f model.Finding
	var supJSON, techJSON, first, last, created string
	err := row.Scan(lead,
		&f.ID, &f.CaseID, &f.RuleID, &f.Title, &f.Severity, &f.Confidence, &f.Description,
		&supJSON, &techJSON, &first, &last, &created, &f.AnalysisRunID)
	if err != nil {
		return model.Finding{}, err
	}
	_ = json.Unmarshal([]byte(supJSON), &f.SupportingEvents)
	_ = json.Unmarshal([]byte(techJSON), &f.Techniques)
	f.FirstSeen, f.LastSeen, f.CreatedAt = parseTime(first), parseTime(last), parseTime(created)
	return f, nil
}

// EventsByIDs loads the given events in one query, skipping ids that no
// longer exist.
//
// Distinct from GetEvents, which issues one statement per id and fails
// if any is missing. Both behaviours are wanted somewhere: a finding's
// supporting events are a fixed set whose absence is an error worth
// surfacing, while a caller assembling context (investigations, event
// detail) is asking "whichever of these still exist", and an event whose
// evidence was deleted must not turn that into a failure.
//
// Ids are chunked because SQLite caps the number of bound parameters in
// one statement (999 by default); a case with thousands of findings
// would otherwise fail here for a reason that has nothing to do with the
// question being asked.
func (s *Store) EventsByIDs(ids []string) ([]model.Event, error) {
	ids = nonEmptyStrings(ids)
	out := make([]model.Event, 0, len(ids))
	const chunk = 500
	for start := 0; start < len(ids); start += chunk {
		end := start + chunk
		if end > len(ids) {
			end = len(ids)
		}
		batch := ids[start:end]
		args := make([]any, 0, len(batch))
		for _, id := range batch {
			args = append(args, id)
		}
		rows, err := s.db.Query(
			`SELECT `+eventCols+` FROM events WHERE id IN (`+placeholders(len(batch))+`) AND `+srcVisible("source_file_id"), args...)
		if err != nil {
			return nil, fmt.Errorf("store: loading events by id: %w", err)
		}
		for rows.Next() {
			e, err := scanEvent(rows)
			if err != nil {
				rows.Close()
				return nil, err
			}
			out = append(out, e)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// CorrelationsForEvents returns the CURRENT correlations referencing any
// of the given events, keyed by event id.
//
// The mirror of FindingsForEvents, and it exists for the same reason: a
// timeline row shows whether its event is part of a reconstructed
// activity chain, and answering that by loading every correlation in the
// case to annotate one page is work proportional to the case rather than
// to the page.
func (s *Store) CorrelationsForEvents(caseID string, eventIDs []string) (map[string][]model.Correlation, error) {
	out := map[string][]model.Correlation{}
	eventIDs = nonEmptyStrings(eventIDs)
	if strings.TrimSpace(caseID) == "" || len(eventIDs) == 0 {
		return out, nil
	}

	q := `SELECT je.value, ` + prefixCols(correlationCols, "c") + `
		FROM correlations c, json_each(c.event_ids_json) je
		WHERE c.case_id = ?` + currentAnalysisFilter + `
		  AND je.value IN (` + placeholders(len(eventIDs)) + `)
		ORDER BY c.first_seen ASC, c.id ASC`

	args := []any{caseID, caseID, caseID}
	for _, id := range eventIDs {
		args = append(args, id)
	}

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: correlations for events: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var eventID string
		c, err := scanCorrelationWithLead(rows, &eventID)
		if err != nil {
			return nil, err
		}
		out[eventID] = append(out[eventID], c)
	}
	return out, rows.Err()
}

// scanCorrelationWithLead scans one row shaped as (lead, correlationCols).
func scanCorrelationWithLead(row interface{ Scan(...any) error }, lead *string) (model.Correlation, error) {
	var c model.Correlation
	var eventIDsJSON, first, last string
	err := row.Scan(lead,
		&c.ID, &c.CaseID, &c.Type, &c.Title, &c.Description, &eventIDsJSON, &first, &last, &c.AnalysisRunID)
	if err != nil {
		return model.Correlation{}, err
	}
	_ = json.Unmarshal([]byte(eventIDsJSON), &c.EventIDs)
	c.FirstSeen, c.LastSeen = parseTime(first), parseTime(last)
	return c, nil
}
