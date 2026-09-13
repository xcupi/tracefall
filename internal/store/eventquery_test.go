package store

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
)

// The free-text surface is a documented promise: docs/forensic-search.md
// tells an analyst exactly which fields a search term reaches, and an
// examiner may have to state that in a report. These tests pin the
// promise to the implementation so the two cannot drift.

func TestSearchSemantics_FreeTextSearchesExactlyTheDocumentedColumns(t *testing.T) {
	want := map[string]bool{
		"host": true, "user": true, "event_type": true, "artifact_type": true,
		"parser": true, "provider": true, "process_name": true, "process_path": true,
		"parent_process": true, "parent_process_path": true, "command_line": true,
		"file_path": true, "registry_path": true, "network_source": true, "network_dest": true,
	}
	got := map[string]bool{}
	for _, c := range freeTextColumns {
		if !want[c] {
			t.Errorf("free-text search reads column %q, which docs/forensic-search.md does not list", c)
		}
		if got[c] {
			t.Errorf("column %q is searched twice", c)
		}
		got[c] = true
	}
	for c := range want {
		if !got[c] {
			t.Errorf("docs/forensic-search.md lists column %q, but free-text search does not read it", c)
		}
	}
}

func TestSearchSemantics_FreeTextSearchesExactlyTheDocumentedExtraKeys(t *testing.T) {
	want := map[string]bool{
		"url": true, "page_title": true, "original_path": true, "original_name": true,
		"target_path": true, "file_name": true, "application": true,
		"executable_name": true, "content_type": true,
	}
	got := map[string]bool{}
	for _, k := range freeTextJSONKeys {
		if !want[k] {
			t.Errorf("free-text search reads extra key %q, which is not documented", k)
		}
		got[k] = true
	}
	for k := range want {
		if !got[k] {
			t.Errorf("documented extra key %q is not searched", k)
		}
	}
}

// The fields free text must NOT reach. Each would let an analyst's term
// collide with plumbing: a hash is hex that any term can hit by
// accident, and an identifier is a row key, not evidence.
func TestSearchSemantics_FreeTextNeverReachesIdentifiersOrHashes(t *testing.T) {
	forbidden := []string{
		"id", "case_id", "collection_id", "source_file_id", "raw_evidence_id",
		"dedup_hash", "source_reference", "confidence", "extra_json",
	}
	for _, col := range freeTextColumns {
		for _, bad := range forbidden {
			if col == bad {
				t.Errorf("free-text search reads %q, which is internal plumbing rather than evidence", col)
			}
		}
	}
}

// Every field-scoped term must actually search something, and must not
// reach a column outside the documented normalized set. A term wired to
// nothing would fail silently -- the analyst types a filename, gets no
// results, and concludes the evidence is absent.
func TestSearchSemantics_EveryFieldTermSearchesSomething(t *testing.T) {
	knownColumns := map[string]bool{}
	for _, c := range freeTextColumns {
		knownColumns[c] = true
	}
	for _, ft := range fieldTerms {
		if len(ft.columns) == 0 && len(ft.jsonKeys) == 0 {
			t.Errorf("field term %q searches no columns and no extra keys", ft.name)
		}
		for _, c := range ft.columns {
			if !knownColumns[c] {
				t.Errorf("field term %q reads column %q, which is not part of the documented normalized field set",
					ft.name, c)
			}
		}
	}
}

// The generated SQL must contain no analyst-supplied text: every value
// travels as a bound parameter. This is the structural guarantee behind
// the API-level injection test -- it checks the shape of the query
// rather than the outcome of a handful of payloads.
func TestSearchSemantics_QueryTextNeverContainsAnalystInput(t *testing.T) {
	payloads := []string{
		`'; DROP TABLE events; --`,
		`" OR "1"="1`,
		`admin' --`,
		`100%`,
		`C:\Users\jdoe`,
	}
	for _, p := range payloads {
		q := EventQuery{
			CaseID: p, Text: p, Filename: p, Path: p, URL: p, Domain: p, IP: p,
			CommandLine: p, OriginalPath: p,
			ArtifactTypes: []string{p}, EventTypes: []string{p}, Hosts: []string{p},
			Users: []string{p}, Processes: []string{p}, CollectionIDs: []string{p},
		}
		sql, args := eventWhere(q)
		if strings.Contains(sql, p) {
			t.Errorf("payload %q appears literally in the generated SQL:\n%s", p, sql)
		}
		found := false
		for _, a := range args {
			if s, ok := a.(string); ok && strings.Contains(s, p) {
				found = true
			}
		}
		if !found {
			t.Errorf("payload %q reached neither the SQL nor the bound arguments; it was dropped", p)
		}
	}
}

// A query with no case is refused rather than answered. Without this,
// one missing scope would read across every case in the database.
func TestSearchSemantics_QueryWithoutACaseIsRefused(t *testing.T) {
	s := openTest(t)
	if _, _, err := s.SearchEvents(EventQuery{}); err == nil {
		t.Error("a search with no case id was accepted")
	}
	if _, err := s.EventFacets(""); err == nil {
		t.Error("facets with no case id were accepted")
	}
}

// LIKE metacharacters in an analyst's term are escaped, so a Windows
// path full of underscores matches literally.
func TestSearchSemantics_LikeMetacharactersAreEscaped(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`plain`, `plain`},
		{`100%`, `100\%`},
		{`a_b`, `a\_b`},
		{`back\slash`, `back\\slash`},
		{`%_\`, `\%\_\\`},
	} {
		if got := escapeLike(tc.in); got != tc.want {
			t.Errorf("escapeLike(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// The ordering is a total order in both directions, with the tie-break
// running the same way as the timestamp so it can be read off the index.
func TestSearchSemantics_OrderingIsTotalAndIndexFriendly(t *testing.T) {
	desc := EventSortTimeDesc.orderClause()
	asc := EventSortTimeAsc.orderClause()
	if !strings.Contains(desc, "timestamp DESC") || !strings.Contains(desc, "id DESC") {
		t.Errorf("descending order is not (timestamp DESC, id DESC): %s", desc)
	}
	if !strings.Contains(asc, "timestamp ASC") || !strings.Contains(asc, "id ASC") {
		t.Errorf("ascending order is not (timestamp ASC, id ASC): %s", asc)
	}
	// An unknown sort must fall back to a defined order, never to none.
	if EventSort("nonsense; DROP TABLE events").orderClause() != desc {
		t.Error("an unrecognized sort did not fall back to the default ordering")
	}
}

// seedTiedEvents writes n events that ALL carry the same timestamp.
//
// Identical timestamps are the normal case in real evidence, not an edge
// case: an $MFT record contributes four events off the same $STANDARD_
// INFORMATION times, and a USN journal records a rename as two entries
// in the same second. Any of those groups is large enough to straddle a
// page boundary.
func seedTiedEvents(t *testing.T, s *Store, n int) time.Time {
	t.Helper()
	seedCaseAndSourceFile(t, s)
	at := time.Date(2021, 4, 29, 18, 17, 38, 0, time.UTC)
	events := make([]model.Event, 0, n)
	for i := 0; i < n; i++ {
		events = append(events, model.Event{
			// Ids deliberately out of insertion order, so a correct
			// result cannot come from rowid order by accident.
			ID:     fmt.Sprintf("ev-%04d", (i*7919)%n),
			CaseID: "case-1", CollectionID: "collection-1", SourceFileID: "sf-1",
			Timestamp: at, EventType: model.EventFilesystemCreated,
			ArtifactType: model.ArtifactMFT, Parser: "mft@1", Confidence: 1,
			FilePath: fmt.Sprintf(`C:\dir\file%04d.txt`, i),
		})
	}
	if err := s.SaveEvents(events); err != nil {
		t.Fatalf("seeding events: %v", err)
	}
	return at
}

// Paging must partition the result set exactly, even when every event
// shares one timestamp -- the case where an ordering without a
// tie-breaker is free to return a different sequence per query, showing
// one event twice and hiding another.
func TestSearchSemantics_PagingPartitionsEventsWithIdenticalTimestamps(t *testing.T) {
	s := openTest(t)
	const n = 97
	seedTiedEvents(t, s, n)

	for _, sort := range []EventSort{EventSortTimeDesc, EventSortTimeAsc} {
		for _, size := range []int{1, 7, 10, 25} {
			seen := map[string]int{}
			var order []string
			for page := 0; ; page++ {
				got, total, err := s.SearchEvents(EventQuery{
					CaseID: "case-1", Sort: sort, Limit: size, Offset: page * size,
				})
				if err != nil {
					t.Fatal(err)
				}
				if total != n {
					t.Fatalf("sort=%s size=%d: total = %d, want %d", sort, size, total, n)
				}
				if len(got) == 0 {
					break
				}
				for _, e := range got {
					seen[e.ID]++
					order = append(order, e.ID)
				}
				if page > n+5 {
					t.Fatal("paging did not terminate")
				}
			}
			if len(seen) != n {
				t.Errorf("sort=%s size=%d: saw %d distinct events, want %d", sort, size, len(seen), n)
			}
			for id, count := range seen {
				if count != 1 {
					t.Errorf("sort=%s size=%d: event %s returned %d times", sort, size, id, count)
				}
			}
			// A single unpaged read must produce the very same sequence,
			// so the page boundary itself changes nothing.
			whole, _, err := s.SearchEvents(EventQuery{CaseID: "case-1", Sort: sort, Limit: n})
			if err != nil {
				t.Fatal(err)
			}
			for i := range whole {
				if whole[i].ID != order[i] {
					t.Fatalf("sort=%s size=%d: paged order differs from the unpaged order at %d (%s vs %s)",
						sort, size, i, order[i], whole[i].ID)
				}
			}
		}
	}
}

// The same query, run twice, returns the same order. Without this an
// analyst citing "the third event on page 4" cannot rely on it still
// being there.
func TestSearchSemantics_RepeatedQueriesReturnTheSameOrder(t *testing.T) {
	s := openTest(t)
	seedTiedEvents(t, s, 40)

	first, _, err := s.SearchEvents(EventQuery{CaseID: "case-1", Limit: 40})
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 5; attempt++ {
		again, _, err := s.SearchEvents(EventQuery{CaseID: "case-1", Limit: 40})
		if err != nil {
			t.Fatal(err)
		}
		for i := range first {
			if first[i].ID != again[i].ID {
				t.Fatalf("attempt %d: order changed at position %d (%s -> %s)",
					attempt, i, first[i].ID, again[i].ID)
			}
		}
	}
}

// The ordering must not depend on which index SQLite chooses.
//
// This is the concrete reason the tie-breaker exists, and it is not
// hypothetical: with ORDER BY timestamp alone, the same 60 tied events
// come back as [ev-0059, ev-0058, ...] when the query is served by
// idx_events_case_ts_id and as [ev-0000, ev-0059, ...] when it is served
// by idx_events_case -- one event silently moves from last place to
// first. Which index gets chosen is SQLite's decision, and it varies
// with the data, with ANALYZE statistics, and across SQLite versions. An
// analyst who cites "the first event on page 3" needs that to be a fact
// about the evidence, not about the query planner's mood.
//
// INDEXED BY forces the plan here so the property is tested rather than
// left to chance. Production queries never name an index.
func TestSearchSemantics_OrderIsIndependentOfTheQueryPlan(t *testing.T) {
	s := openTest(t)
	seedTiedEvents(t, s, 60)

	plans := []string{
		"", // whatever SQLite picks
		"INDEXED BY idx_events_case_ts_id",
		"INDEXED BY idx_events_case",
		"INDEXED BY idx_events_case_type",
		"INDEXED BY idx_events_case_dedup",
	}
	for _, sort := range []EventSort{EventSortTimeDesc, EventSortTimeAsc} {
		var reference []string
		for _, plan := range plans {
			q := `SELECT id FROM events ` + plan + ` WHERE case_id = 'case-1' ` + sort.orderClause()
			rows, err := s.db.Query(q)
			if err != nil {
				t.Fatalf("%s: %v", q, err)
			}
			var ids []string
			for rows.Next() {
				var id string
				if err := rows.Scan(&id); err != nil {
					rows.Close()
					t.Fatal(err)
				}
				ids = append(ids, id)
			}
			rows.Close()
			if reference == nil {
				reference = ids
				continue
			}
			if len(ids) != len(reference) {
				t.Fatalf("sort=%s plan=%q returned %d rows, want %d", sort, plan, len(ids), len(reference))
			}
			for i := range ids {
				if ids[i] != reference[i] {
					t.Fatalf("sort=%s: plan %q orders tied events differently at position %d (%s vs %s)",
						sort, plan, i, ids[i], reference[i])
				}
			}
		}
	}
}

// seedManyEvents writes n events spread across artifacts, hosts, users
// and one second apart, for the scale tests below.
func seedManyEvents(t *testing.T, s *Store, n int) {
	t.Helper()
	seedCaseAndSourceFile(t, s)
	arts := []string{model.ArtifactMFT, model.ArtifactPrefetch, model.ArtifactBrowserHistory,
		model.ArtifactLNK, model.ArtifactRecycleBin}
	types := []string{model.EventFilesystemCreated, model.EventPrefetchExecution, model.EventBrowserVisit,
		model.EventLnkTargetAccessed, model.EventRecycleBinDeletion}
	base := time.Date(2021, 4, 1, 0, 0, 0, 0, time.UTC)

	// Written in batches so one oversized transaction does not dominate
	// what the test is measuring.
	const batch = 5000
	for start := 0; start < n; start += batch {
		end := start + batch
		if end > n {
			end = n
		}
		events := make([]model.Event, 0, end-start)
		for i := start; i < end; i++ {
			k := i % len(arts)
			events = append(events, model.Event{
				ID: fmt.Sprintf("ev-%08d", i), CaseID: "case-1", CollectionID: "collection-1",
				SourceFileID: "sf-1", Timestamp: base.Add(time.Duration(i) * time.Second),
				Host: fmt.Sprintf("HOST-%02d", i%20), User: fmt.Sprintf("user%d", i%50),
				EventType: types[k], ArtifactType: arts[k], Parser: "p@1", Confidence: 1,
				ProcessName: fmt.Sprintf("proc%d.exe", i%100),
				FilePath:    fmt.Sprintf(`C:\dir%d\file%d.txt`, i%500, i),
				NetworkDest: fmt.Sprintf("host%d.example.test", i%997),
				Extra: map[string]string{
					"url":           fmt.Sprintf("https://host%d.example.test/p/%d", i%997, i),
					"file_name":     fmt.Sprintf("file%d.txt", i),
					"original_path": fmt.Sprintf(`C:\Users\u\deleted%d.txt`, i),
				},
			})
		}
		if err := s.SaveEvents(events); err != nil {
			t.Fatalf("seeding events: %v", err)
		}
	}
}

// A large case must stay usable: a page is a bounded query, and the
// TOTAL is counted rather than derived from the page.
//
// This is the guard against the regression the whole phase exists to
// fix. Before Phase 14 the only way to look at a timeline was to read
// every event in the case; reading 200,000 events took about four
// seconds before the browser had even begun to filter them. The
// assertions below are deliberately loose -- they are about complexity,
// not about this machine's speed -- but they cannot be satisfied by an
// implementation that reads the case to answer a page.
func TestSearchScale_LargeCaseStaysPaged(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped in short mode")
	}
	s := openTest(t)
	const n = 50000
	seedManyEvents(t, s, n)

	cases := []struct {
		name string
		q    EventQuery
		want int
	}{
		{"first page", EventQuery{CaseID: "case-1", Limit: 10}, n},
		{"deep page", EventQuery{CaseID: "case-1", Limit: 10, Offset: n - 20}, n},
		{"artifact filter", EventQuery{CaseID: "case-1", Limit: 10, ArtifactTypes: []string{model.ArtifactPrefetch}}, n / 5},
		// The seed writes one event per second from 2021-04-01 00:00, so
		// 50,000 events occupy just under 14 hours of that first day --
		// the whole set falls inside it, and the day after holds none.
		{"the day the evidence is on", EventQuery{CaseID: "case-1", Limit: 10,
			From: time.Date(2021, 4, 1, 0, 0, 0, 0, time.UTC),
			To:   time.Date(2021, 4, 1, 23, 59, 59, 999999999, time.UTC)}, n},
		{"a day with no evidence", EventQuery{CaseID: "case-1", Limit: 10,
			From: time.Date(2021, 4, 3, 0, 0, 0, 0, time.UTC),
			To:   time.Date(2021, 4, 3, 23, 59, 59, 999999999, time.UTC)}, 0},
	}
	for _, tc := range cases {
		got, total, err := s.SearchEvents(tc.q)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if total != tc.want {
			t.Errorf("%s: total = %d, want %d", tc.name, total, tc.want)
		}
		// The page is bounded regardless of how many matched. This is
		// the property that makes the view usable at all.
		if len(got) > tc.q.Limit {
			t.Errorf("%s: returned %d events for a page size of %d", tc.name, len(got), tc.q.Limit)
		}
	}

	// Facets stay bounded by the number of DISTINCT values, not by the
	// number of events -- 50,000 events, at most a few hundred options.
	facets, err := s.EventFacets("case-1")
	if err != nil {
		t.Fatal(err)
	}
	total := len(facets.ArtifactTypes) + len(facets.EventTypes) + len(facets.Hosts) +
		len(facets.Users) + len(facets.Processes) + len(facets.Collections)
	if total > 1000 {
		t.Errorf("facets returned %d options for %d events; the vocabulary must be bounded by distinct values", total, n)
	}
	if len(facets.ArtifactTypes) != 5 || len(facets.Hosts) != 20 || len(facets.Users) != 50 {
		t.Errorf("facets = %d artifacts / %d hosts / %d users, want 5 / 20 / 50",
			len(facets.ArtifactTypes), len(facets.Hosts), len(facets.Users))
	}
	if facets.Earliest.IsZero() || facets.Latest.IsZero() || !facets.Latest.After(facets.Earliest) {
		t.Errorf("time bounds not reported sensibly: %s .. %s", facets.Earliest, facets.Latest)
	}
}

// Paging all the way through a large filtered set must still partition
// it exactly. Run at a size where the walk crosses hundreds of pages.
func TestSearchScale_DeepPagingRemainsAPartition(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped in short mode")
	}
	s := openTest(t)
	const n = 20000
	seedManyEvents(t, s, n)

	seen := make(map[string]int, n)
	const size = 100
	for page := 0; ; page++ {
		got, total, err := s.SearchEvents(EventQuery{CaseID: "case-1", Limit: size, Offset: page * size})
		if err != nil {
			t.Fatal(err)
		}
		if total != n {
			t.Fatalf("page %d: total = %d, want %d", page, total, n)
		}
		if len(got) == 0 {
			break
		}
		for _, e := range got {
			seen[e.ID]++
		}
		if page > n/size+5 {
			t.Fatal("paging did not terminate")
		}
	}
	if len(seen) != n {
		t.Errorf("saw %d distinct events across all pages, want %d", len(seen), n)
	}
	for id, count := range seen {
		if count != 1 {
			t.Errorf("event %s appeared %d times", id, count)
			break
		}
	}
}
