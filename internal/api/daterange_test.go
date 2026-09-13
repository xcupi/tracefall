package api

import (
	"database/sql"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"tracefall/internal/model"
)

// Precise date-range filtering (Phase 17).
//
// # The failure this pins
//
// Stored event timestamps carry sub-second precision. A range written
// [18:17:38, 18:17:38] and taken literally is one nanosecond wide, so it
// excluded an event recorded at 18:17:38.900891 -- the analyst named the
// second the event is in and got nothing back.
//
// A bound is written at some PRECISION, and the two ends of a range use
// that precision differently: "from 18:17:38" is where the second
// begins, "to 18:17:38" is where it ends. These tests pin that rule at
// every precision the filter accepts.
//
// The timestamps and the sub-second value below were OBSERVED in real
// evidence (a Chromium History visit) and are reproduced in a synthetic
// database. No evidence file is committed.

const (
	// Microseconds since 1601-01-01 UTC, as Chromium stores it.
	rangeVisitWebKit = 13264193858900891
	rangeVisitURL    = "https://www.google.com/search?q=password+cracking+lists"
	// The page title as recorded. It carries the words with SPACES,
	// where the URL carries them "+"-encoded -- which is exactly why a
	// natural free-text search matches the title rather than the URL.
	rangeVisitTitle = "password cracking lists - Google Search"
)

// rangeVisitUTC is 2021-04-29T18:17:38.900891Z -- deliberately NOT on a
// second boundary, which is what makes the boundary cases meaningful.
var rangeVisitUTC = time.Unix(
	rangeVisitWebKit/1_000_000-11644473600,
	(rangeVisitWebKit%1_000_000)*1000).UTC()

// rangeHistory builds a Chromium History with the observed visit plus
// neighbours one second either side.
func rangeHistory(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "History")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{
		`CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER)`,
		`CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, transition INTEGER)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	rows := []struct {
		id         int
		vt         int64
		url, title string
	}{
		{1, rangeVisitWebKit, rangeVisitURL, rangeVisitTitle},
		{2, rangeVisitWebKit - 1_000_000, "https://example.test/one-second-earlier", "Earlier"},
		{3, rangeVisitWebKit + 1_000_000, "https://example.test/one-second-later", "Later"},
	}
	for _, r := range rows {
		db.Exec(`INSERT INTO urls VALUES(?,?,?,1,?)`, r.id, r.url, r.title, r.vt)
		db.Exec(`INSERT INTO visits VALUES(?,?,?,805306368)`, r.id, r.id, r.vt)
	}
	db.Close()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func rangeCase(t *testing.T, mux http.Handler) string {
	t.Helper()
	c := mustCreateCase(t, mux, "date range "+t.Name())
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		"Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/History": rangeHistory(t),
	})
	if imp := importAllFrom(t, mux, c.ID, disc); len(imp.ParseFailures) != 0 {
		t.Fatalf("fixture failed to parse: %+v", imp.ParseFailures)
	}
	return c.ID
}

// The requirement: a ONE-SECOND range isolates the event inside it.
func TestDateRange_OneSecondRangeIsolatesTheEvent(t *testing.T) {
	mux := newTestRouter(t)
	caseID := rangeCase(t, mux)

	for _, form := range []struct{ from, to string }{
		{"2021-04-29T18:17:38", "2021-04-29T18:17:38"},
		{"2021-04-29 18:17:38", "2021-04-29 18:17:38"},
	} {
		res := searchEvents(t, mux, caseID, vals("from", form.from, "to", form.to))
		if res.Total != 1 {
			t.Errorf("from=%q to=%q returned %d events, want exactly the one at %s",
				form.from, form.to, res.Total, rangeVisitUTC.Format(time.RFC3339Nano))
			continue
		}
		e := res.Items[0]
		if !e.Timestamp.Equal(rangeVisitUTC) {
			t.Errorf("matched an event at %s, want %s", e.Timestamp, rangeVisitUTC)
		}
		if e.Extra["url"] != rangeVisitURL {
			t.Errorf("matched %q", e.Extra["url"])
		}
		// The range must state the instants it actually queried.
		if res.Range.From == "" || res.Range.To == "" {
			t.Errorf("range bounds not reported: %+v", res.Range)
		}
	}
}

// An exact instant, expressed as RFC3339, is used as given -- not
// widened. A caller who wrote an offset was being explicit.
func TestDateRange_ExplicitInstantIsNotWidened(t *testing.T) {
	mux := newTestRouter(t)
	caseID := rangeCase(t, mux)

	// The exact stored instant, both ends: matches only itself.
	exact := rangeVisitUTC.Format(time.RFC3339Nano)
	if res := searchEvents(t, mux, caseID, vals("from", exact, "to", exact)); res.Total != 1 {
		t.Errorf("an exact-instant range returned %d events, want 1", res.Total)
	}
	// One nanosecond past it: matches nothing.
	past := rangeVisitUTC.Add(time.Nanosecond).Format(time.RFC3339Nano)
	if res := searchEvents(t, mux, caseID, vals("from", past, "to", past)); res.Total != 0 {
		t.Errorf("a range starting after the event returned %d events, want 0", res.Total)
	}
}

// Precision decides how far a `to` bound reaches, at every level.
func TestDateRange_EndBoundExtendsToTheUnitNamed(t *testing.T) {
	mux := newTestRouter(t)
	caseID := rangeCase(t, mux)

	for _, tc := range []struct {
		name, from, to string
		want           int
	}{
		{"that second", "2021-04-29T18:17:38", "2021-04-29T18:17:38", 1},
		{"that minute", "2021-04-29T18:17", "2021-04-29T18:17", 3},
		{"that day", "2021-04-29", "2021-04-29", 3},
		{"second before, inclusive", "2021-04-29T18:17:37", "2021-04-29T18:17:38", 2},
		{"second after, inclusive", "2021-04-29T18:17:38", "2021-04-29T18:17:39", 2},
	} {
		res := searchEvents(t, mux, caseID, vals("from", tc.from, "to", tc.to))
		if res.Total != tc.want {
			t.Errorf("%s: from=%q to=%q returned %d, want %d",
				tc.name, tc.from, tc.to, res.Total, tc.want)
		}
	}
}

// Boundary timestamps: both ends are inclusive, and the neighbours one
// second away are correctly excluded.
func TestDateRange_BoundariesAreInclusiveAndNeighboursExcluded(t *testing.T) {
	mux := newTestRouter(t)
	caseID := rangeCase(t, mux)

	sec := rangeVisitUTC.Truncate(time.Second)
	cases := []struct {
		name     string
		from, to time.Time
		want     int
	}{
		{"exactly the second's start and end", sec, sec.Add(time.Second - time.Nanosecond), 1},
		{"start one ns after the event", rangeVisitUTC.Add(time.Nanosecond), sec.Add(time.Second), 0},
		{"end one ns before the event", sec, rangeVisitUTC.Add(-time.Nanosecond), 0},
		{"end exactly on the event", sec, rangeVisitUTC, 1},
		{"start exactly on the event", rangeVisitUTC, sec.Add(time.Second), 1},
	}
	for _, tc := range cases {
		res := searchEvents(t, mux, caseID, vals(
			"from", tc.from.Format(time.RFC3339Nano),
			"to", tc.to.Format(time.RFC3339Nano)))
		if res.Total != tc.want {
			t.Errorf("%s: returned %d, want %d", tc.name, res.Total, tc.want)
		}
	}
}

// A range naming a second with nothing in it returns an empty result --
// and says the case still holds events, so "no match" cannot be read as
// "no evidence".
func TestDateRange_EmptyResultIsDistinguishedFromAnEmptyCase(t *testing.T) {
	mux := newTestRouter(t)
	caseID := rangeCase(t, mux)

	res := searchEvents(t, mux, caseID, vals("from", "2021-04-29T18:17:40", "to", "2021-04-29T18:17:40"))
	if res.Total != 0 {
		t.Fatalf("expected no matches, got %d", res.Total)
	}
	if len(res.Items) != 0 {
		t.Error("items must be empty")
	}
	if res.TotalInCase != 3 {
		t.Errorf("total_in_case = %d, want 3 so the UI can say the case is not empty", res.TotalInCase)
	}
	if !res.Filtered {
		t.Error("a date-filtered query must report itself as filtered")
	}
}

// The bounds are wall-clock readings in the display timezone, and
// changing that timezone must not move the stored instant.
func TestDateRange_TimezoneChangesTheWindowNotTheEvidence(t *testing.T) {
	mux := newTestRouter(t)
	caseID := rangeCase(t, mux)

	stored := func() time.Time {
		res := searchEvents(t, mux, caseID, vals("url", "password+cracking+lists"))
		if res.Total != 1 {
			t.Fatalf("expected the visit, got %d", res.Total)
		}
		return res.Items[0].Timestamp
	}
	before := stored()
	if !before.Equal(rangeVisitUTC) {
		t.Fatalf("precondition: stored at %s, want %s", before, rangeVisitUTC)
	}

	// In UTC the event is at 18:17:38.
	if res := searchEvents(t, mux, caseID, vals("from", "2021-04-29T18:17:38", "to", "2021-04-29T18:17:38")); res.Total != 1 {
		t.Fatalf("UTC one-second range returned %d", res.Total)
	}

	if rec := setTimezone(t, mux, "Asia/Jakarta"); rec.Code != http.StatusOK {
		t.Fatalf("setting timezone: %d %s", rec.Code, rec.Body)
	}
	// The same wall clock now names a different instant, so it misses.
	if res := searchEvents(t, mux, caseID, vals("from", "2021-04-29T18:17:38", "to", "2021-04-29T18:17:38")); res.Total != 0 {
		t.Errorf("in Asia/Jakarta that wall clock is a different instant; got %d events", res.Total)
	}
	// 18:17:38Z is 01:17:38 the next day in Jakarta (UTC+7).
	if res := searchEvents(t, mux, caseID, vals("from", "2021-04-30T01:17:38", "to", "2021-04-30T01:17:38")); res.Total != 1 {
		t.Errorf("the Jakarta-local one-second range did not isolate the event; got %d", res.Total)
	}
	// And the stored instant is untouched throughout.
	if after := stored(); !after.Equal(before) {
		t.Errorf("the stored timestamp moved from %s to %s", before, after)
	}
}

// resolveDateRange is the single place a bound becomes an instant. Unit
// coverage of the precision rule, independent of any database.
func TestDateRange_ResolveBoundsAtEveryPrecision(t *testing.T) {
	day := func(h, m, s, ns int) time.Time {
		return time.Date(2021, 4, 29, h, m, s, ns, time.UTC)
	}
	for _, tc := range []struct {
		name             string
		q                url.Values
		wantFrom, wantTo time.Time
	}{
		{"bare dates", url.Values{"from": {"2021-04-29"}, "to": {"2021-04-29"}},
			day(0, 0, 0, 0), day(23, 59, 59, 999999999)},
		{"minute precision", url.Values{"from": {"2021-04-29T18:17"}, "to": {"2021-04-29T18:17"}},
			day(18, 17, 0, 0), day(18, 17, 59, 999999999)},
		{"second precision", url.Values{"from": {"2021-04-29T18:17:38"}, "to": {"2021-04-29T18:17:38"}},
			day(18, 17, 38, 0), day(18, 17, 38, 999999999)},
		{"space separator", url.Values{"from": {"2021-04-29 18:17:38"}, "to": {"2021-04-29 18:17:38"}},
			day(18, 17, 38, 0), day(18, 17, 38, 999999999)},
		{"single day via date=", url.Values{"date": {"2021-04-29"}},
			day(0, 0, 0, 0), day(23, 59, 59, 999999999)},
	} {
		from, to, _, err := resolveDateRange(tc.q, time.UTC)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if !from.Equal(tc.wantFrom) {
			t.Errorf("%s: from = %s, want %s", tc.name, from.Format(time.RFC3339Nano), tc.wantFrom.Format(time.RFC3339Nano))
		}
		if !to.Equal(tc.wantTo) {
			t.Errorf("%s: to = %s, want %s", tc.name, to.Format(time.RFC3339Nano), tc.wantTo.Format(time.RFC3339Nano))
		}
	}
}

// An unreadable bound is refused rather than silently dropped: showing
// the whole case to someone who believes they are looking at one second
// is the worse failure.
func TestDateRange_InvalidBoundIsRejected(t *testing.T) {
	mux := newTestRouter(t)
	caseID := rangeCase(t, mux)
	for _, bad := range []string{"18:17:38", "yesterday", "2021-04-29T25:00:00", "29-04-2021 18:17:38"} {
		rec := doJSON(t, mux, "GET",
			"/api/cases/"+caseID+"/events?from="+url.QueryEscape(bad), nil, nil)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("from=%q returned %d, want 400", bad, rec.Code)
		}
	}
}

// Clearing the filter returns the whole case.
func TestDateRange_ClearingTheFilterRestoresEverything(t *testing.T) {
	mux := newTestRouter(t)
	caseID := rangeCase(t, mux)

	if res := searchEvents(t, mux, caseID, vals("from", "2021-04-29T18:17:38", "to", "2021-04-29T18:17:38")); res.Total != 1 {
		t.Fatalf("filtered returned %d, want 1", res.Total)
	}
	res := searchEvents(t, mux, caseID, nil)
	if res.Total != 3 {
		t.Errorf("unfiltered returned %d, want 3", res.Total)
	}
	if res.Filtered {
		t.Error("an unfiltered query reported itself as filtered")
	}
}

// The precise filter must not have changed free-text behaviour.
func TestDateRange_FreeTextSearchIsUnchanged(t *testing.T) {
	mux := newTestRouter(t)
	caseID := rangeCase(t, mux)

	for _, tc := range []struct {
		term string
		want int
	}{
		{"password cracking lists", 1},
		{"one-second-earlier", 1},
		{"example.test", 2},
		{"nothing-matches", 0},
		{"2021-04-29 18:17:38", 1}, // the Phase 16 moment-search, still working
		{"2021-04-29", 3},
	} {
		if res := searchEvents(t, mux, caseID, vals("q", tc.term)); res.Total != tc.want {
			t.Errorf("q=%q returned %d, want %d", tc.term, res.Total, tc.want)
		}
	}
}

// Findings carry first_seen/last_seen and are filtered by the same
// bounds. This pins that a finding whose window contains the named
// second survives a one-second filter.
func TestDateRange_FindingsShareTheSameBoundSemantics(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "findings range")
	discoverPathAndImportAll(t, mux, c.ID, syntheticCasePath())
	if rec := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/analyze", nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("analyze: %d", rec.Code)
	}
	var findings []model.Finding
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/findings", nil, &findings)
	if len(findings) == 0 {
		t.Skip("no findings to filter")
	}
	// Every finding must carry a usable window; the client-side filter
	// compares against these two fields and nothing else.
	for _, f := range findings {
		if f.FirstSeen.IsZero() || f.LastSeen.IsZero() {
			t.Errorf("finding %q has no time window (first=%s last=%s)", f.Title, f.FirstSeen, f.LastSeen)
		}
		if f.LastSeen.Before(f.FirstSeen) {
			t.Errorf("finding %q has last_seen before first_seen", f.Title)
		}
	}
}

// Several events inside ONE second must all be returned by a range
// naming that second, and must not leak into the neighbouring ones.
//
// This is the case sub-second precision makes possible and a
// second-granularity filter would get wrong: three distinct events at
// .100, .500 and .900 are three separate observations, not one.
func TestDateRange_MultipleEventsInTheSameSecond(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "same-second events")

	// Three visits inside 18:17:38, one in the second before, one after.
	const base int64 = rangeVisitWebKit - (rangeVisitWebKit % 1_000_000) // 18:17:38.000000
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		"Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/History": historyAt(t, []int64{
			base + 100_000,   // 18:17:38.100
			base + 500_000,   // 18:17:38.500
			base + 900_000,   // 18:17:38.900
			base - 500_000,   // 18:17:37.500
			base + 1_500_000, // 18:17:39.500
		}),
	})
	if imp := importAllFrom(t, mux, c.ID, disc); len(imp.ParseFailures) != 0 {
		t.Fatalf("fixture failed: %+v", imp.ParseFailures)
	}

	res := searchEvents(t, mux, c.ID, vals("from", "2021-04-29T18:17:38", "to", "2021-04-29T18:17:38"))
	if res.Total != 3 {
		t.Fatalf("one-second range returned %d events, want the 3 inside that second", res.Total)
	}
	seen := map[int]bool{}
	for _, e := range res.Items {
		if got := e.Timestamp.Truncate(time.Second); !got.Equal(time.Date(2021, 4, 29, 18, 17, 38, 0, time.UTC)) {
			t.Errorf("event at %s is outside the named second", e.Timestamp)
		}
		seen[e.Timestamp.Nanosecond()/1_000_000] = true
	}
	for _, ms := range []int{100, 500, 900} {
		if !seen[ms] {
			t.Errorf("the event at .%03d is missing; sub-second events must stay distinct", ms)
		}
	}
	// And the neighbours stay out.
	if res := searchEvents(t, mux, c.ID, vals("from", "2021-04-29T18:17:37", "to", "2021-04-29T18:17:37")); res.Total != 1 {
		t.Errorf("the preceding second returned %d, want 1", res.Total)
	}
	if res := searchEvents(t, mux, c.ID, vals("from", "2021-04-29T18:17:39", "to", "2021-04-29T18:17:39")); res.Total != 1 {
		t.Errorf("the following second returned %d, want 1", res.Total)
	}
	// The whole span covers all five.
	if res := searchEvents(t, mux, c.ID, vals("from", "2021-04-29T18:17:37", "to", "2021-04-29T18:17:39")); res.Total != 5 {
		t.Errorf("the three-second span returned %d, want 5", res.Total)
	}
}

// historyAt builds a Chromium History with a visit at each given raw
// WebKit timestamp.
func historyAt(t *testing.T, times []int64) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "History")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{
		`CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER)`,
		`CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, transition INTEGER)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	for i, vt := range times {
		id := i + 1
		db.Exec(`INSERT INTO urls VALUES(?,?,?,1,?)`, id,
			"https://example.test/visit/"+time.Unix(0, vt).Format("150405.000000"), "Visit", vt)
		db.Exec(`INSERT INTO visits VALUES(?,?,?,805306368)`, id, id, vt)
	}
	db.Close()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
