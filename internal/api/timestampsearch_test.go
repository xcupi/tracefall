package api

import (
	"database/sql"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"tracefall/internal/model"
)

// Searching the timeline for a TIMESTAMP.
//
// # The failure this pins
//
// An analyst searched a real case for "2021-04-29 18:17:38" and got zero
// events, for a Chromium History visit that was present, correctly
// parsed and stored at exactly that instant. The parser was right; the
// SEARCH was the problem -- free text reads string fields, and no string
// field contains a timestamp, so a term naming a moment could never
// match anything. The evidence was reachable only through the date
// picker.
//
// Answering "no events" for evidence that exists is a retrieval failure,
// and the fix is that a free-text term naming a moment now also searches
// that moment (see searchTermMoment).
//
// # About the values below
//
// The raw visit_time, the URL and the title were OBSERVED in real
// evidence, and are reproduced here in a synthetic Chromium History so
// the regression is pinned to what actually happens rather than to a
// value invented to make the test pass. No evidence file is committed;
// the fixture is built by this test.
const (
	// The raw Chromium visit_time as stored: microseconds since
	// 1601-01-01 UTC (the WebKit epoch).
	observedWebKitVisitTime = 13264193858900891
	observedVisitURL        = "https://www.google.com/search?q=password+cracking+lists&rlz=1C1VDKB_enUS951US951"
	observedVisitTitle      = "password cracking lists - Google Search"
)

// observedVisitUTC is what that raw value must convert to. Computed
// here from the epoch definition rather than pasted, so the test states
// the arithmetic it is asserting.
var observedVisitUTC = time.Unix(
	observedWebKitVisitTime/1_000_000-11644473600,
	(observedWebKitVisitTime%1_000_000)*1000).UTC()

// chromiumHistoryWithObservedVisit builds a Chromium History carrying
// the observed visit, plus neighbours a second either side so a
// second-precision search has something to exclude.
func chromiumHistoryWithObservedVisit(t *testing.T) []byte {
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
		id    int
		vt    int64
		url   string
		title string
	}{
		{1, observedWebKitVisitTime, observedVisitURL, observedVisitTitle},
		{2, observedWebKitVisitTime - 1_000_000, "https://example.test/one-second-earlier", "Earlier"},
		{3, observedWebKitVisitTime + 1_000_000, "https://example.test/one-second-later", "Later"},
	}
	for _, r := range rows {
		if _, err := db.Exec(`INSERT INTO urls VALUES(?,?,?,1,?)`, r.id, r.url, r.title, r.vt); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO visits VALUES(?,?,?,805306368)`, r.id, r.id, r.vt); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func historyCase(t *testing.T, mux http.Handler) string {
	t.Helper()
	c := mustCreateCase(t, mux, "timestamp search "+t.Name())
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		"Users/John Doe/AppData/Local/Google/Chrome/User Data/Default/History": chromiumHistoryWithObservedVisit(t),
	})
	imp := importAllFrom(t, mux, c.ID, disc)
	if len(imp.ParseFailures) != 0 {
		t.Fatalf("fixture failed to parse: %+v", imp.ParseFailures)
	}
	return c.ID
}

// The raw WebKit value must convert to the observed UTC instant. This is
// the parser half of the chain, asserted against the value as stored.
func TestTimestampSearch_WebKitConversionMatchesTheObservedInstant(t *testing.T) {
	mux := newTestRouter(t)
	caseID := historyCase(t, mux)

	res := searchEvents(t, mux, caseID, vals("artifact_type", model.ArtifactBrowserHistory, "page_size", "50"))
	if res.Total != 3 {
		t.Fatalf("got %d visits, want 3", res.Total)
	}
	var found *TimelineEvent
	for i := range res.Items {
		if res.Items[i].Extra["url"] == observedVisitURL {
			found = &res.Items[i]
		}
	}
	if found == nil {
		t.Fatal("the observed visit did not become an event")
	}
	if !found.Timestamp.Equal(observedVisitUTC) {
		t.Errorf("stored timestamp = %s, want %s (from raw visit_time %d)",
			found.Timestamp.Format(time.RFC3339Nano),
			observedVisitUTC.Format(time.RFC3339Nano), observedWebKitVisitTime)
	}
	// Sub-second precision must survive: truncating to the second would
	// still satisfy a second-wide search but loses ordering fidelity.
	if found.Timestamp.Nanosecond() == 0 {
		t.Error("sub-second precision was lost in conversion")
	}
	if got := found.Extra["page_title"]; got != observedVisitTitle {
		t.Errorf("page title = %q, want %q", got, observedVisitTitle)
	}
}

// The regression itself: a timestamp typed into the SEARCH BOX must find
// the event at that moment.
func TestTimestampSearch_FreeTextTimestampFindsTheEvent(t *testing.T) {
	mux := newTestRouter(t)
	caseID := historyCase(t, mux)

	for _, term := range []string{
		"2021-04-29 18:17:38",
		"2021-04-29T18:17:38",
	} {
		res := searchEvents(t, mux, caseID, vals("q", term))
		if res.Total == 0 {
			t.Errorf("searching %q returned nothing; the event at that instant is present", term)
			continue
		}
		if res.Total != 1 {
			t.Errorf("searching %q returned %d events, want just the one in that second", term, res.Total)
		}
		e := res.Items[0]
		if e.Extra["url"] != observedVisitURL {
			t.Errorf("searching %q found %q, want the observed visit", term, e.Extra["url"])
		}
		if !e.Timestamp.Equal(observedVisitUTC) {
			t.Errorf("searching %q found an event at %s", term, e.Timestamp)
		}
		// The row must carry what makes it usable as evidence.
		if e.Extra["page_title"] == "" {
			t.Error("the matched event carries no page title")
		}
		if e.ArtifactLabel == "" {
			t.Error("the matched event carries no artifact label")
		}
	}
}

// Precision must be honoured: a second means that second, a minute that
// minute, a day that day. Widening a pasted timestamp to its whole day
// would bury the event the analyst came for.
func TestTimestampSearch_PrecisionOfTheTermSetsTheWindow(t *testing.T) {
	mux := newTestRouter(t)
	caseID := historyCase(t, mux)

	for _, tc := range []struct {
		term string
		want int
	}{
		{"2021-04-29 18:17:38", 1}, // that second
		{"2021-04-29 18:17", 3},    // that minute: all three visits
		{"2021-04-29", 3},          // that day
		{"2021-04-28", 0},          // a day with nothing
		{"2021-04-29 18:18", 0},    // a minute with nothing
	} {
		res := searchEvents(t, mux, caseID, vals("q", tc.term))
		if res.Total != tc.want {
			t.Errorf("searching %q returned %d events, want %d", tc.term, res.Total, tc.want)
		}
	}
}

// A timestamp search must be interpreted in the display timezone, like
// every other time input -- otherwise the search disagrees with the
// timestamps rendered beside it.
func TestTimestampSearch_IsInterpretedInTheDisplayTimezone(t *testing.T) {
	mux := newTestRouter(t)
	caseID := historyCase(t, mux)

	if res := searchEvents(t, mux, caseID, vals("q", "2021-04-29 18:17:38")); res.Total != 1 {
		t.Fatalf("precondition: in UTC the visit is at 18:17:38, got %d", res.Total)
	}
	if rec := setTimezone(t, mux, "Asia/Jakarta"); rec.Code != http.StatusOK {
		t.Fatalf("setting timezone: %d %s", rec.Code, rec.Body)
	}
	// 18:17:38Z is 01:17:38 the next day in Jakarta (UTC+7).
	if res := searchEvents(t, mux, caseID, vals("q", "2021-04-29 18:17:38")); res.Total != 0 {
		t.Errorf("in Asia/Jakarta that wall clock names a different instant; got %d events", res.Total)
	}
	if res := searchEvents(t, mux, caseID, vals("q", "2021-04-30 01:17:38")); res.Total != 1 {
		t.Errorf("in Asia/Jakarta the visit is at 2021-04-30 01:17:38; got %d events", res.Total)
	}
}

// An ordinary term must be unaffected, and a term that is BOTH text and
// a date must still match text -- the time window is OR'd, not a
// replacement.
func TestTimestampSearch_OrdinaryTermsAreUnaffected(t *testing.T) {
	mux := newTestRouter(t)
	caseID := historyCase(t, mux)

	if res := searchEvents(t, mux, caseID, vals("q", "password cracking lists")); res.Total != 1 {
		t.Errorf("a text search returned %d events, want 1", res.Total)
	}
	if res := searchEvents(t, mux, caseID, vals("q", "one-second-earlier")); res.Total != 1 {
		t.Errorf("a URL-fragment search returned %d events, want 1", res.Total)
	}
	if res := searchEvents(t, mux, caseID, vals("q", "nothing-matches-this")); res.Total != 0 {
		t.Errorf("a non-matching term returned %d events", res.Total)
	}
	// Not a moment, and must not be mistaken for one.
	for _, notATime := range []string{"2021", "20210429", "18:17:38", "2021-13-45 99:99:99"} {
		res := searchEvents(t, mux, caseID, vals("q", notATime))
		if res.Total != 0 {
			t.Errorf("%q matched %d events; it names no moment and no field", notATime, res.Total)
		}
	}
}

// Provenance must resolve from an event found by timestamp, exactly as
// from one found any other way.
func TestTimestampSearch_MatchedEventTracesBackToItsEvidence(t *testing.T) {
	mux := newTestRouter(t)
	caseID := historyCase(t, mux)

	res := searchEvents(t, mux, caseID, vals("q", "2021-04-29 18:17:38"))
	if res.Total != 1 {
		t.Fatalf("got %d events", res.Total)
	}
	var prov EventProvenance
	rec := doJSON(t, mux, "GET", "/api/cases/"+caseID+"/events/"+res.Items[0].ID, nil, &prov)
	if rec.Code != http.StatusOK {
		t.Fatalf("provenance: %d %s", rec.Code, rec.Body.String())
	}
	if prov.RawEvidence.Raw == "" {
		t.Error("no raw record")
	}
	if prov.SourceFile.Path == "" {
		t.Error("the event does not name the History database it came from")
	}
	if prov.SourceFile.ArtifactType != model.ArtifactBrowserHistory {
		t.Errorf("source file artifact type = %q", prov.SourceFile.ArtifactType)
	}
	if prov.Collection == nil || prov.Collection.CollectionID == "" {
		t.Error("the event does not resolve to a collection")
	}
}
