package api

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"tracefall/internal/model"
	"tracefall/internal/recyclebin/rbgen"
)

// Phase 14: the forensic timeline.
//
// These tests are about VISIBILITY, not about parsing. Each one asks the
// same underlying question from a different angle: can an analyst find,
// filter, page through and trace an event that a parser already
// produced, without that event having had to become a finding first?

// phase14Visit is the browser visit the Chrome History acceptance test
// looks for. The date is the one the walkthrough uses; the URL is
// synthetic and invented here.
//
// It is a search-engine query URL because that is the shape of evidence
// the acceptance case turns on, but NOTHING in the implementation knows
// that: the search term lives only in this fixture, is read back out of
// the parsed evidence, and is never referenced by name in any non-test
// file. TestPhase14_NoHardcodedAcceptanceTerm enforces that.
var (
	phase14VisitAt    = time.Date(2021, 4, 29, 18, 17, 38, 0, time.UTC)
	phase14SearchTerm = "unattended workstation lockout policy"
	phase14VisitURL   = "https://search.example.test/results?q=" + url.QueryEscape(phase14SearchTerm)
	phase14DeletedAt  = time.Date(2021, 4, 29, 18, 15, 12, 0, time.UTC)
	phase14DeletedTo  = `C:\Users\jdoe\Documents\quarterly-figures.xlsx`
)

// phase14ChromeHistory builds a Chromium History database holding one
// visit at phase14VisitAt plus a handful of unrelated visits on other
// days, so a date filter has something to exclude.
func phase14ChromeHistory(t *testing.T) []byte {
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
	// Chromium stores microseconds since 1601-01-01 UTC.
	chromeTime := func(at time.Time) int64 { return (at.Unix() + 11644473600) * 1_000_000 }
	rows := []struct {
		id    int
		url   string
		title string
		at    time.Time
	}{
		{1, phase14VisitURL, "Search results", phase14VisitAt},
		{2, "https://intranet.example.test/hr/handbook", "Handbook", phase14VisitAt.AddDate(0, 0, -3)},
		{3, "https://docs.example.test/reference", "Reference", phase14VisitAt.AddDate(0, 0, 5)},
	}
	for _, r := range rows {
		if _, err := db.Exec(`INSERT INTO urls VALUES(?,?,?,1,?)`, r.id, r.url, r.title, chromeTime(r.at)); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO visits VALUES(?,?,?,805306368)`, r.id, r.id, chromeTime(r.at)); err != nil {
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

// phase14IRecord is a Recycle Bin $I record for the acceptance test:
// a real original path, name, size and deletion time.
func phase14IRecord() []byte {
	return rbgen.Build(rbgen.Record{
		Version: 2, Size: 20480, Deleted: phase14DeletedAt, Path: phase14DeletedTo,
	})
}

// phase14Catalog is one evidence collection spanning every artifact
// family that currently reaches the event layer.
func phase14Catalog(t *testing.T) map[string][]byte {
	t.Helper()
	return map[string][]byte{
		"Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/History":           phase14ChromeHistory(t),
		`C/$Recycle.Bin/S-1-5-21-1004336348-1177238915-682003330-1001/$IA1B2C3.xlsx`: phase14IRecord(),
		"Windows/Prefetch/UPDATE.EXE-0BADF00D.pf":                                    samplePrefetch(),
		"Users/jdoe/AppData/Roaming/Microsoft/Windows/Recent/report.lnk":             sampleLNK(),
		"C/$MFT":       sampleMFT(),
		"C/$Extend/$J": sampleUsnJournal(),
	}
}

// phase14Case imports the catalog and returns the case id.
func phase14Case(t *testing.T, mux http.Handler) string {
	t.Helper()
	c := mustCreateCase(t, mux, "Phase 14 timeline "+t.Name())
	disc := discoverBinaryDir(t, mux, c.ID, phase14Catalog(t))
	imp := importAllFrom(t, mux, c.ID, disc)
	if len(imp.ParseFailures) != 0 {
		t.Fatalf("fixture failed to parse: %+v", imp.ParseFailures)
	}
	if imp.EventCount == 0 {
		t.Fatal("fixture produced no events")
	}
	return c.ID
}

// searchEvents runs one timeline query and decodes the page.
func searchEvents(t *testing.T, mux http.Handler, caseID string, q url.Values) EventSearchResponse {
	t.Helper()
	path := "/api/cases/" + caseID + "/events"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var res EventSearchResponse
	rec := doJSON(t, mux, "GET", path, nil, &res)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: status %d, body %s", path, rec.Code, rec.Body.String())
	}
	return res
}

// syntheticCasePath is the bundled synthetic evidence directory, used
// where a test needs a case that actually produces findings.
func syntheticCasePath() string {
	return filepath.Join("..", "..", "testdata", "synthetic_case")
}

func vals(pairs ...string) url.Values {
	v := url.Values{}
	for i := 0; i+1 < len(pairs); i += 2 {
		v.Add(pairs[i], pairs[i+1])
	}
	return v
}

// setTimezone changes the application display timezone.
func setTimezone(t *testing.T, mux http.Handler, tz string) *httpRecorder {
	t.Helper()
	rec := doJSON(t, mux, "PUT", "/api/settings", map[string]string{"timezone": tz}, nil)
	return &httpRecorder{Code: rec.Code, Body: rec.Body.String()}
}

type httpRecorder struct {
	Code int
	Body string
}

// ---------------- A. Event search ----------------

func TestPhase14_EventSearchReturnsEventsWithoutAnalysis(t *testing.T) {
	mux := newTestRouter(t)
	caseID := phase14Case(t, mux)

	// Deliberately no /analyze call: raw events must be searchable
	// before, and without, any detection ever running.
	res := searchEvents(t, mux, caseID, nil)

	if res.Total == 0 {
		t.Fatal("no events returned from an imported case that has events")
	}
	if res.TotalInCase != res.Total {
		t.Errorf("unfiltered search total = %d, case holds %d; an unfiltered query must match everything",
			res.Total, res.TotalInCase)
	}
	if res.Filtered {
		t.Error("an unfiltered query reported itself as filtered")
	}
	for _, e := range res.Items {
		if e.ID == "" || e.EventType == "" || e.ArtifactType == "" {
			t.Errorf("event missing identity fields: %+v", e.Event)
		}
		if e.ArtifactLabel == "" {
			t.Errorf("event %s (%s) has no human-readable artifact label", e.ID, e.ArtifactType)
		}
	}
}

// ---------------- N. Chrome History acceptance ----------------

// The Phase 14 acceptance criterion, stated as a test: a Chrome History
// visit recorded on 2021-04-29 must be findable by that date in the
// forensic event layer, WITHOUT any finding existing for it.
func TestPhase14_ChromeHistoryVisitIsFindableByDate(t *testing.T) {
	mux := newTestRouter(t)
	caseID := phase14Case(t, mux)

	res := searchEvents(t, mux, caseID, vals("date", "2021-04-29"))
	if res.Total == 0 {
		t.Fatal("searching 2021-04-29 returned nothing; the Chrome History visit on that date is invisible")
	}

	var visit *TimelineEvent
	for i, e := range res.Items {
		if e.ArtifactType == model.ArtifactBrowserHistory {
			visit = &res.Items[i]
			break
		}
	}
	if visit == nil {
		t.Fatalf("2021-04-29 matched %d events but none was a browser history visit", res.Total)
	}
	if visit.EventType != model.EventBrowserVisit {
		t.Errorf("event type = %q, want %q", visit.EventType, model.EventBrowserVisit)
	}
	if got := visit.Extra["url"]; got != phase14VisitURL {
		t.Errorf("URL = %q, want %q", got, phase14VisitURL)
	}
	if !visit.Timestamp.Equal(phase14VisitAt) {
		t.Errorf("timestamp = %s, want %s", visit.Timestamp, phase14VisitAt)
	}
	if !visit.TimestampKnown {
		t.Error("a recorded browser visit reported timestamp_known = false")
	}
	// The whole point of the phase: no detection is required.
	if len(visit.Findings) != 0 {
		t.Errorf("the visit carries %d findings; this fixture should raise none, and visibility must not depend on one",
			len(visit.Findings))
	}
}

// The same event must also be reachable by searching its content, since
// an analyst rarely knows the date first.
func TestPhase14_ChromeHistoryVisitIsFindableByItsSearchText(t *testing.T) {
	mux := newTestRouter(t)
	caseID := phase14Case(t, mux)

	// A word out of the recorded query string, read from the fixture --
	// never a constant the implementation knows.
	term := strings.Fields(phase14SearchTerm)[0]
	res := searchEvents(t, mux, caseID, vals("q", term))
	if res.Total == 0 {
		t.Fatalf("free-text %q matched nothing, though it appears in a recorded URL", term)
	}
	found := false
	for _, e := range res.Items {
		if e.ArtifactType == model.ArtifactBrowserHistory && strings.Contains(e.Extra["url"], term) {
			found = true
		}
	}
	if !found {
		t.Error("free-text search did not reach the URL recorded in browser history")
	}
}

// ---------------- O. Recycle Bin acceptance ----------------

func TestPhase14_RecycleBinDeletionIsVisibleWithItsRecordedFields(t *testing.T) {
	mux := newTestRouter(t)
	caseID := phase14Case(t, mux)

	res := searchEvents(t, mux, caseID, vals("artifact_type", model.ArtifactRecycleBin))
	if res.Total != 1 {
		t.Fatalf("recycle bin events = %d, want 1", res.Total)
	}
	e := res.Items[0]

	if e.EventType != model.EventRecycleBinDeletion {
		t.Errorf("event type = %q, want %q", e.EventType, model.EventRecycleBinDeletion)
	}
	if !e.Timestamp.Equal(phase14DeletedAt) {
		t.Errorf("deletion timestamp = %s, want %s", e.Timestamp, phase14DeletedAt)
	}
	// Every field the acceptance criterion names, read off the event.
	checks := map[string]string{
		"original_path":      phase14DeletedTo,
		"original_name":      "quarterly-figures.xlsx",
		"original_size":      "20480",
		"record_version":     "2",
		"original_directory": `C:\Users\jdoe\Documents`,
	}
	for key, want := range checks {
		if got := e.Extra[key]; got != want {
			t.Errorf("extra[%q] = %q, want %q", key, got, want)
		}
	}
	// Provenance must resolve from the timeline row.
	var prov EventProvenance
	rec := doJSON(t, mux, "GET", "/api/cases/"+caseID+"/events/"+e.ID, nil, &prov)
	if rec.Code != http.StatusOK {
		t.Fatalf("provenance: %d %s", rec.Code, rec.Body.String())
	}
	if prov.SourceFile.Path == "" {
		t.Error("the deletion record does not resolve back to a source file")
	}
}

// The deleted file must be findable by the path it had BEFORE deletion,
// which is the only path an investigator knows to search for.
func TestPhase14_DeletedFileIsFoundByItsOriginalPath(t *testing.T) {
	mux := newTestRouter(t)
	caseID := phase14Case(t, mux)

	res := searchEvents(t, mux, caseID, vals("original_path", "quarterly-figures.xlsx"))
	if res.Total != 1 {
		t.Fatalf("original_path search matched %d events, want 1", res.Total)
	}
	if res.Items[0].ArtifactType != model.ArtifactRecycleBin {
		t.Errorf("matched %s, want a recycle bin record", res.Items[0].ArtifactType)
	}
}

// ---------------- B / K. Date range, and its timezone ----------------

func TestPhase14_DateRangeExcludesOtherDays(t *testing.T) {
	mux := newTestRouter(t)
	caseID := phase14Case(t, mux)

	all := searchEvents(t, mux, caseID, nil)
	day := searchEvents(t, mux, caseID, vals("date", "2021-04-29"))
	if day.Total >= all.Total {
		t.Fatalf("date filter matched %d of %d events; it excluded nothing", day.Total, all.Total)
	}
	for _, e := range day.Items {
		y, m, d := e.Timestamp.UTC().Date()
		if y != 2021 || m != time.April || d != 29 {
			t.Errorf("event %s at %s is outside the requested UTC day", e.ID, e.Timestamp)
		}
	}
}

// The requirement that makes the timezone setting real: selecting a
// calendar date must map to that date IN THE ANALYST'S ZONE, not in UTC.
//
// phase14VisitAt is 2021-04-29 18:17:38Z, which in Asia/Jakarta (UTC+7)
// is 2021-04-30 01:17:38. So in Jakarta the visit belongs to the 30th,
// and asking for the 29th must NOT return it -- the exact off-by-one an
// analyst would otherwise carry into a report.
func TestPhase14_DateRangeIsInterpretedInTheDisplayTimezone(t *testing.T) {
	mux := newTestRouter(t)
	caseID := phase14Case(t, mux)

	utcDay := searchEvents(t, mux, caseID, vals("date", "2021-04-29"))
	utcHasVisit := containsArtifact(utcDay.Items, model.ArtifactBrowserHistory)
	if !utcHasVisit {
		t.Fatal("precondition: in UTC the visit belongs to 2021-04-29")
	}

	if rec := setTimezone(t, mux, "Asia/Jakarta"); rec.Code != http.StatusOK {
		t.Fatalf("setting timezone: %d %s", rec.Code, rec.Body)
	}

	jkt29 := searchEvents(t, mux, caseID, vals("date", "2021-04-29"))
	if containsArtifact(jkt29.Items, model.ArtifactBrowserHistory) {
		t.Error("in Asia/Jakarta the 18:17Z visit falls on 30 April, but searching 29 April returned it")
	}
	jkt30 := searchEvents(t, mux, caseID, vals("date", "2021-04-30"))
	if !containsArtifact(jkt30.Items, model.ArtifactBrowserHistory) {
		t.Error("in Asia/Jakarta the visit falls on 30 April, but searching that date did not return it")
	}

	// The response must SAY which instants it queried, so the conversion
	// is checkable rather than implicit.
	if jkt30.Range.Timezone != "Asia/Jakarta" {
		t.Errorf("range timezone = %q, want Asia/Jakarta", jkt30.Range.Timezone)
	}
	if jkt30.Range.From == "" || jkt30.Range.To == "" {
		t.Errorf("range bounds not reported: %+v", jkt30.Range)
	}
	from, err := time.Parse(time.RFC3339Nano, jkt30.Range.From)
	if err != nil {
		t.Fatalf("range.from is not a timestamp: %v", err)
	}
	// 2021-04-30 00:00 +07:00 == 2021-04-29 17:00Z
	if want := time.Date(2021, 4, 29, 17, 0, 0, 0, time.UTC); !from.Equal(want) {
		t.Errorf("range.from = %s, want %s", from.UTC(), want)
	}
}

func containsArtifact(events []TimelineEvent, artifactType string) bool {
	for _, e := range events {
		if e.ArtifactType == artifactType {
			return true
		}
	}
	return false
}

// A date search must not be a string prefix match on the stored format.
func TestPhase14_DateSearchIsNotAStringPrefixMatch(t *testing.T) {
	mux := newTestRouter(t)
	caseID := phase14Case(t, mux)
	if rec := setTimezone(t, mux, "Asia/Jakarta"); rec.Code != http.StatusOK {
		t.Fatalf("setting timezone: %d %s", rec.Code, rec.Body)
	}
	res := searchEvents(t, mux, caseID, vals("date", "2021-04-30"))
	if !containsArtifact(res.Items, model.ArtifactBrowserHistory) {
		t.Fatal("no visit returned")
	}
	for _, e := range res.Items {
		if e.ArtifactType != model.ArtifactBrowserHistory {
			continue
		}
		// The stored timestamp still begins "2021-04-29", so a prefix
		// match on the stored string could not have produced this row.
		if !strings.HasPrefix(e.Timestamp.UTC().Format(time.RFC3339), "2021-04-29") {
			t.Errorf("fixture assumption broken: stored time is %s", e.Timestamp.UTC())
		}
	}
}

func TestPhase14_InvalidDateIsRejectedRatherThanIgnored(t *testing.T) {
	mux := newTestRouter(t)
	caseID := phase14Case(t, mux)
	for _, bad := range []string{"29-04-2021", "2021-13-45", "yesterday", "2021/04/29"} {
		rec := doJSON(t, mux, "GET", "/api/cases/"+caseID+"/events?date="+url.QueryEscape(bad), nil, nil)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("date=%q returned %d; an unreadable date must not silently widen the search to the whole case",
				bad, rec.Code)
		}
	}
}

// ---------------- C / D. Artifact and event type filters ----------------

func TestPhase14_ArtifactAndEventTypeFiltersUseRealConstants(t *testing.T) {
	mux := newTestRouter(t)
	caseID := phase14Case(t, mux)

	var facets EventFacetsResponse
	rec := doJSON(t, mux, "GET", "/api/cases/"+caseID+"/events/facets", nil, &facets)
	if rec.Code != http.StatusOK {
		t.Fatalf("facets: %d %s", rec.Code, rec.Body.String())
	}
	if len(facets.ArtifactTypes) == 0 || len(facets.EventTypes) == 0 {
		t.Fatal("facets returned no artifact or event types for a case that has events")
	}

	// Every offered value must be a real stored value that returns rows,
	// and must carry a human label distinct from the raw constant only
	// where the registry provides one.
	for _, opt := range facets.ArtifactTypes {
		res := searchEvents(t, mux, caseID, vals("artifact_type", opt.Value))
		if res.Total == 0 {
			t.Errorf("artifact filter %q is offered but matches nothing", opt.Value)
		}
		for _, e := range res.Items {
			if e.ArtifactType != opt.Value {
				t.Errorf("artifact filter %q returned an event of type %q", opt.Value, e.ArtifactType)
			}
		}
		if opt.Label == "" {
			t.Errorf("artifact option %q has no label", opt.Value)
		}
	}
	for _, opt := range facets.EventTypes {
		res := searchEvents(t, mux, caseID, vals("event_type", opt.Value))
		if res.Total == 0 {
			t.Errorf("event type filter %q is offered but matches nothing", opt.Value)
		}
		for _, e := range res.Items {
			if e.EventType != opt.Value {
				t.Errorf("event type filter %q returned %q", opt.Value, e.EventType)
			}
		}
	}
}

// Values within one filter are OR'd; separate filters are AND'd. This is
// the same rule the evidence table uses, and getting it backwards would
// silently show an analyst less evidence than matched.
func TestPhase14_FiltersOrWithinAndAndAcross(t *testing.T) {
	mux := newTestRouter(t)
	caseID := phase14Case(t, mux)

	lnk := searchEvents(t, mux, caseID, vals("artifact_type", model.ArtifactLNK)).Total
	rb := searchEvents(t, mux, caseID, vals("artifact_type", model.ArtifactRecycleBin)).Total
	both := searchEvents(t, mux, caseID, vals("artifact_type", model.ArtifactLNK, "artifact_type", model.ArtifactRecycleBin))
	if both.Total != lnk+rb {
		t.Errorf("two artifact values matched %d, want %d (%d + %d): values within one filter must OR",
			both.Total, lnk+rb, lnk, rb)
	}

	crossed := searchEvents(t, mux, caseID,
		vals("artifact_type", model.ArtifactLNK, "event_type", model.EventRecycleBinDeletion))
	if crossed.Total != 0 {
		t.Errorf("LNK artifact AND recycle-bin event type matched %d events; separate filters must AND", crossed.Total)
	}
}

// ---------------- E. Free-text search ----------------

func TestPhase14_FreeTextReachesTypedAndExtraFields(t *testing.T) {
	mux := newTestRouter(t)
	caseID := phase14Case(t, mux)

	cases := []struct{ name, term string }{
		{"a URL fragment (extra.url)", "search.example.test"},
		{"a deleted file's original name (extra.original_name)", "quarterly-figures"},
		{"a shortcut target (extra.target_path)", "report.docx"},
		{"a filesystem path (file_path)", "notepad.exe"},
	}
	for _, tc := range cases {
		res := searchEvents(t, mux, caseID, vals("q", tc.term))
		if res.Total == 0 {
			t.Errorf("%s: free-text %q matched nothing", tc.name, tc.term)
		}
	}
}

func TestPhase14_FreeTextIsCaseInsensitive(t *testing.T) {
	mux := newTestRouter(t)
	caseID := phase14Case(t, mux)

	lower := searchEvents(t, mux, caseID, vals("q", "quarterly-figures")).Total
	upper := searchEvents(t, mux, caseID, vals("q", "QUARTERLY-FIGURES")).Total
	mixed := searchEvents(t, mux, caseID, vals("q", "Quarterly-Figures")).Total
	if lower == 0 {
		t.Fatal("precondition: the lowercase term matches nothing")
	}
	if upper != lower || mixed != lower {
		t.Errorf("case sensitivity leaked: lower=%d upper=%d mixed=%d", lower, upper, mixed)
	}
}

// Free-text must not reach internal identifiers. Searching an event's
// own id, or its dedup hash, must not return it: those are database
// plumbing, and matching them would mean an analyst's search term could
// collide with a row key.
func TestPhase14_FreeTextDoesNotSearchIdentifiersOrHashes(t *testing.T) {
	mux := newTestRouter(t)
	caseID := phase14Case(t, mux)

	all := searchEvents(t, mux, caseID, vals("page_size", "100"))
	if len(all.Items) == 0 {
		t.Fatal("no events")
	}
	e := all.Items[0]
	for _, tc := range []struct{ name, term string }{
		{"event id", e.ID},
		{"dedup hash", e.DedupHash},
		{"raw evidence id", e.RawEvidenceID},
		{"source file id", e.SourceFileID},
	} {
		if tc.term == "" {
			continue
		}
		res := searchEvents(t, mux, caseID, vals("q", tc.term))
		if res.Total != 0 {
			t.Errorf("free-text search on %s (%q) returned %d events; identifiers are not searchable",
				tc.name, tc.term, res.Total)
		}
	}
}

// ---------------- F / G / H. Pagination and ordering ----------------

func TestPhase14_PageSizesAndDefault(t *testing.T) {
	mux := newTestRouter(t)
	caseID := phase14Case(t, mux)

	def := searchEvents(t, mux, caseID, nil)
	if def.PageSize != 10 {
		t.Errorf("default page size = %d, want 10", def.PageSize)
	}
	for _, size := range []int{10, 25, 50, 100} {
		res := searchEvents(t, mux, caseID, vals("page_size", fmt.Sprint(size)))
		if res.PageSize != size {
			t.Errorf("page_size=%d honoured as %d", size, res.PageSize)
		}
		if len(res.Items) > size {
			t.Errorf("page_size=%d returned %d items", size, len(res.Items))
		}
	}
}

func TestPhase14_OversizedAndInvalidPagingIsHandledSafely(t *testing.T) {
	mux := newTestRouter(t)
	caseID := phase14Case(t, mux)

	// An arbitrary page size must fall back to the default rather than
	// materializing an unbounded response.
	for _, bad := range []string{"1000000", "-5", "0", "abc", "9999999999999999999"} {
		res := searchEvents(t, mux, caseID, vals("page_size", bad))
		if res.PageSize != 10 {
			t.Errorf("page_size=%q produced page size %d, want the default 10", bad, res.PageSize)
		}
		if len(res.Items) > 10 {
			t.Errorf("page_size=%q returned %d items", bad, len(res.Items))
		}
	}
	// A bad page number clamps to the first page; a page past the end is
	// empty rather than clamped, so the caller learns there is nothing
	// there instead of silently getting a different page.
	for _, bad := range []string{"-1", "0", "notanumber"} {
		res := searchEvents(t, mux, caseID, vals("page", bad))
		if res.Number != 1 {
			t.Errorf("page=%q produced page %d, want 1", bad, res.Number)
		}
	}
	far := searchEvents(t, mux, caseID, vals("page", "9999"))
	if len(far.Items) != 0 {
		t.Errorf("page 9999 returned %d items, want none", len(far.Items))
	}
	if far.Total == 0 {
		t.Error("a page past the end must still report the true total")
	}
}

// Paging must partition the result set exactly: every event once, none
// missing, none repeated -- the property that makes a page a view rather
// than a filter.
func TestPhase14_PagingIsAPartitionAndOrderIsDeterministic(t *testing.T) {
	mux := newTestRouter(t)
	caseID := phase14Case(t, mux)

	total := searchEvents(t, mux, caseID, nil).Total
	if total < 15 {
		t.Fatalf("fixture too small to page meaningfully: %d events", total)
	}

	collect := func(size int) []string {
		var ids []string
		for page := 1; ; page++ {
			res := searchEvents(t, mux, caseID, vals("page_size", fmt.Sprint(size), "page", fmt.Sprint(page)))
			if len(res.Items) == 0 {
				break
			}
			for _, e := range res.Items {
				ids = append(ids, e.ID)
			}
			if page > 200 {
				t.Fatal("pagination did not terminate")
			}
		}
		return ids
	}

	byTen := collect(10)
	byTwentyFive := collect(25)

	if len(byTen) != total {
		t.Errorf("paging by 10 yielded %d events, total says %d", len(byTen), total)
	}
	seen := map[string]int{}
	for _, id := range byTen {
		seen[id]++
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("event %s appeared %d times across pages", id, n)
		}
	}
	// Different page sizes must walk the same order.
	if len(byTen) != len(byTwentyFive) {
		t.Fatalf("page size changed the result set: %d vs %d", len(byTen), len(byTwentyFive))
	}
	for i := range byTen {
		if byTen[i] != byTwentyFive[i] {
			t.Fatalf("ordering differs by page size at position %d: %s vs %s", i, byTen[i], byTwentyFive[i])
		}
	}

	// And repeating the identical query must produce the identical order.
	again := collect(10)
	for i := range byTen {
		if byTen[i] != again[i] {
			t.Fatalf("repeating the same query changed the order at position %d", i)
		}
	}
}

func TestPhase14_OrderingIsNewestFirstByDefaultAndReversible(t *testing.T) {
	mux := newTestRouter(t)
	caseID := phase14Case(t, mux)

	desc := searchEvents(t, mux, caseID, vals("page_size", "100"))
	for i := 1; i < len(desc.Items); i++ {
		if desc.Items[i].Timestamp.After(desc.Items[i-1].Timestamp) {
			t.Fatalf("default order is not newest-first at position %d", i)
		}
	}
	asc := searchEvents(t, mux, caseID, vals("page_size", "100", "sort", "asc"))
	for i := 1; i < len(asc.Items); i++ {
		if asc.Items[i].Timestamp.Before(asc.Items[i-1].Timestamp) {
			t.Fatalf("sort=asc is not oldest-first at position %d", i)
		}
	}
}

// ---------------- I. Empty results ----------------

func TestPhase14_EmptyResultsAreDistinguishedFromAnEmptyCase(t *testing.T) {
	mux := newTestRouter(t)

	empty := mustCreateCase(t, mux, "no evidence at all")
	res := searchEvents(t, mux, empty.ID, nil)
	if res.Total != 0 || res.TotalInCase != 0 {
		t.Errorf("a case with no evidence reported total=%d in_case=%d", res.Total, res.TotalInCase)
	}
	if res.Items == nil {
		t.Error("items must serialize as [], never null")
	}

	caseID := phase14Case(t, mux)
	noMatch := searchEvents(t, mux, caseID, vals("q", "nothing-in-this-case-matches-this-string"))
	if noMatch.Total != 0 {
		t.Errorf("expected no matches, got %d", noMatch.Total)
	}
	if noMatch.TotalInCase == 0 {
		t.Error("a filtered-to-nothing result must still report that the case HAS events, so the UI can say which of the two happened")
	}
	if len(noMatch.Items) != 0 {
		t.Error("no matches but items returned")
	}
}

func TestPhase14_SingleResultPagesCorrectly(t *testing.T) {
	mux := newTestRouter(t)
	caseID := phase14Case(t, mux)

	res := searchEvents(t, mux, caseID, vals("artifact_type", model.ArtifactRecycleBin))
	if res.Total != 1 || len(res.Items) != 1 {
		t.Fatalf("total=%d items=%d, want 1 and 1", res.Total, len(res.Items))
	}
	if res.TotalPages != 1 {
		t.Errorf("total_pages = %d, want 1", res.TotalPages)
	}
}

// ---------------- L. Provenance navigation ----------------

func TestPhase14_EveryEventTracesBackToItsEvidence(t *testing.T) {
	mux := newTestRouter(t)
	caseID := phase14Case(t, mux)

	res := searchEvents(t, mux, caseID, vals("page_size", "100"))
	if len(res.Items) == 0 {
		t.Fatal("no events")
	}
	for _, e := range res.Items {
		var prov EventProvenance
		rec := doJSON(t, mux, "GET", "/api/cases/"+caseID+"/events/"+e.ID, nil, &prov)
		if rec.Code != http.StatusOK {
			t.Fatalf("provenance for %s: %d %s", e.ID, rec.Code, rec.Body.String())
		}
		// Event -> raw record -> source file -> collection.
		if prov.RawEvidence.Raw == "" {
			t.Errorf("event %s has no raw evidence record", e.ID)
		}
		if prov.SourceFile.Path == "" {
			t.Errorf("event %s does not name the file it came from", e.ID)
		}
		if prov.Collection == nil || prov.Collection.CollectionID == "" {
			t.Errorf("event %s does not resolve to an evidence collection", e.ID)
		}
		if prov.ArtifactLabel == "" {
			t.Errorf("event %s provenance has no artifact label", e.ID)
		}
		if len(prov.Observations) == 0 {
			t.Errorf("event %s records no observation", e.ID)
		}
		// Non-nil so "no related finding" is a normal answer, not a null.
		if prov.Findings == nil || prov.Investigations == nil {
			t.Errorf("event %s: findings/investigations must be [] not null", e.ID)
		}
	}
}

// ---------------- P / Q / R. Layer boundaries ----------------

// The central architectural assertion of the phase: importing evidence
// produces events and NOTHING else. No findings, no investigations.
func TestPhase14_ImportingEvidenceCreatesNoFindingsOrInvestigations(t *testing.T) {
	mux := newTestRouter(t)
	caseID := phase14Case(t, mux)

	events := searchEvents(t, mux, caseID, nil)
	if events.Total == 0 {
		t.Fatal("no events")
	}

	var findings []model.Finding
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/findings", nil, &findings)
	if len(findings) != 0 {
		t.Errorf("importing evidence produced %d findings; events must not become findings", len(findings))
	}
	var investigations []model.Investigation
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/investigations", nil, &investigations)
	if len(investigations) != 0 {
		t.Errorf("importing evidence produced %d investigations", len(investigations))
	}
	for _, e := range events.Items {
		if len(e.Findings) != 0 {
			t.Errorf("event %s carries findings before any analysis ran", e.ID)
		}
		if len(e.Investigations) != 0 {
			t.Errorf("event %s carries investigations before any analysis ran", e.ID)
		}
	}
}

// Where a detection DOES cite an event, the timeline links to it -- and
// the event is still an event, not a finding.
func TestPhase14_EventLinksToItsFindingAndInvestigation(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "linked layers")
	discoverPathAndImportAll(t, mux, c.ID, syntheticCasePath())

	rec := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/analyze", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("analyze: %d %s", rec.Code, rec.Body.String())
	}

	var findings []model.Finding
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/findings", nil, &findings)
	if len(findings) == 0 {
		t.Skip("the synthetic case produced no findings; nothing to link")
	}
	// Pick an event a finding actually cites.
	var wantEvent string
	for _, f := range findings {
		if len(f.SupportingEvents) > 0 {
			wantEvent = f.SupportingEvents[0]
			break
		}
	}
	if wantEvent == "" {
		t.Skip("no finding cites a specific event")
	}

	var prov EventProvenance
	if rec := doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/events/"+wantEvent, nil, &prov); rec.Code != http.StatusOK {
		t.Fatalf("provenance: %d %s", rec.Code, rec.Body.String())
	}
	if len(prov.Findings) == 0 {
		t.Fatal("an event cited by a finding reports no related finding")
	}
	for _, f := range prov.Findings {
		if f.FindingID == "" || f.Title == "" || f.Severity == "" {
			t.Errorf("finding reference is not usable for navigation: %+v", f)
		}
	}

	// And an investigation that groups that finding is reachable from
	// the same event.
	var investigations []model.Investigation
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/investigations", nil, &investigations)
	grouped := false
	for _, inv := range investigations {
		for _, fid := range inv.FindingIDs {
			if fid == prov.Findings[0].FindingID {
				grouped = true
			}
		}
	}
	if grouped && len(prov.Investigations) == 0 {
		t.Error("the event's finding belongs to an investigation, but the event reports none")
	}
}

// Most events must remain unlinked even after analysis: a timeline where
// everything has a finding would mean detection had stopped selecting.
func TestPhase14_MostEventsHaveNoFindingAfterAnalysis(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "unlinked majority")
	discoverPathAndImportAll(t, mux, c.ID, syntheticCasePath())
	doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/analyze", nil, nil)

	res := searchEvents(t, mux, c.ID, vals("page_size", "100"))
	if res.Total == 0 {
		t.Fatal("no events")
	}
	linked := 0
	for _, e := range res.Items {
		if len(e.Findings) > 0 {
			linked++
		}
	}
	if linked == len(res.Items) {
		t.Error("every event on the page is cited by a finding; raw events are being treated as detections")
	}
}

// ---------------- S. Evidence deletion ----------------

func TestPhase14_DeletedEvidenceLeavesNoSearchableEvents(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "deletion clears the timeline")
	disc := discoverBinaryDir(t, mux, c.ID, phase14Catalog(t))
	importAllFrom(t, mux, c.ID, disc)

	before := searchEvents(t, mux, c.ID, nil)
	if before.Total == 0 {
		t.Fatal("no events to delete")
	}

	rec := doJSON(t, mux, "DELETE", "/api/cases/"+c.ID+"/collections/"+disc.Collection.ID, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("deleting collection: %d %s", rec.Code, rec.Body.String())
	}

	after := searchEvents(t, mux, c.ID, nil)
	if after.Total != 0 {
		t.Errorf("%d events still searchable after their evidence was deleted", after.Total)
	}
	if after.TotalInCase != 0 {
		t.Errorf("case still reports %d events", after.TotalInCase)
	}
	// The specific acceptance event must be gone too.
	day := searchEvents(t, mux, c.ID, vals("date", "2021-04-29"))
	if day.Total != 0 {
		t.Errorf("the 2021-04-29 search still returns %d events after deletion", day.Total)
	}
	// Facets must not keep advertising filters that can return nothing.
	var facets EventFacetsResponse
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/events/facets", nil, &facets)
	if len(facets.ArtifactTypes) != 0 || len(facets.EventTypes) != 0 {
		t.Errorf("facets still offer %d artifact and %d event types after all evidence was deleted",
			len(facets.ArtifactTypes), len(facets.EventTypes))
	}
}

// ---------------- M. Authorization ----------------

func TestPhase14_EventSearchRequiresAuthenticationWhenEnabled(t *testing.T) {
	mux := newAuthFixture(t, time.Hour).mux
	for _, path := range []string{
		"/api/cases/any-case/events",
		"/api/cases/any-case/events/facets",
		"/api/cases/any-case/events/any-event",
	} {
		rec := doJSON(t, mux, "GET", path, nil, nil)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("GET %s without a session returned %d, want 401", path, rec.Code)
		}
	}
}

// A query is scoped to its case. Events from another case must never
// appear, whatever the filters say.
func TestPhase14_EventsAreScopedToTheirCase(t *testing.T) {
	mux := newTestRouter(t)
	caseA := phase14Case(t, mux)

	b := mustCreateCase(t, mux, "case B, different evidence")
	discB := discoverBinaryDir(t, mux, b.ID, map[string][]byte{
		"Windows/Prefetch/OTHER.EXE-CAFEBABE.pf": samplePrefetch(),
	})
	importAllFrom(t, mux, b.ID, discB)

	aIDs := map[string]bool{}
	for _, e := range searchEvents(t, mux, caseA, vals("page_size", "100")).Items {
		aIDs[e.ID] = true
		if e.CaseID != caseA {
			t.Errorf("case %s returned an event belonging to case %s", caseA, e.CaseID)
		}
	}
	for _, e := range searchEvents(t, mux, b.ID, vals("page_size", "100")).Items {
		if aIDs[e.ID] {
			t.Errorf("event %s appears in both cases", e.ID)
		}
		if e.CaseID != b.ID {
			t.Errorf("case %s returned an event belonging to case %s", b.ID, e.CaseID)
		}
	}

	// Even a filter naming the other case's values returns nothing.
	crossed := searchEvents(t, mux, b.ID, vals("q", "quarterly-figures"))
	if crossed.Total != 0 {
		t.Errorf("case B matched %d events using a term that only exists in case A", crossed.Total)
	}
	// And an event id from case A is not readable through case B.
	var anyA string
	for id := range aIDs {
		anyA = id
		break
	}
	rec := doJSON(t, mux, "GET", "/api/cases/"+b.ID+"/events/"+anyA, nil, nil)
	if rec.Code == http.StatusOK {
		t.Error("case B returned provenance for case A's event")
	}
}

// ---------------- 22. Negative tests ----------------

func TestPhase14_SearchInputCannotInjectSQL(t *testing.T) {
	mux := newTestRouter(t)
	caseID := phase14Case(t, mux)
	baseline := searchEvents(t, mux, caseID, nil).Total

	payloads := []string{
		`'; DROP TABLE events; --`,
		`" OR "1"="1`,
		`' OR 1=1 --`,
		`%' OR '1'='1`,
		`\'; DELETE FROM events WHERE '1'='1`,
		`1'; UPDATE events SET host='pwned'; --`,
		`') UNION SELECT * FROM users --`,
	}
	for _, p := range payloads {
		for _, param := range []string{"q", "path", "url", "domain", "filename", "command_line", "original_path", "ip"} {
			res := searchEvents(t, mux, caseID, vals(param, p))
			// A literal search for SQL punctuation matches nothing here,
			// which is the correct answer: it is a search TERM.
			if res.Total != 0 {
				t.Errorf("%s=%q returned %d events; it should be treated as a literal term", param, p, res.Total)
			}
		}
	}
	// The table must still be intact and unmodified afterwards.
	after := searchEvents(t, mux, caseID, nil)
	if after.Total != baseline {
		t.Fatalf("event count changed from %d to %d after injection attempts", baseline, after.Total)
	}
	for _, e := range after.Items {
		if e.Host == "pwned" {
			t.Fatal("an injection payload modified stored evidence")
		}
	}
}

// LIKE wildcards typed by an analyst are literal characters, not
// operators. A Windows path is full of underscores, and "_" silently
// meaning "any character" would quietly widen a search.
func TestPhase14_SearchTermsTreatWildcardsLiterally(t *testing.T) {
	mux := newTestRouter(t)
	caseID := phase14Case(t, mux)

	all := searchEvents(t, mux, caseID, nil).Total
	if all == 0 {
		t.Fatal("no events")
	}

	// The precise assertion: a term must match the characters an analyst
	// typed. "quarterly-figures" is in the evidence; "quarterly_figures"
	// is not, and would match it only if "_" were still acting as
	// LIKE's any-character wildcard.
	literal := searchEvents(t, mux, caseID, vals("q", "quarterly-figures")).Total
	if literal == 0 {
		t.Fatal("precondition: the hyphenated term is in the evidence")
	}
	if wild := searchEvents(t, mux, caseID, vals("q", "quarterly_figures")).Total; wild != 0 {
		t.Errorf("q=%q matched %d events; \"_\" must be a literal underscore, not a wildcard",
			"quarterly_figures", wild)
	}
	// Likewise "%" is a literal percent sign. No value in this fixture
	// contains one, so a term of "%" must match nothing rather than
	// everything.
	if pct := searchEvents(t, mux, caseID, vals("q", "%")).Total; pct != 0 {
		t.Errorf("q=%q matched %d of %d events; \"%%\" must be literal, not \"any characters\"", "%", pct, all)
	}
	if pct := searchEvents(t, mux, caseID, vals("q", "quarterly%figures")).Total; pct != 0 {
		t.Errorf("q=%q matched %d events; the percent sign must not span characters", "quarterly%figures", pct)
	}
	// A backslash -- which every Windows path contains, and which is the
	// LIKE escape character here -- must still match literally.
	if bs := searchEvents(t, mux, caseID, vals("q", `Users\jdoe`)).Total; bs == 0 {
		t.Error(`escaping broke matching on a literal backslash (Users\jdoe)`)
	}
}

func TestPhase14_ChangingTimezoneNeverAltersStoredTimestamps(t *testing.T) {
	mux := newTestRouter(t)
	caseID := phase14Case(t, mux)

	snapshot := func() map[string]string {
		out := map[string]string{}
		for _, e := range searchEvents(t, mux, caseID, vals("page_size", "100")).Items {
			out[e.ID] = e.Timestamp.UTC().Format(time.RFC3339Nano)
		}
		return out
	}
	before := snapshot()
	if len(before) == 0 {
		t.Fatal("no events")
	}

	for _, tz := range []string{"Asia/Jakarta", "America/New_York", "Australia/Sydney", "UTC"} {
		if rec := setTimezone(t, mux, tz); rec.Code != http.StatusOK {
			t.Fatalf("setting %s: %d %s", tz, rec.Code, rec.Body)
		}
		after := snapshot()
		if len(after) != len(before) {
			t.Fatalf("timezone %s changed the number of events: %d -> %d", tz, len(before), len(after))
		}
		for id, ts := range before {
			if after[id] != ts {
				t.Errorf("timezone %s changed event %s from %s to %s", tz, id, ts, after[id])
			}
		}
	}
}

func TestPhase14_InvalidTimezoneCannotCorruptSettings(t *testing.T) {
	mux := newTestRouter(t)
	if rec := setTimezone(t, mux, "Asia/Jakarta"); rec.Code != http.StatusOK {
		t.Fatalf("precondition: %d %s", rec.Code, rec.Body)
	}
	for _, bad := range []string{"Asia/Jakata", "+07:00", "-05:00", "Local", "", "; DROP TABLE app_settings;"} {
		rec := setTimezone(t, mux, bad)
		if rec.Code == http.StatusOK {
			t.Errorf("timezone %q was accepted", bad)
		}
	}
	var settings struct {
		Display DisplaySettings `json:"display"`
	}
	doJSON(t, mux, "GET", "/api/settings", nil, &settings)
	if settings.Display.Timezone != "Asia/Jakarta" {
		t.Errorf("timezone is now %q; a rejected value must leave the setting untouched", settings.Display.Timezone)
	}
}

// Very long values must be returned intact by the API. Truncation is a
// display decision and belongs in the UI -- an API that truncated would
// make the full value unavailable to the detail view that needs it.
func TestPhase14_VeryLongValuesAreReturnedIntact(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "long values")

	longSegment := strings.Repeat("extremely-long-directory-segment-", 12)
	longPath := `C:\Users\jdoe\` + longSegment + `\report.docx`
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		`C/$Recycle.Bin/S-1-5-21-1-1-1-1001/$ILONG01.docx`: rbgen.Build(rbgen.Record{
			Version: 2, Size: 4096, Deleted: phase14DeletedAt, Path: longPath,
		}),
	})
	importAllFrom(t, mux, c.ID, disc)

	res := searchEvents(t, mux, c.ID, nil)
	if res.Total != 1 {
		t.Fatalf("expected 1 event, got %d", res.Total)
	}
	if got := res.Items[0].Extra["original_path"]; got != longPath {
		t.Errorf("original path came back altered:\n got %q (%d chars)\nwant %q (%d chars)",
			got, len(got), longPath, len(longPath))
	}
	if res := searchEvents(t, mux, c.ID, vals("q", longSegment)); res.Total != 1 {
		t.Errorf("a long value is stored but not searchable: matched %d", res.Total)
	}
}

// The acceptance term must exist only in test fixtures. A search string
// baked into the product would mean the acceptance test was validating
// the implementation's memory rather than parsed evidence.
func TestPhase14_NoHardcodedAcceptanceTerm(t *testing.T) {
	root := "../.."
	var offenders []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if name := info.Name(); name == ".git" || name == "bin" || name == "data" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, ".js") {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		lower := strings.ToLower(string(b))
		for _, term := range []string{"password cracking", "africanfalls", phase14SearchTerm} {
			if strings.Contains(lower, strings.ToLower(term)) {
				offenders = append(offenders, path+" contains "+term)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) != 0 {
		t.Errorf("acceptance-case terms leaked into non-test code:\n  %s", strings.Join(offenders, "\n  "))
	}
}

// ---------------- Investigations: scoped event load ----------------

// Investigations now load only the events findings and correlations
// reference, rather than every event in the case (see
// Service.Investigations). That is a performance change and must be
// provably not a behaviour change: this recomputes the investigations
// the OLD way -- from the complete event set -- and requires the two to
// be identical.
func TestInvestigations_ScopedEventLoadMatchesFullLoad(t *testing.T) {
	svc := newTestService(t)
	mux := routerFor(svc)
	c := mustCreateCase(t, mux, "scoped investigation load")
	discoverPathAndImportAll(t, mux, c.ID, syntheticCasePath())
	if rec := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/analyze", nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("analyze: %d %s", rec.Code, rec.Body.String())
	}

	scoped, err := svc.Investigations(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(scoped) == 0 {
		t.Skip("the synthetic case produced no investigations")
	}

	full, err := svc.investigationsFromAllEvents(c.ID)
	if err != nil {
		t.Fatal(err)
	}

	if len(scoped) != len(full) {
		t.Fatalf("scoped load produced %d investigations, full load %d", len(scoped), len(full))
	}
	for i := range scoped {
		a, b := scoped[i], full[i]
		if a.ID != b.ID || a.Title != b.Title || a.Severity != b.Severity ||
			a.Confidence != b.Confidence || a.Score != b.Score || a.Summary != b.Summary {
			t.Errorf("investigation %d differs:\n scoped: %+v\n full:   %+v", i, a, b)
		}
		if !a.StartTime.Equal(b.StartTime) || !a.EndTime.Equal(b.EndTime) {
			t.Errorf("investigation %d time span differs: %s..%s vs %s..%s",
				i, a.StartTime, a.EndTime, b.StartTime, b.EndTime)
		}
		if len(a.EventIDs) != len(b.EventIDs) || len(a.FindingIDs) != len(b.FindingIDs) {
			t.Errorf("investigation %d references differ: %d/%d events, %d/%d findings",
				i, len(a.EventIDs), len(b.EventIDs), len(a.FindingIDs), len(b.FindingIDs))
		}
	}
}
