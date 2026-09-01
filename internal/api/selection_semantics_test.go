package api

import (
	"net/url"
	"os"
	"strings"
	"testing"

	"tracefall/internal/model"
)

// browserHistoryFixture holds the real Chromium History sample, loaded
// once. A medium-priority supported artifact is what makes the
// selectable and recommended sets differ.
var browserHistoryFixture []byte

// mixedRecommendedCatalog produces a collection where the SELECTABLE set
// is strictly larger than the RECOMMENDED set, so the two can be told
// apart. Registry hives are critical (recommended); browser history is
// medium priority -- supported and importable, but not recommended.
func mixedRecommendedCatalog(hives, browsers int) map[string][]byte {
	if browserHistoryFixture == nil {
		browserHistoryFixture, _ = os.ReadFile("../../testdata/native_samples/History")
	}
	files := map[string][]byte{}
	for i := 0; i < hives; i++ {
		files[fmtIndexed("Users/u%03d/NTUSER.DAT", i)] = uniqueBytes(persistenceHive(), i)
	}
	for i := 0; i < browsers; i++ {
		files[fmtIndexed("Users/u%03d/History", i)] = uniqueBytes(browserHistoryFixture, i)
	}
	return files
}

// Selection scopes must be distinct and exact. The reported defect:
// "Select recommended (240)" ADDED to an existing 242-file selection
// using an UNFILTERED query, leaving 242 selected -- a count that
// described neither the action nor its result.
func TestSelection_RecommendedIsAStrictSubsetOfMatching(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Recommended subset")
	disc := discoverBinaryDir(t, mux, c.ID, mixedRecommendedCatalog(40, 12))
	coll := disc.Collection.ID

	page := getEvidencePage(t, mux, c.ID, coll, nil)
	if page.SelectableTotal <= page.RecommendedTotal {
		t.Fatalf("fixture does not separate the scopes: selectable=%d recommended=%d",
			page.SelectableTotal, page.RecommendedTotal)
	}

	recommended := getEvidenceIDs(t, mux, c.ID, coll, url.Values{"recommended": {"true"}})
	allMatching := getEvidenceIDs(t, mux, c.ID, coll, nil)

	// The button's number and the set it selects must be the same thing.
	if len(recommended) != page.RecommendedTotal {
		t.Errorf("recommended_total = %d but the recommended id set has %d entries",
			page.RecommendedTotal, len(recommended))
	}
	if len(allMatching) != page.SelectableTotal {
		t.Errorf("selectable_total = %d but the matching id set has %d entries",
			page.SelectableTotal, len(allMatching))
	}
	if len(recommended) >= len(allMatching) {
		t.Errorf("recommended (%d) is not a strict subset of matching (%d)", len(recommended), len(allMatching))
	}
	// Strict subset, not merely smaller.
	matchingSet := map[string]bool{}
	for _, id := range allMatching {
		matchingSet[id] = true
	}
	for _, id := range recommended {
		if !matchingSet[id] {
			t.Errorf("recommended id %s is not in the matching set", id)
		}
	}
}

// recommended_total must follow the FILTER, since the button selects
// within the filter. A count taken from the whole catalog would promise
// one thing and do another.
func TestSelection_RecommendedTotalIsScopedToTheFilter(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Recommended scoping")
	disc := discoverBinaryDir(t, mux, c.ID, mixedRecommendedCatalog(40, 12))
	coll := disc.Collection.ID

	unfiltered := getEvidencePage(t, mux, c.ID, coll, nil)

	// Filter to the browser history only: nothing there is recommended.
	browsers := getEvidencePage(t, mux, c.ID, coll, url.Values{"q": {"History"}})
	if browsers.Total == 0 {
		t.Fatal("the History filter matched nothing")
	}
	if browsers.RecommendedTotal != 0 {
		t.Errorf("recommended_total = %d under a filter matching only medium-priority files, want 0",
			browsers.RecommendedTotal)
	}
	ids := getEvidenceIDs(t, mux, c.ID, coll, url.Values{"q": {"History"}, "recommended": {"true"}})
	if len(ids) != 0 {
		t.Errorf("recommended ids under that filter = %d, want 0", len(ids))
	}

	// Filter to the hives: every match is recommended.
	hives := getEvidencePage(t, mux, c.ID, coll, url.Values{"q": {"NTUSER"}})
	if hives.RecommendedTotal != hives.SelectableTotal || hives.RecommendedTotal == 0 {
		t.Errorf("hive filter: recommended=%d selectable=%d, want them equal and non-zero",
			hives.RecommendedTotal, hives.SelectableTotal)
	}
	if hives.RecommendedTotal >= unfiltered.RecommendedTotal+1 {
		t.Errorf("a narrowing filter did not narrow recommended_total: %d vs %d",
			hives.RecommendedTotal, unfiltered.RecommendedTotal)
	}
}

// The four scopes must remain distinct: page ⊆ matching, recommended ⊆
// matching, and clear means zero.
func TestSelection_ScopesRemainDistinct(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Scope distinctness")
	disc := discoverBinaryDir(t, mux, c.ID, mixedRecommendedCatalog(40, 12))
	coll := disc.Collection.ID

	page := getEvidencePage(t, mux, c.ID, coll, url.Values{"page_size": {"10"}})
	if len(page.Items) != 10 {
		t.Fatalf("page returned %d items, want 10", len(page.Items))
	}
	if page.Total <= len(page.Items) {
		t.Fatal("the fixture fits on one page; the scopes cannot be told apart")
	}
	// "Select page" must never be able to mean "select all matching".
	if len(page.Items) >= page.SelectableTotal {
		t.Errorf("a page (%d) is not smaller than the matching selectable set (%d)",
			len(page.Items), page.SelectableTotal)
	}
}

// Changing the filter must not leave a stale bulk selection described as
// "everything matching" -- the count and the claim have to agree.
func TestSelection_FilterChangeInvalidatesTheMatchingClaim(t *testing.T) {
	src, err := os.ReadFile("../web/static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	body := functionBody(t, src, "function wireDiscoverySelection(")

	// The selection must be REPLACED by "select recommended", not added to.
	// Anchor on the CLICK HANDLER specifically -- the id also appears in
	// the count-refresh helper, and slicing from the first occurrence
	// would examine the wrong block.
	const marker = `"#ev-select-recommended").addEventListener`
	idx := strings.Index(body, marker)
	if idx < 0 {
		t.Fatal("the recommended click handler is gone; update this test")
	}
	handler := body[idx:]
	if end := strings.Index(handler, "addEventListener"); end > 0 {
		if next := strings.Index(handler[end+1:], "addEventListener"); next > 0 {
			handler = handler[:end+1+next]
		}
	}
	if !strings.Contains(handler, "selected.clear()") {
		t.Error("Select recommended does not clear the previous selection; it will add to it " +
			"and leave a count that matches neither the button nor the recommended set")
	}
	if strings.Contains(handler, "files/ids?recommended=true`") {
		t.Error("Select recommended queries the whole catalog rather than the current filter")
	}
	// The stale-bulk warning must still exist.
	if !strings.Contains(body, "bulk.signature !== filterSignature()") {
		t.Error("the stale bulk-selection check is gone")
	}
}

// "Clear all" must reset the WHOLE filter state, including a search box
// that lives outside the filter bar.
func TestSelection_ClearAllResetsScreenLevelSearch(t *testing.T) {
	src, err := os.ReadFile("../web/static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	body := functionBody(t, src, "function wireFilterBar(")

	if !strings.Contains(body, "`${prefix}-search`") {
		t.Error("Clear all does not clear a screen-level search input; a search-only filter " +
			"survives the button that says it clears everything")
	}
	if !strings.Contains(body, "`${prefix}-f-q`") {
		t.Error("Clear all no longer clears the in-bar search input")
	}
}

func fmtIndexed(pattern string, i int) string {
	return strings.Replace(pattern, "%03d", pad3(i), 1)
}

func pad3(i int) string {
	s := []byte{'0', '0', '0'}
	for p := 2; p >= 0 && i > 0; p-- {
		s[p] = byte('0' + i%10)
		i /= 10
	}
	return string(s)
}

func uniqueBytes(base []byte, i int) []byte {
	out := append([]byte{}, base...)
	return append(out, []byte("\x00sel-"+pad3(i))...)
}

var _ = model.RoleAnalyst
