package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"tracefall/internal/model"
)

// largeCatalog builds a collection big enough that paging is the only
// sane way to read it, mixing artifact classes and priorities so the
// filters have something real to cut against.
//
// Every file gets UNIQUE trailing bytes. Without them each copy of a
// fixture hashes identically and the batch's SHA-256 duplicate detection
// correctly marks all but the first as "duplicate" -- leaving three
// selectable files in a 400-file catalog and testing nothing about
// pagination. The suffix changes the hash without disturbing the
// structures the readers parse (both formats are length-driven and
// ignore trailing bytes).
func largeCatalog(n int) map[string][]byte {
	files := map[string][]byte{}
	uniq := func(base []byte, i int) []byte {
		return append(append([]byte{}, base...), []byte(fmt.Sprintf("\x00tracefall-fixture-%06d", i))...)
	}
	for i := 0; i < n; i++ {
		switch i % 4 {
		case 0:
			files[fmt.Sprintf("Windows/System32/winevt/Logs/App-%04d.evtx", i)] = uniq(attackEvtx(), i)
		case 1:
			files[fmt.Sprintf("Users/u%04d/NTUSER.DAT", i)] = uniq(persistenceHive(), i)
		case 2:
			files[fmt.Sprintf("Windows/Prefetch/PROG%04d.EXE-A1B2C3D4.pf", i)] = uniq([]byte("MAM\x04synthetic"), i)
		default:
			files[fmt.Sprintf("Windows/Fonts/face%04d.ttf", i)] = uniq([]byte("synthetic font"), i)
		}
	}
	return files
}

func getEvidencePage(t *testing.T, mux http.Handler, caseID, collectionID string, q url.Values) EvidenceFilePage {
	t.Helper()
	path := "/api/cases/" + caseID + "/evidence/" + collectionID + "/files"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: status %d, body %s", path, rec.Code, rec.Body.String())
	}
	var page EvidenceFilePage
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatalf("decoding page: %v", err)
	}
	return page
}

func getEvidenceIDs(t *testing.T, mux http.Handler, caseID, collectionID string, q url.Values) []string {
	t.Helper()
	path := "/api/cases/" + caseID + "/evidence/" + collectionID + "/files/ids"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: status %d", path, rec.Code)
	}
	var out struct {
		IDs   []string `json:"ids"`
		Total int      `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Total != len(out.IDs) {
		t.Errorf("total = %d but %d ids returned", out.Total, len(out.IDs))
	}
	return out.IDs
}

func bigCase(t *testing.T, n int) (http.Handler, string, string) {
	t.Helper()
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Large catalog")
	disc := discoverBinaryDir(t, mux, c.ID, largeCatalog(n))
	return mux, c.ID, disc.Collection.ID
}

// ---------------- discovery response is bounded ----------------

// The whole point of Phase 10B: discovering a large image must not hand
// the browser the entire catalog.
func TestDiscover_ReturnsOnlyTheFirstPage(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Bounded discovery")
	disc := discoverBinaryDir(t, mux, c.ID, largeCatalog(250))

	if disc.SourceFilesTotal != 250 {
		t.Errorf("source_files_total = %d, want 250 -- the true total must always be reported", disc.SourceFilesTotal)
	}
	if len(disc.SourceFiles) != defaultEvidencePageSize {
		t.Errorf("discovery returned %d files, want one page of %d", len(disc.SourceFiles), defaultEvidencePageSize)
	}
	if disc.SourceFilesPageSize != defaultEvidencePageSize {
		t.Errorf("source_files_page_size = %d, want %d", disc.SourceFilesPageSize, defaultEvidencePageSize)
	}
	// Coverage still describes the WHOLE catalog, not the page -- a
	// coverage summary of page 1 would be actively misleading.
	if disc.Coverage.Discovered != 250 {
		t.Errorf("coverage.discovered = %d, want 250 (the whole catalog)", disc.Coverage.Discovered)
	}
}

// A catalog that fits in one page must behave exactly as it did before
// Phase 10B, so every existing workflow is untouched.
func TestDiscover_SmallCatalogUnchanged(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Small catalog")
	disc := discoverBinaryDir(t, mux, c.ID, mixedCatalog())

	if len(disc.SourceFiles) != disc.SourceFilesTotal {
		t.Errorf("a %d-file catalog was paged: returned %d", disc.SourceFilesTotal, len(disc.SourceFiles))
	}
}

// ---------------- pagination boundaries ----------------

func TestEvidencePage_Boundaries(t *testing.T) {
	const n = 250
	mux, caseID, collID := bigCase(t, n)

	first := getEvidencePage(t, mux, caseID, collID, url.Values{"page": {"1"}, "page_size": {"100"}})
	if first.Total != n {
		t.Fatalf("total = %d, want %d", first.Total, n)
	}
	if first.TotalPages != 3 {
		t.Errorf("total_pages = %d, want 3 for %d records at 100/page", first.TotalPages, n)
	}
	if len(first.Items) != 100 {
		t.Errorf("page 1 returned %d items, want 100", len(first.Items))
	}

	// The last page is a partial page, and must return the remainder --
	// not a full page padded, and not nothing.
	last := getEvidencePage(t, mux, caseID, collID, url.Values{"page": {"3"}, "page_size": {"100"}})
	if len(last.Items) != 50 {
		t.Errorf("last page returned %d items, want the remaining 50", len(last.Items))
	}

	// Past the end: an empty page, with the totals still correct so the
	// client can right itself.
	past := getEvidencePage(t, mux, caseID, collID, url.Values{"page": {"99"}, "page_size": {"100"}})
	if len(past.Items) != 0 {
		t.Errorf("page 99 returned %d items, want 0", len(past.Items))
	}
	if past.Total != n || past.TotalPages != 3 {
		t.Errorf("an out-of-range page lost the totals: total=%d pages=%d", past.Total, past.TotalPages)
	}
	if past.Items == nil {
		t.Error("an empty page serialized as null; it must be an empty array")
	}
}

// Every record must appear exactly once across the pages. This is the
// property that makes paginated selection safe: a record shown twice
// could be imported twice, and one skipped could never be selected.
func TestEvidencePage_PagesCoverEveryRecordExactlyOnce(t *testing.T) {
	const n = 250
	mux, caseID, collID := bigCase(t, n)

	seen := map[string]int{}
	for page := 1; page <= 5; page++ {
		p := getEvidencePage(t, mux, caseID, collID, url.Values{"page": {fmt.Sprint(page)}, "page_size": {"50"}})
		for _, f := range p.Items {
			seen[f.ID]++
		}
	}
	if len(seen) != n {
		t.Errorf("paging saw %d distinct files, want %d", len(seen), n)
	}
	for id, count := range seen {
		if count != 1 {
			t.Errorf("file %s appeared on %d pages; pagination must not duplicate records", id, count)
		}
	}
}

// Ordering must be stable across identical requests, or the set above
// would only hold by luck.
func TestEvidencePage_OrderIsDeterministic(t *testing.T) {
	mux, caseID, collID := bigCase(t, 120)
	var first []string
	for attempt := 0; attempt < 3; attempt++ {
		p := getEvidencePage(t, mux, caseID, collID, url.Values{"page": {"2"}, "page_size": {"25"}})
		ids := make([]string, 0, len(p.Items))
		for _, f := range p.Items {
			ids = append(ids, f.ID)
		}
		if attempt == 0 {
			first = ids
			continue
		}
		if strings.Join(ids, ",") != strings.Join(first, ",") {
			t.Fatal("the same page returned a different order on a repeat request")
		}
	}
}

func TestEvidencePage_PageSizeAllowList(t *testing.T) {
	mux, caseID, collID := bigCase(t, 120)

	for _, size := range []int{25, 50, 100, 250} {
		p := getEvidencePage(t, mux, caseID, collID, url.Values{"page_size": {fmt.Sprint(size)}})
		if p.PageSize != size {
			t.Errorf("page_size=%d was not honored (got %d)", size, p.PageSize)
		}
	}
	// An unbounded page size is exactly what pagination exists to
	// prevent, so it must fall back rather than be honored.
	huge := getEvidencePage(t, mux, caseID, collID, url.Values{"page_size": {"1000000"}})
	if huge.PageSize != defaultEvidencePageSize {
		t.Errorf("page_size=1000000 was honored as %d; the allow-list must reject it", huge.PageSize)
	}
	if len(huge.Items) > defaultEvidencePageSize {
		t.Errorf("an out-of-range page size returned %d items", len(huge.Items))
	}
	// Garbage is clamped, not rejected: a bad page number is a
	// navigation mistake, not a forensic one.
	bad := getEvidencePage(t, mux, caseID, collID, url.Values{"page": {"-3"}, "page_size": {"abc"}})
	if bad.Number != 1 || bad.PageSize != defaultEvidencePageSize {
		t.Errorf("invalid paging input was not clamped: page=%d size=%d", bad.Number, bad.PageSize)
	}
}

// ---------------- filtering + pagination ----------------

func TestEvidencePage_FilterReducesTotalAndPages(t *testing.T) {
	const n = 200
	mux, caseID, collID := bigCase(t, n)

	all := getEvidencePage(t, mux, caseID, collID, nil)
	if all.Total != n {
		t.Fatalf("unfiltered total = %d, want %d", all.Total, n)
	}

	// One in four fixtures is a font: unrecognized, unknown priority.
	filtered := getEvidencePage(t, mux, caseID, collID, url.Values{"priority": {"unknown"}, "page_size": {"25"}})
	if filtered.Total == 0 || filtered.Total >= n {
		t.Fatalf("priority filter did not reduce the total: %d of %d", filtered.Total, n)
	}
	if filtered.TotalPages != (filtered.Total+24)/25 {
		t.Errorf("total_pages = %d, inconsistent with total %d at 25/page", filtered.TotalPages, filtered.Total)
	}
	for _, f := range filtered.Items {
		if f.Priority != "unknown" {
			t.Errorf("filtered page contains priority %q", f.Priority)
		}
	}
	// The collection total is unchanged by a filter -- the UI needs both
	// "120 matching" and "of 7,074 files".
	if filtered.CollectionTotal != n {
		t.Errorf("collection_total = %d, want %d regardless of the filter", filtered.CollectionTotal, n)
	}
}

// Phase 9A semantics, preserved: OR within one multi-select, AND across
// different ones.
func TestEvidencePage_FilterSemanticsOrWithinAndAcross(t *testing.T) {
	mux, caseID, collID := bigCase(t, 200)

	critical := getEvidencePage(t, mux, caseID, collID, url.Values{"priority": {"critical"}})
	unknown := getEvidencePage(t, mux, caseID, collID, url.Values{"priority": {"unknown"}})
	both := getEvidencePage(t, mux, caseID, collID, url.Values{"priority": {"critical", "unknown"}})

	if both.Total != critical.Total+unknown.Total {
		t.Errorf("OR within one filter is broken: critical=%d unknown=%d both=%d",
			critical.Total, unknown.Total, both.Total)
	}

	// AND across filters can only ever narrow.
	andAcross := getEvidencePage(t, mux, caseID, collID, url.Values{
		"priority": {"critical", "unknown"}, "status": {"supported"}})
	if andAcross.Total > both.Total {
		t.Errorf("adding a second filter widened the result: %d > %d", andAcross.Total, both.Total)
	}
	for _, f := range andAcross.Items {
		if p := f.Priority; p != "critical" && p != "unknown" {
			t.Errorf("record with priority %q survived the priority filter", p)
		}
		if evidenceStatusValue(f) != "supported" {
			t.Errorf("record with status %q survived the status filter", evidenceStatusValue(f))
		}
	}
}

func TestEvidencePage_SearchIsCaseInsensitiveAndPaginates(t *testing.T) {
	mux, caseID, collID := bigCase(t, 200)

	lower := getEvidencePage(t, mux, caseID, collID, url.Values{"q": {"ntuser"}, "page_size": {"25"}})
	upper := getEvidencePage(t, mux, caseID, collID, url.Values{"q": {"NTUSER"}, "page_size": {"25"}})
	if lower.Total == 0 {
		t.Fatal("search for ntuser matched nothing")
	}
	if lower.Total != upper.Total {
		t.Errorf("search is case-sensitive: %d vs %d", lower.Total, upper.Total)
	}
	if len(lower.Items) > 25 {
		t.Errorf("search results were not paginated: %d items", len(lower.Items))
	}
	for _, f := range lower.Items {
		hay := strings.ToLower(f.OriginalFilename + " " + f.Path + " " + f.TypeLabel)
		if !strings.Contains(hay, "ntuser") {
			t.Errorf("search returned a non-matching record: %s", f.Path)
		}
	}
}

// Vocabularies must describe the whole collection, never the page --
// a dropdown that shrank as you paged would be unusable.
func TestEvidencePage_VocabulariesDescribeTheWholeCollection(t *testing.T) {
	mux, caseID, collID := bigCase(t, 200)

	page3 := getEvidencePage(t, mux, caseID, collID, url.Values{"page": {"3"}, "page_size": {"25"}})
	page1 := getEvidencePage(t, mux, caseID, collID, url.Values{"page": {"1"}, "page_size": {"25"}})

	if len(page1.Priorities) != len(page3.Priorities) {
		t.Errorf("priority vocabulary changed between pages: %d vs %d", len(page1.Priorities), len(page3.Priorities))
	}
	total := 0
	for _, v := range page1.Priorities {
		total += v.Count
	}
	if total != 200 {
		t.Errorf("priority counts sum to %d, want the whole catalog (200)", total)
	}
	// Even under a filter, the vocabulary still describes the catalog, so
	// the investigator can always widen back out.
	filtered := getEvidencePage(t, mux, caseID, collID, url.Values{"priority": {"critical"}})
	if len(filtered.Priorities) != len(page1.Priorities) {
		t.Error("filtering shrank the priority vocabulary; a filter must not remove its own escape route")
	}
}

// ---------------- select all matching ----------------

func TestEvidenceIDs_ResolveOnlyMatchingSelectableFiles(t *testing.T) {
	mux, caseID, collID := bigCase(t, 200)

	all := getEvidenceIDs(t, mux, caseID, collID, nil)
	page := getEvidencePage(t, mux, caseID, collID, nil)
	if len(all) != page.SelectableTotal {
		t.Errorf("ids returned %d, but selectable_total reported %d -- the count shown and the set acted on must agree",
			len(all), page.SelectableTotal)
	}
	if len(all) == 0 || len(all) >= page.CollectionTotal {
		t.Fatalf("selectable set is implausible: %d of %d", len(all), page.CollectionTotal)
	}

	// "Select all matching" must respect the filter it was invoked under.
	filteredPage := getEvidencePage(t, mux, caseID, collID, url.Values{"q": {"ntuser"}})
	filteredIDs := getEvidenceIDs(t, mux, caseID, collID, url.Values{"q": {"ntuser"}})
	if len(filteredIDs) != filteredPage.SelectableTotal {
		t.Errorf("filtered ids = %d, selectable_total = %d", len(filteredIDs), filteredPage.SelectableTotal)
	}
	if len(filteredIDs) >= len(all) {
		t.Errorf("a filter did not narrow the selectable set: %d vs %d", len(filteredIDs), len(all))
	}

	// The IDs must be stable identifiers, and every one must really be
	// importable -- not merely "on the current page".
	byID := map[string]TriagedSourceFile{}
	for p := 1; p <= 8; p++ {
		for _, f := range getEvidencePage(t, mux, caseID, collID, url.Values{"page": {fmt.Sprint(p)}, "page_size": {"25"}}).Items {
			byID[f.ID] = f
		}
	}
	for _, id := range all {
		f, ok := byID[id]
		if !ok {
			t.Errorf("id %s is not any file in the collection", id)
			continue
		}
		if !f.Supported || f.ImportStatus != model.SourceFileDiscovered {
			t.Errorf("%s is not importable (supported=%v status=%s) but was offered for selection",
				f.Path, f.Supported, f.ImportStatus)
		}
	}
}

// "Select all matching" must never quietly mean "select the first page".
func TestEvidenceIDs_NotLimitedToOnePage(t *testing.T) {
	mux, caseID, collID := bigCase(t, 400)
	ids := getEvidenceIDs(t, mux, caseID, collID, nil)
	if len(ids) <= defaultEvidencePageSize {
		t.Fatalf("select-all resolved %d ids, which is at most one page -- it must span the whole match set", len(ids))
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("duplicate id %s in the select-all set", id)
		}
		seen[id] = true
	}
}

// ---------------- import safety ----------------

// The forensic guarantee: only what was selected is imported, whatever
// the client sends.
func TestImport_ImportsExactlyTheSelectedFilesAndNothingElse(t *testing.T) {
	mux, caseID, collID := bigCase(t, 120)

	ids := getEvidenceIDs(t, mux, caseID, collID, url.Values{"q": {"ntuser"}})
	if len(ids) < 5 {
		t.Fatalf("expected several NTUSER files, got %d", len(ids))
	}
	chosen := ids[:5]

	jobID, code := startImport(t, mux, caseID, collID, chosen)
	if code != http.StatusAccepted {
		t.Fatalf("start import: %d", code)
	}
	_, final := pollJob(t, mux, caseID, jobID)
	if final.FilesTotal != len(chosen) {
		t.Errorf("import reported %d files, want exactly the %d selected", final.FilesTotal, len(chosen))
	}

	imported := map[string]bool{}
	for p := 1; p <= 5; p++ {
		for _, f := range getEvidencePage(t, mux, caseID, collID, url.Values{"page": {fmt.Sprint(p)}, "page_size": {"25"}}).Items {
			if f.ImportStatus == model.SourceFileImported {
				imported[f.ID] = true
			}
		}
	}
	if len(imported) != len(chosen) {
		t.Errorf("%d files ended up imported, but only %d were selected", len(imported), len(chosen))
	}
	for _, id := range chosen {
		if !imported[id] {
			t.Errorf("selected file %s was not imported", id)
		}
	}
}

// A client that sends the same ID twice -- which a selection assembled
// across pages can do -- must not cause the file to be counted twice.
func TestImport_DuplicateSelectionIDsAreCollapsed(t *testing.T) {
	mux, caseID, collID := bigCase(t, 40)
	ids := getEvidenceIDs(t, mux, caseID, collID, nil)
	if len(ids) < 3 {
		t.Fatalf("need at least 3 selectable files, got %d", len(ids))
	}
	chosen := ids[:3]
	withDupes := append(append([]string{}, chosen...), chosen...)

	jobID, code := startImport(t, mux, caseID, collID, withDupes)
	if code != http.StatusAccepted {
		t.Fatalf("start import: %d", code)
	}
	_, final := pollJob(t, mux, caseID, jobID)
	if final.FilesTotal != len(chosen) {
		t.Errorf("files_total = %d for %d distinct files sent %d times; duplicates must be collapsed",
			final.FilesTotal, len(chosen), len(withDupes))
	}
}

// An ID from another case's collection must never be importable through
// this case, whatever the client claims.
func TestImport_RejectsIDsFromAnotherCase(t *testing.T) {
	mux := newTestRouter(t)
	a := mustCreateCase(t, mux, "Case A")
	b := mustCreateCase(t, mux, "Case B")
	discA := discoverBinaryDir(t, mux, a.ID, largeCatalog(20))
	discB := discoverBinaryDir(t, mux, b.ID, mixedCatalog())

	foreign := getEvidenceIDs(t, mux, a.ID, discA.Collection.ID, nil)
	if len(foreign) == 0 {
		t.Fatal("no selectable files in case A")
	}

	jobID, code := startImport(t, mux, b.ID, discB.Collection.ID, foreign[:3])
	if code != http.StatusAccepted {
		t.Fatalf("start import: %d", code)
	}
	_, final := pollJob(t, mux, b.ID, jobID)
	if final.Result == nil {
		t.Fatal("no import result")
	}
	if len(final.Result.Imported) != 0 {
		t.Errorf("%d files from another case were imported", len(final.Result.Imported))
	}
	if len(final.Result.Skipped) != 3 {
		t.Errorf("expected all 3 foreign IDs skipped, got %d skips", len(final.Result.Skipped))
	}
}

// Paging another case's collection through this case's URL must 404,
// not serve it.
func TestEvidencePage_RejectsCollectionFromAnotherCase(t *testing.T) {
	mux := newTestRouter(t)
	a := mustCreateCase(t, mux, "Case A")
	b := mustCreateCase(t, mux, "Case B")
	discA := discoverBinaryDir(t, mux, a.ID, largeCatalog(20))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET",
		"/api/cases/"+b.ID+"/evidence/"+discA.Collection.ID+"/files", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status %d, want 404 -- case B must not be able to page case A's evidence", rec.Code)
	}
}

// Phase 9A's "Select recommended" must survive Phase 10B's rewrite of
// the selection screen. It resolves to high-value evidence that can
// ACTUALLY be imported, and its count must agree with the coverage
// summary the same screen displays -- two numbers on one screen that
// disagree is worse than either being absent.
func TestEvidenceIDs_RecommendedMatchesCoverage(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Recommended")
	disc := discoverBinaryDir(t, mux, c.ID, mixedCatalog())

	ids := getEvidenceIDs(t, mux, c.ID, disc.Collection.ID, url.Values{"recommended": {"true"}})
	if len(ids) != disc.Coverage.Recommended {
		t.Errorf("recommended ids = %d, but coverage.recommended = %d", len(ids), disc.Coverage.Recommended)
	}
	if len(ids) == 0 {
		t.Fatal("nothing recommended in a catalog holding an EVTX and a hive")
	}

	// Every recommended file must be genuinely importable. Recommending
	// something unselectable would put entries in the button that do
	// nothing.
	page := getEvidencePage(t, mux, c.ID, disc.Collection.ID, url.Values{"page_size": {"250"}})
	byID := map[string]TriagedSourceFile{}
	for _, f := range page.Items {
		byID[f.ID] = f
	}
	for _, id := range ids {
		f := byID[id]
		if !f.Recommended {
			t.Errorf("%s was returned as recommended but is not flagged recommended", f.Path)
		}
		if !selectable(f) {
			t.Errorf("%s is recommended but cannot be imported (supported=%v status=%s)",
				f.Path, f.Supported, f.ImportStatus)
		}
	}
}

// "recommended" is a filter like any other, so it must narrow rather
// than replace: a high-priority unsupported artifact is never
// recommended even though it is prominent in the catalog.
func TestEvidenceIDs_RecommendedNarrowsTheSelectableSet(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Recommended narrows")
	// Add a low-priority-but-supported file alongside the critical ones.
	files := mixedCatalog()
	files["Users/jdoe/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt"] = []byte("whoami\n")
	disc := discoverBinaryDir(t, mux, c.ID, files)

	all := getEvidenceIDs(t, mux, c.ID, disc.Collection.ID, nil)
	rec := getEvidenceIDs(t, mux, c.ID, disc.Collection.ID, url.Values{"recommended": {"true"}})
	if len(rec) > len(all) {
		t.Errorf("recommended (%d) exceeds the selectable set (%d)", len(rec), len(all))
	}
	selectableSet := map[string]bool{}
	for _, id := range all {
		selectableSet[id] = true
	}
	for _, id := range rec {
		if !selectableSet[id] {
			t.Errorf("recommended id %s is not in the selectable set", id)
		}
	}
}

// ---------------- Phase 13: page size 10 ----------------

// 10 is the new smallest offered size and the new default. The dense
// evidence rows are the reason: ten of them is about what fits on
// screen, and scanning them is the task.
func TestEvidencePage_SupportsPageSizeTenAsTheDefault(t *testing.T) {
	const n = 120
	mux, caseID, collID := bigCase(t, n)

	// Default, with no page_size given.
	def := getEvidencePage(t, mux, caseID, collID, nil)
	if def.PageSize != 10 {
		t.Errorf("default page_size = %d, want 10", def.PageSize)
	}
	if len(def.Items) != 10 {
		t.Errorf("default page returned %d items, want 10", len(def.Items))
	}
	if def.TotalPages != 12 {
		t.Errorf("total_pages = %d, want 12 for %d records at 10/page", def.TotalPages, n)
	}

	// Every offered size is honored.
	for _, size := range []int{10, 25, 50, 100, 250} {
		p := getEvidencePage(t, mux, caseID, collID, url.Values{"page_size": {fmt.Sprint(size)}})
		if p.PageSize != size {
			t.Errorf("page_size=%d was not honored (got %d)", size, p.PageSize)
		}
		want := size
		if want > n {
			want = n
		}
		if len(p.Items) != want {
			t.Errorf("page_size=%d returned %d items, want %d", size, len(p.Items), want)
		}
	}
}

// Changing page size must land on a valid page, never an empty one.
// Page 12 of 12 at size 10 has no equivalent at size 100.
func TestEvidencePage_ChangingPageSizeNeverProducesAnEmptyPage(t *testing.T) {
	const n = 120
	mux, caseID, collID := bigCase(t, n)

	last := getEvidencePage(t, mux, caseID, collID, url.Values{"page": {"12"}, "page_size": {"10"}})
	if len(last.Items) == 0 {
		t.Fatalf("page 12 at size 10 is empty; expected the final %d records", n%10)
	}
	// The UI resets to page 1 on a size change; the server must serve
	// that correctly rather than honouring a now-out-of-range page.
	resized := getEvidencePage(t, mux, caseID, collID, url.Values{"page": {"1"}, "page_size": {"100"}})
	if len(resized.Items) != 100 {
		t.Errorf("after resizing to 100, page 1 returned %d items, want 100", len(resized.Items))
	}
	if resized.TotalPages != 2 {
		t.Errorf("total_pages = %d, want 2", resized.TotalPages)
	}
}

// A filter that shrinks the result set must not leave the caller on a
// page that no longer exists.
func TestEvidencePage_FilteringRecomputesPageCountAtSizeTen(t *testing.T) {
	mux, caseID, collID := bigCase(t, 200)

	all := getEvidencePage(t, mux, caseID, collID, url.Values{"page_size": {"10"}})
	filtered := getEvidencePage(t, mux, caseID, collID,
		url.Values{"page_size": {"10"}, "priority": {"critical"}})

	if filtered.Total >= all.Total {
		t.Fatalf("filter did not narrow: %d of %d", filtered.Total, all.Total)
	}
	if filtered.TotalPages != (filtered.Total+9)/10 {
		t.Errorf("total_pages = %d, inconsistent with total %d at 10/page", filtered.TotalPages, filtered.Total)
	}
	// A page beyond the filtered result is empty but still reports the
	// true totals, so the client can correct itself to page 1.
	beyond := getEvidencePage(t, mux, caseID, collID,
		url.Values{"page_size": {"10"}, "priority": {"critical"}, "page": {fmt.Sprint(filtered.TotalPages + 5)}})
	if len(beyond.Items) != 0 {
		t.Errorf("a page beyond the filtered set returned %d items", len(beyond.Items))
	}
	if beyond.Total != filtered.Total || beyond.TotalPages != filtered.TotalPages {
		t.Error("an out-of-range page lost the totals the client needs to recover")
	}
}

// Selection must survive paging at the new default size, which is the
// size an analyst will actually be on.
func TestEvidencePage_SelectionSpansPagesAtSizeTen(t *testing.T) {
	mux, caseID, collID := bigCase(t, 120)

	ids := getEvidenceIDs(t, mux, caseID, collID, nil)
	if len(ids) < 30 {
		t.Fatalf("expected at least 30 selectable files, got %d", len(ids))
	}
	// Files drawn from across many pages of 10 import together.
	chosen := []string{ids[0], ids[15], ids[29]}
	jobID, code := startImport(t, mux, caseID, collID, chosen)
	if code != http.StatusAccepted {
		t.Fatalf("start import: %d", code)
	}
	_, final := pollJob(t, mux, caseID, jobID)
	if final.FilesTotal != len(chosen) {
		t.Errorf("files_total = %d, want %d", final.FilesTotal, len(chosen))
	}
}
