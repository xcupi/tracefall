package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
)

func deleteCollection(t *testing.T, mux http.Handler, caseID, collectionID string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("DELETE", "/api/cases/"+caseID+"/collections/"+collectionID, nil))
	return rec
}

func collectionsOf(t *testing.T, mux http.Handler, caseID string) []model.Collection {
	t.Helper()
	var out []model.Collection
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/evidence", nil, &out)
	return out
}

// (2)(3)(14)(15) Deleting a collection with imported files removes the
// collection, its catalog rows and its events, leaving nothing orphaned.
func TestDeleteCollection_RemovesCollectionAndItsEvidence(t *testing.T) {
	svc := newTestService(t)
	mux := routerFor(svc)
	c := mustCreateCase(t, mux, "Delete collection")
	disc, _ := discoverPathAndImportAll(t, mux, c.ID, "../../testdata/synthetic_case")
	analyzeStatus(t, mux, c.ID)

	before := derivedCounts(t, mux, c.ID)
	if before.Events == 0 {
		t.Fatal("no events to remove")
	}

	rec := deleteCollection(t, mux, c.ID, disc.Collection.ID)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete collection: status %d, body %s", rec.Code, rec.Body.String())
	}
	var res DeletedCollectionResult
	json.Unmarshal(rec.Body.Bytes(), &res)
	if res.SourceFilesRemoved == 0 {
		t.Error("reported 0 source files removed")
	}
	if !res.AnalysisStale {
		t.Error("deletion did not report the analysis as stale")
	}

	// The collection is gone from the case.
	if cols := collectionsOf(t, mux, c.ID); len(cols) != 0 {
		t.Errorf("%d collection(s) remain after deleting the only one", len(cols))
	}
	// No orphaned catalog rows, events or observations.
	var sources []model.SourceFile
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/sources", nil, &sources)
	if len(sources) != 0 {
		t.Errorf("%d source file(s) orphaned after collection deletion", len(sources))
	}
	all, err := svc.store.ListSourceFilesIncludingDeleted(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 0 {
		t.Errorf("%d soft-deleted source file row(s) still reference the removed collection", len(all))
	}
	var events []model.Event
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/timeline", nil, &events)
	if len(events) != 0 {
		t.Errorf("%d event(s) survived the removal of their only collection", len(events))
	}
}

// (4) A collection with nothing imported still deletes cleanly.
func TestDeleteCollection_WithZeroImportedFiles(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Discovered only")
	rec := discoverPath(t, mux, c.ID, "../../testdata/synthetic_case")
	if rec.Code != http.StatusOK {
		t.Fatalf("discover: %d", rec.Code)
	}
	var disc DiscoverResult
	mustDecode(t, rec, &disc)
	if disc.Collection.ImportedFileCount != 0 {
		t.Fatalf("fixture already has %d imported files", disc.Collection.ImportedFileCount)
	}

	if got := deleteCollection(t, mux, c.ID, disc.Collection.ID); got.Code != http.StatusOK {
		t.Fatalf("delete: status %d, body %s", got.Code, got.Body.String())
	}
	if cols := collectionsOf(t, mux, c.ID); len(cols) != 0 {
		t.Errorf("%d collection(s) remain", len(cols))
	}
}

// (5)(6)(16) Deleting one collection leaves the other intact, and a
// later analysis reflects only what remains.
func TestDeleteCollection_OtherCollectionSurvivesAndAnalysisReflectsIt(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Two collections")
	keep, _ := discoverPathAndImportAll(t, mux, c.ID, "../../testdata/synthetic_case")
	drop, _ := discoverPathAndImportAll(t, mux, c.ID, "../../testdata/native_samples")
	analyzeStatus(t, mux, c.ID)
	both := derivedCounts(t, mux, c.ID)

	if got := deleteCollection(t, mux, c.ID, drop.Collection.ID); got.Code != http.StatusOK {
		t.Fatalf("delete: status %d, body %s", got.Code, got.Body.String())
	}

	cols := collectionsOf(t, mux, c.ID)
	if len(cols) != 1 || cols[0].ID != keep.Collection.ID {
		t.Fatalf("expected only the surviving collection, got %d", len(cols))
	}

	if code := analyzeStatus(t, mux, c.ID); code != http.StatusOK {
		t.Fatalf("rerun: %d", code)
	}
	after := derivedCounts(t, mux, c.ID)
	if after.Events == 0 {
		t.Error("the surviving collection's events were removed too")
	}
	if after.Events >= both.Events {
		t.Errorf("events did not shrink: %d -> %d", both.Events, after.Events)
	}
	// (6) Nothing from the deleted collection may contribute.
	var events []model.Event
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/timeline", nil, &events)
	for _, e := range events {
		if e.CollectionID == drop.Collection.ID {
			t.Errorf("an event still attributed to the deleted collection: %s", e.ID)
		}
	}
}

// (7) Deleting a collection marks the case for re-analysis.
func TestDeleteCollection_MarksAnalysisStale(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Stale after collection delete")
	disc, _ := discoverPathAndImportAll(t, mux, c.ID, "../../testdata/synthetic_case")
	analyzeStatus(t, mux, c.ID)

	var wrapper struct {
		Case model.Case `json:"case"`
	}
	doJSON(t, mux, "GET", "/api/cases/"+c.ID, nil, &wrapper)
	if wrapper.Case.Status != model.CaseStatusAnalyzed {
		t.Fatalf("case status = %q, want analyzed", wrapper.Case.Status)
	}

	deleteCollection(t, mux, c.ID, disc.Collection.ID)
	doJSON(t, mux, "GET", "/api/cases/"+c.ID, nil, &wrapper)
	if wrapper.Case.Status == model.CaseStatusAnalyzed {
		t.Error("the case still reports itself analyzed after a collection was deleted")
	}

	// And a rerun produces the coherent empty snapshot.
	if code := analyzeStatus(t, mux, c.ID); code != http.StatusOK {
		t.Fatalf("rerun after collection deletion: status %d, want 200", code)
	}
	if got := derivedCounts(t, mux, c.ID); got != (derived{}) {
		t.Errorf("derived results survived the collection: %+v", got)
	}
}

// (8) Phase 11 analysis-run history is unaffected by evidence deletion:
// the record that a run happened outlives the evidence it read.
func TestDeleteCollection_PreservesAnalysisRunHistory(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Run history preserved")
	disc, _ := discoverPathAndImportAll(t, mux, c.ID, "../../testdata/synthetic_case")
	analyzeStatus(t, mux, c.ID)

	var before CaseProvenance
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/provenance", nil, &before)
	if len(before.AnalysisRuns) == 0 {
		t.Fatal("no analysis runs recorded")
	}

	deleteCollection(t, mux, c.ID, disc.Collection.ID)

	var after CaseProvenance
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/provenance", nil, &after)
	if len(after.AnalysisRuns) < len(before.AnalysisRuns) {
		t.Errorf("analysis run history shrank on evidence deletion: %d -> %d",
			len(before.AnalysisRuns), len(after.AnalysisRuns))
	}
	if after.AnalysisRuns[len(after.AnalysisRuns)-1].ID != before.AnalysisRuns[len(before.AnalysisRuns)-1].ID {
		t.Error("an existing analysis run record was altered by deletion")
	}
}

// (9)(10)(11) Lifecycle enforcement, server-side.
func TestDeleteCollection_LifecycleEnforcement(t *testing.T) {
	for _, tc := range []struct {
		status   string
		wantCode int
	}{
		{model.CaseWorkflowOpen, http.StatusOK},
		{model.CaseWorkflowInvestigating, http.StatusOK},
		{model.CaseWorkflowContained, http.StatusConflict},
		{model.CaseWorkflowClosed, http.StatusConflict},
	} {
		t.Run(tc.status, func(t *testing.T) {
			mux := newTestRouter(t)
			c := mustCreateCase(t, mux, "Lifecycle "+tc.status)
			disc, _ := discoverPathAndImportAll(t, mux, c.ID, "../../testdata/synthetic_case")
			setStatus(t, mux, c.ID, tc.status)

			got := deleteCollection(t, mux, c.ID, disc.Collection.ID)
			if got.Code != tc.wantCode {
				t.Fatalf("delete collection while %s: status %d, want %d (body %s)",
					tc.status, got.Code, tc.wantCode, got.Body.String())
			}
			cols := collectionsOf(t, mux, c.ID)
			if tc.wantCode == http.StatusOK && len(cols) != 0 {
				t.Errorf("collection survived a permitted deletion")
			}
			if tc.wantCode != http.StatusOK && len(cols) != 1 {
				t.Errorf("a refused deletion still removed the collection")
			}
		})
	}
}

// A refused deletion must leave the evidence completely untouched.
func TestDeleteCollection_RefusalIsAtomic(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Refusal atomic")
	disc, _ := discoverPathAndImportAll(t, mux, c.ID, "../../testdata/synthetic_case")
	analyzeStatus(t, mux, c.ID)
	setStatus(t, mux, c.ID, model.CaseWorkflowContained)

	before := sourcesSnapshot(t, mux, c.ID)
	beforeDerived := derivedCounts(t, mux, c.ID)

	if got := deleteCollection(t, mux, c.ID, disc.Collection.ID); got.Code != http.StatusConflict {
		t.Fatalf("status %d, want 409", got.Code)
	}
	if after := sourcesSnapshot(t, mux, c.ID); after != before {
		t.Error("a refused collection deletion changed the evidence set")
	}
	if after := derivedCounts(t, mux, c.ID); after != beforeDerived {
		t.Error("a refused collection deletion changed the derived results")
	}
}

// A collection belonging to another case must not be deletable through
// this case's URL.
func TestDeleteCollection_RejectsCollectionFromAnotherCase(t *testing.T) {
	mux := newTestRouter(t)
	a := mustCreateCase(t, mux, "Owner")
	b := mustCreateCase(t, mux, "Bystander")
	disc, _ := discoverPathAndImportAll(t, mux, a.ID, "../../testdata/synthetic_case")

	if got := deleteCollection(t, mux, b.ID, disc.Collection.ID); got.Code != http.StatusNotFound {
		t.Errorf("cross-case collection deletion: status %d, want 404", got.Code)
	}
	if cols := collectionsOf(t, mux, a.ID); len(cols) != 1 {
		t.Error("case A's collection was removed through case B")
	}
}

// (13) The deletion is audited, naming what went.
func TestDeleteCollection_IsAudited(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Audited deletion")
	disc, _ := discoverPathAndImportAll(t, mux, c.ID, "../../testdata/synthetic_case")

	deleteCollection(t, mux, c.ID, disc.Collection.ID)

	var found bool
	for _, e := range auditEntries(t, mux, c.ID) {
		if e.Action == model.AuditEvidenceDeleted && e.TargetType == model.TargetCollection {
			found = true
			if e.TargetID != disc.Collection.ID {
				t.Errorf("audit target = %q, want the collection id", e.TargetID)
			}
			if e.Actor == "" {
				t.Error("audit entry records no actor")
			}
		}
	}
	if !found {
		t.Error("collection deletion left no collection-scoped audit entry")
	}
}

// (1) "Delete selected" keeps working, and removes exactly the selected
// files rather than the whole collection.
func TestDeleteSelected_RemovesExactlyTheSelectedFiles(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Delete selected")
	discoverPathAndImportAll(t, mux, c.ID, "../../testdata/synthetic_case")

	var sources []model.SourceFile
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/sources", nil, &sources)
	if len(sources) < 3 {
		t.Fatalf("need at least 3 files, got %d", len(sources))
	}
	chosen := []string{sources[0].ID, sources[1].ID}

	rec := doJSON(t, mux, "DELETE", "/api/cases/"+c.ID+"/evidence",
		map[string][]string{"source_file_ids": chosen}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete selected: status %d, body %s", rec.Code, rec.Body.String())
	}

	var after []model.SourceFile
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/sources", nil, &after)
	if len(after) != len(sources)-len(chosen) {
		t.Errorf("%d files remain, want %d", len(after), len(sources)-len(chosen))
	}
	gone := map[string]bool{chosen[0]: true, chosen[1]: true}
	for _, sf := range after {
		if gone[sf.ID] {
			t.Errorf("selected file %s was not deleted", sf.ID)
		}
	}
	// The collection itself survives a per-file deletion.
	if cols := collectionsOf(t, mux, c.ID); len(cols) != 1 {
		t.Errorf("deleting selected files removed the collection")
	}
}

// (12) Collection deletion is a DELETE, so it inherits the router's
// admin-only rule. An analyst must be refused, and the collection must
// survive.
func TestDeleteCollection_RequiresAdmin(t *testing.T) {
	f := newAuthFixture(t, time.Hour)
	f.mustCreateUser(t, "boss", "admin-password-here", model.RoleAdmin)
	f.mustCreateUser(t, "annie", "analyst-password-12", model.RoleAnalyst)

	admin, _ := f.login(t, "boss", "admin-password-here")
	created := admin.do("POST", "/api/cases", map[string]string{"name": "Admin-only deletion"})
	var c model.Case
	json.Unmarshal(created.Body.Bytes(), &c)

	// Seed evidence THROUGH the authenticated admin client, so the
	// request carries the session and CSRF token the router requires.
	if got := admin.do("POST", "/api/cases/"+c.ID+"/ingest",
		map[string]string{"path": "../../testdata/synthetic_case"}); got.Code != http.StatusOK {
		t.Fatalf("seeding evidence: status %d, body %s", got.Code, got.Body.String())
	}
	var cols []model.Collection
	adminList := admin.do("GET", "/api/cases/"+c.ID+"/evidence", nil)
	json.Unmarshal(adminList.Body.Bytes(), &cols)
	if len(cols) != 1 {
		t.Fatalf("expected 1 collection, got %d", len(cols))
	}
	collID := cols[0].ID

	analyst, _ := f.login(t, "annie", "analyst-password-12")
	if got := analyst.do("DELETE", "/api/cases/"+c.ID+"/collections/"+collID, nil); got.Code != http.StatusForbidden {
		t.Errorf("analyst deleting a collection: status %d, want 403", got.Code)
	}
	// It is still there.
	after := admin.do("GET", "/api/cases/"+c.ID+"/evidence", nil)
	var remaining []model.Collection
	json.Unmarshal(after.Body.Bytes(), &remaining)
	if len(remaining) != 1 {
		t.Errorf("the collection an analyst was refused permission to delete is gone")
	}
	// And the admin can.
	if got := admin.do("DELETE", "/api/cases/"+c.ID+"/collections/"+collID, nil); got.Code != http.StatusOK {
		t.Errorf("admin deleting a collection: status %d, want 200 (body %s)", got.Code, got.Body.String())
	}
}

// The coverage counts are TWO independent partitions, and the UI states
// their relationship explicitly. This pins that relationship so the
// statement on screen cannot drift from the model behind it.
//
// Measured, not assumed:
//
//	supported + unsupported                          = discovered
//	imported + not_imported + duplicates + parse_failed = SUPPORTED
//
// The second sums to supported rather than discovered because an
// unsupported file carries import_status "unsupported" and is never a
// candidate for import -- it belongs to the first breakdown only.
func TestCoverage_CountAxesPartitionAsDocumented(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Coverage axes")

	hive := persistenceHive()
	files := map[string][]byte{
		"Users/a/NTUSER.DAT":                  hive,
		"Users/b/NTUSER.DAT":                  hive, // exact duplicate by SHA-256
		"Windows/Prefetch/A.pf":               []byte("MAM\x04compressed-one"),
		"Windows/Prefetch/B.pf":               []byte("MAM\x04compressed-two"),
		"readme.txt":                          []byte("not evidence"),
		"Windows/System32/winevt/Logs/S.evtx": attackEvtx(),
	}
	disc := discoverBinaryDir(t, mux, c.ID, files)
	coll := disc.Collection.ID

	// Import everything selectable so imported / parse_failed are populated.
	ids := getEvidenceIDs(t, mux, c.ID, coll, nil)
	if len(ids) > 0 {
		doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/evidence/"+coll+"/import",
			map[string][]string{"source_file_ids": ids}, nil)
	}

	var detail CollectionDetail
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/evidence/"+coll, nil, &detail)
	cov := detail.Coverage

	if got := cov.Supported + cov.Unsupported; got != cov.Discovered {
		t.Errorf("supported(%d) + unsupported(%d) = %d, want discovered(%d)",
			cov.Supported, cov.Unsupported, got, cov.Discovered)
	}
	importAxis := cov.Imported + cov.NotImported + cov.Duplicates + cov.ParseFailed
	if importAxis != cov.Supported {
		t.Errorf("imported(%d)+not_imported(%d)+duplicates(%d)+parse_failed(%d) = %d, want supported(%d)",
			cov.Imported, cov.NotImported, cov.Duplicates, cov.ParseFailed, importAxis, cov.Supported)
	}
	// The fixture must actually exercise every bucket, or the assertion
	// above would hold vacuously.
	if cov.Unsupported == 0 || cov.Duplicates == 0 || cov.ParseFailed == 0 || cov.Imported == 0 {
		t.Errorf("fixture did not populate every bucket: %+v", cov)
	}
	// Parse failed must never be folded into unsupported.
	if cov.ParseFailed > 0 && cov.Unsupported == cov.Discovered {
		t.Error("parse failures were classified as unsupported")
	}
}

// The UI's stated relationship must match the model.
func TestCoverage_UIStatesTheMeasuredRelationship(t *testing.T) {
	src, err := os.ReadFile("../web/static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	body := functionBody(t, src, "function renderEvidenceCoverage(")

	if !strings.Contains(body, "Supported + Unsupported") {
		t.Error("the coverage note no longer states the capability-axis relationship")
	}
	if !strings.Contains(body, "supported</em> files only") {
		t.Error("the coverage note does not say the import breakdown covers only supported files; " +
			"it would imply those four numbers sum to discovered, which they do not")
	}
	for _, label := range []string{"Discovered", "Supported", "Unsupported", "Imported", "Not imported", "Duplicates", "Parse failed"} {
		if !strings.Contains(body, ">"+label+"<") {
			t.Errorf("coverage strip is missing the %q category", label)
		}
	}
}
