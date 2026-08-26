package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"tracefall/internal/casefiles"
	"tracefall/internal/model"
	"tracefall/internal/store"
)

// ---------------- shared helpers ----------------

func deleteSourceFile(t *testing.T, mux *http.ServeMux, caseID, sourceFileID string) (*httptest.ResponseRecorder, DeletedEvidenceResult) {
	t.Helper()
	rec := doJSON(t, mux, "DELETE", "/api/cases/"+caseID+"/evidence/"+sourceFileID, nil, nil)
	var res DeletedEvidenceResult
	if rec.Code == http.StatusOK {
		mustDecode(t, rec, &res)
	}
	return rec, res
}

func deleteSourceFiles(t *testing.T, mux *http.ServeMux, caseID string, ids []string) (*httptest.ResponseRecorder, DeletedEvidenceResult) {
	t.Helper()
	rec := doJSON(t, mux, "DELETE", "/api/cases/"+caseID+"/evidence", map[string][]string{"source_file_ids": ids}, nil)
	var res DeletedEvidenceResult
	if rec.Code == http.StatusOK {
		mustDecode(t, rec, &res)
	}
	return rec, res
}

func deleteCase(t *testing.T, mux *http.ServeMux, caseID string) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, mux, "DELETE", "/api/cases/"+caseID, nil, nil)
}

func bulkDeleteCases(t *testing.T, mux *http.ServeMux, ids []string) (*httptest.ResponseRecorder, BulkDeleteCasesResult) {
	t.Helper()
	rec := doJSON(t, mux, "DELETE", "/api/cases", map[string][]string{"case_ids": ids}, nil)
	var res BulkDeleteCasesResult
	if rec.Code == http.StatusOK {
		mustDecode(t, rec, &res)
	}
	return rec, res
}

// newTestServiceWithFiles is like newTestService, but also returns the
// *casefiles.Store so tests can assert directly on what's (or isn't) on
// disk -- needed for filesystem-cleanup assertions that newTestService's
// black-box *Service doesn't expose.
func newTestServiceWithFiles(t *testing.T) (*Service, *casefiles.Store) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("opening test store: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	files := casefiles.NewStore(t.TempDir())
	return NewService(db, files), files
}

// ---------------- evidence selection ----------------

// TestEvidenceSelection_OnlySelectedFilesImported covers item 3/18: a ZIP
// with 5 supported files, selecting only 2, must import exactly those 2
// -- the other 3 must not be parsed and must not contribute events.
func TestEvidenceSelection_OnlySelectedFilesImported(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "Selection case")

	files := map[string]string{}
	for i, name := range []string{"a", "b", "c", "d", "e"} {
		row := evtxRow("2026-01-15T09:0"+string(rune('0'+i))+":00.0000000Z", "4624", "Security", "WKSTN-042", name,
			"TargetUserName: "+name+"; LogonType: 2", "1")
		files["EvtxECmd/"+name+"_EvtxECmd_Output.csv"] = evtxHeader + row
	}
	zipData := buildZipBytes(t, files)

	discRec := uploadZip(t, mux, c.ID, zipData)
	if discRec.Code != http.StatusOK {
		t.Fatalf("discover: status %d, body %s", discRec.Code, discRec.Body.String())
	}
	var disc DiscoverResult
	mustDecode(t, discRec, &disc)
	if disc.SupportedCount != 5 {
		t.Fatalf("got %d supported files discovered, want 5", disc.SupportedCount)
	}

	// Select only the first 2.
	var selected []string
	for _, sf := range disc.SourceFiles {
		if len(selected) < 2 {
			selected = append(selected, sf.ID)
		}
	}
	importRec := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/evidence/"+disc.Collection.ID+"/import",
		map[string][]string{"source_file_ids": selected}, nil)
	if importRec.Code != http.StatusOK {
		t.Fatalf("import: status %d, body %s", importRec.Code, importRec.Body.String())
	}
	var imp ImportResult
	mustDecode(t, importRec, &imp)
	if len(imp.Imported) != 2 {
		t.Fatalf("got %d imported files, want 2", len(imp.Imported))
	}
	if imp.EventCount != 2 {
		t.Errorf("EventCount = %d, want 2 (one logon event per imported file)", imp.EventCount)
	}

	// The other 3 must still be sitting there un-imported, not parsed.
	var collDetail CollectionDetail
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/evidence/"+disc.Collection.ID, nil, &collDetail)
	var stillDiscovered, imported int
	for _, sf := range collDetail.SourceFiles {
		switch sf.ImportStatus {
		case model.SourceFileDiscovered:
			stillDiscovered++
		case model.SourceFileImported:
			imported++
			if sf.EventCount == 0 {
				t.Errorf("imported file %s has EventCount 0", sf.OriginalFilename)
			}
		}
	}
	if imported != 2 {
		t.Errorf("got %d imported files in collection detail, want 2", imported)
	}
	if stillDiscovered != 3 {
		t.Errorf("got %d files still only discovered, want 3 (not selected, not parsed)", stillDiscovered)
	}

	var timeline []model.Event
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/timeline", nil, &timeline)
	if len(timeline) != 2 {
		t.Fatalf("timeline has %d events, want 2 (only the selected/imported files)", len(timeline))
	}
}

// ---------------- duplicate handling ----------------

// TestEvidenceDuplicate_WithinCollectionNotImportedTwice covers item 5:
// the same file content appearing twice within one discovered batch is
// classified as a duplicate and cannot be selected for import -- no
// second copy of its events is ever created.
func TestEvidenceDuplicate_WithinCollectionNotImportedTwice(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "In-batch duplicate case")

	csv := evtxHeader + evtxRow("2026-01-15T09:00:00.0000000Z", "4624", "Security", "WKSTN-042", "jdoe",
		"TargetUserName: jdoe; LogonType: 2", "1")
	zipData := buildZipBytes(t, map[string]string{
		"EvtxECmd/a_EvtxECmd_Output.csv": csv, // identical content, two different paths
		"EvtxECmd/b_EvtxECmd_Output.csv": csv,
	})

	discRec := uploadZip(t, mux, c.ID, zipData)
	if discRec.Code != http.StatusOK {
		t.Fatalf("discover: status %d, body %s", discRec.Code, discRec.Body.String())
	}
	var disc DiscoverResult
	mustDecode(t, discRec, &disc)
	if disc.DuplicateCount != 1 {
		t.Fatalf("DuplicateCount = %d, want 1", disc.DuplicateCount)
	}

	var selectableID, duplicateID string
	for _, sf := range disc.SourceFiles {
		switch sf.ImportStatus {
		case model.SourceFileDiscovered:
			selectableID = sf.ID
		case model.SourceFileDuplicate:
			duplicateID = sf.ID
		}
	}
	if selectableID == "" || duplicateID == "" {
		t.Fatalf("expected one discovered + one duplicate file, got %+v", disc.SourceFiles)
	}

	// Attempting to import the duplicate-flagged file must not succeed --
	// it's reported as skipped, not imported.
	importRec := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/evidence/"+disc.Collection.ID+"/import",
		map[string][]string{"source_file_ids": {selectableID, duplicateID}}, nil)
	if importRec.Code != http.StatusOK {
		t.Fatalf("import: status %d, body %s", importRec.Code, importRec.Body.String())
	}
	var imp ImportResult
	mustDecode(t, importRec, &imp)
	if len(imp.Imported) != 1 {
		t.Fatalf("got %d imported files, want 1 (the duplicate must be skipped, not imported)", len(imp.Imported))
	}
	foundSkip := false
	for _, sk := range imp.Skipped {
		if sk.SourceFileID == duplicateID {
			foundSkip = true
		}
	}
	if !foundSkip {
		t.Errorf("expected the duplicate file ID to be reported in Skipped, got %+v", imp.Skipped)
	}

	var timeline []model.Event
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/timeline", nil, &timeline)
	if len(timeline) != 1 {
		t.Fatalf("timeline has %d events, want 1 (no duplicate event created)", len(timeline))
	}
}

// ---------------- evidence deletion ----------------

// TestEvidenceDeletion_OtherFileRemains covers item 7/18: deleting one
// evidence file must not affect a case's other, unrelated evidence file.
func TestEvidenceDeletion_OtherFileRemains(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "Delete one file case")

	csvA := evtxHeader + evtxRow("2026-01-15T09:00:00.0000000Z", "4624", "Security", "WKSTN-042", "alice",
		"TargetUserName: alice; LogonType: 2", "1")
	csvB := evtxHeader + evtxRow("2026-01-15T09:05:00.0000000Z", "4624", "Security", "WKSTN-042", "bob",
		"TargetUserName: bob; LogonType: 2", "1")
	zipData := buildZipBytes(t, map[string]string{
		"EvtxECmd/a_EvtxECmd_Output.csv": csvA,
		"EvtxECmd/b_EvtxECmd_Output.csv": csvB,
	})
	disc, imp := uploadAndImportAll(t, mux, c.ID, zipData)
	if len(imp.Imported) != 2 {
		t.Fatalf("got %d imported files, want 2", len(imp.Imported))
	}

	var aliceFileID, bobFileID string
	for _, sf := range imp.Imported {
		if sf.OriginalFilename == "a_EvtxECmd_Output.csv" {
			aliceFileID = sf.ID
		} else {
			bobFileID = sf.ID
		}
	}
	if aliceFileID == "" || bobFileID == "" {
		t.Fatalf("could not resolve both file IDs from %+v", imp.Imported)
	}

	delRec, delRes := deleteSourceFile(t, mux, c.ID, aliceFileID)
	if delRec.Code != http.StatusOK {
		t.Fatalf("delete: status %d, body %s", delRec.Code, delRec.Body.String())
	}
	if len(delRes.DeletedSourceFiles) != 1 || delRes.EventsRemoved != 1 || delRes.EventsRetained != 0 {
		t.Errorf("got %+v, want 1 deleted file, 1 event removed, 0 retained", delRes)
	}

	var timeline []model.Event
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/timeline", nil, &timeline)
	if len(timeline) != 1 || timeline[0].User != "bob" {
		t.Fatalf("timeline after deletion = %+v, want just bob's event", timeline)
	}

	var collDetail CollectionDetail
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/evidence/"+disc.Collection.ID, nil, &collDetail)
	if len(collDetail.SourceFiles) != 1 || collDetail.SourceFiles[0].ID != bobFileID {
		t.Errorf("collection detail after deletion = %+v, want just bob's file", collDetail.SourceFiles)
	}
	if collDetail.ImportedFileCount != 1 || collDetail.ParsedEventCount != 1 {
		t.Errorf("collection counts after deletion = imported=%d events=%d, want 1/1", collDetail.ImportedFileCount, collDetail.ParsedEventCount)
	}
}

// TestEvidenceDeletion_SharedEventSurvivesUntilLastObservationRemoved is
// the dedicated test item 10/18 requires: an event observed via two
// different source files (the same underlying event, re-collected --
// see docs/data-model.md) must survive deleting just one of those source
// files, and only disappear once its last remaining observation is also
// deleted.
func TestEvidenceDeletion_SharedEventSurvivesUntilLastObservationRemoved(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "Shared event deletion case")

	sharedRow := evtxRow("2026-01-15T09:00:00.0000000Z", "4624", "Security", "WKSTN-042", "jdoe",
		"TargetUserName: jdoe; LogonType: 2", "1")
	csv1 := evtxHeader + sharedRow + evtxRow("2026-01-15T09:05:00.0000000Z", "4624", "Security", "WKSTN-042", "alice",
		"TargetUserName: alice; LogonType: 2", "2")
	csv2 := evtxHeader + sharedRow + evtxRow("2026-01-15T09:10:00.0000000Z", "4624", "Security", "WKSTN-042", "bob",
		"TargetUserName: bob; LogonType: 2", "3")
	zip1 := buildZipBytes(t, map[string]string{"EvtxECmd/a_EvtxECmd_Output.csv": csv1})
	zip2 := buildZipBytes(t, map[string]string{"EvtxECmd/b_EvtxECmd_Output.csv": csv2})

	disc1, imp1 := uploadAndImportAll(t, mux, c.ID, zip1)
	_, imp2 := uploadAndImportAll(t, mux, c.ID, zip2)
	if len(imp1.Imported) != 1 || len(imp2.Imported) != 1 {
		t.Fatalf("expected exactly one imported file per collection: %+v / %+v", imp1.Imported, imp2.Imported)
	}
	collection1FileID := imp1.Imported[0].ID

	var timeline []model.Event
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/timeline", nil, &timeline)
	if len(timeline) != 3 {
		t.Fatalf("timeline has %d events, want 3 (deduplicated jdoe + alice + bob)", len(timeline))
	}
	var sharedEventID string
	for _, e := range timeline {
		if e.User == "jdoe" {
			sharedEventID = e.ID
		}
	}
	if sharedEventID == "" {
		t.Fatal("could not find the shared jdoe event")
	}

	var provBefore EventProvenance
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/events/"+sharedEventID, nil, &provBefore)
	if len(provBefore.Observations) != 2 {
		t.Fatalf("got %d observations before deletion, want 2", len(provBefore.Observations))
	}

	// Delete collection #1's file (one of the shared event's two
	// observations) -- the event must survive via collection #2's.
	delRec, delRes := deleteSourceFile(t, mux, c.ID, collection1FileID)
	if delRec.Code != http.StatusOK {
		t.Fatalf("delete collection #1 file: status %d, body %s", delRec.Code, delRec.Body.String())
	}
	if delRes.EventsRemoved != 1 || delRes.EventsRetained != 1 {
		t.Fatalf("got %+v, want 1 event removed (alice), 1 retained (the shared jdoe event)", delRes)
	}

	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/timeline", nil, &timeline)
	if len(timeline) != 2 {
		t.Fatalf("timeline after first deletion has %d events, want 2 (jdoe survives, alice gone, bob untouched)", len(timeline))
	}
	var stillHasShared bool
	for _, e := range timeline {
		if e.ID == sharedEventID {
			stillHasShared = true
		}
	}
	if !stillHasShared {
		t.Fatal("shared jdoe event disappeared after deleting only one of its two observations")
	}

	// Its own denormalized provenance must have been re-pointed at the
	// surviving observation (collection #2), not left dangling at the
	// now-deleted collection #1 file.
	var provAfter EventProvenance
	rec := doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/events/"+sharedEventID, nil, &provAfter)
	if rec.Code != http.StatusOK {
		t.Fatalf("get event provenance after partial deletion: status %d, body %s", rec.Code, rec.Body.String())
	}
	if len(provAfter.Observations) != 1 {
		t.Fatalf("got %d observations after deleting one, want 1", len(provAfter.Observations))
	}
	if provAfter.Event.SourceFileID == collection1FileID {
		t.Error("event's own provenance still points at the deleted source file")
	}
	if provAfter.SourceFile.ID == "" || provAfter.RawEvidence.Raw == "" {
		t.Error("event provenance broken after re-pointing (source file / raw evidence unresolved)")
	}

	// Now delete the last remaining observation's file (collection #2's)
	// -- the event must disappear entirely.
	delRec2, delRes2 := deleteSourceFile(t, mux, c.ID, imp2.Imported[0].ID)
	if delRec2.Code != http.StatusOK {
		t.Fatalf("delete collection #2 file: status %d, body %s", delRec2.Code, delRec2.Body.String())
	}
	if delRes2.EventsRemoved != 2 || delRes2.EventsRetained != 0 {
		t.Fatalf("got %+v, want 2 events removed (jdoe's last observation + bob), 0 retained", delRes2)
	}

	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/timeline", nil, &timeline)
	if len(timeline) != 0 {
		t.Fatalf("timeline after both collections' files deleted has %d events, want 0", len(timeline))
	}
	_ = disc1
}

// TestEvidenceDeletion_RecalculatesFindings covers items 9/18: deleting
// the evidence a finding depends on must make that finding disappear on
// the next analysis run (never silently kept as if still current), while
// a finding independently supported by remaining evidence survives.
// Reuses the exact fixture TestMultiCollection_EndToEnd already proves
// produces an execution-persistence-temporal finding only once both its
// collections are present -- deleting the persistence collection's
// evidence here is the mirror image of adding it there.
func TestEvidenceDeletion_RecalculatesFindings(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "Recalculate findings case")

	_, execImp := uploadAndImportAll(t, mux, c.ID, buildExecutionCollectionZip(t))
	_, persistImp := uploadAndImportAll(t, mux, c.ID, buildPersistenceCollectionZip(t))
	if len(persistImp.Imported) == 0 {
		t.Fatal("persistence collection imported nothing")
	}

	var analyzeBefore AnalyzeResultSummary
	rec := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/analyze", nil, &analyzeBefore)
	if rec.Code != http.StatusOK {
		t.Fatalf("analyze: status %d, body %s", rec.Code, rec.Body.String())
	}
	var hadCrossCollectionFinding, hadExecutionOnlyFinding bool
	for _, f := range analyzeBefore.Findings {
		if f.RuleID == "execution-persistence-temporal" {
			hadCrossCollectionFinding = true
		}
		if f.RuleID == "office-spawns-powershell" {
			hadExecutionOnlyFinding = true
		}
	}
	if !hadCrossCollectionFinding {
		t.Fatal("expected execution-persistence-temporal before deletion")
	}
	if !hadExecutionOnlyFinding {
		t.Fatal("expected office-spawns-powershell (supported by the execution collection alone) before deletion")
	}

	// Delete every file the persistence collection imported -- the
	// evidence execution-persistence-temporal depends on is now gone.
	var persistFileIDs []string
	for _, sf := range persistImp.Imported {
		persistFileIDs = append(persistFileIDs, sf.ID)
	}
	delRec, _ := deleteSourceFiles(t, mux, c.ID, persistFileIDs)
	if delRec.Code != http.StatusOK {
		t.Fatalf("bulk delete: status %d, body %s", delRec.Code, delRec.Body.String())
	}

	// Stale findings must not be presented as current: status must have
	// reverted so the dashboard prompts a re-run rather than continuing
	// to show analysis based on evidence that's now gone.
	var caseDetail struct {
		Case model.Case `json:"case"`
	}
	doJSON(t, mux, "GET", "/api/cases/"+c.ID, nil, &caseDetail)
	if caseDetail.Case.Status == model.CaseStatusAnalyzed {
		t.Error("case still shows status 'analyzed' after evidence it was analyzed from was deleted")
	}

	var analyzeAfter AnalyzeResultSummary
	rec = doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/analyze", nil, &analyzeAfter)
	if rec.Code != http.StatusOK {
		t.Fatalf("re-analyze: status %d, body %s", rec.Code, rec.Body.String())
	}
	var stillHasCrossCollectionFinding, stillHasExecutionOnlyFinding bool
	for _, f := range analyzeAfter.Findings {
		if f.RuleID == "execution-persistence-temporal" {
			stillHasCrossCollectionFinding = true
		}
		if f.RuleID == "office-spawns-powershell" {
			stillHasExecutionOnlyFinding = true
		}
	}
	if stillHasCrossCollectionFinding {
		t.Error("execution-persistence-temporal finding survived even though its persistence evidence was deleted")
	}
	if !stillHasExecutionOnlyFinding {
		t.Error("office-spawns-powershell finding disappeared even though its evidence (the execution collection) was never touched")
	}

	_ = execImp
}

// TestBulkEvidenceDeletion_OnlySelectedRemoved covers item 8/18.
func TestBulkEvidenceDeletion_OnlySelectedRemoved(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "Bulk delete evidence case")

	files := map[string]string{}
	for _, name := range []string{"alice", "bob", "carol"} {
		files["EvtxECmd/"+name+"_EvtxECmd_Output.csv"] = evtxHeader + evtxRow(
			"2026-01-15T09:00:00.0000000Z", "4624", "Security", "WKSTN-042", name, "TargetUserName: "+name+"; LogonType: 2", "1")
	}
	_, imp := uploadAndImportAll(t, mux, c.ID, buildZipBytes(t, files))
	if len(imp.Imported) != 3 {
		t.Fatalf("got %d imported files, want 3", len(imp.Imported))
	}

	byName := map[string]string{}
	for _, sf := range imp.Imported {
		byName[sf.OriginalFilename] = sf.ID
	}
	toDelete := []string{byName["alice_EvtxECmd_Output.csv"], byName["bob_EvtxECmd_Output.csv"]}

	delRec, delRes := deleteSourceFiles(t, mux, c.ID, toDelete)
	if delRec.Code != http.StatusOK {
		t.Fatalf("bulk delete: status %d, body %s", delRec.Code, delRec.Body.String())
	}
	if len(delRes.DeletedSourceFiles) != 2 {
		t.Errorf("got %d deleted files, want 2", len(delRes.DeletedSourceFiles))
	}

	var timeline []model.Event
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/timeline", nil, &timeline)
	if len(timeline) != 1 || timeline[0].User != "carol" {
		t.Fatalf("timeline after bulk deletion = %+v, want just carol's event", timeline)
	}
}

// ---------------- case deletion ----------------

// TestCaseDeletion_RemovesEverything covers item 18's case-deletion
// requirements directly: deleting a case removes its collections,
// source files, events, findings, correlations, and on-disk evidence,
// and leaves a sibling case completely untouched.
func TestCaseDeletion_RemovesEverything(t *testing.T) {
	svc, files := newTestServiceWithFiles(t)
	mux := routerFor(svc)

	c := createTestCase(t, mux, "Case to delete")
	disc, imp := uploadAndImportAll(t, mux, c.ID, buildKAPEZip(t))
	if len(imp.Imported) == 0 {
		t.Fatal("expected at least one imported file")
	}
	var analyzeRes AnalyzeResultSummary
	rec := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/analyze", nil, &analyzeRes)
	if rec.Code != http.StatusOK || len(analyzeRes.Findings) == 0 {
		t.Fatalf("analyze: status %d, findings=%d", rec.Code, len(analyzeRes.Findings))
	}

	// A sibling case, untouched by the deletion below.
	other := createTestCase(t, mux, "Untouched sibling case")
	uploadAndImportAll(t, mux, other.ID, buildKAPEZip(t))

	caseDir := files.CaseDir(c.ID)
	if _, err := os.Stat(caseDir); err != nil {
		t.Fatalf("expected case directory to exist before deletion: %v", err)
	}

	delRec := deleteCase(t, mux, c.ID)
	if delRec.Code != http.StatusOK {
		t.Fatalf("delete case: status %d, body %s", delRec.Code, delRec.Body.String())
	}

	if rec := doJSON(t, mux, "GET", "/api/cases/"+c.ID, nil, nil); rec.Code != http.StatusNotFound {
		t.Errorf("GET deleted case: status %d, want %d", rec.Code, http.StatusNotFound)
	}
	if _, err := os.Stat(caseDir); !os.IsNotExist(err) {
		t.Errorf("case directory still exists after deletion: err=%v", err)
	}

	// No orphan records anywhere -- verified directly against the store,
	// not just through case-scoped API endpoints (which would 404/empty
	// regardless of whether rows were actually deleted).
	if cols, err := svc.store.ListCollections(c.ID); err != nil || len(cols) != 0 {
		t.Errorf("collections after case deletion: %+v, err=%v, want none", cols, err)
	}
	if sources, err := svc.store.ListSourceFiles(c.ID); err != nil || len(sources) != 0 {
		t.Errorf("source files after case deletion: %+v, err=%v, want none", sources, err)
	}
	if events, err := svc.store.ListEvents(c.ID); err != nil || len(events) != 0 {
		t.Errorf("events after case deletion: %+v, err=%v, want none", events, err)
	}
	if findings, err := svc.store.ListFindings(c.ID); err != nil || len(findings) != 0 {
		t.Errorf("findings after case deletion: %+v, err=%v, want none", findings, err)
	}
	if corrs, err := svc.store.ListCorrelations(c.ID); err != nil || len(corrs) != 0 {
		t.Errorf("correlations after case deletion: %+v, err=%v, want none", corrs, err)
	}

	// The sibling case must be completely unaffected.
	if rec := doJSON(t, mux, "GET", "/api/cases/"+other.ID, nil, nil); rec.Code != http.StatusOK {
		t.Errorf("sibling case no longer reachable: status %d", rec.Code)
	}
	var otherTimeline []model.Event
	doJSON(t, mux, "GET", "/api/cases/"+other.ID+"/timeline", nil, &otherTimeline)
	if len(otherTimeline) == 0 {
		t.Error("sibling case lost its events")
	}
	_ = disc
}

// TestCaseDeletion_DoesNotAffectSameEvidenceInAnotherCase covers item
// 18's specific requirement: deleting a case must not affect another
// case that happens to contain evidence with the same archive/source
// hash -- collection-level duplicate detection is scoped per case (see
// docs/data-model.md), and deletion must respect that same boundary.
func TestCaseDeletion_DoesNotAffectSameEvidenceInAnotherCase(t *testing.T) {
	mux := newTestRouter(t)
	caseA := createTestCase(t, mux, "Case A")
	caseB := createTestCase(t, mux, "Case B")

	zipData := buildKAPEZip(t)
	_, impA := uploadAndImportAll(t, mux, caseA.ID, zipData)
	_, impB := uploadAndImportAll(t, mux, caseB.ID, zipData) // identical archive hash, different case: allowed
	if len(impA.Imported) == 0 || len(impB.Imported) == 0 {
		t.Fatal("expected both cases to import evidence from the identical archive")
	}

	if rec := deleteCase(t, mux, caseA.ID); rec.Code != http.StatusOK {
		t.Fatalf("delete case A: status %d, body %s", rec.Code, rec.Body.String())
	}

	var timelineB []model.Event
	rec := doJSON(t, mux, "GET", "/api/cases/"+caseB.ID+"/timeline", nil, &timelineB)
	if rec.Code != http.StatusOK {
		t.Fatalf("get case B timeline: status %d", rec.Code)
	}
	if len(timelineB) != impB.EventCount {
		t.Errorf("case B timeline has %d events after case A (same evidence hash) was deleted, want %d (unchanged)", len(timelineB), impB.EventCount)
	}
	if len(timelineB) == 0 {
		t.Error("case B timeline unexpectedly empty after deleting case A")
	}
}

// TestCaseDeletion_Bulk covers bulk case deletion, including a request
// that mixes valid and invalid IDs -- the valid ones must still be
// deleted, with the invalid one clearly reported as failed rather than
// aborting the whole batch.
func TestCaseDeletion_Bulk(t *testing.T) {
	mux := newTestRouter(t)
	c1 := createTestCase(t, mux, "Bulk delete A")
	c2 := createTestCase(t, mux, "Bulk delete B")
	c3 := createTestCase(t, mux, "Bulk delete C (kept)")

	rec, res := bulkDeleteCases(t, mux, []string{c1.ID, c2.ID, "does-not-exist"})
	if rec.Code != http.StatusOK {
		t.Fatalf("bulk delete: status %d, body %s", rec.Code, rec.Body.String())
	}
	if len(res.Deleted) != 2 {
		t.Errorf("got %d deleted, want 2: %+v", len(res.Deleted), res)
	}
	if _, failed := res.Failed["does-not-exist"]; !failed {
		t.Errorf("expected 'does-not-exist' to be reported failed, got %+v", res.Failed)
	}

	for _, id := range []string{c1.ID, c2.ID} {
		if rec := doJSON(t, mux, "GET", "/api/cases/"+id, nil, nil); rec.Code != http.StatusNotFound {
			t.Errorf("case %s: status %d, want %d (deleted)", id, rec.Code, http.StatusNotFound)
		}
	}
	if rec := doJSON(t, mux, "GET", "/api/cases/"+c3.ID, nil, nil); rec.Code != http.StatusOK {
		t.Errorf("case C (not in the delete request): status %d, want %d (kept)", rec.Code, http.StatusOK)
	}
}

// TestCaseDeletion_ConcurrentDeleteSameCase covers item 18's "concurrent
// safety where relevant": firing many simultaneous delete requests at
// the exact same case must delete it exactly once (not error out with a
// partial/corrupt deletion), leaving every other case untouched. Run
// with -race to also catch any data races in the Go-level request
// handling itself.
func TestCaseDeletion_ConcurrentDeleteSameCase(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "Concurrently deleted case")
	other := createTestCase(t, mux, "Untouched during concurrent delete")

	const attempts = 8
	var wg sync.WaitGroup
	codes := make([]int, attempts)
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i] = deleteCase(t, mux, c.ID).Code
		}(i)
	}
	wg.Wait()

	var succeeded int
	for _, code := range codes {
		if code == http.StatusOK {
			succeeded++
		} else if code != http.StatusNotFound {
			t.Errorf("unexpected status %d among concurrent deletes", code)
		}
	}
	if succeeded < 1 {
		t.Error("expected at least one concurrent delete to succeed")
	}

	if rec := doJSON(t, mux, "GET", "/api/cases/"+c.ID, nil, nil); rec.Code != http.StatusNotFound {
		t.Errorf("case after concurrent deletes: status %d, want %d", rec.Code, http.StatusNotFound)
	}
	if rec := doJSON(t, mux, "GET", "/api/cases/"+other.ID, nil, nil); rec.Code != http.StatusOK {
		t.Errorf("unrelated case affected by concurrent deletes of another case: status %d", rec.Code)
	}
}
