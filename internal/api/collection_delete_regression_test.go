package api

import (
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"tracefall/internal/model"
)

// Regression tests for collection deletion, covering the shapes the
// performance investigation exercised and the correctness boundary the
// bulk path depends on.

// The whole safety argument for the bulk path is this guard. If it ever
// returns true for a collection whose events another collection also
// observes, that other collection's evidence is destroyed.
func TestDeleteCollection_GuardDistinguishesSharedFromSelfContained(t *testing.T) {
	svc := newTestService(t)
	c, err := svc.CreateCase("guard", "")
	if err != nil {
		t.Fatal(err)
	}

	// Self-contained: its own files, its own events.
	own, _ := perfCollection(t, svc, c.ID, 5, 5, false)
	if ok, err := svc.store.CollectionEventsAreSelfContained(own); err != nil || !ok {
		t.Fatalf("a collection with only its own events reported shared (ok=%v err=%v)", ok, err)
	}

	// Empty collections are trivially self-contained.
	empty, _ := perfCollection(t, svc, c.ID, 0, 0, false)
	if ok, err := svc.store.CollectionEventsAreSelfContained(empty); err != nil || !ok {
		t.Fatalf("an empty collection reported shared (ok=%v err=%v)", ok, err)
	}

	// Shared: a second collection observes one of the first's events.
	second, secondFiles := perfCollection(t, svc, c.ID, 3, 0, false)
	events, err := svc.store.ListEvents(c.ID)
	if err != nil || len(events) == 0 {
		t.Fatalf("no events to share: %v", err)
	}
	shared := events[0]
	if err := svc.store.SaveEventObservations([]model.EventObservation{{
		ID: uuid.NewString(), EventID: shared.ID, CaseID: c.ID,
		CollectionID: second, SourceFileID: secondFiles[0].ID,
	}}); err != nil {
		t.Fatal(err)
	}

	// The event is attributed to `own` and now observed by `second`.
	if ok, err := svc.store.CollectionEventsAreSelfContained(own); err != nil || ok {
		t.Errorf("a collection whose event is observed elsewhere reported self-contained (ok=%v err=%v)", ok, err)
	}
	if ok, err := svc.store.CollectionEventsAreSelfContained(second); err != nil || ok {
		t.Errorf("a collection observing another's event reported self-contained (ok=%v err=%v)", ok, err)
	}
}

// The behaviour the guard protects: deleting a collection must not
// destroy an event another collection independently observed.
func TestDeleteCollection_SharedEventSurvivesAndIsRepointed(t *testing.T) {
	svc := newTestService(t)
	c, err := svc.CreateCase("shared events", "")
	if err != nil {
		t.Fatal(err)
	}

	first, _ := perfCollection(t, svc, c.ID, 2, 2, false)
	second, secondFiles := perfCollection(t, svc, c.ID, 2, 0, false)

	events, err := svc.store.ListEvents(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}
	shared := events[0]
	if err := svc.store.SaveEventObservations([]model.EventObservation{{
		ID: uuid.NewString(), EventID: shared.ID, CaseID: c.ID,
		CollectionID: second, SourceFileID: secondFiles[0].ID,
	}}); err != nil {
		t.Fatal(err)
	}

	res, err := svc.DeleteCollection(c.ID, first)
	if err != nil {
		t.Fatalf("DeleteCollection: %v", err)
	}
	if res.EventsRetained != 1 {
		t.Errorf("EventsRetained = %d, want 1 (the shared event)", res.EventsRetained)
	}
	if res.EventsRemoved != 1 {
		t.Errorf("EventsRemoved = %d, want 1 (the unshared event)", res.EventsRemoved)
	}

	survived, err := svc.store.GetEvent(shared.ID)
	if err != nil {
		t.Fatalf("the shared event was destroyed along with the collection that no longer holds it: %v", err)
	}
	// Its provenance must now point at the collection that still has it.
	if survived.CollectionID != second {
		t.Errorf("the surviving event still points at the deleted collection (%s)", survived.CollectionID)
	}
	if survived.SourceFileID == "" {
		t.Error("the surviving event has no source file")
	}
}

// The reported case: PENDING, thousands of discovered rows, nothing
// imported, no events. It must delete completely, and the result must
// report what actually went.
func TestDeleteCollection_PendingWithThousandsDiscoveredAndNothingImported(t *testing.T) {
	svc := newTestService(t)
	c, err := svc.CreateCase("pending bulk", "")
	if err != nil {
		t.Fatal(err)
	}
	// Thousands of rows is the point of this test. Under -race the
	// detector makes building them the dominant cost, so the figure is
	// reduced there -- still thousands, still the same assertion.
	discovered := 7074
	if raceEnabled {
		discovered = 2000
	}
	collectionID, files := perfCollection(t, svc, c.ID, discovered, 0, true)

	col, err := svc.store.GetCollection(collectionID)
	if err != nil {
		t.Fatal(err)
	}
	if col.IngestionStatus != model.CollectionStatusPending {
		t.Fatalf("fixture is not pending: %q", col.IngestionStatus)
	}
	if col.ImportedFileCount != 0 {
		t.Fatalf("fixture has %d imported files", col.ImportedFileCount)
	}

	res, err := svc.DeleteCollection(c.ID, collectionID)
	if err != nil {
		t.Fatalf("DeleteCollection: %v", err)
	}
	if res.SourceFilesRemoved != discovered {
		t.Errorf("SourceFilesRemoved = %d, want %d", res.SourceFilesRemoved, discovered)
	}
	if res.EventsRemoved != 0 || res.EventsRetained != 0 {
		t.Errorf("events removed/retained = %d/%d, want 0/0", res.EventsRemoved, res.EventsRetained)
	}

	// Every row gone -- not soft-deleted and left behind.
	if _, err := svc.store.GetCollection(collectionID); err == nil {
		t.Error("the collection row survived")
	}
	var rows int
	if err := svc.store.DB().QueryRow(
		`SELECT COUNT(*) FROM source_files WHERE collection_id = ?`, collectionID).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Errorf("%d source_files rows survived (soft-deleted rows are not good enough)", rows)
	}

	// The evidence directory goes with it.
	if _, err := os.Stat(svc.files.CollectionDir(c.ID, collectionID)); !os.IsNotExist(err) {
		t.Errorf("the collection directory survived: %v", err)
	}
	_ = files
}

// Unsupported files are ordinary catalog rows. This is the reason "0
// imported" does not mean "little to delete", and it is asserted so the
// assumption cannot quietly stop being true.
func TestDeleteCollection_UnsupportedFilesArePersistentRowsAndAreRemoved(t *testing.T) {
	svc := newTestService(t)
	c, err := svc.CreateCase("unsupported rows", "")
	if err != nil {
		t.Fatal(err)
	}
	const discovered = 400
	collectionID, _ := perfCollection(t, svc, c.ID, discovered, 0, false)

	var unsupported int
	if err := svc.store.DB().QueryRow(
		`SELECT COUNT(*) FROM source_files WHERE collection_id = ? AND supported = 0`,
		collectionID).Scan(&unsupported); err != nil {
		t.Fatal(err)
	}
	if unsupported == 0 {
		t.Fatal("the fixture produced no unsupported rows; this test would prove nothing")
	}

	res, err := svc.DeleteCollection(c.ID, collectionID)
	if err != nil {
		t.Fatal(err)
	}
	if res.SourceFilesRemoved != discovered {
		t.Errorf("SourceFilesRemoved = %d, want %d (unsupported rows count too)",
			res.SourceFilesRemoved, discovered)
	}
}

// Both paths must agree about what they removed, or the fast one is
// reporting a different deletion from the one it performed.
func TestDeleteCollection_BothPathsReportTheSameCounts(t *testing.T) {
	build := func(t *testing.T) (*Service, string, string) {
		t.Helper()
		svc := newTestService(t)
		c, err := svc.CreateCase("parity "+t.Name(), "")
		if err != nil {
			t.Fatal(err)
		}
		collectionID, _ := perfCollection(t, svc, c.ID, 40, 10, false)
		return svc, c.ID, collectionID
	}

	// Fast path.
	svcFast, caseFast, colFast := build(t)
	if ok, _ := svcFast.store.CollectionEventsAreSelfContained(colFast); !ok {
		t.Fatal("precondition: this fixture should be self-contained")
	}
	fast, err := svcFast.DeleteCollection(caseFast, colFast)
	if err != nil {
		t.Fatal(err)
	}

	// Same shape, forced down the per-file path by giving one event an
	// observation in a second collection, then removing that collection's
	// influence is not possible -- so instead compare against the
	// per-file path run directly over the same fixture.
	svcSlow, caseSlow, colSlow := build(t)
	files, err := svcSlow.store.ListSourceFilesByCollection(colSlow)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(files))
	for _, f := range files {
		ids = append(ids, f.ID)
	}
	slow, err := svcSlow.DeleteSourceFiles(caseSlow, ids)
	if err != nil {
		t.Fatal(err)
	}

	if fast.SourceFilesRemoved != len(slow.DeletedSourceFiles) {
		t.Errorf("source files: bulk reported %d, per-file reported %d",
			fast.SourceFilesRemoved, len(slow.DeletedSourceFiles))
	}
	if fast.EventsRemoved != slow.EventsRemoved {
		t.Errorf("events removed: bulk reported %d, per-file reported %d",
			fast.EventsRemoved, slow.EventsRemoved)
	}
	if fast.EventsRetained != slow.EventsRetained {
		t.Errorf("events retained: bulk reported %d, per-file reported %d",
			fast.EventsRetained, slow.EventsRetained)
	}
}

// Deleting one collection must not touch another.
func TestDeleteCollection_LeavesOtherCollectionsIntact(t *testing.T) {
	svc := newTestService(t)
	c, err := svc.CreateCase("isolation", "")
	if err != nil {
		t.Fatal(err)
	}
	victim, _ := perfCollection(t, svc, c.ID, 300, 0, true)
	keep, keepFiles := perfCollection(t, svc, c.ID, 120, 20, true)

	if _, err := svc.DeleteCollection(c.ID, victim); err != nil {
		t.Fatal(err)
	}

	remaining, err := svc.store.ListSourceFilesByCollection(keep)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != len(keepFiles) {
		t.Errorf("the surviving collection has %d files, want %d", len(remaining), len(keepFiles))
	}
	if _, err := svc.store.GetCollection(keep); err != nil {
		t.Errorf("the surviving collection's row was removed: %v", err)
	}
	if _, err := os.Stat(svc.files.CollectionDir(c.ID, keep)); err != nil {
		t.Errorf("the surviving collection's directory was removed: %v", err)
	}
	n, err := svc.store.CountEventsByCollection(keep)
	if err != nil {
		t.Fatal(err)
	}
	if n != 20 {
		t.Errorf("the surviving collection has %d events, want 20", n)
	}
}

// Deletion failure: a locked case refuses, and refuses BEFORE anything
// is removed.
func TestDeleteCollection_FailureLeavesEverythingInPlace(t *testing.T) {
	svc := newTestService(t)
	c, err := svc.CreateCase("locked", "")
	if err != nil {
		t.Fatal(err)
	}
	collectionID, files := perfCollection(t, svc, c.ID, 250, 0, true)

	closed := model.CaseWorkflowClosed
	if _, err := svc.UpdateCaseMetadata(c.ID, CaseMetadataUpdate{CaseStatus: &closed}); err != nil {
		t.Fatalf("closing the case: %v", err)
	}

	if _, err := svc.DeleteCollection(c.ID, collectionID); err == nil {
		t.Fatal("deleting a collection from a closed case succeeded")
	}

	if _, err := svc.store.GetCollection(collectionID); err != nil {
		t.Errorf("the refused deletion removed the collection anyway: %v", err)
	}
	remaining, err := svc.store.ListSourceFilesByCollection(collectionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != len(files) {
		t.Errorf("%d of %d catalog rows survived a refused deletion", len(remaining), len(files))
	}
	if _, err := os.Stat(svc.files.CollectionDir(c.ID, collectionID)); err != nil {
		t.Errorf("the refused deletion removed the evidence directory: %v", err)
	}
}

// A collection that does not belong to this case is not found, and
// nothing of the other case is touched.
func TestDeleteCollection_CrossCaseIsRefused(t *testing.T) {
	svc := newTestService(t)
	a, err := svc.CreateCase("case a", "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := svc.CreateCase("case b", "")
	if err != nil {
		t.Fatal(err)
	}
	collectionID, _ := perfCollection(t, svc, a.ID, 50, 0, true)

	if _, err := svc.DeleteCollection(b.ID, collectionID); err == nil {
		t.Fatal("a collection was deleted through the wrong case")
	}
	if _, err := svc.store.GetCollection(collectionID); err != nil {
		t.Errorf("the other case's collection was removed: %v", err)
	}
}

// The HTTP surface: a pending collection with thousands of rows deletes
// synchronously and answers 200 with the counts.
func TestDeleteCollection_HTTPReturnsCountsSynchronously(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	c := mustCreateCase(t, mux, "http bulk delete")
	discovered := 3000
	if raceEnabled {
		discovered = 1000
	}
	collectionID, _ := perfCollection(t, svc, c.ID, discovered, 0, true)

	start := time.Now()
	var res DeletedCollectionResult
	rec := doJSON(t, mux, "DELETE", "/api/cases/"+c.ID+"/collections/"+collectionID, nil, &res)
	elapsed := time.Since(start)

	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE: %d %s", rec.Code, rec.Body.String())
	}
	if res.SourceFilesRemoved != discovered {
		t.Errorf("SourceFilesRemoved = %d, want %d", res.SourceFilesRemoved, discovered)
	}
	// The response IS the completion signal -- deletion is synchronous,
	// so by the time it arrives the rows are gone.
	if _, err := svc.store.GetCollection(collectionID); err == nil {
		t.Error("the response arrived before the collection was removed")
	}
	t.Logf("HTTP DELETE of %d discovered rows: %v", discovered, elapsed)

	// A guard against the per-file loop coming back unnoticed. The
	// measured cost of that path was ~0.4 ms per catalog row; the bulk
	// path is ~0.02 ms. This threshold sits far above the bulk path and
	// far below the loop, so it fails on a regression without being
	// flaky on a slow machine -- see timingBudgetFactor for why it is
	// scaled rather than fixed.
	budget := time.Duration(discovered) * 200 * time.Microsecond * timingBudgetFactor
	if elapsed > budget {
		t.Errorf("deleting %d discovered rows took %v, over the %v budget -- "+
			"the per-file path has probably returned", discovered, elapsed, budget)
	}
}

// Deleting a collection twice: the second attempt is a clean not-found,
// not a partial re-run.
func TestDeleteCollection_SecondAttemptIsNotFound(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	c := mustCreateCase(t, mux, "double delete")
	collectionID, _ := perfCollection(t, svc, c.ID, 20, 0, true)

	if rec := doJSON(t, mux, "DELETE", "/api/cases/"+c.ID+"/collections/"+collectionID, nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("first delete: %d", rec.Code)
	}
	rec := doJSON(t, mux, "DELETE", "/api/cases/"+c.ID+"/collections/"+collectionID, nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("second delete returned %d, want 404", rec.Code)
	}
}
