package api

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"tracefall/internal/model"
)

func queuedImportFixture(t *testing.T) (svc *Service, caseID, collectionID string, ids []string) {
	t.Helper()
	svc = newTestService(t)
	mux := routerFor(svc)
	c := mustCreateCase(t, mux, "Queued import")
	rec := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/ingest",
		map[string]string{"path": filepath.Join("..", "..", "testdata", "synthetic_case")}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("discover: %d %s", rec.Code, rec.Body.String())
	}
	var disc DiscoverResult
	mustDecode(t, rec, &disc)
	ids = getEvidenceIDs(t, mux, c.ID, disc.Collection.ID, nil)
	if len(ids) == 0 {
		t.Fatal("nothing to import")
	}
	return svc, c.ID, disc.Collection.ID, ids
}

func waitImport(t *testing.T, svc *Service, caseID, jobID string, ok func(ImportProgress) bool) ImportProgress {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		p, err := svc.ImportJob(caseID, jobID)
		if err != nil {
			t.Fatal(err)
		}
		if ok(p) {
			return p
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out; last progress: %+v", p)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// With the one place taken, a second import is queued, says so, and runs when
// the place is free. Nothing is read or written while it waits.
func TestImport_ASecondImportWaitsForTheFirstThenRuns(t *testing.T) {
	svc, caseID, colID, ids := queuedImportFixture(t)
	svc.SetImportLimit(1)
	hold, err := svc.imports.Acquire(context.Background()) // another import is running
	if err != nil {
		t.Fatal(err)
	}
	jobID, err := svc.StartImport(caseID, colID, ids)
	if err != nil {
		t.Fatal(err)
	}
	waitImport(t, svc, caseID, jobID, func(p ImportProgress) bool { return p.Phase == PhaseQueued })
	time.Sleep(300 * time.Millisecond)
	p, _ := svc.ImportJob(caseID, jobID)
	if p.Done || p.Phase != PhaseQueued {
		t.Fatalf("the import ran while another held the only place: %+v", p)
	}
	if st := svc.ImportStats(); st.Waiting != 1 || st.Running != 1 {
		t.Fatalf("gate: %+v", st)
	}
	if n, _ := svc.store.CountEvents(caseID); n != 0 {
		t.Fatalf("%d events were written while the import was queued", n)
	}

	hold()
	done := waitImport(t, svc, caseID, jobID, func(p ImportProgress) bool { return p.Done })
	if done.Phase != PhaseComplete || done.Result == nil || len(done.Result.Imported) == 0 {
		t.Fatalf("the queued import did not complete: %+v", done)
	}
	if st := svc.ImportStats(); st.Running != 0 || st.Waiting != 0 || st.PeakRunning > 1 {
		t.Fatalf("after: %+v", st)
	}
}

// Cancelling a queued import ends it as cancelled, imports nothing and frees
// its place in the queue; the collection can be imported afterwards.
func TestImport_ACancelledQueuedImportImportsNothing(t *testing.T) {
	svc, caseID, colID, ids := queuedImportFixture(t)
	svc.SetImportLimit(1)
	hold, _ := svc.imports.Acquire(context.Background())
	jobID, err := svc.StartImport(caseID, colID, ids)
	if err != nil {
		t.Fatal(err)
	}
	waitImport(t, svc, caseID, jobID, func(p ImportProgress) bool { return p.Phase == PhaseQueued })
	if _, err := svc.CancelImport(caseID, jobID); err != nil {
		t.Fatal(err)
	}
	p := waitImport(t, svc, caseID, jobID, func(p ImportProgress) bool { return p.Done })
	if p.Phase != PhaseCancelled || !p.Cancelled || p.Result == nil || p.Result.Unprocessed != len(ids) || len(p.Result.Imported) != 0 {
		t.Fatalf("cancelled while queued: %+v", p)
	}
	if st := svc.ImportStats(); st.Waiting != 0 {
		t.Fatalf("the cancelled import is still queued: %+v", st)
	}
	files, _ := svc.store.ListSourceFilesByCollection(colID)
	for _, f := range files {
		if f.ImportStatus == model.SourceFileImported {
			t.Fatalf("file %s was imported by an import cancelled while queued", f.Path)
		}
	}

	hold()
	jobID2, err := svc.StartImport(caseID, colID, ids)
	if err != nil {
		t.Fatal(err)
	}
	done := waitImport(t, svc, caseID, jobID2, func(p ImportProgress) bool { return p.Done })
	if done.Phase != PhaseComplete {
		t.Fatalf("the import after the cancelled one: %+v", done)
	}
}
