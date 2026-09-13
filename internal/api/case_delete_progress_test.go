package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Deletion progress must describe what the backend has actually
// confirmed -- never more.

// Nothing may be reported as removed before the transaction commits, and
// everything must be reported after it.
func TestDeletionProgress_RecordsAreOnlyReportedAfterTheCommit(t *testing.T) {
	svc := newTestService(t)
	caseID, _ := caseWithEvidence(t, svc, "progress commit", 400, 200)

	var (
		mu        sync.Mutex
		snapshots []DeletionProgress
	)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if p, ok := svc.DeletionProgressFor(caseID); ok {
				mu.Lock()
				snapshots = append(snapshots, p)
				mu.Unlock()
			}
			time.Sleep(200 * time.Microsecond)
		}
	}()

	if err := svc.DeleteCase(caseID); err != nil {
		t.Fatalf("DeleteCase: %v", err)
	}
	close(stop)
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(snapshots) == 0 {
		t.Fatal("no progress was published during a deletion")
	}

	for _, p := range snapshots {
		// The invariant: counts exist only alongside confirmation.
		if p.RecordsRemoved != nil && !p.RecordsConfirmed {
			t.Error("row counts were published without being marked confirmed")
		}
		// Nothing may be reported removed while the transaction is still
		// running.
		if p.Stage == DeletionStageRemovingRecords && p.RecordsConfirmed {
			t.Error("records were reported as removed while the transaction was still running")
		}
		if p.Stage == DeletionStagePreparing && p.RecordsRemoved != nil {
			t.Error("records were reported as removed before deletion started")
		}
		// "Complete" may only appear on a finished deletion.
		if p.Stage == DeletionStageComplete && !p.Done {
			t.Error("the stage read Complete before the deletion finished")
		}
	}

	final, ok := svc.DeletionProgressFor(caseID)
	if !ok {
		t.Fatal("the finished deletion left no record to read")
	}
	if !final.Done || final.Stage != DeletionStageComplete {
		t.Fatalf("final stage = %q done=%v", final.Stage, final.Done)
	}
	if final.Error != "" {
		t.Errorf("a successful deletion reported an error: %q", final.Error)
	}
	if !final.RecordsConfirmed || final.RecordsRemoved == nil {
		t.Fatal("a completed deletion did not report what it removed")
	}
	if !final.FilesRemoved {
		t.Error("a completed deletion did not confirm the evidence files were removed")
	}
}

// The counts must be the real ones the database reported, not estimates.
func TestDeletionProgress_CountsMatchWhatWasActuallyDeleted(t *testing.T) {
	svc := newTestService(t)
	const files, events = 500, 321
	caseID, _ := caseWithEvidence(t, svc, "progress counts", files, events)

	if err := svc.DeleteCase(caseID); err != nil {
		t.Fatal(err)
	}
	p, ok := svc.DeletionProgressFor(caseID)
	if !ok || p.RecordsRemoved == nil {
		t.Fatal("no confirmed counts after deletion")
	}
	c := p.RecordsRemoved

	if c.SourceFiles != int64(files) {
		t.Errorf("source files reported %d, actually created %d", c.SourceFiles, files)
	}
	if c.Events != int64(events) {
		t.Errorf("events reported %d, actually created %d", c.Events, events)
	}
	if c.EventObservations != int64(events) {
		t.Errorf("observations reported %d, want %d", c.EventObservations, events)
	}
	if c.Collections != 1 {
		t.Errorf("collections reported %d, want 1", c.Collections)
	}
}

// A failed deletion must report the failure, must not read Complete, and
// must still report whatever WAS confirmed before it failed.
func TestDeletionProgress_FailureIsReportedWithoutClaimingCompletion(t *testing.T) {
	svc := newTestService(t)
	caseID, _ := caseWithEvidence(t, svc, "progress failure", 20, 5)

	// Make the evidence directory undeletable so the filesystem phase
	// fails after the transaction has already committed -- the one
	// partial state this operation can genuinely reach.
	dir := svc.files.CaseDir(caseID)
	if err := makeUndeletable(t, dir); err != nil {
		t.Skipf("cannot make %s undeletable in this environment: %v", dir, err)
	}

	err := svc.DeleteCase(caseID)
	if err == nil {
		t.Skip("the filesystem removal succeeded anyway; this environment cannot exercise the failure")
	}

	p, ok := svc.DeletionProgressFor(caseID)
	if !ok {
		t.Fatal("a failed deletion left no progress record")
	}
	if p.Stage != DeletionStageFailed {
		t.Errorf("stage = %q, want %q", p.Stage, DeletionStageFailed)
	}
	if p.Stage == DeletionStageComplete {
		t.Error("a failed deletion reported Complete")
	}
	if p.Error == "" {
		t.Error("a failed deletion reported no error")
	}
	if p.Error != err.Error() {
		t.Errorf("the progress record and the caller describe the failure differently:\n  progress: %s\n  returned: %s",
			p.Error, err.Error())
	}
	// The records really were removed before the filesystem failed, so
	// that much must still be reported.
	if !p.RecordsConfirmed {
		t.Error("the committed transaction was not reported as confirmed")
	}
	if p.FilesRemoved {
		t.Error("a failed filesystem removal was reported as removed")
	}
}

// Polling must not queue behind the deletion it reports on: the store
// holds a single database connection, and the registry is in memory for
// exactly that reason.
func TestDeletionProgress_PollingDoesNotTouchTheDatabase(t *testing.T) {
	svc := newTestService(t)
	files, events := 7074, 2319
	if raceEnabled {
		files, events = 800, 300
	}
	caseID, _ := caseWithEvidence(t, svc, "progress polling", files, events)

	var slowest time.Duration
	var polls int
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			s := time.Now()
			svc.DeletionProgressFor(caseID)
			if d := time.Since(s); d > slowest {
				slowest = d
			}
			polls++
		}
	}()

	if err := svc.DeleteCase(caseID); err != nil {
		t.Fatal(err)
	}
	close(stop)
	<-done

	t.Logf("%d progress reads during the deletion, slowest %v", polls, slowest)
	// A read that had to wait for the database would be milliseconds.
	if slowest > 20*time.Millisecond*timingBudgetFactor {
		t.Errorf("a progress read took %v; it is supposed to read memory only", slowest)
	}
}

// The publishing must not measurably slow deletion down.
func TestDeletionProgress_OverheadIsNegligible(t *testing.T) {
	if testing.Short() {
		t.Skip("timing measurement skipped in -short")
	}

	// Smaller under -race: the detector makes fixture construction the
	// dominant cost, and the question here is whether publishing adds
	// anything -- not how fast SQLite is.
	files, events := 7074, 2319
	if raceEnabled {
		files, events = 1000, 300
	}
	run := func(t *testing.T) time.Duration {
		svc := newTestService(t)
		caseID, _ := caseWithEvidence(t, svc, "overhead", files, events)
		start := time.Now()
		if err := svc.DeleteCase(caseID); err != nil {
			t.Fatal(err)
		}
		return time.Since(start)
	}

	// Three runs, take the best of each to damp scheduling noise.
	best := time.Hour
	for i := 0; i < 3; i++ {
		if d := run(t); d < best {
			best = d
		}
	}
	t.Logf("delete with progress publishing, %d files / %d events: %v", files, events, best)
	// The publishing is a handful of map writes. If it ever costs enough
	// to matter, this is where it shows up.
	if budget := 3 * time.Second * timingBudgetFactor; best > budget {
		t.Errorf("deletion took %v, over the %v budget; progress publishing should add nothing measurable",
			best, budget)
	}
}

// The HTTP surface.
func TestDeletionProgress_Endpoint(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	c := mustCreateCase(t, mux, "progress endpoint")

	// Nothing running: an honest 404, not an error state.
	rec := doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/deletion-progress", nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("with no deletion running, got %d, want 404", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "no deletion is in progress") {
		t.Errorf("the 404 does not explain itself: %s", rec.Body.String())
	}

	caseID, _ := caseWithEvidence(t, svc, "progress endpoint run", 50, 20)
	if rec := doJSON(t, mux, "DELETE", "/api/cases/"+caseID, nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}

	// The record survives briefly after completion, so a poll that lands
	// just after the response still reads the final state.
	var prog DeletionProgress
	rec = doJSON(t, mux, "GET", "/api/cases/"+caseID+"/deletion-progress", nil, &prog)
	if rec.Code != http.StatusOK {
		t.Fatalf("progress after deletion: %d", rec.Code)
	}
	if !prog.Done || prog.Stage != DeletionStageComplete {
		t.Errorf("stage = %q done = %v", prog.Stage, prog.Done)
	}
	if prog.Label == "" {
		t.Error("the stage has no analyst-facing label")
	}
	if prog.RecordsRemoved == nil || prog.RecordsRemoved.SourceFiles != 50 {
		t.Errorf("records removed = %+v", prog.RecordsRemoved)
	}
	if prog.ElapsedMS < 0 {
		t.Errorf("elapsed = %d", prog.ElapsedMS)
	}
}

// Every stage the API can emit must have a label, or the UI renders a
// raw identifier at an analyst.
func TestDeletionProgress_EveryStageHasALabel(t *testing.T) {
	for _, stage := range []string{
		DeletionStagePreparing, DeletionStageRemovingRecords,
		DeletionStageRemovingFiles, DeletionStageComplete, DeletionStageFailed,
	} {
		if DeletionStageLabels[stage] == "" {
			t.Errorf("stage %q has no label", stage)
		}
	}
}

// makeUndeletable makes dir's contents resist removal, so the
// filesystem phase of a deletion fails. Running as root defeats this,
// which the caller treats as "cannot exercise here" rather than a
// failure.
func makeUndeletable(t *testing.T, dir string) error {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	sub := filepath.Join(dir, "locked")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(sub, "file.bin"), []byte("x"), 0o644); err != nil {
		return err
	}
	// A directory with no write permission cannot have entries removed
	// from it.
	if err := os.Chmod(sub, 0o500); err != nil {
		return err
	}
	t.Cleanup(func() { _ = os.Chmod(sub, 0o755) })
	return nil
}
