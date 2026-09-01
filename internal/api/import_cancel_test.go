package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/prefetch/prefetchgen"
)

// Import cancellation (issue 2).
//
// The guarantee under test is not "the button works" but the data-model
// promise behind it: a cancelled import leaves every file either fully
// imported or completely untouched, never half-written, and reports
// honestly which is which.

// startBigImport discovers a directory with enough files that an import
// takes long enough to be cancellable, and starts it.
func startBigImport(t *testing.T, mux http.Handler, caseID string, n int) (collectionID, jobID string, selected []string) {
	t.Helper()
	// Each file must have DISTINCT content. samplePrefetch() returns the
	// same bytes every time, so a directory of copies is deduplicated by
	// SHA-256 at discovery and only one file is ever selectable -- which
	// would make "cancel a large import" silently test a one-file
	// import, and never exercise the partial-import case at all.
	files := map[string][]byte{}
	for i := 0; i < n; i++ {
		files[fmt.Sprintf("Windows/Prefetch/APP%03d.pf", i)] = distinctPrefetch(i)
	}
	disc := discoverBinaryDir(t, mux, caseID, files)
	collectionID = disc.Collection.ID
	// The ids endpoint, not disc.SourceFiles: discovery returns only the
	// first PAGE of files, so selecting from it would cap every "large"
	// import at one page regardless of how many files were built.
	selected = getEvidenceIDs(t, mux, caseID, collectionID, nil)
	if len(selected) < n/2 {
		t.Fatalf("only %d of %d files selectable; the fixture is not exercising a large import", len(selected), n)
	}

	jobID, code := startImport(t, mux, caseID, collectionID, selected)
	if code != http.StatusAccepted {
		t.Fatalf("start import: status %d, want 202", code)
	}
	return collectionID, jobID, selected
}

// distinctPrefetch builds a valid Prefetch file whose content is unique
// per index, so a directory of them survives discovery-time
// deduplication as separate importable files.
func distinctPrefetch(i int) []byte {
	run := time.Date(2026, 3, 1, 9, 20, 0, 0, time.UTC).Add(time.Duration(i) * time.Minute)
	return prefetchgen.Build(prefetchgen.File{
		Version:        30,
		ExecutableName: fmt.Sprintf("APP%03d.EXE", i),
		PrefetchHash:   uint32(0x0BADF000 + i),
		RunCount:       uint32(1 + i%7),
		LastRunTimes:   []time.Time{run, run.Add(-2 * time.Hour)},
		Filenames: []string{
			fmt.Sprintf(`\VOLUME{01d7}\USERS\JDOE\APPDATA\LOCAL\TEMP\APP%03d.EXE`, i),
			`\VOLUME{01d7}\WINDOWS\SYSTEM32\NTDLL.DLL`,
		},
		VolumeDevicePath: `\DEVICE\HARDDISKVOLUME1`,
		VolumeSerial:     0xA1B2C3D4,
		VolumeCreated:    run.Add(-720 * time.Hour),
	})
}

// waitJob is pollJob with only the final state, which is all these
// tests care about.
func waitJob(t *testing.T, mux http.Handler, caseID, jobID string) ImportProgress {
	t.Helper()
	_, final := pollJob(t, mux, caseID, jobID)
	return final
}

// postCancel issues a cancel and returns the HTTP status.
func postCancel(t *testing.T, mux http.Handler, caseID, jobID string) int {
	t.Helper()
	rec := doJSON(t, mux, "POST", "/api/cases/"+caseID+"/import-jobs/"+jobID+"/cancel", nil, nil)
	return rec.Code
}

// Cancelling immediately must stop the import and leave nothing
// half-written.
func TestCancelImport_StopsAndLeavesConsistentState(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Cancel import")
	coll, jobID, selected := startBigImport(t, mux, c.ID, 40)

	var cancelled ImportProgress
	doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/import-jobs/"+jobID+"/cancel", nil, &cancelled)
	_ = cancelled
	if !cancelled.CancelRequested {
		t.Error("cancel did not record that cancellation was requested")
	}

	final := waitJob(t, mux, c.ID, jobID)
	if !final.Done {
		t.Fatal("job never finished after cancellation")
	}
	// The import may legitimately have completed before the cancel
	// landed -- that race is real and must not fail the test. What must
	// hold either way is that the state is consistent.
	if final.Phase != PhaseCancelled && final.Phase != PhaseComplete {
		t.Fatalf("phase = %q, want cancelled or complete", final.Phase)
	}
	if final.Phase == PhaseFailed || final.Error != "" {
		t.Errorf("cancellation was reported as a failure: phase=%q err=%q", final.Phase, final.Error)
	}
	if final.Result == nil {
		t.Fatal("a cancelled import returned no result; the analyst cannot see what was imported")
	}

	// Every file is either imported or still discovered. Nothing is left
	// in a partial state, and nothing untouched is called a failure.
	var listing EvidenceFilePage
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/evidence/"+coll+"/files?page=1&page_size=250", nil, &listing)
	var imported, discovered, other int
	for _, f := range listing.Items {
		switch f.ImportStatus {
		case model.SourceFileImported:
			imported++
		case model.SourceFileDiscovered:
			discovered++
		default:
			other++
		}
	}
	if imported+discovered+other != len(listing.Items) {
		t.Fatal("file accounting does not add up")
	}
	if imported != len(final.Result.Imported) {
		t.Errorf("result claims %d imported, catalog shows %d", len(final.Result.Imported), imported)
	}
	if final.Result.Cancelled && final.Result.Unprocessed > 0 && discovered == 0 {
		t.Error("result reports unprocessed files but none remain importable")
	}
	// Unprocessed files must never be recorded as parse failures.
	if final.Result.Cancelled {
		for _, pf := range final.Result.ParseFailures {
			if strings.Contains(strings.ToLower(pf.Message), "cancel") {
				t.Errorf("an unprocessed file was recorded as a parse failure: %+v", pf)
			}
		}
		if len(final.Result.ParseFailures) > len(selected) {
			t.Error("more parse failures than files selected")
		}
	}
}

// Every event that WAS imported before the stop must be intact and
// attributable -- cancellation must not corrupt committed evidence.
func TestCancelImport_ImportedFilesRemainValidEvidence(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Cancel keeps evidence valid")
	coll, jobID, _ := startBigImport(t, mux, c.ID, 40)

	postCancel(t, mux, c.ID, jobID)
	final := waitJob(t, mux, c.ID, jobID)
	if final.Result == nil {
		t.Fatal("no result")
	}

	var listing EvidenceFilePage
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/evidence/"+coll+"/files?page=1&page_size=250", nil, &listing)
	for _, f := range listing.Items {
		if f.ImportStatus != model.SourceFileImported {
			continue
		}
		// An imported file carries a hash and a real import timestamp:
		// the same invariants a completed import guarantees.
		if f.SHA256 == "" {
			t.Errorf("imported file %s has no SHA-256", f.OriginalFilename)
		}
		if f.ImportedAt == nil || f.ImportedAt.IsZero() {
			t.Errorf("imported file %s has no import timestamp", f.OriginalFilename)
		}
	}
	// Counts must have been recomputed, not left stale.
	var detail CollectionDetail
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/evidence/"+coll, nil, &detail)
	if detail.Coverage.Imported != len(final.Result.Imported) {
		t.Errorf("collection coverage reports %d imported, result reports %d",
			detail.Coverage.Imported, len(final.Result.Imported))
	}
}

// Cancelling twice, and cancelling after completion, must both be
// no-ops rather than errors.
func TestCancelImport_IsIdempotent(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Cancel idempotent")
	_, jobID, _ := startBigImport(t, mux, c.ID, 20)

	for i := 0; i < 5; i++ {
		if code := postCancel(t, mux, c.ID, jobID); code != http.StatusOK {
			t.Fatalf("cancel #%d: status %d, want 200", i+1, code)
		}
	}
	final := waitJob(t, mux, c.ID, jobID)

	// Cancelling a job that has already finished is still not an error:
	// the click may have been in flight when the import completed.
	if code := postCancel(t, mux, c.ID, jobID); code != http.StatusOK {
		t.Errorf("cancel after completion: status %d, want 200", code)
	}
	if !final.Done {
		t.Error("job not done")
	}
}

// A job ID must not be cancellable through a different case.
func TestCancelImport_ScopedToItsCase(t *testing.T) {
	mux := newTestRouter(t)
	c1 := mustCreateCase(t, mux, "Cancel scope A")
	c2 := mustCreateCase(t, mux, "Cancel scope B")
	_, jobID, _ := startBigImport(t, mux, c1.ID, 10)

	if code := postCancel(t, mux, c2.ID, jobID); code != http.StatusNotFound {
		t.Errorf("cross-case cancel: status %d, want 404", code)
	}
	waitJob(t, mux, c1.ID, jobID)
}

// An unknown job ID is a 404, not a panic or a 500.
func TestCancelImport_UnknownJob(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Cancel unknown")
	if code := postCancel(t, mux, c.ID, "does-not-exist"); code != http.StatusNotFound {
		t.Errorf("status %d, want 404", code)
	}
}

// Letting an import run to completion must be entirely unaffected by
// cancellation existing -- no phantom cancels, no changed counts.
func TestCancelImport_UncancelledImportStillCompletes(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Uncancelled import")
	coll, jobID, selected := startBigImport(t, mux, c.ID, 12)

	final := waitJob(t, mux, c.ID, jobID)
	if final.Phase != PhaseComplete {
		t.Fatalf("phase = %q, want complete", final.Phase)
	}
	if final.Cancelled || (final.Result != nil && final.Result.Cancelled) {
		t.Error("an import nobody cancelled reported itself cancelled")
	}
	if final.Result == nil {
		t.Fatal("no result")
	}
	if final.Result.Unprocessed != 0 {
		t.Errorf("unprocessed = %d, want 0 for a complete import", final.Result.Unprocessed)
	}
	var detail CollectionDetail
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/evidence/"+coll, nil, &detail)
	if detail.Coverage.Imported+detail.Coverage.ParseFailed != len(selected) {
		t.Errorf("imported(%d) + parse_failed(%d) != selected(%d)",
			detail.Coverage.Imported, detail.Coverage.ParseFailed, len(selected))
	}
}

// A cancelled import that imported anything must make prior analysis
// stale, exactly as a complete one does.
func TestCancelImport_MakesAnalysisStale(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Cancel staleness")

	// Import something and analyze, so there is analysis to invalidate.
	seed := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		"Windows/Prefetch/SEED.pf": samplePrefetch(),
	})
	seedIDs := selectableIDs(seed)
	doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/evidence/"+seed.Collection.ID+"/import",
		map[string][]string{"source_file_ids": seedIDs}, nil)
	doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/analyze", nil, nil)

	var before struct {
		Case model.Case `json:"case"`
	}
	doJSON(t, mux, "GET", "/api/cases/"+c.ID, nil, &before)
	if before.Case.Status != model.CaseStatusAnalyzed {
		t.Fatalf("setup: case status = %q, want analyzed", before.Case.Status)
	}

	_, jobID, _ := startBigImport(t, mux, c.ID, 30)
	postCancel(t, mux, c.ID, jobID)
	final := waitJob(t, mux, c.ID, jobID)

	var after struct {
		Case model.Case `json:"case"`
	}
	doJSON(t, mux, "GET", "/api/cases/"+c.ID, nil, &after)
	if final.Result != nil && len(final.Result.Imported) > 0 {
		if after.Case.Status != model.CaseStatusIngested {
			t.Errorf("case status = %q after a cancelled import that imported %d file(s); want ingested (stale)",
				after.Case.Status, len(final.Result.Imported))
		}
	}
	// The case must remain in a valid lifecycle state either way.
	if after.Case.CaseStatus != model.CaseWorkflowOpen {
		t.Errorf("case_status = %q, want it unchanged at open", after.Case.CaseStatus)
	}
}

// Cancellation must be recorded in the audit history.
func TestCancelImport_IsAudited(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Cancel audit")
	_, jobID, _ := startBigImport(t, mux, c.ID, 40)
	postCancel(t, mux, c.ID, jobID)
	final := waitJob(t, mux, c.ID, jobID)

	if final.Result == nil || !final.Result.Cancelled {
		t.Skip("import completed before the cancel landed; nothing to audit")
	}
	var entries []model.AuditEvent
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/audit", nil, &entries)
	var found bool
	for _, e := range entries {
		if e.Action == model.AuditEvidenceImportCancelled {
			found = true
			if !strings.Contains(e.Summary, "cancelled") {
				t.Errorf("audit summary does not say what happened: %q", e.Summary)
			}
			if !strings.Contains(e.Summary, "not imported and still available") {
				t.Errorf("audit summary does not report unprocessed files: %q", e.Summary)
			}
		}
	}
	if !found {
		t.Error("no evidence_import_cancelled audit entry was recorded")
	}
}

// Cancelling DURING the persist phase is the case that actually matters:
// some files are already committed evidence, the rest were parsed into
// memory but never written. This drives the import to that exact point
// deterministically -- by waiting for the phase rather than for a
// duration -- instead of hoping a sleep lands in the right window.
func TestCancelImport_MidPersistLeavesNoPartialFiles(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Cancel mid-persist")
	coll, jobID, selected := startBigImport(t, mux, c.ID, 60)

	// Wait for persisting, then cancel.
	deadline := time.Now().Add(30 * time.Second)
	var reached bool
	for time.Now().Before(deadline) {
		var p ImportProgress
		doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/import-jobs/"+jobID, nil, &p)
		if p.Phase == PhasePersisting {
			reached = true
			postCancel(t, mux, c.ID, jobID)
			break
		}
		if p.Done {
			break
		}
	}
	final := waitJob(t, mux, c.ID, jobID)
	if !reached {
		t.Skip("import completed before the persist phase could be observed")
	}
	if final.Result == nil {
		t.Fatal("no result")
	}

	var listing EvidenceFilePage
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/evidence/"+coll+"/files?page=1&page_size=250", nil, &listing)

	imported := 0
	for _, f := range listing.Items {
		switch f.ImportStatus {
		case model.SourceFileImported:
			imported++
			// A committed file must be fully committed: hash, timestamp
			// and a real event count.
			if f.SHA256 == "" || f.ImportedAt == nil || f.ImportedAt.IsZero() {
				t.Errorf("half-written file %s: sha=%q importedAt=%v", f.OriginalFilename, f.SHA256, f.ImportedAt)
			}
		case model.SourceFileDiscovered, model.SourceFileDuplicate, model.SourceFileFailed:
			// All legitimate resting states.
		default:
			t.Errorf("file %s left in unexpected state %q", f.OriginalFilename, f.ImportStatus)
		}
	}
	if imported != len(final.Result.Imported) {
		t.Errorf("catalog shows %d imported, result claims %d", imported, len(final.Result.Imported))
	}
	// The accounting must add up: what was imported plus what was left
	// equals what was selected.
	if final.Result.Cancelled {
		accounted := len(final.Result.Imported) + final.Result.Unprocessed +
			len(final.Result.ParseFailures) + len(final.Result.Skipped)
		if accounted > len(selected) {
			t.Errorf("accounting exceeds the selection: imported=%d unprocessed=%d failures=%d skipped=%d > selected=%d",
				len(final.Result.Imported), final.Result.Unprocessed,
				len(final.Result.ParseFailures), len(final.Result.Skipped), len(selected))
		}
	}
	// Re-importing what was left must work: those files were untouched.
	remaining := getEvidenceIDs(t, mux, c.ID, coll, nil)
	if len(remaining) > 0 {
		var again ImportResult
		doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/evidence/"+coll+"/import",
			map[string][]string{"source_file_ids": remaining}, &again)
		if len(again.Imported) == 0 {
			t.Error("files left unprocessed by cancellation could not be imported afterwards")
		}
	}
}

// A DETERMINISTIC cancellation test, with no dependence on winning a
// race against the import goroutine.
//
// The tests above all tolerate "the import finished before the cancel
// landed", because that race is real in a running system. But that
// tolerance means they would also pass if cancellation did nothing at
// all. This one cannot: the job is cancelled BEFORE importEvidence is
// called, so the very first safe point must observe it, on every run,
// on any machine.
func TestCancelImport_SafePointIsObservedDeterministically(t *testing.T) {
	svc := newTestService(t)
	mux := routerFor(svc)
	c := mustCreateCase(t, mux, "Deterministic cancel")

	files := map[string][]byte{}
	for i := 0; i < 25; i++ {
		files[fmt.Sprintf("Windows/Prefetch/DET%03d.pf", i)] = distinctPrefetch(i)
	}
	disc := discoverBinaryDir(t, mux, c.ID, files)
	coll := disc.Collection.ID
	selected := getEvidenceIDs(t, mux, c.ID, coll, nil)
	if len(selected) < 10 {
		t.Fatalf("only %d files selectable", len(selected))
	}

	// An already-cancelled job. importEvidence must stop at its first
	// safe point without importing anything.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	job := &importJob{ctx: ctx, cancel: cancel, progress: ImportProgress{
		JobID: "deterministic", CaseID: c.ID, CollectionID: coll,
		StartedAt: time.Now().UTC(),
	}}

	res, err := svc.importEvidence(c.ID, coll, selected, &progressSink{job: job})
	if err != nil {
		t.Fatalf("importEvidence returned an error rather than a cancelled result: %v", err)
	}
	if !res.Cancelled {
		t.Fatal("cancellation was requested before any work began, but the result is not marked cancelled")
	}
	if len(res.Imported) != 0 {
		t.Errorf("imported %d file(s) despite being cancelled before the first safe point", len(res.Imported))
	}
	if res.Unprocessed != len(selected) {
		t.Errorf("unprocessed = %d, want %d (the whole selection)", res.Unprocessed, len(selected))
	}
	if len(res.ParseFailures) != 0 {
		t.Errorf("unprocessed files were recorded as %d parse failure(s)", len(res.ParseFailures))
	}

	// Nothing was touched: every file is still importable.
	remaining := getEvidenceIDs(t, mux, c.ID, coll, nil)
	if len(remaining) != len(selected) {
		t.Errorf("%d file(s) still selectable after a cancelled import, want %d", len(remaining), len(selected))
	}
	var detail CollectionDetail
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/evidence/"+coll, nil, &detail)
	if detail.Coverage.Imported != 0 {
		t.Errorf("coverage reports %d imported after a fully-cancelled import", detail.Coverage.Imported)
	}
}

// The cancelled summary must ADD UP: everything selected either became
// evidence or is still importable. An analyst reading "0 imported" after
// cancelling a 4,001-file selection needs to know all 4,001 are still
// there, and a number that did not reconcile would be worse than none.
func TestCancelImport_AccountingReconciles(t *testing.T) {
	svc := newTestService(t)
	mux := routerFor(svc)
	c := mustCreateCase(t, mux, "Cancel accounting")

	files := map[string][]byte{}
	for i := 0; i < 30; i++ {
		files[fmt.Sprintf("Windows/Prefetch/ACC%03d.pf", i)] = distinctPrefetch(i)
	}
	disc := discoverBinaryDir(t, mux, c.ID, files)
	coll := disc.Collection.ID
	selected := getEvidenceIDs(t, mux, c.ID, coll, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	job := &importJob{ctx: ctx, cancel: cancel, progress: ImportProgress{
		JobID: "acct", CaseID: c.ID, CollectionID: coll, StartedAt: time.Now().UTC(),
	}}
	res, err := svc.importEvidence(c.ID, coll, selected, &progressSink{job: job})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(res.Imported) + res.Unprocessed; got != len(selected) {
		t.Errorf("imported(%d) + unprocessed(%d) = %d, want the selection size %d",
			len(res.Imported), res.Unprocessed, got, len(selected))
	}
	// And what is reported unprocessed must genuinely still be importable.
	still := getEvidenceIDs(t, mux, c.ID, coll, nil)
	if len(still) != res.Unprocessed {
		t.Errorf("result reports %d unprocessed but %d are actually still selectable", res.Unprocessed, len(still))
	}
}
