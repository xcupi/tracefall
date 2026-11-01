package api

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/store"
)

// crashLeaving leaves the big source of env importing with committed segments,
// exactly as a killed process would.
func crashLeaving(t *testing.T, env segEnv) {
	t.Helper()
	env.svc.seg.noAbort = true
	env.svc.seg.hook = func(idx int) error {
		if idx == 2 {
			return errors.New("simulated process death")
		}
		return nil
	}
	env.importAll(t)
	env.svc.seg.hook, env.svc.seg.noAbort = nil, false
	if sf, _ := env.svc.store.GetSourceFile(env.ids["ERRORLOG"]); sf.ImportStatus != model.SourceFileImporting {
		t.Fatalf("setup: status = %q, want importing", sf.ImportStatus)
	}
}

// Startup must not wait for the cleanup: it returns at once, the orphan stays
// hidden and its case stays blocked (with a message that says why) until the
// background cleanup finishes; other cases keep working meanwhile.
func TestBackgroundRecoveryReturnsAtOnceAndBlocksOnlyTheOrphansCase(t *testing.T) {
	env := newSegEnv(t, 1, 400, [2]int{0, 10}, [2]int{1000, 2500})
	crashLeaving(t, env)
	other := newSegEnvOn(t, env.svc, "other case", [2]int{0, 20}, [2]int{2000, 2300})

	entered, release := make(chan string, 4), make(chan struct{})
	env.svc.seg.recoverHook = func(id string) { entered <- id; <-release }
	var reported []store.RecoveredImport
	var reportErr error
	n, done, err := env.svc.StartSegmentedRecovery(context.Background(), func(r []store.RecoveredImport, e error) { reported, reportErr = r, e })
	if err != nil || n != 1 || done == nil {
		t.Fatalf("StartSegmentedRecovery = %d, %v, %v; want 1 orphan and a done channel", n, done != nil, err)
	}
	select {
	case id := <-entered:
		if id != env.ids["ERRORLOG"] {
			t.Fatalf("cleaning %s, want the orphan", id)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("cleanup never started")
	}
	// Mid-cleanup: still hidden, the case says why it is blocked, others work.
	if c, _ := env.svc.store.CountEvents(env.caseID); c != 10 {
		t.Errorf("visible events mid-recovery = %d, want only the 10 of the ordinary source", c)
	}
	_, err = env.svc.ImportEvidence(env.caseID, env.coll, []string{env.ids["ERRORLOG.1"]})
	if !errors.Is(err, ErrImportInProgress) || !strings.Contains(err.Error(), "cleaned up") {
		t.Errorf("import into the orphan's case mid-recovery = %v, want ErrImportInProgress mentioning the cleanup", err)
	}
	if _, err := env.svc.DeleteSourceFiles(env.caseID, []string{env.ids["ERRORLOG.1"]}); !errors.Is(err, ErrImportInProgress) {
		t.Errorf("delete mid-recovery = %v, want ErrImportInProgress", err)
	}
	res := other.importAll(t)
	if len(res.ParseFailures) != 0 || res.EventCount != 320 {
		t.Errorf("another case mid-recovery: count=%d failures=%+v, want 320 and none", res.EventCount, res.ParseFailures)
	}
	if sf, _ := other.svc.store.GetSourceFile(other.ids["ERRORLOG"]); sf.ImportStatus != model.SourceFileImported {
		t.Errorf("the other case's segmented import was disturbed: %q", sf.ImportStatus)
	}
	close(release)
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("cleanup never finished")
	}
	if reportErr != nil || len(reported) != 1 || reported[0].SourceFileID != env.ids["ERRORLOG"] || reported[0].Segments != 3 {
		t.Errorf("report = %+v, %v; want the one orphan with 3 segments", reported, reportErr)
	}
	if n := env.rows(t, `SELECT COUNT(*) FROM events WHERE source_file_id = ?`, env.ids["ERRORLOG"]); n != 0 {
		t.Errorf("%d orphan events left", n)
	}
	out, ok, _ := env.svc.store.SegmentedImportOutcome(env.ids["ERRORLOG"])
	if !ok || out.Outcome != "aborted" {
		t.Errorf("outcome = %+v, want aborted", out)
	}
	res, err = env.svc.ImportEvidence(env.caseID, env.coll, []string{env.ids["ERRORLOG"]})
	if err != nil || res.EventCount != 1500 || len(res.ParseFailures) != 0 {
		t.Fatalf("re-import after cleanup: err=%v count=%d failures=%+v", err, res.EventCount, res.ParseFailures)
	}
}

// A segmented import that starts AFTER the startup snapshot is never mistaken
// for an orphan, even while the cleanup is still running.
func TestBackgroundRecoveryNeverTouchesImportsStartedAfterTheSnapshot(t *testing.T) {
	env := newSegEnv(t, 1, 400, [2]int{0, 10}, [2]int{1000, 2500})
	crashLeaving(t, env)
	other := newSegEnvOn(t, env.svc, "late case", [2]int{0, 20}, [2]int{2000, 4000})
	entered, release := make(chan string, 4), make(chan struct{})
	env.svc.seg.recoverHook = func(id string) { entered <- id; <-release }
	_, done, err := env.svc.StartSegmentedRecovery(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	hooked := false
	other.svc.seg.hook = func(idx int) error {
		if idx == 1 && !hooked {
			hooked = true
			close(release) // let the cleanup run while this import is importing
			select {
			case <-done:
			case <-time.After(60 * time.Second):
				t.Error("cleanup did not finish")
			}
		}
		return nil
	}
	res := other.importAll(t)
	other.svc.seg.hook = nil
	if !hooked || len(res.ParseFailures) != 0 || res.EventCount != 2020 {
		t.Fatalf("late import: hooked=%v count=%d failures=%+v", hooked, res.EventCount, res.ParseFailures)
	}
	if sf, _ := other.svc.store.GetSourceFile(other.ids["ERRORLOG"]); sf.ImportStatus != model.SourceFileImported {
		t.Errorf("late import status = %q, want imported", sf.ImportStatus)
	}
}

// Nothing to recover: no goroutine work, the guards stay silent.
func TestBackgroundRecoveryWithoutOrphansIsANoOp(t *testing.T) {
	env := newSegEnv(t, 1, 400, [2]int{0, 10}, [2]int{1000, 1100})
	called := false
	n, done, err := env.svc.StartSegmentedRecovery(context.Background(), func([]store.RecoveredImport, error) { called = true })
	if err != nil || n != 0 {
		t.Fatalf("= %d, %v; want 0 orphans", n, err)
	}
	if done != nil {
		<-done
	}
	if called {
		t.Error("report called with nothing recovered")
	}
	if err := env.svc.refuseIfSegmentedPending(env.caseID); err != nil {
		t.Errorf("guard refuses with nothing pending: %v", err)
	}
}
