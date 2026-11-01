package api

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"tracefall/internal/model"
)

// ---- helpers -------------------------------------------------------------

type segEnv struct {
	svc          *Service
	caseID, coll string
	ids          map[string]string // file name -> source id
}

func writeLog(t *testing.T, path string, from, to int, extra ...string) {
	t.Helper()
	var b strings.Builder
	for i := from; i < to; i++ {
		fmt.Fprintf(&b, "2025-01-02 03:%02d:%02d.00 Server Microsoft SQL Server record %d %s\n", (i/60)%60, i%60, i, strings.Repeat("p", 40))
	}
	for _, l := range extra {
		b.WriteString(l + "\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0600); err != nil {
		t.Fatal(err)
	}
}

// newSegEnv builds a case with a small ordinary log "A.log"-like file and a
// large log; names are ERRORLOG files so the MSSQL stream parser handles them.
func newSegEnv(t *testing.T, minBytes int64, segEvents int, small, big [2]int, bigExtra ...string) segEnv {
	t.Helper()
	svc := newTestService(t)
	svc.SetSegmentedImport(minBytes, segEvents)
	c, err := svc.CreateCase("segmented "+t.Name(), "")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	writeLog(t, filepath.Join(root, "ERRORLOG.1"), small[0], small[1])
	writeLog(t, filepath.Join(root, "ERRORLOG"), big[0], big[1], bigExtra...)
	disc, err := svc.DiscoverEvidenceFromPath(c.ID, root)
	if err != nil {
		t.Fatal(err)
	}
	files, err := svc.store.ListSourceFilesByCollection(disc.Collection.ID)
	if err != nil || len(files) != 2 {
		t.Fatalf("discover: %v %d", err, len(files))
	}
	env := segEnv{svc: svc, caseID: c.ID, coll: disc.Collection.ID, ids: map[string]string{}}
	for _, f := range files {
		env.ids[filepath.Base(f.Path)] = f.ID
	}
	return env
}

func (e segEnv) importAll(t *testing.T) ImportResult {
	t.Helper()
	res, err := e.svc.ImportEvidence(e.caseID, e.coll, []string{e.ids["ERRORLOG.1"], e.ids["ERRORLOG"]})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// snapshot is everything a reader can see, with run-specific ids removed.
func (e segEnv) snapshot(t *testing.T) []string {
	t.Helper()
	evs, err := e.svc.store.ListEvents(e.caseID)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, ev := range evs {
		out = append(out, fmt.Sprintf("event|%s|%s|%s|%s|%s", ev.Timestamp.UTC().Format("15:04:05"), ev.Host, ev.EventType, ev.DedupHash, ev.SourceReference))
	}
	for name, id := range e.ids {
		sf, err := e.svc.store.GetSourceFile(id)
		if err != nil {
			t.Fatal(err)
		}
		obs, err := e.svc.store.ListEventObservationsBySourceFile(id)
		if err != nil {
			t.Fatal(err)
		}
		cov := ""
		if sf.ParseCoverage != nil {
			cov = fmt.Sprintf("%d/%d/%d", sf.ParseCoverage.RecordsRead, sf.ParseCoverage.Mapped, sf.ParseCoverage.Unmapped)
		}
		out = append(out, fmt.Sprintf("source|%s|%s|%d|%d|%s", name, sf.ImportStatus, sf.EventCount, len(obs), cov))
	}
	sort.Strings(out)
	return out
}

func (e segEnv) rows(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := e.svc.store.DB().QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// ---- tests ---------------------------------------------------------------

// A segmented import must produce exactly what the single-transaction import
// produces: same events, dedup identities, observations, counts, coverage,
// including duplicates across files and repeated lines inside the big file.
func TestSegmentedImportMatchesSingleTransactionImport(t *testing.T) {
	dup := "2025-01-02 03:00:10.00 Server Microsoft SQL Server record 10 " + strings.Repeat("p", 40)
	small, big := [2]int{0, 400}, [2]int{300, 2600}
	whole := newSegEnv(t, 0, 0, small, big, dup, dup) // minBytes 0: segmented disabled
	seg := newSegEnv(t, 1, 500, small, big, dup, dup) // every streaming source segmented
	rw, rs := whole.importAll(t), seg.importAll(t)
	if len(rw.ParseFailures) != 0 || len(rs.ParseFailures) != 0 {
		t.Fatalf("failures: whole=%+v seg=%+v", rw.ParseFailures, rs.ParseFailures)
	}
	if rw.EventCount != rs.EventCount || rw.NewEventCount != rs.NewEventCount || rw.DuplicateEventCount != rs.DuplicateEventCount {
		t.Errorf("counts differ: whole=%d/%d/%d seg=%d/%d/%d", rw.EventCount, rw.NewEventCount, rw.DuplicateEventCount, rs.EventCount, rs.NewEventCount, rs.DuplicateEventCount)
	}
	a, b := whole.snapshot(t), seg.snapshot(t)
	if len(a) != len(b) {
		t.Fatalf("visible rows: whole=%d seg=%d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("row %d differs:\n whole %s\n seg   %s", i, a[i], b[i])
		}
	}
	// It really was segmented: both sources went through segments (2 + 6).
	out, ok, err := seg.svc.store.SegmentedImportOutcome(seg.ids["ERRORLOG"])
	if err != nil || !ok || out.Outcome != "imported" || out.Segments < 4 {
		t.Fatalf("big source outcome = %+v ok=%v err=%v, want imported in >=4 segments", out, ok, err)
	}
	if n := seg.rows(t, `SELECT COUNT(*) FROM source_import_segments`); n != 0 {
		t.Errorf("%d checkpoint rows left after finalization", n)
	}
	if _, ok, _ := whole.svc.store.SegmentedImportOutcome(whole.ids["ERRORLOG"]); ok {
		t.Error("the single-transaction run used segments")
	}
}

// While a segmented import runs, nothing it has committed is visible; the
// case refuses conflicting operations; both become possible afterwards.
func TestSegmentedImportKeepsPendingRowsHiddenAndRefusesConflicts(t *testing.T) {
	env := newSegEnv(t, 1, 400, [2]int{0, 50}, [2]int{1000, 2500})
	svc := env.svc
	var checked bool
	svc.seg.hook = func(idx int) error {
		if idx != 1 {
			return nil
		}
		checked = true
		pending := env.rows(t, `SELECT COUNT(*) FROM events WHERE source_file_id = ?`, env.ids["ERRORLOG"])
		if pending < 800 {
			t.Errorf("only %d pending rows physically committed after 2 segments", pending)
		}
		if n, _ := svc.store.CountEvents(env.caseID); n != 50 {
			t.Errorf("visible events during import = %d, want only the 50 of the ordinary source", n)
		}
		if _, err := svc.DeleteSourceFiles(env.caseID, []string{env.ids["ERRORLOG.1"]}); !errors.Is(err, ErrImportInProgress) {
			t.Errorf("DeleteSourceFiles during import = %v, want ErrImportInProgress", err)
		}
		if _, err := svc.ImportEvidence(env.caseID, env.coll, []string{env.ids["ERRORLOG.1"]}); !errors.Is(err, ErrImportInProgress) {
			t.Errorf("ImportEvidence during import = %v, want ErrImportInProgress", err)
		}
		if n := env.rows(t, `SELECT COUNT(*) FROM source_files WHERE id = ? AND deleted_at = ''`, env.ids["ERRORLOG.1"]); n != 1 {
			t.Error("refused delete still altered the source")
		}
		return nil
	}
	res := env.importAll(t)
	if !checked {
		t.Fatal("hook never ran: the source was not imported in segments")
	}
	svc.seg.hook = nil
	if res.EventCount != 1550 {
		t.Fatalf("event count = %d, want 1550", res.EventCount)
	}
	if n, _ := svc.store.CountEvents(env.caseID); n != 1550 {
		t.Errorf("visible after finalization = %d, want 1550", n)
	}
	if _, err := svc.DeleteSourceFiles(env.caseID, []string{env.ids["ERRORLOG.1"]}); err != nil {
		t.Errorf("delete after the import finished: %v", err)
	}
}

// A failure after some segments are committed leaves nothing behind, is
// disclosed, and the source can be imported again to exactly the right count.
func TestSegmentedImportFailureRollsBackAndRetries(t *testing.T) {
	env := newSegEnv(t, 1, 400, [2]int{0, 10}, [2]int{1000, 2500})
	boom := errors.New("simulated failure after the third segment")
	env.svc.seg.hook = func(idx int) error {
		if idx == 2 {
			return boom
		}
		return nil
	}
	res := env.importAll(t)
	if len(res.ParseFailures) != 1 || !strings.Contains(res.ParseFailures[0].Message+res.Errors[0], "simulated failure") {
		t.Fatalf("failure not disclosed: %+v errors=%v", res.ParseFailures, res.Errors)
	}
	for _, q := range []string{`SELECT COUNT(*) FROM events WHERE source_file_id = ?`, `SELECT COUNT(*) FROM raw_evidence WHERE source_file_id = ?`, `SELECT COUNT(*) FROM event_observations WHERE source_file_id = ?`, `SELECT COUNT(*) FROM source_import_segments WHERE source_file_id = ?`} {
		if n := env.rows(t, q, env.ids["ERRORLOG"]); n != 0 {
			t.Errorf("%s = %d after rollback", q, n)
		}
	}
	sf, _ := env.svc.store.GetSourceFile(env.ids["ERRORLOG"])
	if sf.ImportStatus != model.SourceFileFailed {
		t.Errorf("status = %q, want failed", sf.ImportStatus)
	}
	out, ok, _ := env.svc.store.SegmentedImportOutcome(env.ids["ERRORLOG"])
	if !ok || out.Outcome != "aborted" || !strings.Contains(out.Reason, "simulated failure") || out.Segments != 3 {
		t.Errorf("outcome = %+v ok=%v, want aborted after 3 segments with the reason", out, ok)
	}
	if n, _ := env.svc.store.CountEvents(env.caseID); n != 10 {
		t.Errorf("visible events = %d, want only the ordinary source's 10", n)
	}
	env.svc.seg.hook = nil
	res, err := env.svc.ImportEvidence(env.caseID, env.coll, []string{env.ids["ERRORLOG"]})
	if err != nil || len(res.ParseFailures) != 0 || res.EventCount != 1500 {
		t.Fatalf("retry: err=%v failures=%+v count=%d, want 1500", err, res.ParseFailures, res.EventCount)
	}
	if n, _ := env.svc.store.CountEvents(env.caseID); n != 1510 {
		t.Errorf("visible after retry = %d, want 1510", n)
	}
}

// A process that dies mid-import leaves an importing source; startup recovery
// removes its rows, discloses why, and lets it be imported again.
func TestSegmentedImportCrashIsRecoveredAtStartup(t *testing.T) {
	env := newSegEnv(t, 1, 400, [2]int{0, 10}, [2]int{1000, 2500})
	crash := errors.New("simulated process death")
	env.svc.seg.noAbort = true // a dead process cannot abort
	env.svc.seg.hook = func(idx int) error {
		if idx == 2 {
			return crash
		}
		return nil
	}
	env.importAll(t)
	env.svc.seg.hook, env.svc.seg.noAbort = nil, false
	sf, _ := env.svc.store.GetSourceFile(env.ids["ERRORLOG"])
	if sf.ImportStatus != model.SourceFileImporting {
		t.Fatalf("status = %q, want importing (crash left it pending)", sf.ImportStatus)
	}
	if n, _ := env.svc.store.CountEvents(env.caseID); n != 10 {
		t.Fatalf("pending rows visible after the crash: %d", n)
	}
	if _, err := env.svc.ImportEvidence(env.caseID, env.coll, []string{env.ids["ERRORLOG.1"]}); !errors.Is(err, ErrImportInProgress) {
		t.Fatalf("a pending crashed import must block the case until recovered, got %v", err)
	}
	rec, err := env.svc.RecoverSegmentedImports(context.Background())
	if err != nil || len(rec) != 1 || rec[0].SourceFileID != env.ids["ERRORLOG"] || rec[0].Segments != 3 {
		t.Fatalf("recovery = %+v err=%v, want the one orphan with 3 segments", rec, err)
	}
	if n := env.rows(t, `SELECT COUNT(*) FROM events WHERE source_file_id = ?`, env.ids["ERRORLOG"]); n != 0 {
		t.Errorf("%d orphan events left", n)
	}
	out, ok, _ := env.svc.store.SegmentedImportOutcome(env.ids["ERRORLOG"])
	if !ok || out.Outcome != "aborted" {
		t.Errorf("outcome = %+v, want aborted", out)
	}
	res, err := env.svc.ImportEvidence(env.caseID, env.coll, []string{env.ids["ERRORLOG"]})
	if err != nil || res.EventCount != 1500 || len(res.ParseFailures) != 0 {
		t.Fatalf("re-import after recovery: err=%v count=%d failures=%+v", err, res.EventCount, res.ParseFailures)
	}
}

// Below the size threshold, behaviour is the unchanged single-transaction path.
func TestSmallSourcesKeepTheSingleTransactionPath(t *testing.T) {
	env := newSegEnv(t, 1<<30, 100, [2]int{0, 50}, [2]int{1000, 1300})
	env.svc.seg.hook = func(int) error { t.Error("segment hook ran for a source below the threshold"); return nil }
	res := env.importAll(t)
	if res.EventCount != 350 || len(res.ParseFailures) != 0 {
		t.Fatalf("count=%d failures=%+v", res.EventCount, res.ParseFailures)
	}
	if n := env.rows(t, `SELECT COUNT(*) FROM source_import_outcomes`); n != 0 {
		t.Errorf("%d segmented outcomes recorded for small sources", n)
	}
}
