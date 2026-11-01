package api

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"tracefall/internal/ingest"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
	"tracefall/internal/report"
	"tracefall/internal/store"
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
		out = append(out, fmt.Sprintf("event|%s|%s|%s|%s|%s|%s", ev.Timestamp.UTC().Format("15:04:05"), ev.Host, ev.Extra["host_inherited_from"], ev.EventType, ev.DedupHash, ev.SourceReference))
	}
	// Observation -> event -> raw text, per source: the evidence chain itself.
	rows, err := e.svc.store.DB().Query(`SELECT sf.original_filename, ev.dedup_hash, o.source_reference, COALESCE(r.raw, '<no raw>')
 FROM event_observations o JOIN events ev ON ev.id = o.event_id JOIN source_files sf ON sf.id = o.source_file_id
 LEFT JOIN raw_evidence r ON r.id = o.raw_evidence_id`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var a, b, c, d string
		if err := rows.Scan(&a, &b, &c, &d); err != nil {
			t.Fatal(err)
		}
		out = append(out, fmt.Sprintf("chain|%s|%s|%s|%x", a, b, c, d))
	}
	rows.Close()
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
	// dup repeats a record of the SMALL file; dupIn repeats record 1000 of the big
	// file itself, whose first occurrence sits in an earlier segment.
	line := func(i int) string {
		return fmt.Sprintf("2025-01-02 03:%02d:%02d.00 Server Microsoft SQL Server record %d %s", (i/60)%60, i%60, i, strings.Repeat("p", 40))
	}
	dup, dupIn := line(10), line(1000)
	small, big := [2]int{0, 400}, [2]int{300, 2600}
	whole := newSegEnv(t, 0, 0, small, big, dup, dup, dupIn, dupIn) // minBytes 0: segmented disabled
	seg := newSegEnv(t, 1, 500, small, big, dup, dup, dupIn, dupIn) // every streaming source segmented
	// A host already persisted in the collection is inherited identically.
	for _, e := range []segEnv{whole, seg} {
		e.seedHost(t, "SRV-A")
	}
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

// seedHost persists one event with a named host, from a separate imported
// source, so the collection already has exactly one host.
func (e segEnv) seedHost(t *testing.T, host string) {
	t.Helper()
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) // fixed: both runs must seed the same instant
	sf := model.SourceFile{ID: "seed-source", CaseID: e.caseID, CollectionID: e.coll, OriginalFilename: "seed.log", Path: "seed.log",
		ArtifactType: model.ArtifactMSSQLLog, Parser: "mssql@1", Supported: true, SHA256: "seed-hash", ImportStatus: model.SourceFileImported, DiscoveredAt: now}
	if err := e.svc.store.SaveSourceFiles([]model.SourceFile{sf}); err != nil {
		t.Fatal(err)
	}
	ev := model.Event{ID: "seed-event", CaseID: e.caseID, CollectionID: e.coll, Timestamp: now, Host: host, EventType: "seed",
		ArtifactType: model.ArtifactMSSQLLog, SourceFileID: sf.ID, DedupHash: "seed-dedup"}
	if err := e.svc.store.SaveEvents([]model.Event{ev}); err != nil {
		t.Fatal(err)
	}
}

// F3: only verified hostless artifact types are admitted in segments, so the
// host a source gets never depends on the path taken.
func TestSegmentedPathIsLimitedToVerifiedArtifacts(t *testing.T) {
	svc := newTestService(t)
	svc.SetSegmentedImport(1, 100)
	for _, p := range ingest.Registry() {
		_, streaming := p.(parsers.StreamingParser)
		want := streaming && p.ArtifactType() == model.ArtifactMSSQLLog
		if got := svc.wantsSegmented(1<<40, p); got != want {
			t.Errorf("wantsSegmented(%s/%s) = %v, want %v", p.Name(), p.ArtifactType(), got, want)
		}
	}
}

// A source that names its own host stops instead of inheriting a wrong one.
func TestSegmentedImportStopsWhenTheSourceNamesAHost(t *testing.T) {
	env := newSegEnv(t, 1, 400, [2]int{0, 10}, [2]int{1000, 1500})
	env.svc.seg.hook = nil
	// Force a named host by replacing the parser output path: persisted events
	// cannot do that, so inject through the sink seam.
	env.svc.seg.mutate = func(e *model.Event) { e.Host = "NAMED-BY-SOURCE" }
	res := env.importAll(t)
	env.svc.seg.mutate = nil
	if len(res.ParseFailures) == 0 || !strings.Contains(strings.Join(res.Errors, " "), "names its own host") {
		t.Fatalf("host conflict not disclosed: failures=%+v errors=%v", res.ParseFailures, res.Errors)
	}
	if n := env.rows(t, `SELECT COUNT(*) FROM events WHERE source_file_id = ?`, env.ids["ERRORLOG"]); n != 0 {
		t.Errorf("%d rows left", n)
	}
}

// Analyst cancel: nothing remains, the source goes back to discovered (as in
// the single-transaction path) and imports normally afterwards.
func TestSegmentedImportCancelReturnsTheSourceToDiscovered(t *testing.T) {
	env := newSegEnv(t, 1, 400, [2]int{0, 10}, [2]int{1000, 3500})
	var jobID string
	cancelled := make(chan struct{})
	env.svc.seg.hook = func(idx int) error {
		if idx == 1 {
			if _, err := env.svc.CancelImport(env.caseID, jobID); err != nil {
				t.Errorf("CancelImport: %v", err)
			}
			close(cancelled)
			time.Sleep(500 * time.Millisecond) // let the 100 ms cancel watcher see it
		}
		return nil
	}
	var err error
	jobID, err = env.svc.StartImport(env.caseID, env.coll, []string{env.ids["ERRORLOG.1"], env.ids["ERRORLOG"]})
	if err != nil {
		t.Fatal(err)
	}
	var prog ImportProgress
	for i := 0; i < 600; i++ {
		prog, _ = env.svc.ImportJob(env.caseID, jobID)
		if prog.Done {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !prog.Done || prog.Result == nil || !prog.Result.Cancelled {
		t.Fatalf("job = %+v, want done and cancelled", prog)
	}
	env.svc.seg.hook = nil
	for _, q := range []string{`SELECT COUNT(*) FROM events WHERE source_file_id = ?`, `SELECT COUNT(*) FROM source_import_segments WHERE source_file_id = ?`} {
		if n := env.rows(t, q, env.ids["ERRORLOG"]); n != 0 {
			t.Errorf("%s = %d after cancel", q, n)
		}
	}
	sf, _ := env.svc.store.GetSourceFile(env.ids["ERRORLOG"])
	if sf.ImportStatus != model.SourceFileDiscovered {
		t.Errorf("status = %q, want discovered", sf.ImportStatus)
	}
	res, err := env.svc.ImportEvidence(env.caseID, env.coll, []string{env.ids["ERRORLOG"]})
	if err != nil || res.EventCount != 2500 {
		t.Fatalf("import after cancel: err=%v count=%d", err, res.EventCount)
	}
}

// If the pending rows cannot be removed the analyst is told, the rows stay
// hidden, the source stays importing, and the remaining queue is not started.
func TestSegmentedImportAbortFailureIsDisclosedAndStaysHidden(t *testing.T) {
	env := newSegEnv(t, 1, 400, [2]int{0, 10}, [2]int{1000, 2500})
	env.svc.seg.hook = func(idx int) error {
		if idx == 1 {
			return errors.New("simulated failure")
		}
		return nil
	}
	env.svc.seg.abortErr = errors.New("simulated disk error")
	res := env.importAll(t)
	env.svc.seg.hook, env.svc.seg.abortErr = nil, nil
	if len(res.ParseFailures) != 1 || !strings.Contains(strings.Join(res.Errors, " "), "removing its pending segments failed") {
		t.Fatalf("abort failure not disclosed: failures=%+v errors=%v", res.ParseFailures, res.Errors)
	}
	sf, _ := env.svc.store.GetSourceFile(env.ids["ERRORLOG"])
	if sf.ImportStatus != model.SourceFileImporting {
		t.Fatalf("status = %q, want importing (hidden)", sf.ImportStatus)
	}
	if n, _ := env.svc.store.CountEvents(env.caseID); n != 10 {
		t.Errorf("pending rows visible: %d", n)
	}
	if rec, err := env.svc.RecoverSegmentedImports(context.Background()); err != nil || len(rec) != 1 {
		t.Errorf("recovery = %+v err=%v", rec, err)
	}
}

// The guards answer 409, never 500, on every route a UI can use.
func TestPendingSegmentedImportAnswers409OnEveryRoute(t *testing.T) {
	env := newSegEnv(t, 1, 400, [2]int{0, 10}, [2]int{1000, 2500})
	router := routerFor(env.svc)
	call := func(method, path, body string) int {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec.Code
	}
	checked := false
	env.svc.seg.hook = func(idx int) error {
		if idx != 1 {
			return nil
		}
		checked = true
		ids := `{"source_file_ids":["` + env.ids["ERRORLOG.1"] + `"]}`
		for name, got := range map[string]int{
			"sync import":  call("POST", "/api/cases/"+env.caseID+"/evidence/"+env.coll+"/import", ids),
			"start import": call("POST", "/api/cases/"+env.caseID+"/evidence/"+env.coll+"/import/start", ids),
			"delete files": call("DELETE", "/api/cases/"+env.caseID+"/evidence", ids),
		} {
			if got != 409 {
				t.Errorf("%s answered %d, want 409", name, got)
			}
		}
		if _, err := env.svc.DeleteCollection(env.caseID, env.coll); !errors.Is(err, ErrImportInProgress) {
			t.Errorf("DeleteCollection = %v, want ErrImportInProgress", err)
		}
		if err := env.svc.DeleteCase(env.caseID); !errors.Is(err, ErrImportInProgress) {
			t.Errorf("DeleteCase = %v, want ErrImportInProgress", err)
		}
		return nil
	}
	env.importAll(t)
	if !checked {
		t.Fatal("hook never ran")
	}
}

// Dedup inside one importing source: an event whose hash was committed in an
// EARLIER segment of the same source is a known event, not a second row. (The
// MSSQL parser keys identity on the line, so repeated text cannot produce this
// through a file; the store-level contract is tested directly.)
func TestDeduplicateForImportSeesTheSourcesOwnEarlierSegments(t *testing.T) {
	env := newSegEnv(t, 1, 100, [2]int{0, 5}, [2]int{1000, 1010})
	src := env.ids["ERRORLOG"]
	if err := env.svc.store.BeginSegmentedImport(src); err != nil {
		t.Fatal(err)
	}
	mk := func(id string) model.Event {
		return model.Event{ID: id, CaseID: env.caseID, CollectionID: env.coll, Timestamp: time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC),
			Host: "H", EventType: "same", ArtifactType: model.ArtifactMSSQLLog, SourceFileID: src, SourceReference: "same-ref"}
	}
	st := env.svc.store
	n1, o1, err := deduplicateForImport(st, env.caseID, env.coll, src, []model.Event{mk("first")}, nil)
	if err != nil || len(n1) != 1 {
		t.Fatalf("first: new=%d err=%v", len(n1), err)
	}
	if _, err := st.CommitSegment(context.Background(), src, store.SegmentCheckpoint{Index: 0, Records: 1}, store.SegmentPayload{Events: n1, Observations: o1}); err != nil {
		t.Fatal(err)
	}
	n2, o2, err := deduplicateForImport(st, env.caseID, env.coll, src, []model.Event{mk("second")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(n2) != 0 || len(o2) != 1 || o2[0].EventID != "first" {
		t.Fatalf("second segment: new=%d observations=%+v, want 0 new and an observation of event \"first\"", len(n2), o2)
	}
}

// A failing host lookup stops the import (nothing is guessed) and is disclosed.
func TestSegmentedImportStopsWhenTheCollectionHostsCannotBeRead(t *testing.T) {
	env := newSegEnv(t, 1, 400, [2]int{0, 10}, [2]int{1000, 1500})
	env.svc.seg.hostsErr = errors.New("simulated host lookup failure")
	res := env.importAll(t)
	env.svc.seg.hostsErr = nil
	if len(res.ParseFailures) != 2 || !strings.Contains(strings.Join(res.Errors, " "), "reading the collection's hosts") {
		t.Fatalf("not disclosed: failures=%d errors=%v", len(res.ParseFailures), res.Errors)
	}
	if n := env.rows(t, `SELECT COUNT(*) FROM events`); n != 0 {
		t.Errorf("%d events imported despite the failure", n)
	}
	for _, id := range env.ids {
		if sf, _ := env.svc.store.GetSourceFile(id); sf.ImportStatus != model.SourceFileFailed {
			t.Errorf("source %s status = %q, want failed", id, sf.ImportStatus)
		}
	}
}

// After an abort that could not remove the pending rows, the sources queued
// behind it must not start (they could not be admitted beside it anyway).
func TestSegmentedImportStopsTheQueueAfterAnAbortFailure(t *testing.T) {
	env := newSegEnv(t, 1, 400, [2]int{0, 10}, [2]int{1000, 2500})
	env.svc.seg.hook = func(idx int) error {
		if idx == 1 {
			return errors.New("simulated failure")
		}
		return nil
	}
	env.svc.seg.abortErr = errors.New("simulated disk error")
	// The big source first, the small one queued behind it.
	res, err := env.svc.ImportEvidence(env.caseID, env.coll, []string{env.ids["ERRORLOG"], env.ids["ERRORLOG.1"]})
	env.svc.seg.hook, env.svc.seg.abortErr = nil, nil
	if err != nil {
		t.Fatal(err)
	}
	if len(res.ParseFailures) != 1 || len(res.Errors) != 1 {
		t.Fatalf("failures=%d errors=%v, want exactly the one stuck source reported", len(res.ParseFailures), res.Errors)
	}
	if res.Unprocessed != 1 {
		t.Errorf("unprocessed = %d, want the 1 queued source", res.Unprocessed)
	}
	if sf, _ := env.svc.store.GetSourceFile(env.ids["ERRORLOG.1"]); sf.ImportStatus != model.SourceFileDiscovered {
		t.Errorf("the queued source was started: status %q", sf.ImportStatus)
	}
}

// A duplicate-content source and a cancelled one go back to discovered, and the
// failure of that step is never silent.
func TestAbortSegmentedReturnsDuplicateAndCancelledSourcesToDiscovered(t *testing.T) {
	for name, cause := range map[string]error{"duplicate": store.ErrDuplicateSourceFile, "cancelled": context.Canceled, "other": errors.New("boom")} {
		t.Run(name, func(t *testing.T) {
			env := newSegEnv(t, 1, 400, [2]int{0, 10}, [2]int{1000, 1500})
			src := env.ids["ERRORLOG"]
			if err := env.svc.store.BeginSegmentedImport(src); err != nil {
				t.Fatal(err)
			}
			if err := env.svc.abortSegmented(src, cause, nil); !errors.Is(err, cause) {
				t.Fatalf("abortSegmented = %v, want the cause preserved", err)
			}
			want := model.SourceFileFailed
			if name != "other" {
				want = model.SourceFileDiscovered
			}
			if sf, _ := env.svc.store.GetSourceFile(src); sf.ImportStatus != want {
				t.Errorf("status = %q, want %q", sf.ImportStatus, want)
			}
		})
	}
}

// An importing source is disclosed to every reader of source status: the report
// says it is not part of the analysis, and the evidence filter/triage name it.
func TestImportingStatusIsDisclosedInReportAndEvidenceViews(t *testing.T) {
	sf := model.SourceFile{ID: "x", ImportStatus: model.SourceFileImporting, Supported: true}
	lim := reportLimitations(report.Data{}, reportInputs{sourceFiles: []model.SourceFile{sf}})
	found := false
	for _, l := range lim {
		if strings.Contains(l, "still being imported in segments") {
			found = true
		}
	}
	if !found {
		t.Errorf("report limitations do not mention the importing source: %v", lim)
	}
	if got := evidenceStatusValue(triage(sf)); got != "importing" {
		t.Errorf("evidenceStatusValue = %q, want importing", got)
	}
}

// The second pending check (after the imports gate) refuses an import that was
// queued while a segmented import became pending, and frees the gate.
func TestImportQueuedBehindThePendingCheckIsRefusedAndReleasesTheGate(t *testing.T) {
	env := newSegEnv(t, 1, 400, [2]int{0, 10}, [2]int{1000, 1500})
	svc := env.svc
	release, err := svc.imports.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, e := svc.ImportEvidence(env.caseID, env.coll, []string{env.ids["ERRORLOG.1"]})
		done <- e
	}()
	time.Sleep(300 * time.Millisecond) // it passed the first check and waits at the gate
	if err := svc.store.BeginSegmentedImport(env.ids["ERRORLOG"]); err != nil {
		t.Fatal(err)
	}
	release()
	select {
	case e := <-done:
		if !errors.Is(e, ErrImportInProgress) {
			t.Fatalf("queued import = %v, want ErrImportInProgress", e)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("queued import never returned: the gate was not released or it deadlocked")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rel, err := svc.imports.Acquire(ctx)
	if err != nil {
		t.Fatalf("the gate stayed held after the refusal: %v", err)
	}
	rel()
	if sf, _ := svc.store.GetSourceFile(env.ids["ERRORLOG.1"]); sf.ImportStatus != model.SourceFileDiscovered {
		t.Errorf("refused source status = %q, want discovered", sf.ImportStatus)
	}
}
