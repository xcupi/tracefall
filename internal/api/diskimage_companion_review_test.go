package api

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
)

// Review findings on companion extraction: what persisted and rendered text may
// say, how a capped index is disclosed, and what a companion row may claim.

// leakBlobs is every persisted or rendered text the extraction status can reach.
func leakBlobs(t *testing.T, r companionRun) map[string]string {
	t.Helper()
	out := map[string]string{}
	files, err := r.svc.store.ListSourceFilesByCollection(r.col.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		b, _ := json.Marshal(f.ParseCoverage)
		out["coverage:"+f.Path] = string(b)
	}
	evs, err := r.svc.store.ListEventsByCollection(r.col.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range evs {
		b, _ := json.Marshal(e.Extra)
		out["extra:"+e.ID] = string(b)
	}
	b, err := r.svc.buildReport(r.c.ID, time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	defer b.release()
	out["report.html"] = string(b.HTML)
	d, _ := json.Marshal(b.Data)
	out["report.json"] = string(d)
	return out
}

func TestCompanion_FailedExtractionPersistsNoServerPath(t *testing.T) {
	r := discoverCompanionImage(t)
	// The destination of SYSTEM.LOG2 is a directory, so the OS refuses to create
	// the file and its error names the absolute evidence path.
	lp := r.svc.files.EvidenceDir(r.c.ID, r.col.ID) + "/" + v1cfg + "SYSTEM.LOG2"
	if err := os.MkdirAll(lp, 0o755); err != nil {
		t.Fatal(err)
	}
	// A file inside keeps the clean-up of a failed copy from removing the directory.
	if err := os.WriteFile(lp+"/keep", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.ImportEvidence(r.c.ID, r.col.ID, r.hiveIDs()); err != nil {
		t.Fatal(err)
	}
	r.files = catalogPaths(t, r.svc, r.col.ID)
	hr := r.replay(t, v1cfg+"SYSTEM")
	var failed *model.HiveCompanion
	for i := range hr.Companions {
		if strings.HasSuffix(hr.Companions[i].Path, "SYSTEM.LOG2") {
			failed = &hr.Companions[i]
		}
	}
	if failed == nil || failed.Status != model.CompanionFailed {
		t.Fatalf("SYSTEM.LOG2 must be recorded as failed: %+v", hr.Companions)
	}
	if !strings.Contains(failed.Detail, "(io)") {
		t.Errorf("detail must state a fixed error class: %q", failed.Detail)
	}
	if !strings.Contains(strings.Join(r.files[v1cfg+"SYSTEM"].ParseCoverage.Notes, " "), "SYSTEM.LOG2 was not extracted") {
		t.Errorf("the missing log must be a visible note: %v", r.files[v1cfg+"SYSTEM"].ParseCoverage.Notes)
	}
	forbidden := []string{r.col.EvidenceDirectory, os.TempDir(), "is a directory"}
	for name, text := range leakBlobs(t, r) {
		for _, f := range forbidden {
			if f != "" && strings.Contains(text, f) {
				i := strings.Index(text, f)
				lo, hi := max(0, i-80), min(len(text), i+160)
				t.Errorf("%s leaks %q: ...%s...", name, f, text[lo:hi])
			}
		}
	}
}

func TestCompanion_PermissionFailureHasFixedPathFreeClass(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores file modes")
	}
	r := importCompanionImage(t)
	lp := r.abs(v1cfg + "SYSTEM.LOG2")
	if err := os.Chmod(lp, 0o444); err != nil {
		t.Fatal(err)
	}
	x, err := r.svc.newDiskExtractor(r.c.ID, r.col.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	if err := x.extract(r.files[v1cfg+"SYSTEM"]); err != nil {
		t.Fatal(err)
	}
	var got *model.HiveCompanion
	for i, c := range x.companions[v1cfg+"SYSTEM"] {
		if strings.HasSuffix(c.Path, "SYSTEM.LOG2") {
			got = &x.companions[v1cfg+"SYSTEM"][i]
		}
	}
	if got == nil || got.Status != model.CompanionFailed {
		t.Fatalf("a read-only destination must fail the companion: %+v", x.companions[v1cfg+"SYSTEM"])
	}
	if got.Detail != "it could not be extracted (permission)" {
		t.Errorf("detail = %q, want the fixed permission class", got.Detail)
	}
	if strings.Contains(got.Detail, r.col.EvidenceDirectory) {
		t.Errorf("detail leaks the evidence path: %q", got.Detail)
	}
}

func TestCompanion_IndexCapIsDisclosedOnEveryHiveAndInDiscovery(t *testing.T) {
	old := maxCompanionIndex
	maxCompanionIndex = 2
	t.Cleanup(func() { maxCompanionIndex = old })
	r := importCompanionImage(t)

	rep, ok := r.svc.loadDiskImageReport(r.c.ID, r.col.ID)
	if !ok || !strings.Contains(strings.Join(rep.Notes, " "), "transaction log") || !strings.Contains(strings.Join(rep.Notes, " "), "limit") {
		t.Errorf("discovery notes must disclose the capped log index: %v", rep.Notes)
	}
	var dirtyWithLog, hives int
	for p, f := range r.files {
		if f.ArtifactType != model.ArtifactRegistryHive || f.ParseCoverage == nil || f.ParseCoverage.HiveReplay == nil {
			continue
		}
		hives++
		hr := f.ParseCoverage.HiveReplay
		if !strings.Contains(hr.Reason, "truncated") {
			t.Errorf("%s (%s): the capped index is not disclosed in the replay status: %q", p, hr.State, hr.Reason)
		}
		notes := strings.Join(f.ParseCoverage.Notes, " ")
		if hr.State != "clean" {
			if !strings.Contains(notes, "may be incomplete") || !f.ParseCoverage.Incomplete() {
				t.Errorf("%s (%s): a dirty hive must say replay may be incomplete: %v", p, hr.State, f.ParseCoverage.Notes)
			}
			if len(hr.Companions) > 0 {
				dirtyWithLog++
			}
		} else if strings.Contains(notes, "truncated") || f.ParseCoverage.Incomplete() {
			t.Errorf("%s: a clean hive needs no logs, so the cap is information only, not an incompleteness claim: %v", p, f.ParseCoverage.Notes)
		}
		if hr.State == "no_logs" && len(hr.Companions) == 0 {
			if !strings.Contains(hr.Reason, "none found in the (truncated) index") || strings.Contains(hr.Reason, "holds no") {
				t.Errorf("%s: no_logs must not claim the image holds none: %q", p, hr.Reason)
			}
		}
	}
	if hives < 5 || dirtyWithLog == 0 {
		t.Errorf("fixture coverage: %d hives, %d dirty hives with at least one indexed log", hives, dirtyWithLog)
	}
}

func TestCompanion_NoCapNoticeWhenIndexIsComplete(t *testing.T) {
	r := importCompanionImage(t)
	rep, _ := r.svc.loadDiskImageReport(r.c.ID, r.col.ID)
	if strings.Contains(strings.Join(rep.Notes, " "), "transaction log") {
		t.Errorf("unexpected log index notice: %v", rep.Notes)
	}
	for p, f := range r.files {
		if f.ParseCoverage != nil && f.ParseCoverage.HiveReplay != nil && strings.Contains(f.ParseCoverage.HiveReplay.Reason, "truncated") {
			t.Errorf("%s: unexpected truncation text %q", p, f.ParseCoverage.HiveReplay.Reason)
		}
	}
}

func TestCompanion_CleanHiveWithUnextractedLogSaysSoWithoutClaimingIncomplete(t *testing.T) {
	old := maxCompanionLogBytes
	maxCompanionLogBytes = 1024
	t.Cleanup(func() { maxCompanionLogBytes = old })
	r := importCompanionImage(t)
	sf := r.files[v1cfg+"SECURITY"]
	hr := r.replay(t, v1cfg+"SECURITY")
	if hr.State != "clean" {
		t.Fatalf("fixture: SECURITY state %q", hr.State)
	}
	for _, want := range []string{"cleanly written", "SECURITY.LOG1", "not extracted", "oversize"} {
		if !strings.Contains(hr.Reason, want) {
			t.Errorf("reason lacks %q: %q", want, hr.Reason)
		}
	}
	if sf.ParseCoverage.Incomplete() {
		t.Errorf("information about an unused log must not mark a clean hive incomplete: %v", sf.ParseCoverage.Notes)
	}
}

func TestCompanion_FailureAfterSuccessClearsTheCompanionHash(t *testing.T) {
	r := importCompanionImage(t)
	logPath := v1cfg + "SYSTEM.LOG1"
	if r.files[logPath].SHA256 == "" {
		t.Fatal("fixture: the log has no hash after a successful extraction")
	}
	old := maxCompanionLogBytes
	maxCompanionLogBytes = 1024
	t.Cleanup(func() { maxCompanionLogBytes = old })
	x, err := r.svc.newDiskExtractor(r.c.ID, r.col.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	if err := x.extract(r.files[v1cfg+"SYSTEM"]); err != nil {
		t.Fatal(err)
	}
	row := catalogPaths(t, r.svc, r.col.ID)[logPath]
	if row.SHA256 != "" {
		t.Errorf("a log that is no longer extracted keeps a stale hash %s", row.SHA256)
	}
	if _, err := os.Stat(r.abs(logPath)); err == nil {
		t.Error("the stale copy is still on disk")
	}
	if row.ParseCoverage == nil || row.ParseCoverage.CompanionOf != v1cfg+"SYSTEM" {
		t.Errorf("the catalog label must survive: %+v", row.ParseCoverage)
	}
}

func TestCompanion_AggregateByteLimitIsAVisibleFailure(t *testing.T) {
	r0 := importCompanionImage(t)
	comps := r0.replay(t, v1cfg+"SYSTEM").Companions
	if len(comps) != 2 {
		t.Fatalf("fixture: %+v", comps)
	}
	old := maxCompanionTotalBytes
	maxCompanionTotalBytes = comps[0].SizeBytes + 1
	t.Cleanup(func() { maxCompanionTotalBytes = old })
	r := discoverCompanionImage(t)
	if _, err := r.svc.ImportEvidence(r.c.ID, r.col.ID, []string{r.files[v1cfg+"SYSTEM"].ID}); err != nil {
		t.Fatal(err)
	}
	r.files = catalogPaths(t, r.svc, r.col.ID)
	got := r.replay(t, v1cfg+"SYSTEM").Companions
	if len(got) != 2 || got[0].Status != model.CompanionExtracted || got[1].Status != model.CompanionOversize {
		t.Fatalf("companions = %+v", got)
	}
	if !strings.Contains(got[1].Detail, "per-import") {
		t.Errorf("detail must name the aggregate limit: %q", got[1].Detail)
	}
	if r.files[v1cfg+"SYSTEM.LOG2"].SHA256 != "" {
		t.Error("a log that was not extracted has a hash")
	}
}

func TestReportCoverage_CompanionsAreOneLineAndDoNotCrowdOutRealDiagnostics(t *testing.T) {
	var files []model.SourceFile
	for i := 0; i < 120; i++ {
		files = append(files, model.SourceFile{Path: fmt.Sprintf("vol1/real%03d.evtx", i), ParseCoverage: &model.ParseCoverage{RecordsRead: 3, Mapped: 2, Unmapped: 1}})
	}
	for h := 0; h < 3; h++ {
		hive := fmt.Sprintf("vol1/Windows/System32/config/H%d", h)
		comps := []model.HiveCompanion{{Path: hive + ".LOG1", SizeBytes: 10, Status: model.CompanionExtracted, SHA256: "ab"}}
		switch h {
		case 1:
			comps = append(comps, model.HiveCompanion{Path: hive + ".LOG2", SizeBytes: 20, Status: model.CompanionFailed, Detail: "it could not be extracted (io)"})
		case 2:
			comps = append(comps, model.HiveCompanion{Path: hive + ".LOG2", SizeBytes: 20, Status: model.CompanionOversize, Detail: "too big"})
		}
		files = append(files, model.SourceFile{Path: hive, ArtifactType: model.ArtifactRegistryHive, ParseCoverage: &model.ParseCoverage{RecordsRead: 1, Mapped: 1, HiveReplay: &model.HiveReplay{State: "replayed", Companions: comps}}})
	}
	for i := 0; i < 150; i++ {
		files = append(files, model.SourceFile{Path: fmt.Sprintf("vol1/Windows/System32/config/H%03d.LOG1", i), ArtifactType: model.ArtifactRegistryTransactionLog, ParseCoverage: &model.ParseCoverage{CompanionOf: "vol1/Windows/System32/config/H000"}})
	}
	cov := reportCoverage(files)
	var real, logRows, summary int
	var summaryText string
	for _, d := range cov.ParserDiagnostics {
		switch {
		case strings.HasPrefix(d.Key, "vol1/real"):
			real++
		case strings.HasSuffix(d.Key, ".LOG1") || strings.HasSuffix(d.Key, ".LOG2"):
			logRows++
		case strings.Contains(strings.ToLower(d.Key), "transaction-log companions"):
			summary++
			summaryText = d.Value
		}
	}
	if logRows != 0 {
		t.Errorf("%d per-log rows in the capped diagnostics", logRows)
	}
	if summary != 1 {
		t.Fatalf("want one companion summary row, got %d", summary)
	}
	if real != maxFailedListed-3 || cov.DiagnosticsOmitted != 123-maxFailedListed {
		t.Errorf("real rows %d (want %d), omitted %d (want %d): companions must not take part in the cap", real, maxFailedListed-3, cov.DiagnosticsOmitted, 123-maxFailedListed)
	}
	for _, want := range []string{"150", "H1.LOG2", "failed", "H2.LOG2", "oversize"} {
		if !strings.Contains(summaryText, want) {
			t.Errorf("summary lacks %q: %s", want, summaryText)
		}
	}
	if strings.Contains(summaryText, "H0.LOG1") {
		t.Errorf("extracted logs must not be listed one by one: %s", summaryText)
	}
}

func TestReportCoverage_HiveWithoutRecordedReplayStatusIsNotSilent(t *testing.T) {
	// An import made before hive replay status existed: coverage is recorded
	// (the parser read records) but hive_replay is absent. "Absent" is not "clean".
	var historical model.ParseCoverage
	if err := json.Unmarshal([]byte(`{"records_read":4,"mapped":4,"unmapped":0,"undated":0,"records_failed":0,"chunks_read":0,"chunks_failed":0,"limit_reached":false}`), &historical); err != nil {
		t.Fatal(err)
	}
	r := discoverCompanionImage(t)
	sys := r.files[v1cfg+"SYSTEM"]
	if _, err := r.svc.store.MarkSourceFileImported(sys.ID, 0, time.Now().UTC(), &historical); err != nil {
		t.Fatal(err)
	}
	b, err := r.svc.buildReport(r.c.ID, time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	defer b.release()
	var row string
	for _, d := range b.Data.Coverage.ParserDiagnostics {
		if d.Key == v1cfg+"SYSTEM" {
			row = d.Value
		}
	}
	if row == "" {
		t.Fatalf("the hive row is missing from the report diagnostics: %+v", b.Data.Coverage.ParserDiagnostics)
	}
	if !strings.Contains(row, "hive transaction logs: not recorded") {
		t.Errorf("historical hive row must say transaction logs are not recorded: %s", row)
	}
	if !strings.Contains(string(b.HTML), "hive transaction logs: not recorded") {
		t.Error("the rendered report must carry the statement")
	}

	// A genuinely new clean hive keeps saying clean, never "not recorded".
	cov := reportCoverage([]model.SourceFile{{Path: "vol1/x/SYSTEM", ArtifactType: model.ArtifactRegistryHive, ParseCoverage: &model.ParseCoverage{RecordsRead: 4, Mapped: 4, HiveReplay: &model.HiveReplay{State: "clean"}}}})
	if len(cov.ParserDiagnostics) != 1 || !strings.Contains(cov.ParserDiagnostics[0].Value, "hive transaction logs: clean") || strings.Contains(cov.ParserDiagnostics[0].Value, "not recorded") {
		t.Errorf("new clean hive: %+v", cov.ParserDiagnostics)
	}
}
