//go:build linux

package api

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"tracefall/internal/ingest"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
	"tracefall/internal/parsers/mssql"
)

func TestSQLStreamHundredSourcesLowFD(t *testing.T) {
	if os.Getenv("TRACEFALL_TEST_LOW_FD") != "1" {
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(exe, "-test.run=^TestSQLStreamHundredSourcesLowFD$", "-test.v")
		cmd.Env = append(os.Environ(), "TRACEFALL_TEST_LOW_FD=1")
		out, err := cmd.CombinedOutput()
		t.Log(string(out))
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatal(err)
	}
	lim.Cur = 64
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatal(err)
	}
	svc := newTestService(t)
	c, err := svc.CreateCase("descriptor bounded", "")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	for i := 0; i < 100; i++ {
		dir := filepath.Join(root, fmt.Sprint(i))
		if err = os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dir, "ERRORLOG"), []byte(fmt.Sprintf("2025-01-02 03:04:05.00 Server Microsoft SQL Server message %d\n", i)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	d, err := svc.DiscoverEvidenceFromPath(c.ID, root)
	if err != nil {
		t.Fatal(err)
	}
	files, err := svc.store.ListSourceFilesByCollection(d.Collection.ID)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(files))
	for _, f := range files {
		ids = append(ids, f.ID)
	}
	result, err := svc.ImportEvidence(c.ID, d.Collection.ID, ids)
	if err != nil || len(result.Imported) != 100 || len(result.ParseFailures) != 0 || result.EventCount != 100 {
		t.Fatalf("imported=%d failures=%d events=%d err=%v", len(result.Imported), len(result.ParseFailures), result.EventCount, err)
	}
	t.Logf("soft RLIMIT_NOFILE=64 selected=%d imported=%d failures=%d events=%d", len(ids), len(result.Imported), len(result.ParseFailures), result.EventCount)
}

func TestSQLStreamBudgetFailureCleansStaging(t *testing.T) {
	svc := newTestService(t)
	root := t.TempDir()
	spools := t.TempDir()
	t.Setenv("TMPDIR", spools)
	if err := os.WriteFile(filepath.Join(root, "ERRORLOG"), []byte("2025-01-02 03:04:05.00 Server message\n"), 0600); err != nil {
		t.Fatal(err)
	}
	sf := model.SourceFile{ID: "source01", Path: "ERRORLOG"}
	budget := &stagingBudget{limit: 1}
	_, err := svc.stageStream("case01", "collection01", sf, root, mssql.New(), parsers.ParseContext{}, nil, budget)
	if err == nil || parseFailure(sf, ParseStageParse, err).Category != ParseFailureLimit || !strings.Contains(err.Error(), "aggregate") {
		t.Fatalf("budget failure not visible: %v", err)
	}
	entries, e := os.ReadDir(spools)
	if e != nil || len(entries) != 0 || budget.used != 0 {
		t.Fatalf("cleanup: files=%d bytes=%d err=%v", len(entries), budget.used, e)
	}
}

func TestSQLStreamPartialPersistenceIsFailed(t *testing.T) {
	svc := newTestService(t)
	c, err := svc.CreateCase("partial persistence", "")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	text := ""
	for i := 0; i < 300; i++ {
		text += fmt.Sprintf("2025-01-02 03:04:05.00 Server Microsoft SQL Server message %d\n", i)
	}
	if err = os.WriteFile(filepath.Join(root, "ERRORLOG"), []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	d, err := svc.DiscoverEvidenceFromPath(c.ID, root)
	if err != nil {
		t.Fatal(err)
	}
	files, err := svc.store.ListSourceFilesByCollection(d.Collection.ID)
	if err != nil || len(files) != 1 {
		t.Fatalf("discover: %v", err)
	}
	_, err = svc.store.DB().Exec(`CREATE TRIGGER reject_later_batch BEFORE INSERT ON events WHEN (SELECT count(*) FROM events)>=128 BEGIN SELECT RAISE(FAIL, 'injected persistence failure'); END`)
	if err != nil {
		t.Fatal(err)
	}
	spools := t.TempDir()
	t.Setenv("TMPDIR", spools)
	_, err = svc.ImportEvidence(c.ID, d.Collection.ID, []string{files[0].ID})
	if err == nil {
		t.Fatal("persistence failure hidden")
	}
	// A later batch failure must roll back the whole source, including raw
	// evidence and observations, not merely mark a visible prefix failed.
	entries, e := os.ReadDir(spools)
	if e != nil || len(entries) != 0 {
		t.Fatalf("persistence failure leaked spool: files=%d err=%v", len(entries), e)
	}
	sf, err := svc.store.GetSourceFile(files[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err = svc.store.DB().QueryRow("SELECT count(*) FROM events").Scan(&n); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"events", "raw_evidence", "event_observations"} {
		if err = svc.store.DB().QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 || sf.ImportStatus != model.SourceFileFailed {
			t.Fatalf("source rollback: table=%s persisted=%d status=%s", table, n, sf.ImportStatus)
		}
	}
	if _, err := svc.store.DB().Exec(`DROP TRIGGER reject_later_batch`); err != nil {
		t.Fatal(err)
	}
	retry, err := svc.ImportEvidence(c.ID, d.Collection.ID, []string{files[0].ID})
	if err != nil || len(retry.Imported) != 1 {
		t.Fatalf("failed source retry: imported=%d err=%v", len(retry.Imported), err)
	}
	for _, table := range []string{"events", "raw_evidence", "event_observations"} {
		if err := svc.store.DB().QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 300 {
			t.Fatalf("retry table=%s count=%d", table, n)
		}
	}
}

func TestSQLStreamAggregateStagingBudget(t *testing.T) {
	b := &stagingBudget{limit: 100}
	first, err := newParsedSpool(b)
	if err != nil {
		t.Fatal(err)
	}
	defer first.close()
	second, err := newParsedSpool(b)
	if err != nil {
		t.Fatal(err)
	}
	defer second.close()
	batch := ingest.ParsedFile{}
	if err = first.append(batch); err != nil {
		t.Fatal(err)
	}
	// Each fits separately; both together exceed the import allowance.
	b.limit = first.bytes*2 - 1
	if err = second.append(batch); err == nil {
		t.Fatal("aggregate staging limit accepted two individually bounded sources")
	}
	if second.bytes != 0 {
		t.Fatal("over-budget bytes were written")
	}
}

func TestSQLStreamPendingSpoolsReleaseDescriptors(t *testing.T) {
	svc := newTestService(t)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "ERRORLOG"), []byte("2025-01-02 03:04:05.00 Server message\n"), 0600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadDir("/proc/self/fd")
	var pending []pendingImport
	defer func() {
		for _, p := range pending {
			p.spool.close()
		}
	}()
	for i := 0; i < 100; i++ {
		p, err := svc.stageStream("case01", "collection01", model.SourceFile{ID: fmt.Sprint(i), Path: "ERRORLOG"}, root, mssql.New(), parsers.ParseContext{}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		pending = append(pending, p)
	}
	after, _ := os.ReadDir("/proc/self/fd")
	if len(after) > len(before)+4 {
		t.Fatalf("pending sources retained descriptors: before=%d after=%d", len(before), len(after))
	}
	for _, p := range pending {
		n := 0
		if err := p.spool.each(func(b ingest.ParsedFile) error { n += len(b.Events); return nil }); err != nil || n != 1 {
			t.Fatalf("reopen count=%d err=%v", n, err)
		}
	}
}
