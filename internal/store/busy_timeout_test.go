package store

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
)

// heldReader opens a second connection to the same file (as another process
// would) and keeps a read transaction open, which holds a SHARED lock under
// SQLite's default rollback journal. The returned func releases it.
func heldReader(t *testing.T, path string) func() {
	t.Helper()
	ext, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	ext.SetMaxOpenConns(1)
	tx, err := ext.Begin()
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM cases`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return func() { _ = tx.Rollback(); _ = ext.Close() }
}

func newCaseRow(id string) model.Case {
	now := time.Now().UTC()
	return model.Case{ID: id, Name: "case " + id, Status: model.CaseStatusCreated, CreatedAt: now, UpdatedAt: now}
}

// Another process holding a read lock for a moment must delay the store's write,
// not fail it: the server's writes used to die with SQLITE_BUSY at once.
func TestStoreWaitsForAnExternalReaderInsteadOfFailingWithBusy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "busy.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CreateCase(newCaseRow("seed")); err != nil {
		t.Fatal(err)
	}
	release := heldReader(t, path)
	time.AfterFunc(700*time.Millisecond, release)
	started := time.Now()
	if err := s.CreateCase(newCaseRow("waited")); err != nil {
		t.Fatalf("write while another process held a read lock for 0.7 s failed: %v", err)
	}
	if waited := time.Since(started); waited < 600*time.Millisecond {
		t.Fatalf("write returned after %s: it cannot have waited for the reader (the test proves nothing)", waited)
	}
}

// The wait is bounded: a reader that never lets go still ends in a clear error,
// after the timeout, and the store works again as soon as the lock is gone.
func TestStoreBusyWaitIsBoundedAndRecovers(t *testing.T) {
	old := busyTimeoutMS
	busyTimeoutMS = 300
	defer func() { busyTimeoutMS = old }()
	path := filepath.Join(t.TempDir(), "busy2.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CreateCase(newCaseRow("seed")); err != nil {
		t.Fatal(err)
	}
	release := heldReader(t, path)
	started := time.Now()
	err = s.CreateCase(newCaseRow("blocked"))
	elapsed := time.Since(started)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "locked") {
		t.Fatalf("write with a permanently held read lock = %v, want a database-is-locked error", err)
	}
	if elapsed < 100*time.Millisecond || elapsed > 5*time.Second {
		t.Fatalf("gave up after %s, want about the 300 ms timeout", elapsed)
	}
	release()
	if err := s.CreateCase(newCaseRow("after")); err != nil {
		t.Fatalf("store did not recover after the lock was released: %v", err)
	}
}

// The timeout applies to every connection the pool opens, not only the first.
func TestBusyTimeoutSurvivesAReopenedConnection(t *testing.T) {
	old := busyTimeoutMS
	busyTimeoutMS = 2500
	defer func() { busyTimeoutMS = old }()
	path := filepath.Join(t.TempDir(), "busy3.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.db.SetMaxIdleConns(0) // every statement opens a fresh connection
	if err := s.CreateCase(newCaseRow("seed")); err != nil {
		t.Fatal(err)
	}
	release := heldReader(t, path)
	time.AfterFunc(600*time.Millisecond, release)
	if err := s.CreateCase(newCaseRow("fresh-conn")); err != nil {
		t.Fatalf("a fresh connection did not inherit the busy timeout: %v", err)
	}
}

func TestWithBusyTimeoutKeepsPathsAndURIsIntact(t *testing.T) {
	cases := map[string]string{
		"/tmp/a b/c.db":              "/tmp/a b/c.db?_busy_timeout=",
		":memory:":                   ":memory:?_busy_timeout=",
		"file:x.db?mode=rwc":         "file:x.db?mode=rwc&_busy_timeout=",
		"file::memory:?cache=shared": "file::memory:?cache=shared&_busy_timeout=",
	}
	for in, prefix := range cases {
		got := withBusyTimeout(in)
		if !strings.HasPrefix(got, prefix) || !strings.HasSuffix(got, "=30000") && busyTimeoutMS == 30000 {
			t.Errorf("withBusyTimeout(%q) = %q, want prefix %q and the configured timeout", in, got, prefix)
		}
	}
}
