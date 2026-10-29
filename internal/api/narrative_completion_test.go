package api

import (
	"database/sql"
	"database/sql/driver"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"modernc.org/sqlite"

	"tracefall/internal/casefiles"
	"tracefall/internal/model"
	"tracefall/internal/store"
)

// A real SQLite AFTER INSERT trigger holds the last audit transaction open.
// No scheduler delay is needed to expose an early terminal-state publication.
func TestNarrative_CompletionWaitsForFinalAuditAndProviderRelease(t *testing.T) {
	for _, outcome := range []string{"finished", "failed", "cancelled"} {
		t.Run(outcome, func(t *testing.T) { checkNarrativeCompletion(t, outcome) })
	}
}

func checkNarrativeCompletion(t *testing.T, outcome string) {
	t.Helper()
	entered, resume := make(chan struct{}), make(chan struct{})
	var resumeOnce sync.Once
	unblock := func() { resumeOnce.Do(func() { close(resume) }) }
	defer unblock()
	fn := "summary_completion_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if err := sqlite.RegisterScalarFunction(fn, 0, func(_ *sqlite.FunctionContext, _ []driver.Value) (driver.Value, error) {
		close(entered)
		<-resume
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	svc := newPermissiveService(db, casefiles.NewStore(t.TempDir()))
	mux := routerFor(svc)
	setupChatGPT(t, svc, "")
	stub := newLLMStub(t, svc, true)
	request, respond := make(chan struct{}), make(chan struct{})
	var respondOnce sync.Once
	releaseResponse := func() { respondOnce.Do(func() { close(respond) }) }
	defer releaseResponse()
	stub.answer = func(user string) (int, string) {
		close(request)
		<-respond
		if outcome == "failed" {
			return 500, `{}`
		}
		return goodAnswer(user)
	}
	id := caseWithFindings(t, svc, mux, nil)
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = conn.Exec(`CREATE TRIGGER hold_summary_audit AFTER INSERT ON audit_log
		WHEN NEW.action = '` + model.AuditNarrativeFinished + `' BEGIN SELECT ` + fn + `(); END`)
	conn.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.StartNarrative(id, false); err != nil {
		t.Fatal(err)
	}
	// This cleanup runs before stub closure and temporary-directory removal,
	// including on any assertion failure while either barrier is held.
	t.Cleanup(func() {
		releaseResponse()
		unblock()
		waitNarr(t, svc, id)
	})
	select {
	case <-request:
	case <-time.After(3 * time.Second):
		t.Fatal("synthetic request did not start")
	}
	if outcome == "cancelled" {
		if err := svc.CancelNarrative(id); err != nil {
			t.Fatal(err)
		}
	}
	releaseResponse()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("final audit transaction did not reach barrier")
	}
	svc.narr.mu.Lock()
	run := svc.narr.runs[id]
	svc.narr.mu.Unlock()
	st := run.snapshot()
	// The journal is an actual late filesystem writer in the database's
	// TempDir, not the integration or case-file directories.
	if _, err := os.Stat(dbPath + "-journal"); err != nil {
		t.Fatalf("expected open audit rollback journal: %v", err)
	}
	if st.State != "running" || st.FinishedAt != "" {
		t.Errorf("terminal state published before final audit commit: %+v", st)
	}
	for _, route := range []struct{ method, path string }{{"PUT", ""}, {"DELETE", ""}, {"POST", "/authorize"}} {
		r := doJSON(t, mux, route.method, "/api/admin/integrations/chatgpt"+route.path, map[string]any{"provider": "none"}, nil)
		if r.Code != 409 {
			t.Errorf("provider must stay pinned through final audit: %s %d", route.method, r.Code)
		}
	}
	unblock()
	finished := waitNarr(t, svc, id)
	wantStatus := model.NarrativeError
	if outcome == "finished" {
		wantStatus = model.NarrativeOK
	}
	if finished.Run.State != outcome || finished.Latest == nil || finished.Latest.Status != wantStatus {
		t.Fatalf("unexpected completed outcome: %+v", finished)
	}
	found := 0
	for _, e := range auditActions(t, svc, id) {
		if e.Action == model.AuditNarrativeFinished {
			found++
		}
	}
	if found != 1 {
		t.Errorf("finished run must have one committed completion audit, got %d", found)
	}
	if r := doJSON(t, mux, "PUT", "/api/admin/integrations/chatgpt", map[string]any{"provider": "none"}, nil); r.Code != 200 {
		t.Errorf("completed worker still pins provider: %d %s", r.Code, r.Body.String())
	}
	if stub.count() != 1 {
		t.Errorf("provider changes sent an extra request: %d", stub.count())
	}
}
