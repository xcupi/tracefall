package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
	"tracefall/internal/enrich/llm"
	"tracefall/internal/model"
)

func TestCaseReview_ZeroFindingsPreviewAndExactPersistedRequest(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newLLMStub(t, svc, true)
	stub.answer = func(string) (int, string) { return 200, chatBody("An unflagged observation is recorded. [E1]") }
	id := caseWithFindings(t, svc, mux, func(fs *[]model.Finding) { *fs = nil })
	base := "/api/cases/" + id + "/enrich/case-review"
	var preview map[string]any
	rec := doJSON(t, mux, "GET", base+"/preview", nil, nil)
	if rec.Code != 200 {
		t.Fatalf("preview: %d %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &preview); err != nil {
		t.Fatal(err)
	}
	if stub.count() != 0 {
		t.Fatal("preview sent case data")
	}
	if rec := doJSON(t, mux, "POST", base, map[string]any{"acknowledge": false, "preview_key": preview["preview_key"]}, nil); rec.Code != http.StatusAccepted {
		t.Fatalf("start %d %s", rec.Code, rec.Body.String())
	}
	var st map[string]any
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		doJSON(t, mux, "GET", base, nil, &st)
		if run, ok := st["run"].(map[string]any); ok && run["state"] != "running" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	raw, _ := json.Marshal(st)
	if st["latest"] == nil {
		t.Fatalf("no persisted result %s", raw)
	}
	if st["source_fingerprint"] != preview["source_fingerprint"] {
		t.Fatalf("status lacks current source fingerprint: %v", st["source_fingerprint"])
	}
	latest := st["latest"].(map[string]any)
	if latest["status"] != "ok" || latest["stale"] != false {
		t.Fatalf("result %s", raw)
	}
	var sent map[string]any
	doJSON(t, mux, "GET", base+"/payload", nil, &sent)
	digest := sha256.Sum256([]byte(stub.last().System + "\x00" + stub.last().User))
	if sent["sha256"] != fmt.Sprintf("%x", digest) {
		t.Fatal("payload hash differs from independent digest")
	}
	if sent["user"] != stub.last().User || sent["system"] != stub.last().System || sent["sha256"] != preview["sha256"] {
		t.Fatal("stored payload not exact")
	}
	if _, ok, err := svc.store.LatestNarrative(id); err != nil || ok {
		t.Fatalf("review polluted Summary: %v", err)
	}
}
func reviewPreview(t *testing.T, mux http.Handler, id string) CaseReviewPreview {
	t.Helper()
	var p CaseReviewPreview
	rec := doJSON(t, mux, "GET", "/api/cases/"+id+"/enrich/case-review/preview", nil, &p)
	if rec.Code != 200 {
		t.Fatalf("preview %d %s", rec.Code, rec.Body.String())
	}
	return p
}
func reviewStart(t *testing.T, mux http.Handler, id string, ack bool, hash string) int {
	t.Helper()
	return doJSON(t, mux, "POST", "/api/cases/"+id+"/enrich/case-review", map[string]any{"acknowledge": ack, "preview_key": hash}, nil).Code
}
func waitReview(t *testing.T, svc *Service, id string) CaseReviewStatus {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		st, err := svc.CaseReviewStatus(id)
		if err != nil {
			t.Fatal(err)
		}
		if st.Run != nil && st.Run.State != "running" {
			return st
		}
		time.Sleep(time.Millisecond * 10)
	}
	t.Fatal("review did not finish")
	return CaseReviewStatus{}
}
func TestCaseReview_ExternalGatesPreviewChangeAndNoAutomaticSend(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newLLMStub(t, svc, false)
	id := caseWithFindings(t, svc, mux, nil)
	p := reviewPreview(t, mux, id)
	if stub.count() != 0 {
		t.Fatal("preview sent")
	}
	if got := reviewStart(t, mux, id, true, p.PreviewKey); got != 403 {
		t.Fatalf("no egress got %d", got)
	}
	setLevel(t, mux, id, "pseudonymized")
	if got := reviewStart(t, mux, id, false, p.PreviewKey); got != 403 {
		t.Fatalf("no ack got %d", got)
	}
	if got := reviewStart(t, mux, id, true, "wrong"); got != 409 {
		t.Fatalf("changed preview got %d", got)
	}
	other := createTestCase(t, mux, "unrelated review")
	if got := reviewStart(t, mux, other.ID, true, p.PreviewKey); got == 202 {
		t.Fatal("accepted wrong-case preview")
	}
	if stub.count() != 0 {
		t.Fatal("a refusal sent")
	}
	if _, ok, _ := svc.store.LatestCaseReview(id); ok {
		t.Fatal("refusal persisted sent request")
	}
	if got := reviewStart(t, mux, id, true, p.PreviewKey); got != 202 {
		t.Fatalf("acknowledged got %d", got)
	}
	st := waitReview(t, svc, id)
	if st.Latest == nil {
		t.Fatal("no review")
	}
	req := stub.last()
	for _, name := range realNames {
		if strings.Contains(strings.ToLower(req.User), strings.ToLower(name)) {
			t.Errorf("leaked %s", name)
		}
	}
	for _, bad := range []string{"SELECT *", "ntlm_hash", "Security.evtx", "fnd-1", "ev-1"} {
		if strings.Contains(req.User, bad) {
			t.Errorf("forbidden field/value %s", bad)
		}
	}
}
func TestCaseReview_FailureKeepsPayloadAndDoesNotChangeFindings(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		body string
	}{{"model error", 500, `{"error":{"message":"synthetic-review-secret"}}`}, {"invalid refs", 200, chatBody("Invented source. [C99]\nNo refs.")}} {
		t.Run(tc.name, func(t *testing.T) {
			mux, svc := newTestRouterWithService(t)
			stub := newLLMStub(t, svc, true)
			stub.answer = func(string) (int, string) { return tc.code, tc.body }
			id := caseWithFindings(t, svc, mux, nil)
			before, _ := svc.store.ListFindings(id)
			p := reviewPreview(t, mux, id)
			if got := reviewStart(t, mux, id, false, p.PreviewKey); got != 202 {
				t.Fatal(got)
			}
			st := waitReview(t, svc, id)
			if st.Run.State != "failed" || st.Latest.Status != "error" {
				t.Fatalf("%+v", st)
			}
			row, ok, err := svc.store.LatestCaseReview(id)
			if err != nil || !ok || row.Narrative.PayloadUser != stub.last().User || row.Narrative.PayloadSystem != stub.last().System {
				t.Fatal("exact failure payload absent", err)
			}
			after, _ := svc.store.ListFindings(id)
			a, _ := json.Marshal(before)
			b, _ := json.Marshal(after)
			if string(a) != string(b) {
				t.Fatal("review changed deterministic findings")
			}
		})
	}
}
func TestCaseReview_StaleOnEventsCorrelationsAndCoverage(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newLLMStub(t, svc, true)
	stub.answer = func(string) (int, string) { return 200, chatBody("A bounded observation is recorded. [E1]") }
	id := caseWithFindings(t, svc, mux, nil)
	start := func() {
		p := reviewPreview(t, mux, id)
		if got := reviewStart(t, mux, id, false, p.PreviewKey); got != 202 {
			t.Fatal(got)
		}
		st := waitReview(t, svc, id)
		if st.Latest == nil || st.Latest.Stale {
			t.Fatal("fresh review stale")
		}
	}
	stale := func() {
		st, err := svc.CaseReviewStatus(id)
		if err != nil || !st.Latest.Stale {
			t.Fatal("changed input not stale", err)
		}
	}
	start()
	es, _ := svc.store.ListEvents(id)
	e := es[0]
	e.ID = "unflagged-added"
	e.DedupHash = "unflagged-added"
	if err := svc.store.SaveEvents([]model.Event{e}); err != nil {
		t.Fatal(err)
	}
	stale()
	start()
	if err := svc.store.SaveCorrelations([]model.Correlation{{ID: "new-correlation", CaseID: id, Title: "A link", EventIDs: []string{e.ID}}}); err != nil {
		t.Fatal(err)
	}
	stale()
	ss, _ := svc.store.ListSourceFiles(id)
	newSource := model.SourceFile{ID: "coverage-source", CaseID: id, CollectionID: ss[0].CollectionID, ImportStatus: model.SourceFileDiscovered, SHA256: strings.Repeat("a", 64)}
	if err := svc.store.SaveSourceFiles([]model.SourceFile{newSource}); err != nil {
		t.Fatal(err)
	}
	start()
	if applied, err := svc.store.MarkSourceFileImported(newSource.ID, 3, time.Now(), &model.ParseCoverage{RecordsRead: 10, Mapped: 3, Unmapped: 7}); err != nil || !applied {
		t.Fatal("coverage update", applied, err)
	}
	stale()
}

// Blocking fake provider makes cancellation/lease tests independent of sleep.
type reviewBlockingProvider struct{ entered chan struct{} }

func (p reviewBlockingProvider) Configured() bool            { return true }
func (p reviewBlockingProvider) Destination() (string, bool) { return "synthetic-local", true }
func (p reviewBlockingProvider) ModelName() string           { return "synthetic-blocking" }
func (p reviewBlockingProvider) Notice() string              { return "test only" }
func (p reviewBlockingProvider) Chat(ctx context.Context, _ []llm.Message) (llm.Result, error) {
	close(p.entered)
	<-ctx.Done()
	return llm.Result{}, ctx.Err()
}
func TestCaseReview_CancelAndProviderLease(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	id := caseWithFindings(t, svc, mux, nil)
	p := reviewBlockingProvider{entered: make(chan struct{})}
	svc.SetLLM(p)
	pr := reviewPreview(t, mux, id)
	if got := reviewStart(t, mux, id, false, pr.PreviewKey); got != 202 {
		t.Fatal(got)
	}
	select {
	case <-p.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("provider not entered")
	}
	if got := reviewStart(t, mux, id, false, pr.PreviewKey); got != 409 {
		t.Fatalf("duplicate %d", got)
	}
	svc.llm.mu.Lock()
	active := svc.llm.active
	svc.llm.mu.Unlock()
	if active != 1 {
		t.Fatalf("lease %d", active)
	}
	if rec := doJSON(t, mux, "PUT", "/api/admin/integrations/chatgpt", map[string]string{"provider": "none"}, nil); rec.Code != 409 {
		t.Fatalf("provider selection was not lease-guarded: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doJSON(t, mux, "POST", "/api/cases/"+id+"/enrich/case-review/cancel", map[string]any{}, nil); rec.Code != 204 {
		t.Fatal(rec.Code)
	}
	st := waitReview(t, svc, id)
	if st.Run.State != "cancelled" || st.Latest.Status != "error" {
		t.Fatalf("%+v", st)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		svc.llm.mu.Lock()
		active = svc.llm.active
		svc.llm.mu.Unlock()
		if active == 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if active != 0 {
		t.Fatal("provider lease leaked")
	}
	row, ok, _ := svc.store.LatestCaseReview(id)
	if !ok || row.Narrative.PayloadUser != pr.User {
		t.Fatal("cancel lost payload")
	}
}
func TestCaseReview_LeakRefusalSendsNothing(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newLLMStub(t, svc, true)
	id := caseWithFindings(t, svc, mux, nil)
	// Own enum fields are leak checked rather than silently trusted.
	es, _ := svc.store.ListEvents(id)
	e := es[0]
	e.ID = "leak-event"
	e.DedupHash = "leak-event"
	e.EventType = "203.0.113.77"
	if err := svc.store.SaveEvents([]model.Event{e}); err != nil {
		t.Fatal(err)
	}
	rec := doJSON(t, mux, "GET", "/api/cases/"+id+"/enrich/case-review/preview", nil, nil)
	if rec.Code != 422 {
		t.Fatalf("leak preview %d %s", rec.Code, rec.Body.String())
	}
	if got := reviewStart(t, mux, id, false, "any"); got != 422 {
		t.Fatalf("leak start %d", got)
	}
	if stub.count() != 0 {
		t.Fatal("leak sent")
	}
	if _, ok, _ := svc.store.LatestCaseReview(id); ok {
		t.Fatal("refusal persisted request")
	}
}
func TestCaseReview_PreviewMustBeBoundToProvider(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newLLMStub(t, svc, true)
	id := caseWithFindings(t, svc, mux, nil)
	p := reviewPreview(t, mux, id)
	svc.SetLLM(llm.New(stub.srv.URL, "synthetic-only", "different-model"))
	got := reviewStart(t, mux, id, false, p.PreviewKey)
	if got == 202 {
		waitReview(t, svc, id)
	}
	if got != 409 {
		t.Fatalf("changed provider/model accepted old preview: %d", got)
	}
	if stub.count() != 0 {
		t.Fatal("changed provider received case data")
	}
}
