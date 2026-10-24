package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"tracefall/internal/enrich/llm"
	"tracefall/internal/model"
	"tracefall/internal/store"
)

type privacyBlockingProvider struct{ entered, exited chan struct{} }

func (p privacyBlockingProvider) Configured() bool { return true }
func (p privacyBlockingProvider) Destination() (string, bool) {
	return "synthetic-external.invalid", false
}
func (p privacyBlockingProvider) ModelName() string { return "synthetic-revocation" }
func (p privacyBlockingProvider) Notice() string    { return "synthetic only" }
func (p privacyBlockingProvider) Chat(ctx context.Context, _ []llm.Message) (llm.Result, error) {
	close(p.entered)
	defer close(p.exited)
	<-ctx.Done()
	return llm.Result{}, ctx.Err()
}

func TestCaseReviewPrivacy_RevocationCancelsExternalRequest(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	id := caseWithFindings(t, svc, mux, nil)
	p := privacyBlockingProvider{entered: make(chan struct{}), exited: make(chan struct{})}
	svc.SetLLM(p)
	setLevel(t, mux, id, "pseudonymized")
	pr := reviewPreview(t, mux, id)
	if got := reviewStart(t, mux, id, true, pr.PreviewKey); got != 202 {
		t.Fatal(got)
	}
	t.Cleanup(func() { _ = svc.CancelCaseReview(id) })
	select {
	case <-p.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not enter provider")
	}
	setLevel(t, mux, id, "none")
	select {
	case <-p.exited:
	case <-time.After(2 * time.Second):
		t.Fatal("revocation did not cancel in-flight external review")
	}
	st := waitReview(t, svc, id)
	if st.Run.State != "cancelled" || st.Latest.Status != "error" {
		t.Fatalf("revoked review not cancelled: %+v", st)
	}
}

func TestCaseReviewPrivacy_WorkerRechecksPermissionBeforeProviderCall(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newLLMStub(t, svc, false)
	id := caseWithFindings(t, svc, mux, nil)
	pr, err := svc.prepareCaseReview(id)
	if err != nil {
		t.Fatal(err)
	}
	// Exercise the dispatch boundary independently of HTTP admission: permission
	// can have changed after the request was prepared and persisted.
	row := store.CaseReview{Narrative: model.Narrative{ID: "synthetic-not-dispatched", CaseID: id, CreatedAt: time.Now(), PayloadSystem: pr.System, PayloadUser: pr.User, PayloadSHA256: payloadHash(pr.System, pr.User)}, Coverage: pr.Coverage, Fingerprint: pr.Fingerprint}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	run := &narrativeRun{cancel: cancel, st: NarrativeRun{State: "running"}}
	svc.runCaseReview(ctx, id, pr, row, run, svc.llm.snapshot())
	if stub.count() != 0 {
		t.Fatal("worker dispatched despite current none egress")
	}
	if run.snapshot().State != "failed" {
		t.Fatalf("incorrect dispatch status: %+v", run.snapshot())
	}
}

func TestCaseReviewPrivacy_PreviewIsNotTransmissionPermission(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newLLMStub(t, svc, false)
	id := caseWithFindings(t, svc, mux, nil)
	base := "/api/cases/" + id + "/enrich/case-review"
	var p struct {
		System, User string
		Privacy      struct {
			Contract                   string `json:"contract"`
			Status                     string `json:"status"`
			PayloadBytes               int    `json:"payload_bytes"`
			RequiresSeparatePermission bool   `json:"requires_separate_permission"`
		} `json:"privacy"`
	}
	rec := doJSON(t, mux, "GET", base+"/preview", nil, &p)
	if rec.Code != 200 {
		t.Fatalf("preview %d %s", rec.Code, rec.Body.String())
	}
	if p.Privacy.Contract == "" || p.Privacy.Status != "checked" || !p.Privacy.RequiresSeparatePermission || p.Privacy.PayloadBytes != len(p.System)+len(p.User) {
		t.Fatalf("missing independent privacy-preparation receipt: %+v", p.Privacy)
	}
	var st CaseReviewStatus
	if rec := doJSON(t, mux, "GET", base, nil, &st); rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	if st.Allowed || st.EgressLevel != "none" || stub.count() != 0 {
		t.Fatal("preview granted permission or transmitted")
	}
	if _, ok, _ := svc.store.LatestCaseReview(id); ok {
		t.Fatal("preview created a request record")
	}
}

func TestCaseReviewPrivacy_PreviewExpiresWhenEgressChanges(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newLLMStub(t, svc, false)
	id := caseWithFindings(t, svc, mux, nil)
	p := reviewPreview(t, mux, id)
	setLevel(t, mux, id, "pseudonymized")
	code := reviewStart(t, mux, id, true, p.PreviewKey)
	if code == 202 {
		waitReview(t, svc, id)
	}
	if code != 409 || stub.count() != 0 {
		t.Fatalf("stale permission context used: HTTP %d, calls %d", code, stub.count())
	}
}

func TestCaseReviewPrivacy_ExternalRequestInspectsExactExpandedPacket(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newLLMStub(t, svc, false)
	id := caseWithFindings(t, svc, mux, nil)
	es, err := svc.store.ListEvents(id)
	if err != nil {
		t.Fatal(err)
	}
	e := es[0]
	e.ID = "privacy-extra"
	e.DedupHash = "privacy-extra"
	e.CommandLine = `AWS_SECRET_ACCESS_KEY=EnvSecret7 curl "https://alice:UserInfoSecret@api.example.test/download?access_token=ShortSecret42#ResetSecret7"`
	e.Extra = map[string]string{"sql_statement": "PrivateSQLBody7", "cookie": "PrivateCookieBody7"}
	if err := svc.store.SaveEvents([]model.Event{e}); err != nil {
		t.Fatal(err)
	}
	setLevel(t, mux, id, "pseudonymized")
	p := reviewPreview(t, mux, id)
	if got := reviewStart(t, mux, id, true, p.PreviewKey); got != 202 {
		t.Fatal(got)
	}
	waitReview(t, svc, id)
	req := stub.last()
	for _, bad := range []string{"EnvSecret7", "UserInfoSecret", "ShortSecret42", "ResetSecret7", "PrivateSQLBody7", "PrivateCookieBody7"} {
		if strings.Contains(req.User, bad) {
			t.Errorf("expanded outbound packet leaks %s", bad)
		}
	}
	var stored NarrativePayload
	rec := doJSON(t, mux, "GET", "/api/cases/"+id+"/enrich/case-review/payload", nil, &stored)
	if rec.Code != 200 || stored.User != req.User || stored.System != req.System {
		t.Fatal("not the exact recorded request")
	}
	raw, _ := json.Marshal(p)
	if strings.Contains(string(raw), "PrivateSQLBody7") {
		t.Fatal("preview exposed excluded body")
	}
	row, ok, err := svc.store.LatestCaseReview(id)
	if err != nil || !ok {
		t.Fatal("review not persisted", err)
	}
	record, _ := json.Marshal(row)
	var saved map[string]json.RawMessage
	if err := json.Unmarshal(record, &saved); err != nil {
		t.Fatal(err)
	}
	if len(saved["privacy"]) == 0 {
		t.Fatal("privacy contract not persisted with attempted request")
	}
	var receipt map[string]any
	if err := json.Unmarshal(saved["privacy"], &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt["contract"] != p.Privacy.Contract || receipt["status"] != "checked" {
		t.Fatal("persisted privacy contract differs from inspected preview")
	}
}
