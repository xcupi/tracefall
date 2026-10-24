package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	"tracefall/internal/model"
	"tracefall/internal/narrative"
)

func seedStoredReviewVT(t *testing.T, svc *Service, id string) model.Enrichment {
	t.Helper()
	events, err := svc.store.ListEvents(id)
	if err != nil || len(events) == 0 {
		t.Fatal(err)
	}
	e := events[0]
	if e.Extra == nil {
		e.Extra = map[string]string{}
	}
	e.Extra["content_sha256"] = strings.Repeat("a", 64)
	// Existing SaveEvents ignores duplicates; use a fresh synthetic observation.
	e.ID = "vt-event"
	e.DedupHash = "vt-event"
	if err = svc.store.SaveEvents([]model.Event{e}); err != nil {
		t.Fatal(err)
	}
	vt := model.Enrichment{ID: "vt-original", CaseID: id, Provider: "virustotal", IndicatorType: "sha256", Indicator: strings.Repeat("a", 64), Status: "found", FetchedAt: time.Date(2023, 2, 3, 4, 5, 6, 0, time.UTC), SourceEventIDs: []string{e.ID}, ResultJSON: `{"found":true,"malicious":2,"suspicious":0,"harmless":1,"undetected":3,"timeout":0,"failure":0,"type_unsupported":0,"meaningful_name":"secret-filename","link":"https://secret.invalid/?key=secret-key"}`, Error: "secret-error"}
	if err = svc.store.UpsertEnrichment(vt); err != nil {
		t.Fatal(err)
	}
	return vt
}
func TestCaseReviewVTEmptyCaseStillUnprocessable(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	newLLMStub(t, svc, true)
	c, err := svc.CreateCase("Empty synthetic", "")
	if err != nil {
		t.Fatal(err)
	}
	rec := doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/enrich/case-review/preview", nil, nil)
	if rec.Code != 422 {
		t.Fatalf("empty preview %d %s", rec.Code, rec.Body.String())
	}
}
func TestReviewVTPreparationHonorsCancelledRequest(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	newLLMStub(t, svc, true)
	id := caseWithFindings(t, svc, mux, nil)
	seedStoredReviewVT(t, svc, id)
	p, err := svc.PlanReviewBatches(id, defaultBatchBudget())
	if err != nil {
		t.Fatal(err)
	}
	scoped := *svc
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	scoped.reqCtx = ctx
	if _, err = scoped.prepareCaseReview(id); !errors.Is(err, context.Canceled) {
		t.Fatalf("single preparation ignored cancellation: %v", err)
	}
	if _, err = scoped.batchInput(id, p.ID, "event", 0, 60, p.Snapshot.Names); !errors.Is(err, context.Canceled) {
		t.Fatalf("VT packet preparation ignored cancellation: %v", err)
	}
}
func TestCaseReviewVTFrozenAttemptAndEgress(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newLLMStub(t, svc, false)
	stub.answer = func(string) (int, string) {
		return 200, chatBody("hypothesis | Stored opinion flagged 2 engines. [V1]")
	}
	id := caseWithFindings(t, svc, mux, nil)
	vt := seedStoredReviewVT(t, svc, id)
	p := reviewPreview(t, mux, id)
	if p.Coverage.VTIncluded != 1 {
		t.Fatalf("VT not in preview: %+v", p.Coverage)
	}
	if reviewStart(t, mux, id, true, p.PreviewKey) != 403 {
		t.Fatal("no egress admitted")
	}
	svc.SetEgressLevel(id, "pseudonymized")
	p = reviewPreview(t, mux, id)
	if reviewStart(t, mux, id, false, p.PreviewKey) != 403 {
		t.Fatal("no ack admitted")
	}
	if stub.count() != 0 {
		t.Fatal("preview/gates sent")
	}
	if reviewStart(t, mux, id, true, p.PreviewKey) != 202 {
		t.Fatal("start refused")
	}
	st := waitReview(t, svc, id)
	if st.Latest == nil || st.Latest.Status != "ok" {
		t.Fatalf("review %+v", st)
	}
	for _, bad := range []string{vt.Indicator, vt.ID, "vt-event", "secret-filename", "secret-key", "secret-error"} {
		if strings.Contains(stub.last().System+stub.last().User, bad) {
			t.Fatalf("leaked %s", bad)
		}
	}
	vt.Status = "error"
	vt.ID = "replacement"
	svc.store.UpsertEnrichment(vt)
	base := "/api/cases/" + id + "/enrich/case-review/" + st.Latest.ID + "/virustotal/vt-original"
	var dto narrative.ReviewVT
	rec := doJSON(t, mux, "GET", base, nil, &dto)
	if rec.Code != 200 || dto.Status != "found" || dto.Indicator != vt.Indicator || dto.Scope != "single_review_attempt_snapshot" {
		t.Fatalf("frozen %d %+v %s", rec.Code, dto, rec.Body.String())
	}
	other, err := svc.CreateCase("Other synthetic case", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{strings.Replace(base, id, other.ID, 1), strings.Replace(base, st.Latest.ID, "unknown-review", 1), base + "-missing"} {
		if code := doJSON(t, mux, "GET", path, nil, nil).Code; code != 404 {
			t.Fatalf("snapshot scope failed %s: %d", path, code)
		}
	}
	if strings.Contains(rec.Body.String(), "secret") {
		t.Fatal("readback provider prose")
	}
	st, err = svc.CaseReviewStatus(id)
	if err != nil || !st.Latest.Stale {
		t.Fatal("VT update not stale", err)
	}
	n, err := svc.store.CountProviderRequestsSince("virustotal", time.Time{})
	if err != nil || n != 0 {
		t.Fatal("VT lookup/ledger changed", n, err)
	}
}
func TestReviewBatchesVTDistinctBudgetCoverage(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	newLLMStub(t, svc, true)
	id := caseWithFindings(t, svc, mux, nil)
	seedStoredReviewVT(t, svc, id)
	// Same stored opinion is relevant in event and finding packets. It counts once.
	fs, err := svc.store.ListFindings(id)
	if err != nil {
		t.Fatal(err)
	}
	f := fs[0]
	f.ID = "vt-finding"
	f.SupportingEvents = append(f.SupportingEvents, "vt-event")
	if err = svc.store.SaveFindings([]model.Finding{f}); err != nil {
		t.Fatal(err)
	}
	p, err := svc.PlanReviewBatches(id, defaultBatchBudget())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(p)
	var fields map[string]any
	json.Unmarshal(raw, &fields)
	if fields["vt_included"] != float64(1) || fields["vt_omitted"] != float64(0) {
		t.Fatalf("distinct VT totals %s", raw)
	}
	if p.Snapshot.Coverage.VTTotal != 1 || p.PlannedEvents != 3 {
		t.Fatalf("primary counts changed %+v", p)
	}
}
func TestReviewBatchesVTActualDispatchAndBudgetRelevance(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newLLMStub(t, svc, true)
	id := caseWithFindings(t, svc, mux, nil)
	seedStoredReviewVT(t, svc, id)
	stub.answer = func(user string) (int, string) {
		if strings.Contains(user, "V1 |") {
			return 200, chatBody("hypothesis | Stored opinion flagged 2 engines. [V1]")
		}
		return 200, chatBody("observation | Recorded context. [E1]")
	}
	p, err := svc.PlanReviewBatches(id, defaultBatchBudget())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.StartReviewBatches(id, p.ID, p.PlanKey, false); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		p, err = svc.readBatchPlan(id, p.ID)
		if err != nil {
			t.Fatal(err)
		}
		if p.State != "running" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if (p.State != "completed" && p.State != "partial") || p.SynthesisState != "succeeded" {
		t.Fatalf("actual batch run %+v", p)
	}
	if !strings.Contains(stub.last().User, "commentary_only | kind=hypothesis") || !strings.Contains(stub.last().User, "V1 |") {
		t.Fatalf("synthesis lost external opinion: %s", stub.last().User)
	}
	var extra []model.Event
	for i := 0; i < 500; i++ {
		eid := fmt.Sprintf("zz%04d", i)
		extra = append(extra, model.Event{ID: eid, CaseID: id, CollectionID: "11111111-2222-4333-8444-555555555555", SourceFileID: "sf-1", DedupHash: eid, EventType: "process_start"})
	}
	if err = svc.store.SaveEvents(extra); err != nil {
		t.Fatal(err)
	}
	b := defaultBatchBudget()
	b.Requests = 1
	b.Synthesis = false
	limited, err := svc.PlanReviewBatches(id, b)
	if err != nil {
		t.Fatal(err)
	}
	if limited.TotalBatches <= 8 || limited.EnabledBatches != 1 || limited.VTIncluded != 1 {
		t.Fatalf("linked VT deferred beyond budget %+v", limited)
	}
}
func TestReviewBatchesVTCancelAndDeletionOwnership(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	id := caseWithFindings(t, svc, mux, nil)
	vt := seedStoredReviewVT(t, svc, id)
	c := &batchBlockingChatter{entered: make(chan bool, 8), release: make(chan bool), cancelled: make(chan bool, 1)}
	svc.SetLLM(c)
	svc.SetEgressLevel(id, "pseudonymized")
	p, err := svc.PlanReviewBatches(id, defaultBatchBudget())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.StartReviewBatches(id, p.ID, p.PlanKey, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { svc.CancelReviewBatches(id, p.ID) })
	select {
	case <-c.entered:
	case <-time.After(time.Second):
		t.Fatal("no request")
	}
	if err = svc.CancelReviewBatches(id, p.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case <-c.cancelled:
	case <-time.After(time.Second):
		t.Fatal("transport not cancelled")
	}
	path := "/api/cases/" + id + "/enrich/case-review/batches/" + p.ID + "/virustotal/" + vt.ID
	if rec := doJSON(t, mux, "GET", path, nil, nil); rec.Code != 200 {
		t.Fatalf("cancel lost frozen citation %d", rec.Code)
	}
	if err = svc.DeleteCase(id); err != nil {
		t.Fatal(err)
	}
	if rec := doJSON(t, mux, "GET", path, nil, nil); rec.Code != 404 {
		t.Fatalf("deleted citation retained %d", rec.Code)
	}
	members, err := svc.store.BatchMembers(id, p.ID, "enrichment", 0, 60)
	if err != nil || len(members) != 0 {
		t.Fatal("VT manifest ownership", members, err)
	}
}
func TestReviewBatchesVTContextFreezeAndSynthesis(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	newLLMStub(t, svc, true)
	id := caseWithFindings(t, svc, mux, nil)
	vt := seedStoredReviewVT(t, svc, id)
	p, err := svc.PlanReviewBatches(id, defaultBatchBudget())
	if err != nil {
		t.Fatal(err)
	}
	in, err := svc.batchInput(id, p.ID, "event", 0, 60, p.Snapshot.Names)
	if err != nil {
		t.Fatal(err)
	}
	pr, err := narrative.PrepareReview(in)
	if err != nil || pr.Coverage.VTIncluded != 1 {
		t.Fatalf("packet VT %+v %v", pr, err)
	}
	packet, prepared, omitted, err := svc.prepareBatchSynthesis(p, []ReviewBatchPacket{{Seq: 0, Kind: "event", State: "succeeded", Sentences: []narrative.Sentence{{Kind: "hypothesis", Text: "Stored opinion.", Cites: []narrative.Cite{{Kind: "enrichment", ID: vt.ID}}}}}})
	if err != nil || omitted != 0 || prepared.Coverage.VTIncluded != 1 || !strings.Contains(packet.Payload.User, "kind=hypothesis") || !strings.Contains(packet.Payload.User, "E1 |") {
		t.Fatalf("synthesis omitted=%d err=%v packet=%+v", omitted, err, packet)
	}
	vt.Status = "error"
	svc.store.UpsertEnrichment(vt)
	if _, err = svc.StartReviewBatches(id, p.ID, p.PlanKey, true); err == nil {
		t.Fatal("stale VT plan admitted")
	}
	var dto narrative.ReviewVT
	rec := doJSON(t, mux, "GET", "/api/cases/"+id+"/enrich/case-review/batches/"+p.ID+"/virustotal/"+vt.ID, nil, &dto)
	if rec.Code != 200 || dto.Status != "found" || dto.Scope != "batch_run_snapshot" {
		t.Fatalf("batch readback %d %+v", rec.Code, dto)
	}
	fp, _, err := svc.store.LegacyReviewFingerprint(context.Background(), id)
	full, err2 := svc.reviewInput(id)
	if err != nil || err2 != nil || fp != narrative.ReviewFingerprint(full) {
		t.Fatal("single streaming parity", err, err2)
	}
}
