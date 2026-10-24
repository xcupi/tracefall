package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	"tracefall/internal/enrich/llm"
	"tracefall/internal/model"
	"tracefall/internal/narrative"
)

func TestReviewBatchesDeletionCancelsAndErasesActiveManifest(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	id := caseWithFindings(t, svc, mux, nil)
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
	t.Cleanup(func() {
		svc.batches.mu.Lock()
		if run := svc.batches.runs[id]; run != nil {
			run.cancel()
		}
		svc.batches.mu.Unlock()
	})
	select {
	case <-c.entered:
	case <-time.After(time.Second):
		t.Fatal("not sending")
	}
	if err = svc.DeleteCase(id); err != nil {
		t.Fatal(err)
	}
	select {
	case <-c.cancelled:
	case <-time.After(time.Second):
		t.Fatal("deletion left active model transport uncancelled")
	}
	if _, _, err = svc.store.BatchRun(id, p.ID); err == nil {
		t.Fatal("deleted plan retained")
	}
	rows, err := svc.store.BatchMembers(id, p.ID, "event", 0, 60)
	if err != nil || len(rows) != 0 {
		t.Fatalf("deleted manifest retained: %d %v", len(rows), err)
	}
	select {
	case <-c.entered:
		t.Fatal("future packet sent after deletion")
	default:
	}
}

func TestReviewBatchesRevocationDoesNotWaitForLegacyPreparationLock(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	id := caseWithFindings(t, svc, mux, nil)
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
	select {
	case <-c.entered:
	case <-time.After(time.Second):
		t.Fatal("not sending")
	}
	svc.review.mu.Lock()
	done := make(chan error, 1)
	go func() { _, err := svc.SetEgressLevel(id, "none"); done <- err }()
	cancelled := false
	select {
	case <-c.cancelled:
		cancelled = true
	case <-time.After(time.Second):
	}
	svc.review.mu.Unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !cancelled {
		t.Fatal("active batch cancellation waited for unrelated legacy preparation mutex")
	}
}

func TestReviewBatchesPriorPlansRemainDiscoverable(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	id := caseWithFindings(t, svc, mux, nil)
	for i := 0; i < 2; i++ {
		if _, err := svc.PlanReviewBatches(id, defaultBatchBudget()); err != nil {
			t.Fatal(err)
		}
	}
	rec := doJSON(t, mux, "GET", "/api/cases/"+id+"/enrich/case-review/batches/history?offset=0&limit=1", nil, nil)
	if rec.Code != 200 {
		t.Fatalf("paged prior-plan discovery: %d %s", rec.Code, rec.Body.String())
	}
	var page struct {
		Plans   []ReviewBatchPlan `json:"plans"`
		Total   int               `json:"total"`
		HasMore bool              `json:"has_more"`
	}
	json.Unmarshal(rec.Body.Bytes(), &page)
	if len(page.Plans) != 1 || page.Total != 2 || !page.HasMore {
		t.Fatalf("wrong history pagination: %+v", page)
	}
}

func TestReviewBatchesClaimContextOmissionIsNotMissingEvidence(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	id := caseWithFindings(t, svc, mux, func(fs *[]model.Finding) { *fs = nil })
	stub := newLLMStub(t, svc, true)
	stub.answer = func(string) (int, string) { return 200, chatBody("An observation is recorded. [E1]") }
	var events []model.Event
	var ids []string
	for i := 0; i < 70; i++ {
		eid := fmt.Sprintf("context-%03d", i)
		ids = append(ids, eid)
		events = append(events, model.Event{ID: eid, CaseID: id, CollectionID: "11111111-2222-4333-8444-555555555555", SourceFileID: "sf-1", DedupHash: eid, EventType: "process_start"})
	}
	if err := svc.store.SaveEvents(events); err != nil {
		t.Fatal(err)
	}
	if err := svc.store.SaveFindings([]model.Finding{{ID: "claim01", CaseID: id, RuleID: "synthetic", Title: "Recorded observations", SupportingEvents: ids}}); err != nil {
		t.Fatal(err)
	}
	p, err := svc.PlanReviewBatches(id, defaultBatchBudget())
	if err != nil {
		t.Fatal(err)
	}
	rows, _ := svc.store.BatchPackets(id, p.ID, -1, 8)
	var claim ReviewBatchPacket
	json.Unmarshal(rows[len(rows)-1], &claim)
	if claim.Coverage.SupportingRefsOmitted != 10 || claim.Coverage.MissingSupportingRefs != 0 {
		t.Fatalf("bounded context falsely called missing evidence: %+v", claim.Coverage)
	}
	b, _ := json.Marshal(p)
	var fields map[string]any
	json.Unmarshal(b, &fields)
	if fields["input_incomplete"] != true {
		t.Fatalf("claim-context omission not surfaced in plan: %s", b)
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
	progress, err := svc.store.BatchProgress(id, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if progress.DistinctSuccessfulEvents != 72 || progress.PrimaryReviewedEvents != 72 || progress.Succeeded != 3 || p.State != "partial" {
		t.Fatalf("context repeated in claim packet double-counted or incomplete input called complete: %+v state=%s", progress, p.State)
	}
}

func TestReviewBatchesPayloadAndManifestRoutesAreCaseIsolated(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	id := caseWithFindings(t, svc, mux, nil)
	newLLMStub(t, svc, true)
	p, err := svc.PlanReviewBatches(id, defaultBatchBudget())
	if err != nil {
		t.Fatal(err)
	}
	base := "/api/cases/" + id + "/enrich/case-review/batches/" + p.ID
	rec := doJSON(t, mux, "GET", base+"/packets/0/payload", nil, nil)
	if rec.Code != 200 {
		t.Fatalf("frozen exact payload route: %d %s", rec.Code, rec.Body.String())
	}
	var readback struct {
		Payload   NarrativePayload `json:"payload"`
		Attempted bool             `json:"attempted"`
	}
	json.Unmarshal(rec.Body.Bytes(), &readback)
	hash := sha256.Sum256([]byte(readback.Payload.System + "\x00" + readback.Payload.User))
	if readback.Attempted || readback.Payload.SHA256 != fmt.Sprintf("%x", hash) {
		t.Fatalf("plan payload falsely marked sent or wrong hash: %+v", readback)
	}
	rec = doJSON(t, mux, "GET", base+"/manifest?kind=event&offset=0&limit=1", nil, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "member_id") {
		t.Fatalf("manifest route: %d %s", rec.Code, rec.Body.String())
	}
	other := createTestCase(t, mux, "another case")
	rec = doJSON(t, mux, "GET", "/api/cases/"+other.ID+"/enrich/case-review/batches/"+p.ID+"/packets/0/payload", nil, nil)
	if rec.Code != 404 {
		t.Fatalf("wrong case packet accessible: %d", rec.Code)
	}
}

func TestReviewBatchesCancelIsDurableAndCannotBeRevived(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	id := caseWithFindings(t, svc, mux, nil)
	c := &batchBlockingChatter{entered: make(chan bool, 8), release: make(chan bool)}
	svc.SetLLM(c)
	svc.SetEgressLevel(id, "pseudonymized")
	p, err := svc.PlanReviewBatches(id, defaultBatchBudget())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.StartReviewBatches(id, p.ID, p.PlanKey, true); err != nil {
		t.Fatal(err)
	}
	select {
	case <-c.entered:
	case <-time.After(time.Second):
		t.Fatal("provider not entered")
	}
	if err = svc.CancelReviewBatches(id, p.ID); err != nil {
		t.Fatal(err)
	}
	current, err := svc.readBatchPlan(id, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.State != "cancelled" {
		t.Fatalf("cancel not durable on response: %s", current.State)
	}
	ok, err := svc.store.UpdateBatchRun(id, p.ID, "running", "succeeded", p)
	if err != nil || ok {
		t.Fatalf("cancelled run revived: %v %v", ok, err)
	}
}

func TestReviewBatchesProviderReplacementInvalidatesPlan(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	id := caseWithFindings(t, svc, mux, nil)
	old := newLLMStub(t, svc, true)
	p, err := svc.PlanReviewBatches(id, defaultBatchBudget())
	if err != nil {
		t.Fatal(err)
	}
	replacement := newLLMStub(t, svc, true)
	_, err = svc.StartReviewBatches(id, p.ID, p.PlanKey, false)
	if !errors.Is(err, errReviewPreviewChanged) {
		t.Fatalf("same-metadata provider replacement accepted plan: %v", err)
	}
	if old.count()+replacement.count() != 0 {
		t.Fatal("refused provider replacement sent")
	}
}

func TestReviewBatchesLegacyStreamingFingerprintParity(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	id := caseWithFindings(t, svc, mux, nil)
	in, err := svc.reviewInput(id)
	if err != nil {
		t.Fatal(err)
	}
	want := narrative.ReviewFingerprint(in)
	got, n, err := svc.store.LegacyReviewFingerprint(context.Background(), id)
	if err != nil || got != want || n != len(in.Events) {
		t.Fatalf("streamed historical fingerprint mismatch: got %q/%d want %q/%d err=%v", got, n, want, len(in.Events), err)
	}
}

func TestReviewBatchesSynthesisKeepsPrimaryReferences(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newLLMStub(t, svc, true)
	stub.answer = func(string) (int, string) {
		return 200, chatBody("An observation is recorded. [E1]\nUnvalidated https://untrusted.invalid never enters synthesis. [E1]")
	}
	id := caseWithFindings(t, svc, mux, func(fs *[]model.Finding) { *fs = nil })
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
	if stub.count() != 2 {
		t.Fatalf("want one batch and one bounded synthesis got %d", stub.count())
	}
	rows, err := svc.store.BatchPackets(id, p.ID, -1, 8)
	if err != nil {
		t.Fatal(err)
	}
	var synthesis ReviewBatchPacket
	json.Unmarshal(rows[len(rows)-1], &synthesis)
	if synthesis.Kind != "synthesis" || synthesis.State != "succeeded" || !strings.Contains(synthesis.Payload.User, "VALIDATED COMMENTARY (not primary evidence)") || !strings.Contains(synthesis.Payload.User, "provenance=primary_observation_only") || strings.Contains(synthesis.Payload.User, "untrusted.invalid") {
		t.Fatalf("unsafe/missing synthesis: %+v", synthesis)
	}
	if len(synthesis.Sentences) != 1 || synthesis.Sentences[0].Cites[0].Kind != "event" || synthesis.Sentences[0].Cites[0].ID == "E1" {
		t.Fatalf("synthesis lost original primary citations: %+v", synthesis.Sentences)
	}
}

type batchBlockingChatter struct {
	llm.None
	entered   chan bool
	release   chan bool
	cancelled chan bool
}

func (c *batchBlockingChatter) Configured() bool            { return true }
func (c *batchBlockingChatter) Destination() (string, bool) { return "synthetic.invalid", false }
func (c *batchBlockingChatter) ModelName() string           { return "synthetic" }
func (c *batchBlockingChatter) Chat(ctx context.Context, m []llm.Message) (llm.Result, error) {
	c.entered <- true
	select {
	case <-ctx.Done():
		if c.cancelled != nil {
			c.cancelled <- true
		}
		return llm.Result{}, ctx.Err()
	case <-c.release:
		return llm.Result{Content: "An observation is recorded. [E1]"}, nil
	}
}
func TestReviewBatchesRevocationCancelsActiveRequest(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	id := caseWithFindings(t, svc, mux, nil)
	c := &batchBlockingChatter{entered: make(chan bool, 8), release: make(chan bool)}
	svc.SetLLM(c)
	if _, err := svc.SetEgressLevel(id, "pseudonymized"); err != nil {
		t.Fatal(err)
	}
	p, err := svc.PlanReviewBatches(id, defaultBatchBudget())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.StartReviewBatches(id, p.ID, p.PlanKey, true); err != nil {
		t.Fatal(err)
	}
	select {
	case <-c.entered:
	case <-time.After(time.Second):
		t.Fatal("provider not entered")
	}
	if _, err = svc.SetEgressLevel(id, "none"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
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
	if p.State != "cancelled" {
		svc.CancelReviewBatches(id, p.ID)
		t.Fatalf("policy revocation did not stop active request: %s", p.State)
	}
	select {
	case <-c.entered:
		t.Fatal("future packet sent after revocation")
	default:
	}
}

func TestReviewBatchesWholeCatalogFailureOutsideSample(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newLLMStub(t, svc, true)
	id := caseWithFindings(t, svc, mux, nil)
	var sources []model.SourceFile
	for i := 0; i < 70; i++ {
		status := model.SourceFileImported
		if i == 69 {
			status = model.SourceFileFailed
		}
		sources = append(sources, model.SourceFile{ID: fmt.Sprintf("catalog-%03d", i), CaseID: id, CollectionID: "catalog-col", ImportStatus: status, Supported: true, SHA256: fmt.Sprintf("source-sha-%d", i), Path: fmt.Sprintf("artifact-%d", i)})
	}
	if err := svc.store.CreateCollectionWithSourceFiles(model.Collection{ID: "catalog-col", CaseID: id}, sources); err != nil {
		t.Fatal(err)
	}
	p, err := svc.PlanReviewBatches(id, defaultBatchBudget())
	if err != nil {
		t.Fatal(err)
	}
	if p.Snapshot.Sources != 71 || p.Snapshot.Coverage.SourcesFailed != 1 || p.Snapshot.Coverage.SourcesImported != 70 {
		t.Fatalf("whole source catalog not accounted: %+v", p.Snapshot)
	}
	packets, err := svc.store.BatchPackets(id, p.ID, -1, 8)
	if err != nil {
		t.Fatal(err)
	}
	var packet ReviewBatchPacket
	json.Unmarshal(packets[0], &packet)
	if !strings.Contains(packet.Payload.User, "catalog_sources_failed=1") {
		t.Fatal("parse failure beyond source sample hidden from model")
	}
	if stub.count() != 0 {
		t.Fatal("planning sent")
	}
}

func TestReviewBatchesDistinctCoverageAndBudgetPartial(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newLLMStub(t, svc, true)
	stub.answer = func(string) (int, string) { return 200, chatBody("An observation is recorded. [E1]") }
	id := caseWithFindings(t, svc, mux, func(fs *[]model.Finding) { *fs = nil })
	var events []model.Event
	for i := 0; i < 181; i++ {
		events = append(events, model.Event{ID: fmt.Sprintf("budget-%04d", i), CaseID: id, CollectionID: "11111111-2222-4333-8444-555555555555", SourceFileID: "sf-1", DedupHash: fmt.Sprintf("budget-%d", i), EventType: "process_start"})
	}
	if err := svc.store.SaveEvents(events); err != nil {
		t.Fatal(err)
	}
	b := defaultBatchBudget()
	b.Synthesis = false
	b.Requests = 2
	p, err := svc.PlanReviewBatches(id, b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.StartReviewBatches(id, p.ID, p.PlanKey, false); err != nil {
		t.Fatal(err)
	}
	base := "/api/cases/" + id + "/enrich/case-review/batches/" + p.ID
	var view map[string]any
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		doJSON(t, mux, "GET", base, nil, &view)
		if view["state"] != "running" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if view["state"] != "partial" {
		t.Fatalf("budget-limited review not partial: %v", view)
	}
	progress, ok := view["progress"].(map[string]any)
	if !ok {
		t.Fatalf("missing manifest coverage: %v", view)
	}
	if progress["succeeded"] != float64(2) || progress["primary_reviewed_events"] != float64(120) || progress["distinct_successful_events"] != float64(120) || progress["unreviewed"] != float64(p.TotalBatches-2) {
		t.Fatalf("incorrect manifest coverage: %v", progress)
	}
	if stub.count() != 2 {
		t.Fatalf("request budget exceeded: %d", stub.count())
	}
}

func TestReviewBatchesStartPersistsExactAttempt(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newLLMStub(t, svc, true)
	stub.answer = func(string) (int, string) { return 200, chatBody("An observation is recorded. [E1]") }
	id := caseWithFindings(t, svc, mux, func(fs *[]model.Finding) { *fs = nil })
	budget := defaultBatchBudget()
	budget.Synthesis = false
	var p ReviewBatchPlan
	base := "/api/cases/" + id + "/enrich/case-review/batches"
	rec := doJSON(t, mux, "POST", base+"/plan", map[string]any{"budget": budget}, &p)
	if rec.Code != 201 {
		t.Fatal(rec.Body.String())
	}
	rec = doJSON(t, mux, "POST", base+"/"+p.ID+"/start", map[string]any{"plan_key": p.PlanKey}, nil)
	if rec.Code != 202 {
		t.Fatalf("acknowledged batch start: want 202 got %d %s", rec.Code, rec.Body.String())
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		doJSON(t, mux, "GET", base+"/"+p.ID, nil, &p)
		if p.State != "running" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if p.State != "partial" || p.Progress.Succeeded != 1 {
		t.Fatalf("successful bounded request must retain parse-gap partial status: %+v", p)
	}
	if stub.count() != 1 {
		t.Fatalf("want one bounded call got %d", stub.count())
	}
	rows, err := svc.store.BatchPackets(id, p.ID, -1, 100)
	if err != nil || len(rows) != 1 {
		t.Fatalf("packets %v %v", rows, err)
	}
	var packet ReviewBatchPacket
	if err := json.Unmarshal(rows[0], &packet); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(stub.last().System + "\x00" + stub.last().User))
	if packet.State != "succeeded" || packet.Payload.SHA256 != fmt.Sprintf("%x", digest) || packet.Payload.User != stub.last().User || packet.AttemptedAt == "" || len(packet.Sentences) != 1 {
		t.Fatalf("attempt not exact/persisted: %+v", packet)
	}
}

func TestReviewBatchesPlanAccountsBeyondLegacyCap(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newLLMStub(t, svc, true)
	id := caseWithFindings(t, svc, mux, func(fs *[]model.Finding) { *fs = nil })
	var events []model.Event
	for i := 0; i < 181; i++ {
		events = append(events, model.Event{ID: fmt.Sprintf("batch-event-%04d", i), CaseID: id, CollectionID: "11111111-2222-4333-8444-555555555555", SourceFileID: "sf-1", DedupHash: fmt.Sprintf("batch-hash-%d", i), EventType: "process_start", Host: "host01", User: "alice", ProcessName: "tool.exe"})
	}
	if err := svc.store.SaveEvents(events); err != nil {
		t.Fatal(err)
	}
	var plan map[string]any
	rec := doJSON(t, mux, "POST", "/api/cases/"+id+"/enrich/case-review/batches/plan", map[string]any{}, &plan)
	if rec.Code != 201 {
		t.Fatalf("local batch plan: want 201 got %d %s", rec.Code, rec.Body.String())
	}
	if plan["eligible_events"].(float64) <= 120 {
		t.Fatalf("manifest lost unflagged observations: %v", plan)
	}
	if plan["total_batches"].(float64) < 3 {
		t.Fatalf("not a multipacket manifest: %v", plan)
	}
	if stub.count() != 0 {
		t.Fatal("planning sent case data")
	}
}
