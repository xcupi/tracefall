package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/narrative"
)

func TestReviewBatchesResponseTruncationRetainsValidBoundedUTF8(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	id := caseWithFindings(t, svc, mux, nil)
	stub := newLLMStub(t, svc, true)
	stub.answer = func(string) (int, string) { return 200, chatBody("a" + strings.Repeat("é", 600)) }
	b := defaultBatchBudget()
	b.OutputBytes = 1024
	b.Synthesis = false
	p, err := svc.PlanReviewBatches(id, b)
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
	records, _ := svc.store.BatchPackets(id, p.ID, -1, 8)
	var packet ReviewBatchPacket
	json.Unmarshal(records[0], &packet)
	if len(packet.RawAnswer) > b.OutputBytes || len(packet.RawAnswer) != packet.OutputBytesRetained {
		t.Fatalf("UTF8 replacement expanded retained bytes past approved cap: bytes=%d admitted=%d cap=%d", len(packet.RawAnswer), packet.OutputBytesRetained, b.OutputBytes)
	}
}

func TestReviewBatchesInputBudgetReservationAndInvalidHardBounds(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	id := caseWithFindings(t, svc, mux, nil)
	stub := newLLMStub(t, svc, true)
	stub.answer = func(string) (int, string) { return 200, chatBody("An observation is recorded. [E1]") }
	base := "/api/cases/" + id + "/enrich/case-review/batches"
	for _, change := range []func(*BatchBudget){func(b *BatchBudget) { b.Requests = 9 }, func(b *BatchBudget) { b.InputBytes = 4095 }, func(b *BatchBudget) { b.OutputBytes = 131073 }, func(b *BatchBudget) { b.Concurrency = 2 }, func(b *BatchBudget) { b.Retries = 1 }, func(b *BatchBudget) { b.PerRequestSeconds = 121 }, func(b *BatchBudget) { b.OverallSeconds = 901 }} {
		b := defaultBatchBudget()
		change(&b)
		rec := doJSON(t, mux, "POST", base+"/plan", map[string]any{"budget": b}, nil)
		if rec.Code != 400 {
			t.Fatalf("invalid budget accepted: %+v -> %d", b, rec.Code)
		}
	}
	b := defaultBatchBudget()
	b.InputBytes = 4096
	p, err := svc.PlanReviewBatches(id, b)
	if err != nil {
		t.Fatal(err)
	}
	if p.EnabledBatches != 0 {
		t.Fatalf("synthesis input was not reserved inside budget: %+v", p)
	}
	rec := doJSON(t, mux, "POST", base+"/"+p.ID+"/start", map[string]any{"plan_key": p.PlanKey}, nil)
	if rec.Code != 422 || stub.count() != 0 {
		t.Fatalf("no-enabled-packet start sent or not refused: %d requests=%d", rec.Code, stub.count())
	}
	b.Synthesis = false
	p, err = svc.PlanReviewBatches(id, b)
	if err != nil {
		t.Fatal(err)
	}
	if p.EnabledBatches < 1 || p.EnabledBatches >= p.TotalBatches || p.InitialInputBytes > b.InputBytes {
		t.Fatalf("input allowance admission/coverage: %+v", p)
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
	if p.State != "partial" || progress.InputBytesAdmitted > b.InputBytes || progress.RequestsAttempted != p.EnabledBatches {
		t.Fatalf("input budget exhausted but not partial/bounded: %+v state=%s", progress, p.State)
	}
}

func TestReviewBatchesShapeOnlyNamesAreLearnedAcrossPackets(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	id := caseWithFindings(t, svc, mux, func(fs *[]model.Finding) { *fs = nil })
	stub := newLLMStub(t, svc, true)
	e := model.Event{ID: "000-profile", CaseID: id, CollectionID: "11111111-2222-4333-8444-555555555555", SourceFileID: "sf-1", DedupHash: "000-profile", EventType: "process_start", FilePath: `C:\Users\hiddenperson\AppData\tool.exe`}
	if err := svc.store.SaveEvents([]model.Event{e}); err != nil {
		t.Fatal(err)
	}
	if err := svc.store.SaveFindings([]model.Finding{{ID: "claim01", CaseID: id, RuleID: "synthetic", Title: "Recorded account", Description: "hiddenperson has a recorded lead."}}); err != nil {
		t.Fatal(err)
	}
	p, err := svc.PlanReviewBatches(id, defaultBatchBudget())
	if err != nil {
		t.Fatal(err)
	}
	records, _ := svc.store.BatchPackets(id, p.ID, -1, 8)
	for _, raw := range records {
		var packet ReviewBatchPacket
		json.Unmarshal(raw, &packet)
		if strings.Contains(strings.ToLower(packet.Payload.User), "hiddenperson") {
			t.Fatalf("profile-only identity leaked into another packet: %s", packet.Kind)
		}
	}
	if stub.count() != 0 {
		t.Fatal("planning sent case data")
	}
}

func TestReviewBatchesOverallBudgetExpiryIsPartialNotSuccess(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	id := caseWithFindings(t, svc, mux, nil)
	c := &batchBlockingChatter{entered: make(chan bool, 8), release: make(chan bool)}
	svc.SetLLM(c)
	svc.SetEgressLevel(id, "pseudonymized")
	b := defaultBatchBudget()
	b.OverallSeconds = 1
	b.PerRequestSeconds = 1
	p, err := svc.PlanReviewBatches(id, b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.StartReviewBatches(id, p.ID, p.PlanKey, true); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(4 * time.Second)
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
	if p.State != "partial" {
		t.Fatalf("time budget exhaustion must be partial, got %s", p.State)
	}
	progress, err := svc.store.BatchProgress(id, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if progress.RequestsAttempted != 1 || progress.DistinctSuccessfulEvents != 0 {
		t.Fatalf("deadline future sends/coverage: %+v", progress)
	}
}

func TestReviewBatchesLegacyPollingDoesNotReallocateSnapshot(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	id := caseWithFindings(t, svc, mux, nil)
	var events []model.Event
	for i := 0; i < 200; i++ {
		events = append(events, model.Event{ID: fmt.Sprintf("poll-%03d", i), CaseID: id, CollectionID: "11111111-2222-4333-8444-555555555555", SourceFileID: "sf-1", DedupHash: fmt.Sprintf("poll-%d", i), EventType: "process_start"})
	}
	if err := svc.store.SaveEvents(events); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CaseReviewStatus(id); err != nil {
		t.Fatal(err)
	}
	allocations := testing.AllocsPerRun(3, func() {
		if _, err := svc.CaseReviewStatus(id); err != nil {
			t.Fatal(err)
		}
	})
	if allocations > 1500 {
		t.Fatalf("unchanged legacy polling still reconstructs case-sized metadata: %.0f allocations", allocations)
	}
}

func TestReviewBatchesOutputAllowanceIncludesValidatedOutput(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newLLMStub(t, svc, true)
	id := caseWithFindings(t, svc, mux, func(fs *[]model.Finding) { *fs = nil })
	stub.answer = func(string) (int, string) {
		return 200, chatBody(strings.Repeat("An observation is recorded. [E1]\n", 25))
	}
	b := defaultBatchBudget()
	b.OutputBytes = 1024
	b.Synthesis = false
	p, err := svc.PlanReviewBatches(id, b)
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
	rows, _ := svc.store.BatchPackets(id, p.ID, -1, 8)
	var packet ReviewBatchPacket
	json.Unmarshal(rows[0], &packet)
	validated, _ := json.Marshal(packet.Sentences)
	if len(packet.RawAnswer)+len(validated) > b.OutputBytes || packet.State != "failed" {
		t.Fatalf("local output cap bypassed by validated output: raw=%d validated=%d state=%s", len(packet.RawAnswer), len(validated), packet.State)
	}
}

func TestReviewBatchesGatesStalenessAndSecrets(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newLLMStub(t, svc, false)
	id := caseWithFindings(t, svc, mux, nil)
	p, err := svc.PlanReviewBatches(id, defaultBatchBudget())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.StartReviewBatches(id, p.ID, p.PlanKey, true); !errors.Is(err, ErrNarrativeEgress) {
		t.Fatalf("no-egress: %v", err)
	}
	svc.SetEgressLevel(id, "pseudonymized")
	p, err = svc.PlanReviewBatches(id, defaultBatchBudget())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.StartReviewBatches(id, p.ID, p.PlanKey, false); !errors.Is(err, ErrNarrativeNeedsAck) {
		t.Fatalf("no-ack: %v", err)
	}
	if _, err = svc.StartReviewBatches(id, p.ID, "wrong", true); !errors.Is(err, errReviewPreviewChanged) {
		t.Fatalf("wrong key: %v", err)
	}
	rows, err := svc.store.BatchPackets(id, p.ID, -1, 8)
	if err != nil {
		t.Fatal(err)
	}
	raw := string(rows[0])
	for _, secret := range []string{"Hunter2xyz", "CORP\\\\alice", "corp.example", "10.1.2.3"} {
		if strings.Contains(raw, secret) {
			t.Fatalf("identifying/credential value in sanitized packet metadata: %s", secret)
		}
	}
	e := model.Event{ID: "new-input", CaseID: id, CollectionID: "11111111-2222-4333-8444-555555555555", SourceFileID: "sf-1", DedupHash: "new-input", EventType: "process_start"}
	if err = svc.store.SaveEvents([]model.Event{e}); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.StartReviewBatches(id, p.ID, p.PlanKey, true); !errors.Is(err, errReviewPreviewChanged) {
		t.Fatalf("changed snapshot: %v", err)
	}
	e.ID = "bad-enum"
	e.DedupHash = "bad-enum"
	e.EventType = "cookie=short-private-value"
	if err = svc.store.SaveEvents([]model.Event{e}); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.PlanReviewBatches(id, defaultBatchBudget()); !errors.Is(err, narrative.ErrLeak) {
		t.Fatalf("known prohibited classification did not fail closed: %v", err)
	}
	if stub.count() != 0 {
		t.Fatalf("negative control sent %d requests", stub.count())
	}
}
func TestReviewBatchesFailureStopsFutureAndDoesNotAlterFindings(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newLLMStub(t, svc, true)
	stub.answer = func(string) (int, string) { return 500, `{"error":"synthetic"}` }
	id := caseWithFindings(t, svc, mux, nil)
	before, _ := svc.store.ListFindings(id)
	beforeJSON, _ := json.Marshal(before)
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
	progress, err := svc.store.BatchProgress(id, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stub.count() != 1 || progress.Failed != 1 || progress.DistinctSuccessfulEvents != 0 || progress.PrimaryReviewedEvents != 0 || p.State != "partial" {
		t.Fatalf("failure coverage/retries: requests=%d progress=%+v state=%s", stub.count(), progress, p.State)
	}
	after, _ := svc.store.ListFindings(id)
	afterJSON, _ := json.Marshal(after)
	if string(beforeJSON) != string(afterJSON) {
		t.Fatal("commentary changed core findings")
	}
}
func TestReviewBatchesLargeSnapshotHasBoundedHeap(t *testing.T) {
	if testing.Short() {
		t.Skip("large synthetic parsed snapshot")
	}
	mux, svc := newTestRouterWithService(t)
	newLLMStub(t, svc, true)
	id := caseWithFindings(t, svc, mux, func(fs *[]model.Finding) { *fs = nil })
	const n = 12000
	padding := strings.Repeat("x", 8192)
	for offset := 0; offset < n; offset += 100 {
		events := make([]model.Event, 0, 100)
		for i := offset; i < offset+100; i++ {
			events = append(events, model.Event{ID: fmt.Sprintf("large-%08d", n-i), CaseID: id, CollectionID: "11111111-2222-4333-8444-555555555555", SourceFileID: "sf-1", DedupHash: fmt.Sprintf("large-%d", i), EventType: "process_start", Extra: map[string]string{"not_allowlisted_body": padding}})
		}
		if err := svc.store.SaveEvents(events); err != nil {
			t.Fatal(err)
		}
	}
	runtime.GC()
	var baseline runtime.MemStats
	runtime.ReadMemStats(&baseline)
	var peak atomic.Uint64
	peak.Store(baseline.Alloc)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan bool)
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				var ms runtime.MemStats
				runtime.ReadMemStats(&ms)
				if ms.Alloc > peak.Load() {
					peak.Store(ms.Alloc)
				}
			}
		}
	}()
	started := time.Now()
	p, err := svc.PlanReviewBatches(id, defaultBatchBudget())
	cancel()
	<-done
	if err != nil {
		t.Fatal(err)
	}
	if p.EligibleEvents != n+2 || p.PlannedEvents != 420 || p.TotalBatches != 201 {
		t.Fatalf("large manifest lost data or budgets: %+v", p)
	}
	if peak.Load() > baseline.Alloc+96<<20 {
		t.Fatalf("snapshot retained case-sized heap: baseline=%d peak=%d", baseline.Alloc, peak.Load())
	}
	t.Logf("events=%d frozen_json_bytes=%d initial_packets=%d total_batches=%d baseline_heap=%d peak_heap=%d elapsed=%s", p.EligibleEvents, p.Snapshot.Bytes, p.EnabledBatches, p.TotalBatches, baseline.Alloc, peak.Load(), time.Since(started))
	// A second consistent fingerprint is identical despite reverse insertion,
	// tied timestamps and undated records. No timeline order is fabricated.
	got, err := svc.store.ReviewSnapshotFingerprint(context.Background(), id)
	if err != nil || got != p.SourceFingerprint {
		t.Fatalf("deterministic frozen fingerprint: %s %v", got, err)
	}
}
