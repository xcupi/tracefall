package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"tracefall/internal/narrative"
)

// outcomeObservationContext lets revocation run after an Err observation but
// before admission, if admission has not already serialized that observation.
type outcomeObservationContext struct {
	context.Context
	observe func()
}

func (c *outcomeObservationContext) Err() error {
	err := c.Context.Err()
	if c.observe != nil {
		observe := c.observe
		c.observe = nil
		observe()
	}
	return err
}

func TestReviewBatchesPolicyRevocationSerializesOutcomeObservation(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	c := createTestCase(t, mux, "Synthetic outcome admission")
	if _, err := svc.SetEgressLevel(c.ID, "pseudonymized"); err != nil {
		t.Fatal(err)
	}
	plan := ReviewBatchPlan{ID: "admission-run", CaseID: c.ID, State: "running"}
	if err := svc.store.SaveBatchRun(c.ID, plan.ID, "running", plan); err != nil {
		t.Fatal(err)
	}
	packet := ReviewBatchPacket{Seq: 0, Kind: "event", State: "sending", AttemptedAt: "recorded"}
	if err := svc.store.SaveBatchPacket(c.ID, plan.ID, 0, "sending", packet); err != nil {
		t.Fatal(err)
	}
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.batches.runs[c.ID] = &batchActive{id: plan.ID, external: true, cancel: cancel}
	unserialized := false
	ctx := &outcomeObservationContext{Context: base, observe: func() {
		// The old path permits real policy revocation here while its observed
		// Err remains nil and the durable run remains running.
		if svc.batches.mu.TryLock() {
			svc.batches.mu.Unlock()
			unserialized = true
			if _, err := svc.SetEgressLevel(c.ID, "none"); err != nil {
				t.Fatal(err)
			}
		}
	}}
	packet.State, packet.RawAnswer = "succeeded", "synthetic bounded raw answer"
	packet.Sentences = []narrative.Sentence{{Text: "An observation is recorded."}}
	ok, err := svc.persistBatchOutcome(ctx, plan, &packet)
	if err != nil || !ok {
		t.Fatalf("persist outcome: %t %v", ok, err)
	}
	rows, err := svc.store.BatchPackets(c.ID, plan.ID, -1, 1)
	if err != nil {
		t.Fatal(err)
	}
	var saved ReviewBatchPacket
	if err := json.Unmarshal(rows[0], &saved); err != nil {
		t.Fatal(err)
	}
	if unserialized {
		t.Fatalf("revocation interleaved after Err observation: context=%v durable_packet=%s", base.Err(), saved.State)
	}
	// Admission won before revocation. A later revocation must remain prompt,
	// not wait for a network call or deadlock on an unreleased admission lock.
	if _, err := svc.SetEgressLevel(c.ID, "none"); err != nil {
		t.Fatal(err)
	}
	if base.Err() != context.Canceled || saved.State != "succeeded" {
		t.Fatalf("admission/revocation order: %v %+v", base.Err(), saved)
	}
}

func TestReviewBatchesDeadlineAtOutcomeAdmissionWithholdsCommentary(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	c := createTestCase(t, mux, "Synthetic expired admission")
	plan := ReviewBatchPlan{ID: "deadline-run", CaseID: c.ID, State: "running"}
	if err := svc.store.SaveBatchRun(c.ID, plan.ID, "running", plan); err != nil {
		t.Fatal(err)
	}
	packet := ReviewBatchPacket{Seq: 0, Kind: "event", State: "sending", AttemptedAt: "recorded"}
	if err := svc.store.SaveBatchPacket(c.ID, plan.ID, 0, "sending", packet); err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	packet.State, packet.RawAnswer = "succeeded", "bounded synthetic answer"
	packet.Sentences = []narrative.Sentence{{Text: "An observation is recorded."}}
	ok, err := svc.persistBatchOutcome(ctx, plan, &packet)
	if err != nil || !ok {
		t.Fatalf("persistence: %t %v", ok, err)
	}
	rows, err := svc.store.BatchPackets(c.ID, plan.ID, -1, 1)
	if err != nil {
		t.Fatal(err)
	}
	var saved ReviewBatchPacket
	if err := json.Unmarshal(rows[0], &saved); err != nil {
		t.Fatal(err)
	}
	if saved.State != "failed" || !strings.Contains(saved.Error, "overall time budget exhausted") || len(saved.Sentences) != 0 || saved.RawAnswer != packet.RawAnswer || saved.OutputBytesRetained != len(saved.RawAnswer) {
		t.Fatalf("expired admission earned success/cancel or lost bounded raw answer: %+v", saved)
	}
	progress, err := svc.store.BatchProgress(c.ID, plan.ID)
	if err != nil || progress.Succeeded != 0 || progress.Failed != 1 || progress.DistinctSuccessfulEvents != 0 {
		t.Fatalf("deadline coverage: %+v %v", progress, err)
	}
}

func TestReviewBatchesDeadlineAtFinalBoundaryIsPartial(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	c := createTestCase(t, mux, "Synthetic final deadline")
	p := ReviewBatchPlan{ID: "final-deadline", CaseID: c.ID, State: "running", Budget: defaultBatchBudget()}
	if err := svc.store.SaveBatchRun(c.ID, p.ID, "running", p); err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	// All packet work is over; the optional synthesis boundary sees the deadline.
	svc.runReviewBatches(ctx, p, nil, nil, nil)
	saved, err := svc.readBatchPlan(c.ID, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if saved.State != "partial" || !strings.Contains(saved.Reason, "overall time budget exhausted") {
		t.Fatalf("final deadline mislabeled: %+v", saved)
	}
}

func TestReviewBatchesLateSuccessBecomesCancelledAndRetainsRawAnswer(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	c := createTestCase(t, mux, "Synthetic late cancellation")
	plan := ReviewBatchPlan{ID: "run01", CaseID: c.ID, State: "cancelled"}
	if err := svc.store.SaveBatchRun(c.ID, plan.ID, "cancelled", plan); err != nil {
		t.Fatal(err)
	}
	packet := ReviewBatchPacket{Seq: 0, Kind: "event", State: "sending", AttemptedAt: "recorded"}
	if err := svc.store.SaveBatchPacket(c.ID, plan.ID, 0, "sending", packet); err != nil {
		t.Fatal(err)
	}
	// The context is cancelled after validation but before the success CAS.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	packet.State = "succeeded"
	packet.RawAnswer = "late synthetic answer"
	packet.OutputBytesRetained = len(packet.RawAnswer)
	ok, err := svc.persistBatchOutcome(ctx, plan, &packet)
	if err != nil || !ok {
		t.Fatalf("cancelled late result not retained: %t %v", ok, err)
	}
	rows, err := svc.store.BatchPackets(c.ID, plan.ID, -1, 1)
	if err != nil {
		t.Fatal(err)
	}
	var saved ReviewBatchPacket
	if err = json.Unmarshal(rows[0], &saved); err != nil {
		t.Fatal(err)
	}
	if saved.State != "cancelled" || saved.RawAnswer != "late synthetic answer" || len(saved.Sentences) != 0 {
		t.Fatalf("late result revived success or lost raw answer: %+v", saved)
	}
}
