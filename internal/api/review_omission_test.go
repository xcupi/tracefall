package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"tracefall/internal/model"
	"tracefall/internal/narrative"
)

func TestReviewCoverageIncompleteOptionalProse(t *testing.T) {
	zero, one := 0, 1
	for _, tt := range []struct {
		name string
		cv   narrative.ReviewCoverage
		want bool
	}{
		{"historical unknown", narrative.ReviewCoverage{}, false},
		{"recorded zero", narrative.ReviewCoverage{ProseValuesOmitted: &zero}, false},
		{"prose only", narrative.ReviewCoverage{ProseValuesOmitted: &one}, true},
		{"command only", narrative.ReviewCoverage{CommandLinesOmitted: 1}, true},
		{"events", narrative.ReviewCoverage{EventsOmitted: 1}, true},
		{"findings", narrative.ReviewCoverage{FindingsOmitted: 1}, true},
		{"correlations", narrative.ReviewCoverage{CorrelationsOmitted: 1}, true},
		{"missing references", narrative.ReviewCoverage{MissingSupportingRefs: 1}, true},
		{"bounded references", narrative.ReviewCoverage{SupportingRefsOmitted: 1}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := reviewCoverageIncomplete(tt.cv); got != tt.want {
				t.Fatalf("incomplete=%v want %v", got, tt.want)
			}
		})
	}
}

func TestReviewBatchesSynthesisProseCoverage(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	id := caseWithFindings(t, svc, mux, nil)
	newLLMStub(t, svc, true)
	p, err := svc.PlanReviewBatches(id, defaultBatchBudget())
	if err != nil {
		t.Fatal(err)
	}
	events, err := svc.store.ListEvents(id)
	if err != nil {
		t.Fatal(err)
	}
	// Historical retained commentary is re-prepared, not trusted as safe input.
	commentary := []ReviewBatchPacket{{Seq: 0, Kind: "event", State: "succeeded", Sentences: []narrative.Sentence{{Text: "curl https://api.example.test/download?private=first` DummyQuery@vault.example.test#DummyFragment", Cites: []narrative.Cite{{Kind: "event", ID: events[0].ID}}}}}}
	packet, prepared, omitted, err := svc.prepareBatchSynthesis(p, commentary)
	if err != nil {
		t.Fatal(err)
	}
	cv := packet.Coverage
	if omitted != 0 || cv.CommandLinesOmitted != 0 || cv.ProseValuesOmitted == nil || *cv.ProseValuesOmitted != 1 || !reviewCoverageIncomplete(cv) {
		t.Fatalf("final synthesis coverage not used: %+v omitted=%d", cv, omitted)
	}
	if !strings.Contains(prepared.User, "prose_values_omitted=1") || strings.Contains(prepared.User, "prose_values_omitted=0") || strings.Contains(prepared.User, "DummyQuery") {
		t.Fatal("synthesis payload totals/privacy disagree with final coverage")
	}
}

func TestReviewBatchesProseOmissionIncomplete(t *testing.T) {
	for _, unsafe := range []bool{false, true} {
		name := "recorded_zero"
		if unsafe {
			name = "prose_only"
		}
		t.Run(name, func(t *testing.T) {
			mux, svc := newTestRouterWithService(t)
			id := caseWithFindings(t, svc, mux, func(fs *[]model.Finding) {
				*fs = (*fs)[:1]
				(*fs)[0].Title = "Recorded observation"
				(*fs)[0].Description = "Recorded context"
				if unsafe {
					(*fs)[0].Description = "curl https://api.example.test/download?private=first` DummyQuery@vault.example.test#DummyFragment"
				}
			})
			stub := newLLMStub(t, svc, true)
			p, err := svc.PlanReviewBatches(id, defaultBatchBudget())
			if err != nil {
				t.Fatal(err)
			}
			if stub.count() != 0 {
				t.Fatal("planning sent a provider request")
			}
			raws, err := svc.store.BatchPackets(id, p.ID, -1, 8)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, raw := range raws {
				var packet ReviewBatchPacket
				if err := json.Unmarshal(raw, &packet); err != nil {
					t.Fatal(err)
				}
				if packet.Kind != "finding" {
					continue
				}
				found = true
				want := 0
				if unsafe {
					want = 1
				}
				if packet.Coverage.CommandLinesOmitted != 0 || packet.Coverage.ProseValuesOmitted == nil || *packet.Coverage.ProseValuesOmitted != want {
					t.Fatalf("prose-only fixture coverage: %+v", packet.Coverage)
				}
			}
			if !found {
				t.Fatal("no finding packet")
			}
			if p.InputIncomplete != unsafe {
				t.Fatalf("input_incomplete=%v want %v for prose-only privacy coverage", p.InputIncomplete, unsafe)
			}
			// A stored plan flag alone must not hide actual packet coverage at dispatch.
			p.InputIncomplete = false
			if ok, err := svc.store.UpdateBatchRun(id, p.ID, "planned", "planned", p); err != nil || !ok {
				t.Fatalf("reset fixture flag: %v %v", ok, err)
			}
			stub.answer = func(string) (int, string) { return 200, chatBody("An observation is recorded. [E1]") }
			if _, err := svc.StartReviewBatches(id, p.ID, p.PlanKey, false); err != nil {
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
			if p.InputIncomplete != unsafe {
				t.Fatalf("runner input_incomplete=%v want %v from actual coverage (state %s)", p.InputIncomplete, unsafe, p.State)
			}
			if unsafe && p.State != "partial" {
				t.Fatalf("omission is partial, not failed or complete: %s", p.State)
			}
			// Terminal persistence precedes the worker's deferred cleanup/audit.
			for time.Now().Before(deadline) {
				svc.batches.mu.Lock()
				active := svc.batches.runs[id] != nil
				svc.batches.mu.Unlock()
				if !active {
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
			t.Fatal("batch worker did not finish cleanup")
		})
	}
}
