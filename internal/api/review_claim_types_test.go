package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"tracefall/internal/enrich/llm"

	"tracefall/internal/model"
	"tracefall/internal/narrative"
)

type claimPartialChatter struct {
	mode    string
	calls   atomic.Int32
	entered chan struct{}
}

func (p *claimPartialChatter) Configured() bool            { return true }
func (p *claimPartialChatter) Destination() (string, bool) { return "synthetic-local", true }
func (p *claimPartialChatter) ModelName() string           { return "synthetic-typed" }
func (p *claimPartialChatter) Notice() string              { return "synthetic only" }
func (p *claimPartialChatter) Chat(ctx context.Context, _ []llm.Message) (llm.Result, error) {
	if p.calls.Add(1) == 1 {
		return llm.Result{Content: "possible_conflict | A possible conflict warrants review. [E1]"}, nil
	}
	close(p.entered)
	if p.mode == "failed" {
		return llm.Result{}, errors.New("synthetic failure")
	}
	<-ctx.Done()
	return llm.Result{}, ctx.Err()
}

func TestReviewBatchesClaimKindsSurvivePartialOutcomes(t *testing.T) {
	for _, mode := range []string{"cancelled", "failed", "budget"} {
		t.Run(mode, func(t *testing.T) {
			mux, svc := newTestRouterWithService(t)
			provider := &claimPartialChatter{mode: mode, entered: make(chan struct{})}
			svc.SetLLM(provider)
			id := caseWithFindings(t, svc, mux, func(fs *[]model.Finding) { *fs = nil })
			var events []model.Event
			for i := 0; i < 65; i++ {
				eid := fmt.Sprintf("partial-%03d", i)
				events = append(events, model.Event{ID: eid, CaseID: id, CollectionID: "11111111-2222-4333-8444-555555555555", SourceFileID: "sf-1", DedupHash: eid, EventType: "process_start"})
			}
			if err := svc.store.SaveEvents(events); err != nil {
				t.Fatal(err)
			}
			budget := defaultBatchBudget()
			budget.Synthesis = false
			if mode == "budget" {
				budget.Requests = 1
			}
			base := "/api/cases/" + id + "/enrich/case-review/batches"
			var p ReviewBatchPlan
			if r := doJSON(t, mux, "POST", base+"/plan", map[string]any{"budget": budget}, &p); r.Code != 201 {
				t.Fatalf("plan %d %s", r.Code, r.Body.String())
			}
			if r := doJSON(t, mux, "POST", base+"/"+p.ID+"/start", map[string]any{"plan_key": p.PlanKey}, nil); r.Code != 202 {
				t.Fatalf("start %d %s", r.Code, r.Body.String())
			}
			if mode == "cancelled" {
				select {
				case <-provider.entered:
				case <-time.After(5 * time.Second):
					t.Fatal("second packet not entered")
				}
				if r := doJSON(t, mux, "POST", base+"/"+p.ID+"/cancel", map[string]any{}, nil); r.Code != 204 {
					t.Fatalf("cancel %d %s", r.Code, r.Body.String())
				}
			}
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				current, err := svc.readBatchPlan(id, p.ID)
				if err != nil {
					t.Fatal(err)
				}
				svc.batches.mu.Lock()
				active := svc.batches.runs[id] != nil
				svc.batches.mu.Unlock()
				if current.State != "running" && !active {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			var page struct {
				Packets []ReviewBatchPacket `json:"packets"`
			}
			r := doJSON(t, mux, "GET", base+"/"+p.ID+"/packets?limit=8", nil, &page)
			if r.Code != 200 || len(page.Packets) < 2 {
				t.Fatalf("packets %d %s", r.Code, r.Body.String())
			}
			first := page.Packets[0]
			if first.State != "succeeded" || len(first.Sentences) != 1 || first.Sentences[0].Kind != "possible_conflict" {
				t.Fatalf("earlier kind lost: %+v", first)
			}
			current, err := svc.readBatchPlan(id, p.ID)
			if err != nil || current.State == "running" || current.State == "succeeded" {
				t.Fatalf("wrong partial outcome %+v %v", current, err)
			}
		})
	}
}

func TestCaseReviewClaimKindsRoundTrip(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newLLMStub(t, svc, true)
	kinds := []string{"observation", "possible_conflict", "hypothesis", "gap", "next_check", "unclassified"}
	var lines []string
	for _, kind := range kinds {
		lines = append(lines, kind+" | Recorded commentary. [E1]")
	}
	stub.answer = func(string) (int, string) { return 200, chatBody(strings.Join(lines, "\n")) }
	id := caseWithFindings(t, svc, mux, nil)
	before, _ := svc.store.ListFindings(id)
	p := reviewPreview(t, mux, id)
	if code := reviewStart(t, mux, id, false, p.PreviewKey); code != 202 {
		t.Fatal(code)
	}
	waitReview(t, svc, id)
	var status CaseReviewStatus
	r := doJSON(t, mux, "GET", "/api/cases/"+id+"/enrich/case-review", nil, &status)
	if r.Code != 200 || status.Latest == nil {
		t.Fatalf("status %d %s", r.Code, r.Body.String())
	}
	row, ok, err := svc.store.LatestCaseReview(id)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	// Persisted sentence JSON is the same contract read through the actual route.
	var stored []narrative.Sentence
	if err = json.Unmarshal([]byte(row.Narrative.SentencesJSON), &stored); err != nil {
		t.Fatal(err)
	}
	if len(stored) != len(kinds) {
		t.Fatalf("stored %+v", stored)
	}
	for i, kind := range kinds {
		if stored[i].Kind != kind || stored[i].Text != "Recorded commentary." || !strings.Contains(r.Body.String(), `"kind":"`+kind+`"`) {
			t.Fatalf("kind lost %s: %s", kind, r.Body.String())
		}
	}
	after, _ := svc.store.ListFindings(id)
	a, _ := json.Marshal(before)
	b, _ := json.Marshal(after)
	if string(a) != string(b) {
		t.Fatal("commentary changed findings")
	}
}

func TestReviewBatchesClaimKindsRoundTripAndSynthesis(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newLLMStub(t, svc, true)
	stub.answer = func(string) (int, string) {
		return 200, chatBody("hypothesis | The account [USER_1] is recorded. [E1]")
	}
	id := caseWithFindings(t, svc, mux, func(fs *[]model.Finding) { *fs = nil })
	var events []model.Event
	for i := 0; i < 121; i++ {
		user := "alice"
		if i >= 60 {
			user = "bob"
		}
		if i >= 120 {
			user = "carol"
		}
		eid := fmt.Sprintf("typed-event-%03d", i)
		events = append(events, model.Event{ID: eid, CaseID: id, CollectionID: "11111111-2222-4333-8444-555555555555", SourceFileID: "sf-1", DedupHash: eid, User: user, EventType: "process_start"})
	}
	if err := svc.store.SaveEvents(events); err != nil {
		t.Fatal(err)
	}
	base := "/api/cases/" + id + "/enrich/case-review/batches"
	var p ReviewBatchPlan
	r := doJSON(t, mux, "POST", base+"/plan", map[string]any{"budget": defaultBatchBudget()}, &p)
	if r.Code != 201 {
		t.Fatalf("plan %d %s", r.Code, r.Body.String())
	}
	r = doJSON(t, mux, "POST", base+"/"+p.ID+"/start", map[string]any{"plan_key": p.PlanKey}, nil)
	if r.Code != 202 {
		t.Fatalf("start %d %s", r.Code, r.Body.String())
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		current, err := svc.readBatchPlan(id, p.ID)
		if err != nil {
			t.Fatal(err)
		}
		if current.State != "running" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	var page struct {
		Packets []ReviewBatchPacket `json:"packets"`
	}
	r = doJSON(t, mux, "GET", base+"/"+p.ID+"/packets?limit=8", nil, &page)
	if r.Code != 200 || len(page.Packets) != 4 || stub.count() != 4 {
		t.Fatalf("packets %d %s sends=%d", r.Code, r.Body.String(), stub.count())
	}
	texts := map[string]bool{}
	for _, packet := range page.Packets {
		if packet.State != "succeeded" || len(packet.Sentences) != 1 || packet.Sentences[0].Kind != "hypothesis" {
			t.Fatalf("kind roundtrip: %+v", packet)
		}
		sentence := packet.Sentences[0]
		texts[sentence.Text] = true
		for _, cite := range sentence.Cites {
			if cite.Kind == "event" {
				_, ok, err := svc.store.BatchEvent(id, p.ID, cite.ID)
				if err != nil || !ok {
					t.Fatal("foreign citation", cite, err)
				}
			}
		}
	}
	if len(texts) < 2 {
		t.Fatal("packet identities merged", texts)
	}
	synth := page.Packets[3]
	if synth.Kind != "synthesis" || strings.Count(synth.Payload.User, "commentary_only | kind=hypothesis |") != 3 || !strings.Contains(synth.Payload.User, "[USER_2]") {
		t.Fatalf("synthesis lost kind/context: %s", synth.Payload.User)
	}
	if strings.Contains(synth.Payload.User, "alice") || strings.Contains(synth.Payload.User, "bob") {
		t.Fatal("local names leaked")
	}
}
