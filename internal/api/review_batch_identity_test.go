package api

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
)

func TestReviewBatchesPacketNamespacesRemapIdentitiesInSynthesis(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newLLMStub(t, svc, true)
	id := caseWithFindings(t, svc, mux, func(fs *[]model.Finding) { *fs = nil })
	stub.answer = func(string) (int, string) { return 200, chatBody("The account [USER_1] is recorded. [E1]") }
	var events []model.Event
	for i := 0; i < 121; i++ {
		user := "alice"
		if i >= 60 {
			user = "bob"
		}
		if i >= 120 {
			user = "carol"
		}
		events = append(events, model.Event{ID: fmt.Sprintf("identity-%03d", i), CaseID: id, CollectionID: "11111111-2222-4333-8444-555555555555", SourceFileID: "sf-1", DedupHash: fmt.Sprintf("identity-%d", i), User: user, EventType: "process_start"})
	}
	if err := svc.store.SaveEvents(events); err != nil {
		t.Fatal(err)
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
	raw, err := svc.store.BatchPackets(id, p.ID, -1, 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 4 || stub.count() != 4 {
		t.Fatalf("want three batches plus synthesis: %d packets, %d requests", len(raw), stub.count())
	}
	users := map[string]bool{}
	namespaces := map[string]bool{}
	for _, r := range raw[:3] {
		var packet ReviewBatchPacket
		json.Unmarshal(r, &packet)
		if packet.State != "succeeded" || len(packet.Sentences) != 1 {
			t.Fatalf("bad packet: %+v", packet)
		}
		namespaces[packet.Namespace] = true
		users[packet.Sentences[0].Text] = true
		for _, cite := range packet.Sentences[0].Cites {
			if cite.Kind == "event" {
				_, ok, err := svc.store.BatchEvent(id, p.ID, cite.ID)
				if err != nil || !ok {
					t.Fatalf("citation not same-case primary: %v %v", ok, err)
				}
			}
		}
	}
	if len(users) < 2 || len(namespaces) != 3 {
		t.Fatalf("batch-local USER_1 silently merged: users=%v namespaces=%v", users, namespaces)
	}
	var synthesis ReviewBatchPacket
	json.Unmarshal(raw[3], &synthesis)
	if !strings.Contains(synthesis.Payload.User, "[USER_2]") || strings.Contains(synthesis.Payload.User, "alice") || strings.Contains(synthesis.Payload.User, "bob") {
		t.Fatalf("synthesis did not re-pseudonymize the restored distinct identities: %s", synthesis.Payload.User)
	}
	digest := sha256.Sum256([]byte(stub.last().System + "\x00" + stub.last().User))
	if synthesis.Payload.SHA256 != fmt.Sprintf("%x", digest) {
		t.Fatal("dynamic synthesis exact hash mismatch")
	}
}
