package detect

import (
	"encoding/json"
	"strings"
	"testing"
	"tracefall/internal/model"
)

func TestAVHistoryDeclaredInputAndSameProducerContext(t *testing.T) {
	const id = "12345678-1234-5678-90ab-cdef01020304"
	base := avDet("e", "host-neutral", "{"+strings.ToUpper(id)+"}", "Neutral.Label", "High", 0)
	history := model.Event{ID: "h", CaseID: base.CaseID, CollectionID: base.CollectionID, Host: base.Host, EventType: "antimalware_history_observation", ArtifactType: "defender_detection_history", Extra: map[string]string{"detection_id": id}}
	declared := false
	for _, typ := range (avThreatDetected{}).Inputs().Types {
		if typ == history.EventType {
			declared = true
		}
	}
	if !declared {
		t.Fatal("history missing from declared Inputs")
	}
	before := runRule(t, avRuleID, []model.Event{base})
	after := runRule(t, avRuleID, []model.Event{base, history})
	if len(after) != 1 || after[0].Severity != before[0].Severity || after[0].Confidence != before[0].Confidence || len(after[0].SupportingEvents) != 2 {
		t.Fatal("history context missing or boosted assessment")
	}
	d := after[0].Description
	for _, s := range []string{"Event log: 1 detection record", "History: 1 stateful observation", "not independent confirmation", "sharing 1 detection ID"} {
		if !strings.Contains(d, s) {
			t.Errorf("missing explicit source semantics %q", s)
		}
	}
	for _, tc := range []struct {
		name   string
		change func(*model.Event)
	}{
		{"other-acquisition", func(e *model.Event) { e.CollectionID = "other" }},
		{"other-host", func(e *model.Event) { e.Host = "other" }},
		{"malformed-id", func(e *model.Event) { e.Extra = map[string]string{"detection_id": "not-guid"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := history
			tc.change(&h)
			got := runRule(t, avRuleID, []model.Event{base, h})
			if len(got) != 1 || len(got[0].SupportingEvents) != 1 {
				t.Fatal("unvalidated identity joined")
			}
		})
	}
	if got := runRule(t, avRuleID, []model.Event{history}); len(got) != 0 {
		t.Fatal("routine history invented malicious finding")
	}
	b, _ := json.Marshal(history)
	got := runRule(t, avRuleID, []model.Event{base, history})
	a, _ := json.Marshal(history)
	if string(b) != string(a) || strings.Contains(got[0].Description, "executed successfully") {
		t.Fatal("input rewritten/outcome invented")
	}
}
func TestAVHistoryCanonicalCountsLiteralPreservation(t *testing.T) {
	const id = "12345678-1234-5678-90ab-cdef01020304"
	a := avDet("a", "neutral", id, "Neutral.Label", "", 0)
	b := avDet("b", "neutral", "{"+strings.ToUpper(id)+"}", "Neutral.Label", "", 1)
	got := runRule(t, avRuleID, []model.Event{a, b})
	if len(got) != 1 || !strings.Contains(got[0].Description, "sharing 1 detection ID") {
		t.Fatal("canonical GUID counts missing")
	}
	if b.Extra["detection_id"] != "{"+strings.ToUpper(id)+"}" {
		t.Fatal("literal identifier altered")
	}
}
