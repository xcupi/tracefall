package api

import (
	"testing"
	"time"

	"tracefall/internal/model"
)

// This predicate is the assertion contract of the integration test, not a
// production time inference. Its controls must reject a lost or partial window.
func findingRangeIsHonest(f model.Finding, events map[string]model.Event) bool {
	if f.FirstSeen.IsZero() && f.LastSeen.IsZero() {
		// The fixture's zone-less task XML has no recorded instant. Display labels
		// may change; only this rule with resolved, wholly undated task evidence is
		// the known exception. Never excuse a lost window over dated evidence.
		if f.RuleID != "new-scheduled-task" || len(f.SupportingEvents) == 0 {
			return false
		}
		for _, id := range f.SupportingEvents {
			e, ok := events[id]
			if !ok || !e.Timestamp.IsZero() || e.EventType != model.EventScheduledTaskCreate {
				return false
			}
		}
		return true
	}
	return !f.FirstSeen.IsZero() && !f.LastSeen.IsZero() && !f.LastSeen.Before(f.FirstSeen)
}

func TestDateRange_FindingWindowAssertionControls(t *testing.T) {
	now := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	unknown := model.Event{ID: "unknown", EventType: model.EventScheduledTaskCreate}
	dated := model.Event{ID: "dated", EventType: model.EventScheduledTaskCreate, Timestamp: now}
	events := map[string]model.Event{"unknown": unknown, "dated": dated}
	for _, tc := range []struct {
		name string
		f    model.Finding
		want bool
	}{
		{"undated renamed task", model.Finding{RuleID: "new-scheduled-task", Title: "Task configuration review", SupportingEvents: []string{"unknown"}}, true},
		{"dated window", model.Finding{FirstSeen: now, LastSeen: now}, true},
		{"lost dated window", model.Finding{RuleID: "new-scheduled-task", Title: "Scheduled Task persistence", SupportingEvents: []string{"dated"}}, false},
		{"mixed evidence", model.Finding{RuleID: "new-scheduled-task", SupportingEvents: []string{"unknown", "dated"}}, false},
		{"missing evidence", model.Finding{RuleID: "new-scheduled-task", SupportingEvents: []string{"absent"}}, false},
		{"empty evidence", model.Finding{RuleID: "new-scheduled-task"}, false},
		{"other rule", model.Finding{RuleID: "other", SupportingEvents: []string{"unknown"}}, false},
		{"partial first", model.Finding{RuleID: "new-scheduled-task", FirstSeen: now, SupportingEvents: []string{"unknown"}}, false},
		{"partial last", model.Finding{RuleID: "new-scheduled-task", LastSeen: now, SupportingEvents: []string{"unknown"}}, false},
		{"reversed window", model.Finding{FirstSeen: now, LastSeen: now.Add(-time.Second)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := findingRangeIsHonest(tc.f, events); got != tc.want {
				t.Errorf("honest window=%t want %t", got, tc.want)
			}
		})
	}
}
