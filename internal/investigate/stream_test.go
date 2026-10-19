package investigate

import (
	"encoding/json"
	"testing"
	"time"

	"tracefall/internal/model"
)

// RunStreamed must not depend on the order events arrive in. The store streams
// them in its own order, and the previous per-slice code sorted by timestamp
// and id; a regression here would make report output depend on storage order.
func TestRunStreamed_EventArrivalOrderDoesNotChangeTheResult(t *testing.T) {
	base := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	mk := func(id, typ string, at time.Duration, user string) model.Event {
		return model.Event{
			ID: id, CaseID: "case", CollectionID: "col", SourceFileID: "sf", Host: "host01",
			User: user, EventType: typ, ArtifactType: model.ArtifactWindowsEventLog,
			Timestamp: base.Add(at), ProcessName: "cmd.exe", ParentProcessName: "explorer.exe",
		}
	}
	events := []model.Event{
		mk("e1", model.EventLogonFailure, 0, "alice"),
		mk("e2", model.EventLogonFailure, time.Second, "alice"),
		mk("e3", model.EventLogonFailure, 2*time.Second, "alice"),
		mk("e4", model.EventLogonSuccess, 3*time.Second, "alice"),
		// Two events with the same timestamp: order between them is by id.
		mk("e5", model.EventProcessCreate, 4*time.Second, "alice"),
		mk("e6", model.EventNetworkConnection, 4*time.Second, "alice"),
	}
	findings := []model.Finding{{
		ID: "f1", CaseID: "case", RuleID: "brute-force-then-success", Title: "burst",
		Severity: model.SeverityHigh, Confidence: model.ConfidenceHigh,
		SupportingEvents: []string{"e1", "e2", "e3", "e4", "e5", "e6"}, FirstSeen: base,
		Techniques: []string{"T1110"},
	}}

	want, _ := json.Marshal(Run("case", events, findings, nil))

	orders := [][]int{{5, 4, 3, 2, 1, 0}, {2, 0, 5, 1, 4, 3}, {1, 3, 5, 0, 2, 4}}
	for _, ord := range orders {
		each := func(fn func(model.Event) error) error {
			for _, i := range ord {
				if err := fn(events[i]); err != nil {
					return err
				}
			}
			return nil
		}
		got, err := RunStreamed("case", each, findings, nil)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(got)
		if string(b) != string(want) {
			t.Fatalf("order %v changed the investigations:\n got  %s\n want %s", ord, b, want)
		}
	}
}
