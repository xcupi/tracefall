package detect

import (
	"testing"
	"time"

	"tracefall/internal/model"
)

// One request can resemble two kinds of attack. The rule reports each kind as
// its own finding, both supported by the same event; the identifier is derived
// from the case, the rule and the supporting events, so without care the two
// share an ID and the second cannot be stored.
func TestRunFrom_FindingsFromOneRuleOverTheSameEventsGetDistinctIDs(t *testing.T) {
	at := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	// A SQL injection string sent by a scanner: two kinds, one request.
	ev := []model.Event{webReq("a", model.ArtifactIISLog, "/products.aspx?id=1'+UNION+SELECT+username,password+FROM+users--", at)}
	ev[0].Extra["user_agent"] = "sqlmap/1.7.2#stable"
	got, err := RunFrom("case1", model.SliceSource(ev))
	if err != nil {
		t.Fatal(err)
	}
	var web []model.Finding
	for _, f := range got {
		if f.RuleID == "web-attack-indicators" {
			web = append(web, f)
		}
	}
	if len(web) < 2 {
		t.Fatalf("the fixture must give the rule two findings over one event, got %d", len(web))
	}
	seen := map[string]bool{}
	for _, f := range got {
		if seen[f.ID] {
			t.Fatalf("two findings share the ID %s", f.ID)
		}
		seen[f.ID] = true
	}
	again, _ := RunFrom("case1", model.SliceSource(ev))
	for i := range got {
		if got[i].ID != again[i].ID {
			t.Fatalf("IDs must be reproducible: %s vs %s", got[i].ID, again[i].ID)
		}
	}
}
