package detect

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
)

// The same request can be written by more than one log: a container's stdout and
// the application's own file, or a proxy and the server behind it. Counting the
// copies together would turn one request into several and push a single probe
// over a threshold, so each log is judged on its own.
func webReq(id, artifact, uri string, at time.Time) model.Event {
	return model.Event{
		ID: id, CaseID: "case1", Timestamp: at, SourceFileID: artifact + "-file",
		EventType: model.EventWebRequest, ArtifactType: artifact, NetworkSource: "203.0.113.9",
		Extra: map[string]string{"method": "GET", "uri": uri, "status": "404"},
	}
}

func TestWebAttack_OneRequestInTwoLogsIsNotTwoRequests(t *testing.T) {
	at := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	const uri = "/public/plugins/x/../../../../etc/passwd"
	ev := []model.Event{webReq("a", model.ArtifactContainerLog, uri, at), webReq("b", model.ArtifactGrafanaLog, uri, at)}
	var got []model.Finding
	for _, r := range All() {
		if r.ID() == "web-attack-indicators" {
			got = r.Evaluate(ev)
		}
	}
	if len(got) != 2 {
		t.Fatalf("want one finding per log, got %d", len(got))
	}
	for _, f := range got {
		if !strings.HasPrefix(f.Title, "1 web requests") {
			t.Errorf("a single request was counted as %q", f.Title)
		}
		if !strings.Contains(f.Description, "may also record the same request") {
			t.Errorf("no note that logs can overlap: %s", f.Description)
		}
	}
}

func TestWebAttack_AThresholdIsNotReachedByCopies(t *testing.T) {
	at := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	var ev []model.Event
	// 3 admin-interface probes are needed from one source; 2 here, copied into a second log.
	for i := 0; i < 2; i++ {
		u := fmt.Sprintf("/phpmyadmin/%d/", i)
		ev = append(ev, webReq(fmt.Sprintf("a%d", i), model.ArtifactContainerLog, u, at.Add(time.Duration(i)*time.Second)),
			webReq(fmt.Sprintf("b%d", i), model.ArtifactGrafanaLog, u, at.Add(time.Duration(i)*time.Second)))
	}
	for _, r := range All() {
		if r.ID() == "web-attack-indicators" {
			if got := r.Evaluate(ev); len(got) != 0 {
				t.Fatalf("2 probes copied into 2 logs reached the 3-request threshold: %d findings", len(got))
			}
			// Control: three real probes in one log do reach it, so the fixture is live.
			three := append([]model.Event{}, ev[:0]...)
			for i := 0; i < 3; i++ {
				three = append(three, webReq(fmt.Sprintf("c%d", i), model.ArtifactContainerLog, fmt.Sprintf("/phpmyadmin/%d/", i), at.Add(time.Duration(i)*time.Second)))
			}
			if got := r.Evaluate(three); len(got) != 1 {
				t.Fatalf("control: 3 probes in one log made %d findings", len(got))
			}
		}
	}
}
