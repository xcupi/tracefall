package correlate

import (
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
)

func chainPair(parentExit string) []model.Event {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	p := model.Event{ID: "p", CaseID: "c", CollectionID: "col", Host: "host01", EventType: model.EventProcessCreate, ProcessName: "svc.exe", PID: 100, Timestamp: base, Extra: map[string]string{}}
	if parentExit != "" {
		p.Extra["exit_time"] = parentExit
	}
	ch := model.Event{ID: "k", CaseID: "c", CollectionID: "col", Host: "host01", EventType: model.EventProcessCreate, ProcessName: "child.exe", PID: 200, PPID: 100, ParentProcessName: "svc.exe", Timestamp: base.Add(time.Hour), Extra: map[string]string{}}
	return []model.Event{p, ch}
}

// A process-creation record carries no exit time, so a PID reused by a
// same-named process between the recorded creation and the child cannot be
// excluded. The link stays, and says so.
func TestProcessChain_SaysWhenTheParentsExitIsNotRecorded(t *testing.T) {
	got := BuildProcessChains("c", chainPair(""))
	if len(got) != 1 {
		t.Fatalf("got %d chains, want 1", len(got))
	}
	if !strings.Contains(got[0].Description, "exit is not recorded") {
		t.Errorf("description must state the PID-reuse limit: %s", got[0].Description)
	}
	known := BuildProcessChains("c", chainPair("2026-01-01T05:00:00Z"))
	if len(known) != 1 || strings.Contains(known[0].Description, "exit is not recorded") {
		t.Errorf("a recorded exit that covers the child needs no caveat: %+v", known)
	}
}
