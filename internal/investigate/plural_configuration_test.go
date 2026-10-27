package investigate

import (
	"strings"
	"testing"
	"time"

	"tracefall/internal/correlate"
	"tracefall/internal/model"
)

func TestPluralCrossAcquisitionConfigurationDoesNotCorroborate(t *testing.T) {
	base := time.Date(2026, 1, 15, 9, 0, 0, 0, time.UTC)
	var events []model.Event
	for i, name := range []string{"winword.exe", "powershell.exe", "worker.exe"} {
		e := model.Event{ID: name, CaseID: "case", CollectionID: "execution", Host: "host01", ArtifactType: model.ArtifactWindowsEventLog, EventType: model.EventProcessCreate, ProcessName: name, ProcessPath: `C:\Tools\` + name, PID: int64(100 + i), Timestamp: base.Add(time.Duration(i) * time.Minute)}
		if i > 0 {
			e.ParentProcessName = events[i-1].ProcessName
			e.PPID = events[i-1].PID
		}
		events = append(events, e)
	}
	fs := []model.Finding{{ID: "lead", RuleID: "suspicious-process-chain", Severity: model.SeverityLow, Confidence: model.ConfidenceLow, SupportingEvents: []string{"worker.exe"}}}
	baseline := Run("case", events, fs, nil)[0]
	for i, typ := range []string{model.EventRegistryRunKey, model.EventScheduledTaskCreate} {
		e := events[2]
		e.ID = []string{"run-key", "task"}[i]
		e.CollectionID = "configuration"
		e.ArtifactType = []string{model.ArtifactRegistryHive, model.ArtifactScheduledTask}[i]
		e.EventType = typ
		e.Timestamp = base.Add(time.Duration(3+i) * time.Minute)
		events = append(events, e)
	}
	cs := correlate.BuildActivityChains("case", events)
	if len(cs) != 1 || len(cs[0].EventIDs) != 5 {
		t.Fatalf("missing plural contextual chain: %+v", cs)
	}
	cs[0].ID = "context"
	got := Run("case", events, fs, cs)[0]
	if got.Score != baseline.Score || got.Severity != baseline.Severity || got.Confidence != baseline.Confidence {
		t.Fatalf("context escalated baseline=%+v got=%+v", baseline, got)
	}
	if !strings.Contains(got.Summary, "does not establish") || strings.Contains(got.Summary, "subsequently") {
		t.Fatal(got.Summary)
	}
}
