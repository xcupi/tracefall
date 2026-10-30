package investigate

import (
	"reflect"
	"testing"
	"tracefall/internal/model"
)

// A new context-only artifact/acquisition must neither merge findings nor
// change ANY assessment, including diversity, score and confidence rationale.
func TestTaskContextsNeverInflateInvestigations(t *testing.T) {
	events, fs, _ := reviewIdentityEvents()
	events = events[:2]
	extra := events[0]
	extra.ID = "task"
	extra.CollectionID = "new-context-capture"
	extra.ArtifactType = model.ArtifactRegistryHive
	extra.EventType = model.EventScheduledTaskRun
	events = append(events, extra)
	baseline := Run("case", events, fs, nil)
	for _, typ := range []string{"task_instance_context", "task_process_context"} {
		cs := []model.Correlation{{ID: "context", Type: typ, EventIDs: []string{events[0].ID, events[1].ID, extra.ID}}}
		got := Run("case", events, fs, cs)
		if !reflect.DeepEqual(got, baseline) {
			t.Fatalf("context %s changed assessment: baseline=%+v actual=%+v", typ, baseline, got)
		}
		if routine := Run("case", events, nil, cs); len(routine) != 0 {
			t.Fatalf("routine context seeded investigation: %+v", routine)
		}
	}
}
