package investigate

import (
	"testing"
	"tracefall/internal/model"
)

func TestWMIContextNeverMergesOrAddsScoring(t *testing.T) {
	if mergeworthy(model.CorrelationWMIConfigurationContext) {
		t.Fatal("same-producer configuration is a grouping edge")
	}
	events, fs, _ := reviewIdentityEvents()
	events = events[:2]
	for i := range events {
		events[i].ArtifactType = model.ArtifactWindowsEventLog
	}
	baseline := Run("case", events, fs, nil)
	w := events[0]
	w.ID = "snapshot"
	w.CollectionID = "snapshot-collection"
	w.EventType = model.EventWMISnapshot
	w.ArtifactType = model.ArtifactWMIRepository
	events = append(events, w)
	fs[0].SupportingEvents = append(append([]string(nil), fs[0].SupportingEvents...), w.ID)
	correlations := []model.Correlation{{ID: "context", Type: model.CorrelationWMIConfigurationContext, EventIDs: []string{"x", "y", w.ID}}}
	got := Run("case", events, fs, correlations)
	streamed, err := RunStreamed("case", func(fn func(model.Event) error) error {
		for _, e := range events {
			if err := fn(e); err != nil {
				return err
			}
		}
		return nil
	}, fs, correlations)
	if err != nil {
		t.Fatal(err)
	}
	for _, all := range [][]model.Investigation{got, streamed} {
		if len(all) != len(baseline) {
			t.Fatal("context merged unrelated investigations")
		}
		for i, v := range all {
			if v.Score != baseline[i].Score || v.Confidence != baseline[i].Confidence || v.Severity != baseline[i].Severity {
				t.Fatal("snapshot supplied independent corroboration or scoring")
			}
		}
	}
}
