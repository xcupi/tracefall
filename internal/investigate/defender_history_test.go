package investigate

import (
	"testing"
	"tracefall/internal/model"
)

func TestDefenderHistoryNeverAddsIndependentScoring(t *testing.T) {
	events, fs, _ := reviewIdentityEvents()
	events = events[:2]
	for i := range events {
		events[i].ArtifactType = model.ArtifactWindowsEventLog
	}
	base := Run("case", events, fs, nil)
	h := events[0]
	h.ID = "history"
	h.ArtifactType = model.ArtifactDefenderHistory
	h.EventType = model.EventAntimalwareHistory
	fs[0].SupportingEvents = append(append([]string(nil), fs[0].SupportingEvents...), h.ID)
	events = append(events, h)
	got := Run("case", events, fs, nil)
	streamed, err := RunStreamed("case", func(fn func(model.Event) error) error {
		for _, e := range events {
			if err := fn(e); err != nil {
				return err
			}
		}
		return nil
	}, fs, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, all := range [][]model.Investigation{got, streamed} {
		if len(all) != len(base) {
			t.Fatal("history changed groups")
		}
		for i, v := range all {
			if v.Score != base[i].Score || v.Confidence != base[i].Confidence || v.Severity != base[i].Severity {
				t.Fatalf("history inflated assessment: before=%+v after=%+v", base[i], v)
			}
		}
	}
}
