package investigate

import (
	"reflect"
	"strings"
	"testing"
	"time"
	"tracefall/internal/model"
)

func reviewIdentityEvents() ([]model.Event, []model.Finding, []model.Correlation) {
	b := time.Date(2026, 1, 15, 9, 0, 0, 0, time.UTC)
	events := []model.Event{{ID: "x", CaseID: "case", CollectionID: "one", Host: "host01", Timestamp: b, EventType: model.EventProcessCreate, ProcessName: "worker.exe"}, {ID: "y", CaseID: "case", CollectionID: "two", Host: "host01", Timestamp: b.Add(time.Minute), EventType: model.EventProcessCreate, ProcessName: "worker.exe"}, {ID: "a", CaseID: "case", CollectionID: "three", Host: "host01.a.example", EventType: model.EventRegistryKeyLastWrite}, {ID: "b", CaseID: "case", CollectionID: "four", Host: "host01.b.example", EventType: model.EventRegistryKeyLastWrite}}
	fs := []model.Finding{{ID: "fx", Severity: model.SeverityLow, Confidence: model.ConfidenceLow, SupportingEvents: []string{"x"}}, {ID: "fy", Severity: model.SeverityLow, Confidence: model.ConfidenceLow, SupportingEvents: []string{"y"}}}
	return events, fs, []model.Correlation{{ID: "entity", Type: model.CorrelationEntity, EventIDs: []string{"x", "y"}}}
}
func TestReviewContextOnlyArtifactCannotEscalate(t *testing.T) {
	events, _, _ := reviewIdentityEvents()
	proc := events[0]
	proc.ArtifactType = model.ArtifactWindowsEventLog
	config := proc
	config.ID = "config"
	config.EventType = model.EventServiceInstall
	config.Timestamp = proc.Timestamp.Add(-time.Minute)
	config.ArtifactType = model.ArtifactRegistryHive
	config.CollectionID = "context-collection"
	fs := []model.Finding{{ID: "f", RuleID: "suspicious-process-chain", Severity: model.SeverityLow, Confidence: model.ConfidenceLow, SupportingEvents: []string{proc.ID}}}
	cs := []model.Correlation{{ID: "context", Type: model.CorrelationServiceChain, Title: "Contextual service configuration association", Description: "Configuration does not establish execution or causality.", EventIDs: []string{config.ID, proc.ID}}}
	baseline := Run("case", []model.Event{proc, config}, fs, nil)[0]
	got := Run("case", []model.Event{proc, config}, fs, cs)[0]
	if got.Score != baseline.Score || got.Severity != baseline.Severity || got.Confidence != baseline.Confidence {
		t.Fatalf("context-only NEW artifact/collection escalated baseline=%+v actual=%+v", baseline, got)
	}
	if got.EventCount != 2 || !strings.Contains(got.Summary, "Configuration does not establish") || !strings.Contains(got.Summary, "Contextual") {
		t.Fatalf("context facts/caveat lost: %+v", got)
	}
	if strings.Contains(got.Summary, "subsequently") || strings.Contains(got.Summary, "was installed") {
		t.Fatalf("context became an execution sequence: %s", got.Summary)
	}
	fs = append(fs, model.Finding{ID: "genuine", Severity: model.SeverityLow, Confidence: model.ConfidenceLow, SupportingEvents: []string{config.ID}})
	genuine := Run("case", []model.Event{proc, config}, fs, cs)
	if len(genuine) != 1 || genuine[0].Score <= baseline.Score {
		t.Fatalf("genuine independent support removed: %+v", genuine)
	}
}

func TestReviewUnreferencedIdentityInventory(t *testing.T) {
	events, fs, cs := reviewIdentityEvents()
	for _, metadata := range []bool{false, true} {
		events, fs, cs = reviewIdentityEvents()
		if metadata {
			events = events[:2]
			events = append(events, model.Event{ID: "a", CaseID: "case", Host: "host01", EventType: model.EventRegistryKeyLastWrite, Extra: map[string]string{"os_current_build": "1"}}, model.Event{ID: "b", CaseID: "case", Host: "host01", EventType: model.EventRegistryKeyLastWrite, Extra: map[string]string{"os_current_build": "2"}})
		}
		for order := 0; order < 2; order++ {
			got, err := RunStreamed("case", func(fn func(model.Event) error) error {
				for _, e := range events {
					if !NeedsExtra(e.EventType) {
						e.Extra = nil
					}
					if err := fn(e); err != nil {
						return err
					}
				}
				return nil
			}, fs, cs)
			if full := Run("case", events, fs, cs); !reflect.DeepEqual(full, got) {
				t.Fatalf("stream/full inventory mismatch: full=%+v stream=%+v", full, got)
			}
			if err != nil || len(got) != 2 {
				t.Fatalf("metadata=%v: unreferenced identity conflict merged acquisitions: %+v err=%v", metadata, got, err)
			}
			for _, inv := range got {
				if strings.Contains(inv.ConfidenceRationale, "across 2") {
					t.Fatal(inv.ConfidenceRationale)
				}
			}
			events[0], events[len(events)-1] = events[len(events)-1], events[0]
		}
	}
}
