package correlate

import (
	"fmt"
	"reflect"
	"testing"
	"time"
	"tracefall/internal/model"
)

func TestWindowsAuthSuccessDuringFailures(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var events []model.Event
	for i, typ := range []string{model.EventLogonFailure, model.EventLogonFailure, model.EventLogonFailure, model.EventLogonSuccess, model.EventLogonFailure, model.EventLogonFailure} {
		events = append(events, model.Event{ID: string(rune('a' + i)), CaseID: "case01", Host: "host01", User: "alice", EventType: typ, Timestamp: base.Add(time.Duration(i) * time.Minute)})
	}
	got := buildBruteForceChains("case01", events)
	if len(got) != 1 {
		t.Fatalf("success inside continuing failures: got %d, want 1", len(got))
	}
	if !reflect.DeepEqual(got[0].EventIDs, []string{"a", "b", "c", "d"}) {
		t.Fatalf("wrong pre-success burst: %v", got[0].EventIDs)
	}
	// Control: the success after the entire run still works.
	events[3].Timestamp = base.Add(7 * time.Minute)
	got = buildBruteForceChains("case01", events)
	if len(got) != 1 || len(got[0].EventIDs) != 6 {
		t.Fatalf("late success: %+v", got)
	}
}

func TestWindowsAuthContextIsolation(t *testing.T) {
	for _, dimension := range []string{"source", "domain", "case", "user", "subject_session", "zero", "tied", "memory"} {
		t.Run(dimension, func(t *testing.T) {
			base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			var events []model.Event
			for i := 0; i < 4; i++ {
				typ := model.EventLogonFailure
				if i == 3 {
					typ = model.EventLogonSuccess
				}
				events = append(events, model.Event{ID: string(rune('a' + i)), CaseID: "case01", CollectionID: "collection01", Host: "host01", User: "alice", NetworkSource: "203.0.113.1", EventType: typ, Timestamp: base.Add(time.Duration(i) * time.Minute), Extra: map[string]string{"target_domain": "domain01", "logon_type": "3", "subject_logon_id": "0x123"}})
			}
			s := &events[3]
			switch dimension {
			case "source":
				s.NetworkSource = "203.0.113.2"
			case "domain":
				s.Extra["target_domain"] = "domain02"
			case "type":
				s.Extra["logon_type"] = "10"
			case "case":
				s.CaseID = "case02"
			case "collection":
				s.CollectionID = "collection02"
			case "user":
				s.User = "carol"
			case "subject_session":
				s.Extra["subject_logon_id"] = "0x456"
			case "zero":
				for i := 0; i < 3; i++ {
					events[i].Timestamp = time.Time{}
				}
			case "tied":
				for i := range events {
					events[i].Timestamp = base
				}
			case "memory":
				for i := range events {
					events[i].ArtifactType = model.ArtifactMemoryAnalysis
				}
			}
			if got := buildBruteForceChains("case01", events); len(got) != 0 {
				t.Fatalf("cross-context/unknown-time sequence: %+v", got)
			}
		})
	}
}

func TestWindowsAuthInterleavedContexts(t *testing.T) {
	for _, dimension := range []string{"source", "domain", "subject_session"} {
		t.Run(dimension, func(t *testing.T) {
			base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			var events []model.Event
			for i := 0; i < 3; i++ {
				for stream := 0; stream < 2; stream++ {
					e := model.Event{ID: fmt.Sprintf("f%d%d", stream, i), CaseID: "case01", CollectionID: "collection01", Host: "host01", User: "alice", EventType: model.EventLogonFailure, Timestamp: base.Add(time.Duration(i)*time.Minute + time.Duration(stream)*time.Second), Extra: map[string]string{}}
					if dimension == "source" {
						e.NetworkSource = fmt.Sprintf("203.0.113.%d", stream+1)
					} else if dimension == "domain" {
						e.Extra["target_domain"] = fmt.Sprintf("domain%d", stream)
					} else {
						e.Extra["subject_logon_id"] = fmt.Sprintf("0x12%d", stream)
					}
					events = append(events, e)
				}
			}
			success := events[0]
			success.ID = "success"
			success.EventType = model.EventLogonSuccess
			success.Timestamp = base.Add(3 * time.Minute)
			success.Extra = map[string]string{}
			for k, v := range events[0].Extra {
				success.Extra[k] = v
			}
			success.Extra["logon_id"] = "0x999" // New target session, not the subject session.
			events = append(events, success)
			got := buildBruteForceChains("case01", events)
			if len(got) != 1 || !reflect.DeepEqual(got[0].EventIDs, []string{"f00", "f01", "f02", "success"}) {
				t.Fatalf("mixed or lost context: %+v", got)
			}
			for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
				events[i], events[j] = events[j], events[i]
			}
			shuffled := buildBruteForceChains("case01", events)
			if len(shuffled) != 1 || !reflect.DeepEqual(got[0].EventIDs, shuffled[0].EventIDs) {
				t.Fatalf("order-dependent result: %+v", shuffled)
			}
		})
	}
}

func TestWindowsAuthDoesNotRelabelAnotherCase(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var es []model.Event
	for i := 0; i < 4; i++ {
		typ := model.EventLogonFailure
		if i == 3 {
			typ = model.EventLogonSuccess
		}
		es = append(es, model.Event{ID: string(rune('a' + i)), CaseID: "case02", Host: "host01", User: "alice", EventType: typ, Timestamp: base.Add(time.Duration(i) * time.Minute)})
	}
	if got := buildBruteForceChains("case01", es); len(got) != 0 {
		t.Fatalf("other case relabelled as case01: %+v", got)
	}
}
