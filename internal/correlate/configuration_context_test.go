package correlate

import (
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
)

func configurationContextFixture() []model.Event {
	events := activityFixture()
	events[2].ProcessPath = `C:\Tools\worker.exe`
	for i, typ := range []string{model.EventRegistryRunKey, model.EventScheduledTaskCreate} {
		e := events[2]
		e.ID = []string{"run-key", "task"}[i]
		e.CollectionID = "collection-2"
		e.EventType = typ
		e.PID = 900 // Configuration writer is not the target process.
		e.Timestamp = e.Timestamp.Add(time.Duration(i+1) * time.Minute)
		e.ProcessPath = `c:/TOOLS/WORKER.exe`
		e.Extra = map[string]string{}
		if i == 0 {
			e.Extra["value_data"] = e.ProcessPath
		}
		events = append(events, e)
	}
	return events
}

func TestActivityPluralConfigurationAcrossEstablishedMachineAcquisitions(t *testing.T) {
	for _, scope := range []string{"collection-1", "collection-2"} {
		for _, indexes := range [][]int{{3}, {4}, {3, 4}} {
			t.Run(scope+"/"+fmt.Sprint(indexes), func(t *testing.T) {
				events := configurationContextFixture()
				selected := append([]model.Event(nil), events[:3]...)
				for _, i := range indexes {
					events[i].CollectionID = scope
					selected = append(selected, events[i])
				}
				got := BuildActivityChains("case-1", selected)
				if len(got) != 1 || len(got[0].EventIDs) != 3+len(indexes) {
					t.Fatalf("full-path configuration contexts lost for %v: %+v", indexes, got)
				}
				if !strings.HasPrefix(got[0].Title, "Contextual ") || !strings.Contains(got[0].Description, "does not establish") {
					t.Fatalf("configuration promoted to execution: %+v", got)
				}
			})
		}
	}
}

func TestActivityConfigurationAliasShuffleSourceParity(t *testing.T) {
	events := configurationContextFixture()
	events[1].Host = "host01.corp.example" // Same acquisition proves the alias.
	want := BuildActivityChains("case-1", events)
	if len(want) != 1 || len(want[0].EventIDs) != 5 {
		t.Fatalf("alias context lost: %+v", want)
	}
	rng := rand.New(rand.NewSource(10))
	for i := 0; i < 20; i++ {
		rng.Shuffle(len(events), func(i, j int) { events[i], events[j] = events[j], events[i] })
		if got := BuildActivityChains("case-1", events); !reflect.DeepEqual(got, want) {
			t.Fatalf("shuffle differs: %+v", got)
		}
		all, err := RunFrom("case-1", model.SliceSource(events))
		if err != nil {
			t.Fatal(err)
		}
		var got []model.Correlation
		for _, c := range all {
			if c.Type == model.CorrelationActivityChain {
				c.ID = ""
				got = append(got, c)
			}
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("source parity differs: got %+v want %+v", got, want)
		}
	}
}

func TestActivityConfigurationContextAbstainsUnsupportedEvidence(t *testing.T) {
	tests := map[string]func([]model.Event) []model.Event{
		"unknown-collection": func(e []model.Event) []model.Event { e[3].CollectionID = ""; return e },
		"unknown-process-collection": func(e []model.Event) []model.Event {
			for i := 0; i < 3; i++ {
				e[i].CollectionID = ""
			}
			return e
		},
		"unknown-case":   func(e []model.Event) []model.Event { e[3].CaseID = ""; return e },
		"wrong-case":     func(e []model.Event) []model.Event { e[3].CaseID = "other"; return e },
		"unknown-host":   func(e []model.Event) []model.Event { e[3].Host = ""; return e },
		"different-host": func(e []model.Event) []model.Event { e[3].Host = "host02"; return e },
		"unproven-alias": func(e []model.Event) []model.Event { e[3].Host = "host01.corp.example"; return e },
		"ambiguous-host": func(e []model.Event) []model.Event {
			for _, h := range []string{"host01.a.example", "host01.b.example"} {
				x := e[3]
				x.ID = h
				x.Host = h
				x.EventType = model.EventRegistryKeyLastWrite
				e = append(e, x)
			}
			return e
		},
		"conflicting-metadata": func(e []model.Event) []model.Event {
			e[0].Extra = map[string]string{"os_current_build": "100"}
			e[3].Extra["os_current_build"] = "200"
			return e
		},
		"basename":       func(e []model.Event) []model.Event { e[3].Extra["value_data"] = "worker.exe"; return e },
		"different-path": func(e []model.Event) []model.Event { e[3].Extra["value_data"] = `C:\Other\worker.exe`; return e },
		"unknown-path":   func(e []model.Event) []model.Event { e[3].Extra = map[string]string{}; e[3].ProcessPath = ""; return e },
		"unknown-time":   func(e []model.Event) []model.Event { e[3].Timestamp = time.Time{}; return e },
		"tied-time":      func(e []model.Event) []model.Event { e[3].Timestamp = e[2].Timestamp; return e },
		"before-process": func(e []model.Event) []model.Event { e[3].Timestamp = e[2].Timestamp.Add(-time.Second); return e },
		"outside-window": func(e []model.Event) []model.Event {
			e[3].Timestamp = e[2].Timestamp.Add(activityLookWindow + time.Second)
			return e
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			events := mutate(configurationContextFixture()[:4])
			got := BuildActivityChains("case-1", events)
			for _, c := range got {
				for _, id := range c.EventIDs {
					if id == "run-key" {
						t.Fatalf("unsupported context retained: %+v", c)
					}
				}
			}
		})
	}
}
