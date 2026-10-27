package correlate

import (
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"
	"tracefall/internal/model"
)

func activityFixture() []model.Event {
	base := mustTime("2026-01-15T09:00:00Z")
	names := []string{"winword.exe", "powershell.exe", "worker.exe"}
	var out []model.Event
	for i, n := range names {
		e := model.Event{ID: n, CaseID: "case-1", CollectionID: "collection-1", Host: "host01", User: "alice", EventType: model.EventProcessCreate, ProcessName: n, PID: int64(100 + i), Timestamp: base.Add(time.Duration(i) * time.Minute), Extra: map[string]string{}}
		if i > 0 {
			e.ParentProcessName = names[i-1]
			e.PPID = int64(99 + i)
		}
		out = append(out, e)
	}
	return out
}

func TestActivityRejectsConflictingChildPID(t *testing.T) {
	events := activityFixture()
	if got := BuildActivityChains("case-1", events); len(got) != 1 {
		t.Fatalf("genuine lineage lost: %+v", got)
	}
	events[2].PPID = 900
	if got := BuildActivityChains("case-1", events); len(got) != 0 {
		t.Fatalf("name-only child attributed to wrong process: %+v", got)
	}
}

func TestActivityLineageEvidenceBoundaries(t *testing.T) {
	tests := map[string]func([]model.Event) []model.Event{
		"parent-conflicting-ppid": func(e []model.Event) []model.Event { e[1].PPID = 900; return e },
		"parent-conflicting-guid": func(e []model.Event) []model.Event {
			e[1].Extra["parent_process_guid"] = "other"
			e[0].Extra["process_guid"] = "parent"
			return e
		},
		"child-conflicting-guid": func(e []model.Event) []model.Event {
			e[2].Extra["parent_process_guid"] = "other"
			e[1].Extra["process_guid"] = "parent"
			return e
		},
		"child-missing-identity": func(e []model.Event) []model.Event { e[2].PPID = 0; return e },
		"wrong-collection":       func(e []model.Event) []model.Event { e[2].CollectionID = "other"; return e },
		"unknown-collection": func(e []model.Event) []model.Event {
			for i := range e {
				e[i].CollectionID = ""
			}
			return e
		},
		"wrong-case": func(e []model.Event) []model.Event { e[2].CaseID = "other"; return e },
		"unknown-host": func(e []model.Event) []model.Event {
			for i := range e {
				e[i].Host = ""
			}
			return e
		},
		"too-distant":  func(e []model.Event) []model.Event { e[2].Timestamp = e[1].Timestamp.Add(3 * time.Hour); return e },
		"tied-times":   func(e []model.Event) []model.Event { e[2].Timestamp = e[1].Timestamp; return e },
		"missing-time": func(e []model.Event) []model.Event { e[1].Timestamp = time.Time{}; return e },
		"exited-parent": func(e []model.Event) []model.Event {
			e[1].Extra["exit_time"] = e[2].Timestamp.Format(time.RFC3339)
			return e
		},
		"pid-reuse": func(e []model.Event) []model.Event {
			p := e[1]
			p.ID = "reuse"
			p.ProcessName = "other.exe"
			p.ParentProcessName = ""
			p.Timestamp = p.Timestamp.Add(30 * time.Second)
			return append(e, p)
		},
		"ambiguous-parent": func(e []model.Event) []model.Event { p := e[0]; p.ID = "duplicate"; return append(e, p) },
		"ambiguous-child": func(e []model.Event) []model.Event {
			p := e[2]
			p.ID = "second-child"
			p.PID = 999
			return append(e, p)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			events := mutate(activityFixture())
			for i := 0; i < 2; i++ {
				if got := BuildActivityChains("case-1", events); len(got) != 0 {
					t.Fatalf("unsupported instance chain: %+v", got)
				}
				for l, r := 0, len(events)-1; l < r; l, r = l+1, r-1 {
					events[l], events[r] = events[r], events[l]
				}
			}
		})
	}
}

func serviceFixture() []model.Event {
	base := activityFixture()[0]
	base.ID = "install"
	base.EventType = model.EventServiceInstall
	base.ProcessName = "worker.exe"
	base.ProcessPath = `C:\Tools\worker.exe`
	base.PID = 0
	proc := base
	proc.ID = "start"
	proc.EventType = model.EventProcessCreate
	proc.PID = 200
	proc.Timestamp = base.Timestamp.Add(time.Minute)
	net := proc
	net.ID = "network"
	net.EventType = model.EventNetworkConnection
	net.Timestamp = proc.Timestamp.Add(time.Minute)
	net.NetworkDest = "203.0.113.5"
	return []model.Event{base, proc, net}
}
func TestServiceAbstainsNameOnlyAndLabelsConfiguration(t *testing.T) {
	events := serviceFixture()
	got := BuildServiceChains("case-1", events)
	if len(got) != 1 || len(got[0].EventIDs) != 3 {
		t.Fatalf("valid configuration context lost: %+v", got)
	}
	if !strings.Contains(got[0].Description, "configuration") || strings.Contains(got[0].Description, "evidenced sequence") {
		t.Fatalf("configuration claimed as proven service execution: %+v", got)
	}
	for i := range events {
		events[i].ProcessPath = ""
	}
	if got := BuildServiceChains("case-1", events); len(got) != 0 {
		t.Fatalf("name-only service claimed execution: %+v", got)
	}
}

func TestServiceNetworkInstanceBoundaries(t *testing.T) {
	for name, mutate := range map[string]func([]model.Event) []model.Event{
		"pid-conflict": func(e []model.Event) []model.Event { e[2].PID = 900; return e },
		"missing-pid":  func(e []model.Event) []model.Event { e[2].PID = 0; return e },
		"guid-conflict": func(e []model.Event) []model.Event {
			e[1].Extra = map[string]string{"process_guid": "one"}
			e[2].Extra = map[string]string{"process_guid": "two"}
			return e
		},
		"collection-conflict": func(e []model.Event) []model.Event { e[2].CollectionID = "other"; return e },
		"case-conflict":       func(e []model.Event) []model.Event { e[2].CaseID = "other"; return e },
		"time-tie":            func(e []model.Event) []model.Event { e[2].Timestamp = e[1].Timestamp; return e },
		"exit": func(e []model.Event) []model.Event {
			e[1].Extra = map[string]string{"exit_time": e[2].Timestamp.Format(time.RFC3339)}
			return e
		},
		"reuse": func(e []model.Event) []model.Event {
			p := e[1]
			p.ID = "reuse"
			p.ProcessName = "other.exe"
			p.ProcessPath = `C:\Tools\other.exe`
			p.Timestamp = p.Timestamp.Add(30 * time.Second)
			return append(e, p)
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := BuildServiceChains("case-1", mutate(serviceFixture()))
			if len(got) != 1 || len(got[0].EventIDs) != 2 {
				t.Fatalf("unsupported network instance joined: %+v", got)
			}
		})
	}
}
func TestServiceConfigurationScopeBoundaries(t *testing.T) {
	for name, mutate := range map[string]func([]model.Event) []model.Event{
		"collection":   func(e []model.Event) []model.Event { e[1].CollectionID = "other"; return e },
		"case":         func(e []model.Event) []model.Event { e[1].CaseID = "other"; return e },
		"missing-time": func(e []model.Event) []model.Event { e[0].Timestamp = time.Time{}; return e },
		"missing-collection": func(e []model.Event) []model.Event {
			for i := range e {
				e[i].CollectionID = ""
			}
			return e
		},
		"ambiguous": func(e []model.Event) []model.Event { p := e[1]; p.ID = "other-start"; p.PID = 800; return append(e, p) },
	} {
		t.Run(name, func(t *testing.T) {
			if got := BuildServiceChains("case-1", mutate(serviceFixture())); len(got) != 0 {
				t.Fatalf("unsupported configuration scope joined: %+v", got)
			}
		})
	}
}

func TestActivityRetainsIdentifiedNetworkAndDisclosedConfiguration(t *testing.T) {
	events := activityFixture()
	for i := range events {
		events[i].ProcessPath = `C:\Tools\` + events[i].ProcessName
		events[i].Extra["logon_id"] = "0x10"
	}
	logon := events[0]
	logon.ID = "logon"
	logon.EventType = model.EventLogonSuccess
	logon.Timestamp = logon.Timestamp.Add(-time.Minute)
	config := events[2]
	config.ID = "configuration"
	config.EventType = model.EventRegistryRunKey
	config.PID = 900
	config.Timestamp = config.Timestamp.Add(time.Minute)
	// A configuration PID is the WRITER, never the configured target instance.
	config.Extra = map[string]string{"value_data": events[2].ProcessPath, "writing_process": `C:\Tools\configurator.exe`}
	net := events[2]
	net.ID = "network"
	net.EventType = model.EventNetworkConnection
	net.Timestamp = net.Timestamp.Add(2 * time.Minute)
	events = append(events, logon, config, net)
	got := BuildActivityChains("case-1", events)
	if len(got) != 1 || len(got[0].EventIDs) != 6 {
		t.Fatalf("supported context lost: %+v", got)
	}
	if !strings.Contains(got[0].Description, "configuration") || strings.Contains(got[0].Description, "evidenced sequence") {
		t.Fatalf("context promoted to proof: %+v", got)
	}
	for i := range events {
		if events[i].ID == "network" {
			events[i].PID = 901
		}
	}
	got = BuildActivityChains("case-1", events)
	if len(got) != 1 || len(got[0].EventIDs) != 5 {
		t.Fatalf("conflicting network retained: %+v", got)
	}
}

func TestChainsUseUnambiguousAcquisitionHostNames(t *testing.T) {
	events := activityFixture()
	events[1].Host = "host01.corp.example"
	if got := BuildActivityChains("case-1", events); len(got) != 1 {
		t.Fatalf("compatible acquisition alias lost: %+v", got)
	}
	other := events[0]
	other.ID = "other-host"
	other.Host = "host01.other.example"
	other.EventType = model.EventRegistryKeyLastWrite
	events = append(events, other)
	if got := BuildActivityChains("case-1", events); len(got) != 0 {
		t.Fatalf("ambiguous short host resolved: %+v", got)
	}
}

func TestChainShuffleAndFilteredSourceParity(t *testing.T) {
	activity := activityFixture()
	service := serviceFixture()
	for i := range service {
		service[i].ID = "service-" + service[i].ID
	}
	events := append(activity, service...)
	wantA := BuildActivityChains("case-1", events)
	wantS := BuildServiceChains("case-1", events)
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 30; i++ {
		rng.Shuffle(len(events), func(i, j int) { events[i], events[j] = events[j], events[i] })
		if got := BuildActivityChains("case-1", events); !reflect.DeepEqual(got, wantA) {
			t.Fatalf("activity changed under shuffle: %+v", got)
		}
		if got := BuildServiceChains("case-1", events); !reflect.DeepEqual(got, wantS) {
			t.Fatalf("service changed under shuffle: %+v", got)
		}
		got, err := RunFrom("case-1", model.SliceSource(events))
		if err != nil {
			t.Fatal(err)
		}
		a, s := 0, 0
		for _, c := range got {
			switch c.Type {
			case model.CorrelationActivityChain:
				a++
			case model.CorrelationServiceChain:
				s++
			}
		}
		if a != len(wantA) || s != len(wantS) {
			t.Fatalf("source parity: activity=%d service=%d", a, s)
		}
	}
}
func TestConfigurationAndNetworkRetainOnlySupportedContext(t *testing.T) {
	for name, mutate := range map[string]func(*model.Event){
		"wrong-host":         func(e *model.Event) { e.Host = "host02" },
		"unknown-collection": func(e *model.Event) { e.CollectionID = "" },
		"wrong-case":         func(e *model.Event) { e.CaseID = "other" },
		"missing-time":       func(e *model.Event) { e.Timestamp = time.Time{} },
		"same-time":          func(e *model.Event) { e.Timestamp = activityFixture()[2].Timestamp },
		"distant":            func(e *model.Event) { e.Timestamp = e.Timestamp.Add(3 * time.Hour) },
		"different-path":     func(e *model.Event) { e.ProcessPath = `C:\Other\worker.exe` },
	} {
		t.Run(name, func(t *testing.T) {
			events := activityFixture()
			events[2].ProcessPath = `C:\Tools\worker.exe`
			config := events[2]
			config.ID = "config"
			config.EventType = model.EventServiceInstall
			config.Timestamp = config.Timestamp.Add(time.Minute)
			mutate(&config)
			events = append(events, config)
			got := BuildActivityChains("case-1", events)
			if len(got) != 1 || len(got[0].EventIDs) != 3 {
				t.Fatalf("unsupported config joined: %+v", got)
			}
		})
	}
}
