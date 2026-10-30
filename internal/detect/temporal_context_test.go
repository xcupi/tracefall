package detect

import (
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"
	"tracefall/internal/hostid"
	"tracefall/internal/model"
)

func temporalPair() []model.Event {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return []model.Event{
		{ID: "exec", CaseID: "case", CollectionID: "acq", Host: "host01", EventType: model.EventProcessCreate, ProcessName: "agent.exe", ProcessPath: `C:\Tools\agent.exe`, Timestamp: base},
		{ID: "config", CaseID: "case", CollectionID: "acq", Host: "host01", EventType: model.EventRegistryRunKey, ProcessName: "agent.exe", ProcessPath: `C:\Other\agent.exe`, Timestamp: base.Add(time.Minute)},
	}
}

func TestTemporalContextConflictingPathsAbstain(t *testing.T) {
	if got := (executionThenPersistence{}).Evaluate(temporalPair()); len(got) != 0 {
		t.Fatalf("conflicting full paths joined: %+v", got)
	}
}
func TestTemporalContextPolicy(t *testing.T) {
	tests := []struct {
		name                 string
		change               func([]model.Event)
		count                int
		severity, confidence string
	}{
		{"exact path context", func(es []model.Event) { es[1].ProcessPath = es[0].ProcessPath }, 1, "medium", "medium"},
		{"basename uncertain", func(es []model.Event) { es[0].ProcessPath = ""; es[1].ProcessPath = "" }, 1, "low", "low"},
		{"case insensitive", func(es []model.Event) {
			es[1].ProcessPath = `c:\TOOLS\AGENT.EXE`
			es[1].ProcessName = "AGENT.EXE"
			es[1].Host = "HOST01"
		}, 1, "medium", "medium"},
		{"cross acquisition exact", func(es []model.Event) { es[1].ProcessPath = es[0].ProcessPath; es[1].CollectionID = "acq2" }, 1, "medium", "medium"},
		{"unknown acquisition basename", func(es []model.Event) {
			es[0].CollectionID = ""
			es[1].CollectionID = ""
			es[0].ProcessPath = ""
			es[1].ProcessPath = ""
		}, 0, "", ""},
		{"cross acquisition basename", func(es []model.Event) { es[0].ProcessPath = ""; es[1].ProcessPath = ""; es[1].CollectionID = "acq2" }, 0, "", ""},
		{"unknown hosts", func(es []model.Event) { es[0].Host = ""; es[1].Host = "" }, 0, "", ""},
		{"case contradiction", func(es []model.Event) { es[1].CaseID = "other" }, 0, "", ""},
		{"memory artifact", func(es []model.Event) {
			es[1].ProcessPath = es[0].ProcessPath
			es[0].ArtifactType = model.ArtifactMemoryAnalysis
		}, 0, "", ""},
		{"memory basis", func(es []model.Event) {
			es[1].ProcessPath = es[0].ProcessPath
			es[0].Extra = map[string]string{"timestamp_basis": "memory_snapshot"}
		}, 0, "", ""},
		{"undated", func(es []model.Event) { es[0].Timestamp = time.Time{} }, 0, "", ""},
		{"equal", func(es []model.Event) { es[0].Timestamp = es[1].Timestamp }, 0, "", ""},
		{"reversed", func(es []model.Event) { es[0].Timestamp = es[1].Timestamp.Add(time.Second) }, 0, "", ""},
		{"outside window", func(es []model.Event) { es[1].Timestamp = es[0].Timestamp.Add(16 * time.Minute) }, 0, "", ""},
		{"prefetch approximate", func(es []model.Event) {
			es[1].ProcessPath = es[0].ProcessPath
			es[0].EventType = model.EventPrefetchExecution
		}, 1, "low", "low"},
		{"relative unknown", func(es []model.Event) { es[0].ProcessPath = `Tools\agent.exe`; es[1].ProcessPath = `Other\agent.exe` }, 1, "low", "low"},
		{"file path target", func(es []model.Event) {
			es[0].ProcessPath = ""
			es[0].FilePath = `C:\Tools\agent.exe`
			es[1].ProcessPath = ""
			es[1].FilePath = es[0].FilePath
		}, 1, "medium", "medium"},
		{"task xml not target", func(es []model.Event) {
			es[1].EventType = model.EventScheduledTaskCreate
			es[1].ProcessPath = ""
			es[1].FilePath = `C:\Windows\Tasks\agent.exe`
		}, 1, "low", "low"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			es := temporalPair()
			es[1].ProcessPath = es[0].ProcessPath
			tt.change(es)
			before := mustJSON(t, es)
			got := (executionThenPersistence{}).Evaluate(es)
			if len(got) != tt.count {
				t.Fatalf("count=%d want=%d: %+v", len(got), tt.count, got)
			}
			if len(got) > 0 {
				f := got[0]
				if f.Severity != tt.severity || f.Confidence != tt.confidence {
					t.Fatalf("levels=%s/%s want=%s/%s", f.Severity, f.Confidence, tt.severity, tt.confidence)
				}
				if !reflect.DeepEqual(f.SupportingEvents, []string{"exec", "config"}) {
					t.Fatal(f.SupportingEvents)
				}
				if !strings.Contains(f.Description, "does not establish") || strings.Contains(f.Title, "established persistence") {
					t.Fatal(f.Description)
				}
			}
			if mustJSON(t, es) != before {
				t.Fatal("source evidence mutated")
			}
		})
	}
}

func TestTemporalContextIdentityInventoryAndInputs(t *testing.T) {
	es := temporalPair()
	es[1].ProcessPath = es[0].ProcessPath
	es = append(es, model.Event{ID: "metadata-a", CaseID: "case", CollectionID: "acq", Host: "host01", EventType: "metadata", Extra: map[string]string{"domain": "one.example"}}, model.Event{ID: "metadata-b", CaseID: "case", CollectionID: "acq2", Host: "host01", EventType: "metadata", Extra: map[string]string{"domain": "two.example"}})
	if got := (executionThenPersistence{}).Evaluate(es); len(got) != 0 {
		t.Fatal("contradictory case-wide metadata joined", got)
	}
	filtered, err := model.SliceSource(es).Load((executionThenPersistence{}).Inputs())
	if err != nil {
		t.Fatal(err)
	}
	inventory := hostid.Inventory{}
	for _, e := range es {
		inventory.Add(e)
	}
	filtered = append(filtered, inventory.Events()...)
	if got := (executionThenPersistence{}).Evaluate(filtered); len(got) != 0 {
		t.Fatal("Inputs dropped identity blockers", got)
	}
	for _, f := range Run("case", es) {
		if f.RuleID == "execution-persistence-temporal" {
			t.Fatal("engine dropped blockers", f)
		}
	}
}

func TestTemporalContextDeterministicPreference(t *testing.T) {
	es := temporalPair()
	es[1].ProcessPath = es[0].ProcessPath
	exact := es[0]
	exact.ID = "a-exact"
	es[0].ID = "z-exact"
	unknown := es[0]
	unknown.ID = "closer-unknown"
	unknown.ProcessPath = ""
	unknown.Timestamp = unknown.Timestamp.Add(30 * time.Second)
	es = append(es, exact, unknown)
	for i := 0; i < 20; i++ {
		rand.New(rand.NewSource(int64(i))).Shuffle(len(es), func(i, j int) { es[i], es[j] = es[j], es[i] })
		got := (executionThenPersistence{}).Evaluate(es)
		if len(got) != 1 || got[0].SupportingEvents[0] != "a-exact" {
			t.Fatalf("unstable/nonexact choice: %+v", got)
		}
	}
}
func TestTemporalContextPathAndIdentityBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func([]model.Event)
		want   int
	}{
		{"wrong target", func(es []model.Event) { es[1].ProcessName = "other.exe" }, 0},
		{"wrong host", func(es []model.Event) { es[1].Host = "host02" }, 0},
		{"missing acquisition cross", func(es []model.Event) { es[1].CollectionID = "" }, 0},
		{"unknown hosts cross acquisition", func(es []model.Event) { es[0].Host = ""; es[1].Host = ""; es[1].CollectionID = "acq2" }, 0},
		{"conflicting fields", func(es []model.Event) { es[1].FilePath = `C:\Other\agent.exe` }, 0},
		{"memory config", func(es []model.Event) { es[1].ArtifactType = model.ArtifactMemoryAnalysis }, 0},
		{"snapshot config", func(es []model.Event) { es[1].Extra = map[string]string{"timestamp_basis": "memory_snapshot"} }, 0},
		{"undated config", func(es []model.Event) { es[1].Timestamp = time.Time{} }, 0},
		{"recorded boundary", func(es []model.Event) { es[1].Timestamp = es[0].Timestamp.Add(15 * time.Minute) }, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			es := temporalPair()
			es[1].ProcessPath = es[0].ProcessPath
			tc.change(es)
			if got := (executionThenPersistence{}).Evaluate(es); len(got) != tc.want {
				t.Fatalf("count=%d want=%d: %+v", len(got), tc.want, got)
			}
		})
	}
	for _, path := range []string{`agent.exe`, `relative\agent.exe`, `%TEMP%\agent.exe`, `C:\Tools\..\Tools\agent.exe`, "C:\\Tools\x0b\\agent.exe"} {
		t.Run(path, func(t *testing.T) {
			es := temporalPair()
			es[0].ProcessPath = path
			es[1].ProcessPath = path
			got := (executionThenPersistence{}).Evaluate(es)
			if len(got) != 1 || got[0].Severity != "low" || got[0].Confidence != "low" {
				t.Fatalf("untrustworthy path escalated: %+v", got)
			}
		})
	}
}

func TestTemporalContextValidatedAliasCrossAcquisition(t *testing.T) {
	es := temporalPair()
	es[1].ProcessPath = es[0].ProcessPath
	es[1].CollectionID = "acq2"
	es[1].Host = "host01.example.test"
	es = append(es, model.Event{ID: "alias-proof", CaseID: "case", CollectionID: "acq", Host: "host01.example.test", EventType: "identity"})
	if got := (executionThenPersistence{}).Evaluate(es); len(got) != 1 {
		t.Fatal("validated alias context lost", got)
	}
	es = append(es, model.Event{ID: "ambiguous", CaseID: "case", CollectionID: "acq3", Host: "host01.other.test", EventType: "identity"})
	if got := (executionThenPersistence{}).Evaluate(es); len(got) != 0 {
		t.Fatal("ambiguous alias joined", got)
	}
}

func TestTemporalContextPrefersExactPrefetchOverUnknownProcess(t *testing.T) {
	es := temporalPair()
	es[1].ProcessPath = es[0].ProcessPath
	pf := es[0]
	pf.ID = "prefetch"
	pf.EventType = model.EventPrefetchExecution
	es[0].ProcessPath = ""
	es = append(es, pf)
	got := (executionThenPersistence{}).Evaluate(es)
	if len(got) != 1 || got[0].SupportingEvents[0] != "prefetch" || got[0].Confidence != "low" || !strings.Contains(got[0].Description, "not a precise process-start instant") {
		t.Fatal(got)
	}
}
