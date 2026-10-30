package detect

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"tracefall/internal/hostid"
	"tracefall/internal/model"
)

// Every rule must give the same findings whether it reads the full event set
// or only the inputs it declares. A declared input that misses a type the
// rule reads would drop findings without any error; this test fails instead.
func TestRuleInputs_DeclaredFilterGivesTheSameFindingsAsTheFullSet(t *testing.T) {
	events := mixedEvents()
	src := model.SliceSource(events)
	for _, rule := range All() {
		filter := model.EventFilter{All: true}
		if in, ok := rule.(interface{ Inputs() model.EventFilter }); ok {
			filter = in.Inputs()
		}
		full, err := src.Load(model.EventFilter{All: true})
		if err != nil {
			t.Fatal(err)
		}
		typed, err := src.Load(filter)
		if err != nil {
			t.Fatal(err)
		}
		if in, ok := rule.(interface{ NeedsIdentityInventory() bool }); ok && in.NeedsIdentityInventory() {
			inventory := hostid.Inventory{}
			if err := src.Each(func(string) bool { return true }, func(e model.Event) error { inventory.Add(e); return nil }); err != nil {
				t.Fatal(err)
			}
			typed = append(typed, inventory.Events()...)
		}
		want := mustJSON(t, withoutCreatedAt(rule.Evaluate(full)))
		got := mustJSON(t, withoutCreatedAt(rule.Evaluate(typed)))
		if want != got {
			t.Errorf("rule %s: findings differ between the full set and its declared inputs", rule.ID())
		}
	}
}

// mixedEvents holds events of every type any rule reads, plus memory-analysis
// artifacts, spread over two hosts, so each filter is exercised on a set it
// does not fully cover.
func mixedEvents() []model.Event {
	types := []string{
		model.EventProcessCreate, model.EventPrefetchExecution, model.EventRegistryRunKey,
		model.EventScheduledTaskCreate, model.EventRegistryPersistence, model.EventServiceInstall,
		model.EventLogonFailure, model.EventLogonSuccess, model.EventLogonExplicitCreds,
		model.EventPrivilegedLogon, model.EventNetworkConnection, model.EventPowerShellScript,
		model.EventMemorySnapshot, model.EventMemoryInjection,
		"unrelated_event",
	}
	base := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	var out []model.Event
	n := 0
	for _, host := range []string{"host01", "host02"} {
		for ti, typ := range types {
			for k := 0; k < 3; k++ {
				n++
				artifact := model.ArtifactWindowsEventLog
				if ti%3 == 0 {
					artifact = model.ArtifactMemoryAnalysis
				}
				out = append(out, model.Event{
					ID:                fmt.Sprintf("e%03d", n),
					CaseID:            "case",
					CollectionID:      "col",
					Host:              host,
					EventType:         typ,
					ArtifactType:      artifact,
					ProcessName:       []string{"winword.exe", "powershell.exe", "cmd.exe"}[k],
					ParentProcessName: []string{"explorer.exe", "winword.exe", "services.exe"}[k],
					CommandLine:       "powershell -enc AAAA",
					User:              "alice",
					PID:               int64(100 + n),
					Timestamp:         base.Add(time.Duration(n) * time.Minute),
					Extra:             map[string]string{"protection": "PAGE_EXECUTE_READWRITE", "private_memory": "1"},
				})
			}
		}
	}
	return out
}

// withoutCreatedAt drops the wall-clock stamp every finding carries when it is
// built. It differs between two evaluations of the same rule by design, so it
// is not part of what must match.
func withoutCreatedAt(fs []model.Finding) []model.Finding {
	out := make([]model.Finding, len(fs))
	for i, f := range fs {
		f.CreatedAt = time.Time{}
		out[i] = f
	}
	return out
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
