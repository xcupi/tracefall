package detect_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
	"tracefall/internal/correlate"
	"tracefall/internal/detect"
	"tracefall/internal/model"
	"tracefall/internal/parsers/winevent"
)

func authIPEvents(t *testing.T, failures []string, success string) []model.Event {
	t.Helper()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var es []model.Event
	for i, ip := range append(append([]string{}, failures...), success) {
		id := 4771
		if i == len(failures) {
			id = 4624
		}
		e := model.Event{ID: fmt.Sprint("auth-", i), CaseID: "case", CollectionID: "acq", Host: "host01", Timestamp: base.Add(time.Duration(i) * time.Minute), ArtifactType: model.ArtifactWindowsEventLog, Extra: map[string]string{}}
		if !winevent.Normalize(&e, winevent.Input{Channel: "Security", Provider: "Microsoft-Windows-Security-Auditing", EventID: id, Data: map[string]string{"TargetUserName": "alice", "IpAddress": ip, "Status": "0x18", "LogonType": "3"}}) {
			t.Fatal("unmapped authentication fixture")
		}
		es = append(es, e)
	}
	return es
}

func assertIPSequence(t *testing.T, es []model.Event, want int) {
	t.Helper()
	before, _ := json.Marshal(es)
	found := 0
	for _, f := range detect.Run("case", es) {
		if f.RuleID == "brute-force-then-success" {
			found++
			if !reflect.DeepEqual(f.SupportingEvents, []string{"auth-0", "auth-1", "auth-2", "auth-3"}) {
				t.Fatal(f.SupportingEvents)
			}
		}
	}
	if found != want {
		t.Fatalf("detect sequences=%d want=%d", found, want)
	}
	chains := correlate.BuildCredentialChains("case", es)
	found = 0
	for _, c := range chains {
		if strings.HasPrefix(c.Title, "Brute-force chain:") {
			found++
		}
	}
	if found != want {
		t.Fatalf("correlate sequences=%d want=%d: %+v", found, want, chains)
	}
	after, _ := json.Marshal(es)
	if string(before) != string(after) {
		t.Fatal("source fields changed")
	}
}

func TestEquivalentIPNormalizedAuthentication(t *testing.T) {
	es := authIPEvents(t, []string{"::ffff:10.0.0.5", "::ffff:10.0.0.5", "::ffff:10.0.0.5"}, "10.0.0.5")
	assertIPSequence(t, es, 1)
}
func TestEquivalentIPMixedFailureStream(t *testing.T) {
	assertIPSequence(t, authIPEvents(t, []string{"::ffff:10.0.0.5", "10.0.0.5", "::ffff:a00:5"}, "10.0.0.5"), 1)
}
func TestEquivalentIPProductionControls(t *testing.T) {
	for _, tc := range []struct {
		name, a, b string
		want       int
	}{
		{"plain", "10.0.0.5", "10.0.0.5", 1},
		{"different", "10.0.0.5", "10.0.0.6", 0},
		{"different mapped", "::ffff:10.0.0.5", "10.0.0.6", 0},
		{"IPv6 alternate", "2001:0DB8:0:0:0:0:0:5", "2001:db8::5", 1},
		{"zone contradiction", "fe80::1%ifaceA", "fe80::1%ifaceB", 0},
		{"hostname literal", "HOST01", "host01", 0},
	} {
		t.Run(tc.name, func(t *testing.T) { assertIPSequence(t, authIPEvents(t, []string{tc.a, tc.a, tc.a}, tc.b), tc.want) })
	}
	for _, field := range []string{"target_domain", "subject_logon_id"} {
		t.Run(field, func(t *testing.T) {
			es := authIPEvents(t, []string{"::ffff:10.0.0.5", "::ffff:10.0.0.5", "::ffff:10.0.0.5"}, "10.0.0.5")
			for i := range es {
				es[i].Extra[field] = "one"
			}
			es[3].Extra[field] = "two"
			assertIPSequence(t, es, 0)
		})
	}
}

// Exercise actual RunFrom loading, once with its declared filters and once
// with an intentionally unfiltered source, not just the rule's helper.
type allComparisonSource struct{ model.SliceSource }

func (s allComparisonSource) Load(model.EventFilter) ([]model.Event, error) {
	return []model.Event(s.SliceSource), nil
}
func TestComparisonFixesEngineInputsParity(t *testing.T) {
	ip := authIPEvents(t, []string{"::ffff:10.0.0.5", "10.0.0.5", "::ffff:a00:5"}, "10.0.0.5")
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	temporal := []model.Event{
		{ID: "exec", CaseID: "case", CollectionID: "acq1", Host: "host01", EventType: model.EventProcessCreate, ProcessName: "agent.exe", ProcessPath: `C:\Tools\agent.exe`, CommandLine: `C:\Tools\agent.exe -ordinary`, Timestamp: base},
		{ID: "config", CaseID: "case", CollectionID: "acq2", Host: "host01", EventType: model.EventRegistryRunKey, ProcessName: "agent.exe", ProcessPath: `C:\Tools\agent.exe`, Timestamp: base.Add(time.Minute)},
	}
	for _, tc := range []struct {
		name, rule string
		es         []model.Event
	}{{"IP", "brute-force-then-success", ip}, {"temporal", "execution-persistence-temporal", temporal}} {
		t.Run(tc.name, func(t *testing.T) {
			filtered, err := detect.RunFrom("case", model.SliceSource(tc.es))
			if err != nil {
				t.Fatal(err)
			}
			full, err := detect.RunFrom("case", allComparisonSource{model.SliceSource(tc.es)})
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			for i := range filtered {
				filtered[i].CreatedAt = time.Time{}
				if filtered[i].RuleID == tc.rule {
					count++
				}
			}
			for i := range full {
				full[i].CreatedAt = time.Time{}
			}
			if count != 1 || !reflect.DeepEqual(filtered, full) {
				t.Fatalf("engine parity/count failed: filtered=%+v full=%+v", filtered, full)
			}
		})
	}
}
