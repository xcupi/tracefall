package correlate

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"

	"tracefall/internal/model"
	"tracefall/internal/store"
)

// These are normalized software fixtures, not native-reader fidelity proof.
func TestCredentialValidatedAliasReacquisition(t *testing.T) {
	for _, scenario := range []string{"short control", "proven alias", "fqdn control", "unproven alias", "fqdn collision", "recorded domain contradiction", "machine contradiction", "shared IP", "unknown host"} {
		t.Run(scenario, func(t *testing.T) {
			es := credentialIdentityFixture()
			want := 1
			if scenario != "short control" {
				es = append(es, identityFact("alias-proof", "one", "host01.corp.example"))
			}
			switch scenario {
			case "fqdn control":
				es[3].Host = "host01.corp.example"
			case "unproven alias":
				es[4].CollectionID = "three"
				es[3].Host = "host01.corp.example"
				want = 0
			case "fqdn collision":
				es = append(es, identityFact("collision", "three", "host01.other.example"))
				want = 0
			case "recorded domain contradiction":
				es[3].Extra["domain"] = "other.example"
				want = 0
			case "machine contradiction":
				es[4].Extra = map[string]string{"os_current_build": "one"}
				es[3].Extra["os_current_build"] = "two"
				want = 0
			case "shared IP":
				es[3].Host = "host02"
				es[4].EventType = model.EventRegistryKeyLastWrite
				es[4].Extra = map[string]string{"registry_value_name": "ComputerName", "ip_origin": "203.0.113.5=static"}
				other := identityFact("other-owner", "two", "host02")
				other.EventType = model.EventRegistryKeyLastWrite
				other.Extra = map[string]string{"registry_value_name": "ComputerName", "ip_origin": "203.0.113.5=static"}
				es = append(es, other)
				want = 0
			case "unknown host":
				es[3].Host = ""
				want = 0
			}
			var baseline []model.Correlation
			for _, reverse := range []bool{false, true} {
				ordered := append([]model.Event(nil), es...)
				if reverse {
					for i, j := 0, len(ordered)-1; i < j; i, j = i+1, j-1 {
						ordered[i], ordered[j] = ordered[j], ordered[i]
					}
				}
				s, err := store.Open(filepath.Join(t.TempDir(), "case.db"))
				if err != nil {
					t.Fatal(err)
				}
				must := func(err error) {
					t.Helper()
					if err != nil {
						t.Fatal(err)
					}
				}
				must(s.CreateCase(model.Case{ID: "case", Name: "normalized alias reacquisition"}))
				cols := map[string]bool{}
				for i := range ordered {
					col := ordered[i].CollectionID
					if !cols[col] {
						must(s.CreateCollectionWithSourceFiles(model.Collection{ID: col, CaseID: "case"}, []model.SourceFile{{ID: col + "-source", CaseID: "case", CollectionID: col}}))
						cols[col] = true
					}
					ordered[i].SourceFileID = col + "-source"
					ordered[i].DedupHash = ordered[i].ID
				}
				must(s.SaveEvents(ordered))
				before, _ := json.Marshal(ordered)
				persisted, err := RunFrom("case", s.EventSourceFor("case"))
				must(err)
				must(s.Close())
				for path, cs := range map[string][]model.Correlation{"Run": Run("case", ordered), "persisted RunFrom": persisted} {
					chains := []model.Correlation{}
					for _, c := range cs {
						if c.Type == model.CorrelationCredentialChain {
							chains = append(chains, c)
						}
					}
					if len(chains) != want {
						t.Errorf("reverse=%v %s credential chains=%d want=%d", reverse, path, len(chains), want)
					}
					if baseline == nil {
						baseline = chains
					} else if !reflect.DeepEqual(baseline, chains) {
						t.Errorf("reverse=%v %s nondeterministic credential chains", reverse, path)
					}
				}
				after, _ := json.Marshal(ordered)
				if string(before) != string(after) {
					t.Fatal("recorded facts mutated")
				}
			}
		})
	}
}
