package correlate

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"

	"tracefall/internal/model"
	"tracefall/internal/store"
)

// These normalized fixtures exercise identity decisions, not native-reader fidelity.
func TestExplicitCredentialTargetIdentity(t *testing.T) {
	for _, proof := range []string{"local", "earlier"} {
		for _, kind := range []string{"short", "fqdn", "remote", "unresolved", "empty", "dash", "localhost", "collision", "domain contradiction", "unproven", "session", "pid", "account", "collection", "machine conflict"} {
			t.Run(proof+"/"+kind, func(t *testing.T) {
				es := explicitSequence()
				es[0].Extra["target_server_name"] = "host01"
				fact := func(id, collection, host string) model.Event {
					return model.Event{ID: id, CaseID: "case01", CollectionID: collection, Host: host, EventType: model.EventFileCreate}
				}
				collection := "collection01"
				if proof == "earlier" {
					collection = "prior"
					es = append(es, fact("prior-short", collection, "host01"))
				}
				es = append(es, fact("alias-proof", collection, "host01.corp.example"))
				want := 0
				switch kind {
				case "short":
					want = 1
				case "fqdn":
					es[0].Extra["target_server_name"] = "host01.corp.example"
					want = 1
				case "remote":
					es[0].Extra["target_server_name"] = "host02"
					es = append(es, fact("remote", "remote", "host02"))
				case "unresolved":
					es[0].Extra["target_server_name"] = "not-in-inventory"
				case "empty":
					es[0].Extra["target_server_name"] = ""
					want = 1
				case "dash":
					es[0].Extra["target_server_name"] = "-"
					want = 1
				case "localhost":
					es[0].Extra["target_server_name"] = "localhost"
					want = 1
				case "collision":
					es = append(es, fact("collision", "other", "host01.other.example"))
				case "domain contradiction":
					es[0].Extra["domain"] = "other.example"
				case "unproven":
					es = explicitSequence()
					es[0].Extra["target_server_name"] = "host01.corp.example"
					es = append(es, fact("separate-fqdn", "other", "host01.corp.example"))
				case "session":
					es[0].Extra["target_logon_id"] = "0x456"
				case "pid":
					es[2].PID = 999
				case "account":
					es[1].User = "alice"
				case "collection":
					es[1].CollectionID = "other"
				case "machine conflict":
					es[0].Extra["os_current_build"] = "one"
					es[1].Extra["os_current_build"] = "two"
				}
				s, err := store.Open(filepath.Join(t.TempDir(), "case.db"))
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				must := func(err error) {
					t.Helper()
					if err != nil {
						t.Fatal(err)
					}
				}
				must(s.CreateCase(model.Case{ID: "case01", Name: "synthetic explicit target identity"}))
				cols := map[string]bool{}
				for i := range es {
					col := es[i].CollectionID
					if !cols[col] {
						must(s.CreateCollectionWithSourceFiles(model.Collection{ID: col, CaseID: "case01"}, []model.SourceFile{{ID: col + "-source", CaseID: "case01", CollectionID: col}}))
						cols[col] = true
					}
					es[i].SourceFileID = col + "-source"
					es[i].DedupHash = es[i].ID
				}
				must(s.SaveEvents(es))
				before, err := json.Marshal(es)
				must(err)
				persisted, err := RunFrom("case01", s.EventSourceFor("case01"))
				must(err)
				reversed := append([]model.Event(nil), es...)
				for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
					reversed[i], reversed[j] = reversed[j], reversed[i]
				}
				onlyCredentials := func(cs []model.Correlation) []model.Correlation {
					var out []model.Correlation
					for _, c := range cs {
						if c.Type == model.CorrelationCredentialChain {
							// Direct builders leave ID assignment to RunFrom.
							if c.ID == "" {
								c.ID = model.StableID("corr", append([]string{c.CaseID, c.Type}, c.EventIDs...)...)
							}
							out = append(out, c)
						}
					}
					return out
				}
				direct := onlyCredentials(BuildCredentialChains("case01", es))
				paths := map[string][]model.Correlation{"direct": direct, "Run": onlyCredentials(Run("case01", es)), "persisted RunFrom": onlyCredentials(persisted), "reverse direct": onlyCredentials(BuildCredentialChains("case01", reversed)), "reverse Run": onlyCredentials(Run("case01", reversed))}
				for path, got := range paths {
					if len(got) != want {
						t.Errorf("%s chains=%d want=%d", path, len(got), want)
					}
					if !reflect.DeepEqual(direct, got) {
						t.Errorf("%s differs from direct (including stable IDs): %+v vs %+v", path, got, direct)
					}
				}
				after, err := json.Marshal(es)
				must(err)
				if string(before) != string(after) {
					t.Fatal("recorded host/target facts mutated")
				}
			})
		}
	}
}
