package correlate

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/store"
)

func credentialIdentityFixture() []model.Event {
	var es []model.Event
	at := time.Date(2026, 1, 15, 9, 0, 0, 0, time.UTC)
	for i := 0; i < 4; i++ {
		e := model.Event{ID: fmt.Sprintf("auth-%d", i), CaseID: "case", CollectionID: "one", Host: "host01", EventType: model.EventLogonFailure, User: "alice", NetworkSource: "203.0.113.9", Timestamp: at.Add(time.Duration(i) * time.Minute), Extra: map[string]string{}}
		if i == 3 {
			e.EventType = model.EventLogonSuccess
			e.CollectionID = "two"
		}
		es = append(es, e)
	}
	return es
}

func identityFact(id, collection, host string) model.Event {
	return model.Event{ID: id, CaseID: "case", CollectionID: collection, Host: host, EventType: model.EventFileCreate}
}

func TestCredentialCasewideIdentity(t *testing.T) {
	for _, kind := range []string{"ambiguous", "validated alias", "reacquisition", "unknown host", "domain conflict", "source conflict", "subject conflict", "machine conflict"} {
		t.Run(kind, func(t *testing.T) {
			es := credentialIdentityFixture()
			want := 0
			switch kind {
			case "ambiguous":
				es = append(es, identityFact("fqdn-a", "three", "host01.a.example"), identityFact("fqdn-b", "four", "host01.b.example"))
			case "validated alias":
				es[3].Host = "host01.corp.example"
				es[3].CollectionID = "one"
				want = 1
			case "reacquisition":
				want = 1
			case "unknown host":
				for i := range es {
					es[i].Host = ""
				}
			case "domain conflict":
				for i := 0; i < 3; i++ {
					es[i].Extra["target_domain"] = "a"
				}
				es[3].Extra["target_domain"] = "b"
			case "source conflict":
				es[3].NetworkSource = "203.0.113.10"
			case "subject conflict":
				for i := 0; i < 3; i++ {
					es[i].Extra["subject_logon_id"] = "0x1"
				}
				es[3].Extra["subject_logon_id"] = "0x2"
			case "machine conflict":
				a, b := identityFact("machine-a", "one", "host01"), identityFact("machine-b", "two", "host01")
				a.Extra = map[string]string{"os_current_build": "one"}
				b.Extra = map[string]string{"os_current_build": "two"}
				es = append(es, a, b)
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
			must(s.CreateCase(model.Case{ID: "case", Name: "synthetic normalized identity contract"}))
			cols := map[string]bool{}
			for i := range es {
				col := es[i].CollectionID
				if !cols[col] {
					must(s.CreateCollectionWithSourceFiles(model.Collection{ID: col, CaseID: "case"}, []model.SourceFile{{ID: col + "-source", CaseID: "case", CollectionID: col}}))
					cols[col] = true
				}
				es[i].SourceFileID = col + "-source"
				es[i].DedupHash = es[i].ID
			}
			must(s.SaveEvents(es))
			// Compare immutability after fixture persistence fields have been assigned.
			before, _ := json.Marshal(es)
			persisted, err := RunFrom("case", s.EventSourceFor("case"))
			must(err)
			reversed := append([]model.Event(nil), es...)
			for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
				reversed[i], reversed[j] = reversed[j], reversed[i]
			}
			for path, cs := range map[string][]model.Correlation{"direct": BuildCredentialChains("case", es), "Run": Run("case", es), "filtered store": persisted, "reversed": Run("case", reversed)} {
				n := 0
				for _, c := range cs {
					if c.Type == model.CorrelationCredentialChain {
						n++
					}
				}
				if n != want {
					t.Errorf("%s credential chains=%d want=%d: %+v", path, n, want, cs)
				}
			}
			after, _ := json.Marshal(es)
			if string(before) != string(after) {
				t.Fatal("recorded facts mutated")
			}
		})
	}
}
