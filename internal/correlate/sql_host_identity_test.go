package correlate

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"tracefall/internal/model"
	"tracefall/internal/store"
)

func TestSQLCasewideIdentity(t *testing.T) {
	for _, flow := range []string{"client", "os"} {
		for _, kind := range []string{"ambiguous", "validated alias", "unknown host", "unknown collection", "other case", "machine conflict"} {
			t.Run(flow+"/"+kind, func(t *testing.T) {
				es := sqlOSFixture()
				if flow == "client" {
					es = sqlFixture()
				}
				// A same-machine acquisition can establish short/FQDN equivalence.
				for i := range es {
					es[i].Host = "host01"
				}
				if flow == "client" {
					es[1].Extra["sql_server_host"] = "host01"
				}
				want := 0
				switch kind {
				case "ambiguous":
					a, b := identityFact("fqdn-a", "three", "host01.a.example"), identityFact("fqdn-b", "four", "host01.b.example")
					a.CaseID = "case01"
					b.CaseID = "case01"
					es = append(es, a, b)
				case "validated alias":
					es[0].Host = "host01.corp.example"
					want = 1
				case "unknown host":
					for i := range es {
						es[i].Host = ""
					}
				case "unknown collection":
					for i := range es {
						es[i].CollectionID = ""
					}
				case "other case":
					es[0].CaseID = "case02"
				case "machine conflict":
					a, b := identityFact("machine-a", "collection01", "host01"), identityFact("machine-b", "collection01", "host01")
					a.CaseID = "case01"
					b.CaseID = "case01"
					a.Extra = map[string]string{"domain": "a.example"}
					b.Extra = map[string]string{"domain": "b.example"}
					es = append(es, a, b)
				}
				before, _ := json.Marshal(es)
				paths := map[string][]model.Correlation{"direct": buildSQLWindows("case01", es), "Run": sqlCorrelations(es)}
				afterDirect, _ := json.Marshal(es)
				if string(before) != string(afterDirect) {
					t.Fatal("recorded SQL/Windows facts mutated by direct/Run path")
				}
				for i, j := 0, len(es)-1; i < j; i, j = i+1, j-1 {
					es[i], es[j] = es[j], es[i]
				}
				paths["reversed"] = sqlCorrelations(es)
				before, _ = json.Marshal(es)
				if kind == "ambiguous" || kind == "validated alias" || kind == "machine conflict" {
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
					must(s.CreateCase(model.Case{ID: "case01", Name: "synthetic SQL identity contract"}))
					cols := map[string][]model.SourceFile{}
					for i := range es {
						if es[i].SourceFileID == "" {
							es[i].SourceFileID = es[i].ID + "-source"
						}
						cols[es[i].CollectionID] = append(cols[es[i].CollectionID], model.SourceFile{ID: es[i].SourceFileID, CaseID: "case01", CollectionID: es[i].CollectionID})
						es[i].DedupHash = es[i].ID
					}
					for col, files := range cols {
						must(s.CreateCollectionWithSourceFiles(model.Collection{ID: col, CaseID: "case01"}, files))
					}
					must(s.SaveEvents(es))
					cs, err := RunFrom("case01", s.EventSourceFor("case01"))
					must(err)
					for _, c := range cs {
						if c.Type == sqlClientCorrelation || c.Type == sqlOSCorrelation {
							paths["filtered store"] = append(paths["filtered store"], c)
						}
					}
					if _, ok := paths["filtered store"]; !ok {
						paths["filtered store"] = nil
					}
					before, _ = json.Marshal(es)
				}
				for path, cs := range paths {
					if len(cs) != want {
						t.Errorf("%s SQL chains=%d want=%d: %+v", path, len(cs), want, cs)
					}
				}
				after, _ := json.Marshal(es)
				if string(before) != string(after) {
					t.Fatal("recorded SQL/Windows facts mutated")
				}
			})
		}
	}
}
