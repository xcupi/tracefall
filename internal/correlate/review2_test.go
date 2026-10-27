package correlate

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
	"tracefall/internal/hostid"
	"tracefall/internal/model"
	"tracefall/internal/store"
)

func TestReview2UntypedMetadataParity(t *testing.T) {
	for _, field := range []string{"domain", "host_role", "os_product_name", "os_current_build"} {
		t.Run(field, func(t *testing.T) {
			es := review2DomainEvents("")[:2]
			es[1].Host = "host01"
			for i, v := range []string{"one", "two"} {
				es = append(es, model.Event{ID: v, CaseID: "case", CollectionID: "one", Host: "host01", EventType: model.EventFileCreate, Extra: map[string]string{field: v}})
				_ = i
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
			must(s.CreateCase(model.Case{ID: "case", Name: "normalized contract"}))
			must(s.CreateCollectionWithSourceFiles(model.Collection{ID: "one", CaseID: "case"}, []model.SourceFile{{ID: "source", CaseID: "case", CollectionID: "one"}}))
			for i := range es {
				es[i].SourceFileID = "source"
				es[i].DedupHash = es[i].ID
			}
			must(s.SaveEvents(es))
			for order := 0; order < 2; order++ {
				persisted, err := RunFrom("case", s.EventSourceFor("case"))
				must(err)
				for path, cs := range map[string][]model.Correlation{"direct": BuildProcessChains("case", es), "Run": Run("case", es), "store": persisted} {
					for _, c := range cs {
						if c.Type == model.CorrelationProcessChain {
							t.Fatalf("%s erased untyped %s contradiction: %+v", path, field, c)
						}
					}
				}
				es[0], es[len(es)-1] = es[len(es)-1], es[0]
			}
		})
	}
}

func review2DomainEvents(domain string) []model.Event {
	b := time.Date(2026, 1, 15, 9, 0, 0, 0, time.UTC)
	p := model.Event{ID: "parent", CaseID: "case", CollectionID: "one", Host: "host01", Timestamp: b, EventType: model.EventProcessCreate, ProcessName: "winword.exe", PID: 100, User: "alice"}
	c := p
	c.ID = "child"
	c.Host = "host01.domain-b.example"
	c.Timestamp = b.Add(time.Minute)
	c.ProcessName = "powershell.exe"
	c.ParentProcessName = "winword.exe"
	c.PID = 101
	c.PPID = 100
	c.ProcessPath = `C:\Tools\powershell.exe`
	m := reviewFact("machine", "host01", "one", "")
	m.Extra["domain"] = domain
	s := p
	s.ID = "service"
	s.EventType = model.EventServiceInstall
	s.ProcessName = "powershell.exe"
	s.ProcessPath = `C:\Tools\powershell.exe`
	s.Extra = map[string]string{"service_name": "worker"}
	n := c
	n.ID = "network"
	n.EventType = model.EventNetworkConnection
	n.Timestamp = b.Add(2 * time.Minute)
	return []model.Event{p, c, m, s, n}
}
func TestReview2DomainAliasAgreement(t *testing.T) {
	for _, domain := range []string{"domain-a.example", " DOMAIN-B.EXAMPLE "} {
		t.Run(domain, func(t *testing.T) {
			es := review2DomainEvents(domain)
			want := strings.Contains(domain, "DOMAIN-B")
			for order := 0; order < 2; order++ {
				names := hostid.AcquisitionNames(es)
				reg := hostid.Build(es)
				if (names["parent"] != "") != want || reg.AmbiguousName("host01") == want {
					t.Fatalf("domain decision disagrees: domain=%q names=%v ambiguous=%v", domain, names, reg.AmbiguousName("host01"))
				}
				for kind, cs := range map[string][]model.Correlation{"process": BuildProcessChains("case", es), "activity": BuildActivityChains("case", es), "service": BuildServiceChains("case", es)} {
					found := false
					for _, c := range cs {
						hasP, hasC := false, false
						for _, id := range c.EventIDs {
							hasP = hasP || id == "parent" || id == "service"
							hasC = hasC || id == "child"
						}
						found = found || (hasP && hasC)
					}
					if found != want {
						t.Fatalf("%s domain=%q linked=%v want=%v: %+v", kind, domain, found, want, cs)
					}
				}
				es[0], es[len(es)-1] = es[len(es)-1], es[0]
			}
			if es[2].Extra["domain"] != domain {
				t.Fatal("literal domain changed")
			}
		})
	}
}
