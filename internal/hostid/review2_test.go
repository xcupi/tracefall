package hostid

import (
	"testing"
	"tracefall/internal/model"
)

func TestReview2RankedAmbiguousOwners(t *testing.T) {
	fact := func(id, h string) model.Event {
		return model.Event{ID: id, CaseID: "case", Host: h, EventType: model.EventRegistryKeyLastWrite, Extra: map[string]string{"registry_value_name": "ComputerName"}}
	}
	for _, kind := range []string{"fqdn", "domain", "metadata"} {
		for _, basis := range []Basis{BasisDNS, BasisClaimed, BasisDHCP, BasisStatic, BasisMemory} {
			t.Run(kind+"/"+string(basis), func(t *testing.T) {
				es := []model.Event{fact("a", "host01"), fact("b", "host02")}
				switch kind {
				case "fqdn":
					es = append(es, fact("c", "host01.a.example"), fact("d", "host01.b.example"))
				case "domain":
					es[0].Extra["domain"] = "a.example"
					x := fact("c", "host01")
					x.Extra["domain"] = "b.example"
					es = append(es, x)
				case "metadata":
					es[0].Extra["os_current_build"] = "1"
					x := fact("c", "host01")
					x.Extra["os_current_build"] = "2"
					es = append(es, x)
				}
				for _, h := range []string{"host01", "host02"} {
					e := fact("owner-"+h, h)
					switch basis {
					case BasisDNS:
						e.EventType = model.EventDNSQuery
						e.Host = ""
						e.NetworkDest = h
						e.Extra = map[string]string{"answers": "10.0.0.5"}
					case BasisClaimed:
						e.EventType = model.EventLogonSuccess
						e.Host = ""
						e.NetworkSource = "10.0.0.5"
						e.Extra = map[string]string{"workstation_name": h}
					case BasisMemory:
						e.EventType = model.EventNetworkConnection
						e.ArtifactType = model.ArtifactMemoryAnalysis
						e.NetworkSource = "10.0.0.5"
					default:
						e.Extra["ip_origin"] = "10.0.0.5=" + string(basis)
					}
					es = append(es, e)
				}
				for i := 0; i < 2; i++ {
					r := Build(es).ByIP("10.0.0.5")
					if !r.Ambiguous || r.Identity != nil {
						t.Fatalf("ambiguous %s owner lost: %+v", basis, r)
					}
					es[0], es[len(es)-1] = es[len(es)-1], es[0]
				}
				if basis == BasisDNS {
					strong := fact("strong", "host02")
					strong.Extra["ip_origin"] = "10.0.0.5=static"
					r := Build(append(es, strong)).ByIP("10.0.0.5")
					if r.Identity == nil || r.Identity.Name != "HOST02" || r.Basis != BasisStatic {
						t.Fatalf("weaker blocker overrode static: %+v", r)
					}
				}
			})
		}
	}
	// DNS cannot invent a collected owner.
	e := model.Event{ID: "dns", EventType: model.EventDNSQuery, NetworkDest: "absent", Extra: map[string]string{"answers": "10.0.0.5"}}
	if r := Build([]model.Event{e}).ByIP("10.0.0.5"); r.Identity != nil || r.Ambiguous {
		t.Fatalf("invented DNS owner: %+v", r)
	}
	es := []model.Event{fact("short", "host01"), fact("full", "host01.corp.example"), e}
	es[0].CollectionID = "one"
	es[1].CollectionID = "one"
	es[2].NetworkDest = "host01"
	if r := Build(es).ByIP("10.0.0.5"); r.Identity == nil || r.Basis != BasisDNS || r.Ambiguous {
		t.Fatalf("valid DNS alias lost: %+v", r)
	}
}
