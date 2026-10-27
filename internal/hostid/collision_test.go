package hostid

import (
	"encoding/json"
	"testing"
	"tracefall/internal/model"
)

func TestRegistryDistinctFQDNsDoNotMerge(t *testing.T) {
	a := sysEvent("a", "host01.domain-a.example", "10.0.0.5=static", "")
	b := sysEvent("b", "host01.domain-b.example", "10.0.0.5=static", "")
	for _, events := range [][]model.Event{{a, b}, {b, a}} {
		r := Build(events)
		if r.ByName(a.Host) == r.ByName(b.Host) {
			t.Fatal("distinct FQDNs merged")
		}
		if r.ByName("host01") != nil {
			t.Fatal("ambiguous short name resolved")
		}
		if got := r.ByIP("10.0.0.5"); got.Identity != nil || !got.Ambiguous {
			t.Fatalf("shared IP resolved: %+v", got)
		}
	}
}

func TestRegistryContradictoryMetadataAbstains(t *testing.T) {
	a := sysEvent("a", "host01", "10.0.0.5=static", "")
	b := sysEvent("b", "host01", "10.0.0.6=static", "")
	a.Extra["domain"] = "domain-a.example"
	b.Extra["domain"] = "domain-b.example"
	for _, events := range [][]model.Event{{a, b}, {b, a}} {
		r := Build(events)
		if r.ByName("host01") != nil || r.ByIP("10.0.0.5").Identity != nil {
			t.Fatal("contradictory identity metadata overwritten")
		}
	}
}
func TestRegistryShortAliasCollisionIsOrderIndependent(t *testing.T) {
	a := sysEvent("a", "host01", "10.0.0.5=static", "")
	a.Extra["domain"] = "domain-a.example"
	b := sysEvent("b", "host01.domain-a.example", "10.0.0.6=static", "")
	b.Extra["domain"] = "domain-a.example"
	a.CollectionID = "one"
	b.CollectionID = "one"
	r := Build([]model.Event{a, b})
	if r.ByName(a.Host) == nil || r.ByName(a.Host) != r.ByName(b.Host) {
		t.Fatal("compatible observed alias did not resolve")
	}
	c := sysEvent("c", "host01.domain-b.example", "10.0.0.7=static", "")
	for _, events := range [][]model.Event{{a, b, c}, {c, b, a}} {
		r = Build(events)
		if r.ByName("host01") != nil || r.ByIP("10.0.0.5").Identity != nil {
			t.Fatal("later collision retained short attribution")
		}
	}
}

func TestRegistryMetadataConflictsAndShuffle(t *testing.T) {
	for _, field := range []string{"host_role", "os_product_name", "os_current_build"} {
		t.Run(field, func(t *testing.T) {
			a := sysEvent("a", "host01", "10.0.0.5=static", "")
			b := sysEvent("b", "host01", "10.0.0.6=static", "")
			a.Extra[field] = "one"
			b.Extra[field] = "two"
			for _, events := range [][]model.Event{{a, b}, {b, a}} {
				r := Build(events)
				if r.ByName("host01") != nil || r.ByIP("10.0.0.5").Identity != nil {
					t.Fatal("conflicting metadata resolved")
				}
			}
		})
	}
	a := sysEvent("a", "host01", "10.0.0.5=static", "")
	b := sysEvent("b", "HOST01", "10.0.0.6=static", "")
	x, _ := json.Marshal(Build([]model.Event{a, b}).Hosts())
	y, _ := json.Marshal(Build([]model.Event{b, a}).Hosts())
	if string(x) != string(y) {
		t.Fatalf("identity output depends on order: %s != %s", x, y)
	}
}
func TestAcquisitionNamesUnknownAndCollision(t *testing.T) {
	e := []model.Event{{ID: "a", Host: "host01", CollectionID: "one"}, {ID: "b", Host: "host01.corp.example", CollectionID: "one"}, {ID: "c", CollectionID: "one"}, {ID: "d", Host: "host01", CollectionID: "two"}}
	got := AcquisitionNames(e)
	if got["a"] != "host01.corp.example" || got["c"] != "" || got["d"] != "host01" {
		t.Fatalf("scope or alias: %+v", got)
	}
	e = append(e, model.Event{ID: "other", Host: "host01.other.example", CollectionID: "three"})
	got = AcquisitionNames(e)
	if got["a"] != "" || got["d"] != "" || got["b"] != "host01.corp.example" {
		t.Fatalf("ambiguous short attributed: %+v", got)
	}
}

func TestAliasCannotOverrideContradictoryOwnedMetadata(t *testing.T) {
	a := sysEvent("a", "host01", "10.0.0.5=static", "server")
	b := sysEvent("b", "host01.corp.example", "10.0.0.6=static", "workstation")
	a.CollectionID = "one"
	b.CollectionID = "one"
	for _, events := range [][]model.Event{{a, b}, {b, a}} {
		r := Build(events)
		if r.ByName(a.Host) != nil || r.ByName(b.Host) != nil || r.ByIP("10.0.0.5").Identity != nil {
			t.Fatal("alias overrode contradictory machine facts")
		}
		names := AcquisitionNames(events)
		if names["a"] != "" || names["b"] != "" {
			t.Fatalf("acquisition disagrees with registry: %+v", names)
		}
	}
}

func TestDNSUsesTheSameValidatedAliasAsByName(t *testing.T) {
	a := sysEvent("a", "host01", "", "")
	a.CollectionID = "one"
	b := model.Event{ID: "b", Host: "host01.corp.example", CollectionID: "one"}
	dns := model.Event{ID: "dns", EventType: model.EventDNSQuery, NetworkDest: "host01", Extra: map[string]string{"answers": "10.0.0.5"}}
	r := Build([]model.Event{a, b, dns})
	got := r.ByIP("10.0.0.5")
	if got.Identity == nil || got.Identity != r.ByName("host01.corp.example") || got.Basis != BasisDNS {
		t.Fatalf("DNS used a different alias policy: %+v", got)
	}
}
