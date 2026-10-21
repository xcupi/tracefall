package hostid

import (
	"testing"

	"tracefall/internal/model"
)

func sysEvent(id, host, ips, role string) model.Event {
	return model.Event{
		ID: id, Host: host, EventType: model.EventRegistryKeyLastWrite,
		Extra: map[string]string{"registry_value_name": "ComputerName", "ip_origin": ips, "host_role": role, "domain": "corp.example"},
	}
}

func TestBuild_ConfigurationOwnsItsAddresses(t *testing.T) {
	r := Build([]model.Event{
		sysEvent("e1", "DC-A", "10.0.0.10=static;10.0.0.77=dhcp lease", "domain_controller"),
		sysEvent("e2", "WS-B", "10.0.0.20=dhcp lease", "workstation"),
	})
	got := r.ByIP("10.0.0.10")
	if got.Identity == nil || got.Identity.Name != "DC-A" || got.Basis != BasisStatic || got.Identity.Role != "domain_controller" || !got.Identity.Collected {
		t.Fatalf("static: %+v", got)
	}
	if got := r.ByIP("10.0.0.20"); got.Identity == nil || got.Identity.Name != "WS-B" || got.Basis != BasisDHCP {
		t.Fatalf("lease: %+v", got)
	}
	if got := r.ByIP("10.0.0.99"); got.Identity != nil || got.Ambiguous {
		t.Fatalf("an address nothing explains stays unresolved: %+v", got)
	}
}

func TestBuild_TheStrongestFactWins_AndATieIsAmbiguous(t *testing.T) {
	// Both machines remember the same lease; one also has the address in a
	// live socket. The socket decides.
	ev := []model.Event{
		sysEvent("e1", "WS-A", "10.0.0.50=dhcp lease", ""),
		sysEvent("e2", "WS-B", "10.0.0.50=dhcp lease", ""),
	}
	if got := Build(ev).ByIP("10.0.0.50"); got.Identity != nil || !got.Ambiguous {
		t.Fatalf("two leases for one address is ambiguous, not a guess: %+v", got)
	}
	ev = append(ev, model.Event{ID: "m1", Host: "WS-B", EventType: model.EventNetworkConnection,
		ArtifactType: model.ArtifactMemoryAnalysis, NetworkSource: "10.0.0.50"})
	got := Build(ev).ByIP("10.0.0.50")
	if got.Identity == nil || got.Identity.Name != "WS-B" || got.Basis != BasisMemory {
		t.Fatalf("a memory socket outranks a stale lease: %+v", got)
	}
}

func TestBuild_ALogonClaimIsWeakAndDoesNotOverrideConfiguration(t *testing.T) {
	ev := []model.Event{
		sysEvent("e1", "DC-A", "10.0.0.10=static", ""),
		// A client at 10.0.0.10's neighbour says it is DC-A: a claim only.
		{ID: "l1", EventType: model.EventLogonSuccess, NetworkSource: "10.0.0.66", Extra: map[string]string{"workstation_name": "DC-A"}},
		{ID: "l2", EventType: model.EventLogonSuccess, NetworkSource: "10.0.0.31", Extra: map[string]string{"workstation_name": "LAPTOP-9"}},
	}
	r := Build(ev)
	if got := r.ByIP("10.0.0.66"); got.Identity == nil || got.Basis != BasisClaimed || got.Identity.Name != "DC-A" {
		t.Fatalf("claim: %+v", got)
	}
	if got := r.ByIP("10.0.0.10"); got.Basis != BasisStatic {
		t.Fatalf("configuration must keep its strength: %+v", got)
	}
	l := r.ByName("LAPTOP-9")
	if l == nil || l.Collected {
		t.Fatalf("a machine only another machine mentioned is not collected: %+v", l)
	}
}

func TestBuild_DNSOnlyAttachesToMachinesAlreadyKnown(t *testing.T) {
	ev := []model.Event{
		sysEvent("e1", "WS-B", "", ""),
		{ID: "d1", EventType: model.EventDNSQuery, NetworkDest: "ws-b.corp.example", Extra: map[string]string{"answers": "10.0.0.20,CNAME:x"}},
		{ID: "d2", EventType: model.EventDNSQuery, NetworkDest: "unknown.example", Extra: map[string]string{"answers": "10.0.0.88"}},
	}
	r := Build(ev)
	if got := r.ByIP("10.0.0.20"); got.Identity == nil || got.Basis != BasisDNS {
		t.Fatalf("fqdn should reach the short name: %+v", got)
	}
	if got := r.ByIP("10.0.0.88"); got.Identity != nil {
		t.Fatalf("DNS alone must not create a machine: %+v", got)
	}
}

func TestBuild_IgnoresAddressesThatAreNotIdentity(t *testing.T) {
	r := Build([]model.Event{
		sysEvent("e1", "WS-B", "127.0.0.1=static;0.0.0.0=static;169.254.1.1=dhcp lease;224.0.0.251=static;10.0.0.20=static", ""),
	})
	for _, ip := range []string{"127.0.0.1", "0.0.0.0", "169.254.1.1", "224.0.0.251"} {
		if got := r.ByIP(ip); got.Identity != nil {
			t.Errorf("%s resolved to %v", ip, got.Identity.Name)
		}
	}
	if got := r.ByIP("10.0.0.20"); got.Identity == nil {
		t.Error("the real address must resolve")
	}
	if got := r.ByIP("not an address"); got.Identity != nil {
		t.Error("garbage must not resolve")
	}
}

func TestHosts_CollectedFirst(t *testing.T) {
	r := Build([]model.Event{
		sysEvent("e1", "ZED", "", ""),
		{ID: "l1", EventType: model.EventLogonSuccess, NetworkSource: "10.0.0.31", Extra: map[string]string{"workstation_name": "ALPHA"}},
	})
	hs := r.Hosts()
	if len(hs) != 2 || hs[0].Name != "ZED" || hs[1].Name != "ALPHA" {
		t.Fatalf("order: %+v", hs)
	}
}
