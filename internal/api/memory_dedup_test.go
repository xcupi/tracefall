package api

import (
	"os"
	"testing"

	"tracefall/internal/model"
)

// Exercise the whole parser -> identity -> persistence path. Merely counting
// ParseResult.Events missed this bug: distinct regions existed there but
// disappeared when the generic event identity ignored their address bounds.
func TestMemory_DedupPreservesSocketsWithDifferentLocalPorts(t *testing.T) {
	for _, listener := range []bool{false, true} {
		name := "connections"
		typ := model.EventNetworkConnection
		if listener {
			name, typ = "listeners", model.EventNetworkListener
		}
		t.Run(name, func(t *testing.T) {
			doc := memDoc()
			socket := func(port int) any {
				r := map[string]any{"PID": 4242, "Owner": "powershell.exe", "Proto": "TCPv4",
					"LocalAddr": "10.0.0.5", "LocalPort": port, "ForeignAddr": "203.0.113.77",
					"ForeignPort": 443, "State": "ESTABLISHED", "Created": nil}
				if listener {
					r["ForeignAddr"], r["ForeignPort"], r["State"] = "0.0.0.0", 0, "LISTENING"
				}
				return r
			}
			doc["windows.netscan.NetScan"] = []any{socket(49812), socket(49813), socket(49812)}
			svc, c, img := memFixture(t, doc, name+".vmem")
			res, err := svc.DiscoverEvidenceFromPath(c.ID, img)
			if err != nil {
				t.Fatal(err)
			}
			ids, err := svc.EvidenceFileIDs(c.ID, res.Collection.ID, EvidenceFilter{})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := svc.ImportEvidence(c.ID, res.Collection.ID, ids); err != nil {
				t.Fatal(err)
			}
			events, err := svc.store.ListEvents(c.ID)
			if err != nil {
				t.Fatal(err)
			}
			ports := map[string]int{}
			for _, ev := range events {
				if ev.EventType == typ {
					ports[ev.Extra["local_port"]]++
				}
			}
			if len(ports) != 2 || ports["49812"] != 1 || ports["49813"] != 1 {
				t.Fatalf("persisted %s %v, want exactly one socket per local port", name, ports)
			}
		})
	}
}

func TestMemory_DedupPreservesDifferentServicesSharingOneHostProcess(t *testing.T) {
	doc := memDoc()
	service := func(name string) any {
		return map[string]any{"PID": 600, "Name": name, "Display": name,
			"State": "SERVICE_RUNNING", "Start": "SERVICE_AUTO_START", "Type": "SERVICE_WIN32_SHARE_PROCESS",
			"Binary": `C:\Windows\System32\svchost.exe -k netsvcs -p`}
	}
	// Two names hosted by the same process, plus a genuine duplicate.
	doc["windows.svcscan.SvcScan"] = []any{service("BITS"), service("Schedule"), service("BITS")}
	svc, c, img := memFixture(t, doc, "services.vmem")
	res, err := svc.DiscoverEvidenceFromPath(c.ID, img)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := svc.EvidenceFileIDs(c.ID, res.Collection.ID, EvidenceFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ImportEvidence(c.ID, res.Collection.ID, ids); err != nil {
		t.Fatal(err)
	}
	events, err := svc.store.ListEvents(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	services := map[string]int{}
	for _, ev := range events {
		if ev.EventType == model.EventMemoryService {
			services[ev.Extra["service_name"]]++
		}
	}
	if services["BITS"] != 1 || services["Schedule"] != 1 || len(services) != 2 {
		t.Fatalf("persisted services %v, want one BITS and one Schedule; distinct names must survive while duplicates collapse", services)
	}

	// A differently packaged recollection of the same rows must not inflate
	// the timeline. Every duplicate row must still retain its own provenance.
	data, err := os.ReadFile(img)
	if err != nil {
		t.Fatal(err)
	}
	recollected := img + ".recollected.vmem"
	if err := os.WriteFile(recollected, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := svc.DiscoverEvidenceFromPath(c.ID, recollected)
	if err != nil {
		t.Fatal(err)
	}
	ids, err = svc.EvidenceFileIDs(c.ID, second.Collection.ID, EvidenceFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ImportEvidence(c.ID, second.Collection.ID, ids); err != nil {
		t.Fatal(err)
	}
	after, err := svc.store.ListEvents(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(events) {
		t.Fatalf("recollection inflated timeline: %d -> %d events", len(events), len(after))
	}
	for _, ev := range after {
		if ev.EventType != model.EventMemoryService {
			continue
		}
		obs, err := svc.store.ListEventObservations(ev.ID)
		if err != nil {
			t.Fatal(err)
		}
		want := 2
		if ev.Extra["service_name"] == "BITS" {
			want = 4 // two raw BITS rows in each collection
		}
		if len(obs) != want {
			t.Errorf("%s has %d observations, want %d", ev.Extra["service_name"], len(obs), want)
		}
		collections, raws := map[string]bool{}, map[string]bool{}
		for _, o := range obs {
			collections[o.CollectionID], raws[o.RawEvidenceID] = true, true
			if o.RawEvidenceID == "" || o.SourceFileID == "" || o.SourceReference == "" {
				t.Errorf("service observation lost provenance: %+v", o)
			}
		}
		if len(collections) != 2 || len(raws) != want {
			t.Errorf("service provenance is incomplete: %d collections, %d distinct raw rows", len(collections), len(raws))
		}
	}
}

func TestMemory_DedupPreservesDistinctRegionsInTheSameProcess(t *testing.T) {
	doc := memDoc()
	rows := doc["windows.malware.malfind.Malfind"].([]any)
	second := map[string]any{}
	for k, v := range rows[0].(map[string]any) {
		second[k] = v
	}
	second["Start VPN"], second["End VPN"] = 2000000010000, 2000000014095
	doc["windows.malware.malfind.Malfind"] = append(rows, second)

	svc, c, img := memFixture(t, doc, "regions.vmem")
	res, err := svc.DiscoverEvidenceFromPath(c.ID, img)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := svc.EvidenceFileIDs(c.ID, res.Collection.ID, EvidenceFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ImportEvidence(c.ID, res.Collection.ID, ids); err != nil {
		t.Fatal(err)
	}
	events, err := svc.store.ListEvents(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	regions := map[string]bool{}
	for _, ev := range events {
		if ev.EventType == model.EventMemoryInjection {
			regions[ev.Extra["start_vpn"]] = true
		}
	}
	if len(regions) != 2 {
		t.Fatalf("persisted %d distinct regions, want 2: different memory regions in one PID at the snapshot time must not collapse", len(regions))
	}
}
