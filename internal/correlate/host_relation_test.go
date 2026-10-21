package correlate

import (
	"strings"
	"testing"
	"time"

	"tracefall/internal/hostid"
	"tracefall/internal/model"
)

func remoteLogon(id, host, srcIP, logonType string) model.Event {
	return model.Event{ID: id, Host: host, EventType: model.EventLogonSuccess, ArtifactType: model.ArtifactWindowsEventLog,
		Timestamp: skewBase.Add(time.Hour), NetworkSource: srcIP, Extra: map[string]string{"logon_type": logonType}}
}

func TestHostRelations_ALogonFromAnotherMachinesAddressIsARelation(t *testing.T) {
	ev := []model.Event{
		hostWithIP("i1", "DC-A", "10.0.0.10"), hostWithIP("i2", "WS-B", "10.0.0.20"),
		remoteLogon("l1", "DC-A", "10.0.0.20", "10"),
		remoteLogon("l2", "DC-A", "10.0.0.20", "10"),
		remoteLogon("l3", "DC-A", "10.0.0.20", "2"),  // interactive: says nothing about a second machine
		remoteLogon("l4", "DC-A", "10.0.0.10", "10"), // from itself
		remoteLogon("l5", "DC-A", "10.0.0.99", "10"), // an address nothing explains
	}
	got := BuildHostRelations("case-1", ev, hostid.Build(ev))
	if len(got) != 1 {
		t.Fatalf("got %d: %+v", len(got), got)
	}
	c := got[0]
	if c.Type != model.CorrelationHostRelation || !strings.Contains(c.Title, "WS-B reached DC-A: Remote Desktop logon (2 event(s))") {
		t.Fatalf("title %q", c.Title)
	}
	if !strings.Contains(c.Description, "configuration lists this address") || strings.Contains(c.Description, "treat the direction as a lead") {
		t.Errorf("%s", c.Description)
	}
}

func TestHostRelations_AClaimedNameIsAWeakBasisAndSaysSo(t *testing.T) {
	ev := []model.Event{
		hostWithIP("i1", "DC-A", "10.0.0.10"), hostWithIP("i2", "WS-B", "10.0.0.20"),
		{ID: "l1", Host: "DC-A", EventType: model.EventLogonSuccess, ArtifactType: model.ArtifactWindowsEventLog, Timestamp: skewBase,
			NetworkSource: "10.0.0.77", Extra: map[string]string{"logon_type": "3", "workstation_name": "WS-B"}},
	}
	got := BuildHostRelations("case-1", ev, hostid.Build(ev))
	if len(got) != 1 || !strings.Contains(got[0].Description, "treat the direction as a lead") || !strings.Contains(got[0].Description, "the client chose the name") {
		t.Fatalf("%+v", got)
	}
}

func TestHostRelations_CapturedTrafficNeedsBothEndsToResolve(t *testing.T) {
	conv := func(id, src, dst string) model.Event {
		return model.Event{ID: id, ArtifactType: model.ArtifactNetworkCapture, EventType: model.EventNetworkConnection, Timestamp: skewBase,
			NetworkSource: src, NetworkDest: dst, Extra: map[string]string{"application": "smb"}}
	}
	ev := []model.Event{hostWithIP("i1", "DC-A", "10.0.0.10"), hostWithIP("i2", "WS-B", "10.0.0.20"),
		conv("c1", "10.0.0.20", "10.0.0.10"), conv("c2", "10.0.0.20", "203.0.113.5")}
	got := BuildHostRelations("case-1", ev, hostid.Build(ev))
	if len(got) != 1 || !strings.Contains(got[0].Title, "WS-B reached DC-A: captured SMB traffic") || !strings.Contains(got[0].Description, "capturing machine's clock") {
		t.Fatalf("%+v", got)
	}
}

func TestHostRelations_AnAmbiguousAddressIsLeftOut(t *testing.T) {
	ev := []model.Event{hostWithIP("i1", "DC-A", "10.0.0.10"), hostWithIP("i2", "WS-B", "10.0.0.20"), hostWithIP("i3", "WS-C", "10.0.0.20"),
		remoteLogon("l1", "DC-A", "10.0.0.20", "3")}
	for i := range ev {
		if ev[i].ID == "i2" || ev[i].ID == "i3" {
			ev[i].Extra["ip_origin"] = "10.0.0.20=dhcp lease"
		}
	}
	if got := BuildHostRelations("case-1", ev, hostid.Build(ev)); len(got) != 0 {
		t.Fatalf("two machines with the same lease: %+v", got)
	}
}
