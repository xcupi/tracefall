package correlate

import (
	"testing"
	"tracefall/internal/hostid"
	"tracefall/internal/model"
)

func TestClockIdentityAmbiguityNeverPairsLogon(t *testing.T) {
	sess := model.Event{ID: "session", SourceFileID: "capture", ArtifactType: model.ArtifactNetworkCapture, EventType: model.EventNetworkConnection, Timestamp: skewBase, NetworkSource: "10.0.0.66", NetworkDest: "10.0.0.5", Extra: map[string]string{"session": "true", "client_port": "50123", "last_seen_utc": skewBase.Add(activityLookWindow).Format("2006-01-02T15:04:05Z")}}
	logon := model.Event{ID: "logon", Host: "host01", EventType: model.EventLogonSuccess, Timestamp: skewBase, NetworkSource: "10.0.0.66", Extra: map[string]string{"source_port": "50123"}}
	for _, facts := range [][]model.Event{nil, {hostWithIP("a", "host01.domain-a.example", "10.0.0.5"), hostWithIP("b", "host01.domain-b.example", "10.0.0.5")}} {
		events := append(append([]model.Event(nil), facts...), sess, logon)
		if got := logonObservations(events, hostid.Build(events)); len(got) != 0 {
			t.Fatalf("unresolved destination clock paired: %+v", got)
		}
	}
}
func TestRunFromUsesAllHostReferenceNames(t *testing.T) {
	events := activityFixture()
	other := events[0]
	other.ID = "other"
	other.Host = "host01.domain-b.example"
	other.EventType = "unrelated_type"
	fqdn := other
	fqdn.ID = "fqdn"
	fqdn.Host = "host01.domain-a.example"
	events = append(events, other, fqdn)
	for _, c := range Run("case-1", events) {
		if c.Type == model.CorrelationActivityChain {
			t.Fatalf("filtered load hid conflicting host identity: %+v", c)
		}
	}
}

func TestHostRelationsDoNotAttributeAmbiguousShortDestination(t *testing.T) {
	events := []model.Event{hostWithIP("source", "host02", "10.0.0.2"), hostWithIP("a", "host01.domain-a.example", "10.0.0.5"), hostWithIP("b", "host01.domain-b.example", "10.0.0.6"), {ID: "logon", Host: "host01", EventType: model.EventLogonSuccess, NetworkSource: "10.0.0.2", Timestamp: skewBase, Extra: map[string]string{"logon_type": "3"}}}
	if got := BuildHostRelations("case-1", events, hostid.Build(events)); len(got) != 0 {
		t.Fatalf("ambiguous destination attributed: %+v", got)
	}
}

func TestRunFromLoadsDNSIdentityFacts(t *testing.T) {
	events := []model.Event{hostWithIP("source", "host02", ""), hostWithIP("target", "host01", "10.0.0.5"), {ID: "dns", EventType: model.EventDNSQuery, NetworkDest: "host02", Extra: map[string]string{"answers": "10.0.0.2"}}, {ID: "traffic", Timestamp: skewBase, EventType: model.EventNetworkConnection, ArtifactType: model.ArtifactNetworkCapture, NetworkSource: "10.0.0.2", NetworkDest: "10.0.0.5", Extra: map[string]string{"application": "rdp"}}}
	expected := BuildHostRelations("case-1", events, hostid.Build(events))
	if len(expected) != 1 {
		t.Fatalf("full-input positive failed: %+v", expected)
	}
	count := 0
	for _, c := range Run("case-1", events) {
		if c.Type == model.CorrelationHostRelation {
			count++
		}
	}
	if count != len(expected) {
		t.Fatalf("filtered identity inputs lost DNS: got %d want %d", count, len(expected))
	}
}

func TestHostRelationsAmbiguousClaimedAliasDoesNotResolveDestination(t *testing.T) {
	events := []model.Event{hostWithIP("source", "host02", "10.0.0.2"), {ID: "claim-a", EventType: model.EventLogonSuccess, Extra: map[string]string{"workstation_name": "host01.domain-a.example"}}, {ID: "claim-b", EventType: model.EventLogonSuccess, Extra: map[string]string{"workstation_name": "host01.domain-b.example"}}, {ID: "logon", Host: "host01", EventType: model.EventLogonSuccess, Timestamp: skewBase, NetworkSource: "10.0.0.2", Extra: map[string]string{"logon_type": "3"}}}
	if got := BuildHostRelations("case-1", events, hostid.Build(events)); len(got) != 0 {
		t.Fatalf("ambiguous client-named alias resolved: %+v", got)
	}
}
