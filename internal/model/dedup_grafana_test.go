package model

import (
	"testing"
	"time"
)

// Grafana stores whole seconds, so several rows of grafana.db can tie on type,
// time, user and file. They are separate records (three failed logins in one
// second are three), and each carries its table row in SourceReference.
func grafanaRow(typ, ref string) Event {
	return Event{
		EventType: typ, ArtifactType: ArtifactGrafanaDB, FilePath: "grafana.db",
		Timestamp: time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC), NetworkSource: "203.0.113.5",
		SourceReference: ref,
		Extra:           map[string]string{"login": "alice01"},
	}
}

func TestDedup_GrafanaRowsThatTieStayDistinct(t *testing.T) {
	a := grafanaRow(EventGrafanaLoginAttempt, "login_attempt:id=1")
	b := grafanaRow(EventGrafanaLoginAttempt, "login_attempt:id=2")
	if a.ComputeDedupHash() == b.ComputeDedupHash() {
		t.Fatal("two login_attempt rows in the same second collapsed into one")
	}
	u1 := grafanaRow(EventGrafanaUser, "user:id=2")
	u2 := grafanaRow(EventGrafanaUser, "user:id=3")
	if u1.ComputeDedupHash() == u2.ComputeDedupHash() {
		t.Fatal("two users created in the same second collapsed into one")
	}
}

func TestDedup_GrafanaSameRowFromARecollectionStillDeduplicates(t *testing.T) {
	a := grafanaRow(EventGrafanaLoginAttempt, "login_attempt:id=1")
	b := grafanaRow(EventGrafanaLoginAttempt, "login_attempt:id=1")
	b.SourceFileID, b.CollectionID = "other-file", "other-collection"
	if a.ComputeDedupHash() != b.ComputeDedupHash() {
		t.Fatal("the same row seen in a second collection no longer deduplicates")
	}
}

func TestDedup_OtherArtifactsAreUnchangedByTheGrafanaRule(t *testing.T) {
	e := grafanaRow(EventWebRequest, "line:7")
	e.ArtifactType = ArtifactWebAccessLog
	f := e
	f.SourceReference = "line:99"
	if e.ComputeDedupHash() != f.ComputeDedupHash() {
		t.Fatal("a timestamped web request now depends on its line number")
	}
}
