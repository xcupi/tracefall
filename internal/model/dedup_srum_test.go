package model

import (
	"testing"
	"time"
)

// SRUM writes one row per application per interval, and many applications are
// services or packages that carry no process name. Rows that tie on time and
// user are different observations; the row's own identity (table and AutoIncId)
// is what separates them, and it is stable when the same database is collected
// again.
func TestDedupHash_SRUMRowsThatTieOnTimeAndUserStayDistinct(t *testing.T) {
	at := time.Date(2026, 3, 14, 9, 30, 0, 0, time.UTC)
	mk := func(ref string) Event {
		return Event{EventType: EventSRUMAppUsage, ArtifactType: ArtifactSRUM, Timestamp: at, User: "S-1-5-18", SourceReference: ref}
	}
	a, b, again := mk("table:{T}#id:1"), mk("table:{T}#id:2"), mk("table:{T}#id:1")
	if a.ComputeDedupHash() == b.ComputeDedupHash() {
		t.Errorf("two SRUM rows with different AutoIncId collapsed into one event")
	}
	if a.ComputeDedupHash() != again.ComputeDedupHash() {
		t.Errorf("the same row collected twice must still deduplicate")
	}
	other := mk("table:{U}#id:1")
	if a.ComputeDedupHash() == other.ComputeDedupHash() {
		t.Errorf("the same AutoIncId in another table is another row")
	}
}

// The SDP network table has no process name at all, so every row of an
// interval ties on type, time and user with its neighbours; only the table and
// AutoIncId tell them apart. The same row collected twice (another collection,
// another path) must still deduplicate, and a counter value must not matter.
func TestDedupHash_SRUMSDPNetworkRowsStayDistinctAndRecollectionsCollapse(t *testing.T) {
	at := time.Date(2026, 3, 14, 9, 30, 0, 0, time.UTC)
	mk := func(ref, coll string, sent string) Event {
		return Event{EventType: EventSRUMSDPNetwork, ArtifactType: ArtifactSRUM, Timestamp: at, SourceReference: ref, CollectionID: coll, Extra: map[string]string{"bytes_out_bound": sent}}
	}
	a, b := mk("table:{T}#id:1", "c1", "5"), mk("table:{T}#id:2", "c1", "5")
	if a.ComputeDedupHash() == b.ComputeDedupHash() {
		t.Errorf("two SDP rows with different AutoIncId collapsed")
	}
	if a.ComputeDedupHash() != mk("table:{T}#id:1", "c2", "5").ComputeDedupHash() {
		t.Errorf("an identical recollection must deduplicate")
	}
	if a.ComputeDedupHash() == (Event{EventType: EventSRUMNetworkUsage, ArtifactType: ArtifactSRUM, Timestamp: at, SourceReference: "table:{T}#id:1"}).ComputeDedupHash() {
		t.Errorf("the event type is part of the identity")
	}
}
