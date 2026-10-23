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
