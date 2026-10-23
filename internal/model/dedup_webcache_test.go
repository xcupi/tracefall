package model

import (
	"testing"
	"time"
)

// WebCache records tie on type, time, user and host (a page and its resources
// are fetched in the same instant); the container and EntryId separate them.
func TestDedupHash_WebCacheRecordsThatTieStayDistinct(t *testing.T) {
	at := time.Date(2026, 3, 14, 9, 30, 0, 0, time.UTC)
	mk := func(ref string) Event {
		return Event{EventType: EventBrowserCacheEntry, ArtifactType: ArtifactWebCache, Timestamp: at, User: "alice", NetworkDest: "example.com", SourceReference: ref}
	}
	a, b, again := mk("container:3#entry:1"), mk("container:3#entry:2"), mk("container:3#entry:1")
	if a.ComputeDedupHash() == b.ComputeDedupHash() {
		t.Errorf("two cache entries of one host and instant collapsed into one event")
	}
	if a.ComputeDedupHash() != again.ComputeDedupHash() {
		t.Errorf("the same record collected twice must still deduplicate")
	}
	if a.ComputeDedupHash() == mk("container:9#entry:1").ComputeDedupHash() {
		t.Errorf("the same EntryId in another container is another record")
	}
}
