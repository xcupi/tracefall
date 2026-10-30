package model

import (
	"testing"
	"time"
)

func TestDefenderHistoryDedupIdentity(t *testing.T) {
	for _, dated := range []bool{false, true} {
		base := Event{EventType: EventAntimalwareHistory, ArtifactType: ArtifactDefenderHistory, Host: "host01", SourceReference: "record:0;bytes:0-100", Extra: map[string]string{"detection_id": "00000001-0000-0000-0000-000000000000", "source_sha256": "content-a"}}
		if dated {
			base.Timestamp = time.Date(2024, 1, 1, 0, 0, 0, 100, time.UTC)
		}
		for _, key := range []string{"detection_id", "source_sha256"} {
			other := base
			other.Extra = map[string]string{"detection_id": base.Extra["detection_id"], "source_sha256": base.Extra["source_sha256"]}
			other.Extra[key] += "different"
			if base.ComputeDedupHash() == other.ComputeDedupHash() {
				t.Errorf("dated=%v: distinct %s collapsed", dated, key)
			}
		}
		recollected := base
		recollected.CollectionID = "collection-b"
		recollected.SourceFileID = "source-b"
		if base.ComputeDedupHash() != recollected.ComputeDedupHash() {
			t.Errorf("dated=%v: identical recollection split", dated)
		}
	}
}

func TestDefenderHistoryDedupPreservesMalformedIdentifiers(t *testing.T) {
	a := Event{ArtifactType: ArtifactDefenderHistory, Extra: map[string]string{"detection_id": "{invalid", "source_sha256": "same"}}
	b := a
	b.Extra = map[string]string{"detection_id": "invalid", "source_sha256": "same"}
	if a.ComputeDedupHash() == b.ComputeDedupHash() {
		t.Fatal("malformed recorded identifiers collapsed")
	}
}
