package model

import (
	"testing"
	"time"
)

func TestNTFSRecordIdentityPreservesTiedObservations(t *testing.T) {
	for _, artifact := range []string{ArtifactMFT, ArtifactUsnJournal} {
		a := Event{ArtifactType: artifact, EventType: "filesystem_created", Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), FilePath: "same.txt", SourceReference: "record:64-1", Extra: map[string]string{"mft_file_reference": "64-1"}}
		b := a
		b.SourceReference = "record:65-1"
		b.Extra = map[string]string{"mft_file_reference": "65-1"}
		if a.ComputeDedupHash() == b.ComputeDedupHash() {
			t.Fatalf("%s collapsed distinct records at same time", artifact)
		}
		b = a
		b.CollectionID = "recollected"
		b.SourceFileID = "new-source"
		if a.ComputeDedupHash() != b.ComputeDedupHash() {
			t.Fatal("recollection split identity")
		}
	}
}
