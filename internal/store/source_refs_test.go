package store

import (
	"reflect"
	"testing"
	"time"

	"tracefall/internal/model"
)

// The store's references carry the acquisition, as an in-memory slice's do,
// so an unknown-host event stays scoped to the acquisition it came from.
func TestRefs_CarryTheCollectionLikeTheSliceSource(t *testing.T) {
	s := openTest(t)
	seedCaseAndSourceFile(t, s)
	at := time.Date(2021, 4, 29, 18, 0, 0, 0, time.UTC)
	events := []model.Event{{ID: "a", CaseID: "case-1", CollectionID: "collection-1", SourceFileID: "sf-1", Timestamp: at,
		EventType: model.EventProcessCreate, ArtifactType: model.ArtifactMFT, Parser: "mft@1", Confidence: 1, ProcessName: "agent.exe"}}
	if err := s.SaveEvents(events); err != nil {
		t.Fatal(err)
	}
	got, err := s.EventSourceFor("case-1").Refs()
	if err != nil {
		t.Fatal(err)
	}
	want, _ := model.SliceSource(events).Refs()
	if !reflect.DeepEqual(got, want) || got[0].CollectionID != "collection-1" {
		t.Fatalf("got %+v want %+v", got, want)
	}
}
