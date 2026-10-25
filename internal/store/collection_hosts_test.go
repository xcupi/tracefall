package store

import (
	"reflect"
	"testing"
	"time"
	"tracefall/internal/model"
)

func TestCollectionHostsIncludesOnlyCollectionAndObservations(t *testing.T) {
	s := openTest(t)
	seedCaseAndSourceFile(t, s)
	if err := s.SaveCollection(model.Collection{ID: "collection-2", CaseID: "case-1", CreatedAt: time.Now().UTC(), SourceType: model.SourceTypeLocalPath, IngestionStatus: model.CollectionStatusIngested}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveEvents([]model.Event{{ID: "e1", CaseID: "case-1", CollectionID: "collection-1", SourceFileID: "sf-1", Host: "host01", EventType: model.EventSQLMessage, Parser: "mssql@1"}}); err != nil {
		t.Fatal(err)
	}
	got, err := s.CollectionHosts("case-1", "collection-1")
	if err != nil || !reflect.DeepEqual(got, []string{"host01"}) {
		t.Fatalf("direct hosts=%v err=%v", got, err)
	}
	got, err = s.CollectionHosts("case-1", "collection-2")
	if err != nil || len(got) != 0 {
		t.Fatalf("cross-collection host leak=%v err=%v", got, err)
	}
	if err := s.SaveSourceFiles([]model.SourceFile{{ID: "sf-2", CaseID: "case-1", CollectionID: "collection-2", Path: "ERRORLOG", OriginalFilename: "ERRORLOG", ImportStatus: model.SourceFileImported, DiscoveredAt: time.Now().UTC()}}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveEventObservations([]model.EventObservation{{ID: "o1", EventID: "e1", CaseID: "case-1", CollectionID: "collection-2", SourceFileID: "sf-2"}}); err != nil {
		t.Fatal(err)
	}
	got, err = s.CollectionHosts("case-1", "collection-2")
	if err != nil || !reflect.DeepEqual(got, []string{"host01"}) {
		t.Fatalf("observed hosts=%v err=%v", got, err)
	}
	got, err = s.CollectionHosts("other-case", "collection-2")
	if err != nil || len(got) != 0 {
		t.Fatalf("cross-case leak=%v err=%v", got, err)
	}
	if err := s.SoftDeleteSourceFile("sf-2", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	got, err = s.CollectionHosts("case-1", "collection-2")
	if err != nil || len(got) != 0 {
		t.Fatalf("deleted observation leaked host=%v err=%v", got, err)
	}
}
