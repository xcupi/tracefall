package store

import (
	"fmt"
	"sort"
	"testing"
	"time"

	"tracefall/internal/model"
)

func withPageSize(t *testing.T, n int) {
	t.Helper()
	old := eventPageSize
	eventPageSize = n
	t.Cleanup(func() { eventPageSize = old })
}

func collect(t *testing.T, each func(func(model.Event) error) error) []model.Event {
	t.Helper()
	var out []model.Event
	if err := each(func(e model.Event) error { out = append(out, e); return nil }); err != nil {
		t.Fatal(err)
	}
	return out
}

// Streaming in pages must give every event exactly once, in (timestamp, id)
// order, even when a page ends inside a run of events that share a timestamp.
func TestForEachEvent_PagesCrossTiedTimestampsWithoutLossOrRepeat(t *testing.T) {
	s := openTest(t)
	const n = 97
	seedTiedEvents(t, s, n) // all one timestamp, ids out of insertion order
	for _, size := range []int{1, 7, 10, 96, 97, 98, 2000} {
		withPageSize(t, size)
		got := collect(t, func(fn func(model.Event) error) error { return s.ForEachEvent("case-1", fn) })
		if len(got) != n {
			t.Fatalf("page size %d: %d events, want %d", size, len(got), n)
		}
		for i := 1; i < len(got); i++ {
			if got[i-1].ID >= got[i].ID {
				t.Fatalf("page size %d: ids %q then %q are out of order or repeated", size, got[i-1].ID, got[i].ID)
			}
		}
	}
}

func TestForEachEvent_MixedTimestampsComeOutInTimeThenIDOrder(t *testing.T) {
	s := openTest(t)
	seedCaseAndSourceFile(t, s)
	base := time.Date(2021, 4, 29, 18, 0, 0, 0, time.UTC)
	var evs []model.Event
	for i := 0; i < 60; i++ {
		ts := base.Add(time.Duration(i%4) * time.Second) // four groups of fifteen
		if i%11 == 0 {
			ts = time.Time{} // undated events
		}
		if i%13 == 0 {
			ts = base.Add(500 * time.Millisecond) // a sub-second timestamp between groups
		}
		evs = append(evs, model.Event{
			ID: fmt.Sprintf("m-%03d", (i*37)%60), CaseID: "case-1", CollectionID: "collection-1", SourceFileID: "sf-1",
			Timestamp: ts, EventType: model.EventFilesystemCreated, ArtifactType: model.ArtifactMFT, Parser: "mft@1", Confidence: 1,
		})
	}
	if err := s.SaveEvents(evs); err != nil {
		t.Fatal(err)
	}
	want, err := s.ListEvents("case-1")
	if err != nil {
		t.Fatal(err)
	}
	sort.SliceStable(want, func(i, j int) bool {
		a, b := fmtTime(want[i].Timestamp), fmtTime(want[j].Timestamp)
		if a != b {
			return a < b
		}
		return want[i].ID < want[j].ID
	})
	for _, size := range []int{1, 4, 9, 16} {
		withPageSize(t, size)
		got := collect(t, func(fn func(model.Event) error) error { return s.ForEachEvent("case-1", fn) })
		if len(got) != len(want) {
			t.Fatalf("page size %d: %d events, want %d", size, len(got), len(want))
		}
		for i := range got {
			if got[i].ID != want[i].ID {
				t.Fatalf("page size %d: position %d is %s, want %s", size, i, got[i].ID, want[i].ID)
			}
		}
	}
}

func TestForEachEventInCollection_StreamsOnlyThatCollection(t *testing.T) {
	s := openTest(t)
	seedTiedEvents(t, s, 30)
	if err := s.SaveCollection(model.Collection{
		ID: "collection-2", CaseID: "case-1", CreatedAt: time.Now().UTC(), SourceType: model.SourceTypeLocalPath,
		IngestionStatus: model.CollectionStatusIngested,
	}); err != nil {
		t.Fatal(err)
	}
	extra := []model.Event{}
	for i := 0; i < 12; i++ {
		extra = append(extra, model.Event{
			ID: fmt.Sprintf("other-%02d", i), CaseID: "case-1", CollectionID: "collection-2", SourceFileID: "sf-1",
			Timestamp: time.Date(2021, 4, 29, 18, 17, 38, 0, time.UTC), EventType: model.EventFilesystemCreated,
			ArtifactType: model.ArtifactMFT, Parser: "mft@1", Confidence: 1,
		})
	}
	if err := s.SaveEvents(extra); err != nil {
		t.Fatal(err)
	}
	withPageSize(t, 5)
	got := collect(t, func(fn func(model.Event) error) error { return s.ForEachEventInCollection("collection-2", fn) })
	if len(got) != 12 {
		t.Fatalf("got %d events, want the 12 of collection-2", len(got))
	}
	for _, e := range got {
		if e.CollectionID != "collection-2" {
			t.Fatalf("event %s is from %s", e.ID, e.CollectionID)
		}
	}
}

func TestForEachEventLazy_DecodesExtraOnlyWhereAsked(t *testing.T) {
	s := openTest(t)
	seedCaseAndSourceFile(t, s)
	at := time.Date(2021, 4, 29, 18, 17, 38, 0, time.UTC)
	evs := []model.Event{
		{ID: "a", CaseID: "case-1", CollectionID: "collection-1", SourceFileID: "sf-1", Timestamp: at,
			EventType: model.EventFilesystemCreated, ArtifactType: model.ArtifactMFT, Parser: "mft@1", Confidence: 1,
			Extra: map[string]string{"k": "v"}},
		{ID: "b", CaseID: "case-1", CollectionID: "collection-1", SourceFileID: "sf-1", Timestamp: at.Add(time.Second),
			EventType: model.EventProcessCreate, ArtifactType: model.ArtifactMFT, Parser: "mft@1", Confidence: 1,
			Extra: map[string]string{"k": "w"}},
	}
	if err := s.SaveEvents(evs); err != nil {
		t.Fatal(err)
	}
	withPageSize(t, 1)
	got := collect(t, func(fn func(model.Event) error) error {
		return s.ForEachEventLazy("case-1", func(typ string) bool { return typ == model.EventProcessCreate }, fn)
	})
	if len(got) != 2 || got[0].Extra != nil || got[1].Extra["k"] != "w" {
		t.Fatalf("lazy decoding: %+v", got)
	}
}

// A consumer that stops to wait (a client reading slowly) must not hold the
// store's only connection: any other request has to be served meanwhile.
func TestForEachEvent_AStalledConsumerDoesNotBlockOtherQueries(t *testing.T) {
	s := openTest(t)
	seedTiedEvents(t, s, 40)
	withPageSize(t, 8)

	served := make(chan error, 1)
	err := s.ForEachEvent("case-1", func(e model.Event) error {
		if e.ID != "ev-0010" {
			return nil
		}
		// In the middle of a page, as a slow client would be.
		go func() {
			_, err := s.GetCase("case-1")
			served <- err
		}()
		select {
		case <-served:
		case <-time.After(3 * time.Second):
			t.Error("another query was not served while the consumer was busy: the stream holds the connection")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
