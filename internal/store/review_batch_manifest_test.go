package store_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/store"
)

func TestReviewBatchesManifestDeterministicAcrossInsertionOrderAndFrozen(t *testing.T) {
	build := func(reverse bool) (*store.Store, store.ReviewSnapshot) {
		s, err := store.Open(filepath.Join(t.TempDir(), "synthetic.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		if err = s.CreateCase(model.Case{ID: "case01", Name: "Synthetic", Status: "created"}); err != nil {
			t.Fatal(err)
		}
		if err = s.CreateCollectionWithSourceFiles(model.Collection{ID: "collection01", CaseID: "case01"}, []model.SourceFile{{ID: "source01", CaseID: "case01", CollectionID: "collection01", Path: "artifact.log", ImportStatus: model.SourceFileImported, Supported: true}}); err != nil {
			t.Fatal(err)
		}
		var events []model.Event
		for index := 0; index < 126; index++ {
			i := index
			if reverse {
				i = 125 - index
			}
			stamp := time.Time{}
			if i%2 == 1 {
				stamp = time.Date(2024, 1, 1, 1, 0, 0, 0, time.UTC)
			}
			events = append(events, model.Event{ID: fmt.Sprintf("e%04d", i), CaseID: "case01", CollectionID: "collection01", SourceFileID: "source01", DedupHash: fmt.Sprintf("hash-%d", i), EventType: "process_start", Timestamp: stamp})
		}
		if err = s.SaveEvents(events); err != nil {
			t.Fatal(err)
		}
		snap, err := s.FreezeReviewSnapshot(context.Background(), "case01", "plan01")
		if err != nil {
			t.Fatal(err)
		}
		return s, snap
	}
	a, sa := build(false)
	_, sb := build(true)
	if sa.Fingerprint != sb.Fingerprint || sa.Events != 126 || sa.Coverage.UndatedTotal != 63 {
		t.Fatalf("shuffled/tied/undated snapshot differs: %+v %+v", sa, sb)
	}
	members, err := a.BatchMembers("case01", "plan01", "event", 60, 60)
	if err != nil || len(members) != 60 || members[0].ID != "e0060" || members[59].ID != "e0119" {
		t.Fatalf("deterministic exact membership page: %v %v", members, err)
	}
	if err = a.SaveEvents([]model.Event{{ID: "new", CaseID: "case01", CollectionID: "collection01", SourceFileID: "source01", DedupHash: "new", EventType: "process_start"}}); err != nil {
		t.Fatal(err)
	}
	current, err := a.ReviewSnapshotFingerprint(context.Background(), "case01")
	if err != nil || current == sa.Fingerprint {
		t.Fatalf("changed current source not detected: %s %v", current, err)
	}
	_, found, err := a.BatchEvent("case01", "plan01", "new")
	if err != nil || found {
		t.Fatalf("frozen membership changed after plan: %t %v", found, err)
	}
}

func TestReviewBatchesOversizedNormalizedRecordRefusesAtomically(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "limits.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.CreateCase(model.Case{ID: "case01", Name: "Synthetic", Status: "created"}); err != nil {
		t.Fatal(err)
	}
	if err = s.CreateCollectionWithSourceFiles(model.Collection{ID: "collection01", CaseID: "case01"}, []model.SourceFile{{ID: "source01", CaseID: "case01", CollectionID: "collection01", Path: "artifact.log"}}); err != nil {
		t.Fatal(err)
	}
	if err = s.SaveEvents([]model.Event{{ID: "oversized", CaseID: "case01", CollectionID: "collection01", SourceFileID: "source01", DedupHash: "oversized", EventType: "process_start", Extra: map[string]string{"not_allowlisted": strings.Repeat("x", 140000)}}}); err != nil {
		t.Fatal(err)
	}
	_, err = s.FreezeReviewSnapshot(context.Background(), "case01", "plan01")
	if !errors.Is(err, store.ErrReviewSnapshotLimit) {
		t.Fatalf("oversized row not explicitly refused: %v", err)
	}
	members, err := s.BatchMembers("case01", "plan01", "event", 0, 60)
	if err != nil || len(members) != 0 {
		t.Fatalf("failed snapshot retained a partial manifest: %d %v", len(members), err)
	}
}
