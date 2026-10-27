package store_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/store"
)

// A companion row carries only a label in its parse coverage; the review
// snapshot must count it as not recorded and never as a parse gap.
func TestReviewSnapshot_CompanionLabelCountsAsNotRecorded(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.CreateCase(model.Case{ID: "case01", Name: "Synthetic"}); err != nil {
		t.Fatal(err)
	}
	if err = s.SaveCollection(model.Collection{ID: "col01", CaseID: "case01", CreatedAt: time.Now().UTC(), SourceType: model.SourceTypeDiskImage, ArchiveHash: "h", EvidenceDirectory: "e"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	rows := []model.SourceFile{
		{ID: "s1", CaseID: "case01", CollectionID: "col01", Path: "vol1/a.evtx", ImportStatus: model.SourceFileImported, DiscoveredAt: now, ParseCoverage: &model.ParseCoverage{}},
		{ID: "s2", CaseID: "case01", CollectionID: "col01", Path: "vol1/SYSTEM.LOG1", ImportStatus: model.SourceFileUnsupported, DiscoveredAt: now, ParseCoverage: &model.ParseCoverage{CompanionOf: "vol1/SYSTEM"}},
	}
	if err = s.SaveSourceFiles(rows); err != nil {
		t.Fatal(err)
	}
	snap, err := s.FreezeReviewSnapshot(context.Background(), "case01", "run01")
	if err != nil {
		t.Fatal(err)
	}
	if snap.Coverage.ParseCoverageNotRecorded != 1 {
		t.Errorf("not-recorded sources = %d, want 1 (the companion label is not a measurement)", snap.Coverage.ParseCoverageNotRecorded)
	}
	if snap.SourceParseGaps != 0 {
		t.Errorf("parse gaps = %d, want 0", snap.SourceParseGaps)
	}
}
