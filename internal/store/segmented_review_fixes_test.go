package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"tracefall/internal/model"
)

// Regression tests for the findings of the independent review of 3bda19e.

// F1: the review snapshot builds its SQL from a dynamic table name, so a
// literal-text scan cannot see it; it must still hide pending rows.
func TestReviewSnapshotWalkAndFingerprintIgnorePendingRows(t *testing.T) {
	s := openTest(t)
	seedSegSources(t, s)
	ctx := context.Background()
	if err := s.BeginSegmentedImport(segSrcA); err != nil {
		t.Fatal(err)
	}
	before, err := s.ReviewSnapshotFingerprint(ctx, segCase)
	if err != nil {
		t.Fatal(err)
	}
	commitSeg(t, s, segSrcA, 0, 3)
	commitSeg(t, s, segSrcA, 1, 2)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var events []string
	walkErr := walkReviewTx(ctx, tx, segCase, func(r BatchRecord) error {
		if r.Kind == "event" {
			events = append(events, r.ID)
		}
		return nil
	})
	_ = tx.Rollback() // single connection: release before the next call
	if walkErr != nil {
		t.Fatal(walkErr)
	}
	if len(events) != 1 || events[0] != "ev-base" {
		t.Errorf("review walk saw %v, want only the visible baseline event", events)
	}
	after, err := s.ReviewSnapshotFingerprint(ctx, segCase)
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Errorf("review fingerprint changed while only pending rows were added: %s -> %s", before, after)
	}
}

// The raw-size pre-check of the review snapshot must also ignore pending rows
// (a pending oversized row must not block or alter a visible case's review).
func TestReviewSnapshotSizeCheckIgnoresPendingRows(t *testing.T) {
	s := openTest(t)
	seedSegSources(t, s)
	if err := s.BeginSegmentedImport(segSrcA); err != nil {
		t.Fatal(err)
	}
	p := segPayload(segSrcA, 0, 1)
	big := make([]byte, 200*1024)
	for i := range big {
		big[i] = 'x'
	}
	p.Events[0].CommandLine = string(big)
	if _, err := s.CommitSegment(context.Background(), segSrcA, SegmentCheckpoint{Index: 0, Records: 1}, p); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReviewSnapshotFingerprint(context.Background(), segCase); err != nil {
		t.Errorf("a pending oversized event affected the review snapshot: %v", err)
	}
}

// F2: an importing source must not be soft-deletable (its rows would stay
// hidden forever and recovery could not reach it).
func TestSoftDeleteRefusesAnImportingSource(t *testing.T) {
	s := openTest(t)
	seedSegSources(t, s)
	if err := s.BeginSegmentedImport(segSrcA); err != nil {
		t.Fatal(err)
	}
	commitSeg(t, s, segSrcA, 0, 2)
	err := s.SoftDeleteSourceFile(segSrcA, time.Now().UTC())
	if !errors.Is(err, ErrSourceNotAdmissible) {
		t.Errorf("SoftDeleteSourceFile on an importing source = %v, want ErrSourceNotAdmissible", err)
	}
	sf, _ := s.GetSourceFile(segSrcA)
	if sf.ImportStatus != model.SourceFileImporting {
		t.Errorf("status changed to %q", sf.ImportStatus)
	}
	// An ordinary source still deletes exactly as before.
	if err := s.SoftDeleteSourceFile(segSrcB, time.Now().UTC()); err != nil {
		t.Errorf("ordinary soft delete: %v", err)
	}
}

// F2 (legacy/forced state): an importing source that is already marked
// deleted is still cleaned by recovery, and a failure on one orphan does not
// stop recovery of the others.
func TestRecoveryReachesADeletedImportingSourceAndContinues(t *testing.T) {
	s := openTest(t)
	seedSegSources(t, s)
	now := time.Now().UTC()
	if err := s.CreateCase(model.Case{ID: "case-2", Name: "second", Status: model.CaseStatusCreated, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveCollection(model.Collection{ID: "collection-2", CaseID: "case-2", CreatedAt: now, SourceType: model.SourceTypeLocalPath, IngestionStatus: model.CollectionStatusIngested}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveSourceFiles([]model.SourceFile{{ID: "src-c", CaseID: "case-2", CollectionID: "collection-2", OriginalFilename: "c.log", Path: "c.log",
		ArtifactType: model.ArtifactMSSQLLog, Parser: "mssql@1", Supported: true, SHA256: "h-c", ImportStatus: model.SourceFileDiscovered, DiscoveredAt: now}}); err != nil {
		t.Fatal(err)
	}
	if err := s.BeginSegmentedImport(segSrcA); err != nil {
		t.Fatal(err)
	}
	commitSeg(t, s, segSrcA, 0, 2)
	if err := s.BeginSegmentedImport("src-c"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE source_files SET deleted_at = ? WHERE id = ?`, fmtTime(now), segSrcA); err != nil {
		t.Fatal(err)
	}
	rec, err := s.RecoverOrphanedImports(context.Background(), func(string) bool { return false })
	if err != nil || len(rec) != 2 {
		t.Fatalf("recovery = %+v err=%v, want both orphans cleaned", rec, err)
	}
	if n := rowCount(t, s, `SELECT COUNT(*) FROM events WHERE source_file_id = ?`, segSrcA); n != 0 {
		t.Errorf("deleted importing source left %d events", n)
	}
	if has, _ := s.CaseHasImportingSource(segCase); has {
		t.Error("case still reports an importing source")
	}
}

// F3: while a segmented import is pending, another source of the same case
// must not commit events (it could not see the pending rows, so it could
// publish a duplicate); other cases are unaffected.
func TestOrdinaryEventWritesAreRefusedWhileTheCaseHasAnImportingSource(t *testing.T) {
	s := openTest(t)
	seedSegSources(t, s)
	if err := s.BeginSegmentedImport(segSrcA); err != nil {
		t.Fatal(err)
	}
	ts, _ := time.Parse(time.RFC3339, segTimeA)
	ordinary := model.Event{ID: "ev-ordinary", CaseID: segCase, CollectionID: segColl, Timestamp: ts, Host: "H", EventType: "x",
		ArtifactType: model.ArtifactMSSQLLog, SourceFileID: segSrcB, DedupHash: "dh-ordinary"}
	if err := s.SaveEvents([]model.Event{ordinary}); !errors.Is(err, ErrCaseImportInProgress) {
		t.Errorf("SaveEvents for another source = %v, want ErrCaseImportInProgress", err)
	}
	obs := model.EventObservation{ID: "ob-ordinary", EventID: "ev-base", CaseID: segCase, CollectionID: segColl, SourceFileID: segSrcB}
	if err := s.SaveEventObservations([]model.EventObservation{obs}); !errors.Is(err, ErrCaseImportInProgress) {
		t.Errorf("SaveEventObservations for another source = %v, want ErrCaseImportInProgress", err)
	}
	if n := rowCount(t, s, `SELECT COUNT(*) FROM events WHERE id = 'ev-ordinary'`); n != 0 {
		t.Error("refused write left a row")
	}
	// The importing source itself still commits.
	commitSeg(t, s, segSrcA, 0, 1)
	// After abort the case accepts ordinary writes again.
	if err := s.AbortSegmentedImport(context.Background(), segSrcA, "test"); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveEvents([]model.Event{ordinary}); err != nil {
		t.Errorf("ordinary write after abort: %v", err)
	}
}
