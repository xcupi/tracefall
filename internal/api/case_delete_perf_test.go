package api

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"tracefall/internal/model"
)

// What Delete Case actually costs, and where.
//
// The shape measured here is the one reported: one collection, 7,074
// evidence files, 2,319 events. The point is to find out whether the
// backend has anything real to report progress ABOUT before any progress
// UI is designed around it.

func caseWithEvidence(t *testing.T, svc *Service, name string, files, events int) (string, string) {
	t.Helper()
	c, err := svc.CreateCase(name, "")
	if err != nil {
		t.Fatal(err)
	}
	collectionID, sourceFiles := perfCollection(t, svc, c.ID, files, 0, true)

	// Events spread across the collection's files, with one observation
	// each -- what an import actually writes.
	if events > 0 {
		evs := make([]model.Event, 0, events)
		obs := make([]model.EventObservation, 0, events)
		now := time.Now().UTC()
		for i := 0; i < events; i++ {
			sf := sourceFiles[i%len(sourceFiles)]
			e := model.Event{
				ID: uuid.NewString(), CaseID: c.ID, CollectionID: collectionID,
				SourceFileID: sf.ID, Timestamp: now,
				EventType: model.EventPrefetchExecution, ArtifactType: model.ArtifactPrefetch,
				Parser: "prefetchraw@1", FilePath: sf.Path, DedupHash: uuid.NewString(),
			}
			evs = append(evs, e)
			obs = append(obs, model.EventObservation{
				ID: uuid.NewString(), EventID: e.ID, CaseID: c.ID,
				CollectionID: collectionID, SourceFileID: sf.ID,
			})
		}
		if err := svc.store.SaveEvents(evs); err != nil {
			t.Fatal(err)
		}
		if err := svc.store.SaveEventObservations(obs); err != nil {
			t.Fatal(err)
		}
	}
	return c.ID, collectionID
}

func TestPerf_DeleteCase_ReportedShape(t *testing.T) {
	skipMeasurementUnderRace(t)
	if testing.Short() {
		t.Skip("timing measurement skipped in -short")
	}

	for _, tc := range []struct {
		name          string
		files, events int
	}{
		{"small", 10, 10},
		{"reported shape", 7074, 2319},
		{"large", 7074, 50000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := newTestService(t)
			caseID, _ := caseWithEvidence(t, svc, "delete perf "+tc.name, tc.files, tc.events)

			start := time.Now()
			if err := svc.DeleteCase(caseID); err != nil {
				t.Fatalf("DeleteCase: %v", err)
			}
			total := time.Since(start)
			t.Logf("%-16s %5d files / %6d events -> %v", tc.name, tc.files, tc.events, total)

			if _, err := svc.GetCase(caseID); err == nil {
				t.Error("the case survived deletion")
			}
		})
	}
}

// The two phases separately, because the whole progress question is
// whether the backend passes through anything an analyst could be shown.
func TestPerf_DeleteCase_PhaseBreakdown(t *testing.T) {
	skipMeasurementUnderRace(t)
	if testing.Short() {
		t.Skip("timing measurement skipped in -short")
	}

	svc := newTestService(t)
	caseID, _ := caseWithEvidence(t, svc, "phase breakdown", 7074, 2319)

	dir := svc.files.CaseDir(caseID)
	var onDisk int
	_ = filepathWalkCount(dir, &onDisk)

	t0 := time.Now()
	if err := svc.store.DeleteCase(caseID); err != nil {
		t.Fatal(err)
	}
	dbPhase := time.Since(t0)

	t1 := time.Now()
	if err := svc.files.RemoveCaseDir(caseID); err != nil {
		t.Fatal(err)
	}
	fsPhase := time.Since(t1)

	t.Logf("phase 1  database transaction (13 bulk DELETEs, one commit)  %v", dbPhase)
	t.Logf("phase 2  RemoveCaseDir (%d files on disk)                    %v", onDisk, fsPhase)
	t.Logf("total                                                        %v", dbPhase+fsPhase)
	t.Logf("db share %.0f%%, filesystem share %.0f%%",
		100*float64(dbPhase)/float64(dbPhase+fsPhase),
		100*float64(fsPhase)/float64(dbPhase+fsPhase))
}

func filepathWalkCount(root string, n *int) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			_ = filepathWalkCount(root+"/"+e.Name(), n)
			continue
		}
		*n++
	}
	return nil
}

var _ = fmt.Sprintf
