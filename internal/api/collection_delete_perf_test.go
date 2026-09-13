package api

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"tracefall/internal/model"
)

// Measurement harness for collection deletion. This file exists to
// ANSWER a question before anything is changed: why does deleting a
// pending collection of 7,074 discovered files with nothing imported
// take a long time?

// perfCollection builds a collection with `discovered` cataloged source
// files, `imported` of which are marked imported and carry one event
// each. Rows are written in ONE transaction, so building the fixture
// does not itself measure the thing under test.
func perfCollection(t *testing.T, svc *Service, caseID string, discovered, imported int, onDisk bool) (string, []model.SourceFile) {
	t.Helper()
	collectionID := uuid.NewString()

	dir := ""
	if onDisk {
		dir = svc.files.EvidenceDir(caseID, collectionID)
		if err := svc.files.EnsureCollectionDir(caseID, collectionID); err != nil {
			t.Fatal(err)
		}
	}

	files := make([]model.SourceFile, 0, discovered)
	now := time.Now().UTC()
	for i := 0; i < discovered; i++ {
		rel := fmt.Sprintf("Windows/Prefetch/FILE_%05d.pf", i)
		f := model.SourceFile{
			ID: uuid.NewString(), CaseID: caseID, CollectionID: collectionID,
			OriginalFilename: filepath.Base(rel), Path: rel,
			SizeBytes: 1024, DiscoveredAt: now,
			ImportStatus: model.SourceFileDiscovered,
		}
		// The real shape: most discovered files are unsupported and were
		// never imported.
		if i%4 == 0 {
			f.ArtifactType = model.ArtifactPrefetch
			f.Parser = "prefetchraw@1"
			f.Supported = true
		}
		if i < imported {
			// Distinct hashes: idx_source_files_collection_sha256_active is
			// a UNIQUE index over (collection_id, sha256) scoped to
			// imported, non-deleted rows.
			f.SHA256 = fmt.Sprintf("%064x", i+1)
			f.ImportStatus = model.SourceFileImported
			f.Supported = true
			f.ArtifactType = model.ArtifactPrefetch
			f.Parser = "prefetchraw@1"
			f.EventCount = 1
			ts := now
			f.ImportedAt = &ts
		}
		files = append(files, f)

		if onDisk {
			full := filepath.Join(dir, filepath.FromSlash(rel))
			_ = os.MkdirAll(filepath.Dir(full), 0o755)
			_ = os.WriteFile(full, []byte("x"), 0o644)
		}
	}

	col := model.Collection{
		ID: collectionID, CaseID: caseID, CreatedAt: now,
		SourceType: model.SourceTypeUpload, OriginalFilename: "upload.zip",
		EvidenceDirectory: dir,
		IngestionStatus:   model.CollectionStatusPending,
		FileCount:         discovered,
		ImportedFileCount: imported,
	}
	if err := svc.store.CreateCollectionWithSourceFiles(col, files); err != nil {
		t.Fatal(err)
	}

	// Imported files get one event and one observation each, written in
	// bulk so the fixture cost stays out of the measurement.
	if imported > 0 {
		events := make([]model.Event, 0, imported)
		for i := 0; i < imported; i++ {
			events = append(events, model.Event{
				ID: uuid.NewString(), CaseID: caseID, CollectionID: collectionID,
				SourceFileID: files[i].ID, Timestamp: now,
				EventType: model.EventPrefetchExecution, ArtifactType: model.ArtifactPrefetch,
				Parser: "prefetchraw@1", FilePath: files[i].Path,
				DedupHash: uuid.NewString(),
			})
		}
		if err := svc.store.SaveEvents(events); err != nil {
			t.Fatal(err)
		}
		// One observation per event, which is what a real import writes.
		// Without them the per-file loop finds nothing to unpick and the
		// comparison would not exercise the event path at all.
		obs := make([]model.EventObservation, 0, imported)
		for i, e := range events {
			obs = append(obs, model.EventObservation{
				ID: uuid.NewString(), EventID: e.ID, CaseID: caseID,
				CollectionID: collectionID, SourceFileID: files[i].ID,
			})
		}
		if err := svc.store.SaveEventObservations(obs); err != nil {
			t.Fatal(err)
		}
	}
	return collectionID, files
}

// TestPerf_DeleteCollection_ABC is the reproduction the investigation
// asked for: the same operation against three collection shapes, timed.
func TestPerf_DeleteCollection_ABC(t *testing.T) {
	skipMeasurementUnderRace(t)
	if testing.Short() {
		t.Skip("timing measurement skipped in -short")
	}

	cases := []struct {
		name                 string
		discovered, imported int
	}{
		{"C empty", 0, 0},
		{"A 7074 discovered / 0 imported", 7074, 0},
		{"B 500 discovered / 500 imported", 500, 500},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := newTestService(t)
			c, err := svc.CreateCase("perf "+tc.name, "")
			if err != nil {
				t.Fatal(err)
			}
			collectionID, _ := perfCollection(t, svc, c.ID, tc.discovered, tc.imported, true)

			start := time.Now()
			res, err := svc.DeleteCollection(c.ID, collectionID)
			elapsed := time.Since(start)
			if err != nil {
				t.Fatalf("DeleteCollection: %v", err)
			}

			t.Logf("%-34s discovered=%-5d imported=%-4d -> %v (source files removed %d, events removed %d)",
				tc.name, tc.discovered, tc.imported, elapsed, res.SourceFilesRemoved, res.EventsRemoved)

			// The collection and its rows must actually be gone.
			if _, err := svc.store.GetCollection(collectionID); err == nil {
				t.Error("the collection row survived deletion")
			}
			remaining, err := svc.store.ListSourceFilesByCollection(collectionID)
			if err != nil {
				t.Fatal(err)
			}
			if len(remaining) != 0 {
				t.Errorf("%d source file rows survived deletion", len(remaining))
			}
		})
	}
}

// TestPerf_DeleteCollection_PhaseBreakdown splits the same deletion into
// its phases, so the cost can be attributed rather than guessed at.
func TestPerf_DeleteCollection_PhaseBreakdown(t *testing.T) {
	skipMeasurementUnderRace(t)
	if testing.Short() {
		t.Skip("timing measurement skipped in -short")
	}

	svc := newTestService(t)
	c, err := svc.CreateCase("phase breakdown", "")
	if err != nil {
		t.Fatal(err)
	}
	const n = 7074
	collectionID, files := perfCollection(t, svc, c.ID, n, 0, true)

	// Phase 1: read the catalog.
	t0 := time.Now()
	listed, err := svc.store.ListSourceFilesByCollection(collectionID)
	listMs := time.Since(t0)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != n {
		t.Fatalf("listed %d files, want %d", len(listed), n)
	}

	// Phase 2: the per-file loop, measured on a SAMPLE so the remaining
	// rows are still there for phase 3.
	const sample = 200
	ids := make([]string, 0, sample)
	for _, f := range files[:sample] {
		ids = append(ids, f.ID)
	}
	t1 := time.Now()
	if _, err := svc.DeleteSourceFiles(c.ID, ids); err != nil {
		t.Fatal(err)
	}
	loopMs := time.Since(t1)

	// Phase 3: the bulk statements, over everything that is left.
	t2 := time.Now()
	if err := svc.store.DeleteCollection(collectionID); err != nil {
		t.Fatal(err)
	}
	bulkMs := time.Since(t2)

	// Phase 4: the filesystem.
	t3 := time.Now()
	_ = svc.files.RemoveCollectionDir(c.ID, collectionID)
	fsMs := time.Since(t3)

	perFile := loopMs / sample
	t.Logf("phase 1  list %d catalog rows            %v", n, listMs)
	t.Logf("phase 2  per-file loop, %d files         %v  (%v per file)", sample, loopMs, perFile)
	t.Logf("         -> projected for %d files       %v", n, perFile*time.Duration(n))
	t.Logf("phase 3  bulk DELETE statements (%d left) %v", n-sample, bulkMs)
	t.Logf("phase 4  RemoveCollectionDir             %v", fsMs)
}

// The store opens SQLite with SetMaxOpenConns(1). A deletion that spends
// seconds issuing thousands of separate writes therefore holds the only
// connection for that whole time, and every other request queues behind
// it. This measures that, because a UI that has gone unresponsive looks
// identical to a deletion that has hung.
func TestPerf_DeleteCollection_BlocksOtherRequests(t *testing.T) {
	skipMeasurementUnderRace(t)
	if testing.Short() {
		t.Skip("timing measurement skipped in -short")
	}

	svc := newTestService(t)
	c, err := svc.CreateCase("contention", "")
	if err != nil {
		t.Fatal(err)
	}
	collectionID, _ := perfCollection(t, svc, c.ID, 7074, 0, true)

	// Baseline: an ordinary read with nothing else running.
	t0 := time.Now()
	if _, err := svc.GetCase(c.ID); err != nil {
		t.Fatal(err)
	}
	idle := time.Since(t0)

	type sample struct {
		wait time.Duration
		err  error
	}
	got := make(chan sample, 1)
	started := make(chan struct{})

	go func() {
		close(started)
		// Give the deletion a moment to be well inside its write loop.
		time.Sleep(150 * time.Millisecond)
		s := time.Now()
		_, err := svc.GetCase(c.ID)
		got <- sample{time.Since(s), err}
	}()

	<-started
	delStart := time.Now()
	if _, err := svc.DeleteCollection(c.ID, collectionID); err != nil {
		t.Fatal(err)
	}
	deletion := time.Since(delStart)

	s := <-got
	if s.err != nil {
		t.Fatalf("concurrent read failed: %v", s.err)
	}
	t.Logf("deletion took            %v", deletion)
	t.Logf("read with DB idle        %v", idle)
	t.Logf("same read during deletion %v  (%.0fx slower)", s.wait, float64(s.wait)/float64(idle))
}
