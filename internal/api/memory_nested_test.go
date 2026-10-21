package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tracefall/internal/model"
)

func nestedMemoryDir(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	b, _ := json.Marshal(memDoc())
	if err := os.WriteFile(filepath.Join(dir, "host01.vmem"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("acquisition notes"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A crash dump is not a memory image: the extension alone is far too
	// common in a triage folder to hand to Volatility.
	if err := os.WriteFile(filepath.Join(dir, "app.dmp"), []byte("crash"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, "host01.vmem"
}

func TestMemory_AnImageInsideAFolderIsAnalysedAsItsOwnCollection(t *testing.T) {
	svc, c, _ := memFixture(t, memDoc(), "unused.vmem")
	dir, name := nestedMemoryDir(t)
	res, err := svc.DiscoverEvidenceFromPath(c.ID, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.RelatedCollections) != 1 {
		t.Fatalf("related collections = %+v, want exactly the .vmem (not the .dmp)", res.RelatedCollections)
	}
	rc := res.RelatedCollections[0]
	if rc.Status != "discovered" || rc.CollectionID == "" || rc.Path != name {
		t.Fatalf("related = %+v", rc)
	}
	col, err := svc.store.GetCollection(rc.CollectionID)
	if err != nil || col.SourceType != model.SourceTypeMemoryImage || col.CaseID != c.ID {
		t.Fatalf("collection = %+v err=%v", col, err)
	}
	if cols, _ := svc.store.ListCollections(c.ID); len(cols) != 2 {
		t.Fatalf("case has %d collections, want folder + memory image", len(cols))
	}
}

func TestMemory_AFolderImageWithoutVolatilityIsDisclosedNotSilentlyDropped(t *testing.T) {
	svc := newTestService(t) // no runner
	c, _ := svc.CreateCase("nested no vol", "")
	dir, name := nestedMemoryDir(t)
	res, err := svc.DiscoverEvidenceFromPath(c.ID, dir)
	if err != nil {
		t.Fatalf("the folder itself must still be catalogued: %v", err)
	}
	if len(res.RelatedCollections) != 1 || res.RelatedCollections[0].Status != "not_analyzed" ||
		res.RelatedCollections[0].Path != name || res.RelatedCollections[0].Note == "" {
		t.Fatalf("related = %+v", res.RelatedCollections)
	}
	if cols, _ := svc.store.ListCollections(c.ID); len(cols) != 1 {
		t.Fatalf("case has %d collections, want only the folder", len(cols))
	}
}

func TestMemory_PipelineAnalysesAnImageFoundInsideAFolder(t *testing.T) {
	svc, c, _ := memFixture(t, memDoc(), "unused.vmem")
	svc.pipe.poll = 10 * time.Millisecond
	startWorker(t, svc)
	mux := routerFor(svc)
	dir, _ := nestedMemoryDir(t)
	_, job := enqueue(t, mux, c.ID, map[string]any{"local_path": dir})
	done := waitPipelineJob(t, mux, c.ID, job.ID)
	if done.Status != model.JobSucceeded || num(done.Result, "events") < 5 {
		t.Fatalf("job = %+v: the memory image in the folder produced no events", done)
	}
	evs, err := svc.store.ListEvents(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range evs {
		if e.ArtifactType == model.ArtifactMemoryAnalysis {
			return
		}
	}
	t.Fatal("no memory-analysis event was imported")
}
