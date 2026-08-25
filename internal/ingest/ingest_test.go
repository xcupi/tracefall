package ingest

import (
	"os"
	"path/filepath"
	"testing"

	"tracefall/internal/model"
)

func TestBackfillHost(t *testing.T) {
	events := []model.Event{
		{Host: "WKSTN-042"},
		{Host: "WKSTN-042"},
		{Host: ""}, // e.g. a Prefetch/registry event with no native host field
		{Host: "OTHER-HOST"},
	}
	backfillHost(events)
	if events[2].Host != "WKSTN-042" {
		t.Errorf("blank host backfilled to %q, want the dominant host WKSTN-042", events[2].Host)
	}
	if events[3].Host != "OTHER-HOST" {
		t.Errorf("non-blank host was overwritten: got %q", events[3].Host)
	}
}

func TestWalk_SkipsUnrecognizedFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("not evidence"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Walk("case-1", "collection-1", dir, Registry())
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(res.SourceFiles) != 0 {
		t.Errorf("got %d source files, want 0", len(res.SourceFiles))
	}
	if len(res.Skipped) != 1 || res.Skipped[0] != "readme.txt" {
		t.Errorf("skipped = %v, want [readme.txt]", res.Skipped)
	}
}

func TestWalk_SyntheticCase(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "synthetic_case")
	res, err := Walk("case-1", "collection-1", root, Registry())
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(res.Errors) != 0 {
		t.Fatalf("unexpected parse errors: %v", res.Errors)
	}
	if len(res.SourceFiles) != 5 {
		t.Errorf("got %d source files, want 5 (EvtxECmd, PECmd, RECmd, 2 task XML)", len(res.SourceFiles))
	}
	if len(res.Events) == 0 {
		t.Error("got 0 events from the synthetic dataset")
	}
	for _, e := range res.Events {
		if e.ID == "" || e.CaseID != "case-1" || e.CollectionID != "collection-1" || e.SourceFileID == "" {
			t.Errorf("event missing required provenance fields: %+v", e)
		}
		if e.Host == "" {
			t.Errorf("event has no host after backfill: %+v", e)
		}
	}
}
