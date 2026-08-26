package ingest

import (
	"os"
	"path/filepath"
	"testing"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

// findParser mirrors Discover's own first-match-wins detection, for
// tests that need to hand ParseFile the same parser Discover would have
// classified a file under.
func findParser(registry []parsers.ArtifactParser, relPath string) parsers.ArtifactParser {
	for _, p := range registry {
		if p.Detect(relPath) {
			return p
		}
	}
	return nil
}

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

func TestDiscover_ClassifiesUnrecognizedFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("not evidence"), 0o644); err != nil {
		t.Fatal(err)
	}
	files, err := Discover(dir, Registry())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("got %d discovered files, want 1", len(files))
	}
	f := files[0]
	if f.Path != "readme.txt" || f.Supported {
		t.Errorf("readme.txt classified as %+v, want unsupported", f)
	}
	if f.SHA256 == "" {
		t.Error("expected a SHA-256 to be computed even for an unsupported file")
	}
}

func TestDiscover_SyntheticCase(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "synthetic_case")
	files, err := Discover(root, Registry())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	var supported, unsupported int
	for _, f := range files {
		if f.Supported {
			supported++
			if f.ArtifactType == "" || f.Parser == "" {
				t.Errorf("supported file %s missing artifact type/parser: %+v", f.Path, f)
			}
		} else {
			unsupported++
		}
		if f.SHA256 == "" {
			t.Errorf("discovered file %s has no SHA-256", f.Path)
		}
		if f.SizeBytes <= 0 {
			t.Errorf("discovered file %s has non-positive size %d", f.Path, f.SizeBytes)
		}
	}
	if supported != 5 {
		t.Errorf("got %d supported files, want 5 (EvtxECmd, PECmd, RECmd, 2 task XML)", supported)
	}
	if unsupported == 0 {
		t.Error("expected at least one unsupported file in the synthetic dataset (e.g. its README)")
	}
}

// TestParseFile_SyntheticCase parses each supported file independently
// (the way the select-then-import workflow does, one file at a time --
// see internal/api.Service.ImportEvidence) and checks provenance
// stamping. It deliberately does not assert every event ends up with a
// host: ParseFile's own backfillHost only has the one file it just
// parsed to learn a dominant host from, and several artifact types here
// (Prefetch, registry, Scheduled Tasks) never carry a host natively at
// all -- filling those in from the rest of the case is
// Service.enrichMissingHosts's job, exercised at the API level in
// internal/api's tests, not this package's.
func TestParseFile_SyntheticCase(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "synthetic_case")
	files, err := Discover(root, Registry())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	registry := Registry()
	var totalEvents int
	var sawHost bool
	for _, df := range files {
		if !df.Supported {
			continue
		}
		matched := findParser(registry, df.Path)
		if matched == nil {
			t.Fatalf("no parser matched supposedly-supported file %s", df.Path)
		}
		res, err := ParseFile("case-1", "collection-1", "sf-1", root, df.Path, matched)
		if err != nil {
			t.Fatalf("ParseFile(%s): %v", df.Path, err)
		}
		for _, e := range res.Events {
			if e.ID == "" || e.CaseID != "case-1" || e.CollectionID != "collection-1" || e.SourceFileID != "sf-1" {
				t.Errorf("event missing required provenance fields: %+v", e)
			}
			if e.Host != "" {
				sawHost = true
			}
		}
		totalEvents += len(res.Events)
	}
	if totalEvents == 0 {
		t.Error("got 0 events from the synthetic dataset")
	}
	if !sawHost {
		t.Error("expected at least the EvtxECmd file's events to carry a host natively")
	}
}
