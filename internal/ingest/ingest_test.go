package ingest

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/normalize"
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

// TestParseFile_LeavesHostToTheServiceLayer pins ParseFile's Phase 7.1
// contract: it reports the host the artifact itself recorded and nothing
// more. Prefetch records structurally have no host field, so parsing a
// Prefetch file alone must yield blank hosts here rather than a value
// guessed from this one file -- resolving those is
// internal/api.Service.enrichBatchHosts's job, done once over the whole
// import batch so the answer can't depend on which file was parsed
// first (see that function, and internal/api's host-enrichment tests).
//
// This replaces the old TestBackfillHost, which asserted the removed
// per-file backfillHost's majority-vote behavior -- the exact behavior
// Phase 7.1 removed as both order-dependent in aggregate and, on a
// genuinely multi-host file, a fabricated answer.
func TestParseFile_LeavesHostToTheServiceLayer(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "synthetic_case")
	files, err := Discover(root, Registry())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	registry := Registry()

	var prefetchPath string
	for _, df := range files {
		if df.ArtifactType == model.ArtifactPrefetch {
			prefetchPath = df.Path
			break
		}
	}
	if prefetchPath == "" {
		t.Fatal("test setup: no Prefetch file in the synthetic dataset")
	}

	res, err := ParseFile("case-1", "collection-1", "sf-1", root, prefetchPath, findParser(registry, prefetchPath))
	if err != nil {
		t.Fatalf("ParseFile(%s): %v", prefetchPath, err)
	}
	if len(res.Events) == 0 {
		t.Fatal("got 0 events from the Prefetch file")
	}
	for _, e := range res.Events {
		if e.Host != "" {
			t.Errorf("Prefetch event carries Host %q -- ParseFile must not infer a host from a single file", e.Host)
		}
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
// host: several artifact types here (Prefetch, registry, Scheduled
// Tasks) never carry a host natively at all, and ParseFile reports only
// what the artifact recorded -- filling those in from the rest of the
// import batch is Service.enrichBatchHosts's job, exercised at the API
// level in internal/api's tests, not this package's.
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

// Raw evidence a parser produces beyond its events must survive import.
//
// ParseFile pairs raw[i] to events[i] positionally. Anything past that
// index was silently dropped, which lost two real things: a parser's own
// analysis report (appended after its events), and the ENTIRE output of
// a parser that deliberately produces no events -- the NTFS $LogFile
// parser validates the transaction log and emits metadata only, so
// every record it produced was discarded.

func TestParseFileWithContextUserAttributionIgnoresServerRoot(t *testing.T) {
	const relPath = "Users/jdoe/AppData/Local/Chrome/History"
	parser := contextUserParser{}
	for _, rootLabel := range []string{"home/x/data", "Users/x/data", "tmp/tracefall/data"} {
		t.Run(rootLabel, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), filepath.FromSlash(rootLabel))
			full := filepath.Join(root, filepath.FromSlash(relPath))
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, []byte("evidence"), 0o600); err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseFileWithContext("case", "collection", "source", root, relPath, parser, parsers.ParseContext{})
			if err != nil {
				t.Fatal(err)
			}
			if got := parsed.Events[0].User; got != "jdoe" {
				t.Fatalf("server root %q changed evidence user: got %q", rootLabel, got)
			}
		})
	}
}

type contextUserParser struct{}

func (contextUserParser) Name() string         { return "context-user@1" }
func (contextUserParser) ArtifactType() string { return "test" }
func (contextUserParser) Detect(string) bool   { return true }
func (contextUserParser) Parse(string) (parsers.ParseResult, error) {
	return parsers.ParseResult{}, fmt.Errorf("Parse called without path context")
}
func (contextUserParser) ParseWithContext(_ string, ctx parsers.ParseContext) (parsers.ParseResult, error) {
	return parsers.ParseResult{Events: []model.Event{{User: normalize.UserFromEvidencePath(ctx.EvidencePath)}}}, nil
}

func TestParseFile_KeepsRawEvidenceBeyondTheEventCount(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.bin")
	if err := os.WriteFile(path, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}

	parsed, err := ParseFile("case-1", "coll-1", "sf-1", dir, "sample.bin", &extraRawParser{events: 2, extraRaw: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Events) != 2 {
		t.Fatalf("got %d events, want 2", len(parsed.Events))
	}
	if len(parsed.Raw) != 5 {
		t.Fatalf("got %d raw records, want 5 (2 paired + 3 unpaired)", len(parsed.Raw))
	}
	// The paired ones keep their link.
	for i := 0; i < 2; i++ {
		if parsed.Events[i].RawEvidenceID != parsed.Raw[i].ID {
			t.Errorf("event %d is not linked to raw[%d]", i, i)
		}
	}
	// The extras are scoped to the source file and carry no event link.
	for i := 2; i < 5; i++ {
		if parsed.Raw[i].SourceFileID != "sf-1" {
			t.Errorf("unpaired raw %d lost its source file", i)
		}
		if parsed.Raw[i].CaseID != "case-1" {
			t.Errorf("unpaired raw %d lost its case", i)
		}
		if parsed.Raw[i].ID == "" {
			t.Errorf("unpaired raw %d was given no id", i)
		}
	}

	// A parser with NO events keeps all of its raw evidence.
	metaOnly, err := ParseFile("case-1", "coll-1", "sf-1", dir, "sample.bin", &extraRawParser{events: 0, extraRaw: 4})
	if err != nil {
		t.Fatal(err)
	}
	if len(metaOnly.Events) != 0 {
		t.Fatalf("got %d events, want 0", len(metaOnly.Events))
	}
	if len(metaOnly.Raw) != 4 {
		t.Fatalf("a parser producing no events kept %d of 4 raw records", len(metaOnly.Raw))
	}
}

// extraRawParser emits a chosen number of events plus unpaired raw.
type extraRawParser struct {
	events   int
	extraRaw int
}

func (extraRawParser) Name() string         { return "extraraw@1" }
func (extraRawParser) ArtifactType() string { return "test_artifact" }
func (extraRawParser) Detect(string) bool   { return true }

func (p *extraRawParser) Parse(string) (parsers.ParseResult, error) {
	var res parsers.ParseResult
	for i := 0; i < p.events; i++ {
		res.Events = append(res.Events, model.Event{
			Timestamp: time.Unix(int64(1700000000+i), 0).UTC(),
			EventType: "test_event", SourceReference: fmt.Sprintf("evt:%d", i),
		})
		res.Raw = append(res.Raw, model.RawEvidence{
			SourceReference: fmt.Sprintf("evt:%d", i), Raw: `{"paired":true}`,
		})
	}
	for i := 0; i < p.extraRaw; i++ {
		res.Raw = append(res.Raw, model.RawEvidence{
			SourceReference: fmt.Sprintf("report:%d", i), Raw: `{"unpaired":true}`,
		})
	}
	return res, nil
}
