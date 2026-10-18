package browsercacheindex_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tracefall/internal/browsercache/cachegen"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
	parser "tracefall/internal/parsers/browsercacheindex"
)

var indexBase = time.Date(2025, 11, 3, 7, 0, 0, 0, time.UTC)

func write(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A Chromium blockfile index yields container metadata and NO events.
func TestIndex_BlockfileIndexIsMetadataOnly(t *testing.T) {
	data := cachegen.BuildChromiumBlockfileIndex(cachegen.BlockfileIndexOptions{
		NumEntries: 4812, NumBytes: 91_237_888, TableLen: 0x10000, LastFile: 6,
		CreateTimeUnix: indexBase.Unix(),
	})
	res, err := parser.New().Parse(write(t, "index", data))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 0 {
		t.Fatalf("a cache container produced %d timeline events; it describes a cache, not an activity", len(res.Events))
	}
	if len(res.Raw) != 1 {
		t.Fatalf("got %d records, want 1", len(res.Raw))
	}
	raw := res.Raw[0].Raw
	for _, want := range []string{
		`"declared_entries":4812`,
		`"cache_created":"2025-11-03T07:00:00Z"`,
		`"contains_urls":false`,
		"chromium_blockfile_index",
		"holds no cache keys",
		"data_1",
	} {
		if !strings.Contains(raw, want) {
			t.Errorf("the container record omits %q:\n%s", want, raw)
		}
	}
	if !strings.HasPrefix(res.Raw[0].SourceReference, "cache-container:") {
		t.Errorf("reference does not mark this as a container: %q", res.Raw[0].SourceReference)
	}
}

// A Firefox cache1 map yields its own counts and its clean-shutdown flag.
func TestIndex_Cache1MapIsMetadataOnly(t *testing.T) {
	data := cachegen.BuildFirefoxCache1Map(cachegen.Cache1MapOptions{
		EntryCount: 1204, RecordCount: 1204, Records: 1204, DataSize: 8 << 20, IsDirty: true,
	})
	res, err := parser.New().Parse(write(t, "_CACHE_MAP_", data))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 0 {
		t.Fatalf("got %d events, want 0", len(res.Events))
	}
	raw := res.Raw[0].Raw
	for _, want := range []string{
		`"declared_entries":1204`,
		`"shutdown_was_clean":false`,
		"firefox_cache1_map",
		"_CACHE_001_",
		"not shut down cleanly",
	} {
		if !strings.Contains(raw, want) {
			t.Errorf("the container record omits %q:\n%s", want, raw)
		}
	}
}

// A container with no recorded creation time reports null, not 1601.
func TestIndex_MissingCreationTimeIsNull(t *testing.T) {
	data := cachegen.BuildChromiumBlockfileIndex(cachegen.BlockfileIndexOptions{NumEntries: 2})
	res, err := parser.New().Parse(write(t, "index", data))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Raw[0].Raw, `"cache_created":null`) {
		t.Errorf("an unrecorded creation time was not reported as null:\n%s", res.Raw[0].Raw)
	}
	if strings.Contains(res.Raw[0].Raw, "1601") {
		t.Error("a 1601 epoch date leaked into the record")
	}
}

// Detection is content-only: "index" is far too common a name to claim.
func TestIndex_DetectionIsStructuralOnly(t *testing.T) {
	p := parser.New()
	for _, name := range []string{
		"Cache/index", "index", "cache2/index", "Documents/index", "_CACHE_MAP_",
	} {
		if p.Detect(name) {
			t.Errorf("%q was claimed by filename", name)
		}
	}
	if p.ArtifactType() != model.ArtifactBrowserCacheIndex {
		t.Errorf("artifact type = %q", p.ArtifactType())
	}

	for name, data := range map[string][]byte{
		"blockfile index": cachegen.BuildChromiumBlockfileIndex(cachegen.BlockfileIndexOptions{NumEntries: 1}),
		"cache1 map":      cachegen.BuildFirefoxCache1Map(cachegen.Cache1MapOptions{Records: 3}),
	} {
		if !p.DetectContent(data) {
			t.Errorf("%s was not content-detected", name)
		}
	}
	// It must not claim entry files, or anything else.
	for name, data := range map[string][]byte{
		"blockfile data": cachegen.BuildChromiumBlockfileData(nil),
		"cache1 block":   cachegen.BuildFirefoxCache1Block(256, nil),
		"simple cache":   cachegen.BuildChromiumSimple(cachegen.ChromiumEntry{Key: "https://example.test/x"}),
		"text":           []byte(strings.Repeat("plain text ", 60)),
		"zeros":          make([]byte, 512),
		"empty":          {},
	} {
		if p.DetectContent(data) {
			t.Errorf("%s was wrongly claimed as a cache container", name)
		}
	}
}

func TestIndex_RejectsNonContainers(t *testing.T) {
	_, err := parser.New().Parse(write(t, "index", []byte(strings.Repeat("nope ", 100))))
	if err == nil {
		t.Fatal("an unrelated file parsed as a cache container")
	}
	if !strings.Contains(err.Error(), "blockfile index") {
		t.Errorf("the error does not say what was expected: %v", err)
	}
}

// A truncated container is an error, not a record of zero entries.
func TestIndex_TruncatedContainerIsAnError(t *testing.T) {
	good := cachegen.BuildChromiumBlockfileIndex(cachegen.BlockfileIndexOptions{NumEntries: 5})
	if _, err := parser.New().Parse(write(t, "index", good[:20])); err == nil {
		t.Fatal("a truncated index parsed successfully")
	}
}

func TestIndex_IsDeterministic(t *testing.T) {
	path := write(t, "index", cachegen.BuildChromiumBlockfileIndex(cachegen.BlockfileIndexOptions{
		NumEntries: 77, CreateTimeUnix: indexBase.Unix(),
	}))
	p := parser.New()
	first, err := p.Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := p.Parse(path)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if again.Raw[0].Raw != first.Raw[0].Raw {
			t.Fatalf("run %d produced different output", i)
		}
	}
}

// Browser context is recovered from the path when the collection kept
// it, and is never presented as an identity.
func TestIndex_RecoversBrowserContext(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "Users", "jdoe", "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Cache")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(nested, "index")
	data := cachegen.BuildChromiumBlockfileIndex(cachegen.BlockfileIndexOptions{NumEntries: 9})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := parser.New().ParseWithContext(path, parsers.ParseContext{EvidencePath: "Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/Cache/index"})
	if err != nil {
		t.Fatal(err)
	}
	raw := res.Raw[0].Raw
	if !strings.Contains(raw, `"browser_profile":"Default"`) {
		t.Errorf("profile not recovered:\n%s", raw)
	}
	if !strings.Contains(raw, `"user_profile_path":"jdoe"`) {
		t.Errorf("user path not recovered:\n%s", raw)
	}
}
