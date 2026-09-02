package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"tracefall/internal/browsercache/cachegen"
	"tracefall/internal/model"
)

// Browser-cache triage classification.
//
// A browser cache is a small filesystem of its own: entry records,
// rankings, payload blocks, indexes, journals, locks and raw bodies. The
// question these tests answer is not "can we parse it" but "does triage
// tell an analyst the truth about each one" -- because most of those
// files are neither parseable nor broken, and a single message for all
// of them says nothing.

const cacheDir = "Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/Cache/"
const ffCacheDir = "Users/jdoe/AppData/Local/Mozilla/Firefox/Profiles/ab12.default/Cache/"

// fullCacheDirectory is every kind of file a real browser cache holds.
func fullCacheDirectory() map[string][]byte {
	at := time.Date(2026, 3, 14, 8, 15, 0, 0, time.UTC)
	entry := cachegen.BuildChromiumBlockfileData([]cachegen.BlockfileEntry{
		{Key: "https://example.test/app.js", CreationUnix: at.Unix(),
			StatusLine: "HTTP/1.1 200 OK", Headers: []string{"Content-Type: application/javascript"}},
	})
	return map[string][]byte{
		// Entries and containers: parsed.
		cacheDir + "data_1":                blockfileData(),
		cacheDir + "index":                 cachegen.BuildChromiumBlockfileIndex(cachegen.BlockfileIndexOptions{NumEntries: 3}),
		cacheDir + "Cache_Data/aa11bb22_0": chromeCacheEntry("https://example.test/simple.js", "application/javascript"),
		ffCacheDir + "_CACHE_001_":         cache1Block(),
		ffCacheDir + "_CACHE_MAP_":         cachegen.BuildFirefoxCache1Map(cachegen.Cache1MapOptions{EntryCount: 2, Records: 2}),
		// Auxiliary: recognized structurally, not parsed.
		cacheDir + "data_0": cachegen.BuildChromiumBlockfileDataSized(36, 64),
		cacheDir + "data_2": cachegen.BuildChromiumBlockfileDataSized(1024, 16),
		cacheDir + "data_3": cachegen.BuildChromiumBlockfileDataSized(4096, 4),
		// A cached body: no signature, exact filename shape.
		cacheDir + "f_0000a5": []byte("\x89PNG\r\n\x1a\n raw cached body, no metadata"),
		// Bookkeeping.
		cacheDir + "journal":              []byte("cache journal bookkeeping"),
		cacheDir + "LOCK":                 []byte(""),
		ffCacheDir + "parent.lock":        []byte("firefox profile lock"),
		cacheDir + "Cache_Data/index.log": []byte("cache2 index log"),
		// A hash index: names no URL.
		cacheDir + "Cache_Data/the-real-index": []byte("simple cache hash index"),
		// An unsupported variant: recognized structure, unknown layout.
		cacheDir + "data_9": cachegen.BuildChromiumBlockfileDataSized(777, 4),
		// Genuinely unidentifiable.
		cacheDir + "mystery.bin": []byte("\x17\x42\x99\x03 nothing identifies this at all"),
		// A real entry file, to prove nothing above swallowed it.
		cacheDir + "Cache_Data/data_1_lookalike": entry,
	}
}

// allTriaged pulls every file in a collection, not just discovery's
// first page. Discovery paginates, so a fixture larger than one page
// silently loses rows from disc.SourceFiles.
func allTriaged(t *testing.T, mux http.Handler, caseID, collectionID string) []TriagedSourceFile {
	t.Helper()
	var page struct {
		Items []TriagedSourceFile `json:"items"`
		Total int                 `json:"total"`
	}
	doJSON(t, mux, "GET",
		"/api/cases/"+caseID+"/evidence/"+collectionID+"/files?page=1&page_size=250", nil, &page)
	if len(page.Items) != page.Total {
		t.Fatalf("got %d of %d files; the fixture needs more than one page", len(page.Items), page.Total)
	}
	return page.Items
}

func triagedByPath(files []TriagedSourceFile, path string) (TriagedSourceFile, bool) {
	for _, f := range files {
		if f.Path == path {
			return f, true
		}
	}
	return TriagedSourceFile{}, false
}

type classExpect struct {
	artifact  string
	label     string
	supported bool
	priority  string
	// noteContains is a distinguishing fragment of the row's Notes text.
	noteContains string
}

// Every kind of file in a cache directory gets its own classification,
// its own label, its own priority and its own one-line note.
func TestCacheClass_EveryStructureIsClassifiedDistinctly(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Cache classification matrix")
	disc := discoverBinaryDir(t, mux, c.ID, fullCacheDirectory())
	files := allTriaged(t, mux, c.ID, disc.Collection.ID)

	want := map[string]classExpect{
		// --- 1. Supported entries ---
		cacheDir + "data_1": {model.ArtifactBrowserCache, "Browser cache entry", true, "medium", ""},
		cacheDir + "Cache_Data/aa11bb22_0": {
			model.ArtifactBrowserCache, "Browser cache entry", true, "medium", ""},
		cacheDir + "Cache_Data/data_1_lookalike": {
			model.ArtifactBrowserCache, "Browser cache entry", true, "medium", ""},
		ffCacheDir + "_CACHE_001_": {model.ArtifactBrowserCache, "Browser cache entry", true, "medium", ""},

		// --- 2. Supported containers ---
		cacheDir + "index": {
			model.ArtifactBrowserCacheIndex, "Browser cache container/index", true, "medium",
			"Not an event source"},
		ffCacheDir + "_CACHE_MAP_": {
			model.ArtifactBrowserCacheIndex, "Browser cache container/index", true, "medium",
			"Not an event source"},

		// --- 3. Blockfile auxiliary files ---
		cacheDir + "data_0": {
			model.ArtifactBrowserCacheRankings, "Chromium blockfile auxiliary file", false, "low",
			"Ranking/index data is not independently parsed"},
		cacheDir + "data_2": {
			model.ArtifactBrowserCachePayload, "Chromium blockfile payload file", false, "low",
			"metadata is stored in the associated data_1 entry records"},
		cacheDir + "data_3": {
			model.ArtifactBrowserCachePayload, "Chromium blockfile payload file", false, "low",
			"metadata is stored in the associated data_1 entry records"},
		cacheDir + "f_0000a5": {
			model.ArtifactBrowserCacheBody, "Chromium cached response body", false, "low",
			"metadata is stored in the associated data_1 entry record"},

		// --- 4. Journal / state / lock ---
		cacheDir + "journal": {
			model.ArtifactBrowserCacheState, "Browser cache journal/state", false, "low",
			"No independently parsed cache-entry metadata"},
		cacheDir + "LOCK": {
			model.ArtifactBrowserCacheState, "Browser cache journal/state", false, "low",
			"No independently parsed cache-entry metadata"},
		ffCacheDir + "parent.lock": {
			model.ArtifactBrowserCacheState, "Browser cache journal/state", false, "low",
			"No independently parsed cache-entry metadata"},
		cacheDir + "Cache_Data/index.log": {
			model.ArtifactBrowserCacheState, "Browser cache journal/state", false, "low",
			"No independently parsed cache-entry metadata"},

		// --- 5. Recognized structure, unsupported variant ---
		cacheDir + "data_9": {
			model.ArtifactBrowserCacheVariant, "Browser cache unsupported format", false, "medium",
			"this version or variant is not supported"},

		// --- 6. Unknown ---
		cacheDir + "mystery.bin": {
			model.ArtifactBrowserCacheUnknown, "Browser cache unknown", false, "low",
			"format could not be identified"},

		// The hash index keeps its own path-matched classification.
		cacheDir + "Cache_Data/the-real-index": {
			model.ArtifactBrowserCacheUnknown, "Browser cache hash index", false, "low",
			"names no URL"},
	}

	for path, w := range want {
		sf, ok := triagedByPath(files, path)
		if !ok {
			t.Errorf("%s was not discovered", path)
			continue
		}
		if sf.Supported != w.supported {
			t.Errorf("%s: supported = %v, want %v", path, sf.Supported, w.supported)
		}
		if sf.TypeLabel != w.label {
			t.Errorf("%s: label = %q, want %q", path, sf.TypeLabel, w.label)
		}
		if sf.Priority != w.priority {
			t.Errorf("%s: priority = %q, want %q", path, sf.Priority, w.priority)
		}
		if w.supported && sf.ArtifactType != w.artifact {
			t.Errorf("%s: artifact type = %q, want %q", path, sf.ArtifactType, w.artifact)
		}
		if w.noteContains != "" {
			note := sf.UnsupportedReason + sf.Note
			if !strings.Contains(note, w.noteContains) {
				t.Errorf("%s: note %q does not contain %q", path, note, w.noteContains)
			}
		}
	}
}

// The Notes column has to fit a table. No row may carry a paragraph, and
// no row may recite the list of supported cache formats.
func TestCacheClass_NotesAreConciseAndDoNotReciteTheFormatList(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Cache notes")
	disc := discoverBinaryDir(t, mux, c.ID, fullCacheDirectory())

	for _, sf := range allTriaged(t, mux, c.ID, disc.Collection.ID) {
		note := sf.UnsupportedReason
		if note == "" {
			note = sf.Note
		}
		if note == "" {
			continue
		}
		if len(note) > 200 {
			t.Errorf("%s: note is %d characters; the Notes column needs a line, not a paragraph:\n%s",
				sf.Path, len(note), note)
		}
		// The old fallback recited every supported format in every row.
		formats := 0
		for _, f := range []string{"Simple Cache", "blockfile data_1", "cache2", "_CACHE_00x_", "_CACHE_MAP_"} {
			if strings.Contains(note, f) {
				formats++
			}
		}
		if formats > 1 {
			t.Errorf("%s: the note recites the supported-format list (%d of them):\n%s", sf.Path, formats, note)
		}
	}
}

// No unsupported cache file may be described as a parse failure or as
// broken evidence. They are files that hold no independently useful
// metadata, which is a different thing entirely.
func TestCacheClass_UnsupportedIsNeverDescribedAsFailure(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Cache not failure")
	disc := discoverBinaryDir(t, mux, c.ID, fullCacheDirectory())

	banned := []string{"parse failed", "parse failure", "failed to parse", "corrupt", "broken", "damaged", "error"}
	for _, sf := range allTriaged(t, mux, c.ID, disc.Collection.ID) {
		note := strings.ToLower(sf.UnsupportedReason + " " + sf.Note)
		for _, b := range banned {
			if strings.Contains(note, b) {
				t.Errorf("%s: the note calls an unparsed cache file %q:\n%s", sf.Path, b, note)
			}
		}
	}
	// And importing the whole directory produces no parse failures for
	// them, because they are never selected in the first place.
	imp := importAllFrom(t, mux, c.ID, disc)
	if len(imp.ParseFailures) != 0 {
		t.Errorf("parse failures on a normal cache directory: %+v", imp.ParseFailures)
	}
}

// The supported count means "can be parsed into forensic records" and
// nothing looser. Recognizing a file must never inflate it.
func TestCacheClass_RecognitionDoesNotInflateTheSupportedCount(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Cache supported count")
	disc := discoverBinaryDir(t, mux, c.ID, fullCacheDirectory())

	// 6 parseable files: data_1, index, aa11bb22_0, data_1_lookalike,
	// _CACHE_001_, _CACHE_MAP_. Everything else is recognized, not
	// supported.
	if disc.Coverage.Supported != 6 {
		t.Errorf("supported = %d, want 6", disc.Coverage.Supported)
	}
	if disc.Coverage.Unsupported != 11 {
		t.Errorf("unsupported = %d, want 11", disc.Coverage.Unsupported)
	}
	if disc.Coverage.Discovered != 17 {
		t.Errorf("discovered = %d, want 17", disc.Coverage.Discovered)
	}
	// Recognized-but-unsupported classes must report zero supported
	// files in their coverage bucket.
	for _, b := range disc.Coverage.ByType {
		if !b.Supported && b.SupportedFiles != 0 {
			t.Errorf("%q is unsupported but claims %d supported files", b.TypeLabel, b.SupportedFiles)
		}
	}
	// None of the auxiliary/state/unknown classes may be recommended.
	for _, sf := range allTriaged(t, mux, c.ID, disc.Collection.ID) {
		if sf.Recommended && !sf.Supported {
			t.Errorf("%s is recommended but not supported", sf.Path)
		}
	}
}

// Recognition is structural. The same filename with different content
// must classify differently, and an auxiliary-looking name outside a
// cache directory must not be claimed at all.
func TestCacheClass_RecognitionIsStructuralNotByName(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Structural recognition")
	at := time.Date(2026, 3, 14, 8, 15, 0, 0, time.UTC)
	entry := cachegen.BuildChromiumBlockfileData([]cachegen.BlockfileEntry{
		{Key: "https://example.test/x.js", CreationUnix: at.Unix()},
	})
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		// Named data_0 but structurally an ENTRY file: must be parsed.
		cacheDir + "data_0": entry,
		// Named data_1 but structurally a RANKINGS file: must not be.
		cacheDir + "data_1": cachegen.BuildChromiumBlockfileDataSized(36, 32),
		// Cache-ish names outside any cache directory: not claimed.
		"Users/jdoe/Documents/journal":     []byte("a personal journal"),
		"Users/jdoe/Documents/data_0":      []byte("unrelated file"),
		"Users/jdoe/Documents/f_0000a5":    []byte("unrelated file"),
		"Users/jdoe/Documents/mystery.bin": []byte("unrelated file"),
	})

	files := allTriaged(t, mux, c.ID, disc.Collection.ID)
	sf, _ := triagedByPath(files, cacheDir+"data_0")
	if !sf.Supported || sf.ArtifactType != model.ArtifactBrowserCache {
		t.Errorf("a real entry file named data_0 was classified as %q (supported=%v); "+
			"classification must follow the bytes", sf.ArtifactType, sf.Supported)
	}
	sf, _ = triagedByPath(files, cacheDir+"data_1")
	if sf.Supported {
		t.Error("a rankings file named data_1 was classified as a parseable entry file")
	}
	if sf.TypeLabel != "Chromium blockfile auxiliary file" {
		t.Errorf("rankings-named-data_1 label = %q", sf.TypeLabel)
	}

	for _, p := range []string{
		"Users/jdoe/Documents/journal", "Users/jdoe/Documents/data_0",
		"Users/jdoe/Documents/f_0000a5", "Users/jdoe/Documents/mystery.bin",
	} {
		sf, ok := triagedByPath(files, p)
		if !ok {
			t.Errorf("%s was not discovered", p)
			continue
		}
		if strings.Contains(strings.ToLower(sf.TypeLabel), "cache") {
			t.Errorf("%s (outside any cache directory) was classified as browser cache: %q", p, sf.TypeLabel)
		}
	}
}

// A container is supported and parsed, and its note says plainly that it
// is not where the cached resources are.
func TestCacheClass_ContainerSaysItIsNotAnEventSource(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Container note")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		cacheDir + "index":         cachegen.BuildChromiumBlockfileIndex(cachegen.BlockfileIndexOptions{NumEntries: 9}),
		ffCacheDir + "_CACHE_MAP_": cachegen.BuildFirefoxCache1Map(cachegen.Cache1MapOptions{EntryCount: 4, Records: 4}),
	})
	for _, sf := range allTriaged(t, mux, c.ID, disc.Collection.ID) {
		if sf.ArtifactType != model.ArtifactBrowserCacheIndex {
			continue
		}
		if !sf.Supported {
			t.Errorf("%s: a container IS parsed and must stay supported", sf.Path)
		}
		if sf.UnsupportedReason != "" {
			t.Errorf("%s: a supported file carries an unsupported reason: %q", sf.Path, sf.UnsupportedReason)
		}
		if !strings.Contains(sf.Note, "Not an event source") {
			t.Errorf("%s: the note does not say it is not an event source: %q", sf.Path, sf.Note)
		}
		if !strings.Contains(strings.ToLower(sf.Note), "container") {
			t.Errorf("%s: the note does not identify it as a container: %q", sf.Path, sf.Note)
		}
	}
	imp := importAllFrom(t, mux, c.ID, disc)
	if imp.EventCount != 0 {
		t.Errorf("containers produced %d events", imp.EventCount)
	}
}

// A recognized-but-unsupported variant keeps MEDIUM: unlike an auxiliary
// file it may still hold recoverable forensic data.
func TestCacheClass_UnsupportedVariantKeepsMediumPriority(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Variant priority")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		cacheDir + "data_9":    cachegen.BuildChromiumBlockfileDataSized(777, 4),
		cacheDir + "truncated": cachegen.BuildChromiumBlockfileIndex(cachegen.BlockfileIndexOptions{NumEntries: 1})[:16],
		cacheDir + "data_0":    cachegen.BuildChromiumBlockfileDataSized(36, 4),
	})
	for path, want := range map[string]string{
		cacheDir + "data_9":    "medium",
		cacheDir + "truncated": "medium",
		cacheDir + "data_0":    "low",
	} {
		sf, ok := triagedByPath(allTriaged(t, mux, c.ID, disc.Collection.ID), path)
		if !ok {
			t.Errorf("%s was not discovered", path)
			continue
		}
		if sf.Priority != want {
			t.Errorf("%s: priority = %q, want %q", path, sf.Priority, want)
		}
		if sf.Supported {
			t.Errorf("%s: a variant/auxiliary file must not be supported", path)
		}
	}
}

// Every cache row still tells the analyst which cache formats ARE
// parsed, so a directory of auxiliary files can never read as "browser
// cache is unsupported".
func TestCacheClass_EveryRowStillNamesWhatIsParsed(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Boundary retained")
	disc := discoverBinaryDir(t, mux, c.ID, fullCacheDirectory())
	for _, sf := range allTriaged(t, mux, c.ID, disc.Collection.ID) {
		if sf.Supported {
			continue
		}
		if len(sf.ParsedInstead) == 0 {
			t.Errorf("%s does not name the browser evidence that IS parsed", sf.Path)
		}
		joined := strings.Join(sf.ParsedInstead, " | ")
		if !strings.Contains(joined, "Simple Cache") {
			t.Errorf("%s: ParsedInstead does not mention the cache formats: %q", sf.Path, joined)
		}
	}
}

// The classification changes must not disturb parsing: the same
// directory still yields exactly the entries it did.
func TestCacheClass_ParsingIsUnchanged(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Parsing unchanged")
	disc := discoverBinaryDir(t, mux, c.ID, fullCacheDirectory())
	imp := importAllFrom(t, mux, c.ID, disc)
	if len(imp.ParseFailures) != 0 {
		t.Fatalf("parse failures: %+v", imp.ParseFailures)
	}

	byFormat := map[string]int{}
	for _, e := range cacheEvents(typedTimeline(t, mux, c.ID)) {
		byFormat[e.Extra["cache_format"]]++
	}
	// data_1 (3) + the lookalike entry file (1) = 4 blockfile entries;
	// _CACHE_001_ holds 2; the Simple Cache entry records no time.
	if byFormat["chromium_blockfile"] != 4 {
		t.Errorf("got %d blockfile events, want 4", byFormat["chromium_blockfile"])
	}
	if byFormat["firefox_cache1"] != 2 {
		t.Errorf("got %d cache1 events, want 2", byFormat["firefox_cache1"])
	}
	if byFormat["chromium_simple_cache"] != 0 {
		t.Errorf("the Simple Cache produced %d events; it records no timestamp", byFormat["chromium_simple_cache"])
	}
}
