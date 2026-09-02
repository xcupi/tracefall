package api

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tracefall/internal/browsercache/cachegen"
	"tracefall/internal/model"
)

// Regression guards for the browser evidence that already worked before
// legacy cache support was added.
//
// Adding two cache formats meant a new filename claim, two new content
// sniffs and a second parser in the registry. Any of those could have
// silently taken a file that belonged to an existing parser. These tests
// exist to fail loudly if that ever happens.

// firefoxPlaces builds a Firefox places.sqlite history database.
func firefoxPlaces(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "places.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{
		`CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_date INTEGER)`,
		`CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER, visit_type INTEGER)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	micros := pfRun.UnixMicro()
	if _, err := db.Exec(`INSERT INTO moz_places VALUES(1,'https://firefox.example.test/download.exe','Download',3,?)`, micros); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO moz_historyvisits VALUES(1,1,?,1)`, micros); err != nil {
		t.Fatal(err)
	}
	db.Close()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// browserRegressionCatalog puts every browser artifact in one collection
// alongside the new legacy cache files, which is the arrangement most
// likely to expose a parser stealing another's file.
func browserRegressionCatalog(t *testing.T) map[string][]byte {
	t.Helper()
	return map[string][]byte{
		"Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/History":                           sampleBrowserHistory(t),
		"Users/jdoe/AppData/Roaming/Mozilla/Firefox/Profiles/x1y2.default-release/places.sqlite":     firefoxPlaces(t),
		"Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/Cache/Cache_Data/aa11bb22cc33_0":   chromeCacheEntry("https://simple.example.test/current.js", "application/javascript"),
		"Users/jdoe/AppData/Roaming/Mozilla/Firefox/Profiles/x1y2.default-release/cache2/entries/A1": ffCacheEntry("https://cache2.example.test/current.css", cacheFetched, "text/css"),
		"Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/Cache/data_1":                      blockfileData(),
		"Users/jdoe/AppData/Local/Mozilla/Firefox/Profiles/ab12.default/Cache/_CACHE_001_":           cache1Block(),
	}
}

// Every browser artifact is still claimed by the parser that owns it.
func TestRegression_EachBrowserArtifactKeepsItsOwnParser(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Browser parser ownership")
	disc := discoverBinaryDir(t, mux, c.ID, browserRegressionCatalog(t))

	want := map[string]struct{ artifact, parser string }{
		"Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/History":                           {model.ArtifactBrowserHistory, "browserhistory@1"},
		"Users/jdoe/AppData/Roaming/Mozilla/Firefox/Profiles/x1y2.default-release/places.sqlite":     {model.ArtifactBrowserHistory, "browserhistory@1"},
		"Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/Cache/Cache_Data/aa11bb22cc33_0":   {model.ArtifactBrowserCache, "browsercache@1"},
		"Users/jdoe/AppData/Roaming/Mozilla/Firefox/Profiles/x1y2.default-release/cache2/entries/A1": {model.ArtifactBrowserCache, "browsercache@1"},
		"Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/Cache/data_1":                      {model.ArtifactBrowserCache, "browsercache@1"},
		"Users/jdoe/AppData/Local/Mozilla/Firefox/Profiles/ab12.default/Cache/_CACHE_001_":           {model.ArtifactBrowserCache, "browsercache@1"},
	}
	for path, w := range want {
		sf, ok := sourceFileByPath(disc.SourceFiles, path)
		if !ok {
			t.Errorf("%s was not discovered", path)
			continue
		}
		if !sf.Supported {
			t.Errorf("%s is no longer supported: %s", path, sf.UnsupportedReason)
			continue
		}
		if sf.ArtifactType != w.artifact {
			t.Errorf("%s artifact type = %q, want %q -- a parser took another's file", path, sf.ArtifactType, w.artifact)
		}
		if sf.Parser != w.parser {
			t.Errorf("%s parser = %q, want %q", path, sf.Parser, w.parser)
		}
	}
}

// Chromium History parsing is byte-for-byte what it was: same event
// count, same type, same confidence, same URL, same user and process.
func TestRegression_ChromiumHistoryIsUnchanged(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Chromium history regression")
	disc := discoverBinaryDir(t, mux, c.ID, browserRegressionCatalog(t))
	importAllFrom(t, mux, c.ID, disc)

	var visits []model.Event
	for _, e := range typedTimeline(t, mux, c.ID) {
		if e.ArtifactType == model.ArtifactBrowserHistory && e.Extra["browser"] == "chromium" {
			visits = append(visits, e)
		}
	}
	if len(visits) != 1 {
		t.Fatalf("got %d Chromium history events, want 1", len(visits))
	}
	e := visits[0]
	if e.EventType != model.EventBrowserVisit {
		t.Errorf("event type = %q", e.EventType)
	}
	if e.Confidence != 1.0 {
		t.Errorf("confidence = %v; browser history must stay at 1.0", e.Confidence)
	}
	if e.Extra["url"] != "https://updates.example.test/payload.exe" {
		t.Errorf("url = %q", e.Extra["url"])
	}
	if e.User != "jdoe" {
		t.Errorf("user = %q; history still attributes a user, unlike cache", e.User)
	}
	if e.ProcessName == "" {
		t.Error("history still names the browser process, unlike cache")
	}
	if !e.Timestamp.Equal(pfRun.UTC()) {
		t.Errorf("timestamp = %s, want %s", e.Timestamp, pfRun.UTC())
	}
}

// Firefox places.sqlite parsing is unchanged.
func TestRegression_FirefoxPlacesIsUnchanged(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Firefox places regression")
	disc := discoverBinaryDir(t, mux, c.ID, browserRegressionCatalog(t))
	importAllFrom(t, mux, c.ID, disc)

	var visits []model.Event
	for _, e := range typedTimeline(t, mux, c.ID) {
		if e.ArtifactType == model.ArtifactBrowserHistory && strings.Contains(e.Extra["url"], "firefox.example.test") {
			visits = append(visits, e)
		}
	}
	if len(visits) != 1 {
		t.Fatalf("got %d Firefox history events, want 1", len(visits))
	}
	e := visits[0]
	if e.EventType != model.EventBrowserVisit {
		t.Errorf("event type = %q", e.EventType)
	}
	if e.Confidence != 1.0 {
		t.Errorf("confidence = %v", e.Confidence)
	}
	if e.Extra["browser"] != "firefox" {
		t.Errorf("browser = %q", e.Extra["browser"])
	}
	if e.Extra["visit_count"] != "3" {
		t.Errorf("visit count = %q, want 3", e.Extra["visit_count"])
	}
	if !e.Timestamp.Equal(pfRun.UTC()) {
		t.Errorf("timestamp = %s", e.Timestamp)
	}
}

// Simple Cache parsing is unchanged: still imported, still producing NO
// timeline event, still keeping its metadata.
func TestRegression_SimpleCacheIsUnchanged(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Simple cache regression")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		"Cache/Cache_Data/aa11bb22cc33_0": chromeCacheEntry("https://simple.example.test/current.js", "application/javascript"),
		// Present so the new formats are in the same import.
		"Cache/data_1":      blockfileData(),
		"Cache/_CACHE_001_": cache1Block(),
	})
	imp := importAllFrom(t, mux, c.ID, disc)
	if len(imp.ParseFailures) != 0 {
		t.Fatalf("parse failures: %+v", imp.ParseFailures)
	}
	if len(imp.Imported) != 3 {
		t.Fatalf("imported %d files, want 3", len(imp.Imported))
	}

	for _, e := range cacheEvents(typedTimeline(t, mux, c.ID)) {
		if e.Extra["cache_format"] == "chromium_simple_cache" {
			t.Error("a Simple Cache entry reached the timeline; the format records no timestamp")
		}
		// The formats that DO record a time still carry their own.
		if e.Timestamp.IsZero() {
			t.Errorf("%s event has no timestamp", e.Extra["cache_format"])
		}
	}
	// The Simple Cache entry's own metadata still resolves, unchanged.
	var found bool
	for _, sf := range imp.Imported {
		if sf.OriginalFilename != "aa11bb22cc33_0" {
			continue
		}
		found = true
		var prov SourceFileProvenance
		rec := doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/sources/"+sf.ID+"/provenance", nil, &prov)
		if rec.Code != 200 {
			t.Fatalf("provenance returned %d", rec.Code)
		}
		if prov.SourceFile.Parser != "browsercache@1" {
			t.Errorf("parser = %q", prov.SourceFile.Parser)
		}
		if prov.EventCount != 0 {
			t.Errorf("the Simple Cache entry produced %d events", prov.EventCount)
		}
	}
	if !found {
		t.Fatal("the Simple Cache entry was not imported")
	}
}

// The new filename claim is the narrowest possible: it must not take a
// file from any other parser, in or out of a cache directory.
func TestRegression_Cache1NameClaimStealsNothing(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Name claim scope")
	files := map[string][]byte{
		"Windows/Prefetch/UPDATE.EXE-0BADF00D.pf":                                                    samplePrefetch(),
		"Users/jdoe/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadline/ConsoleHost_history.txt": []byte("whoami\n"),
		"Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/History":                           sampleBrowserHistory(t),
		"C/$MFT": sampleMFT(),
	}
	disc := discoverBinaryDir(t, mux, c.ID, files)
	want := map[string]string{
		"Windows/Prefetch/UPDATE.EXE-0BADF00D.pf":                                                    model.ArtifactPrefetch,
		"Users/jdoe/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadline/ConsoleHost_history.txt": model.ArtifactPowerShellHistory,
		"Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/History":                           model.ArtifactBrowserHistory,
		"C/$MFT": model.ArtifactMFT,
	}
	for path, artifact := range want {
		sf, ok := sourceFileByPath(disc.SourceFiles, path)
		if !ok {
			t.Errorf("%s was not discovered", path)
			continue
		}
		if sf.ArtifactType != artifact {
			t.Errorf("%s artifact type = %q, want %q", path, sf.ArtifactType, artifact)
		}
	}
}

// The container parser must never claim an entry file, and vice versa.
func TestRegression_ContainerAndEntryParsersDoNotOverlap(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Parser overlap")
	files := map[string][]byte{
		"Cache/index":       cachegen.BuildChromiumBlockfileIndex(cachegen.BlockfileIndexOptions{NumEntries: 3}),
		"Cache/_CACHE_MAP_": cachegen.BuildFirefoxCache1Map(cachegen.Cache1MapOptions{EntryCount: 2, Records: 2}),
		"Cache/data_1":      blockfileData(),
		"Cache/_CACHE_001_": cache1Block(),
	}
	disc := discoverBinaryDir(t, mux, c.ID, files)
	want := map[string]string{
		"Cache/index":       model.ArtifactBrowserCacheIndex,
		"Cache/_CACHE_MAP_": model.ArtifactBrowserCacheIndex,
		"Cache/data_1":      model.ArtifactBrowserCache,
		"Cache/_CACHE_001_": model.ArtifactBrowserCache,
	}
	for path, artifact := range want {
		sf, _ := sourceFileByPath(disc.SourceFiles, path)
		if sf.ArtifactType != artifact {
			t.Errorf("%s artifact type = %q, want %q", path, sf.ArtifactType, artifact)
		}
	}
	imp := importAllFrom(t, mux, c.ID, disc)
	if len(imp.ParseFailures) != 0 {
		t.Fatalf("parse failures: %+v", imp.ParseFailures)
	}
	if len(imp.Imported) != 4 {
		t.Errorf("imported %d of 4", len(imp.Imported))
	}
}

// Evidence integrity is untouched by any of this: the original files are
// never modified, and their recorded hashes still verify.
func TestRegression_LegacyCacheImportPreservesIntegrity(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Legacy integrity")
	disc := discoverBinaryDir(t, mux, c.ID, browserRegressionCatalog(t))
	before := map[string]string{}
	for _, sf := range disc.SourceFiles {
		before[sf.Path] = sf.SHA256
	}
	importAllFrom(t, mux, c.ID, disc)

	var verify struct {
		Verified int  `json:"verified"`
		Failed   int  `json:"failed"`
		OK       bool `json:"ok"`
	}
	rec := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/evidence/"+disc.Collection.ID+"/verify-integrity", nil, &verify)
	if rec.Code != 200 {
		t.Fatalf("integrity verification returned %d: %s", rec.Code, rec.Body.String())
	}
	if verify.Failed != 0 {
		t.Errorf("%d files failed integrity verification after a legacy cache import", verify.Failed)
	}

	// Hashes recorded at discovery must be unchanged after parsing.
	var after DiscoverResult
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/evidence/"+disc.Collection.ID, nil, &after)
	for _, sf := range after.SourceFiles {
		if want, ok := before[sf.Path]; ok && sf.SHA256 != want {
			t.Errorf("%s hash changed during import: %s -> %s", sf.Path, want, sf.SHA256)
		}
	}
	_ = time.Now
}
