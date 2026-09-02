package api

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"tracefall/internal/browsercache/cachegen"
	"tracefall/internal/model"
)

// End-to-end browser cache ingestion (Phase 14).
//
// The recurring theme: a cache entry is response evidence, not user
// activity. Most of these tests exist to prove the negatives -- no
// invented timestamps, no invented user, no findings manufactured from
// a cached URL, and no regression in the browser HISTORY parser, which
// makes a much stronger claim about the same domains.

var cacheFetched = time.Date(2026, 4, 18, 9, 30, 0, 0, time.UTC)

func ffCacheEntry(url string, at time.Time, contentType string) []byte {
	return cachegen.BuildFirefoxCache2(cachegen.FirefoxEntry{
		Key:          "O^partitionKey=%28https%2Cexample.org%29,:" + url,
		LastFetched:  uint32(at.Unix()),
		LastModified: uint32(at.Add(-time.Hour).Unix()),
		FetchCount:   4,
		ResponseHead: "HTTP/1.1 200 OK\r\nContent-Type: " + contentType +
			"\r\nContent-Length: 4096\r\nServer: nginx\r\n",
		Body: []byte("cached-bytes"),
	})
}

func chromeCacheEntry(url, contentType string) []byte {
	return cachegen.BuildChromiumSimple(cachegen.ChromiumEntry{
		Key:        url,
		StatusLine: "HTTP/1.1 200 OK",
		Headers: []string{
			"Content-Type: " + contentType,
			"Content-Length: 2048",
			"Cache-Control: max-age=3600",
		},
		Body: []byte("chromium-cached-bytes"),
	})
}

// cacheCatalog holds both browsers' caches plus a browser History
// database, so every test can check that the two artifact types stay
// distinct.
func cacheCatalog(t *testing.T) map[string][]byte {
	t.Helper()
	return map[string][]byte{
		"Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/Cache/Cache_Data/0a1b2c3d4e5f6789_0": chromeCacheEntry(
			"https://cdn.example.test/analytics.js", "application/javascript"),
		"Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/Cache/Cache_Data/1b2c3d4e5f678901_0": chromeCacheEntry(
			"https://images.example.test/banner.png", "image/png"),
		"Users/jdoe/AppData/Roaming/Mozilla/Firefox/Profiles/x1y2.default-release/cache2/entries/5F2A91C0": ffCacheEntry(
			"https://updates.example.test/payload.exe", cacheFetched, "application/octet-stream"),
		"Users/jdoe/AppData/Roaming/Mozilla/Firefox/Profiles/x1y2.default-release/cache2/entries/6A3B82D1": ffCacheEntry(
			"https://cdn.example.test/style.css", cacheFetched.Add(2*time.Minute), "text/css"),
		"Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/History": sampleBrowserHistory(t),
	}
}

func cacheEvents(events []model.Event) []model.Event {
	var out []model.Event
	for _, e := range events {
		if e.ArtifactType == model.ArtifactBrowserCache {
			out = append(out, e)
		}
	}
	return out
}

func typedTimeline(t *testing.T, mux http.Handler, caseID string) []model.Event {
	t.Helper()
	var events []model.Event
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/timeline", nil, &events)
	return events
}

//  1. Classification: entries are recognized structurally, in both
//     browsers, and never confused with browser history.
func TestBrowserCache_ClassifiedAsItsOwnSupportedArtifact(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Cache classification")
	disc := discoverBinaryDir(t, mux, c.ID, cacheCatalog(t))

	var cacheFiles int
	for path := range cacheCatalog(t) {
		sf, ok := sourceFileByPath(disc.SourceFiles, path)
		if !ok {
			t.Errorf("%s was not discovered", path)
			continue
		}
		if strings.HasSuffix(path, "/History") {
			if sf.ArtifactType != model.ArtifactBrowserHistory {
				t.Errorf("the History database was classified as %q; browser history must not be reclassified as cache",
					sf.ArtifactType)
			}
			continue
		}
		cacheFiles++
		if !sf.Supported {
			t.Errorf("%s is not supported: %s", path, sf.UnsupportedReason)
		}
		if sf.ArtifactType != model.ArtifactBrowserCache {
			t.Errorf("%s artifact type = %q, want %q", path, sf.ArtifactType, model.ArtifactBrowserCache)
		}
		// The label is short; WHICH cache format an entry came from is
		// on the event and the raw record as cache_format_name, not
		// recited on every catalog row.
		if sf.TypeLabel != "Browser cache entry" {
			t.Errorf("%s label = %q", path, sf.TypeLabel)
		}
		// Deliberately NOT recommended: a real cache holds tens of
		// thousands of subresources, and "select recommended" must stay
		// a small high-value selection.
		if sf.Recommended {
			t.Errorf("%s is recommended; a bulk artifact of this size must not be in the recommended set", path)
		}
		if sf.Priority != "medium" {
			t.Errorf("%s priority = %q, want medium", path, sf.Priority)
		}
	}
	if cacheFiles != 4 {
		t.Fatalf("checked %d cache files, want 4", cacheFiles)
	}
}

// 2. A file that merely LIVES in a cache directory is not claimed.
func TestBrowserCache_NonEntryFilesAreNotClaimed(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Cache directory noise")
	files := map[string][]byte{
		"Users/j/AppData/Local/Google/Chrome/User Data/Default/Cache/Cache_Data/index":     []byte("not an entry, just an index stub"),
		"Users/j/AppData/Local/Google/Chrome/User Data/Default/Cache/Cache_Data/index-dir": make([]byte, 512),
		"Users/j/AppData/Local/Google/Chrome/User Data/Default/Cache/Cache_Data/data_1":    cachegen.ChromiumBlockfileIndex(),
		"Users/j/AppData/Local/Google/Chrome/User Data/Default/Cache/Cache_Data/todo.txt":  []byte("shopping list"),
		"Users/j/AppData/Local/Google/Chrome/User Data/Default/Cache/Cache_Data/valid_0":   chromeCacheEntry("https://example.test/x.js", "application/javascript"),
	}
	disc := discoverBinaryDir(t, mux, c.ID, files)

	for path := range files {
		sf, ok := sourceFileByPath(disc.SourceFiles, path)
		if !ok {
			t.Errorf("%s was not discovered", path)
			continue
		}
		isEntry := strings.HasSuffix(path, "valid_0")
		if isEntry && sf.ArtifactType != model.ArtifactBrowserCache {
			t.Errorf("a genuine entry was not recognized: %q", sf.ArtifactType)
		}
		if !isEntry && sf.Supported && sf.ArtifactType == model.ArtifactBrowserCache {
			t.Errorf("%s was claimed as a parseable cache entry; it is not one", path)
		}
		if !isEntry && sf.Supported == false && sf.UnsupportedReason == "" {
			t.Errorf("%s is unsupported but gives the analyst no reason", path)
		}
	}
}

//  3. Import: Firefox entries reach the timeline; Chromium entries are
//     imported without inventing a time.
func TestBrowserCache_ImportsAndReachesTheTimeline(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Cache import")
	disc := discoverBinaryDir(t, mux, c.ID, cacheCatalog(t))
	imp := importAllFrom(t, mux, c.ID, disc)
	if len(imp.ParseFailures) != 0 {
		t.Fatalf("parse failures: %+v", imp.ParseFailures)
	}
	if len(imp.Imported) != 5 {
		t.Fatalf("imported %d files, want 5", len(imp.Imported))
	}

	events := typedTimeline(t, mux, c.ID)
	cache := cacheEvents(events)
	if len(cache) != 2 {
		t.Fatalf("got %d cache events, want 2 (the two Firefox entries; Chromium Simple Cache records no time)", len(cache))
	}

	byURL := map[string]model.Event{}
	for _, e := range cache {
		byURL[e.Extra["url"]] = e
		if e.EventType != model.EventBrowserCacheEntry {
			t.Errorf("event type = %q", e.EventType)
		}
		if e.Extra["cached_body"] == "" || strings.Contains(e.Extra["cached_body"], "extracted (") == false {
			t.Errorf("the record does not state that the body was not extracted: %q", e.Extra["cached_body"])
		}
	}
	payload, ok := byURL["https://updates.example.test/payload.exe"]
	if !ok {
		t.Fatalf("the payload entry is missing; got %v", cachedURLs(byURL))
	}
	if !payload.Timestamp.Equal(cacheFetched) {
		t.Errorf("timestamp = %s, want %s (cache2 lastFetched)", payload.Timestamp, cacheFetched)
	}
	if payload.Extra["content_type"] != "application/octet-stream" {
		t.Errorf("content type = %q", payload.Extra["content_type"])
	}
	if payload.Extra["host"] != "updates.example.test" {
		t.Errorf("host = %q", payload.Extra["host"])
	}
	if payload.Extra["browser"] == "" {
		t.Error("the event does not name the browser")
	}
	if payload.Extra["browser_profile"] != "x1y2.default-release" {
		t.Errorf("profile = %q", payload.Extra["browser_profile"])
	}
	if payload.Extra["user_profile_path"] != "jdoe" {
		t.Errorf("user profile path = %q", payload.Extra["user_profile_path"])
	}
}

func cachedURLs(m map[string]model.Event) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

//  4. Chromium Simple Cache imports cleanly but contributes no timeline
//     event -- the format records no time and none is fabricated.
func TestBrowserCache_ChromiumImportsWithoutFabricatingTime(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Chromium cache")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		"Users/j/AppData/Local/Google/Chrome/User Data/Default/Cache/Cache_Data/aa11_0": chromeCacheEntry("https://example.test/a.js", "application/javascript"),
		"Users/j/AppData/Local/Google/Chrome/User Data/Default/Cache/Cache_Data/bb22_0": chromeCacheEntry("https://example.test/b.css", "text/css"),
	})
	imp := importAllFrom(t, mux, c.ID, disc)

	if len(imp.ParseFailures) != 0 {
		t.Fatalf("a valid Chromium entry was reported as a parse failure: %+v", imp.ParseFailures)
	}
	if len(imp.Imported) != 2 {
		t.Fatalf("imported %d files, want 2", len(imp.Imported))
	}
	if imp.EventCount != 0 {
		t.Errorf("Chromium Simple Cache produced %d timeline events; the format records no timestamp", imp.EventCount)
	}
	if len(typedTimeline(t, mux, c.ID)) != 0 {
		t.Error("a Chromium cache event reached the timeline with an invented time")
	}
}

// 5. Provenance resolves back to the original file for cache events.
func TestBrowserCache_ProvenanceResolves(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Cache provenance")
	disc := discoverBinaryDir(t, mux, c.ID, cacheCatalog(t))
	importAllFrom(t, mux, c.ID, disc)

	cache := cacheEvents(typedTimeline(t, mux, c.ID))
	if len(cache) == 0 {
		t.Fatal("no cache events")
	}
	for _, e := range cache {
		var prov EventProvenance
		rec := doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/events/"+e.ID, nil, &prov)
		if rec.Code != 200 {
			t.Fatalf("provenance for %s returned %d: %s", e.SourceReference, rec.Code, rec.Body.String())
		}
		if prov.RawEvidence.Raw == "" {
			t.Fatalf("event %s resolved no raw evidence", e.SourceReference)
		}
		for _, want := range []string{"cache_key", "url", "body_extracted", "evidence_meaning"} {
			if !strings.Contains(prov.RawEvidence.Raw, want) {
				t.Errorf("raw evidence is missing %q", want)
			}
		}
		if prov.SourceFile.OriginalFilename == "" {
			t.Error("provenance names no source file")
		}
		if prov.SourceFile.SHA256 == "" {
			t.Error("provenance carries no hash for the cache file")
		}
		if prov.Collection == nil {
			t.Error("provenance does not reach the collection")
		}
	}
}

//  6. Cache never becomes evidence of user activity: no user, no
//     process, confidence below history's, and the disclaimer present.
func TestBrowserCache_MakesNoUserActivityClaim(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Cache claims")
	disc := discoverBinaryDir(t, mux, c.ID, cacheCatalog(t))
	importAllFrom(t, mux, c.ID, disc)

	events := typedTimeline(t, mux, c.ID)
	var history, cache int
	for _, e := range events {
		switch e.ArtifactType {
		case model.ArtifactBrowserHistory:
			history++
			if e.Confidence != 1.0 {
				t.Errorf("browser history confidence changed to %v; that is a regression", e.Confidence)
			}
		case model.ArtifactBrowserCache:
			cache++
			if e.User != "" || e.ProcessName != "" || e.Host != "" {
				t.Errorf("a cache event names an actor: user=%q process=%q host=%q", e.User, e.ProcessName, e.Host)
			}
			if e.Confidence >= 1.0 {
				t.Errorf("cache confidence = %v; it must rank below browser history", e.Confidence)
			}
			meaning := e.Extra["evidence_meaning"]
			for _, phrase := range []string{"NOT evidence", "navigated"} {
				if !strings.Contains(meaning, phrase) {
					t.Errorf("evidence_meaning does not disclaim %q: %q", phrase, meaning)
				}
			}
		}
	}
	if history == 0 {
		t.Fatal("the browser history parser produced nothing; cache support regressed it")
	}
	if cache == 0 {
		t.Fatal("no cache events")
	}
}

// 7. A suspicious-looking cached URL alone must not raise a finding.
func TestBrowserCache_SuspiciousURLAloneRaisesNoFinding(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Cache findings")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		// Every one of these would look alarming to a keyword matcher.
		"Users/j/AppData/Roaming/Mozilla/Firefox/Profiles/p.default-release/cache2/entries/A1": ffCacheEntry(
			"https://evil.example.test/mimikatz.exe", cacheFetched, "application/octet-stream"),
		"Users/j/AppData/Roaming/Mozilla/Firefox/Profiles/p.default-release/cache2/entries/A2": ffCacheEntry(
			"http://c2.example.test/beacon?cmd=whoami", cacheFetched, "text/plain"),
		"Users/j/AppData/Roaming/Mozilla/Firefox/Profiles/p.default-release/cache2/entries/A3": ffCacheEntry(
			"https://example.test/powershell%20-enc%20SQBFAFgA", cacheFetched, "text/html"),
	})
	importAllFrom(t, mux, c.ID, disc)
	doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/analyze", nil, nil)

	var findings []model.Finding
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/findings", nil, &findings)
	for _, f := range findings {
		t.Errorf("a cached URL alone produced a finding: %q (%s)", f.Title, f.Severity)
	}
}

// 8. Credentials are never persisted from cache headers.
func TestBrowserCache_CredentialsNeverPersisted(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Cache credentials")
	secret := "SESSIONSECRETVALUE"
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		"Users/j/AppData/Roaming/Mozilla/Firefox/Profiles/p.default-release/cache2/entries/S1": cachegen.BuildFirefoxCache2(cachegen.FirefoxEntry{
			Key: "a,:https://mail.example.test/inbox", LastFetched: uint32(cacheFetched.Unix()),
			ResponseHead: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n" +
				"Set-Cookie: session=" + secret + "; HttpOnly\r\n" +
				"Authorization: Bearer " + secret + "\r\n",
		}),
	})
	importAllFrom(t, mux, c.ID, disc)

	cache := cacheEvents(typedTimeline(t, mux, c.ID))
	if len(cache) != 1 {
		t.Fatalf("got %d cache events, want 1", len(cache))
	}
	blob := fmt.Sprint(cache[0].Extra)
	var prov EventProvenance
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/events/"+cache[0].ID, nil, &prov)
	blob += prov.RawEvidence.Raw
	if strings.Contains(blob, secret) {
		t.Error("a session cookie / bearer token was persisted into the case")
	}
	// The presence of the header may be recorded; its VALUE may not.
	if !strings.Contains(blob, "redacted") {
		t.Error("the redaction is silent; an analyst cannot tell a header was withheld")
	}
}

//  9. Cache and history for the SAME domain stay separate rows, each
//     keeping its own claim. This is the correlation-relevant case: the
//     two corroborate, and must not collapse into one.
func TestBrowserCache_CoexistsWithHistoryForTheSameDomain(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Cache and history")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		"Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/History": sampleBrowserHistory(t),
		"Users/jdoe/AppData/Roaming/Mozilla/Firefox/Profiles/p.default-release/cache2/entries/H1": ffCacheEntry(
			"https://updates.example.test/payload.exe", cacheFetched, "application/octet-stream"),
	})
	importAllFrom(t, mux, c.ID, disc)

	var fromHistory, fromCache bool
	for _, e := range typedTimeline(t, mux, c.ID) {
		if e.NetworkDest != "updates.example.test" {
			continue
		}
		switch e.ArtifactType {
		case model.ArtifactBrowserHistory:
			fromHistory = true
		case model.ArtifactBrowserCache:
			fromCache = true
		}
	}
	if !fromHistory || !fromCache {
		t.Errorf("the same domain is not represented from both sources (history=%v cache=%v)", fromHistory, fromCache)
	}
}

//  10. Identical cache entries collected twice are deduplicated as
//     evidence, exactly like any other artifact.
func TestBrowserCache_DuplicateEntriesAreDeduplicated(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Cache duplicates")
	entry := ffCacheEntry("https://cdn.example.test/lib.js", cacheFetched, "application/javascript")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		"Users/j/AppData/Roaming/Mozilla/Firefox/Profiles/p.default-release/cache2/entries/D1": entry,
		"Users/j/AppData/Roaming/Mozilla/Firefox/Profiles/p.default-release/cache2/entries/D2": entry,
	})
	var dupes int
	for _, sf := range disc.SourceFiles {
		if sf.ImportStatus == model.SourceFileDuplicate {
			dupes++
		}
	}
	if dupes != 1 {
		t.Errorf("got %d duplicates, want 1: byte-identical cache entries must dedupe like any other evidence", dupes)
	}
}

//  11. A parse failure is attributed to the right file and named, and
//     never fails the whole import.
func TestBrowserCache_CorruptEntryIsIsolatedAndNamed(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Corrupt cache")
	good := ffCacheEntry("https://cdn.example.test/ok.js", cacheFetched, "application/javascript")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		"Users/j/AppData/Roaming/Mozilla/Firefox/Profiles/p.default-release/cache2/entries/OK":  good,
		"Users/j/AppData/Roaming/Mozilla/Firefox/Profiles/p.default-release/cache2/entries/BAD": cachegen.CorruptFirefox(good, "huge-key"),
	})
	imp := importAllFrom(t, mux, c.ID, disc)
	if len(imp.Imported) == 0 {
		t.Fatal("a corrupt entry blocked the whole import")
	}
	var okImported bool
	for _, sf := range imp.Imported {
		if sf.OriginalFilename == "OK" {
			okImported = true
		}
	}
	if !okImported {
		t.Error("the valid entry was not imported alongside the corrupt one")
	}
	for _, f := range imp.ParseFailures {
		if f.Message == "" || f.Category == "" {
			t.Errorf("a parse failure gives no message/category: %+v", f)
		}
	}
}

//  12. The cache structures that are genuinely NOT read are still named
//     precisely, so "browser cache supported" is never read as a claim
//     about everything in a cache directory.
//
//     The blockfile cache itself became supported in phase 15, so the
//     exemplars here are the structures that remain unsupported on
//     purpose: the rankings and payload block files, which hold no entry
//     records, and the hash indexes, which hold no cache keys.
func TestBrowserCache_UnreadCacheStructuresAreExplicitlyUnsupported(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Unread cache structures")
	root := "Users/j/AppData/Local/Google/Chrome/User Data/Default/Cache/"
	files := map[string][]byte{
		root + "data_0":                    cachegen.BuildChromiumBlockfileDataSized(36, 32),
		root + "data_2":                    cachegen.BuildChromiumBlockfileDataSized(1024, 8),
		root + "data_3":                    cachegen.BuildChromiumBlockfileDataSized(4096, 4),
		root + "f_0000a5":                  []byte("raw cached response body bytes"),
		root + "Cache_Data/the-real-index": []byte("simple cache hash index: hashes, no keys"),
	}
	disc := discoverBinaryDir(t, mux, c.ID, files)
	for path := range files {
		sf, ok := sourceFileByPath(disc.SourceFiles, path)
		if !ok {
			t.Errorf("%s was not discovered", path)
			continue
		}
		if sf.Supported {
			t.Errorf("%s is reported as supported; it holds no entry records", path)
			continue
		}
		if sf.UnsupportedReason == "" {
			t.Errorf("%s carries no explanation", path)
		}
		// Identifiable as browser evidence, and its note says which
		// cache structure it is. The LABEL names the concrete format
		// ("Chromium blockfile auxiliary file"), which is more useful
		// than repeating the word "cache" on every row.
		if sf.Family != "browser" {
			t.Errorf("%s is not in the browser family: %q", path, sf.Family)
		}
		if !namesACacheStructure(sf.TypeLabel + " " + sf.UnsupportedReason) {
			t.Errorf("%s: neither label nor note names a browser-cache structure: %q / %q",
				path, sf.TypeLabel, sf.UnsupportedReason)
		}
		// Every one of these rows must still tell the analyst that
		// browser cache IS parsed -- just not this file.
		if len(sf.ParsedInstead) == 0 {
			t.Errorf("%s does not name the cache formats that ARE parsed", path)
		}
	}
}

//  13. Timezone display is presentation-only for cache events too: the
//     stored timestamp never moves.
func TestBrowserCache_StoredTimestampsIgnoreDisplayTimezone(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Cache timezone")
	disc := discoverBinaryDir(t, mux, c.ID, cacheCatalog(t))
	importAllFrom(t, mux, c.ID, disc)

	before := cacheEvents(typedTimeline(t, mux, c.ID))
	if rec := setTZ(t, mux, "Asia/Tokyo"); rec.Code != http.StatusOK {
		t.Fatalf("set timezone: %d %s", rec.Code, rec.Body)
	}
	after := cacheEvents(typedTimeline(t, mux, c.ID))

	if len(before) != len(after) {
		t.Fatalf("event count changed with the display timezone: %d -> %d", len(before), len(after))
	}
	for i := range before {
		if !before[i].Timestamp.Equal(after[i].Timestamp) {
			t.Errorf("stored timestamp moved with the display timezone: %s -> %s",
				before[i].Timestamp, after[i].Timestamp)
		}
		if after[i].Timestamp.Location() != time.UTC {
			t.Errorf("timestamp is no longer stored in UTC: %s", after[i].Timestamp)
		}
	}
}

// 14. Cancelling a large cache import leaves consistent state.
func TestBrowserCache_LargeImportIsCancellable(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Cancel cache import")
	files := map[string][]byte{}
	for i := 0; i < 60; i++ {
		files[fmt.Sprintf("Users/j/AppData/Roaming/Mozilla/Firefox/Profiles/p.default-release/cache2/entries/E%03d", i)] =
			ffCacheEntry(fmt.Sprintf("https://cdn.example.test/asset-%03d.js", i), cacheFetched.Add(time.Duration(i)*time.Second), "application/javascript")
	}
	disc := discoverBinaryDir(t, mux, c.ID, files)
	ids := getEvidenceIDs(t, mux, c.ID, disc.Collection.ID, nil)
	if len(ids) < 50 {
		t.Fatalf("only %d entries selectable; the fixture is not a large import", len(ids))
	}
	jobID, code := startImport(t, mux, c.ID, disc.Collection.ID, ids)
	if code != http.StatusAccepted {
		t.Fatalf("start import: %d", code)
	}
	postCancel(t, mux, c.ID, jobID)
	final := waitJob(t, mux, c.ID, jobID)
	if !final.Done {
		t.Fatal("the job never finished after cancellation")
	}
	if final.Phase != PhaseCancelled && final.Phase != PhaseComplete {
		t.Fatalf("phase = %q", final.Phase)
	}
	// Whatever was imported must be whole: every event resolvable to raw
	// evidence and a source file.
	for _, e := range cacheEvents(typedTimeline(t, mux, c.ID)) {
		var prov EventProvenance
		if rec := doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/events/"+e.ID, nil, &prov); rec.Code != 200 {
			t.Fatalf("a cancelled import left event %s without provenance (%d)", e.SourceReference, rec.Code)
		}
	}
}

//  15. A realistically large cache imports in reasonable time and
//     without quadratic blow-up in the API path.
func TestBrowserCache_LargeCacheImportScales(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped in short mode")
	}
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Large cache")
	const n = 1000
	files := make(map[string][]byte, n)
	for i := 0; i < n; i++ {
		files[fmt.Sprintf("Users/j/AppData/Roaming/Mozilla/Firefox/Profiles/p.default-release/cache2/entries/L%05d", i)] =
			ffCacheEntry(fmt.Sprintf("https://cdn.example.test/bulk-%05d.js", i), cacheFetched.Add(time.Duration(i)*time.Second), "application/javascript")
	}
	start := time.Now()
	disc := discoverBinaryDir(t, mux, c.ID, files)
	discovered := time.Since(start)

	ids := getEvidenceIDs(t, mux, c.ID, disc.Collection.ID, nil)
	if len(ids) != n {
		t.Fatalf("%d of %d entries selectable", len(ids), n)
	}
	start = time.Now()
	rec := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/evidence/"+disc.Collection.ID+"/import",
		map[string][]string{"source_file_ids": ids}, nil)
	imported := time.Since(start)
	if rec.Code != http.StatusOK {
		t.Fatalf("import: %d %s", rec.Code, rec.Body.String())
	}
	start = time.Now()
	events := cacheEvents(typedTimeline(t, mux, c.ID))
	queried := time.Since(start)

	t.Logf("%d cache entries: discover %s, import %s, timeline %s (%d events)",
		n, discovered.Round(time.Millisecond), imported.Round(time.Millisecond),
		queried.Round(time.Millisecond), len(events))
	if len(events) != n {
		t.Errorf("got %d timeline events, want %d", len(events), n)
	}
	if imported > 90*time.Second {
		t.Errorf("importing %d cache entries took %s", n, imported)
	}
}

// ---------------- Legacy cache formats (phase 15) ----------------
//
// The Chromium blockfile cache and Firefox cache1. Both are multi-entry
// files, and both record per-entry timestamps that the Simple Cache does
// not -- which is the reason they are read at all.

var legacyBase = time.Date(2026, 3, 14, 8, 15, 0, 0, time.UTC)

// namesACacheStructure reports whether a row identifies which
// browser-cache structure it describes.
//
// Not a search for the literal word "cache": the most useful labels name
// the concrete format instead -- "Chromium blockfile auxiliary file"
// tells an analyst more than "browser cache file" does. What must never
// happen is a row that names no structure at all.
func namesACacheStructure(text string) bool {
	lower := strings.ToLower(text)
	for _, token := range []string{"cache", "blockfile", "cache1", "cache2", "data_1", "f_######"} {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

func blockfileData() []byte {
	return cachegen.BuildChromiumBlockfileData([]cachegen.BlockfileEntry{
		{Key: "https://legacy.example.test/app.js", CreationUnix: legacyBase.Unix(), ReuseCount: 3,
			StatusLine: "HTTP/1.1 200 OK",
			Headers:    []string{"Content-Type: application/javascript", "Content-Length: 8451"}, BodySize: 8451},
		{Key: "https://legacy.example.test/logo.png", CreationUnix: legacyBase.Add(time.Minute).Unix(),
			StatusLine: "HTTP/1.1 200 OK", Headers: []string{"Content-Type: image/png"},
			BodySize: 40960, ExternalBody: true},
		{Key: "https://cdn.example.test/legacy.css", CreationUnix: legacyBase.Add(2 * time.Minute).Unix(),
			StatusLine: "HTTP/1.1 200 OK", Headers: []string{"Content-Type: text/css"}},
	})
}

func cache1Block() []byte {
	return cachegen.BuildFirefoxCache1Block(256, []cachegen.Cache1Entry{
		{Key: "HTTP:https://old.example.test/index.html", FetchCount: 5,
			LastFetchedU: uint32(legacyBase.Unix()), LastModifiedU: uint32(legacyBase.Add(-time.Hour).Unix()),
			ExpirationU: uint32(legacyBase.Add(24 * time.Hour).Unix()), DataSize: 5120,
			RequestMethod: "GET",
			ResponseHead:  "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5120\r\n"},
		{Key: "HTTP:https://old.example.test/submit", FetchCount: 1,
			LastFetchedU: uint32(legacyBase.Add(time.Minute).Unix()), DataSize: 64,
			RequestMethod: "POST", ResponseHead: "HTTP/1.1 302 Found\r\nContent-Type: text/plain\r\n"},
	})
}

// legacyCatalog holds both legacy caches, both containers, both current
// formats and a browser history database, so every test can check that
// six distinct things stay distinct.
func legacyCatalog(t *testing.T) map[string][]byte {
	t.Helper()
	return map[string][]byte{
		// Legacy Chromium: container + entries + an external body.
		"Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/Cache/index": cachegen.BuildChromiumBlockfileIndex(
			cachegen.BlockfileIndexOptions{NumEntries: 3, NumBytes: 57344, TableLen: 0x10000,
				CreateTimeUnix: legacyBase.Add(-72 * time.Hour).Unix()}),
		"Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/Cache/data_1":   blockfileData(),
		"Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/Cache/data_0":   cachegen.BuildChromiumBlockfileDataSized(36, 64),
		"Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/Cache/f_0000a5": []byte("\x89PNG\r\n\x1a\n raw cached body bytes"),
		// Legacy Firefox: container + entries.
		"Users/jdoe/AppData/Local/Mozilla/Firefox/Profiles/ab12.default/Cache/_CACHE_MAP_": cachegen.BuildFirefoxCache1Map(
			cachegen.Cache1MapOptions{EntryCount: 2, RecordCount: 2, Records: 2, DataSize: 5184}),
		"Users/jdoe/AppData/Local/Mozilla/Firefox/Profiles/ab12.default/Cache/_CACHE_001_": cache1Block(),
		// Current formats, unchanged.
		"Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/Cache/Cache_Data/9f8e7d6c5b4a3210_0": chromeCacheEntry(
			"https://current.example.test/modern.js", "application/javascript"),
		"Users/jdoe/AppData/Roaming/Mozilla/Firefox/Profiles/x1y2.default-release/cache2/entries/5F2A91C0": ffCacheEntry(
			"https://current.example.test/modern.css", cacheFetched, "text/css"),
		"Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/History": sampleBrowserHistory(t),
	}
}

//  16. Every format lands in the right artifact type, and the two that
//     are deliberately not parsed keep an accurate explanation.
func TestBrowserCache_LegacyFormatsAreClassifiedDistinctly(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Legacy cache classification")
	disc := discoverBinaryDir(t, mux, c.ID, legacyCatalog(t))

	want := map[string]struct {
		artifact  string
		supported bool
	}{
		"Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/Cache/index":             {model.ArtifactBrowserCacheIndex, true},
		"Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/Cache/data_1":            {model.ArtifactBrowserCache, true},
		"Users/jdoe/AppData/Local/Mozilla/Firefox/Profiles/ab12.default/Cache/_CACHE_MAP_": {model.ArtifactBrowserCacheIndex, true},
		"Users/jdoe/AppData/Local/Mozilla/Firefox/Profiles/ab12.default/Cache/_CACHE_001_": {model.ArtifactBrowserCache, true},
		"Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/Cache/data_0":            {"", false},
		"Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/Cache/f_0000a5":          {"", false},
		"Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/History":                 {model.ArtifactBrowserHistory, true},
	}
	for path, w := range want {
		sf, ok := sourceFileByPath(disc.SourceFiles, path)
		if !ok {
			t.Errorf("%s was not discovered", path)
			continue
		}
		if sf.Supported != w.supported {
			t.Errorf("%s supported = %v, want %v (%s)", path, sf.Supported, w.supported, sf.UnsupportedReason)
			continue
		}
		if w.supported && sf.ArtifactType != w.artifact {
			t.Errorf("%s artifact type = %q, want %q", path, sf.ArtifactType, w.artifact)
		}
		if !w.supported {
			// Requirement: a file inside a cache directory that is not
			// parsed must still be explained, not dumped into "unknown".
			if sf.UnsupportedReason == "" {
				t.Errorf("%s is unsupported with no explanation", path)
			}
			if !namesACacheStructure(sf.TypeLabel + " " + sf.UnsupportedReason) {
				t.Errorf("%s: neither label nor note names a browser-cache structure: %q / %q",
					path, sf.TypeLabel, sf.UnsupportedReason)
			}
		}
	}
	// The external body file must say WHY, specifically.
	body, _ := sourceFileByPath(disc.SourceFiles,
		"Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/Cache/f_0000a5")
	if !strings.Contains(strings.ToLower(body.UnsupportedReason), "body") {
		t.Errorf("the external body file's reason does not say it is a body: %q", body.UnsupportedReason)
	}
	if !strings.Contains(body.UnsupportedReason, "data_1") {
		t.Errorf("the reason does not point at the record that DOES describe it: %q", body.UnsupportedReason)
	}
}

//  17. Legacy entries reach the timeline with the times their formats
//     record, and carry the fields those formats provide.
func TestBrowserCache_LegacyEntriesReachTheTimeline(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Legacy cache timeline")
	disc := discoverBinaryDir(t, mux, c.ID, legacyCatalog(t))
	imp := importAllFrom(t, mux, c.ID, disc)
	if len(imp.ParseFailures) != 0 {
		t.Fatalf("parse failures: %+v", imp.ParseFailures)
	}

	byFormat := map[string][]model.Event{}
	for _, e := range cacheEvents(typedTimeline(t, mux, c.ID)) {
		byFormat[e.Extra["cache_format"]] = append(byFormat[e.Extra["cache_format"]], e)
	}
	if n := len(byFormat["chromium_blockfile"]); n != 3 {
		t.Errorf("got %d blockfile events, want 3", n)
	}
	if n := len(byFormat["firefox_cache1"]); n != 2 {
		t.Errorf("got %d cache1 events, want 2", n)
	}
	if n := len(byFormat["firefox_cache2"]); n != 1 {
		t.Errorf("got %d cache2 events, want 1", n)
	}
	// Simple Cache still records no time, so it still contributes none.
	if n := len(byFormat["chromium_simple_cache"]); n != 0 {
		t.Errorf("the Simple Cache produced %d timeline events; it records no timestamp", n)
	}

	var blockJS model.Event
	for _, e := range byFormat["chromium_blockfile"] {
		if e.Extra["url"] == "https://legacy.example.test/app.js" {
			blockJS = e
		}
		if e.Extra["cache_generation"] != "legacy" {
			t.Errorf("blockfile event is not marked legacy: %q", e.Extra["cache_generation"])
		}
		if !strings.Contains(e.Extra["cache_format_name"], "blockfile") {
			t.Errorf("format name = %q", e.Extra["cache_format_name"])
		}
	}
	if blockJS.ID == "" {
		t.Fatal("the blockfile app.js entry is missing")
	}
	if !blockJS.Timestamp.Equal(legacyBase) {
		t.Errorf("blockfile timestamp = %s, want %s", blockJS.Timestamp, legacyBase)
	}
	if blockJS.Extra["content_type"] != "application/javascript" {
		t.Errorf("content type = %q -- stream-0 headers were not recovered", blockJS.Extra["content_type"])
	}
	if blockJS.Extra["http_status"] != "200" {
		t.Errorf("status = %q", blockJS.Extra["http_status"])
	}
	if blockJS.NetworkDest != "legacy.example.test" {
		t.Errorf("host = %q", blockJS.NetworkDest)
	}

	// cache1 is the only format that records an HTTP method.
	var sawGET, sawPOST bool
	for _, e := range byFormat["firefox_cache1"] {
		switch e.Extra["http_method"] {
		case "GET":
			sawGET = true
			if e.Extra["fetch_count"] != "5" {
				t.Errorf("fetch count = %q, want 5", e.Extra["fetch_count"])
			}
			if e.Extra["cache_expires"] == "" {
				t.Error("cache1 expiration time was not recorded")
			}
			if e.Extra["cache_last_modified"] == "" {
				t.Error("cache1 last-modified was not recorded")
			}
		case "POST":
			sawPOST = true
		}
	}
	if !sawGET || !sawPOST {
		t.Errorf("HTTP methods not recovered from cache1 (GET=%v POST=%v)", sawGET, sawPOST)
	}
	// No other format may claim a method it does not record.
	for _, f := range []string{"chromium_blockfile", "chromium_simple_cache", "firefox_cache2"} {
		for _, e := range byFormat[f] {
			if e.Extra["http_method"] != "" {
				t.Errorf("%s reported an HTTP method (%q) that the format does not record", f, e.Extra["http_method"])
			}
		}
	}
}

// 18. Containers import as evidence but produce no timeline events.
func TestBrowserCache_ContainersAreEvidenceWithoutEvents(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Cache containers")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		"Cache/index": cachegen.BuildChromiumBlockfileIndex(cachegen.BlockfileIndexOptions{
			NumEntries: 4812, NumBytes: 91237888, CreateTimeUnix: legacyBase.Unix()}),
		"Cache/_CACHE_MAP_": cachegen.BuildFirefoxCache1Map(cachegen.Cache1MapOptions{
			EntryCount: 1204, RecordCount: 1204, Records: 1204}),
	})
	imp := importAllFrom(t, mux, c.ID, disc)
	if len(imp.ParseFailures) != 0 {
		t.Fatalf("a container was reported as a parse failure: %+v", imp.ParseFailures)
	}
	if len(imp.Imported) != 2 {
		t.Fatalf("imported %d containers, want 2", len(imp.Imported))
	}
	if imp.EventCount != 0 {
		t.Errorf("containers produced %d timeline events; they describe a cache, not an activity", imp.EventCount)
	}
	if len(typedTimeline(t, mux, c.ID)) != 0 {
		t.Error("a container event reached the timeline")
	}
}

//  19. A valid cache file holding zero entries is a successful import
//     with an honest record -- never a parse failure.
func TestBrowserCache_ValidButEmptyIsNotAParseFailure(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Empty cache files")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		"Cache/data_1":      cachegen.BuildChromiumBlockfileDataSized(256, 32),
		"Cache/_CACHE_001_": cachegen.BuildFirefoxCache1Block(256, nil),
	})
	imp := importAllFrom(t, mux, c.ID, disc)
	if len(imp.ParseFailures) != 0 {
		t.Fatalf("an empty but valid cache file was reported as a failure: %+v", imp.ParseFailures)
	}
	if len(imp.Imported) != 2 {
		t.Fatalf("imported %d files, want 2", len(imp.Imported))
	}
	if imp.EventCount != 0 {
		t.Errorf("empty cache files produced %d events", imp.EventCount)
	}
}

//  20. A corrupt legacy cache file is isolated: named, attributed, and
//     never allowed to fail its neighbours.
func TestBrowserCache_CorruptLegacyFileIsIsolated(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Corrupt legacy cache")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		"Cache/data_1":          blockfileData(),
		"Cache/_CACHE_001_":     cache1Block(),
		"Cache/_CACHE_002_":     cachegen.CorruptCache1(cache1Block(), "truncate"),
		"Cache/Cache_Data/aa_0": chromeCacheEntry("https://example.test/ok.js", "application/javascript"),
	})
	imp := importAllFrom(t, mux, c.ID, disc)
	if len(imp.Imported) < 3 {
		t.Errorf("a corrupt file blocked its neighbours: only %d of 4 imported", len(imp.Imported))
	}
	for _, f := range imp.ParseFailures {
		if f.Message == "" || f.Category == "" {
			t.Errorf("a parse failure gives no message/category: %+v", f)
		}
		if f.Filename != "_CACHE_002_" {
			t.Errorf("the failure was attributed to %q, not the corrupt file", f.Filename)
		}
	}
	// The healthy legacy entries still reached the timeline.
	if n := len(cacheEvents(typedTimeline(t, mux, c.ID))); n != 5 {
		t.Errorf("got %d cache events, want 5 (3 blockfile + 2 cache1)", n)
	}
}

//  21. Provenance for a legacy entry resolves through the multi-entry
//     file it came from, and the parse report is retained.
func TestBrowserCache_LegacyProvenanceResolves(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Legacy provenance")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		"Cache/data_1":      blockfileData(),
		"Cache/_CACHE_001_": cache1Block(),
	})
	importAllFrom(t, mux, c.ID, disc)

	events := cacheEvents(typedTimeline(t, mux, c.ID))
	if len(events) != 5 {
		t.Fatalf("got %d events, want 5", len(events))
	}
	seen := map[string]bool{}
	for _, e := range events {
		var prov EventProvenance
		rec := doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/events/"+e.ID, nil, &prov)
		if rec.Code != 200 {
			t.Fatalf("provenance for %s returned %d", e.SourceReference, rec.Code)
		}
		if prov.RawEvidence.Raw == "" {
			t.Errorf("event %s resolved no raw evidence", e.SourceReference)
		}
		if prov.SourceFile.SHA256 == "" {
			t.Error("provenance carries no hash")
		}
		// Every entry in a multi-entry file must have its OWN reference.
		if seen[e.SourceReference] {
			t.Errorf("duplicate source reference %q: two entries share one raw record", e.SourceReference)
		}
		seen[e.SourceReference] = true
	}
}

// 22. Nothing about the legacy formats manufactures a finding.
func TestBrowserCache_LegacyFormatsRaiseNoFindings(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Legacy findings")
	disc := discoverBinaryDir(t, mux, c.ID, legacyCatalog(t))
	importAllFrom(t, mux, c.ID, disc)
	doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/analyze", nil, nil)

	var findings []model.Finding
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/findings", nil, &findings)
	for _, f := range findings {
		t.Errorf("a legacy cache entry produced a finding: %q (%s)", f.Title, f.Severity)
	}
}
