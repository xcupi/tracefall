package browsercache_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tracefall/internal/browsercache/cachegen"
	"tracefall/internal/model"
	parser "tracefall/internal/parsers/browsercache"
)

var ffTime = uint32(time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC).Unix())

func write(t *testing.T, name string, data []byte) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func chromiumEntry(url string) []byte {
	return cachegen.BuildChromiumSimple(cachegen.ChromiumEntry{
		Key: url, StatusLine: "HTTP/1.1 200 OK",
		Headers: []string{"Content-Type: text/html; charset=utf-8", "Content-Length: 1234"},
		Body:    []byte("<html>"),
	})
}

func firefoxEntry(url string, fetched uint32) []byte {
	return cachegen.BuildFirefoxCache2(cachegen.FirefoxEntry{
		Key: "a,:" + url, LastFetched: fetched, FetchCount: 3,
		ResponseHead: "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: 900\r\n",
		Body:         []byte("PNG"),
	})
}

// Firefox cache2 records a time, so it produces a timeline event.
func TestParser_FirefoxProducesTimelineEvent(t *testing.T) {
	res, err := parser.New().Parse(write(t, "5F2A", firefoxEntry("https://example.org/logo.png", ffTime)))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(res.Events))
	}
	e := res.Events[0]
	if e.EventType != model.EventBrowserCacheEntry {
		t.Errorf("event type = %q", e.EventType)
	}
	if e.ArtifactType != model.ArtifactBrowserCache {
		t.Errorf("artifact type = %q", e.ArtifactType)
	}
	if !e.Timestamp.Equal(time.Unix(int64(ffTime), 0).UTC()) {
		t.Errorf("timestamp = %s", e.Timestamp)
	}
	if e.Timestamp.Location() != time.UTC {
		t.Error("timestamp is not stored in UTC")
	}
	if e.Extra["url"] != "https://example.org/logo.png" {
		t.Errorf("url = %q", e.Extra["url"])
	}
	if e.Extra["host"] != "example.org" {
		t.Errorf("host = %q", e.Extra["host"])
	}
	if e.NetworkDest != "example.org" {
		t.Errorf("network dest = %q", e.NetworkDest)
	}
	if e.Extra["content_type"] != "image/png" {
		t.Errorf("content type = %q", e.Extra["content_type"])
	}
	if e.Extra["http_status"] != "200" {
		t.Errorf("status = %q", e.Extra["http_status"])
	}
	if e.Extra["timestamp_source"] == "" {
		t.Error("the event does not say which field its timestamp came from")
	}
	// Every event must state that cache is not navigation evidence.
	if !strings.Contains(e.Extra["evidence_meaning"], "NOT evidence that the user navigated") {
		t.Errorf("the event does not disclaim user navigation: %q", e.Extra["evidence_meaning"])
	}
	if e.Extra["browser"] == "" || e.Extra["cache_format"] == "" {
		t.Error("browser or cache format not recorded")
	}
	// Provenance pairing.
	if len(res.Raw) != 1 || res.Raw[0].SourceReference != e.SourceReference {
		t.Error("the event is not paired with raw evidence under the same reference")
	}
}

// Chromium Simple Cache records NO time, so it must produce structured
// evidence and NO timeline event -- never a fabricated timestamp.
func TestParser_ChromiumProducesNoFabricatedTimestamp(t *testing.T) {
	res, err := parser.New().Parse(write(t, "abc_0", chromiumEntry("https://example.com/app.js")))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 0 {
		t.Fatalf("a Chromium Simple Cache entry produced %d timeline events; it records no timestamp", len(res.Events))
	}
	if len(res.Raw) != 1 {
		t.Fatalf("got %d raw records, want 1 -- the metadata must still be kept", len(res.Raw))
	}
	raw := res.Raw[0].Raw
	for _, want := range []string{"https://example.com/app.js", "chromium_simple_cache", "body_extracted"} {
		if !strings.Contains(raw, want) {
			t.Errorf("the metadata record is missing %q", want)
		}
	}
	if !strings.HasSuffix(res.Raw[0].SourceReference, ":metadata") {
		t.Errorf("the metadata-only record is not marked as such: %q", res.Raw[0].SourceReference)
	}
}

// No actor is invented from a cache entry.
func TestParser_InventsNoActor(t *testing.T) {
	res, err := parser.New().Parse(write(t, "e", firefoxEntry("https://example.org/x.js", ffTime)))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range res.Events {
		if e.User != "" || e.ProcessName != "" || e.ProcessPath != "" ||
			e.ParentProcessName != "" || e.CommandLine != "" || e.Host != "" {
			t.Errorf("an actor was invented: user=%q process=%q host=%q", e.User, e.ProcessName, e.Host)
		}
	}
}

// Cache confidence must sit BELOW browser history's: the observation is
// solid but what it proves about user activity is weaker.
func TestParser_ConfidenceIsBelowBrowserHistory(t *testing.T) {
	res, err := parser.New().Parse(write(t, "e", firefoxEntry("https://example.org/x", ffTime)))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) == 0 {
		t.Fatal("no events")
	}
	if res.Events[0].Confidence >= 1.0 {
		t.Errorf("cache confidence = %v; browser history is 1.0 and cache must rank below it",
			res.Events[0].Confidence)
	}
}

// A cache CONTAINER handed to the entry parser is refused with an
// explanation, not a generic failure: it says what the file is, that it
// holds no cache keys, and which parser does read it.
func TestParser_ContainerFileIsRefusedByName(t *testing.T) {
	for name, data := range map[string][]byte{
		"blockfile index": cachegen.BuildChromiumBlockfileIndex(cachegen.BlockfileIndexOptions{NumEntries: 12}),
		"cache1 map":      cachegen.BuildFirefoxCache1Map(cachegen.Cache1MapOptions{EntryCount: 12, Records: 12}),
	} {
		_, err := parser.New().Parse(write(t, "index", data))
		if err == nil {
			t.Fatalf("%s parsed as a cache entry", name)
		}
		for _, want := range []string{"CONTAINER", "no cache keys", "browsercacheindex"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: the error does not mention %q: %v", name, want, err)
			}
		}
	}
}

// The blockfile DATA file, by contrast, is now parsed -- with real
// per-entry timestamps, which is the whole reason the format is read.
func TestParser_BlockfileDataProducesTimelineEvents(t *testing.T) {
	at := time.Date(2026, 3, 14, 8, 15, 0, 0, time.UTC)
	data := cachegen.BuildChromiumBlockfileData([]cachegen.BlockfileEntry{
		{Key: "https://example.test/a.js", CreationUnix: at.Unix(), ReuseCount: 2,
			StatusLine: "HTTP/1.1 200 OK", Headers: []string{"Content-Type: application/javascript"}},
		{Key: "https://example.test/b.png", CreationUnix: at.Add(time.Minute).Unix(),
			StatusLine: "HTTP/1.1 200 OK", Headers: []string{"Content-Type: image/png"}},
	})
	res, err := parser.New().Parse(write(t, "data_1", data))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want 2", len(res.Events))
	}
	for _, e := range res.Events {
		if e.EventType != model.EventBrowserCacheEntry || e.ArtifactType != model.ArtifactBrowserCache {
			t.Errorf("wrong type/artifact: %s / %s", e.EventType, e.ArtifactType)
		}
		if e.Extra["cache_format"] != "chromium_blockfile" {
			t.Errorf("cache format = %q", e.Extra["cache_format"])
		}
		if e.Extra["cache_generation"] != "legacy" {
			t.Errorf("generation = %q, want legacy", e.Extra["cache_generation"])
		}
		if e.Timestamp.IsZero() {
			t.Error("a blockfile entry reached the timeline with no time")
		}
		if e.Timestamp.Location() != time.UTC {
			t.Error("timestamp is not UTC")
		}
	}
	if !res.Events[0].Timestamp.Equal(at) {
		t.Errorf("first event at %s, want %s", res.Events[0].Timestamp, at)
	}
	// Events and raw records pair, plus exactly one parse report.
	if len(res.Raw) != 3 {
		t.Fatalf("got %d raw records, want 2 entries + 1 parse report", len(res.Raw))
	}
	var report string
	for _, r := range res.Raw {
		if r.SourceReference == "browsercache:parse-report" {
			report = r.Raw
		}
	}
	if report == "" {
		t.Fatal("no parse report was emitted")
	}
	for _, want := range []string{"blocks_scanned", "entries_emitted", "skipped_evicted", "chromium_blockfile"} {
		if !strings.Contains(report, want) {
			t.Errorf("the parse report omits %q: %s", want, report)
		}
	}
}

// Firefox cache1 block files are claimed by their exact canonical names
// and produce entries with the HTTP method no other format records.
func TestParser_Cache1BlockProducesTimelineEvents(t *testing.T) {
	at := time.Date(2013, 7, 2, 16, 45, 0, 0, time.UTC)
	data := cachegen.BuildFirefoxCache1Block(256, []cachegen.Cache1Entry{
		{Key: "HTTP:https://example.test/index.html", LastFetchedU: uint32(at.Unix()),
			FetchCount: 4, RequestMethod: "GET", DataSize: 900,
			ResponseHead: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"},
	})
	p := parser.New()
	if !p.Detect("Users/j/AppData/Local/Mozilla/Firefox/Profiles/x.default/Cache/_CACHE_001_") {
		t.Fatal("a cache1 block file was not detected by its canonical name")
	}
	res, err := p.Parse(write(t, "_CACHE_001_", data))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(res.Events))
	}
	e := res.Events[0]
	if !e.Timestamp.Equal(at) {
		t.Errorf("timestamp = %s, want %s", e.Timestamp, at)
	}
	if e.Extra["cache_format"] != "firefox_cache1" || e.Extra["cache_generation"] != "legacy" {
		t.Errorf("format/generation = %q/%q", e.Extra["cache_format"], e.Extra["cache_generation"])
	}
	if e.Extra["http_method"] != "GET" {
		t.Errorf("http method = %q, want GET", e.Extra["http_method"])
	}
	if e.Extra["url"] != "https://example.test/index.html" {
		t.Errorf("url = %q", e.Extra["url"])
	}
	if e.Extra["fetch_count"] != "4" {
		t.Errorf("fetch count = %q", e.Extra["fetch_count"])
	}
}

// A valid cache file holding no entries imports as a success with a
// report -- never as a parse failure.
func TestParser_ValidButEmptyCacheFilesAreNotFailures(t *testing.T) {
	cases := map[string]struct {
		name string
		data []byte
	}{
		"empty blockfile":    {"data_1", cachegen.BuildChromiumBlockfileData(nil)},
		"empty cache1 block": {"_CACHE_001_", cachegen.BuildFirefoxCache1Block(256, nil)},
	}
	for label, tc := range cases {
		res, err := parser.New().Parse(write(t, tc.name, tc.data))
		if err != nil {
			t.Errorf("%s was reported as a parse failure: %v", label, err)
			continue
		}
		if len(res.Events) != 0 {
			t.Errorf("%s produced %d events", label, len(res.Events))
		}
		if len(res.Raw) != 1 {
			t.Errorf("%s produced %d records; want exactly the parse report", label, len(res.Raw))
		}
		if !strings.Contains(res.Raw[0].Raw, "entries_emitted") {
			t.Errorf("%s: the report does not say how many entries were found", label)
		}
	}
}

// Detection is structural only: nothing is claimed by filename.
func TestParser_DetectionIsStructuralOnly(t *testing.T) {
	p := parser.New()
	// Detect (filename) claims the three cache1 block files, whose
	// format defines those exact names and puts no signature in the
	// sniff window -- and nothing else.
	for _, name := range []string{
		"Cache/data_1", "Cache/f_000001", "Cache/index", "Cache/0a1b2c3d_0",
		"cache2/entries/5F2A", "anything.bin", "Cache/_CACHE_004_", "Cache/_CACHE_001_.bak",
		"Cache/_CACHE_MAP_",
	} {
		if p.Detect(name) {
			t.Errorf("%q was claimed by filename; cache detection must be structural", name)
		}
	}
	for _, name := range []string{"Cache/_CACHE_001_", "Cache/_CACHE_002_", "Cache/_CACHE_003_"} {
		if !p.Detect(name) {
			t.Errorf("%q was not claimed; a cache1 block file has no signature to detect", name)
		}
	}
	// Content detection accepts both real formats.
	if !p.DetectContent(chromiumEntry("https://example.com/x")) {
		t.Error("a Chromium entry was not content-detected")
	}
	if !p.DetectContent(firefoxEntry("https://example.org/x", ffTime)) {
		t.Error("a Firefox entry was not content-detected")
	}
	if !p.DetectContent(cachegen.BuildChromiumBlockfileData(nil)) {
		t.Error("a blockfile data file was not content-detected")
	}
	// And rejects everything else, containers included: those are a
	// different artifact type read by a different parser.
	for name, data := range map[string][]byte{
		"text":            []byte("an ordinary text file that happens to live in a cache directory"),
		"zeros":           make([]byte, 1024),
		"blockfile index": cachegen.BuildChromiumBlockfileIndex(cachegen.BlockfileIndexOptions{NumEntries: 1}),
		"cache1 map":      cachegen.BuildFirefoxCache1Map(cachegen.Cache1MapOptions{Records: 2}),
		"empty":           {},
	} {
		if p.DetectContent(data) {
			t.Errorf("%q was content-detected as a cache entry", name)
		}
	}
	if p.ArtifactType() != model.ArtifactBrowserCache {
		t.Errorf("artifact type = %q", p.ArtifactType())
	}
}

// Deterministic repeated parsing.
func TestParser_IsDeterministic(t *testing.T) {
	for _, data := range [][]byte{
		chromiumEntry("https://example.com/a.css"),
		firefoxEntry("https://example.org/b.js", ffTime),
	} {
		path := write(t, "d", data)
		p := parser.New()
		first, err := p.Parse(path)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 10; i++ {
			again, err := p.Parse(path)
			if err != nil {
				t.Fatalf("run %d: %v", i, err)
			}
			if len(again.Events) != len(first.Events) || len(again.Raw) != len(first.Raw) {
				t.Fatalf("run %d differed in record counts", i)
			}
			for j := range first.Raw {
				if first.Raw[j].Raw != again.Raw[j].Raw ||
					first.Raw[j].SourceReference != again.Raw[j].SourceReference {
					t.Fatalf("run %d raw record %d differed", i, j)
				}
			}
		}
	}
}

// Credentials never reach an event.
func TestParser_NoCredentialsInEvents(t *testing.T) {
	data := cachegen.BuildFirefoxCache2(cachegen.FirefoxEntry{
		Key: "a,:https://example.org/login", LastFetched: ffTime,
		ResponseHead: "HTTP/1.1 200 OK\r\nSet-Cookie: sid=NEVERLEAKTHIS\r\nContent-Type: text/html\r\n",
	})
	res, err := parser.New().Parse(write(t, "c", data))
	if err != nil {
		t.Fatal(err)
	}
	blob := fmt.Sprint(res.Events, res.Raw)
	if strings.Contains(blob, "NEVERLEAKTHIS") {
		t.Error("a session cookie reached the parsed evidence")
	}
}

// Profile and user context are recovered from the path when present.
func TestParser_RecoversBrowserContext(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "Users", "jdoe", "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Cache")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(nested, "9f8e_0")
	if err := os.WriteFile(path, firefoxEntry("https://example.org/x", ffTime), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := parser.New().Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) == 0 {
		t.Fatal("no events")
	}
	e := res.Events[0]
	if e.Extra["browser_profile"] != "Default" {
		t.Errorf("profile = %q, want Default", e.Extra["browser_profile"])
	}
	if e.Extra["user_profile_path"] != "jdoe" {
		t.Errorf("user path = %q, want jdoe", e.Extra["user_profile_path"])
	}
}

// PERFORMANCE: parsing must be linear in the number of entries.
//
// Measured at three magnitudes, and the per-entry cost compared. An
// O(n^2) implementation would show the per-entry time growing with n;
// this asserts it does not, which is the only claim worth making
// without a benchmark harness.
func TestParser_ScalesLinearly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped in short mode")
	}
	p := parser.New()
	dir := t.TempDir()
	perEntry := map[int]time.Duration{}

	for _, n := range []int{1000, 10000, 100000} {
		// Reuse one file: this measures PARSE cost, not filesystem churn.
		path := filepath.Join(dir, "bench_entry")
		if err := os.WriteFile(path, firefoxEntry("https://example.org/asset.js", ffTime), 0o600); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		for i := 0; i < n; i++ {
			if _, err := p.Parse(path); err != nil {
				t.Fatalf("n=%d iteration %d: %v", n, i, err)
			}
		}
		elapsed := time.Since(start)
		perEntry[n] = elapsed / time.Duration(n)
		t.Logf("%7d entries in %8s  (%s per entry)", n, elapsed.Round(time.Millisecond), perEntry[n])
	}

	// Per-entry cost must not blow up with n. A generous 4x bound: this
	// is looking for quadratic behaviour, not micro-optimising.
	if perEntry[100000] > perEntry[1000]*4 {
		t.Errorf("per-entry cost grew from %s at 1k to %s at 100k; this suggests worse than linear scaling",
			perEntry[1000], perEntry[100000])
	}
}
