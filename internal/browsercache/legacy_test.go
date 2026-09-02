package browsercache_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bc "tracefall/internal/browsercache"
	"tracefall/internal/browsercache/cachegen"
)

// Legacy cache formats: the Chromium blockfile cache and Firefox cache1.
//
// Both are multi-entry files, which is what makes them different from
// everything read before: one source file yields many entries, and the
// reader has to be able to say how many it scanned, how many it emitted,
// and why it dropped the rest.

var (
	blockBase  = time.Date(2026, 3, 14, 8, 15, 0, 0, time.UTC)
	cache1Base = time.Date(2013, 7, 2, 16, 45, 0, 0, time.UTC)
)

func tmpWrite(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// ---------------- Chromium blockfile: index ----------------

func TestBlockfileIndex_ReadsContainerMetadata(t *testing.T) {
	data := cachegen.BuildChromiumBlockfileIndex(cachegen.BlockfileIndexOptions{
		NumEntries: 4812, NumBytes: 91_237_888, LastFile: 6, TableLen: 0x10000,
		CreateTimeUnix: blockBase.Unix(),
	})
	idx, err := bc.ParseChromiumBlockfileIndex(tmpWrite(t, "index", data), bc.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if idx.NumEntries != 4812 {
		t.Errorf("entries = %d, want 4812", idx.NumEntries)
	}
	if idx.NumBytes != 91_237_888 {
		t.Errorf("bytes = %d", idx.NumBytes)
	}
	if idx.TableLen != 0x10000 {
		t.Errorf("table length = %d", idx.TableLen)
	}
	if !idx.CreateTime.Equal(blockBase) {
		t.Errorf("create time = %s, want %s", idx.CreateTime, blockBase)
	}
	if idx.Version == 0 {
		t.Error("version not recorded")
	}
}

// An index with no creation time must report none, not 1601.
func TestBlockfileIndex_NoCreationTimeIsNotInvented(t *testing.T) {
	data := cachegen.BuildChromiumBlockfileIndex(cachegen.BlockfileIndexOptions{NumEntries: 3})
	idx, err := bc.ParseChromiumBlockfileIndex(tmpWrite(t, "index", data), bc.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if !idx.CreateTime.IsZero() {
		t.Errorf("a zero creation time became %s", idx.CreateTime)
	}
}

// A creation time outside any plausible range is discarded and said so.
func TestBlockfileIndex_ImplausibleCreationTimeIsDiscarded(t *testing.T) {
	data := cachegen.BuildChromiumBlockfileIndex(cachegen.BlockfileIndexOptions{NumEntries: 1})
	// Year 1601 + a few seconds: a real base::Time value, not a real date.
	data[40] = 0x10
	data[41] = 0x27
	idx, err := bc.ParseChromiumBlockfileIndex(tmpWrite(t, "index", data), bc.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if !idx.CreateTime.IsZero() {
		t.Errorf("an implausible time was kept: %s", idx.CreateTime)
	}
	if len(idx.Warnings) == 0 {
		t.Error("the discarded timestamp was not reported")
	}
}

func TestBlockfileIndex_RejectsNonIndex(t *testing.T) {
	for name, data := range map[string][]byte{
		"text":  []byte(strings.Repeat("not an index file ", 40)),
		"zeros": make([]byte, 512),
		"data":  cachegen.BuildChromiumBlockfileData(nil),
	} {
		if _, err := bc.ParseChromiumBlockfileIndex(tmpWrite(t, "index", data), bc.Limits{}); err == nil {
			t.Errorf("%s parsed as a blockfile index", name)
		}
	}
}

// ---------------- Chromium blockfile: data_1 entries ----------------

func blockEntries() []cachegen.BlockfileEntry {
	return []cachegen.BlockfileEntry{
		{
			Key: "https://example.test/app.js", CreationUnix: blockBase.Unix(),
			ReuseCount: 3, RefetchCount: 1,
			StatusLine: "HTTP/1.1 200 OK",
			Headers:    []string{"Content-Type: application/javascript", "Content-Length: 8451"},
			BodySize:   8451,
		},
		{
			Key: "https://cdn.example.test/logo.png", CreationUnix: blockBase.Add(time.Minute).Unix(),
			StatusLine: "HTTP/1.1 200 OK",
			Headers:    []string{"Content-Type: image/png", "Content-Length: 40960"},
			BodySize:   40960, ExternalBody: true,
		},
		{
			Key: "https://example.test/page.html", CreationUnix: blockBase.Add(2 * time.Minute).Unix(),
			StatusLine: "HTTP/1.1 304 Not Modified",
			Headers:    []string{"Content-Type: text/html"},
		},
	}
}

func TestBlockfileData_ReadsMultipleEntries(t *testing.T) {
	path := tmpWrite(t, "data_1", cachegen.BuildChromiumBlockfileData(blockEntries()))
	scan, err := bc.ParseChromiumBlockfileData(path, bc.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(scan.Entries))
	}
	if scan.Header.EntrySize != 256 {
		t.Errorf("block size = %d, want 256", scan.Header.EntrySize)
	}
	if scan.BlocksScanned == 0 {
		t.Error("no blocks were reported as scanned")
	}

	byURL := map[string]bc.Entry{}
	for _, e := range scan.Entries {
		byURL[e.URL] = e
		if e.Format != bc.FormatChromiumBlockfile {
			t.Errorf("format = %q", e.Format)
		}
		if e.Format.Generation() != bc.GenerationLegacy {
			t.Error("the blockfile cache is not marked as a legacy generation")
		}
		if e.EntryID == "" {
			t.Error("entry has no identifier")
		}
	}

	js, ok := byURL["https://example.test/app.js"]
	if !ok {
		t.Fatalf("app.js missing; got %v", urlsOf(scan.Entries))
	}
	// The timestamp is the whole reason this format is read.
	if !js.LastFetched.Equal(blockBase) {
		t.Errorf("creation time = %s, want %s", js.LastFetched, blockBase)
	}
	if !js.HasTimelineTimestamp() {
		t.Error("a blockfile entry with a creation time is not timeline-eligible")
	}
	if js.StatusCode != 200 {
		t.Errorf("status = %d", js.StatusCode)
	}
	if js.ContentType != "application/javascript" {
		t.Errorf("content type = %q", js.ContentType)
	}
	if !js.HasContentLength || js.ContentLength != 8451 {
		t.Errorf("content length = %d (has=%v)", js.ContentLength, js.HasContentLength)
	}
	if js.FetchCount != 3 {
		t.Errorf("reuse count = %d, want 3", js.FetchCount)
	}
	if js.Host() != "example.test" {
		t.Errorf("host = %q", js.Host())
	}

	// An externally stored body is reported as a reference, never read.
	png := byURL["https://cdn.example.test/logo.png"]
	var sawExternal bool
	for _, w := range png.Warnings {
		if strings.Contains(w, "f_0000a5") && strings.Contains(w, "does not read") {
			sawExternal = true
		}
	}
	if !sawExternal {
		t.Errorf("the external body file was not reported: %v", png.Warnings)
	}
	if byURL["https://example.test/page.html"].StatusCode != 304 {
		t.Error("a 304 entry lost its status code")
	}
}

// A valid block file with no entries is not an error.
func TestBlockfileData_EmptyIsValidNotAFailure(t *testing.T) {
	for name, data := range map[string][]byte{
		"no blocks":    cachegen.BuildChromiumBlockfileData(nil),
		"blocks, none": cachegen.BuildChromiumBlockfileDataSized(256, 40),
	} {
		scan, err := bc.ParseChromiumBlockfileData(tmpWrite(t, "data_1", data), bc.Limits{})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(scan.Entries) != 0 {
			t.Errorf("%s: got %d entries, want 0", name, len(scan.Entries))
		}
	}
}

// Only the 256-byte block file holds entry records.
//
// data_0 (36-byte LRU rankings) and data_2/data_3 (1 KiB and 4 KiB
// stream payloads) are neither sniffed nor parsed: reading one as
// entries would fabricate records out of cached content, and claiming
// one as supported would import a file guaranteed to yield nothing. The
// capability registry names each of them instead.
func TestBlockfileData_OnlyThe256ByteFileHoldsEntries(t *testing.T) {
	for _, size := range []int{36, 1024, 4096} {
		data := cachegen.BuildChromiumBlockfileDataSized(size, 8)
		if bc.SniffChromiumBlockfileData(data) {
			t.Errorf("a %d-byte block file was claimed as holding entry records", size)
		}
		if _, err := bc.ParseChromiumBlockfileData(tmpWrite(t, "data_2", data), bc.Limits{}); err == nil {
			t.Errorf("a %d-byte block file parsed as entry records", size)
		}
		// It is still recognizable AS a blockfile file, which is what
		// lets the registry explain it rather than call it unknown.
		got, ok := bc.IsChromiumBlockfileDataAnySize(data)
		if !ok || got != size {
			t.Errorf("a %d-byte block file is not recognized as a blockfile file (got %d, %v)", size, got, ok)
		}
	}
	// The 256-byte file is the one that is claimed.
	if !bc.SniffChromiumBlockfileData(cachegen.BuildChromiumBlockfileDataSized(256, 8)) {
		t.Error("the 256-byte block file was not claimed")
	}
}

// Evicted and doomed records are counted, never emitted: their fields
// are being recycled and may no longer describe the key.
func TestBlockfileData_EvictedAndDoomedAreNotEmitted(t *testing.T) {
	data := cachegen.BuildChromiumBlockfileData([]cachegen.BlockfileEntry{
		{Key: "https://example.test/live.js", CreationUnix: blockBase.Unix()},
		{Key: "https://example.test/evicted.js", CreationUnix: blockBase.Unix(), State: 1},
		{Key: "https://example.test/doomed.js", CreationUnix: blockBase.Unix(), State: 2},
	})
	scan, err := bc.ParseChromiumBlockfileData(tmpWrite(t, "data_1", data), bc.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Entries) != 1 || scan.Entries[0].URL != "https://example.test/live.js" {
		t.Fatalf("got %v, want only the live entry", urlsOf(scan.Entries))
	}
	if scan.SkippedEvicted != 1 || scan.SkippedDoomed != 1 {
		t.Errorf("skip counts = evicted %d, doomed %d; want 1 and 1", scan.SkippedEvicted, scan.SkippedDoomed)
	}
}

// A record whose creation time is absent is not an entry: the format's
// value is its timestamp, and emitting one without would be worse than
// silence.
func TestBlockfileData_RecordWithoutTimeIsNotEmitted(t *testing.T) {
	data := cachegen.BuildChromiumBlockfileData([]cachegen.BlockfileEntry{
		{Key: "https://example.test/no-time.js"},
	})
	scan, err := bc.ParseChromiumBlockfileData(tmpWrite(t, "data_1", data), bc.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range scan.Entries {
		if e.LastFetched.IsZero() {
			t.Errorf("an entry with no recorded time was emitted: %s", e.URL)
		}
	}
}

// A key stored outside the record is reported as unrecoverable, not
// replaced with something that looks like a URL.
func TestBlockfileData_ExternalKeyIsReportedNotInvented(t *testing.T) {
	data := cachegen.BuildChromiumBlockfileData([]cachegen.BlockfileEntry{
		{Key: "https://example.test/" + strings.Repeat("a", 40), CreationUnix: blockBase.Unix(), LongKey: true},
	})
	scan, err := bc.ParseChromiumBlockfileData(tmpWrite(t, "data_1", data), bc.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range scan.Entries {
		if e.URL != "" {
			t.Errorf("a URL was produced for an externally stored key: %q", e.URL)
		}
	}
	if scan.SkippedNoKey == 0 && len(scan.Entries) == 0 {
		t.Error("the record was neither emitted nor counted")
	}
}

// Malformed input never panics, never hangs, and never yields entries
// built out of damaged fields.
func TestBlockfileData_MalformedInputIsRejectedCleanly(t *testing.T) {
	good := cachegen.BuildChromiumBlockfileData(blockEntries())
	for _, how := range []string{"magic", "block-size", "huge-key", "zero-time", "bad-state", "truncate"} {
		path := tmpWrite(t, "data_1", cachegen.CorruptBlockfile(good, how))
		scan, err := bc.ParseChromiumBlockfileData(path, bc.Limits{})
		if err != nil {
			continue // a classified error is a fine outcome
		}
		for _, e := range scan.Entries {
			if e.LastFetched.IsZero() {
				t.Errorf("%s: emitted an entry with no time", how)
			}
			if e.URL != "" && !strings.Contains(e.URL, "://") {
				t.Errorf("%s: emitted %q as a URL", how, e.URL)
			}
		}
	}
}

// Byte-flip fuzzing: no panic, no runaway allocation, no invented URL.
func TestBlockfileData_ByteFlipsAreSurvivable(t *testing.T) {
	good := cachegen.BuildChromiumBlockfileData(blockEntries())
	for i := 0; i < len(good); i += 37 {
		bad := append([]byte(nil), good...)
		bad[i] ^= 0xFF
		scan, err := bc.ParseChromiumBlockfileData(tmpWrite(t, "data_1", bad), bc.Limits{})
		if err != nil {
			continue
		}
		if len(scan.Entries) > 64 {
			t.Fatalf("offset %d produced %d entries from a 3-entry file", i, len(scan.Entries))
		}
		for _, e := range scan.Entries {
			if e.URL != "" && !strings.Contains(e.URL, "://") {
				t.Fatalf("offset %d produced %q as a URL", i, e.URL)
			}
		}
	}
}

func TestBlockfileData_IsDeterministic(t *testing.T) {
	path := tmpWrite(t, "data_1", cachegen.BuildChromiumBlockfileData(blockEntries()))
	first, err := bc.ParseChromiumBlockfileData(path, bc.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := bc.ParseChromiumBlockfileData(path, bc.Limits{})
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if strings.Join(urlsOf(again.Entries), "|") != strings.Join(urlsOf(first.Entries), "|") {
			t.Fatalf("run %d returned a different order/content", i)
		}
	}
}

// ---------------- Firefox cache1 ----------------

func TestCache1Map_ReadsContainerMetadata(t *testing.T) {
	data := cachegen.BuildFirefoxCache1Map(cachegen.Cache1MapOptions{
		DataSize: 8 << 20, EntryCount: 1204, RecordCount: 1204, Records: 1204,
	})
	m, err := bc.ParseFirefoxCache1Map(tmpWrite(t, "_CACHE_MAP_", data), bc.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if m.EntryCount != 1204 || m.RecordCount != 1204 {
		t.Errorf("counts = %d/%d, want 1204/1204", m.EntryCount, m.RecordCount)
	}
	if m.Records != 1204 {
		t.Errorf("actual record slots = %d", m.Records)
	}
	if m.IsDirty {
		t.Error("a clean map was reported dirty")
	}
	if m.Version == 0 {
		t.Error("version not recorded")
	}
}

// A dirty flag and a truncated record area are both reported.
func TestCache1Map_ReportsDirtyAndTruncated(t *testing.T) {
	data := cachegen.BuildFirefoxCache1Map(cachegen.Cache1MapOptions{
		EntryCount: 500, RecordCount: 500, Records: 10, IsDirty: true,
	})
	m, err := bc.ParseFirefoxCache1Map(tmpWrite(t, "_CACHE_MAP_", data), bc.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if !m.IsDirty {
		t.Error("the dirty flag was lost")
	}
	joined := strings.Join(m.Warnings, " ")
	if !strings.Contains(joined, "not shut down cleanly") {
		t.Errorf("the dirty cache is not explained: %v", m.Warnings)
	}
	if !strings.Contains(joined, "truncated") {
		t.Errorf("the truncated record area is not reported: %v", m.Warnings)
	}
}

func TestCache1Map_RefusesUnknownVersion(t *testing.T) {
	data := cachegen.BuildFirefoxCache1Map(cachegen.Cache1MapOptions{Version: 0x00090001, Records: 2})
	_, err := bc.ParseFirefoxCache1Map(tmpWrite(t, "_CACHE_MAP_", data), bc.Limits{})
	if err == nil {
		t.Fatal("an unknown nsDiskCache version was decoded anyway")
	}
	if !strings.Contains(err.Error(), "version") {
		t.Errorf("the error does not name the problem: %v", err)
	}
}

func cache1Entries() []cachegen.Cache1Entry {
	return []cachegen.Cache1Entry{
		{
			Key: "HTTP:https://example.test/index.html", FetchCount: 5,
			LastFetchedU: uint32(cache1Base.Unix()), LastModifiedU: uint32(cache1Base.Add(-time.Hour).Unix()),
			ExpirationU: uint32(cache1Base.Add(24 * time.Hour).Unix()), DataSize: 5120,
			RequestMethod: "GET",
			ResponseHead:  "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5120\r\nServer: Apache\r\n",
		},
		{
			Key: "HTTP:https://cdn.example.test/style.css", FetchCount: 1,
			LastFetchedU: uint32(cache1Base.Add(time.Minute).Unix()), DataSize: 2048,
			RequestMethod: "GET",
			ResponseHead:  "HTTP/1.1 200 OK\r\nContent-Type: text/css\r\n",
		},
		{
			Key: "HTTP:https://example.test/form", FetchCount: 1,
			LastFetchedU: uint32(cache1Base.Add(2 * time.Minute).Unix()), DataSize: 64,
			RequestMethod: "POST",
			ResponseHead:  "HTTP/1.1 302 Found\r\nContent-Type: text/plain\r\n",
		},
	}
}

func TestCache1Block_ReadsMultipleEntries(t *testing.T) {
	path := tmpWrite(t, "_CACHE_001_", cachegen.BuildFirefoxCache1Block(256, cache1Entries()))
	scan, err := bc.ParseFirefoxCache1Block(path, 1, bc.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Entries) != 3 {
		t.Fatalf("got %d entries, want 3: %v", len(scan.Entries), urlsOf(scan.Entries))
	}

	byURL := map[string]bc.Entry{}
	for _, e := range scan.Entries {
		byURL[e.URL] = e
		if e.Format != bc.FormatFirefoxCache1 {
			t.Errorf("format = %q", e.Format)
		}
		if e.Format.Generation() != bc.GenerationLegacy {
			t.Error("cache1 is not marked as a legacy generation")
		}
	}

	idx := byURL["https://example.test/index.html"]
	if !idx.LastFetched.Equal(cache1Base) {
		t.Errorf("last fetched = %s, want %s", idx.LastFetched, cache1Base)
	}
	if !idx.LastModified.Equal(cache1Base.Add(-time.Hour)) {
		t.Errorf("last modified = %s", idx.LastModified)
	}
	if !idx.ExpirationTime.Equal(cache1Base.Add(24 * time.Hour)) {
		t.Errorf("expiration = %s", idx.ExpirationTime)
	}
	if idx.FetchCount != 5 {
		t.Errorf("fetch count = %d, want 5", idx.FetchCount)
	}
	// cache1 is the only format Tracefall reads that records a method.
	if idx.RequestMethod != "GET" {
		t.Errorf("request method = %q, want GET", idx.RequestMethod)
	}
	if idx.StatusCode != 200 || idx.ContentType != "text/html" {
		t.Errorf("status/type = %d/%q", idx.StatusCode, idx.ContentType)
	}
	if !idx.HasContentLength || idx.ContentLength != 5120 {
		t.Errorf("content length = %d", idx.ContentLength)
	}
	if idx.StoredBytes != 5120 {
		t.Errorf("stored bytes = %d", idx.StoredBytes)
	}
	if byURL["https://example.test/form"].RequestMethod != "POST" {
		t.Error("a POST entry lost its method")
	}
	if byURL["https://example.test/form"].StatusCode != 302 {
		t.Error("a 302 entry lost its status")
	}
}

// Entries spanning more than one block are read, and their trailing
// blocks are not re-read as further entries.
func TestCache1Block_MultiBlockEntriesAreNotDoubleCounted(t *testing.T) {
	long := cachegen.Cache1Entry{
		Key:          "HTTP:https://example.test/" + strings.Repeat("p", 300),
		LastFetchedU: uint32(cache1Base.Unix()), FetchCount: 1, RequestMethod: "GET",
		ResponseHead: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n",
	}
	path := tmpWrite(t, "_CACHE_001_", cachegen.BuildFirefoxCache1Block(256, []cachegen.Cache1Entry{long}))
	scan, err := bc.ParseFirefoxCache1Block(path, 1, bc.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Entries) != 1 {
		t.Fatalf("a multi-block entry produced %d entries, want 1", len(scan.Entries))
	}
}

// The three block sizes are all readable.
func TestCache1Block_AllThreeBlockSizes(t *testing.T) {
	for file, size := range map[int]int{1: 256, 2: 1024, 3: 4096} {
		name := fmt.Sprintf("_CACHE_00%d_", file)
		path := tmpWrite(t, name, cachegen.BuildFirefoxCache1Block(size, cache1Entries()))
		scan, err := bc.ParseFirefoxCache1Block(path, file, bc.Limits{})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(scan.Entries) != 3 {
			t.Errorf("%s: got %d entries, want 3", name, len(scan.Entries))
		}
		if scan.BlockSize != size {
			t.Errorf("%s: block size = %d, want %d", name, scan.BlockSize, size)
		}
	}
}

// A block file holding only its bitmap is valid and empty.
func TestCache1Block_EmptyIsValidNotAFailure(t *testing.T) {
	path := tmpWrite(t, "_CACHE_001_", cachegen.BuildFirefoxCache1Block(256, nil))
	scan, err := bc.ParseFirefoxCache1Block(path, 1, bc.Limits{})
	if err != nil {
		t.Fatalf("an empty block file was reported as an error: %v", err)
	}
	if len(scan.Entries) != 0 {
		t.Errorf("got %d entries from an empty file", len(scan.Entries))
	}
	if len(scan.Warnings) == 0 {
		t.Error("an empty block file gives no explanation")
	}
}

// A file too short to hold even the allocation bitmap is corrupt, and is
// named as such rather than reported as empty.
func TestCache1Block_TruncatedBitmapIsCorrupt(t *testing.T) {
	path := tmpWrite(t, "_CACHE_001_", make([]byte, 100))
	_, err := bc.ParseFirefoxCache1Block(path, 1, bc.Limits{})
	if err == nil {
		t.Fatal("a file shorter than the bitmap parsed successfully")
	}
	if !strings.Contains(err.Error(), "bitmap") {
		t.Errorf("the error does not explain what is missing: %v", err)
	}
}

// A record with no usable timestamp is not emitted.
func TestCache1Block_RecordWithoutTimeIsNotEmitted(t *testing.T) {
	data := cachegen.BuildFirefoxCache1Block(256, []cachegen.Cache1Entry{{
		Key: "HTTP:https://example.test/x", FetchCount: 1, OmitTimestamps: true,
		RequestMethod: "GET", ResponseHead: "HTTP/1.1 200 OK\r\n",
	}})
	scan, err := bc.ParseFirefoxCache1Block(tmpWrite(t, "_CACHE_001_", data), 1, bc.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range scan.Entries {
		if e.LastFetched.IsZero() && e.LastModified.IsZero() {
			t.Error("an entry with no recorded time was emitted")
		}
	}
}

// An expiration sentinel is absence, not a date in 2106.
func TestCache1Block_NeverExpiresIsNotADate(t *testing.T) {
	data := cachegen.BuildFirefoxCache1Block(256, []cachegen.Cache1Entry{{
		Key: "HTTP:https://example.test/x", LastFetchedU: uint32(cache1Base.Unix()),
		ExpirationU: 0xFFFFFFFF, FetchCount: 1,
	}})
	scan, err := bc.ParseFirefoxCache1Block(tmpWrite(t, "_CACHE_001_", data), 1, bc.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Entries) != 1 {
		t.Fatalf("got %d entries", len(scan.Entries))
	}
	if !scan.Entries[0].ExpirationTime.IsZero() {
		t.Errorf("the never-expires sentinel became %s", scan.Entries[0].ExpirationTime)
	}
}

// Only real HTTP methods are accepted into the method field.
func TestCache1Block_GarbageMethodIsDropped(t *testing.T) {
	data := cachegen.BuildFirefoxCache1Block(256, []cachegen.Cache1Entry{{
		Key: "HTTP:https://example.test/x", LastFetchedU: uint32(cache1Base.Unix()),
		FetchCount: 1, RequestMethod: "NOT-A-METHOD\x01\x02",
	}})
	scan, err := bc.ParseFirefoxCache1Block(tmpWrite(t, "_CACHE_001_", data), 1, bc.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Entries) != 1 {
		t.Fatalf("got %d entries", len(scan.Entries))
	}
	if m := scan.Entries[0].RequestMethod; m != "" {
		t.Errorf("request method = %q; garbage must not reach an analyst as a method", m)
	}
}

// Credentials in a cache1 response head are redacted like everywhere else.
func TestCache1Block_CredentialsAreRedacted(t *testing.T) {
	data := cachegen.BuildFirefoxCache1Block(256, []cachegen.Cache1Entry{{
		Key: "HTTP:https://mail.example.test/inbox", LastFetchedU: uint32(cache1Base.Unix()), FetchCount: 1,
		ResponseHead: "HTTP/1.1 200 OK\r\nSet-Cookie: sid=CACHE1SECRET\r\nContent-Type: text/html\r\n",
	}})
	scan, err := bc.ParseFirefoxCache1Block(tmpWrite(t, "_CACHE_001_", data), 1, bc.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fmt.Sprint(scan.Entries), "CACHE1SECRET") {
		t.Error("a session cookie survived into a cache1 entry")
	}
}

func TestCache1Block_MalformedInputIsRejectedCleanly(t *testing.T) {
	good := cachegen.BuildFirefoxCache1Block(256, cache1Entries())
	for _, how := range []string{"version", "huge-key", "huge-meta", "zero-times", "truncate"} {
		scan, err := bc.ParseFirefoxCache1Block(tmpWrite(t, "_CACHE_001_", cachegen.CorruptCache1(good, how)), 1, bc.Limits{})
		if err != nil {
			continue
		}
		for _, e := range scan.Entries {
			if e.LastFetched.IsZero() && e.LastModified.IsZero() {
				t.Errorf("%s: emitted an entry with no time", how)
			}
			if !strings.Contains(e.URL, "://") {
				t.Errorf("%s: emitted %q as a URL", how, e.URL)
			}
		}
	}
}

func TestCache1Block_ByteFlipsAreSurvivable(t *testing.T) {
	good := cachegen.BuildFirefoxCache1Block(256, cache1Entries())
	for i := 4000; i < len(good); i += 29 {
		bad := append([]byte(nil), good...)
		bad[i] ^= 0xFF
		scan, err := bc.ParseFirefoxCache1Block(tmpWrite(t, "_CACHE_001_", bad), 1, bc.Limits{})
		if err != nil {
			continue
		}
		if len(scan.Entries) > 64 {
			t.Fatalf("offset %d produced %d entries", i, len(scan.Entries))
		}
		for _, e := range scan.Entries {
			if !strings.Contains(e.URL, "://") {
				t.Fatalf("offset %d produced %q as a URL", i, e.URL)
			}
		}
	}
}

func TestCache1Block_IsDeterministic(t *testing.T) {
	path := tmpWrite(t, "_CACHE_001_", cachegen.BuildFirefoxCache1Block(256, cache1Entries()))
	first, err := bc.ParseFirefoxCache1Block(path, 1, bc.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := bc.ParseFirefoxCache1Block(path, 1, bc.Limits{})
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if strings.Join(urlsOf(again.Entries), "|") != strings.Join(urlsOf(first.Entries), "|") {
			t.Fatalf("run %d differed", i)
		}
	}
}

// ---------------- Detection ----------------

// Only the cache1 block files are claimed by name, and only by their
// exact format-defined names.
func TestCache1_BlockNameDetectionIsExact(t *testing.T) {
	for _, name := range []string{"_CACHE_001_", "_CACHE_002_", "_CACHE_003_", "_cache_001_"} {
		if _, ok := bc.IsFirefoxCache1BlockName(name); !ok {
			t.Errorf("%q was not recognized as a cache1 block file", name)
		}
	}
	for _, name := range []string{"_CACHE_004_", "_CACHE_001_.bak", "CACHE_001", "_CACHE_MAP_", "data_1", "index"} {
		if _, ok := bc.IsFirefoxCache1BlockName(name); ok {
			t.Errorf("%q was wrongly claimed as a cache1 block file", name)
		}
	}
}

func TestSniff_EachFormatClaimsOnlyItsOwn(t *testing.T) {
	samples := map[string][]byte{
		"blockfile index": cachegen.BuildChromiumBlockfileIndex(cachegen.BlockfileIndexOptions{NumEntries: 1}),
		"blockfile data":  cachegen.BuildChromiumBlockfileData(blockEntries()),
		"cache1 map":      cachegen.BuildFirefoxCache1Map(cachegen.Cache1MapOptions{Records: 4}),
		"simple cache":    cachegen.BuildChromiumSimple(cachegen.ChromiumEntry{Key: "https://example.test/x", StatusLine: "HTTP/1.1 200 OK"}),
		"text":            []byte(strings.Repeat("ordinary text ", 40)),
		"zeros":           make([]byte, 512),
	}
	type sniff struct {
		name string
		fn   func([]byte) bool
	}
	sniffs := []sniff{
		{"blockfile index", bc.SniffChromiumBlockfileIndex},
		{"blockfile data", bc.SniffChromiumBlockfileData},
		{"cache1 map", bc.SniffFirefoxCache1Map},
		{"simple cache", bc.SniffChromiumSimple},
	}
	for sampleName, data := range samples {
		for _, s := range sniffs {
			got := s.fn(data)
			want := s.name == sampleName
			if got != want {
				t.Errorf("%s sniff on %s sample = %v, want %v", s.name, sampleName, got, want)
			}
		}
	}
}

// The cache1 map sniff must not accept a file that merely opens with a
// plausible version word.
func TestSniff_Cache1MapRequiresMoreThanAVersionWord(t *testing.T) {
	data := make([]byte, 200)
	data[0], data[1], data[2], data[3] = 0x00, 0x01, 0x00, 0x13
	// A dirty flag of 0x41414141 is not a boolean.
	copy(data[12:16], []byte{0x41, 0x41, 0x41, 0x41})
	if bc.SniffFirefoxCache1Map(data) {
		t.Error("a file with an implausible header was claimed as _CACHE_MAP_")
	}
}

func urlsOf(entries []bc.Entry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.URL)
	}
	return out
}
