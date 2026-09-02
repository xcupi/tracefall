package browsercache_test

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"tracefall/internal/browsercache"
	"tracefall/internal/browsercache/cachegen"
)

func writeEntry(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// ---------------- Chromium Simple Cache ----------------

func chromiumSample() []byte {
	return cachegen.BuildChromiumSimple(cachegen.ChromiumEntry{
		Key:        "https://example.com/assets/app.js",
		StatusLine: "HTTP/1.1 200 OK",
		Headers: []string{
			"Content-Type: application/javascript; charset=utf-8",
			"Content-Length: 4096",
			"Server: nginx",
			"Cache-Control: max-age=3600",
		},
		Body: []byte(strings.Repeat("console.log(1);", 20)),
	})
}

func TestChromium_ValidEntry(t *testing.T) {
	e, err := browsercache.ParseChromiumSimple(writeEntry(t, "abc123_0", chromiumSample()), browsercache.Limits{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Format != browsercache.FormatChromiumSimple {
		t.Errorf("format = %q", e.Format)
	}
	if e.URL != "https://example.com/assets/app.js" {
		t.Errorf("URL = %q", e.URL)
	}
	if e.Host() != "example.com" {
		t.Errorf("host = %q", e.Host())
	}
	if e.StatusCode != 200 {
		t.Errorf("status = %d, want 200", e.StatusCode)
	}
	if e.ContentType != "application/javascript" {
		t.Errorf("content type = %q, want the media type without parameters", e.ContentType)
	}
	if !e.HasContentLength || e.ContentLength != 4096 {
		t.Errorf("content length = %d (present=%v), want 4096", e.ContentLength, e.HasContentLength)
	}
	if e.EntryID != "abc123_0" {
		t.Errorf("entry id = %q", e.EntryID)
	}
	if e.Version == 0 {
		t.Error("no format version recorded")
	}
	// A Simple Cache ENTRY carries no timestamp. It must not invent one.
	if e.HasTimelineTimestamp() {
		t.Error("a Chromium Simple Cache entry reported a timestamp it does not store")
	}
	if !e.LastFetched.IsZero() || !e.LastModified.IsZero() {
		t.Error("a timestamp was fabricated for a Chromium entry")
	}
}

// The padded and packed header layouts must both decode.
func TestChromium_HeaderPaddingDisambiguation(t *testing.T) {
	for _, padded := range []bool{false, true} {
		t.Run(fmt.Sprintf("padded=%v", padded), func(t *testing.T) {
			data := cachegen.BuildChromiumSimple(cachegen.ChromiumEntry{
				Key: "https://example.com/x.png", PadHeader: padded,
				StatusLine: "HTTP/1.1 200 OK", Headers: []string{"Content-Type: image/png"},
				Body: []byte("PNGDATA"),
			})
			e, err := browsercache.ParseChromiumSimple(writeEntry(t, "e_0", data), browsercache.Limits{})
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if e.URL != "https://example.com/x.png" {
				t.Errorf("URL = %q with padded=%v", e.URL, padded)
			}
			if e.ContentType != "image/png" {
				t.Errorf("content type = %q", e.ContentType)
			}
		})
	}
}

// Partitioned / double-keyed cache keys yield the RESOURCE url.
func TestChromium_PartitionedKeyExtraction(t *testing.T) {
	key := cachegen.ChromiumURL("https://news.example", "https://cdn.example/track.gif")
	data := cachegen.BuildChromiumSimple(cachegen.ChromiumEntry{
		Key: key, StatusLine: "HTTP/1.1 200 OK", Headers: []string{"Content-Type: image/gif"},
	})
	e, err := browsercache.ParseChromiumSimple(writeEntry(t, "p_0", data), browsercache.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if e.URL != "https://cdn.example/track.gif" {
		t.Errorf("URL = %q, want the resource rather than the top-frame site", e.URL)
	}
	// The full key must still be preserved verbatim.
	if e.Key != key {
		t.Errorf("the raw cache key was not preserved: %q", e.Key)
	}
}

// Credentials must never be copied into a case.
func TestChromium_SensitiveHeadersAreRedacted(t *testing.T) {
	data := cachegen.BuildChromiumSimple(cachegen.ChromiumEntry{
		Key: "https://example.com/api", StatusLine: "HTTP/1.1 200 OK",
		Headers: []string{
			"Content-Type: application/json",
			"Set-Cookie: session=SUPERSECRETVALUE; Path=/",
			"Authorization: Bearer TOPSECRETTOKEN",
		},
	})
	e, err := browsercache.ParseChromiumSimple(writeEntry(t, "s_0", data), browsercache.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	blob := fmt.Sprint(e.Headers)
	for _, secret := range []string{"SUPERSECRETVALUE", "TOPSECRETTOKEN"} {
		if strings.Contains(blob, secret) {
			t.Errorf("a credential was retained in the parsed headers: %s", secret)
		}
	}
	var sawRedaction bool
	for _, h := range e.Headers {
		if strings.Contains(h.Value, "redacted") {
			sawRedaction = true
		}
	}
	if !sawRedaction {
		t.Error("sensitive headers were dropped silently rather than marked redacted")
	}
}

func TestChromium_MultipleEntriesAndDeterminism(t *testing.T) {
	urls := []string{
		"https://a.example/1.css", "https://b.example/2.js",
		"http://c.example/3.png", "https://d.example/файл.html",
	}
	for _, u := range urls {
		data := cachegen.BuildChromiumSimple(cachegen.ChromiumEntry{
			Key: u, StatusLine: "HTTP/1.1 200 OK", Headers: []string{"Content-Type: text/plain"},
			Body: []byte("body"),
		})
		path := writeEntry(t, "m_0", data)
		first, err := browsercache.ParseChromiumSimple(path, browsercache.Limits{})
		if err != nil {
			t.Fatalf("%s: %v", u, err)
		}
		if first.URL != u {
			t.Errorf("URL = %q, want %q", first.URL, u)
		}
		for i := 0; i < 10; i++ {
			again, err := browsercache.ParseChromiumSimple(path, browsercache.Limits{})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(first, again) {
				t.Fatalf("%s: run %d differed", u, i)
			}
		}
	}
}

func TestChromium_MalformedNeverPanics(t *testing.T) {
	base := chromiumSample()
	for _, how := range []string{"magic", "huge-key", "zero-key", "key-past-end", "eof-negative-size"} {
		t.Run(how, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on %q: %v", how, r)
				}
			}()
			_, _ = browsercache.ParseChromiumSimple(
				writeEntry(t, "c_0", cachegen.CorruptChromium(base, how)), browsercache.Limits{})
		})
	}
	for cut := 0; cut <= len(base); cut += 7 {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked at truncation %d: %v", cut, r)
				}
			}()
			_, _ = browsercache.ParseChromiumSimple(writeEntry(t, "t_0", base[:cut]), browsercache.Limits{})
		}()
	}
	for i := 0; i < len(base) && i < 400; i += 3 {
		mutated := append([]byte(nil), base...)
		mutated[i] ^= 0xFF
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on byte flip at %d: %v", i, r)
				}
			}()
			_, _ = browsercache.ParseChromiumSimple(writeEntry(t, "f_0", mutated), browsercache.Limits{})
		}()
	}
}

// A declared size beyond the limit is refused before allocating.
func TestChromium_RespectsLimits(t *testing.T) {
	data := cachegen.CorruptChromium(chromiumSample(), "huge-key")
	_, err := browsercache.ParseChromiumSimple(writeEntry(t, "l_0", data),
		browsercache.Limits{MaxKeyBytes: 1024})
	if err == nil {
		t.Fatal("an oversized declared key was accepted")
	}
}

// A large entry parses without difficulty.
func TestChromium_LargeEntry(t *testing.T) {
	data := cachegen.BuildChromiumSimple(cachegen.ChromiumEntry{
		Key: "https://example.com/big.bin", StatusLine: "HTTP/1.1 200 OK",
		Headers: []string{"Content-Type: application/octet-stream"},
		Body:    make([]byte, 4<<20),
	})
	e, err := browsercache.ParseChromiumSimple(writeEntry(t, "big_0", data), browsercache.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if e.StoredBytes != 4<<20 {
		t.Errorf("stored bytes = %d, want %d", e.StoredBytes, 4<<20)
	}
}

// The legacy blockfile cache is DETECTED and refused, not parsed.
func TestChromium_BlockfileIsDetectedNotParsed(t *testing.T) {
	idx := cachegen.ChromiumBlockfileIndex()
	if !browsercache.IsChromiumBlockfile(idx) {
		t.Error("the legacy blockfile index was not detected")
	}
	if browsercache.SniffChromiumSimple(idx) {
		t.Error("a blockfile index was misidentified as a Simple Cache entry")
	}
	if _, err := browsercache.ParseChromiumSimple(writeEntry(t, "index", idx), browsercache.Limits{}); err == nil {
		t.Error("a blockfile index parsed as a Simple Cache entry")
	}
}

func TestChromium_SniffIsNarrow(t *testing.T) {
	if !browsercache.SniffChromiumSimple(chromiumSample()) {
		t.Error("a real entry was not recognized")
	}
	for name, data := range map[string][]byte{
		"empty":     {},
		"text":      []byte("just a plain text file, nothing cached about it at all"),
		"zeros":     make([]byte, 512),
		"firefox":   firefoxSample(),
		"blockfile": cachegen.ChromiumBlockfileIndex(),
	} {
		if browsercache.SniffChromiumSimple(data) {
			t.Errorf("%q was misidentified as a Chromium cache entry", name)
		}
	}
}

// ---------------- Firefox cache2 ----------------

var ffFetched = uint32(time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC).Unix())
var ffModified = uint32(time.Date(2026, 6, 1, 11, 30, 0, 0, time.UTC).Unix())
var ffExpires = uint32(time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC).Unix())

func firefoxSample() []byte {
	return cachegen.BuildFirefoxCache2(cachegen.FirefoxEntry{
		Key:            "a,:https://example.org/styles/site.css",
		FetchCount:     7,
		LastFetched:    ffFetched,
		LastModified:   ffModified,
		ExpirationTime: ffExpires,
		Frecency:       42,
		ResponseHead:   "HTTP/1.1 200 OK\r\nContent-Type: text/css\r\nContent-Length: 2048\r\nServer: Apache\r\n",
		Body:           []byte(strings.Repeat("body{}", 100)),
	})
}

func TestFirefox_ValidEntry(t *testing.T) {
	e, err := browsercache.ParseFirefoxCache2(writeEntry(t, "5F2A", firefoxSample()), browsercache.Limits{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Format != browsercache.FormatFirefoxCache2 {
		t.Errorf("format = %q", e.Format)
	}
	if e.URL != "https://example.org/styles/site.css" {
		t.Errorf("URL = %q", e.URL)
	}
	if e.Host() != "example.org" {
		t.Errorf("host = %q", e.Host())
	}
	if e.StatusCode != 200 {
		t.Errorf("status = %d", e.StatusCode)
	}
	if e.ContentType != "text/css" {
		t.Errorf("content type = %q", e.ContentType)
	}
	if !e.HasContentLength || e.ContentLength != 2048 {
		t.Errorf("content length = %d", e.ContentLength)
	}
	if e.FetchCount != 7 {
		t.Errorf("fetch count = %d, want 7", e.FetchCount)
	}
	// cache2 DOES record timestamps.
	if !e.HasTimelineTimestamp() {
		t.Fatal("a cache2 entry reported no timestamp; it records lastFetched")
	}
	if !e.LastFetched.Equal(time.Unix(int64(ffFetched), 0).UTC()) {
		t.Errorf("lastFetched = %s", e.LastFetched)
	}
	if !e.LastModified.Equal(time.Unix(int64(ffModified), 0).UTC()) {
		t.Errorf("lastModified = %s", e.LastModified)
	}
	if !e.ExpirationTime.Equal(time.Unix(int64(ffExpires), 0).UTC()) {
		t.Errorf("expiration = %s", e.ExpirationTime)
	}
	if e.LastFetched.Location() != time.UTC {
		t.Error("timestamp is not UTC")
	}
	if e.StoredBytes != int64(len(strings.Repeat("body{}", 100))) {
		t.Errorf("stored bytes = %d", e.StoredBytes)
	}
}

// Both header generations decode.
func TestFirefox_HeaderVersions(t *testing.T) {
	for _, v := range []uint32{1, 2, 3} {
		t.Run(fmt.Sprintf("v%d", v), func(t *testing.T) {
			data := cachegen.BuildFirefoxCache2(cachegen.FirefoxEntry{
				Version: v, Key: "a,:https://example.org/x", LastFetched: ffFetched,
				ResponseHead: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n",
			})
			e, err := browsercache.ParseFirefoxCache2(writeEntry(t, "v", data), browsercache.Limits{})
			if err != nil {
				t.Fatalf("v%d: %v", v, err)
			}
			if e.URL != "https://example.org/x" {
				t.Errorf("v%d URL = %q", v, e.URL)
			}
			if e.Version != v {
				t.Errorf("version = %d, want %d", e.Version, v)
			}
		})
	}
}

// An unsupported generation is REFUSED, never parsed with the wrong
// layout and never treated as empty.
func TestFirefox_FutureVersionIsRefusedNotGuessed(t *testing.T) {
	// A PLAUSIBLE next generation: structurally a cache2 entry, but a
	// metadata version this build has no layout for. It must be refused
	// by version rather than decoded with the current offsets -- and
	// never reported as an empty entry.
	data := cachegen.BuildFirefoxCache2(cachegen.FirefoxEntry{
		Version: 5, Key: "a,:https://example.org/future", LastFetched: ffFetched,
		ResponseHead: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n",
	})
	_, err := browsercache.ParseFirefoxCache2(writeEntry(t, "fv", data), browsercache.Limits{})
	if err == nil {
		t.Fatal("an unknown cache2 version was parsed rather than refused")
	}
	if !strings.Contains(err.Error(), "version") {
		t.Errorf("the error does not name the version problem: %v", err)
	}

	// A wildly out-of-range version is not a cache2 entry at all, and is
	// refused as such rather than as a version this build might one day
	// support.
	junk := cachegen.CorruptFirefox(firefoxSample(), "future-version")
	if _, err := browsercache.ParseFirefoxCache2(writeEntry(t, "junk", junk), browsercache.Limits{}); err == nil {
		t.Error("an implausible version word was accepted")
	}
}

func TestFirefox_SensitiveHeadersAreRedacted(t *testing.T) {
	data := cachegen.BuildFirefoxCache2(cachegen.FirefoxEntry{
		Key: "a,:https://example.org/login", LastFetched: ffFetched,
		ResponseHead: "HTTP/1.1 200 OK\r\nSet-Cookie: sid=FIREFOXSECRET; HttpOnly\r\nContent-Type: text/html\r\n",
	})
	e, err := browsercache.ParseFirefoxCache2(writeEntry(t, "sec", data), browsercache.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fmt.Sprint(e.Headers), "FIREFOXSECRET") {
		t.Error("a session cookie was retained")
	}
}

func TestFirefox_MultipleEntriesAndDeterminism(t *testing.T) {
	for i, u := range []string{
		"https://one.example/a", "https://two.example/b", "https://three.example/файл",
	} {
		data := cachegen.BuildFirefoxCache2(cachegen.FirefoxEntry{
			Key: "a,:" + u, LastFetched: ffFetched + uint32(i),
			ResponseHead: "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n",
			Body:         []byte("x"),
		})
		path := writeEntry(t, "d", data)
		first, err := browsercache.ParseFirefoxCache2(path, browsercache.Limits{})
		if err != nil {
			t.Fatalf("%s: %v", u, err)
		}
		if first.URL != u {
			t.Errorf("URL = %q, want %q", first.URL, u)
		}
		for k := 0; k < 10; k++ {
			again, err := browsercache.ParseFirefoxCache2(path, browsercache.Limits{})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(first, again) {
				t.Fatalf("%s run %d differed", u, k)
			}
		}
	}
}

func TestFirefox_MalformedNeverPanics(t *testing.T) {
	base := firefoxSample()
	for _, how := range []string{"offset-past-end", "offset-negative", "huge-key", "future-version"} {
		t.Run(how, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on %q: %v", how, r)
				}
			}()
			_, _ = browsercache.ParseFirefoxCache2(
				writeEntry(t, "c", cachegen.CorruptFirefox(base, how)), browsercache.Limits{})
		})
	}
	for cut := 0; cut <= len(base); cut += 5 {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked at truncation %d: %v", cut, r)
				}
			}()
			_, _ = browsercache.ParseFirefoxCache2(writeEntry(t, "t", base[:cut]), browsercache.Limits{})
		}()
	}
	for i := 0; i < len(base) && i < 400; i += 3 {
		mutated := append([]byte(nil), base...)
		mutated[i] ^= 0xFF
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on byte flip at %d: %v", i, r)
				}
			}()
			_, _ = browsercache.ParseFirefoxCache2(writeEntry(t, "f", mutated), browsercache.Limits{})
		}()
	}
}

func TestFirefox_SniffIsNarrow(t *testing.T) {
	if !browsercache.SniffFirefoxCache2(firefoxSample()) {
		t.Error("a real cache2 entry was not recognized")
	}
	for name, data := range map[string][]byte{
		"empty":    {},
		"text":     []byte("plain text, definitely not a cache2 entry with trailing metadata"),
		"zeros":    make([]byte, 512),
		"chromium": chromiumSample(),
	} {
		if browsercache.SniffFirefoxCache2(data) {
			t.Errorf("%q was misidentified as a Firefox cache2 entry", name)
		}
	}
}

// Implausible timestamps become zero rather than a 1970 date.
func TestFirefox_ImplausibleTimestampsAreZero(t *testing.T) {
	data := cachegen.BuildFirefoxCache2(cachegen.FirefoxEntry{
		Key: "a,:https://example.org/x", LastFetched: 1, LastModified: 0,
		ResponseHead: "HTTP/1.1 200 OK\r\n",
	})
	e, err := browsercache.ParseFirefoxCache2(writeEntry(t, "z", data), browsercache.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if !e.LastFetched.IsZero() {
		t.Errorf("an implausible timestamp became %s instead of zero", e.LastFetched)
	}
	if e.HasTimelineTimestamp() {
		t.Error("an entry with no usable time claims a timeline timestamp")
	}
}
