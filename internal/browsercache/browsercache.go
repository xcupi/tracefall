// Package browsercache reads browser HTTP cache entries for forensic
// triage.
//
// # What a cache entry proves, and what it does not
//
// A cache entry proves the browser RECEIVED and STORED a resource. It
// does not prove the user navigated to it, saw it, clicked it,
// downloaded it, or ran it. Most entries are subresources -- images,
// scripts, fonts, trackers -- fetched by a page the user never chose to
// load. Browser HISTORY is navigation evidence; the cache is response
// evidence, and this package keeps the two vocabularies apart.
//
// # Supported formats
//
// Four, each named for the format rather than for a browser -- "Chrome
// cache" would name three different structures:
//
//	Chromium "Simple Cache" entry files -- the current HTTP cache of
//	Chrome/Edge/Brave/Opera. One file per entry, magic
//	0xFCFB6D1BA7725C30. Records NO timestamp.
//
//	Chromium "blockfile" cache data_1 -- the older disk_cache format,
//	still written by GPUCache and by Chromium embedders. Many entries
//	per file, each with its own creation time. See blockfile.go.
//
//	Firefox "cache2" entry files -- Firefox 32 and later. One file per
//	entry under entries/, metadata at a trailing offset.
//
//	Firefox "cache1" _CACHE_00x_ block files -- pre-Firefox-32. Many
//	entries per file, each with fetch/modify/expiry times, a fetch
//	count and an HTTP request method. See cache1.go.
//
// Two CONTAINER formats are read for their own metadata. They hold
// addresses and hashes, never cache keys, so they yield no URLs and no
// timeline events:
//
//	Chromium blockfile "index" -- entry count, size, cache creation time.
//	Firefox cache1 "_CACHE_MAP_" -- entry/record counts, dirty flag.
//
// Deliberately NOT parsed, and reported as such rather than guessed at:
//
//	Chromium "f_######" external files -- cached response BODIES with no
//	metadata. Referenced by address from the entry that owns them.
//
//	Simple Cache "index" / "index-dir/the-real-index" -- key hashes and
//	last-used times, but no keys. Joining them to entries would mean
//	reading a file other than the one being imported.
//
//	Firefox cache2 "index" -- SHA-1 key hashes only; strictly weaker
//	than the entry files already parsed.
//
//	blockfile "data_0" (rankings) -- LRU nodes with times but no key.
//	A time that cannot be attributed to a resource is not evidence of
//	one.
//
// # Response bodies
//
// Not extracted. Cached bodies are attacker-supplied content; writing
// them into the case would put untrusted executables and scripts into
// the evidence directory for no metadata benefit. Sizes and hashes of
// the cached streams are reported instead. See the package limitations
// in docs/evidence-triage.md.
//
// # Hostile input
//
// Every offset and length comes from the file. All are bounds-checked,
// counts and sizes are capped, and a malformed entry returns an error
// rather than panicking or allocating without bound.
package browsercache

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	// ErrNotCacheEntry means the file is not a cache entry this package
	// reads.
	ErrNotCacheEntry = errors.New("browsercache: not a supported browser cache entry")
	// ErrCorrupt means the entry is structurally invalid or truncated.
	ErrCorrupt = errors.New("browsercache: cache entry is corrupt or truncated")
	// ErrLimitExceeded means a declared size exceeded a safety ceiling.
	ErrLimitExceeded = errors.New("browsercache: cache entry exceeds a safety limit")
	// ErrUnsupportedVersion means the entry's format version is one this
	// build does not decode. Reported rather than parsed with the wrong
	// layout.
	ErrUnsupportedVersion = errors.New("browsercache: unsupported cache format version")
)

// Format names the concrete on-disk format an entry came from. Never
// just "Chrome" or "Firefox": a browser has used several cache formats
// over its life and only some are supported.
type Format string

const (
	FormatChromiumSimple Format = "chromium_simple_cache"
	FormatFirefoxCache2  Format = "firefox_cache2"
	// Legacy generations. Named for the format, never for the browser:
	// "Chrome cache" would be four different structures.
	FormatChromiumBlockfile Format = "chromium_blockfile"
	FormatFirefoxCache1     Format = "firefox_cache1"
	// Container formats. These hold no cache keys and therefore no URLs;
	// they describe a cache rather than an entry in it.
	FormatChromiumBlockfileIndex Format = "chromium_blockfile_index"
	FormatFirefoxCache1Map       Format = "firefox_cache1_map"
)

// Generation separates a browser's CURRENT cache format from one it has
// superseded. An analyst filtering evidence wants to know which they are
// looking at: a legacy cache on a modern system is itself notable.
type Generation string

const (
	GenerationCurrent Generation = "current"
	GenerationLegacy  Generation = "legacy"
)

// Generation reports whether a format is a browser's current cache
// format or a superseded one.
func (f Format) Generation() Generation {
	switch f {
	case FormatChromiumBlockfile, FormatFirefoxCache1,
		FormatChromiumBlockfileIndex, FormatFirefoxCache1Map:
		return GenerationLegacy
	default:
		return GenerationCurrent
	}
}

// IsContainer reports whether a format describes a cache rather than an
// entry in one. Container files hold no URLs, so they never produce
// timeline events.
func (f Format) IsContainer() bool {
	return f == FormatChromiumBlockfileIndex || f == FormatFirefoxCache1Map
}

// Description is the one-line human name for a format, used wherever a
// record has to say what it came from.
func (f Format) Description() string {
	switch f {
	case FormatChromiumSimple:
		return "Chromium Simple Cache entry"
	case FormatChromiumBlockfile:
		return "Chromium blockfile cache entry (legacy)"
	case FormatChromiumBlockfileIndex:
		return "Chromium blockfile cache index (container)"
	case FormatFirefoxCache2:
		return "Firefox cache2 entry"
	case FormatFirefoxCache1:
		return "Firefox cache1 entry (legacy)"
	case FormatFirefoxCache1Map:
		return "Firefox cache1 _CACHE_MAP_ (container)"
	default:
		return string(f)
	}
}

// Browser families, for display.
const (
	BrowserChromium = "Chromium-family (Chrome, Edge, Brave, Opera, Vivaldi)"
	BrowserFirefox  = "Firefox"
)

// Limits bounds what one cache entry may consume.
type Limits struct {
	MaxFileBytes   int64
	MaxKeyBytes    int
	MaxHeaderBytes int
	MaxHeaders     int
}

// DefaultLimits comfortably fit any real entry. A cache key is a URL; a
// header block is a few kilobytes.
func DefaultLimits() Limits {
	return Limits{
		MaxFileBytes:   256 << 20, // 256 MiB
		MaxKeyBytes:    64 << 10,  // 64 KiB
		MaxHeaderBytes: 256 << 10, // 256 KiB
		MaxHeaders:     512,
	}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxFileBytes <= 0 {
		l.MaxFileBytes = d.MaxFileBytes
	}
	if l.MaxKeyBytes <= 0 {
		l.MaxKeyBytes = d.MaxKeyBytes
	}
	if l.MaxHeaderBytes <= 0 {
		l.MaxHeaderBytes = d.MaxHeaderBytes
	}
	if l.MaxHeaders <= 0 {
		l.MaxHeaders = d.MaxHeaders
	}
	return l
}

// Header is one HTTP response header recovered from a cache entry.
type Header struct {
	Name  string
	Value string
}

// Entry is one parsed cache entry.
//
// Fields that a format does not record are left zero. Nothing is
// substituted or inferred from another field.
type Entry struct {
	Format  Format
	Browser string
	// Version is the format's own version number, when it records one.
	Version uint32

	// Key is the cache key exactly as stored. For Chromium this may
	// carry partitioning prefixes; URL is the extracted resource URL.
	Key string
	URL string

	// RequestMethod is the HTTP method, recovered only from formats that
	// actually store one. Chromium's caches and Firefox cache2 do not
	// record it in the entry; Firefox cache1 does.
	RequestMethod string

	// StatusLine and Headers are recovered only when the entry actually
	// stores an HTTP response header block.
	StatusLine  string
	StatusCode  int
	Headers     []Header
	ContentType string
	// ContentLength is the value the RESPONSE declared. StoredBytes is
	// what the cache actually holds. They can legitimately differ.
	ContentLength    int64
	HasContentLength bool
	StoredBytes      int64

	// Timestamps. Zero means the format does not record that field --
	// never that it was zero on disk.
	LastFetched    time.Time
	LastModified   time.Time
	ExpirationTime time.Time
	FetchCount     uint32
	Frecency       uint32

	// EntryID identifies the entry within its cache (the on-disk name).
	EntryID string

	Warnings []string
}

// HasTimelineTimestamp reports whether this entry carries a timestamp
// the format genuinely recorded, and which may therefore be placed on a
// timeline.
func (e Entry) HasTimelineTimestamp() bool {
	return !e.LastFetched.IsZero() || !e.LastModified.IsZero()
}

// Host returns the hostname from the entry's URL, or "".
func (e Entry) Host() string { return hostFromURL(e.URL) }

// hostFromURL extracts a hostname without pulling in net/url's error
// paths for what is a bounded string operation on hostile input.
func hostFromURL(raw string) string {
	i := strings.Index(raw, "://")
	if i < 0 {
		return ""
	}
	rest := raw[i+3:]
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		rest = rest[:j]
	}
	// Strip credentials and port.
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		rest = rest[at+1:]
	}
	if strings.HasPrefix(rest, "[") { // IPv6 literal
		if end := strings.Index(rest, "]"); end >= 0 {
			return rest[:end+1]
		}
		return rest
	}
	if colon := strings.Index(rest, ":"); colon >= 0 {
		rest = rest[:colon]
	}
	return rest
}

// extractURL pulls the resource URL out of a cache key.
//
// Both formats wrap the URL in scheme-specific prefixes -- Chromium's
// partitioning keys ("1/0/", "_dk_https://a https://b ") and Firefox's
// tag prefixes ("a,", "O^partitionKey,") -- and those prefixes change
// between releases. Rather than enumerate them, the URL is located by
// its own scheme separator, which is stable across every variant.
//
// Returns "" when no scheme is present, rather than returning the raw
// key as if it were a URL.
func extractURL(key string) string {
	i := strings.Index(key, "://")
	if i < 0 {
		return ""
	}
	// Walk back to the start of the scheme.
	start := i
	for start > 0 {
		c := key[start-1]
		isSchemeChar := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.'
		if !isSchemeChar {
			break
		}
		start--
	}
	url := key[start:]
	// A double-keyed Chromium entry is "<top-frame-site> <resource-url>";
	// the resource is the LAST space-separated URL.
	if sp := strings.LastIndex(url, " "); sp >= 0 {
		if tail := url[sp+1:]; strings.Contains(tail, "://") {
			url = tail
		}
	}
	return strings.TrimSpace(url)
}

// safeString bounds and sanitizes a string taken from evidence.
//
// Invalid UTF-8 is replaced rather than propagated: these values reach
// JSON, the database and the UI, and a lone surrogate from a corrupt
// entry would fail to marshal or render as mojibake.
func safeString(b []byte, max int) string {
	if len(b) > max {
		b = b[:max]
	}
	s := string(b)
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	// Control characters have no place in a URL or header value.
	return strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' {
			return -1
		}
		return r
	}, s)
}

// parseHeaderBlock decodes a NUL-separated HTTP header block.
//
// Both Chromium and Firefox store response headers as the raw status
// line followed by "Name: value" entries, NUL-separated. The block is
// self-validating: it must begin with an HTTP status line, which is what
// makes locating it inside a larger structure safe rather than a guess.
func parseHeaderBlock(raw string, lim Limits) (statusLine string, code int, headers []Header) {
	parts := strings.Split(raw, "\x00")
	if len(parts) == 0 {
		return "", 0, nil
	}
	statusLine = strings.TrimSpace(parts[0])
	code = statusCodeOf(statusLine)
	for _, p := range parts[1:] {
		if len(headers) >= lim.MaxHeaders {
			break
		}
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		colon := strings.Index(p, ":")
		if colon <= 0 {
			continue
		}
		name := strings.TrimSpace(p[:colon])
		value := strings.TrimSpace(p[colon+1:])
		if name == "" {
			continue
		}
		// Credentials and session material are deliberately NOT retained.
		// A triage tool has no business copying a user's cookies or
		// bearer tokens into a case file, and the forensic question here
		// is what was cached, not who was signed in.
		if isSensitiveHeader(name) {
			headers = append(headers, Header{Name: name, Value: "[redacted by Tracefall: credential or session material]"})
			continue
		}
		headers = append(headers, Header{Name: name, Value: value})
	}
	return statusLine, code, headers
}

// isSensitiveHeader reports whether a header carries authentication or
// session material that must not be copied into a case.
func isSensitiveHeader(name string) bool {
	switch strings.ToLower(name) {
	case "cookie", "set-cookie", "set-cookie2", "authorization",
		"proxy-authorization", "www-authenticate", "proxy-authenticate":
		return true
	}
	return false
}

// statusCodeOf pulls the numeric code out of an HTTP status line.
func statusCodeOf(line string) int {
	if !strings.HasPrefix(line, "HTTP/") {
		return 0
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	code := 0
	for _, c := range fields[1] {
		if c < '0' || c > '9' {
			return 0
		}
		code = code*10 + int(c-'0')
		if code > 999 {
			return 0
		}
	}
	if code < 100 {
		return 0
	}
	return code
}

// headerValue returns the first value for name, case-insensitively.
func headerValue(headers []Header, name string) string {
	for _, h := range headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

// parseContentLength parses a Content-Length value, refusing anything
// that is not a plain non-negative integer.
func parseContentLength(v string) (int64, bool) {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > 19 {
		return 0, false
	}
	var n int64
	for _, c := range v {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int64(c-'0')
		if n < 0 {
			return 0, false
		}
	}
	return n, true
}

// normalizeContentType strips parameters from a Content-Type, keeping
// the media type for filtering.
func normalizeContentType(v string) string {
	if i := strings.Index(v, ";"); i >= 0 {
		v = v[:i]
	}
	return strings.ToLower(strings.TrimSpace(v))
}

// unixSeconds converts a cache2 timestamp, rejecting implausible values
// rather than returning a 1970 or year-2100 date.
func unixSeconds(v uint32) time.Time {
	if v == 0 {
		return time.Time{}
	}
	t := time.Unix(int64(v), 0).UTC()
	if t.Year() < 1995 || t.Year() > 2100 {
		return time.Time{}
	}
	return t
}

func warnf(format string, args ...any) string { return fmt.Sprintf(format, args...) }
