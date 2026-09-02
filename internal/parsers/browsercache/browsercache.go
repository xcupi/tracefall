// Package browsercache turns browser HTTP cache entries into normalized
// evidence.
//
// # Cache is not history
//
// The single most important thing this parser does is refuse to blur two
// different claims. Browser HISTORY says a user navigated somewhere.
// Browser CACHE says the browser received and stored a response --
// usually a subresource (an image, a script, a tracking pixel) that
// nobody chose to load, often from a domain the user never typed.
//
// So cache entries get their own artifact type, their own event type,
// their own timeline category, and an explicit statement on every record
// that they are not evidence of user navigation. Nothing here replaces
// or supersedes a history entry for the same URL.
//
// # Timestamps, and the formats that have none
//
// Firefox cache2 records lastFetched and lastModified in the entry, so
// those entries become timeline events.
//
// A Chromium Simple Cache ENTRY FILE records no time at all -- Chromium
// keeps last-used times in a separate index. Those entries therefore
// produce NO timeline event and are kept as structured evidence
// instead. Using the file's mtime would record when the evidence was
// collected, not when the browser cached the resource.
//
// # Response bodies
//
// Not extracted. See internal/browsercache.
package browsercache

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	bc "tracefall/internal/browsercache"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

const parserName = "browsercache@1"

// Parser implements parsers.ArtifactParser and parsers.ContentDetector.
type Parser struct {
	limits bc.Limits
}

func New() *Parser { return &Parser{limits: bc.DefaultLimits()} }

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactBrowserCache }

// Detect matches exactly three filenames, and nothing else.
//
// Every other cache format this parser reads is identified structurally
// (see DetectContent), because entry files are named for a hash --
// "0a1b2c3d4e5f6789_0", "5F2A91C0" -- which is indistinguishable from
// any other opaque name. Matching a path fragment like "/Cache/" would
// classify every unrelated file sitting in a directory called Cache as a
// parseable cache entry.
//
// The exception is the Firefox cache1 block files. Their first 4096
// bytes are an allocation bitmap: no magic, no version, no fixed shape,
// so nothing in the 512-byte sniff window can identify them. Firefox
// writes exactly _CACHE_001_, _CACHE_002_ and _CACHE_003_ and never
// anything else, so those three exact names are treated as the format
// signature they effectively are -- and the structure is then validated
// while parsing, so a file wearing the name without the format is
// reported rather than accepted.
func (Parser) Detect(relPath string) bool {
	_, ok := bc.IsFirefoxCache1BlockName(pathBase(relPath))
	return ok
}

// DetectContent identifies an entry by the structure of the file.
//
// Both checks are strict about self-consistency: Chromium requires its
// magic AND a key length that fits, Firefox requires a trailing metadata
// offset that lands inside the file with a coherent header at it. That
// is what stops arbitrary files being claimed as browser cache.
func (Parser) DetectContent(header []byte) bool {
	return bc.SniffChromiumSimple(header) ||
		bc.SniffFirefoxCache2(header) ||
		bc.SniffChromiumBlockfileData(header)
}

// Parse reads one cache entry file.
func (p Parser) Parse(absPath string) (parsers.ParseResult, error) {
	// The sniff window discovery uses is only 512 bytes, and a Firefox
	// entry's metadata sits at the END of the file. Both formats are
	// therefore re-checked here against the whole file.
	data, err := os.ReadFile(absPath)
	if err != nil {
		return parsers.ParseResult{}, err
	}

	// Multi-entry formats first: one file, many entries, plus a report
	// of what the scan actually saw.
	base := pathBase(absPath)
	switch {
	case bc.SniffChromiumBlockfileData(data):
		scan, err := bc.ParseChromiumBlockfileData(absPath, p.limits)
		if err != nil {
			return parsers.ParseResult{}, fmt.Errorf("browsercache: %w", err)
		}
		return p.multiResult(scan.Entries, absPath, blockfileReport(scan)), nil
	case isCache1Block(base):
		n, _ := bc.IsFirefoxCache1BlockName(base)
		scan, err := bc.ParseFirefoxCache1Block(absPath, n, p.limits)
		if err != nil {
			return parsers.ParseResult{}, fmt.Errorf("browsercache: %w", err)
		}
		return p.multiResult(scan.Entries, absPath, cache1Report(scan)), nil
	}

	// Single-entry formats.
	var entry bc.Entry
	switch {
	case bc.SniffChromiumSimple(data):
		entry, err = bc.ParseChromiumSimple(absPath, p.limits)
	case bc.SniffFirefoxCache2(data):
		entry, err = bc.ParseFirefoxCache2(absPath, p.limits)
	case bc.SniffChromiumBlockfileIndex(data) || bc.SniffFirefoxCache1Map(data):
		// A container, which the browsercacheindex parser reads. Named
		// precisely rather than reported as a generic failure.
		return parsers.ParseResult{}, fmt.Errorf(
			"%w: this is a browser cache CONTAINER file (a blockfile index or a cache1 _CACHE_MAP_), "+
				"which records the cache's own metadata but holds no cache keys; the browsercacheindex parser "+
				"reads it, and the entries themselves live in the accompanying block files",
			bc.ErrNotCacheEntry)
	default:
		return parsers.ParseResult{}, bc.ErrNotCacheEntry
	}
	if err != nil {
		return parsers.ParseResult{}, fmt.Errorf("browsercache: %w", err)
	}

	return p.result(entry, absPath), nil
}

// isCache1Block reports whether base is a Firefox cache1 block file.
func isCache1Block(base string) bool {
	_, ok := bc.IsFirefoxCache1BlockName(base)
	return ok
}

// multiResult turns a whole-file scan into events plus one parse report.
//
// The report is emitted even when the scan found nothing. "This is a
// valid cache file holding no live entries" is a real forensic answer,
// and it must be distinguishable from "this file failed to parse" --
// which is why a zero-entry scan is a success with a record, not an
// error.
func (p Parser) multiResult(entries []bc.Entry, absPath string, report map[string]any) parsers.ParseResult {
	var out parsers.ParseResult
	for _, e := range entries {
		r := p.result(e, absPath)
		out.Events = append(out.Events, r.Events...)
		out.Raw = append(out.Raw, r.Raw...)
	}
	report["source_file"] = pathBase(absPath)
	report["entries_emitted"] = len(entries)
	report["body_extracted"] = false
	reportJSON, _ := json.Marshal(report)
	out.Raw = append(out.Raw, model.RawEvidence{
		SourceReference: "browsercache:parse-report",
		Raw:             string(reportJSON),
	})
	return out
}

// blockfileReport describes what a data_N scan saw.
func blockfileReport(scan bc.BlockfileScan) map[string]any {
	return map[string]any{
		"cache_format":        string(bc.FormatChromiumBlockfile),
		"format_version":      scan.Header.Version,
		"block_size":          scan.Header.EntrySize,
		"blocks_scanned":      scan.BlocksScanned,
		"header_entry_count":  scan.Header.NumEntries,
		"header_max_entries":  scan.Header.MaxEntries,
		"skipped_evicted":     scan.SkippedEvicted,
		"skipped_doomed":      scan.SkippedDoomed,
		"skipped_no_key":      scan.SkippedNoKey,
		"skipped_implausible": scan.SkippedImplausib,
		"warnings":            scan.Warnings,
	}
}

// cache1Report describes what a _CACHE_00x_ scan saw.
func cache1Report(scan bc.Cache1Scan) map[string]any {
	return map[string]any{
		"cache_format":   string(bc.FormatFirefoxCache1),
		"block_file":     scan.BlockFile,
		"block_size":     scan.BlockSize,
		"blocks_scanned": scan.BlocksScanned,
		"skipped_no_key": scan.SkippedNoKey,
		"warnings":       scan.Warnings,
	}
}

// pathBase is filepath.Base for both a relative slash path and an
// absolute OS path.
func pathBase(p string) string {
	return filepath.Base(filepath.FromSlash(p))
}

func (p Parser) result(e bc.Entry, absPath string) parsers.ParseResult {
	sourceName := filepath.Base(absPath)
	extra := map[string]string{
		"browser":              e.Browser,
		"cache_format":         string(e.Format),
		"cache_format_version": strconv.FormatUint(uint64(e.Version), 10),
		"cache_entry_id":       e.EntryID,
		"cache_key":            e.Key,
		"url":                  e.URL,
		"cache_source_file":    sourceName,
		"stored_bytes":         strconv.FormatInt(e.StoredBytes, 10),
		// Stated on EVERY record. An analyst scanning a timeline must not
		// be able to mistake a cached subresource for a visit.
		"evidence_meaning": "cached response: the browser received and stored this resource. " +
			"This is NOT evidence that the user navigated to it, viewed it, clicked it, downloaded it or ran it.",
		"artifact_class": "browser cache (response evidence)",
		// The exact format, its generation, and a readable name for it.
		// An analyst filtering evidence needs to be able to tell a
		// current cache from a superseded one -- a legacy cache on a
		// modern system is itself worth noticing -- without knowing
		// which magic number belongs to which Chromium release.
		"cache_generation":  string(e.Format.Generation()),
		"cache_format_name": e.Format.Description(),
	}
	if e.RequestMethod != "" {
		extra["http_method"] = e.RequestMethod
	}
	if host := e.Host(); host != "" {
		extra["host"] = host
	}
	if profile := profileFromPath(absPath); profile != "" {
		extra["browser_profile"] = profile
	}
	if user := userFromPath(absPath); user != "" {
		extra["user_profile_path"] = user
	}
	if e.StatusLine != "" {
		extra["http_status_line"] = e.StatusLine
	}
	if e.StatusCode != 0 {
		extra["http_status"] = strconv.Itoa(e.StatusCode)
	}
	if e.ContentType != "" {
		extra["content_type"] = e.ContentType
	}
	if e.HasContentLength {
		extra["content_length"] = strconv.FormatInt(e.ContentLength, 10)
	}
	if e.FetchCount > 0 {
		extra["fetch_count"] = strconv.FormatUint(uint64(e.FetchCount), 10)
	}
	if e.Frecency > 0 {
		extra["frecency"] = strconv.FormatUint(uint64(e.Frecency), 10)
	}
	if !e.LastModified.IsZero() {
		extra["cache_last_modified"] = e.LastModified.UTC().Format("2006-01-02T15:04:05Z")
	}
	if !e.ExpirationTime.IsZero() {
		extra["cache_expires"] = e.ExpirationTime.UTC().Format("2006-01-02T15:04:05Z")
	}
	if n := len(e.Headers); n > 0 {
		extra["response_header_count"] = strconv.Itoa(n)
		extra["response_headers"] = summarizeHeaders(e.Headers, 800)
	}
	if len(e.Warnings) > 0 {
		extra["parse_warnings"] = strings.Join(e.Warnings, "; ")
	}
	// Body extraction is not implemented; say so on the record rather
	// than leaving its absence to be inferred.
	extra["cached_body"] = "not extracted (Tracefall reads cache metadata only)"

	// The reference must be unique within the file: a multi-entry
	// blockfile or cache1 block file yields many records, and the import
	// pairs each event with its raw record by this string.
	ref := "cache:" + string(e.Format) + ":" + e.EntryID
	if e.URL != "" {
		ref += ":" + truncate(e.URL, 180)
	}

	raw, _ := json.Marshal(map[string]any{
		"browser":           e.Browser,
		"format":            string(e.Format),
		"format_name":       e.Format.Description(),
		"format_generation": string(e.Format.Generation()),
		"format_version":    e.Version,
		"entry_id":          e.EntryID,
		"cache_key":         e.Key,
		"url":               e.URL,
		"host":              e.Host(),
		"http_method":       methodOrNil(e),
		"http_status_line":  e.StatusLine,
		"http_status":       e.StatusCode,
		"content_type":      e.ContentType,
		"content_length":    contentLengthOrNil(e),
		"stored_bytes":      e.StoredBytes,
		"fetch_count":       e.FetchCount,
		"frecency":          e.Frecency,
		"last_fetched":      timeOrNil(e.LastFetched),
		"last_modified":     timeOrNil(e.LastModified),
		"expiration_time":   timeOrNil(e.ExpirationTime),
		"response_headers":  headerPairs(e.Headers),
		"body_extracted":    false,
		"warnings":          e.Warnings,
		"evidence_meaning":  "cached response evidence; not proof of user navigation",
	})

	res := parsers.ParseResult{}
	// A timeline event only where the format ACTUALLY records a time.
	if e.HasTimelineTimestamp() {
		at := e.LastFetched
		source := "cache2 lastFetched (when the browser last fetched this resource)"
		if at.IsZero() {
			at = e.LastModified
			source = "cache2 lastModified (when the cache entry was last modified)"
		}
		evExtra := make(map[string]string, len(extra)+1)
		for k, v := range extra {
			evExtra[k] = v
		}
		evExtra["timestamp_source"] = source
		res.Events = append(res.Events, model.Event{
			Timestamp:    at.UTC(),
			EventType:    model.EventBrowserCacheEntry,
			ArtifactType: model.ArtifactBrowserCache,
			Parser:       parserName,
			FilePath:     sourceName,
			// NetworkDest carries the cached host so cache entries join
			// the network category for correlation, exactly as browser
			// history and Sysmon DNS events already do. It does NOT imply
			// the user initiated the request.
			NetworkDest: e.Host(),
			// No User and no ProcessName. A cache entry names neither the
			// account that was signed in nor the process that fetched it,
			// and deriving either from a path would be a guess.
			//
			// 0.7, below browser history's 1.0: the observation itself is
			// solid, but what it proves about user activity is weaker
			// than a recorded navigation.
			Confidence:      0.7,
			SourceReference: ref,
			Extra:           evExtra,
		})
		res.Raw = append(res.Raw, model.RawEvidence{SourceReference: ref, Raw: string(raw)})
		return res
	}

	// No recorded time: structured evidence only, never a fabricated
	// timeline entry.
	res.Raw = append(res.Raw, model.RawEvidence{
		SourceReference: ref + ":metadata",
		Raw:             string(raw),
	})
	return res
}

// methodOrNil keeps an unrecorded HTTP method out of the record as null
// rather than as an empty string that could read as "no method used".
func methodOrNil(e bc.Entry) any {
	if e.RequestMethod == "" {
		return nil
	}
	return e.RequestMethod
}

func contentLengthOrNil(e bc.Entry) any {
	if !e.HasContentLength {
		return nil
	}
	return e.ContentLength
}

func timeOrNil(t interface{ IsZero() bool }) any {
	type formatter interface{ Format(string) string }
	if t.IsZero() {
		return nil
	}
	if f, ok := t.(formatter); ok {
		return f.Format("2006-01-02T15:04:05Z")
	}
	return nil
}

func headerPairs(headers []bc.Header) []map[string]string {
	out := make([]map[string]string, 0, len(headers))
	for _, h := range headers {
		out = append(out, map[string]string{"name": h.Name, "value": h.Value})
	}
	return out
}

func summarizeHeaders(headers []bc.Header, max int) string {
	var b strings.Builder
	for i, h := range headers {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(h.Name)
		b.WriteString(": ")
		b.WriteString(h.Value)
		if b.Len() > max {
			return b.String()[:max] + "..."
		}
	}
	return b.String()
}

// profileFromPath recovers the browser profile directory from the path,
// when the collection preserved it.
func profileFromPath(path string) string {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for i := len(parts) - 1; i >= 0; i-- {
		p := parts[i]
		if strings.EqualFold(p, "Default") || strings.HasPrefix(p, "Profile ") ||
			strings.HasSuffix(p, ".default") || strings.HasSuffix(p, ".default-release") {
			return p
		}
	}
	return ""
}

// userFromPath recovers the user directory, when present.
func userFromPath(path string) string {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for i, p := range parts {
		if (strings.EqualFold(p, "Users") || strings.EqualFold(p, "home")) && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
