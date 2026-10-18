// Package browsercacheindex turns browser cache CONTAINER files into
// structured evidence.
//
// A container is the file that organizes a cache rather than one that
// holds an entry:
//
//	Chromium blockfile "index"  -- a header plus a hash table of
//	                               addresses into data_0..data_3.
//	Firefox cache1 "_CACHE_MAP_" -- a header plus fixed records
//	                               addressing _CACHE_00x_ blocks.
//
// # Why this is a separate parser, and separate evidence
//
// Neither file holds a cache key, so neither yields a URL. What they do
// hold is the cache's own metadata: how many entries it has, how large
// it is, whether it was shut down cleanly, and -- for the Chromium
// index -- when the cache was created.
//
// That is worth recording, and it is NOT a cache entry. Giving it the
// browser_cache artifact type would promise an analyst URLs the file
// does not contain; leaving it unclassified would report a perfectly
// readable structure as an unknown blob. It gets its own artifact type
// and produces structured evidence with no timeline events.
//
// # No timeline events
//
// A container records a state, not an activity. The Chromium index's
// creation time is the cache directory's, not a moment when anything
// was fetched, so it is recorded as a field rather than placed on a
// timeline where it would sit among events that describe requests.
package browsercacheindex

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	bc "tracefall/internal/browsercache"
	"tracefall/internal/model"
	"tracefall/internal/normalize"
	"tracefall/internal/parsers"
)

const parserName = "browsercacheindex@1"

// Parser implements parsers.ArtifactParser and parsers.ContentDetector.
type Parser struct {
	limits bc.Limits
}

func New() *Parser { return &Parser{limits: bc.DefaultLimits()} }

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactBrowserCacheIndex }

// Detect claims nothing by name.
//
// Both containers carry a header this parser can verify, so there is no
// reason to trust a filename -- and "index" is far too common a name to
// claim on sight.
func (Parser) Detect(string) bool { return false }

// DetectContent identifies a container by its header.
func (Parser) DetectContent(header []byte) bool {
	return bc.SniffChromiumBlockfileIndex(header) || bc.SniffFirefoxCache1Map(header)
}

// Parse reads one container file.
func (p Parser) Parse(absPath string) (parsers.ParseResult, error) {
	return p.ParseWithContext(absPath, parsers.ParseContext{})
}

// ParseWithContext uses the evidence-relative path for browser context.
func (p Parser) ParseWithContext(absPath string, ctx parsers.ParseContext) (parsers.ParseResult, error) {
	header, err := readHead(absPath)
	if err != nil {
		return parsers.ParseResult{}, err
	}
	switch {
	case bc.SniffChromiumBlockfileIndex(header):
		idx, err := bc.ParseChromiumBlockfileIndex(absPath, p.limits)
		if err != nil {
			return parsers.ParseResult{}, fmt.Errorf("browsercacheindex: %w", err)
		}
		return p.record(absPath, ctx.EvidencePath, bc.FormatChromiumBlockfileIndex, bc.BrowserChromium, map[string]any{
			"format_version":     idx.Version,
			"declared_entries":   idx.NumEntries,
			"declared_bytes":     idx.NumBytes,
			"hash_table_length":  idx.TableLen,
			"highest_data_file":  idx.LastFile,
			"cache_created":      timeOrNil(idx.CreateTime),
			"entry_records_live": "data_1 (256-byte blocks); this index holds addresses only",
			"warnings":           idx.Warnings,
		}), nil

	case bc.SniffFirefoxCache1Map(header):
		m, err := bc.ParseFirefoxCache1Map(absPath, p.limits)
		if err != nil {
			return parsers.ParseResult{}, fmt.Errorf("browsercacheindex: %w", err)
		}
		return p.record(absPath, ctx.EvidencePath, bc.FormatFirefoxCache1Map, bc.BrowserFirefox, map[string]any{
			"format_version":       m.Version,
			"declared_entries":     m.EntryCount,
			"declared_records":     m.RecordCount,
			"record_slots_present": m.Records,
			"declared_bytes":       m.DataSize,
			"shutdown_was_clean":   !m.IsDirty,
			"entry_records_live":   "_CACHE_001_ / _CACHE_002_ / _CACHE_003_; this map holds addresses only",
			"warnings":             m.Warnings,
		}), nil
	}
	return parsers.ParseResult{}, fmt.Errorf(
		"%w: this file is not a Chromium blockfile index or a Firefox cache1 _CACHE_MAP_",
		bc.ErrNotCacheEntry)
}

// record builds the single metadata record a container yields.
func (p Parser) record(absPath, evidencePath string, format bc.Format, browser string, fields map[string]any) parsers.ParseResult {
	fields["browser"] = browser
	fields["format"] = string(format)
	fields["format_name"] = format.Description()
	fields["format_generation"] = string(format.Generation())
	fields["source_file"] = filepath.Base(absPath)
	fields["contains_urls"] = false
	fields["evidence_meaning"] = "browser cache container metadata: this file describes a cache " +
		"(size, entry count, layout) and holds no cache keys, so it names no URL and records no request. " +
		"The cached resources themselves are in the accompanying block files."
	if profile := profileFromPath(evidencePath); profile != "" {
		fields["browser_profile"] = profile
	}
	if user := normalize.UserFromEvidencePath(evidencePath); user != "" {
		fields["user_profile_path"] = user
	}

	raw, _ := json.Marshal(fields)
	return parsers.ParseResult{
		// No events, deliberately: see the package comment.
		Raw: []model.RawEvidence{{
			SourceReference: "cache-container:" + string(format) + ":" + filepath.Base(absPath),
			Raw:             string(raw),
		}},
	}
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

// profileFromPath / userFromPath recover browser context from the
// collection path when it was preserved, exactly as the entry parser
// does. Neither is an identity claim: a path is a path.
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
