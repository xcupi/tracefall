package browsercache

import (
	"encoding/binary"
	"strings"
)

// Structural recognition of browser-cache files this package does NOT
// parse.
//
// # Why a file in a cache directory is not automatically "broken"
//
// A browser cache is a small filesystem of its own. Alongside the entry
// records it holds rankings, payload blocks, indexes, journals, lock
// files and raw response bodies. Most of those are not parseable into
// forensic records and were never meant to be: their content is either
// bookkeeping for another file, or a payload whose metadata lives
// elsewhere.
//
// Reporting all of them with one message -- and one priority -- tells an
// analyst nothing. Worse, it invites the reading that Tracefall failed
// on them. This recognizes each one for what it is, so triage can say
// "auxiliary payload file, its metadata is in data_1" instead of "not
// supported".
//
// # Structure first
//
// Every recognition here is made from the file's own bytes. The only
// place a name is consulted is where the format itself defines an exact
// canonical filename AND writes no signature -- and even then the name
// is a corroborating input, never the sole basis. Names that merely look
// suggestive are not used at all; a file called "index" that is not a
// cache index is left unrecognized rather than mislabelled.

// Recognition names what an unparsed cache file actually is.
//
// These are recognition results, not parser outputs: nothing here is
// read into evidence. They exist so triage can explain a file instead of
// filing it under a single catch-all.
type Recognition string

const (
	// RecognizedNone means the bytes identified nothing.
	RecognizedNone Recognition = ""

	// RecognizedBlockfileRankings is the blockfile LRU rankings file,
	// normally data_0: 36-byte nodes carrying use times but no cache key.
	// A time that cannot be attributed to a resource is not evidence of
	// one, so it is recognized and not parsed.
	RecognizedBlockfileRankings Recognition = "chromium_blockfile_rankings"

	// RecognizedBlockfilePayload is a blockfile payload block file,
	// normally data_2 (1 KiB blocks) or data_3 (4 KiB). It stores stream
	// content; the metadata describing those streams is in the data_1
	// entry record that addresses them.
	RecognizedBlockfilePayload Recognition = "chromium_blockfile_payload"

	// RecognizedBlockfileVariant is a blockfile file whose header is
	// present but whose layout this build does not decode -- an
	// unexpected block size, or a header too short to trust.
	RecognizedBlockfileVariant Recognition = "chromium_blockfile_variant"

	// RecognizedSimpleCacheVariant is a Simple Cache entry whose magic is
	// present but whose header does not describe a usable entry.
	RecognizedSimpleCacheVariant Recognition = "chromium_simple_cache_variant"

	// RecognizedCache1Variant is a Firefox cache1 map whose canonical
	// name and header shape are present but whose version is outside the
	// range this build decodes.
	RecognizedCache1Variant Recognition = "firefox_cache1_variant"
)

// IsVariant reports whether a recognition means "this IS a browser cache
// structure of a kind Tracefall reads, in a version or state it does
// not". Those may still hold recoverable forensic data, which is why
// they are triaged differently from an auxiliary file that by design
// holds none.
func (r Recognition) IsVariant() bool {
	switch r {
	case RecognizedBlockfileVariant, RecognizedSimpleCacheVariant, RecognizedCache1Variant:
		return true
	}
	return false
}

// RecognizeUnparsed identifies a browser-cache file that no parser
// claimed, from the leading bytes discovery already read.
//
// base is the file's basename. It is used ONLY for the one format that
// defines an exact canonical filename and writes no signature in the
// sniff window, and only in addition to a structural check -- never on
// its own. Pass "" and every remaining recognition still works.
//
// Returns RecognizedNone when the bytes settle nothing, which is the
// signal to fall back to a generic classification rather than guess.
func RecognizeUnparsed(base string, header []byte) Recognition {
	if len(header) < 8 {
		return RecognizedNone
	}

	// ---- Chromium blockfile family: identified by magic ----
	switch binary.LittleEndian.Uint32(header[0:4]) {
	case blockfileDataMagic:
		if len(header) < 24 {
			// The magic is real but the header is too short to say what
			// the file holds. Recognized as blockfile, decoded no further.
			return RecognizedBlockfileVariant
		}
		switch int32(binary.LittleEndian.Uint32(header[12:16])) {
		case 36:
			return RecognizedBlockfileRankings
		case 1024, 4096:
			return RecognizedBlockfilePayload
		case 256:
			// A 256-byte block file is an entry file, which the parser
			// claims. Reaching here means it declared that block size but
			// failed the rest of the entry-file check.
			return RecognizedBlockfileVariant
		default:
			return RecognizedBlockfileVariant
		}
	case blockfileIndexMagic:
		// The index parser claims any header long enough to read. A file
		// carrying the magic that did not get claimed is truncated.
		return RecognizedBlockfileVariant
	}

	// ---- Chromium Simple Cache: magic present, entry not usable ----
	if len(header) >= 12 && binary.LittleEndian.Uint64(header[0:8]) == simpleInitialMagic {
		return RecognizedSimpleCacheVariant
	}

	// ---- Firefox cache1 map: canonical name AND header shape ----
	//
	// The map file carries no magic number, only a version word, so its
	// version being out of range cannot be distinguished from an
	// unrelated file by content alone. Recognition here therefore
	// requires BOTH the format's exact canonical filename and a header
	// whose remaining fields are structurally coherent. Either alone is
	// not enough.
	if IsFirefoxCache1MapName(base) && len(header) >= cache1MapHeader {
		if v := binary.BigEndian.Uint32(header[0:4]); v < cache1MinVersion || v > cache1MaxVersion {
			if int32(binary.BigEndian.Uint32(header[16:20])) >= 0 {
				return RecognizedCache1Variant
			}
		}
	}
	return RecognizedNone
}

// InCacheDirectory reports whether a forward-slash relative path lies
// inside a browser cache directory.
//
// This is a locator, not a classifier: it decides whether the
// cache-specific vocabulary applies at all, so that a file called
// "journal" somewhere else in a collection is never described as browser
// cache. What the file IS still comes from its bytes wherever possible.
func InCacheDirectory(lowerPath string) bool {
	for _, frag := range []string{
		"/cache/", "/cache2/", "/code cache/", "/gpucache/", "/cache_data/",
		"/index-dir/", "/dawncache/", "/shadercache/", "/service worker/cachestorage/",
	} {
		if strings.Contains(lowerPath, frag) {
			return true
		}
	}
	return false
}
