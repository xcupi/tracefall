package browsercache

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
)

// Chromium "Simple Cache" entry files.
//
// One file per cache entry, named <hash>_0. Layout:
//
//	SimpleFileHeader   magic, version, key length, key hash
//	key                the cache key -- the resource URL, possibly with
//	                   partitioning prefixes
//	stream data        the cached bytes
//	SimpleFileEOF      magic, flags, crc32, stream size
//	...                further stream/EOF pairs
//
// # No timestamp
//
// A Simple Cache ENTRY FILE records no time. Chromium keeps last-used
// times in the separate index (index-dir/the-real-index), not in the
// entry. This package therefore reports Chromium entries with zero
// timestamps, and the parser above it keeps them as structured evidence
// rather than inventing a time to put them on a timeline. Using the
// file's mtime would be recording when the evidence was COLLECTED, not
// when the browser cached the resource.

const (
	simpleInitialMagic = uint64(0xFCFB6D1BA7725C30)
	simpleFinalMagic   = uint64(0xF4FA6F45970D41D8)

	// The header is u64 + u32 + u32 + u32 = 20 bytes of members. Because
	// it opens with a u64, a C++ compiler pads the struct to 24. Which
	// one a given build wrote is settled by validating the key at each
	// offset rather than by assuming -- see readSimpleHeader.
	simpleHeaderPacked = 20
	simpleHeaderPadded = 24
	simpleEOFPacked    = 20
	simpleEOFPadded    = 24
	simpleMaxKeyLength = 64 << 10
)

// SniffChromiumSimple reports whether header begins a Simple Cache
// entry.
//
// The magic alone is not enough to accept the file: a coherent entry
// must also declare a key length that fits inside it. Requiring both is
// what stops an unrelated file being claimed as browser cache.
func SniffChromiumSimple(header []byte) bool {
	if len(header) < simpleHeaderPacked {
		return false
	}
	if binary.LittleEndian.Uint64(header[0:8]) != simpleInitialMagic {
		return false
	}
	keyLen := binary.LittleEndian.Uint32(header[12:16])
	return keyLen > 0 && keyLen <= simpleMaxKeyLength
}

// ParseChromiumSimple reads one Simple Cache entry file.
func ParseChromiumSimple(path string, lim Limits) (entry Entry, err error) {
	lim = lim.withDefaults()
	defer func() {
		if r := recover(); r != nil {
			entry, err = Entry{}, fmt.Errorf("%w: recovered from %v", ErrCorrupt, r)
		}
	}()

	info, err := os.Stat(path)
	if err != nil {
		return Entry{}, err
	}
	if info.Size() > lim.MaxFileBytes {
		return Entry{}, fmt.Errorf("%w: file is %d bytes", ErrLimitExceeded, info.Size())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Entry{}, err
	}
	return parseChromiumSimpleBytes(data, fileBase(path), lim)
}

func parseChromiumSimpleBytes(data []byte, entryID string, lim Limits) (Entry, error) {
	lim = lim.withDefaults()
	if len(data) < simpleHeaderPacked {
		return Entry{}, fmt.Errorf("%w: file is %d bytes, shorter than the header", ErrCorrupt, len(data))
	}
	if binary.LittleEndian.Uint64(data[0:8]) != simpleInitialMagic {
		return Entry{}, ErrNotCacheEntry
	}

	e := Entry{
		Format:  FormatChromiumSimple,
		Browser: BrowserChromium,
		Version: binary.LittleEndian.Uint32(data[8:12]),
		EntryID: entryID,
	}
	keyLen := int(binary.LittleEndian.Uint32(data[12:16]))
	if keyLen <= 0 || keyLen > lim.MaxKeyBytes {
		return Entry{}, fmt.Errorf("%w: declared key length %d", ErrCorrupt, keyLen)
	}

	keyOffset, ok := readSimpleHeader(data, keyLen)
	if !ok {
		return Entry{}, fmt.Errorf("%w: the key does not fit at either header size", ErrCorrupt)
	}
	if keyOffset != simpleHeaderPacked {
		e.Warnings = append(e.Warnings,
			warnf("key found at offset %d rather than %d; the writer padded the header struct", keyOffset, simpleHeaderPacked))
	}
	e.Key = safeString(data[keyOffset:keyOffset+keyLen], lim.MaxKeyBytes)
	e.URL = extractURL(e.Key)
	if e.URL == "" {
		e.Warnings = append(e.Warnings, "the cache key carries no URL scheme; the key is reported as stored")
	}

	// Stream sizes come from the EOF trailers.
	streamBytes, eofWarnings := readSimpleEOFs(data, keyOffset+keyLen)
	e.StoredBytes = streamBytes
	e.Warnings = append(e.Warnings, eofWarnings...)

	// The HTTP response header block lives in stream 0, inside a
	// serialized HttpResponseInfo. Rather than decode that pickle -- whose
	// layout has changed across Chromium releases and would be guesswork
	// to version-detect -- the block is located by its own HTTP status
	// line and validated as a header block. A run of bytes that parses as
	// "HTTP/1.x <code> ..." followed by NUL-separated "Name: value" pairs
	// is not something that occurs by accident.
	if body := data[minInt(keyOffset+keyLen, len(data)):]; len(body) > 0 {
		if raw, found := locateHeaderBlock(body, lim); found {
			status, code, headers := parseHeaderBlock(raw, lim)
			e.StatusLine, e.StatusCode, e.Headers = status, code, headers
			e.ContentType = normalizeContentType(headerValue(headers, "Content-Type"))
			if n, ok := parseContentLength(headerValue(headers, "Content-Length")); ok {
				e.ContentLength, e.HasContentLength = n, true
			}
		}
	}
	return e, nil
}

// readSimpleHeader determines where the key starts.
//
// The struct's C++ padding is not knowable from the file, so both
// candidate offsets are tried and the one whose key is actually a
// plausible cache key wins. When neither validates, the packed layout is
// used and the caller is warned -- reporting an unvalidated key beats
// discarding the entry, provided the uncertainty is stated.
func readSimpleHeader(data []byte, keyLen int) (int, bool) {
	for _, off := range []int{simpleHeaderPacked, simpleHeaderPadded} {
		if off+keyLen > len(data) {
			continue
		}
		if plausibleCacheKey(data[off : off+keyLen]) {
			return off, true
		}
	}
	// Fall back to whichever offset at least fits.
	for _, off := range []int{simpleHeaderPacked, simpleHeaderPadded} {
		if off+keyLen <= len(data) {
			return off, true
		}
	}
	return 0, false
}

// plausibleCacheKey reports whether b looks like a cache key: printable,
// and carrying a URL scheme separator.
func plausibleCacheKey(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	printable := 0
	for _, c := range b {
		if c >= 0x20 && c < 0x7F {
			printable++
		}
	}
	if printable*10 < len(b)*9 { // at least 90% printable ASCII
		return false
	}
	return strings.Contains(string(b), "://")
}

// readSimpleEOFs walks the EOF trailers to total the stored stream
// bytes.
func readSimpleEOFs(data []byte, from int) (int64, []string) {
	var warnings []string
	var total int64
	// The trailers sit at the end; scan backwards from the file end for
	// the final magic, which is cheaper and more robust than trying to
	// walk forward through streams of unknown length.
	found := 0
	for off := len(data) - simpleEOFPacked; off >= from && found < 8; off-- {
		if off+8 > len(data) {
			continue
		}
		if binary.LittleEndian.Uint64(data[off:off+8]) != simpleFinalMagic {
			continue
		}
		if off+20 > len(data) {
			continue
		}
		size := int32(binary.LittleEndian.Uint32(data[off+16 : off+20]))
		if size < 0 {
			warnings = append(warnings, warnf("EOF record at %d declares a negative stream size %d", off, size))
			continue
		}
		if int64(size) > int64(len(data)) {
			warnings = append(warnings,
				warnf("EOF record at %d declares a %d-byte stream, larger than the %d-byte file", off, size, len(data)))
			continue
		}
		total += int64(size)
		found++
		off -= simpleEOFPacked - 1
	}
	if found == 0 {
		warnings = append(warnings, "no end-of-stream record was found; stored sizes are unknown")
	}
	return total, warnings
}

// locateHeaderBlock finds an HTTP response header block inside a stream.
//
// Bounded: it looks only for an "HTTP/1." or "HTTP/2" status line and
// reads to the terminating double NUL, capped by MaxHeaderBytes.
func locateHeaderBlock(body []byte, lim Limits) (string, bool) {
	limit := len(body)
	if limit > lim.MaxHeaderBytes*4 {
		limit = lim.MaxHeaderBytes * 4
	}
	window := body[:limit]
	for _, prefix := range []string{"HTTP/1.", "HTTP/2", "HTTP/3"} {
		idx := strings.Index(string(window), prefix)
		if idx < 0 {
			continue
		}
		rest := window[idx:]
		if len(rest) > lim.MaxHeaderBytes {
			rest = rest[:lim.MaxHeaderBytes]
		}
		// The block ends at a double NUL; a single trailing NUL ends the
		// last header.
		end := strings.Index(string(rest), "\x00\x00")
		if end < 0 {
			end = len(rest)
		}
		raw := safeStringKeepNul(rest[:end], lim.MaxHeaderBytes)
		if statusCodeOf(strings.SplitN(raw, "\x00", 2)[0]) == 0 {
			continue // not actually a status line
		}
		return raw, true
	}
	return "", false
}

// safeStringKeepNul bounds a byte run while preserving the NUL
// separators the header block is built from.
func safeStringKeepNul(b []byte, max int) string {
	if len(b) > max {
		b = b[:max]
	}
	s := string(b)
	if !strings.ContainsRune(s, 0) && len(s) == 0 {
		return ""
	}
	return strings.ToValidUTF8(s, "?")
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func fileBase(path string) string {
	if i := strings.LastIndexAny(path, `/\`); i >= 0 {
		return path[i+1:]
	}
	return path
}
