package browsercache

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
)

// Firefox "cache2" entry files (Firefox 32 and later).
//
// One file per entry under entries/, named for the SHA-1 of its key.
// Layout, with the metadata at the END:
//
//	[cached data]
//	[hash chunks]              one uint16 per 256 KiB chunk of data
//	[CacheFileMetadataHeader]  big-endian, see below
//	[key][NUL]
//	[elements]                 NUL-separated name/value pairs
//	[uint32 BE]                offset of the metadata, last 4 bytes
//
// The header is BIG-endian, unlike almost everything else Tracefall
// reads:
//
//	version, fetchCount, lastFetched, lastModified,
//	frecency, expirationTime, keySize, [flags: version >= 2]
//
// # Timestamps are real here
//
// Unlike Chromium's Simple Cache, cache2 records lastFetched and
// lastModified as Unix seconds in the entry itself. They are genuine
// recorded times, so these entries can legitimately appear on a
// timeline.

const (
	// firefoxChunkSize is the data chunk each hash covers.
	firefoxChunkSize = 256 * 1024
	// firefoxHeaderV1 is the header size before the flags field existed.
	firefoxHeaderV1 = 28
	// firefoxHeaderV2 adds mFlags.
	firefoxHeaderV2 = 32
	// firefoxMaxVersion is the highest cache2 metadata version this
	// build decodes. A higher one is REPORTED, never parsed with the
	// wrong layout.
	firefoxMaxVersion = 3
)

// SniffFirefoxCache2 reports whether data is a cache2 entry.
//
// cache2 has no magic number, so detection is structural: the trailing
// offset must point inside the file, the header there must declare a
// version this format uses, and the key size must fit. Requiring all
// three together is what keeps arbitrary files out.
func SniffFirefoxCache2(data []byte) bool {
	_, _, ok := firefoxMetadataAt(data)
	return ok
}

// firefoxMetadataAt locates and validates the metadata block.
func firefoxMetadataAt(data []byte) (metaOffset int, headerOffset int, ok bool) {
	if len(data) < 4+firefoxHeaderV1 {
		return 0, 0, false
	}
	metaOffset = int(binary.BigEndian.Uint32(data[len(data)-4:]))
	// The metadata must start inside the file and leave room for the
	// header plus the trailing offset itself.
	if metaOffset < 0 || metaOffset > len(data)-4-firefoxHeaderV1 {
		return 0, 0, false
	}
	// Data occupies [0, metaOffset); one 16-bit hash covers each chunk.
	chunks := (metaOffset + firefoxChunkSize - 1) / firefoxChunkSize
	headerOffset = metaOffset + chunks*2
	if headerOffset+firefoxHeaderV1 > len(data)-4 {
		return 0, 0, false
	}
	version := binary.BigEndian.Uint32(data[headerOffset : headerOffset+4])
	if version == 0 || version > 64 {
		return 0, 0, false
	}
	keySize := int(binary.BigEndian.Uint32(data[headerOffset+24 : headerOffset+28]))
	if keySize <= 0 || keySize > simpleMaxKeyLength {
		return 0, 0, false
	}
	hdrLen := firefoxHeaderV1
	if version >= 2 {
		hdrLen = firefoxHeaderV2
	}
	if headerOffset+hdrLen+keySize > len(data)-4 {
		return 0, 0, false
	}
	return metaOffset, headerOffset, true
}

// ParseFirefoxCache2 reads one cache2 entry file.
func ParseFirefoxCache2(path string, lim Limits) (entry Entry, err error) {
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
	return parseFirefoxCache2Bytes(data, fileBase(path), lim)
}

func parseFirefoxCache2Bytes(data []byte, entryID string, lim Limits) (Entry, error) {
	lim = lim.withDefaults()
	metaOffset, headerOffset, ok := firefoxMetadataAt(data)
	if !ok {
		return Entry{}, ErrNotCacheEntry
	}

	h := data[headerOffset:]
	version := binary.BigEndian.Uint32(h[0:4])
	e := Entry{
		Format:  FormatFirefoxCache2,
		Browser: BrowserFirefox,
		Version: version,
		EntryID: entryID,
		// Data occupies everything before the metadata.
		StoredBytes: int64(metaOffset),
	}
	if version > firefoxMaxVersion {
		// Refused rather than decoded with a layout that may have moved.
		// Silently treating an unknown generation as empty is exactly the
		// failure mode this avoids.
		return Entry{}, fmt.Errorf("%w: cache2 metadata version %d (this build decodes up to %d)",
			ErrUnsupportedVersion, version, firefoxMaxVersion)
	}

	e.FetchCount = binary.BigEndian.Uint32(h[4:8])
	e.LastFetched = unixSeconds(binary.BigEndian.Uint32(h[8:12]))
	e.LastModified = unixSeconds(binary.BigEndian.Uint32(h[12:16]))
	e.Frecency = binary.BigEndian.Uint32(h[16:20])
	e.ExpirationTime = unixSeconds(binary.BigEndian.Uint32(h[20:24]))
	keySize := int(binary.BigEndian.Uint32(h[24:28]))

	hdrLen := firefoxHeaderV1
	if version >= 2 {
		hdrLen = firefoxHeaderV2
	}
	if keySize <= 0 || keySize > lim.MaxKeyBytes {
		return Entry{}, fmt.Errorf("%w: declared key size %d", ErrCorrupt, keySize)
	}
	keyStart := headerOffset + hdrLen
	if keyStart+keySize > len(data)-4 {
		return Entry{}, fmt.Errorf("%w: the key runs past the end of the metadata", ErrCorrupt)
	}
	e.Key = safeString(data[keyStart:keyStart+keySize], lim.MaxKeyBytes)
	e.URL = extractURL(e.Key)
	if e.URL == "" {
		e.Warnings = append(e.Warnings, "the cache key carries no URL scheme; the key is reported as stored")
	}

	// Elements follow the key: NUL-separated name/value pairs. The
	// response header block is stored under "response-head".
	elemStart := keyStart + keySize
	if elemStart < len(data)-4 {
		elems := data[elemStart : len(data)-4]
		if len(elems) > lim.MaxHeaderBytes {
			elems = elems[:lim.MaxHeaderBytes]
			e.Warnings = append(e.Warnings, "the metadata element block was truncated at the size limit")
		}
		applyFirefoxElements(&e, elems, lim)
	}
	return e, nil
}

// applyFirefoxElements walks the NUL-separated element pairs.
func applyFirefoxElements(e *Entry, elems []byte, lim Limits) {
	parts := strings.Split(string(elems), "\x00")
	for i := 0; i+1 < len(parts); i += 2 {
		name := strings.TrimSpace(parts[i])
		value := parts[i+1]
		if name == "" {
			continue
		}
		switch strings.ToLower(name) {
		case "response-head":
			// The status line and headers, newline-separated here rather
			// than NUL-separated as Chromium stores them.
			status, code, headers := parseResponseHead(value, lim)
			e.StatusLine, e.StatusCode = status, code
			e.Headers = append(e.Headers, headers...)
			e.ContentType = normalizeContentType(headerValue(e.Headers, "Content-Type"))
			if n, ok := parseContentLength(headerValue(e.Headers, "Content-Length")); ok {
				e.ContentLength, e.HasContentLength = n, true
			}
		case "original-response-headers", "net-response-time-onstart", "net-response-time-onstop":
			// Recorded as context, bounded.
			e.Headers = append(e.Headers, Header{
				Name: "cache2:" + name, Value: safeString([]byte(value), 512),
			})
		case "security-info", "alt-data", "strongly-framed":
			// Present but not decoded; noted so the entry does not look
			// like it lacked them.
			e.Warnings = append(e.Warnings, warnf("metadata element %q is present but not decoded", name))
		}
	}
}

// parseResponseHead decodes Firefox's newline-separated response head.
func parseResponseHead(v string, lim Limits) (string, int, []Header) {
	v = strings.ReplaceAll(v, "\r\n", "\n")
	lines := strings.Split(v, "\n")
	if len(lines) == 0 {
		return "", 0, nil
	}
	status := strings.TrimSpace(lines[0])
	code := statusCodeOf(status)
	var headers []Header
	for _, line := range lines[1:] {
		if len(headers) >= lim.MaxHeaders {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		colon := strings.Index(line, ":")
		if colon <= 0 {
			continue
		}
		name := strings.TrimSpace(line[:colon])
		value := strings.TrimSpace(line[colon+1:])
		if name == "" {
			continue
		}
		if isSensitiveHeader(name) {
			headers = append(headers, Header{Name: name, Value: "[redacted by Tracefall: credential or session material]"})
			continue
		}
		headers = append(headers, Header{Name: name, Value: value})
	}
	return status, code, headers
}
