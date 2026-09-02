package browsercache

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// Firefox "cache1" -- the nsDiskCache format Firefox used until version
// 32 (2014), when cache2 replaced it.
//
// # Why it is worth reading
//
// It is the only way to read a cache from a pre-2014 system, and unlike
// every other format Tracefall reads it records an HTTP REQUEST METHOD
// alongside three real timestamps (last fetched, last modified,
// expiration) and a fetch count.
//
// # Layout
//
//	_CACHE_MAP_    a header plus fixed 16-byte records, each pointing at
//	               an entry's metadata and data. Holds hashes, not keys,
//	               so it yields no URLs. Read here as a CONTAINER.
//	_CACHE_001_    256-byte blocks
//	_CACHE_002_    1 KiB blocks
//	_CACHE_003_    4 KiB blocks
//
// Each block file opens with a 4096-byte allocation bitmap, after which
// blocks are numbered from zero. A metadata record (nsDiskCacheEntry) is
// a fixed 36-byte big-endian header, then the NUL-terminated key, then a
// block of NUL-separated name/value metadata elements.
//
// Everything in this format is BIG-endian, unlike cache2 and every
// Chromium format.
//
// # Detection
//
// _CACHE_MAP_ opens with a version word and is detected by content.
//
// The block files are the one exception to structural detection in this
// package: their first 4096 bytes are an allocation bitmap with no
// magic, no version, and no fixed shape, so nothing in the 512-byte
// sniff window identifies them. They are claimed by their format-defined
// canonical names -- Firefox writes exactly _CACHE_001_, _CACHE_002_ and
// _CACHE_003_, never anything else -- and then validated structurally
// while parsing. A file that carries the name but not the structure is
// reported as such rather than silently accepted.

const (
	// cache1BitmapSize is the allocation bitmap at the front of every
	// block file. Blocks are numbered from the end of it.
	cache1BitmapSize = 4096

	// cache1EntryHeader is the fixed part of nsDiskCacheEntry.
	cache1EntryHeader = 36

	// cache1MapHeader is the fixed part of nsDiskCacheHeader:
	// version, dataSize, entryCount, isDirty, recordCount, then
	// eviction ranks and bucket usage for 8 buckets each.
	cache1MapHeader = 20 + 32 + 32

	// cache1MapRecord is one nsDiskCacheRecord.
	cache1MapRecord = 16

	// cache1MinVersion / cache1MaxVersion bound the nsDiskCache versions
	// this build decodes. The layout above is stable across 1.x; a
	// version outside the range is REPORTED, never decoded with a layout
	// that may not apply.
	cache1MinVersion = uint32(0x00010000)
	cache1MaxVersion = uint32(0x0001FFFF)

	cache1MaxEntries = 1 << 16
)

// cache1BlockSizes maps a block file's number to its block size.
var cache1BlockSizes = map[int]int{1: 256, 2: 1024, 3: 4096}

// Cache1Map is a decoded _CACHE_MAP_ header.
//
// A container: it records how many entries the cache holds and how they
// are distributed, but the URLs live in the block files.
type Cache1Map struct {
	Version     uint32
	DataSize    int64
	EntryCount  int
	RecordCount int
	IsDirty     bool
	// Records is how many 16-byte records the file actually contains,
	// which can differ from the header's declared RecordCount when the
	// file was truncated.
	Records  int
	Warnings []string
}

// SniffFirefoxCache1Map reports whether header is a _CACHE_MAP_ file.
//
// The version word plus a header that fits is checked -- the file has no
// magic number, so accepting it on the version alone would claim any
// file that happens to open with those four bytes.
func SniffFirefoxCache1Map(header []byte) bool {
	if len(header) < cache1MapHeader {
		return false
	}
	v := binary.BigEndian.Uint32(header[0:4])
	if v < cache1MinVersion || v > cache1MaxVersion {
		return false
	}
	// A map file's record count is small and non-negative, and its
	// dirty flag is a boolean written as 0 or 1.
	if int32(binary.BigEndian.Uint32(header[16:20])) < 0 {
		return false
	}
	switch binary.BigEndian.Uint32(header[12:16]) {
	case 0, 1:
		return true
	}
	return false
}

// IsFirefoxCache1BlockName reports whether base is one of the three
// canonical cache1 block-file names.
//
// Exact names only: these are defined by the format, not guessed from a
// pattern. A file called _CACHE_004_ or _CACHE_001_.bak is not one.
func IsFirefoxCache1BlockName(base string) (int, bool) {
	switch strings.ToUpper(base) {
	case "_CACHE_001_":
		return 1, true
	case "_CACHE_002_":
		return 2, true
	case "_CACHE_003_":
		return 3, true
	}
	return 0, false
}

// IsFirefoxCache1MapName reports whether base is the canonical map name.
func IsFirefoxCache1MapName(base string) bool {
	return strings.EqualFold(base, "_CACHE_MAP_")
}

// IsFirefoxCache1 reports whether a file belongs to the legacy cache1
// format, by canonical name or by map-file content.
func IsFirefoxCache1(name string, header []byte) bool {
	base := fileBase(name)
	if _, ok := IsFirefoxCache1BlockName(base); ok {
		return true
	}
	if IsFirefoxCache1MapName(base) {
		return true
	}
	return SniffFirefoxCache1Map(header)
}

// ParseFirefoxCache1Map reads a _CACHE_MAP_ header.
func ParseFirefoxCache1Map(path string, lim Limits) (m Cache1Map, err error) {
	lim = lim.withDefaults()
	defer func() {
		if r := recover(); r != nil {
			m, err = Cache1Map{}, fmt.Errorf("%w: recovered from %v", ErrCorrupt, r)
		}
	}()

	data, err := readCapped(path, lim)
	if err != nil {
		return Cache1Map{}, err
	}
	if len(data) < cache1MapHeader {
		return Cache1Map{}, fmt.Errorf("%w: _CACHE_MAP_ is %d bytes, shorter than its own header", ErrCorrupt, len(data))
	}
	v := binary.BigEndian.Uint32(data[0:4])
	if v < cache1MinVersion || v > cache1MaxVersion {
		return Cache1Map{}, fmt.Errorf("%w: _CACHE_MAP_ declares version 0x%08x, which this build does not decode", ErrUnsupportedVersion, v)
	}

	m = Cache1Map{
		Version:     v,
		DataSize:    int64(binary.BigEndian.Uint32(data[4:8])),
		EntryCount:  int(int32(binary.BigEndian.Uint32(data[8:12]))),
		IsDirty:     binary.BigEndian.Uint32(data[12:16]) != 0,
		RecordCount: int(int32(binary.BigEndian.Uint32(data[16:20]))),
		Records:     (len(data) - cache1MapHeader) / cache1MapRecord,
	}
	if m.EntryCount < 0 {
		m.Warnings = append(m.Warnings, "the map declares a negative entry count; the header is damaged")
		m.EntryCount = 0
	}
	if m.RecordCount < 0 {
		m.Warnings = append(m.Warnings, "the map declares a negative record count; the header is damaged")
		m.RecordCount = 0
	}
	if m.RecordCount > m.Records {
		m.Warnings = append(m.Warnings, warnf(
			"the map declares %d records but the file holds room for %d; it is truncated",
			m.RecordCount, m.Records))
	}
	if m.IsDirty {
		m.Warnings = append(m.Warnings, "the cache was not shut down cleanly (dirty flag set); entry records may be stale")
	}
	return m, nil
}

// Cache1Scan is what one _CACHE_00x_ block file yielded.
type Cache1Scan struct {
	BlockFile     int
	BlockSize     int
	Entries       []Entry
	BlocksScanned int
	SkippedNoKey  int
	Warnings      []string
}

// ParseFirefoxCache1Block scans a _CACHE_00x_ block file for metadata
// records.
//
// Like the Chromium blockfile reader this scans the file's own blocks
// rather than following the map, so it needs no sibling file and still
// finds records the map no longer references.
func ParseFirefoxCache1Block(path string, blockFile int, lim Limits) (scan Cache1Scan, err error) {
	lim = lim.withDefaults()
	defer func() {
		if r := recover(); r != nil {
			scan, err = Cache1Scan{}, fmt.Errorf("%w: recovered from %v", ErrCorrupt, r)
		}
	}()

	blockSize, ok := cache1BlockSizes[blockFile]
	if !ok {
		return Cache1Scan{}, fmt.Errorf("%w: %d is not a cache1 block file number", ErrNotCacheEntry, blockFile)
	}
	data, err := readCapped(path, lim)
	if err != nil {
		return Cache1Scan{}, err
	}
	scan.BlockFile, scan.BlockSize = blockFile, blockSize

	if len(data) < cache1BitmapSize {
		return Cache1Scan{}, fmt.Errorf(
			"%w: a cache1 block file opens with a %d-byte allocation bitmap, but this file is only %d bytes",
			ErrCorrupt, cache1BitmapSize, len(data))
	}
	if len(data) == cache1BitmapSize {
		// Valid and empty: a freshly created block file. Not an error.
		scan.Warnings = append(scan.Warnings, "the block file holds its allocation bitmap and no blocks")
		return scan, nil
	}

	body := data[cache1BitmapSize:]
	total := len(body) / blockSize
	consumed := make([]bool, total)
	var sawAnyRecord bool

	for i := 0; i < total; i++ {
		if consumed[i] {
			continue
		}
		scan.BlocksScanned++
		// A record may span up to four contiguous blocks, so hand the
		// decoder everything from this block onward and let the declared
		// sizes bound it.
		rec := body[i*blockSize:]
		ent, size, ok := decodeCache1Entry(rec, lim)
		if !ok {
			continue
		}
		sawAnyRecord = true
		blocks := (size + blockSize - 1) / blockSize
		if blocks < 1 {
			blocks = 1
		}
		for b := i; b < i+blocks && b < total; b++ {
			consumed[b] = true
		}
		if ent.URL == "" {
			scan.SkippedNoKey++
			continue
		}
		if len(scan.Entries) >= cache1MaxEntries {
			scan.Warnings = append(scan.Warnings, warnf("stopped after %d entries", cache1MaxEntries))
			break
		}
		scan.Entries = append(scan.Entries, ent)
	}
	if !sawAnyRecord {
		// Structural validation for a file claimed by name: a real
		// _CACHE_00x_ with content holds at least one decodable record.
		scan.Warnings = append(scan.Warnings, warnf(
			"no cache1 metadata records were found in %d blocks; this file carries a cache1 block-file name "+
				"but holds no records this build can decode (it may hold only cached data blocks, "+
				"whose metadata lives in another _CACHE_00x_ file)", total))
	}
	return scan, nil
}

// decodeCache1Entry validates and decodes one nsDiskCacheEntry, returning
// the total bytes it occupies.
func decodeCache1Entry(rec []byte, lim Limits) (Entry, int, bool) {
	if len(rec) < cache1EntryHeader {
		return Entry{}, 0, false
	}
	version := binary.BigEndian.Uint32(rec[0:4])
	if version < cache1MinVersion || version > cache1MaxVersion {
		return Entry{}, 0, false
	}
	fetchCount := int32(binary.BigEndian.Uint32(rec[8:12]))
	lastFetched := binary.BigEndian.Uint32(rec[12:16])
	lastModified := binary.BigEndian.Uint32(rec[16:20])
	expiration := binary.BigEndian.Uint32(rec[20:24])
	dataSize := binary.BigEndian.Uint32(rec[24:28])
	keySize := binary.BigEndian.Uint32(rec[28:32])
	metaSize := binary.BigEndian.Uint32(rec[32:36])

	// Self-consistency. Every one of these is a rejection test, so an
	// arbitrary block of cached content cannot pass as a record.
	if fetchCount < 0 {
		return Entry{}, 0, false
	}
	if keySize == 0 || keySize > uint32(lim.MaxKeyBytes) {
		return Entry{}, 0, false
	}
	if metaSize > uint32(lim.MaxHeaderBytes) {
		return Entry{}, 0, false
	}
	if int64(dataSize) > lim.MaxFileBytes {
		return Entry{}, 0, false
	}
	total := cache1EntryHeader + int(keySize) + int(metaSize)
	if total > len(rec) {
		return Entry{}, 0, false
	}
	// The key is NUL-terminated and keySize includes the terminator.
	rawKey := rec[cache1EntryHeader : cache1EntryHeader+int(keySize)]
	if i := indexByte(rawKey, 0); i >= 0 {
		rawKey = rawKey[:i]
	}
	if len(rawKey) == 0 || !plausibleCacheKey(rawKey) {
		return Entry{}, 0, false
	}
	// At least one recorded time must be plausible; a record with none is
	// not accepted as an entry rather than emitted with invented times.
	fetched := unixSeconds(lastFetched)
	modified := unixSeconds(lastModified)
	if fetched.IsZero() && modified.IsZero() {
		return Entry{}, 0, false
	}

	e := Entry{
		Format:         FormatFirefoxCache1,
		Browser:        BrowserFirefox,
		Version:        version,
		Key:            safeString(rawKey, lim.MaxKeyBytes),
		LastFetched:    fetched,
		LastModified:   modified,
		ExpirationTime: cache1Expiration(expiration),
		StoredBytes:    int64(dataSize),
	}
	e.URL = extractURL(e.Key)
	if fetchCount > 0 {
		e.FetchCount = uint32(fetchCount)
	}
	// EntryID is the record's own location word, which the map uses to
	// address it -- stable, and unique within the cache.
	e.EntryID = fmt.Sprintf("%08x", binary.BigEndian.Uint32(rec[4:8]))

	if metaSize > 0 {
		start := cache1EntryHeader + int(keySize)
		applyCache1Elements(&e, rec[start:start+int(metaSize)], lim)
	}
	return e, total, true
}

// cache1Expiration converts an expiration word, treating the format's
// "never expires" sentinel as absent rather than as a date.
func cache1Expiration(v uint32) time.Time {
	if v == 0 || v == 0xFFFFFFFF {
		return time.Time{}
	}
	return unixSeconds(v)
}

// applyCache1Elements decodes the NUL-separated metadata element block.
//
// cache1 and cache2 store the same element vocabulary, so the response
// head is decoded by the same routine cache2 uses. request-method is
// handled here because cache1 is the only format Tracefall reads that
// records one.
func applyCache1Elements(e *Entry, elems []byte, lim Limits) {
	parts := strings.Split(string(elems), "\x00")
	for i := 0; i+1 < len(parts); i += 2 {
		name := strings.TrimSpace(parts[i])
		value := parts[i+1]
		if name == "" {
			continue
		}
		switch strings.ToLower(name) {
		case "request-method":
			e.RequestMethod = normalizeMethod(value)
		case "response-head":
			status, code, headers := parseResponseHead(value, lim)
			e.StatusLine, e.StatusCode = status, code
			e.Headers = append(e.Headers, headers...)
			e.ContentType = normalizeContentType(headerValue(e.Headers, "Content-Type"))
			if n, ok := parseContentLength(headerValue(e.Headers, "Content-Length")); ok {
				e.ContentLength, e.HasContentLength = n, true
			}
		case "original-response-headers":
			e.Headers = append(e.Headers, Header{
				Name: "cache1:" + name, Value: safeString([]byte(value), 512),
			})
		case "security-info", "charset", "uncompressed-len":
			e.Warnings = append(e.Warnings, warnf("metadata element %q is present but not decoded", name))
		}
	}
}

// normalizeMethod accepts only the HTTP methods a cache legitimately
// stores, so a corrupt element cannot put arbitrary text in a field an
// analyst will read as a method.
func normalizeMethod(v string) string {
	m := strings.ToUpper(strings.TrimSpace(v))
	switch m {
	case "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE", "CONNECT":
		return m
	}
	return ""
}
