// Package cachegen builds synthetic browser cache entries in memory,
// for TEST FIXTURES ONLY.
//
// A real cache holds the URLs a real person browsed, so one cannot be
// committed. This emits the same on-disk structures the browsers write
// -- Simple Cache headers and EOF trailers, cache2 trailing metadata
// with its big-endian header -- because a fixture that skipped them
// would not exercise the reader that has to handle them.
//
// It lives outside internal/browsercache so no production code can
// import a cache writer by accident.
package cachegen

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	simpleInitialMagic = uint64(0xFCFB6D1BA7725C30)
	simpleFinalMagic   = uint64(0xF4FA6F45970D41D8)
	firefoxChunkSize   = 256 * 1024
)

// ChromiumEntry describes a Simple Cache entry to build.
type ChromiumEntry struct {
	// Version defaults to 5, the current Simple Cache version.
	Version uint32
	// Key is the cache key. Real keys carry partitioning prefixes; pass
	// them here to exercise URL extraction.
	Key string
	// StatusLine and Headers form the response header block. Empty means
	// no block is written, as for an entry whose metadata was evicted.
	StatusLine string
	Headers    []string
	// Body is the cached stream content.
	Body []byte
	// PadHeader writes the 24-byte padded SimpleFileHeader instead of the
	// 20-byte packed one, as a C++ build with struct padding would.
	PadHeader bool
	// OmitEOF leaves out the trailing end-of-stream record.
	OmitEOF bool
}

// BuildChromiumSimple assembles one Simple Cache entry file.
func BuildChromiumSimple(e ChromiumEntry) []byte {
	version := e.Version
	if version == 0 {
		version = 5
	}
	headerLen := 20
	if e.PadHeader {
		headerLen = 24
	}
	out := make([]byte, headerLen)
	binary.LittleEndian.PutUint64(out[0:8], simpleInitialMagic)
	binary.LittleEndian.PutUint32(out[8:12], version)
	binary.LittleEndian.PutUint32(out[12:16], uint32(len(e.Key)))
	binary.LittleEndian.PutUint32(out[16:20], 0xDEADBEEF) // key hash
	out = append(out, []byte(e.Key)...)

	// Stream 1: the body.
	out = append(out, e.Body...)

	// Stream 0: the serialized response info. Real Chromium wraps this in
	// a Pickle; the reader locates the header block by its own status
	// line rather than decoding the pickle, so the fixture writes a
	// plausible pickle-ish prefix followed by the real block.
	if e.StatusLine != "" {
		var meta []byte
		meta = append(meta, 0x01, 0x00, 0x00, 0x00) // flags word
		meta = append(meta, make([]byte, 16)...)    // request/response times
		block := e.StatusLine
		for _, h := range e.Headers {
			block += "\x00" + h
		}
		block += "\x00\x00"
		meta = append(meta, []byte(block)...)
		out = append(out, meta...)
	}

	if !e.OmitEOF {
		out = append(out, buildEOF(int32(len(e.Body)))...)
	}
	return out
}

func buildEOF(streamSize int32) []byte {
	eof := make([]byte, 20)
	binary.LittleEndian.PutUint64(eof[0:8], simpleFinalMagic)
	binary.LittleEndian.PutUint32(eof[8:12], 1) // FLAG_HAS_CRC32
	binary.LittleEndian.PutUint32(eof[12:16], 0x12345678)
	binary.LittleEndian.PutUint32(eof[16:20], uint32(streamSize))
	return eof
}

// FirefoxEntry describes a cache2 entry to build.
type FirefoxEntry struct {
	// Version defaults to 2 (the flags-bearing header).
	Version        uint32
	Key            string
	FetchCount     uint32
	LastFetched    uint32
	LastModified   uint32
	Frecency       uint32
	ExpirationTime uint32
	// ResponseHead is the newline-separated status line and headers.
	ResponseHead string
	// Elements are extra NUL-separated name/value pairs.
	Elements []string
	Body     []byte
}

// BuildFirefoxCache2 assembles one cache2 entry file.
func BuildFirefoxCache2(e FirefoxEntry) []byte {
	version := e.Version
	if version == 0 {
		version = 2
	}
	out := append([]byte(nil), e.Body...)
	metaOffset := len(out)

	// One 16-bit hash per 256 KiB chunk of data.
	chunks := (metaOffset + firefoxChunkSize - 1) / firefoxChunkSize
	for i := 0; i < chunks; i++ {
		out = append(out, 0xAB, 0xCD)
	}

	hdrLen := 28
	if version >= 2 {
		hdrLen = 32
	}
	hdr := make([]byte, hdrLen)
	binary.BigEndian.PutUint32(hdr[0:4], version)
	binary.BigEndian.PutUint32(hdr[4:8], e.FetchCount)
	binary.BigEndian.PutUint32(hdr[8:12], e.LastFetched)
	binary.BigEndian.PutUint32(hdr[12:16], e.LastModified)
	binary.BigEndian.PutUint32(hdr[16:20], e.Frecency)
	binary.BigEndian.PutUint32(hdr[20:24], e.ExpirationTime)
	binary.BigEndian.PutUint32(hdr[24:28], uint32(len(e.Key)))
	if version >= 2 {
		binary.BigEndian.PutUint32(hdr[28:32], 0)
	}
	out = append(out, hdr...)
	out = append(out, []byte(e.Key)...)

	var elems []string
	if e.ResponseHead != "" {
		elems = append(elems, "response-head", e.ResponseHead)
	}
	elems = append(elems, e.Elements...)
	if len(elems) > 0 {
		out = append(out, []byte(strings.Join(elems, "\x00")+"\x00")...)
	}

	tail := make([]byte, 4)
	binary.BigEndian.PutUint32(tail, uint32(metaOffset))
	return append(out, tail...)
}

// ChromiumBlockfileIndex builds a LEGACY blockfile index header, for
// testing that it is detected and refused rather than parsed.
func ChromiumBlockfileIndex() []byte {
	out := make([]byte, 256)
	binary.LittleEndian.PutUint32(out[0:4], 0xC103CAC3)
	binary.LittleEndian.PutUint32(out[4:8], 0x00020001)
	return out
}

// CorruptChromium damages a Simple Cache entry.
func CorruptChromium(data []byte, how string) []byte {
	out := append([]byte(nil), data...)
	if len(out) < 24 {
		return out
	}
	switch how {
	case "magic":
		binary.LittleEndian.PutUint64(out[0:8], 0)
	case "huge-key":
		binary.LittleEndian.PutUint32(out[12:16], 0x7FFFFFFF)
	case "zero-key":
		binary.LittleEndian.PutUint32(out[12:16], 0)
	case "key-past-end":
		binary.LittleEndian.PutUint32(out[12:16], uint32(len(out)+1000))
	case "eof-negative-size":
		for off := len(out) - 20; off >= 0; off-- {
			if binary.LittleEndian.Uint64(out[off:off+8]) == simpleFinalMagic {
				binary.LittleEndian.PutUint32(out[off+16:off+20], 0xFFFFFFFF)
				break
			}
		}
	}
	return out
}

// CorruptFirefox damages a cache2 entry.
func CorruptFirefox(data []byte, how string) []byte {
	out := append([]byte(nil), data...)
	if len(out) < 8 {
		return out
	}
	switch how {
	case "offset-past-end":
		binary.BigEndian.PutUint32(out[len(out)-4:], uint32(len(out)+9999))
	case "offset-negative":
		binary.BigEndian.PutUint32(out[len(out)-4:], 0xFFFFFFFF)
	case "huge-key":
		if mo := int(binary.BigEndian.Uint32(out[len(out)-4:])); mo+28 < len(out) {
			binary.BigEndian.PutUint32(out[mo+24:mo+28], 0x7FFFFFFF)
		}
	case "future-version":
		if mo := int(binary.BigEndian.Uint32(out[len(out)-4:])); mo+4 < len(out) {
			binary.BigEndian.PutUint32(out[mo:mo+4], 99)
		}
	}
	return out
}

// ChromiumURL builds a realistic partitioned cache key.
func ChromiumURL(topFrame, resource string) string {
	if topFrame == "" {
		return resource
	}
	return fmt.Sprintf("_dk_%s %s %s", topFrame, topFrame, resource)
}

// ---------------- Chromium blockfile cache ----------------
//
// The legacy disk_cache format: an index file of addresses plus block
// files holding fixed-size records. Written here exactly as Chromium
// lays it out, because a fixture that skipped the 8192-byte header or
// the address encoding would not exercise the reader that must handle
// them.

const (
	blockfileIndexMagic = uint32(0xC103CAC3)
	blockfileDataMagic  = uint32(0xC104CAC3)
	blockfileHeaderSize = 8192
	// windowsEpochOffsetMicros converts Unix microseconds to the
	// base::Time internal value Chromium stores: microseconds since
	// 1601-01-01 UTC.
	windowsEpochOffsetMicros = int64(11644473600) * 1000000
)

// BlockfileIndexOptions describes an index file to build.
type BlockfileIndexOptions struct {
	// Version defaults to 0x30000 (3.0).
	Version uint32
	// NumEntries / NumBytes are what the header declares the cache holds.
	NumEntries int32
	NumBytes   int32
	LastFile   int32
	TableLen   int32
	// CreateTimeUnix is the cache's creation time. Zero writes zero,
	// which the reader must treat as "not recorded".
	CreateTimeUnix int64
	// TableEntries are hash-table address words written after the header.
	TableEntries []uint32
}

// BuildChromiumBlockfileIndex assembles a blockfile index file.
func BuildChromiumBlockfileIndex(o BlockfileIndexOptions) []byte {
	version := o.Version
	if version == 0 {
		version = 0x30000
	}
	// sizeof(IndexHeader) is 368: 48 bytes of fields, 208 of padding,
	// then a 112-byte LruData.
	out := make([]byte, 368+len(o.TableEntries)*4)
	binary.LittleEndian.PutUint32(out[0:4], blockfileIndexMagic)
	binary.LittleEndian.PutUint32(out[4:8], version)
	binary.LittleEndian.PutUint32(out[8:12], uint32(o.NumEntries))
	binary.LittleEndian.PutUint32(out[12:16], uint32(o.NumBytes))
	binary.LittleEndian.PutUint32(out[16:20], uint32(o.LastFile))
	binary.LittleEndian.PutUint32(out[28:32], uint32(o.TableLen))
	if o.CreateTimeUnix != 0 {
		binary.LittleEndian.PutUint64(out[40:48], uint64(o.CreateTimeUnix*1000000+windowsEpochOffsetMicros))
	}
	for i, a := range o.TableEntries {
		binary.LittleEndian.PutUint32(out[368+i*4:372+i*4], a)
	}
	return out
}

// BlockfileEntry describes one EntryStore record to build.
type BlockfileEntry struct {
	// Key is the cache key; real Chromium keys are the URL, sometimes
	// with a partitioning prefix.
	Key string
	// CreationUnix is the entry's creation time in Unix seconds. Zero
	// writes zero, which the reader must reject rather than emit.
	CreationUnix int64
	ReuseCount   int32
	RefetchCount int32
	// State is 0 normal, 1 evicted, 2 doomed.
	State int32
	// StatusLine and Headers become the stream-0 HTTP response block.
	// Empty writes no stream 0.
	StatusLine string
	Headers    []string
	// BodySize is the size declared for stream 1 (the response body).
	BodySize int32
	// ExternalBody addresses stream 1 in an f_###### file instead of a
	// block, as Chromium does for large responses.
	ExternalBody bool
	// LongKey stores the key outside the record, as Chromium does for
	// keys too long to fit inline. The reader must then report that the
	// URL is not recoverable rather than invent one.
	LongKey bool
}

// BuildChromiumBlockfileData assembles a 256-byte-block data file
// (data_1) holding the given entries, each with its stream-0 header
// block allocated in the same file.
func BuildChromiumBlockfileData(entries []BlockfileEntry) []byte {
	const blockSize = 256
	// Lay out the block area first, then prepend the header.
	var blocks []byte
	allocBlock := func(n int) int {
		start := len(blocks) / blockSize
		blocks = append(blocks, make([]byte, n*blockSize)...)
		return start
	}

	type pending struct {
		entryBlock int
		e          BlockfileEntry
		headerAddr uint32
	}
	var pend []pending

	for _, e := range entries {
		// Stream 0: the NUL-separated response header block.
		var headerAddr uint32
		if e.StatusLine != "" {
			blob := e.StatusLine + "\x00" + strings.Join(e.Headers, "\x00") + "\x00\x00"
			need := (len(blob) + blockSize - 1) / blockSize
			if need > 4 {
				need = 4
			}
			start := allocBlock(need)
			copy(blocks[start*blockSize:], blob)
			// type 2 (256-byte blocks), file selector 1, initialized.
			headerAddr = 0x80000000 | (2 << 28) | (uint32(need-1) << 24) | (1 << 16) | uint32(start)
		}

		keyLen := len(e.Key) + 1
		recordBytes := 96 + keyLen
		if e.LongKey {
			// The key does not fit inline; only the fixed part is
			// written and long_key points elsewhere.
			recordBytes = 96
		}
		need := (recordBytes + blockSize - 1) / blockSize
		if need > 4 {
			need = 4
		}
		start := allocBlock(need)
		pend = append(pend, pending{entryBlock: start, e: e, headerAddr: headerAddr})
	}

	for _, p := range pend {
		rec := blocks[p.entryBlock*blockSize:]
		e := p.e
		binary.LittleEndian.PutUint32(rec[0:4], hashKey(e.Key))
		binary.LittleEndian.PutUint32(rec[12:16], uint32(e.ReuseCount))
		binary.LittleEndian.PutUint32(rec[16:20], uint32(e.RefetchCount))
		binary.LittleEndian.PutUint32(rec[20:24], uint32(e.State))
		if e.CreationUnix != 0 {
			binary.LittleEndian.PutUint64(rec[24:32], uint64(e.CreationUnix*1000000+windowsEpochOffsetMicros))
		}
		if e.LongKey {
			// A key length beyond the inline area, stored at long_key.
			binary.LittleEndian.PutUint32(rec[32:36], uint32(len(e.Key)+1))
			if len(e.Key)+1 <= 928 {
				binary.LittleEndian.PutUint32(rec[32:36], 929)
			}
			binary.LittleEndian.PutUint32(rec[36:40], 0x80000000|(3<<28)|1)
		} else {
			binary.LittleEndian.PutUint32(rec[32:36], uint32(len(e.Key)+1))
			copy(rec[96:], e.Key)
		}
		// Stream 0: response headers. Stream 1: the body.
		if p.headerAddr != 0 {
			blob := e.StatusLine + "\x00" + strings.Join(e.Headers, "\x00") + "\x00\x00"
			binary.LittleEndian.PutUint32(rec[40:44], uint32(len(blob)))
			binary.LittleEndian.PutUint32(rec[56:60], p.headerAddr)
		}
		if e.BodySize != 0 {
			binary.LittleEndian.PutUint32(rec[44:48], uint32(e.BodySize))
			if e.ExternalBody {
				binary.LittleEndian.PutUint32(rec[60:64], 0x80000000|0x000000a5) // f_0000a5
			} else {
				binary.LittleEndian.PutUint32(rec[60:64], 0x80000000|(3<<28)|(1<<16)|7)
			}
		}
		binary.LittleEndian.PutUint32(rec[92:96], hashKey(e.Key)^0x5A5A5A5A) // self_hash
	}

	out := make([]byte, blockfileHeaderSize)
	binary.LittleEndian.PutUint32(out[0:4], blockfileDataMagic)
	binary.LittleEndian.PutUint32(out[4:8], 0x30000)
	binary.LittleEndian.PutUint16(out[8:10], 1)    // this_file: data_1
	binary.LittleEndian.PutUint32(out[12:16], 256) // entry_size
	binary.LittleEndian.PutUint32(out[16:20], uint32(len(entries)))
	binary.LittleEndian.PutUint32(out[20:24], uint32(len(blocks)/blockSize))
	return append(out, blocks...)
}

// BuildChromiumBlockfileDataSized builds an otherwise valid block file
// declaring a block size other than 256 -- data_2 (1 KiB) and data_3
// (4 KiB) hold stream payloads, not entry records.
func BuildChromiumBlockfileDataSized(blockSize int, blocks int) []byte {
	out := make([]byte, blockfileHeaderSize+blockSize*blocks)
	binary.LittleEndian.PutUint32(out[0:4], blockfileDataMagic)
	binary.LittleEndian.PutUint32(out[4:8], 0x30000)
	binary.LittleEndian.PutUint32(out[12:16], uint32(blockSize))
	binary.LittleEndian.PutUint32(out[20:24], uint32(blocks))
	return out
}

func hashKey(s string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	if h == 0 {
		h = 1
	}
	return h
}

// ---------------- Firefox cache1 ----------------
//
// Everything in this format is BIG-endian, unlike cache2.

const (
	cache1BitmapSize  = 4096
	cache1EntryHeader = 36
	cache1MapHeader   = 84
)

// Cache1MapOptions describes a _CACHE_MAP_ file to build.
type Cache1MapOptions struct {
	// Version defaults to 0x00010013, the last nsDiskCache version.
	Version     uint32
	DataSize    uint32
	EntryCount  int32
	RecordCount int32
	IsDirty     bool
	// Records is how many 16-byte record slots to write.
	Records int
}

// BuildFirefoxCache1Map assembles a _CACHE_MAP_ file.
func BuildFirefoxCache1Map(o Cache1MapOptions) []byte {
	version := o.Version
	if version == 0 {
		version = 0x00010013
	}
	out := make([]byte, cache1MapHeader+o.Records*16)
	binary.BigEndian.PutUint32(out[0:4], version)
	binary.BigEndian.PutUint32(out[4:8], o.DataSize)
	binary.BigEndian.PutUint32(out[8:12], uint32(o.EntryCount))
	if o.IsDirty {
		binary.BigEndian.PutUint32(out[12:16], 1)
	}
	binary.BigEndian.PutUint32(out[16:20], uint32(o.RecordCount))
	return out
}

// Cache1Entry describes one nsDiskCacheEntry to build.
type Cache1Entry struct {
	// Key is the cache key. Firefox cache1 keys carry a scheme prefix,
	// e.g. "HTTP:https://example.org/x".
	Key string
	// FetchCount and the three times are what the format records.
	FetchCount     int32
	LastFetchedU   uint32
	LastModifiedU  uint32
	ExpirationU    uint32
	DataSize       uint32
	RequestMethod  string
	ResponseHead   string
	ExtraElements  []string // name, value, name, value...
	OmitTimestamps bool     // write zero for both times
}

// BuildFirefoxCache1Block assembles a _CACHE_00x_ block file holding the
// given metadata records, laid out after the 4096-byte allocation
// bitmap exactly as Firefox writes it.
func BuildFirefoxCache1Block(blockSize int, entries []Cache1Entry) []byte {
	var blocks []byte
	for _, e := range entries {
		var elems []byte
		add := func(name, value string) {
			elems = append(elems, name...)
			elems = append(elems, 0)
			elems = append(elems, value...)
			elems = append(elems, 0)
		}
		if e.RequestMethod != "" {
			add("request-method", e.RequestMethod)
		}
		if e.ResponseHead != "" {
			add("response-head", e.ResponseHead)
		}
		for i := 0; i+1 < len(e.ExtraElements); i += 2 {
			add(e.ExtraElements[i], e.ExtraElements[i+1])
		}

		keyBytes := append([]byte(e.Key), 0)
		rec := make([]byte, cache1EntryHeader+len(keyBytes)+len(elems))
		binary.BigEndian.PutUint32(rec[0:4], 0x00010006)
		binary.BigEndian.PutUint32(rec[4:8], 0x81000000|uint32(len(blocks)/blockSize))
		binary.BigEndian.PutUint32(rec[8:12], uint32(e.FetchCount))
		if !e.OmitTimestamps {
			binary.BigEndian.PutUint32(rec[12:16], e.LastFetchedU)
			binary.BigEndian.PutUint32(rec[16:20], e.LastModifiedU)
		}
		binary.BigEndian.PutUint32(rec[20:24], e.ExpirationU)
		binary.BigEndian.PutUint32(rec[24:28], e.DataSize)
		binary.BigEndian.PutUint32(rec[28:32], uint32(len(keyBytes)))
		binary.BigEndian.PutUint32(rec[32:36], uint32(len(elems)))
		copy(rec[cache1EntryHeader:], keyBytes)
		copy(rec[cache1EntryHeader+len(keyBytes):], elems)

		need := (len(rec) + blockSize - 1) / blockSize
		padded := make([]byte, need*blockSize)
		copy(padded, rec)
		blocks = append(blocks, padded...)
	}
	return append(make([]byte, cache1BitmapSize), blocks...)
}

// CorruptCache1 damages a cache1 block file.
func CorruptCache1(data []byte, how string) []byte {
	out := append([]byte(nil), data...)
	if len(out) <= cache1BitmapSize+cache1EntryHeader {
		return out
	}
	rec := out[cache1BitmapSize:]
	switch how {
	case "version":
		binary.BigEndian.PutUint32(rec[0:4], 0xDEADBEEF)
	case "huge-key":
		binary.BigEndian.PutUint32(rec[28:32], 0x7FFFFFFF)
	case "huge-meta":
		binary.BigEndian.PutUint32(rec[32:36], 0x7FFFFFFF)
	case "zero-times":
		binary.BigEndian.PutUint32(rec[12:16], 0)
		binary.BigEndian.PutUint32(rec[16:20], 0)
	case "truncate":
		out = out[:cache1BitmapSize+8]
	}
	return out
}

// CorruptBlockfile damages a blockfile data file.
func CorruptBlockfile(data []byte, how string) []byte {
	out := append([]byte(nil), data...)
	if len(out) <= blockfileHeaderSize+96 {
		return out
	}
	rec := out[blockfileHeaderSize:]
	switch how {
	case "magic":
		binary.LittleEndian.PutUint32(out[0:4], 0)
	case "block-size":
		binary.LittleEndian.PutUint32(out[12:16], 777)
	case "huge-key":
		binary.LittleEndian.PutUint32(rec[32:36], 0x7FFFFFFF)
	case "zero-time":
		binary.LittleEndian.PutUint64(rec[24:32], 0)
	case "bad-state":
		binary.LittleEndian.PutUint32(rec[20:24], 99)
	case "truncate":
		out = out[:blockfileHeaderSize+64]
	}
	return out
}
