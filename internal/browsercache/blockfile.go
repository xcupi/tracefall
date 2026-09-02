package browsercache

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"time"
)

// Chromium "blockfile" cache -- the disk_cache format that predates the
// Simple Cache and is still written today by GPUCache, older Chrome and
// Edge profiles, and Chromium-embedder applications.
//
// # Why this format is worth reading
//
// A Simple Cache entry file records no time at all. A blockfile
// EntryStore records creation_time, so a blockfile cache is the one
// Chromium cache generation whose entries can legitimately be placed on
// a timeline -- with a time the browser itself wrote, not one inferred
// from the filesystem.
//
// # Layout
//
// The cache is a set of files that reference each other:
//
//	index         a header plus a hash table of CacheAddr words. Holds
//	              no URLs. Read here for its own header only, as a
//	              CONTAINER: entry count, size, and the cache's
//	              creation time.
//	data_0        rankings (LRU) nodes, 36-byte blocks. No key, so a
//	              time from one cannot be attributed to a resource.
//	              Not read.
//	data_1        256-byte blocks. Where EntryStore records live.
//	data_2        1 KiB blocks -- larger stream payloads.
//	data_3        4 KiB blocks.
//	f_######      one file per stream too large to block-allocate.
//	              Response BODIES. Not read; see the package comment.
//
// Each block file opens with an 8192-byte header, after which blocks are
// addressed by index. An EntryStore is 96 fixed bytes plus an inline key
// of up to 928 bytes, so it occupies one to four contiguous 256-byte
// blocks.
//
// # Reading one file at a time
//
// Tracefall imports a file, parses it, and ties every event to that
// file's hash. A reader that followed CacheAddr words into sibling files
// would produce events whose evidence is a file the case never imported.
// So data_1 is scanned STRUCTURALLY for EntryStore records, and an
// address pointing outside the file being read is recorded as an address
// -- never followed, never guessed at.
//
// In practice this costs little: stream 0 holds the HTTP response
// headers and is small, so it is almost always allocated in the same
// 256-byte block file as the entry itself.

const (
	blockfileIndexMagic = uint32(0xC103CAC3)
	blockfileDataMagic  = uint32(0xC104CAC3)

	// blockfileHeaderSize is the reserved header at the front of every
	// data_N file. Blocks are numbered from the end of it.
	blockfileHeaderSize = 8192

	// entryStoreFixed is the size of EntryStore up to the inline key.
	entryStoreFixed = 96
	// entryStoreMaxKey is kMaxInternalKeyLength+1: an EntryStore spans at
	// most four 256-byte blocks, and 4*256-96 = 928 of them are key.
	entryStoreMaxKey = 928

	// entryStateNormal is ENTRY_NORMAL. Evicted (1) and doomed (2)
	// records are counted but not emitted: their fields are being
	// recycled and may no longer describe the resource named by the key.
	entryStateNormal = 0

	// blockfileMaxEntries caps one file's output. A 256-byte block file
	// is limited to 65536 blocks by the address format, so this cannot
	// be reached by a well-formed file -- it bounds a hostile one.
	blockfileMaxEntries = 1 << 16
)

// CacheAddr is a blockfile address word.
//
// bit 31     initialized
// bits 28-30 file type: 0 external (f_######), 1 rankings, 2 256-byte
//
//	blocks, 3 1 KiB, 4 4 KiB
//
// bits 24-25 number of contiguous blocks, minus one
// bits 16-23 which file of that type
// bits 0-15  first block
//
// For an external address the low 28 bits are the f_###### file number
// instead.
type CacheAddr uint32

func (a CacheAddr) initialized() bool { return a&0x80000000 != 0 }
func (a CacheAddr) fileType() int     { return int(a>>28) & 0x7 }
func (a CacheAddr) numBlocks() int    { return int(a>>24)&0x3 + 1 }
func (a CacheAddr) fileSelector() int { return int(a>>16) & 0xff }
func (a CacheAddr) startBlock() int   { return int(a) & 0xffff }
func (a CacheAddr) externalFile() int { return int(a) & 0x0fffffff }

// String renders an address the way a Chromium developer would read it,
// so an analyst can follow a reference to the file that holds it.
func (a CacheAddr) String() string {
	if a == 0 {
		return ""
	}
	if !a.initialized() {
		return fmt.Sprintf("uninitialized(0x%08x)", uint32(a))
	}
	if a.fileType() == 0 {
		return fmt.Sprintf("f_%06x", a.externalFile())
	}
	name := map[int]string{1: "data_0", 2: "data_1", 3: "data_2", 4: "data_3"}[a.fileType()]
	if name == "" {
		name = fmt.Sprintf("blocktype%d", a.fileType())
	}
	if sel := a.fileSelector(); sel > 0 && a.fileType() >= 2 {
		name = fmt.Sprintf("%s+%d", name, sel)
	}
	return fmt.Sprintf("%s:block %d(+%d)", name, a.startBlock(), a.numBlocks()-1)
}

// blockSizeForType is the block size each file type addresses.
var blockSizeForType = map[int]int{1: 36, 2: 256, 3: 1024, 4: 4096}

// BlockfileHeader is the header of one data_N file.
type BlockfileHeader struct {
	Version    uint32
	ThisFile   int
	NextFile   int
	EntrySize  int
	NumEntries int
	MaxEntries int
}

// BlockfileIndex is the header of a blockfile cache's index file.
//
// The index is a CONTAINER: a hash table of addresses pointing into the
// data_N files. It holds no keys and therefore no URLs. What it does
// hold, and nothing else does, is the cache's own creation time.
type BlockfileIndex struct {
	Version    uint32
	NumEntries int
	NumBytes   int64
	LastFile   int
	TableLen   int
	CreateTime time.Time
	Warnings   []string
}

// SniffChromiumBlockfileIndex reports whether header is a blockfile
// index file.
func SniffChromiumBlockfileIndex(header []byte) bool {
	return len(header) >= 48 && binary.LittleEndian.Uint32(header[0:4]) == blockfileIndexMagic
}

// SniffChromiumBlockfileData reports whether header is a blockfile block
// file that can hold ENTRY RECORDS.
//
// Only the 256-byte block file qualifies, which in a normal cache is
// data_1. That is narrower than "is a blockfile data file" on purpose:
//
//	data_0 holds 36-byte LRU rankings nodes -- times, but no cache key.
//	data_2 and data_3 hold 1 KiB and 4 KiB stream payloads.
//
// None of those can yield an entry, so claiming them would import files
// that are guaranteed to produce nothing while telling the analyst they
// were supported. They are left to the capability registry, which names
// each of them and says what it is instead.
//
// The magic is checked together with the block size, so a file that
// merely happens to start with the magic word is not accepted.
func SniffChromiumBlockfileData(header []byte) bool {
	if len(header) < 24 || binary.LittleEndian.Uint32(header[0:4]) != blockfileDataMagic {
		return false
	}
	return int32(binary.LittleEndian.Uint32(header[12:16])) == 256
}

// IsChromiumBlockfileDataAnySize reports whether header is any blockfile
// block file, including the ones that hold no entry records. Used to
// EXPLAIN a file, never to claim one.
func IsChromiumBlockfileDataAnySize(header []byte) (blockSize int, ok bool) {
	if len(header) < 24 || binary.LittleEndian.Uint32(header[0:4]) != blockfileDataMagic {
		return 0, false
	}
	switch n := int32(binary.LittleEndian.Uint32(header[12:16])); n {
	case 36, 256, 1024, 4096:
		return int(n), true
	}
	return 0, false
}

// IsChromiumBlockfile reports whether header is any blockfile-cache
// file, index or data.
func IsChromiumBlockfile(header []byte) bool {
	if len(header) < 8 {
		return false
	}
	magic := binary.LittleEndian.Uint32(header[0:4])
	return magic == blockfileIndexMagic || magic == blockfileDataMagic
}

// ParseChromiumBlockfileIndex reads a blockfile index file's header.
func ParseChromiumBlockfileIndex(path string, lim Limits) (idx BlockfileIndex, err error) {
	lim = lim.withDefaults()
	defer func() {
		if r := recover(); r != nil {
			idx, err = BlockfileIndex{}, fmt.Errorf("%w: recovered from %v", ErrCorrupt, r)
		}
	}()

	data, err := readCapped(path, lim)
	if err != nil {
		return BlockfileIndex{}, err
	}
	if !SniffChromiumBlockfileIndex(data) {
		return BlockfileIndex{}, ErrNotCacheEntry
	}

	idx = BlockfileIndex{
		Version:    binary.LittleEndian.Uint32(data[4:8]),
		NumEntries: int(int32(binary.LittleEndian.Uint32(data[8:12]))),
		NumBytes:   int64(int32(binary.LittleEndian.Uint32(data[12:16]))),
		LastFile:   int(int32(binary.LittleEndian.Uint32(data[16:20]))),
		TableLen:   int(int32(binary.LittleEndian.Uint32(data[28:32]))),
		CreateTime: windowsEpochMicros(binary.LittleEndian.Uint64(data[40:48])),
	}
	// Negative counts mean a damaged header. Reported, not silently
	// clamped to something that looks plausible.
	if idx.NumEntries < 0 {
		idx.Warnings = append(idx.Warnings, warnf("index declares a negative entry count (%d); the header is damaged", idx.NumEntries))
		idx.NumEntries = 0
	}
	if idx.NumBytes < 0 {
		idx.Warnings = append(idx.Warnings, warnf("index declares a negative size; the header is damaged"))
		idx.NumBytes = 0
	}
	if idx.CreateTime.IsZero() && binary.LittleEndian.Uint64(data[40:48]) != 0 {
		idx.Warnings = append(idx.Warnings, "index creation time is outside any plausible range and was discarded")
	}
	return idx, nil
}

// BlockfileScan is what one data_N file yielded.
//
// Counts are reported even when Entries is empty: "this is a valid block
// file holding no live entries" and "this file could not be read" are
// different findings, and an analyst must be able to tell them apart.
type BlockfileScan struct {
	Header        BlockfileHeader
	Entries       []Entry
	BlocksScanned int
	// Skipped counts records that decoded as an EntryStore but were not
	// emitted, by reason.
	SkippedEvicted   int
	SkippedDoomed    int
	SkippedNoKey     int
	SkippedImplausib int
	Warnings         []string
}

// ParseChromiumBlockfileData scans one data_N block file for EntryStore
// records.
//
// Chromium locates entries through the index's hash table. This scans
// the file's own blocks instead, which needs no sibling file and finds
// entries the index no longer points at -- a record whose hash-table
// slot was overwritten is still on disk, and is still evidence. Every
// candidate must satisfy the whole EntryStore shape before it is
// accepted; see plausibleEntryStore.
func ParseChromiumBlockfileData(path string, lim Limits) (scan BlockfileScan, err error) {
	lim = lim.withDefaults()
	defer func() {
		if r := recover(); r != nil {
			scan, err = BlockfileScan{}, fmt.Errorf("%w: recovered from %v", ErrCorrupt, r)
		}
	}()

	data, err := readCapped(path, lim)
	if err != nil {
		return BlockfileScan{}, err
	}
	if !SniffChromiumBlockfileData(data) {
		return BlockfileScan{}, ErrNotCacheEntry
	}

	scan.Header = BlockfileHeader{
		Version:    binary.LittleEndian.Uint32(data[4:8]),
		ThisFile:   int(int16(binary.LittleEndian.Uint16(data[8:10]))),
		NextFile:   int(int16(binary.LittleEndian.Uint16(data[10:12]))),
		EntrySize:  int(int32(binary.LittleEndian.Uint32(data[12:16]))),
		NumEntries: int(int32(binary.LittleEndian.Uint32(data[16:20]))),
		MaxEntries: int(int32(binary.LittleEndian.Uint32(data[20:24]))),
	}
	blockSize := scan.Header.EntrySize
	if len(data) <= blockfileHeaderSize {
		// A header with no block area is valid and simply holds nothing.
		scan.Warnings = append(scan.Warnings, "block file contains a header but no block area")
		return scan, nil
	}
	// EntryStore records only ever live in the 256-byte block file.
	// data_2 and data_3 hold stream payloads, and a 1 KiB or 4 KiB block
	// interpreted as an entry would be a fabrication.
	if blockSize != 256 {
		scan.Warnings = append(scan.Warnings, warnf(
			"this is a %d-byte block file, which holds stream payloads rather than entry records; "+
				"cache entries live in the 256-byte block file (normally data_1)", blockSize))
		return scan, nil
	}

	body := data[blockfileHeaderSize:]
	total := len(body) / blockSize
	consumed := make([]bool, total)

	for i := 0; i < total; i++ {
		if consumed[i] {
			continue
		}
		scan.BlocksScanned++
		rec := body[i*blockSize:]
		st, ok := decodeEntryStore(rec, lim)
		if !ok {
			continue
		}
		switch {
		case st.state == 1:
			scan.SkippedEvicted++
			continue
		case st.state == 2:
			scan.SkippedDoomed++
			continue
		case st.state != entryStateNormal:
			scan.SkippedImplausib++
			continue
		}
		// Mark the blocks this record occupies so its key bytes are not
		// re-read as another record.
		blocks := (entryStoreFixed + st.keyLen + blockSize - 1) / blockSize
		if blocks < 1 {
			blocks = 1
		}
		for b := i; b < i+blocks && b < total; b++ {
			consumed[b] = true
		}

		if st.url == "" {
			scan.SkippedNoKey++
			continue
		}
		if len(scan.Entries) >= blockfileMaxEntries {
			scan.Warnings = append(scan.Warnings, warnf("stopped after %d entries: the file declares more than this build will read", blockfileMaxEntries))
			break
		}
		scan.Entries = append(scan.Entries, st.entry(body, blockSize, lim))
	}
	if scan.Header.NumEntries > 0 && len(scan.Entries) == 0 {
		scan.Warnings = append(scan.Warnings, warnf(
			"the header declares %d entries but no readable entry records were recovered; "+
				"entry records may have been evicted or the block area may be damaged", scan.Header.NumEntries))
	}
	return scan, nil
}

// entryStore is one decoded EntryStore record.
type entryStore struct {
	hash         uint32
	state        int32
	reuseCount   int32
	refetchCount int32
	creation     time.Time
	keyLen       int
	longKey      CacheAddr
	dataSize     [4]int32
	dataAddr     [4]CacheAddr
	key          string
	url          string
}

// decodeEntryStore validates and decodes a candidate record.
//
// Everything here is a rejection test. The record is only accepted when
// its own fields agree with each other, which is what makes scanning
// safe: an arbitrary 256 bytes of cached JPEG will fail one of these.
func decodeEntryStore(rec []byte, lim Limits) (entryStore, bool) {
	if len(rec) < entryStoreFixed {
		return entryStore{}, false
	}
	var st entryStore
	st.hash = binary.LittleEndian.Uint32(rec[0:4])
	st.state = int32(binary.LittleEndian.Uint32(rec[20:24]))
	st.reuseCount = int32(binary.LittleEndian.Uint32(rec[12:16]))
	st.refetchCount = int32(binary.LittleEndian.Uint32(rec[16:20]))
	rawTime := binary.LittleEndian.Uint64(rec[24:32])
	keyLen := int32(binary.LittleEndian.Uint32(rec[32:36]))
	st.longKey = CacheAddr(binary.LittleEndian.Uint32(rec[36:40]))
	for i := 0; i < 4; i++ {
		st.dataSize[i] = int32(binary.LittleEndian.Uint32(rec[40+i*4 : 44+i*4]))
		st.dataAddr[i] = CacheAddr(binary.LittleEndian.Uint32(rec[56+i*4 : 60+i*4]))
	}

	// A live record always has a state in range and a sane key length.
	if st.state < 0 || st.state > 2 {
		return entryStore{}, false
	}
	if keyLen <= 0 || keyLen > int32(lim.MaxKeyBytes) {
		return entryStore{}, false
	}
	st.keyLen = int(keyLen)
	// Stream sizes are non-negative and bounded by what a cache stores.
	for i := 0; i < 4; i++ {
		if st.dataSize[i] < 0 || int64(st.dataSize[i]) > lim.MaxFileBytes {
			return entryStore{}, false
		}
	}
	// creation_time is the field that makes this format worth reading, so
	// it must be real: a record whose time is not a plausible date is not
	// treated as an entry at all, rather than emitted with a zero time.
	st.creation = windowsEpochMicros(rawTime)
	if st.creation.IsZero() {
		return entryStore{}, false
	}

	// The key. Keys longer than the inline area live at long_key, in
	// another block -- possibly in another file, which this reader will
	// not follow. Such a record is recognized and counted, not invented.
	if st.keyLen <= entryStoreMaxKey && len(rec) >= entryStoreFixed+st.keyLen {
		raw := rec[entryStoreFixed : entryStoreFixed+st.keyLen]
		if i := indexByte(raw, 0); i >= 0 {
			raw = raw[:i]
		}
		st.key = safeString(raw, lim.MaxKeyBytes)
		st.url = extractURL(st.key)
	}
	if st.url == "" && st.key == "" && st.longKey == 0 {
		// No inline key and no external key: not an entry record.
		return entryStore{}, false
	}
	if st.url == "" && st.key != "" && !plausibleCacheKey([]byte(st.key)) {
		return entryStore{}, false
	}
	return st, true
}

// entry converts a decoded record into the shared Entry shape,
// recovering the response headers when stream 0 is stored in this same
// file.
func (st entryStore) entry(body []byte, blockSize int, lim Limits) Entry {
	e := Entry{
		Format:  FormatChromiumBlockfile,
		Browser: BrowserChromium,
		Key:     st.key,
		URL:     st.url,
		// creation_time is the entry's own recorded time: when Chromium
		// created this cache entry. It is NOT a navigation time and not
		// the response's Date header.
		LastFetched: st.creation,
		EntryID:     fmt.Sprintf("%08x", st.hash),
		StoredBytes: int64(st.dataSize[0]) + int64(st.dataSize[1]),
	}
	if st.reuseCount > 0 {
		e.FetchCount = uint32(st.reuseCount)
	}
	if st.url == "" {
		e.Warnings = append(e.Warnings, warnf(
			"the cache key is %d bytes and is stored outside this record at %s, which is not read here; "+
				"the URL could not be recovered from this file alone", st.keyLen, st.longKey))
	}

	// Stream 0 holds the pickled HTTP response info. Read it only when
	// its address points into THIS file: following it elsewhere would
	// attribute another file's contents to this one.
	if raw, ok := st.streamInThisFile(0, body, blockSize); ok {
		if block, found := locateHeaderBlock(raw, lim); found {
			e.StatusLine, e.StatusCode, e.Headers = parseHeaderBlock(block, lim)
			e.ContentType = normalizeContentType(headerValue(e.Headers, "Content-Type"))
			if n, ok := parseContentLength(headerValue(e.Headers, "Content-Length")); ok {
				e.ContentLength, e.HasContentLength = n, true
			}
		}
	} else if st.dataAddr[0] != 0 {
		e.Warnings = append(e.Warnings, warnf(
			"HTTP response metadata for this entry is stored at %s, outside the file being read", st.dataAddr[0]))
	}
	if st.dataAddr[1] != 0 && st.dataAddr[1].fileType() == 0 {
		e.Warnings = append(e.Warnings, warnf(
			"the cached response body is stored in the external file %s, which Tracefall does not read", st.dataAddr[1]))
	}
	return e
}

// streamInThisFile returns stream n's bytes when its address refers to a
// block inside the file currently being read.
func (st entryStore) streamInThisFile(n int, body []byte, blockSize int) ([]byte, bool) {
	addr := st.dataAddr[n]
	if addr == 0 || !addr.initialized() {
		return nil, false
	}
	if blockSizeForType[addr.fileType()] != blockSize {
		return nil, false // a different block file
	}
	if addr.fileSelector() > 1 {
		// data_1 is selector 1; a higher selector is an additional file
		// of the same block size, which is not this one.
		return nil, false
	}
	start := addr.startBlock() * blockSize
	length := addr.numBlocks() * blockSize
	if size := int(st.dataSize[n]); size > 0 && size < length {
		length = size
	}
	if start < 0 || start >= len(body) || length <= 0 {
		return nil, false
	}
	if start+length > len(body) {
		length = len(body) - start
	}
	return body[start : start+length], true
}

// windowsEpochMicros converts a base::Time internal value -- microseconds
// since 1601-01-01 UTC -- rejecting anything outside a plausible range
// rather than returning a year-1601 or year-30000 date.
func windowsEpochMicros(v uint64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	const unixEpochOffsetMicros = 11644473600 * 1000000
	if v < unixEpochOffsetMicros {
		return time.Time{} // before 1970: not a browser cache entry
	}
	micros := int64(v - unixEpochOffsetMicros)
	t := time.Unix(micros/1e6, (micros%1e6)*1000).UTC()
	if t.Year() < 1995 || t.Year() > 2100 {
		return time.Time{}
	}
	return t
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// readCapped reads a whole file after checking it against the size cap.
func readCapped(path string, lim Limits) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > lim.MaxFileBytes {
		return nil, fmt.Errorf("%w: file is %d bytes", ErrLimitExceeded, info.Size())
	}
	return os.ReadFile(path)
}

// blockfileDataFileName reports whether a name is one of the canonical
// blockfile data files, and which one. Used only to explain a file, never
// to claim one -- claiming is done by SniffChromiumBlockfileData.
func blockfileDataFileName(base string) (int, bool) {
	lower := strings.ToLower(base)
	if !strings.HasPrefix(lower, "data_") || len(lower) != 6 {
		return 0, false
	}
	n := int(lower[5] - '0')
	if n < 0 || n > 9 {
		return 0, false
	}
	return n, true
}
