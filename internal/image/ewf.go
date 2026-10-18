package image

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/adler32"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"unicode/utf16"
)

// EWF1 (E01 / EnCase) reader.
//
// Layout, as implemented by libewf and documented in its format notes:
//
//	file header   13 bytes   "EVF\x09\x0d\x0a\xff\x00", 0x01, segment u16, 0 u16
//	sections      each starts with a 76-byte descriptor:
//	                type[16] next u64 size u64 pad[40] adler32 u32
//	              "next" is the absolute file offset of the next descriptor
//	              (equal to its own offset on the last "done"/"next" section).
//	header        zlib text: case number, examiner, dates ...
//	volume/disk   media geometry: chunk count, sectors per chunk,
//	              bytes per sector, sector count
//	sectors       the chunk data
//	table         u32 offsets of chunks inside the preceding sectors
//	              section; the top bit marks a zlib-compressed chunk
//	digest/hash   MD5 (and SHA1) recorded at acquisition
//
// A chunk is sectors_per_chunk * bytes_per_sector bytes of media. Stored
// uncompressed it is followed by an Adler-32 of its bytes; compressed it
// is a zlib stream (which carries its own Adler-32). Both checks are done
// on every chunk that is read.
//
// Table entries are 31-bit offsets, so a segment larger than 2 GiB would
// need EnCase's overflow convention; that is detected (offsets that go
// backwards) and reported as ErrUnsupported instead of guessed at.

const (
	ewf1Signature     = "EVF\x09\x0d\x0a\xff\x00"
	ewfFileHeaderSize = 13
	ewfDescriptorSize = 76
	maxEWFChunkBytes  = 64 << 20
	maxEWFSections    = 1 << 20
	maxEWFTextBytes   = 4 << 20
	ewfCacheChunks    = 16
)

type ewfTable struct {
	seg     int
	base    uint64
	entries []uint32
	dataEnd uint64 // end of the sectors section these entries index
}

type ewfImage struct {
	files     []*os.File
	fileSizes []int64
	info      Info
	size      int64
	chunkSize int64
	nChunks   int64
	tables    []ewfTable
	starts    []int64 // first global chunk index of each table

	mu    sync.Mutex
	cache map[int64][]byte
	order []int64
}

func ewfCorrupt(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrCorrupt}, a...)...)
}

func openEWF(paths []string) (Image, error) {
	e := &ewfImage{cache: map[int64][]byte{}}
	ok := false
	defer func() {
		if !ok {
			e.Close()
		}
	}()

	var (
		haveVolume         bool
		bps, spc           uint32
		sectorCount        uint64
		chunkCountDeclared uint32
		headerText         string
		haveHeader2        bool
		md5Hex, sha1Hex    string
		sawDone            bool
		pendingSectorsEnd  uint64
		havePendingSectors bool
	)

	for si, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			return nil, err
		}
		e.files = append(e.files, f)
		st, err := f.Stat()
		if err != nil {
			return nil, err
		}
		fileSize := st.Size()
		e.fileSizes = append(e.fileSizes, fileSize)

		var hdr [ewfFileHeaderSize]byte
		if _, err := f.ReadAt(hdr[:], 0); err != nil {
			return nil, ewfCorrupt("%s: file header is truncated", p)
		}
		if string(hdr[:8]) != ewf1Signature {
			return nil, ewfCorrupt("%s: not an EWF segment", p)
		}
		if seg := binary.LittleEndian.Uint16(hdr[9:11]); int(seg) != si+1 {
			return nil, ewfCorrupt("%s is segment %d but segment %d was expected: a segment is missing or out of order", p, seg, si+1)
		}

		off := int64(ewfFileHeaderSize)
		segmentEnded := false
		for count := 0; ; count++ {
			if count > maxEWFSections {
				return nil, ewfCorrupt("%s: too many sections", p)
			}
			var d [ewfDescriptorSize]byte
			if off < 0 || off+ewfDescriptorSize > fileSize {
				return nil, ewfCorrupt("%s: section descriptor at %d runs past the end of the file (truncated image?)", p, off)
			}
			if _, err := f.ReadAt(d[:], off); err != nil {
				return nil, ewfCorrupt("%s: reading a section descriptor: %v", p, err)
			}
			if adler32.Checksum(d[:72]) != binary.LittleEndian.Uint32(d[72:]) {
				return nil, ewfCorrupt("%s: section descriptor at %d fails its checksum", p, off)
			}
			typ := string(bytes.TrimRight(d[:16], "\x00"))
			next := binary.LittleEndian.Uint64(d[16:24])
			size := binary.LittleEndian.Uint64(d[24:32])
			dataOff := off + ewfDescriptorSize
			dataLen := int64(size) - ewfDescriptorSize
			if size < ewfDescriptorSize || int64(size) < 0 || off+int64(size) > fileSize {
				if typ != "done" && typ != "next" {
					return nil, ewfCorrupt("%s: section %q at %d claims %d bytes, beyond the end of the file", p, typ, off, size)
				}
				dataLen = 0
			}

			readData := func(limit int64) ([]byte, error) {
				if dataLen < 0 || dataLen > limit {
					return nil, ewfCorrupt("%s: section %q has an implausible size %d", p, typ, dataLen)
				}
				b := make([]byte, dataLen)
				if _, err := f.ReadAt(b, dataOff); err != nil {
					return nil, ewfCorrupt("%s: reading section %q: %v", p, typ, err)
				}
				return b, nil
			}

			switch typ {
			case "header", "header2":
				if typ == "header" && haveHeader2 {
					break
				}
				b, err := readData(maxEWFTextBytes)
				if err != nil {
					return nil, err
				}
				if txt, ok := inflateText(b, typ == "header2"); ok {
					headerText = txt
					haveHeader2 = haveHeader2 || typ == "header2"
				}
			case "volume", "disk", "data":
				if haveVolume {
					break
				}
				b, err := readData(1 << 16)
				if err != nil {
					return nil, err
				}
				var chunks uint32
				switch len(b) {
				case 1052: // EnCase: sector count is 64-bit
					chunks = binary.LittleEndian.Uint32(b[4:])
					spc = binary.LittleEndian.Uint32(b[8:])
					bps = binary.LittleEndian.Uint32(b[12:])
					sectorCount = binary.LittleEndian.Uint64(b[16:])
					if adler32.Checksum(b[:1048]) != binary.LittleEndian.Uint32(b[1048:]) {
						return nil, ewfCorrupt("%s: the volume section fails its checksum", p)
					}
				case 94: // SMART: sector count is 32-bit
					chunks = binary.LittleEndian.Uint32(b[4:])
					spc = binary.LittleEndian.Uint32(b[8:])
					bps = binary.LittleEndian.Uint32(b[12:])
					sectorCount = uint64(binary.LittleEndian.Uint32(b[16:]))
					if adler32.Checksum(b[:90]) != binary.LittleEndian.Uint32(b[90:]) {
						return nil, ewfCorrupt("%s: the volume section fails its checksum", p)
					}
				default:
					return nil, ewfCorrupt("%s: volume section has unexpected size %d", p, len(b))
				}
				chunkCountDeclared = chunks
				haveVolume = true
			case "sectors":
				pendingSectorsEnd = uint64(off) + size
				havePendingSectors = true
			case "table":
				if !havePendingSectors {
					return nil, ewfCorrupt("%s: a table section precedes any sectors section", p)
				}
				b, err := readData(1 << 28)
				if err != nil {
					return nil, err
				}
				if len(b) < 24 {
					return nil, ewfCorrupt("%s: table section is too short", p)
				}
				n := binary.LittleEndian.Uint32(b[0:])
				base := binary.LittleEndian.Uint64(b[8:])
				if adler32.Checksum(b[:20]) != binary.LittleEndian.Uint32(b[20:]) {
					return nil, ewfCorrupt("%s: table header fails its checksum", p)
				}
				if uint64(len(b)) < 24+4*uint64(n) {
					return nil, ewfCorrupt("%s: table claims %d entries but holds fewer", p, n)
				}
				ent := make([]uint32, n)
				for i := range ent {
					ent[i] = binary.LittleEndian.Uint32(b[24+4*i:])
				}
				e.tables = append(e.tables, ewfTable{seg: si, base: base, entries: ent, dataEnd: pendingSectorsEnd})
			case "digest":
				b, err := readData(4096)
				if err != nil {
					return nil, err
				}
				if len(b) >= 36 {
					if s := hex.EncodeToString(b[:16]); s != strings.Repeat("0", 32) {
						md5Hex = s
					}
					if s := hex.EncodeToString(b[16:36]); s != strings.Repeat("0", 40) {
						sha1Hex = s
					}
				}
			case "hash":
				b, err := readData(4096)
				if err != nil {
					return nil, err
				}
				if len(b) >= 16 && md5Hex == "" {
					if s := hex.EncodeToString(b[:16]); s != strings.Repeat("0", 32) {
						md5Hex = s
					}
				}
			case "xhash":
				if b, err := readData(maxEWFTextBytes); err == nil {
					if txt, ok := inflateText(b, false); ok {
						if v := xmlValue(txt, "sha1"); v != "" && sha1Hex == "" {
							sha1Hex = v
						}
						if v := xmlValue(txt, "md5"); v != "" && md5Hex == "" {
							md5Hex = v
						}
					}
				}
			case "done":
				sawDone = true
				segmentEnded = true
			case "next":
				segmentEnded = true
			}
			if segmentEnded {
				break
			}
			if next <= uint64(off) || next > uint64(fileSize) {
				return nil, ewfCorrupt("%s: section chain at %d does not advance", p, off)
			}
			off = int64(next)
		}
	}

	if !haveVolume {
		return nil, ewfCorrupt("no volume section: the image has no media description")
	}
	if !sawDone {
		return nil, ewfCorrupt("the image has no final \"done\" section: it is truncated or its last segment is missing")
	}
	if bps < 512 || bps > 1<<16 || bps&(bps-1) != 0 || spc == 0 || uint64(bps)*uint64(spc) > maxEWFChunkBytes {
		return nil, ewfCorrupt("implausible geometry: %d sectors of %d bytes per chunk", spc, bps)
	}
	e.chunkSize = int64(bps) * int64(spc)
	if sectorCount == 0 || sectorCount > (1<<62)/uint64(bps) {
		return nil, ewfCorrupt("implausible sector count %d", sectorCount)
	}
	e.size = int64(sectorCount) * int64(bps)
	need := (e.size + e.chunkSize - 1) / e.chunkSize

	var total int64
	for _, t := range e.tables {
		e.starts = append(e.starts, total)
		total += int64(len(t.entries))
	}
	e.nChunks = total
	if total < need {
		return nil, ewfCorrupt("the tables describe %d chunks but the media needs %d: part of the image is missing", total, need)
	}
	_ = chunkCountDeclared // informational; the tables are authoritative

	// Offsets must grow inside a table. A decrease is EnCase's 2 GiB
	// overflow convention, which is not implemented.
	for ti, t := range e.tables {
		var prev uint64
		for i, v := range t.entries {
			o := t.base + uint64(v&0x7fffffff)
			if i > 0 && o < prev {
				return nil, fmt.Errorf("%w: table %d: chunk offsets go backwards (segment larger than 2 GiB?)", ErrUnsupported, ti)
			}
			prev = o
		}
	}

	e.info = Info{
		Format: FormatEWF, Size: e.size, SectorSize: int(bps), Segments: len(paths),
		StoredMD5: md5Hex, StoredSHA1: sha1Hex, Meta: parseEWFHeader(headerText),
	}
	ok = true
	return e, nil
}

func (e *ewfImage) Size() int64 { return e.size }
func (e *ewfImage) Info() Info  { return e.info }

func (e *ewfImage) Close() error {
	var first error
	for _, f := range e.files {
		if err := f.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// chunkLocation returns where chunk idx lives and whether it is compressed.
func (e *ewfImage) chunkLocation(idx int64) (seg int, off, length int64, compressed bool, err error) {
	ti := sort.Search(len(e.starts), func(i int) bool { return e.starts[i] > idx }) - 1
	if ti < 0 {
		return 0, 0, 0, false, ewfCorrupt("chunk %d has no table", idx)
	}
	t := e.tables[ti]
	j := int(idx - e.starts[ti])
	v := t.entries[j]
	start := t.base + uint64(v&0x7fffffff)
	var end uint64
	if j+1 < len(t.entries) {
		end = t.base + uint64(t.entries[j+1]&0x7fffffff)
	} else {
		end = t.dataEnd
	}
	if end <= start || end > uint64(e.fileSizes[t.seg]) {
		return 0, 0, 0, false, ewfCorrupt("chunk %d has an invalid extent [%d,%d)", idx, start, end)
	}
	return t.seg, int64(start), int64(end - start), v&0x80000000 != 0, nil
}

func (e *ewfImage) chunkData(idx int64) ([]byte, error) {
	e.mu.Lock()
	if b, ok := e.cache[idx]; ok {
		e.mu.Unlock()
		return b, nil
	}
	e.mu.Unlock()

	seg, off, length, compressed, err := e.chunkLocation(idx)
	if err != nil {
		return nil, err
	}
	raw := make([]byte, length)
	if _, err := e.files[seg].ReadAt(raw, off); err != nil {
		return nil, ewfCorrupt("chunk %d: %v", idx, err)
	}
	expected := e.chunkSize
	if rem := e.size - idx*e.chunkSize; rem < expected {
		expected = rem
	}
	var data []byte
	if compressed {
		zr, err := zlib.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, ewfCorrupt("chunk %d: %v", idx, err)
		}
		data, err = io.ReadAll(io.LimitReader(zr, e.chunkSize+1))
		if err != nil {
			return nil, ewfCorrupt("chunk %d: %v", idx, err)
		}
	} else {
		if int64(len(raw)) != expected+4 {
			return nil, ewfCorrupt("chunk %d: stored chunk is %d bytes, expected %d", idx, len(raw), expected+4)
		}
		data = raw[:expected]
		if adler32.Checksum(data) != binary.LittleEndian.Uint32(raw[expected:]) {
			return nil, ewfCorrupt("chunk %d fails its checksum", idx)
		}
	}
	if int64(len(data)) != expected {
		return nil, ewfCorrupt("chunk %d decodes to %d bytes, expected %d", idx, len(data), expected)
	}

	e.mu.Lock()
	if _, ok := e.cache[idx]; !ok {
		e.cache[idx] = data
		e.order = append(e.order, idx)
		if len(e.order) > ewfCacheChunks {
			delete(e.cache, e.order[0])
			e.order = e.order[1:]
		}
	}
	e.mu.Unlock()
	return data, nil
}

func (e *ewfImage) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("image: negative offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= e.size {
		return 0, io.EOF
	}
	total := 0
	for total < len(p) && off < e.size {
		idx := off / e.chunkSize
		data, err := e.chunkData(idx)
		if err != nil {
			return total, err
		}
		n := copy(p[total:], data[off-idx*e.chunkSize:])
		total += n
		off += int64(n)
	}
	if total < len(p) {
		return total, io.EOF
	}
	return total, nil
}

// inflateText decompresses a header/xhash section and decodes it.
func inflateText(b []byte, utf16le bool) (string, bool) {
	zr, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return "", false
	}
	raw, err := io.ReadAll(io.LimitReader(zr, maxEWFTextBytes))
	if err != nil {
		return "", false
	}
	if utf16le || (len(raw) >= 2 && raw[0] == 0xff && raw[1] == 0xfe) {
		if len(raw) >= 2 && raw[0] == 0xff && raw[1] == 0xfe {
			raw = raw[2:]
		}
		u := make([]uint16, len(raw)/2)
		for i := range u {
			u[i] = binary.LittleEndian.Uint16(raw[2*i:])
		}
		return string(utf16.Decode(u)), true
	}
	return string(raw), true
}

var ewfHeaderKeys = map[string]string{
	"c": "case_number", "n": "evidence_number", "a": "description", "e": "examiner", "t": "notes",
	"m": "acquisition_date", "u": "system_date", "ov": "operating_system", "av": "software_version",
}

// parseEWFHeader reads the tab-separated key line and value line.
func parseEWFHeader(text string) map[string]string {
	out := map[string]string{}
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	for i := 0; i+1 < len(lines); i++ {
		keys := strings.Split(lines[i], "\t")
		if len(keys) < 3 || !containsStr(keys, "c") || !containsStr(keys, "e") {
			continue
		}
		vals := strings.Split(lines[i+1], "\t")
		for k, key := range keys {
			if name, ok := ewfHeaderKeys[key]; ok && k < len(vals) {
				out[name] = strings.TrimSpace(vals[k])
			}
		}
		break
	}
	return out
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// xmlValue extracts <tag>value</tag> without a full XML parser: the
// section is machine-written and flat.
func xmlValue(doc, tag string) string {
	open, close := "<"+tag+">", "</"+tag+">"
	i := strings.Index(doc, open)
	if i < 0 {
		return ""
	}
	rest := doc[i+len(open):]
	j := strings.Index(rest, close)
	if j < 0 {
		return ""
	}
	v := strings.ToLower(strings.TrimSpace(rest[:j]))
	for _, c := range v {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return ""
		}
	}
	return v
}
