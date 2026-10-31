// Package wmirepo reads the bounded, active Win7+ repository subset.
// Repository snapshots describe configuration, not execution or event delivery.
// Modified native Go adaptation of mandiant/flare-wmi python-cim/cim,
// revision b0a5a094ff9ca7d7a1c4fc711dc00c74dec4b6b1 (Apache-2.0).
// Changes include bounded readers, strict validation and physical provenance.
// See NOTICE.txt and LICENSE.apache-2.0.txt in this directory.
package wmirepo

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const PageSize = 8192
const MaxRecord = 16 << 20

var ErrCorrupt = errors.New("corrupt WMI repository")
var ErrUnsupported = errors.New("unsupported WMI repository")

type Span struct {
	File         string `json:"file"`
	Offset       int64  `json:"offset"`
	Length       int    `json:"length"`
	RecordOffset int    `json:"record_offset"`
}
type File struct {
	Reader io.ReaderAt
	Size   int64
}
type Mapping struct {
	Entries    [][6]uint32
	Generation uint32
	Offset     int64
}
type Physical struct {
	Data, Index       File
	DataMap, IndexMap Mapping
	MapName           string
}
type Record struct {
	Bytes               []byte
	Spans, MappingSpans []Span
	TOC                 Span
	SHA256              string
}

func read(f File, offset int64, n int) ([]byte, error) {
	if offset < 0 || n < 0 || offset > f.Size || int64(n) > f.Size-offset {
		return nil, fmt.Errorf("%w: structure outside file", ErrCorrupt)
	}
	b := make([]byte, n)
	if _, err := f.Reader.ReadAt(b, offset); err != nil {
		return nil, fmt.Errorf("%w: truncated structure", ErrCorrupt)
	}
	return b, nil
}
func ReadMapping(f File, offset int64) (Mapping, int64, error) {
	h, err := read(f, offset, 24)
	if err != nil {
		return Mapping{}, 0, err
	}
	u := func(i int) uint32 { return binary.LittleEndian.Uint32(h[i*4:]) }
	if u(0) != 0xabcd {
		return Mapping{}, 0, fmt.Errorf("%w: Win7 mapping signature", ErrUnsupported)
	}
	count := u(5)
	if count > 1<<20 || count > u(4) || int64(count) > (f.Size-offset-32)/24 {
		return Mapping{}, 0, fmt.Errorf("%w: mapping count", ErrCorrupt)
	}
	m := Mapping{Entries: make([][6]uint32, count), Generation: u(1), Offset: offset}
	for i := range m.Entries {
		b, e := read(f, offset+24+int64(i)*24, 24)
		if e != nil {
			return Mapping{}, 0, e
		}
		for j := range 6 {
			m.Entries[i][j] = binary.LittleEndian.Uint32(b[j*4:])
		}
		physical := m.Entries[i][0] & 0x3fffffff
		if physical != 0x3fffffff && physical >= u(4) {
			return Mapping{}, 0, fmt.Errorf("%w: physical mapping", ErrCorrupt)
		}
	}
	tail := offset + 24 + int64(count)*24
	b, err := read(f, tail, 4)
	if err != nil {
		return Mapping{}, 0, err
	}
	free := binary.LittleEndian.Uint32(b)
	if free > 1<<20 || int64(free) > (f.Size-tail-8)/4 {
		return Mapping{}, 0, fmt.Errorf("%w: free mapping count", ErrCorrupt)
	}
	end := tail + 4 + int64(free)*4
	b, err = read(f, end, 4)
	if err != nil {
		return Mapping{}, 0, err
	}
	if binary.LittleEndian.Uint32(b) != 0xdcba {
		return Mapping{}, 0, fmt.Errorf("%w: mapping footer", ErrCorrupt)
	}
	return m, end + 4, nil
}
func page(f File, m Mapping, logical uint32) ([]byte, int64, error) {
	if uint64(logical) >= uint64(len(m.Entries)) {
		return nil, 0, fmt.Errorf("%w: logical page outside mapping", ErrCorrupt)
	}
	physical := m.Entries[logical][0] & 0x3fffffff
	if physical == 0x3fffffff {
		return nil, 0, fmt.Errorf("%w: unmapped page", ErrCorrupt)
	}
	offset := int64(physical) * PageSize
	b, err := read(f, offset, PageSize)
	return b, offset, err
}
func (p *Physical) ReadRecord(key string) (Record, error) {
	parts := strings.Split(key, ".")
	if len(parts) != 4 || parts[0] == "" {
		return Record{}, fmt.Errorf("%w: data key grammar", ErrUnsupported)
	}
	var values [3]uint32
	for i, s := range parts[1:] {
		if s == "" || strings.IndexFunc(s, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			return Record{}, fmt.Errorf("%w: data key number", ErrCorrupt)
		}
		n, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			return Record{}, fmt.Errorf("%w: data key number", ErrCorrupt)
		}
		values[i] = uint32(n)
	}
	logical, rid, length := values[0], values[1], values[2]
	if rid == 0 || length == 0 || length > MaxRecord {
		return Record{}, fmt.Errorf("%w: record ID/length", ErrCorrupt)
	}
	first, physical, err := page(p.Data, p.DataMap, logical)
	if err != nil {
		return Record{}, err
	}
	type toc struct {
		id, off, size uint32
		pos           int
	}
	entries := []toc{}
	seen := map[uint32]bool{}
	end := -1
	for off := 0; off < PageSize; off += 16 {
		b := first[off : off+16]
		id := binary.LittleEndian.Uint32(b)
		start := binary.LittleEndian.Uint32(b[4:])
		size := binary.LittleEndian.Uint32(b[8:])
		opaque := binary.LittleEndian.Uint32(b[12:])
		if id == 0 && start == 0 && size == 0 && opaque == 0 {
			end = off + 16
			break
		}
		if id == 0 || seen[id] || start == 0 || start >= PageSize || size == 0 || size > MaxRecord {
			return Record{}, fmt.Errorf("%w: TOC entry", ErrCorrupt)
		}
		seen[id] = true
		entries = append(entries, toc{id, start, size, off})
	}
	if end < 0 {
		return Record{}, fmt.Errorf("%w: TOC sentinel", ErrCorrupt)
	}
	var selected *toc
	for i := range entries {
		e := &entries[i]
		if int(e.off) < end {
			return Record{}, fmt.Errorf("%w: TOC overlap", ErrCorrupt)
		}
		for j := 0; j < i; j++ {
			other := entries[j]
			if uint64(e.off) < uint64(other.off)+uint64(other.size) && uint64(other.off) < uint64(e.off)+uint64(e.size) {
				return Record{}, fmt.Errorf("%w: overlapping TOC payloads", ErrCorrupt)
			}
		}
		if e.id == rid {
			selected = e
		}
	}
	if selected == nil || selected.size != length {
		return Record{}, fmt.Errorf("%w: record ID or TOC size mismatch", ErrCorrupt)
	}
	r := Record{Bytes: make([]byte, 0, int(length)), TOC: Span{File: "OBJECTS.DATA", Offset: physical + int64(selected.pos), Length: 16}}
	local, remaining := int(selected.off), int(length)
	usedPhysical := map[int64]bool{}
	for remaining > 0 {
		b, offset, err := page(p.Data, p.DataMap, logical)
		if err != nil {
			return Record{}, err
		}
		if usedPhysical[offset] {
			return Record{}, fmt.Errorf("%w: repeated physical record extent", ErrCorrupt)
		}
		usedPhysical[offset] = true
		n := min(PageSize-local, remaining)
		r.Spans = append(r.Spans, Span{File: "OBJECTS.DATA", Offset: offset + int64(local), Length: n, RecordOffset: len(r.Bytes)})
		r.MappingSpans = append(r.MappingSpans, Span{File: p.MapName, Offset: p.DataMap.Offset + 24 + int64(logical)*24, Length: 24})
		r.Bytes = append(r.Bytes, b[local:local+n]...)
		remaining -= n
		local = 0
		logical++
	}
	r.SHA256 = fmt.Sprintf("%x", sha256.Sum256(r.Bytes))
	return r, nil
}
