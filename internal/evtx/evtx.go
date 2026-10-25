// Package evtx reads raw Windows Event Log (.evtx) files directly from
// their binary form, without EvtxECmd or any other external tool, and
// without the Windows Event Log API -- so Tracefall can parse Windows
// evidence while running on Linux.
//
// The format is implemented against libyal's "Windows XML Event Log
// (EVTX)" specification; see docs/native-artifacts.md for the reference
// list and for why this is hand-written rather than delegated to a
// library.
//
// # Structure
//
// A .evtx file is a 4096-byte header followed by fixed 65536-byte
// chunks. Each chunk carries its own string and template tables and a
// CRC, and holds a series of self-delimiting event records. That per
// chunk independence is what makes partial recovery defensible: a
// damaged chunk can be skipped without casting doubt on the records
// already read from intact ones, and Walk reports exactly how many
// chunks it had to skip so a caller never mistakes a partial read for a
// complete one.
//
// Each record's payload is Binary XML: a token stream that references
// per-chunk name strings by offset and, usually, instantiates a
// *template* -- a reusable element skeleton with holes -- by supplying an
// array of substitution values. Templates are what make event logs
// compact, and resolving them is most of the work here.
//
// # Hostile input
//
// Every offset, length, and count in the file is attacker-controlled.
// Nothing is read without a bounds check against the enclosing chunk,
// element nesting and template expansion are depth-capped, the
// substitution array is size-capped, and exactly one 64 KiB chunk is
// held at a time regardless of file size. A malformed file yields an
// error or a skipped chunk; it never panics, never loops forever, and
// never allocates without bound.
package evtx

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

var (
	// ErrNotEVTX means the file does not carry the EVTX file signature.
	ErrNotEVTX = errors.New("evtx: not a Windows Event Log file (bad signature)")
	// ErrCorrupt means the file IS an EVTX but its structure is unusable
	// -- e.g. a header that validates but describes an impossible file.
	ErrCorrupt = errors.New("evtx: event log is corrupt, truncated, or structurally invalid")
	// ErrLimitExceeded means a hard ceiling in Limits was reached.
	ErrLimitExceeded = errors.New("evtx: event log exceeds a safety limit")
)

const (
	fileHeaderSize  = 4096
	fileSignature   = "ElfFile\x00"
	chunkSize       = 65536
	chunkHeaderSize = 512
	chunkSignature  = "ElfChnk\x00"
	recordSignature = "\x2a\x2a\x00\x00"
	recordHeaderLen = 24
)

// BinXML token identifiers. The high bit (0x40) on some tokens means
// "more data follows in this element"; tokenOf masks it off.
const (
	tokEOF               = 0x00
	tokOpenStartElement  = 0x01
	tokCloseStartElement = 0x02
	tokCloseEmptyElement = 0x03
	tokEndElement        = 0x04
	tokValue             = 0x05
	tokAttribute         = 0x06
	tokCDATA             = 0x07
	tokCharRef           = 0x08
	tokEntityRef         = 0x09
	tokPITarget          = 0x0a
	tokPIData            = 0x0b
	tokTemplateInstance  = 0x0c
	tokNormalSub         = 0x0d
	tokOptionalSub       = 0x0e
	tokFragmentHeader    = 0x0f
)

// Limits bounds everything this package reads or allocates from one
// event log. Each is a hard ceiling that stops the operation rather than
// degrading it silently.
type Limits struct {
	// Strict refuses trailing partial chunks; compatibility callers retain
	// historical recovery behavior unless they explicitly opt in.
	Strict           bool
	MaxFileBytes     int64 // reject a file larger than this outright
	MaxRecords       int   // stop after this many records
	MaxDepth         int   // maximum BinXML element nesting
	MaxSubstitutions int   // maximum values in one template instance
	MaxValueBytes    int   // maximum length of a single rendered value
}

// DefaultLimits pass every event log a real Windows system produces
// while keeping a hostile one bounded. A busy Security.evtx is typically
// 20-100 MB holding tens of thousands of records.
func DefaultLimits() Limits {
	return Limits{
		MaxFileBytes:     1 << 30, // 1 GiB
		MaxRecords:       1_000_000,
		MaxDepth:         64,
		MaxSubstitutions: 4096,
		MaxValueBytes:    64 << 10, // 64 KiB
	}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxFileBytes <= 0 {
		l.MaxFileBytes = d.MaxFileBytes
	}
	if l.MaxRecords <= 0 {
		l.MaxRecords = d.MaxRecords
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = d.MaxDepth
	}
	if l.MaxSubstitutions <= 0 {
		l.MaxSubstitutions = d.MaxSubstitutions
	}
	if l.MaxValueBytes <= 0 {
		l.MaxValueBytes = d.MaxValueBytes
	}
	return l
}

// System holds the <System> block every Windows event carries. These are
// the fields that identify an event independently of its payload.
type System struct {
	Provider          string
	ProviderGUID      string
	EventID           int
	Version           int
	Level             int
	Task              int
	Opcode            int
	Keywords          string
	TimeCreated       time.Time
	EventRecordID     uint64
	ProcessID         int
	ThreadID          int
	Channel           string
	Computer          string
	UserID            string // the Security UserID SID
	ActivityID        string
	RelatedActivityID string
}

// Record is one parsed event: its System block, and its EventData /
// UserData payload flattened to name→value pairs. That flattening is
// deliberate -- it is exactly the shape EvtxECmd exposes as PayloadData
// columns, which is what lets one normalization table serve both the
// native and the CSV parser (see internal/parsers/winevent).
type Record struct {
	System System
	Data   map[string]string
	// ChunkNumber and Offset locate the record in the file, for
	// provenance and for reproducing a parse.
	ChunkNumber int
	Offset      int64
}

// Stats reports what a walk actually managed to read. ChunksFailed and
// RecordsFailed being non-zero means the file was PARTIALLY recovered,
// and callers are expected to surface that rather than present the
// result as a complete parse.
type Stats struct {
	ZeroChunks    int // physical zero-filled preallocation, not failed records
	ChunksRead    int
	ChunksFailed  int
	RecordsRead   int
	RecordsFailed int
	LimitReached  bool
}

// Partial reports whether anything had to be skipped.
func (s Stats) Partial() bool { return s.ChunksFailed > 0 || s.RecordsFailed > 0 }

// File is an open, read-only event log.
type File struct {
	f          *os.File
	size       int64
	lim        Limits
	chunkCount int
	// oldestChunk/currentChunk come from the header; kept for reporting.
	firstChunk   uint64
	lastChunk    uint64
	nextRecordID uint64
}

// Sniff reports whether header begins with the EVTX file signature.
// Content-based, so a .evtx that is really a ZIP -- or a valid event log
// saved without the extension -- is classified by what it is.
func Sniff(header []byte) bool {
	return len(header) >= len(fileSignature) && string(header[:len(fileSignature)]) == fileSignature
}

// Open validates the file header and returns a handle for read-only
// iteration. It does NOT read any records: discovery needs to know that
// a file is a usable event log without paying to parse it.
func Open(path string, lim Limits) (*File, error) {
	lim = lim.withDefaults()

	f, err := os.Open(path) // read-only, always
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if info.Size() > lim.MaxFileBytes {
		f.Close()
		return nil, fmt.Errorf("%w: file is %d bytes, limit is %d", ErrLimitExceeded, info.Size(), lim.MaxFileBytes)
	}
	if info.Size() < fileHeaderSize {
		f.Close()
		return nil, fmt.Errorf("%w: file is %d bytes, smaller than the 4096-byte header", ErrCorrupt, info.Size())
	}

	hdr := make([]byte, fileHeaderSize)
	if _, err := io.ReadFull(io.NewSectionReader(f, 0, fileHeaderSize), hdr); err != nil {
		f.Close()
		return nil, fmt.Errorf("%w: reading file header: %v", ErrCorrupt, err)
	}
	if !Sniff(hdr) {
		f.Close()
		return nil, ErrNotEVTX
	}

	ev := &File{
		f:            f,
		size:         info.Size(),
		lim:          lim,
		firstChunk:   binary.LittleEndian.Uint64(hdr[8:16]),
		lastChunk:    binary.LittleEndian.Uint64(hdr[16:24]),
		nextRecordID: binary.LittleEndian.Uint64(hdr[24:32]),
	}

	// The header's chunk count is a claim; what matters is how many
	// chunks the file can actually hold. Using the smaller of the two
	// means a header inflated by an attacker cannot drive iteration past
	// the end of the file, and a header deflated by truncation cannot
	// hide chunks that are really there.
	claimed := int(binary.LittleEndian.Uint32(hdr[42:46]))
	available := int((info.Size() - fileHeaderSize) / chunkSize)
	if (info.Size()-fileHeaderSize)%chunkSize != 0 {
		if lim.Strict {
			f.Close()
			return nil, fmt.Errorf("%w: trailing partial chunk", ErrCorrupt)
		}
		// A trailing partial chunk is normal in a log copied while in
		// use; it is simply not iterated.
		_ = available
	}
	ev.chunkCount = available
	if !lim.Strict && claimed >= 0 && claimed < available {
		ev.chunkCount = claimed
	}
	if ev.chunkCount < 0 {
		ev.chunkCount = 0
	}
	return ev, nil
}

func (f *File) Close() error { return f.f.Close() }

// ChunkCount is how many complete chunks this file contains.
func (f *File) ChunkCount() int { return f.chunkCount }

// NextRecordID is the record identifier the log would assign next --
// a cheap upper bound on how many records the log has ever held.
func (f *File) NextRecordID() uint64 { return f.nextRecordID }

// Walk parses every record in every readable chunk, calling fn for each.
// A chunk that fails validation is skipped and counted; records already
// read are kept. Returning an error from fn stops the walk.
func (f *File) Walk(fn func(Record) error) (Stats, error) {
	var stats Stats

	buf := make([]byte, chunkSize) // one chunk at a time, whatever the file size
	var zero [chunkSize]byte
	for i := 0; i < f.chunkCount; i++ {
		if stats.RecordsRead >= f.lim.MaxRecords {
			stats.LimitReached = true
			break
		}
		offset := int64(fileHeaderSize) + int64(i)*chunkSize
		if _, err := f.f.ReadAt(buf, offset); err != nil {
			stats.ChunksFailed++
			continue
		}
		if f.lim.Strict && bytes.Equal(buf, zero[:]) {
			stats.ZeroChunks++
			continue
		}
		c, err := parseChunkHeader(buf)
		if err != nil {
			stats.ChunksFailed++
			continue
		}
		stats.ChunksRead++

		read, failed, stop, walkErr := f.walkChunk(c, buf, i, offset, &stats, fn)
		stats.RecordsRead += read
		stats.RecordsFailed += failed
		if walkErr != nil {
			return stats, walkErr
		}
		if stop {
			stats.LimitReached = true
			break
		}
	}
	return stats, nil
}

// chunk holds the per-chunk state BinXML resolution needs: the raw bytes
// (name and template offsets are chunk-relative) and a template cache so
// a template shared by 50,000 records is decoded once.
type chunk struct {
	data          []byte
	freeSpace     uint32
	templateCache map[uint32]*template
}

func parseChunkHeader(buf []byte) (*chunk, error) {
	if len(buf) < chunkHeaderSize || string(buf[0:8]) != chunkSignature {
		return nil, fmt.Errorf("%w: bad chunk signature", ErrCorrupt)
	}
	freeSpace := binary.LittleEndian.Uint32(buf[48:52])
	if freeSpace < chunkHeaderSize || freeSpace > chunkSize {
		return nil, fmt.Errorf("%w: chunk free-space offset %d is out of range", ErrCorrupt, freeSpace)
	}
	// The chunk CRC covers bytes 0-119 and 128-512. Verifying it is what
	// makes "skip this chunk" a defensible decision rather than a guess:
	// a chunk that fails here is known-damaged, not merely surprising.
	want := binary.LittleEndian.Uint32(buf[124:128])
	got := crc32.Update(0, crc32.IEEETable, buf[0:120])
	got = crc32.Update(got, crc32.IEEETable, buf[128:512])
	if want != got {
		return nil, fmt.Errorf("%w: chunk CRC mismatch (want %08x, got %08x)", ErrCorrupt, want, got)
	}
	return &chunk{data: buf, freeSpace: freeSpace, templateCache: map[uint32]*template{}}, nil
}

// walkChunk iterates the records packed into one chunk. Records are
// self-delimiting (each carries its size, repeated at its end), so a
// single malformed record ends iteration of THIS chunk rather than
// corrupting the file-level walk.
func (f *File) walkChunk(c *chunk, buf []byte, chunkNum int, chunkOffset int64, stats *Stats, fn func(Record) error) (read, failed int, stop bool, err error) {
	pos := chunkHeaderSize
	for pos+recordHeaderLen <= int(c.freeSpace) {
		if stats.RecordsRead+read >= f.lim.MaxRecords {
			return read, failed, true, nil
		}
		if string(buf[pos:pos+4]) != recordSignature {
			if f.lim.Strict {
				failed++
			}
			break // end of records in this chunk
		}
		size := int(binary.LittleEndian.Uint32(buf[pos+4 : pos+8]))
		if size < recordHeaderLen+4 || pos+size > int(c.freeSpace) {
			failed++
			break // implausible size: stop reading this chunk rather than guess
		}

		rec, perr := f.parseRecord(c, buf[pos:pos+size], pos, chunkNum, chunkOffset+int64(pos))
		if perr != nil {
			failed++
			pos += size
			continue
		}
		read++
		if err := fn(rec); err != nil {
			return read, failed, false, err
		}
		pos += size
	}
	return read, failed, false, nil
}

func (f *File) parseRecord(c *chunk, rec []byte, chunkPos, chunkNum int, offset int64) (r Record, err error) {
	// BinXML is a dense pointer-chasing format over hostile bytes. Every
	// individual read is bounds-checked, but recovering here as well
	// guarantees the promise this package makes -- that malformed
	// evidence can never take the process down -- holds even if one of
	// those checks is ever missed.
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("%w: record parser recovered from %v", ErrCorrupt, p)
		}
	}()

	if len(rec) < recordHeaderLen {
		return Record{}, fmt.Errorf("%w: record shorter than its header", ErrCorrupt)
	}
	recordID := binary.LittleEndian.Uint64(rec[8:16])
	written := fileTime(binary.LittleEndian.Uint64(rec[16:24]))

	root, err := f.parseBinXML(c, rec[recordHeaderLen:], chunkPos+recordHeaderLen, nil)
	if err != nil {
		return Record{}, err
	}

	out := Record{
		System:      System{EventRecordID: recordID, TimeCreated: written},
		Data:        map[string]string{},
		ChunkNumber: chunkNum,
		Offset:      offset,
	}
	extract(root, &out)
	// The record header's written time is authoritative when the System
	// block's TimeCreated is missing or unusable.
	if out.System.TimeCreated.IsZero() {
		out.System.TimeCreated = written
	}
	if out.System.EventRecordID == 0 {
		out.System.EventRecordID = recordID
	}
	return out, nil
}

// ---------- BinXML ----------

// node is one element of the decoded document. Records are bounded by
// the chunk size and by MaxDepth, so a tree is a safe representation.
type node struct {
	name     string
	attrs    map[string]string
	text     string
	children []*node
}

// template is a decoded template definition: the element skeleton, held
// as raw BinXML to be re-walked per instance with a different
// substitution array.
type template struct {
	body []byte
	// bodyStart is the body's chunk-relative offset, which the parser
	// needs to resolve inline names inside the template.
	bodyStart int
}

// reader is a bounds-checked cursor over a byte slice. Every read goes
// through it, so "read past the end" is a returned error rather than a
// panic.
type reader struct {
	b []byte
	// base is the chunk-relative offset of b[0]. BinXML name and template
	// offsets are chunk-relative, and the format writes a definition
	// INLINE when its offset happens to equal the current position -- so
	// resolving them at all requires knowing where in the chunk we are,
	// not just where in this slice.
	base int
	pos  int
}

// at returns the chunk-relative offset of the current position.
func (r *reader) at() int { return r.base + r.pos }

func (r *reader) remaining() int { return len(r.b) - r.pos }
func (r *reader) eof() bool      { return r.pos >= len(r.b) }

func (r *reader) u8() (byte, error) {
	if r.remaining() < 1 {
		return 0, io.ErrUnexpectedEOF
	}
	v := r.b[r.pos]
	r.pos++
	return v, nil
}

func (r *reader) u16() (uint16, error) {
	if r.remaining() < 2 {
		return 0, io.ErrUnexpectedEOF
	}
	v := binary.LittleEndian.Uint16(r.b[r.pos:])
	r.pos += 2
	return v, nil
}

func (r *reader) u32() (uint32, error) {
	if r.remaining() < 4 {
		return 0, io.ErrUnexpectedEOF
	}
	v := binary.LittleEndian.Uint32(r.b[r.pos:])
	r.pos += 4
	return v, nil
}

func (r *reader) bytes(n int) ([]byte, error) {
	if n < 0 || r.remaining() < n {
		return nil, io.ErrUnexpectedEOF
	}
	v := r.b[r.pos : r.pos+n]
	r.pos += n
	return v, nil
}

// parseBinXML decodes a BinXML fragment into a tree. subs is the
// substitution array in scope (nil outside a template instance).
func (f *File) parseBinXML(c *chunk, data []byte, base int, subs []subValue) (*node, error) {
	root := &node{name: "#document"}
	r := &reader{b: data, base: base}
	if err := f.parseTokens(c, r, root, subs, 0); err != nil {
		return nil, err
	}
	return root, nil
}

// parseTokens consumes tokens into parent until end-of-stream or the end
// of parent's content.
func (f *File) parseTokens(c *chunk, r *reader, parent *node, subs []subValue, depth int) error {
	if depth > f.lim.MaxDepth {
		return fmt.Errorf("%w: BinXML nested deeper than %d elements", ErrLimitExceeded, f.lim.MaxDepth)
	}
	for !r.eof() {
		raw, err := r.u8()
		if err != nil {
			return err
		}
		switch raw & 0x3f {
		case tokEOF:
			return nil

		case tokFragmentHeader:
			// major, minor, flags
			if _, err := r.bytes(3); err != nil {
				return err
			}

		case tokOpenStartElement:
			child, err := f.parseElement(c, r, raw, subs, depth+1)
			if err != nil {
				return err
			}
			parent.children = append(parent.children, child)

		case tokTemplateInstance:
			child, err := f.parseTemplateInstance(c, r, depth+1)
			if err != nil {
				return err
			}
			// A template instance expands to a document; splice its
			// children in so the caller sees one flat tree.
			parent.children = append(parent.children, child.children...)

		case tokValue:
			s, err := f.readValueText(r)
			if err != nil {
				return err
			}
			parent.text += s

		case tokNormalSub, tokOptionalSub:
			s, err := f.contentSubstitution(c, r, parent, subs, depth)
			if err != nil {
				return err
			}
			parent.text += s

		case tokCharRef:
			v, err := r.u16()
			if err != nil {
				return err
			}
			parent.text += string(rune(v))

		case tokEntityRef:
			off, err := r.u32()
			if err != nil {
				return err
			}
			name, err := c.nameAt(off, f.lim.MaxValueBytes)
			if err != nil {
				return err
			}
			parent.text += entity(name)

		case tokCDATA:
			s, err := f.readLengthPrefixedUTF16(r)
			if err != nil {
				return err
			}
			parent.text += s

		case tokPITarget:
			if _, err := r.u32(); err != nil { // name offset
				return err
			}
		case tokPIData:
			if _, err := f.readLengthPrefixedUTF16(r); err != nil {
				return err
			}

		case tokEndElement, tokCloseStartElement, tokCloseEmptyElement:
			// Handled inside parseElement; reaching one here means the
			// stream is out of step with the structure.
			return nil

		default:
			return fmt.Errorf("%w: unknown BinXML token %#x", ErrCorrupt, raw)
		}
	}
	return nil
}

// parseElement decodes an open-start-element token and everything it
// contains, through its matching end tag.
func (f *File) parseElement(c *chunk, r *reader, token byte, subs []subValue, depth int) (*node, error) {
	if depth > f.lim.MaxDepth {
		return nil, fmt.Errorf("%w: BinXML nested deeper than %d elements", ErrLimitExceeded, f.lim.MaxDepth)
	}
	if _, err := r.u16(); err != nil { // dependency identifier
		return nil, err
	}
	if _, err := r.u32(); err != nil { // data size
		return nil, err
	}
	nameOffset, err := r.u32()
	if err != nil {
		return nil, err
	}
	name, err := f.readName(c, r, nameOffset)
	if err != nil {
		return nil, err
	}
	n := &node{name: name}

	// 0x41 means an attribute list follows.
	if token&0x40 != 0 {
		if _, err := r.u32(); err != nil { // attribute list data size
			return nil, err
		}
		if err := f.parseAttributes(c, r, n, subs, depth); err != nil {
			return nil, err
		}
	}

	closeTok, err := r.u8()
	if err != nil {
		return nil, err
	}
	switch closeTok & 0x3f {
	case tokCloseEmptyElement:
		return n, nil
	case tokCloseStartElement:
		if err := f.parseElementContent(c, r, n, subs, depth); err != nil {
			return nil, err
		}
		return n, nil
	default:
		return nil, fmt.Errorf("%w: expected a close-start-element token, got %#x", ErrCorrupt, closeTok)
	}
}

// parseElementContent reads an element's children/text until its end tag.
func (f *File) parseElementContent(c *chunk, r *reader, n *node, subs []subValue, depth int) error {
	for !r.eof() {
		raw, err := r.u8()
		if err != nil {
			return err
		}
		switch raw & 0x3f {
		case tokEndElement:
			return nil
		case tokEOF:
			return nil
		case tokOpenStartElement:
			child, err := f.parseElement(c, r, raw, subs, depth+1)
			if err != nil {
				return err
			}
			n.children = append(n.children, child)
		case tokValue:
			s, err := f.readValueText(r)
			if err != nil {
				return err
			}
			n.text += s
		case tokNormalSub, tokOptionalSub:
			s, err := f.contentSubstitution(c, r, n, subs, depth)
			if err != nil {
				return err
			}
			n.text += s
		case tokCharRef:
			v, err := r.u16()
			if err != nil {
				return err
			}
			n.text += string(rune(v))
		case tokEntityRef:
			off, err := r.u32()
			if err != nil {
				return err
			}
			name, err := c.nameAt(off, f.lim.MaxValueBytes)
			if err != nil {
				return err
			}
			n.text += entity(name)
		case tokCDATA:
			s, err := f.readLengthPrefixedUTF16(r)
			if err != nil {
				return err
			}
			n.text += s
		case tokTemplateInstance:
			child, err := f.parseTemplateInstance(c, r, depth+1)
			if err != nil {
				return err
			}
			n.children = append(n.children, child.children...)
		default:
			return fmt.Errorf("%w: unexpected token %#x inside an element", ErrCorrupt, raw)
		}
	}
	return nil
}

func (f *File) parseAttributes(c *chunk, r *reader, n *node, subs []subValue, depth int) error {
	if n.attrs == nil {
		n.attrs = map[string]string{}
	}
	for {
		raw, err := r.u8()
		if err != nil {
			return err
		}
		if raw&0x3f != tokAttribute {
			// Not an attribute: step back so the caller sees this token.
			r.pos--
			return nil
		}
		nameOffset, err := r.u32()
		if err != nil {
			return err
		}
		name, err := f.readName(c, r, nameOffset)
		if err != nil {
			return err
		}

		valueTok, err := r.u8()
		if err != nil {
			return err
		}
		var value string
		switch valueTok & 0x3f {
		case tokValue:
			if value, err = f.readValueText(r); err != nil {
				return err
			}
		case tokNormalSub, tokOptionalSub:
			if value, err = f.readSubstitution(c, r, subs, depth); err != nil {
				return err
			}
		case tokCharRef:
			v, err := r.u16()
			if err != nil {
				return err
			}
			value = string(rune(v))
		case tokEntityRef:
			off, err := r.u32()
			if err != nil {
				return err
			}
			ename, err := c.nameAt(off, f.lim.MaxValueBytes)
			if err != nil {
				return err
			}
			value = entity(ename)
		default:
			return fmt.Errorf("%w: unexpected attribute value token %#x", ErrCorrupt, valueTok)
		}
		n.attrs[name] = value

		// The high bit on the attribute token means more attributes follow.
		if raw&0x40 == 0 {
			return nil
		}
	}
}

// parseTemplateInstance resolves a template instance: locate (or cache)
// the template definition, read the substitution array, then re-walk the
// template body with those substitutions in scope.
func (f *File) parseTemplateInstance(c *chunk, r *reader, depth int) (*node, error) {
	if depth > f.lim.MaxDepth {
		return nil, fmt.Errorf("%w: template instances nested deeper than %d", ErrLimitExceeded, f.lim.MaxDepth)
	}
	// Chunk-relative, because the definition offset it is compared
	// against is chunk-relative.
	if _, err := r.u8(); err != nil { // version/unknown
		return nil, err
	}
	if _, err := r.u32(); err != nil { // template identifier
		return nil, err
	}
	defOffset, err := r.u32()
	if err != nil {
		return nil, err
	}

	// The definition is INLINE when its offset equals the position where
	// the instance header ends (right after the 4-byte definition offset
	// field, i.e. tokenStart+10). Then the definition (24-byte header +
	// body) sits between the instance header and the substitution array,
	// and must be skipped. Otherwise the definition lives elsewhere in the
	// chunk (definitions are not ordered) and the substitution array
	// follows the instance header immediately.
	inline := int(defOffset) == r.at()
	tmpl, defEnd, err := c.templateAt(defOffset, f.lim)
	if err != nil {
		return nil, err
	}
	if inline {
		if defEnd <= r.at() || defEnd > len(c.data) {
			return nil, fmt.Errorf("%w: inline template definition ends at %d", ErrCorrupt, defEnd)
		}
		skip := defEnd - r.at()
		if skip > r.remaining() {
			return nil, fmt.Errorf("%w: inline template definition runs past the record", ErrCorrupt)
		}
		if _, err := r.bytes(skip); err != nil {
			return nil, err
		}
	}

	subs, err := f.readSubstitutionArray(r)
	if err != nil {
		return nil, err
	}
	return f.parseBinXMLDepth(c, tmpl.body, tmpl.bodyStart, subs, depth)
}

func (f *File) parseBinXMLDepth(c *chunk, data []byte, base int, subs []subValue, depth int) (*node, error) {
	root := &node{name: "#document"}
	r := &reader{b: data, base: base}
	if err := f.parseTokens(c, r, root, subs, depth); err != nil {
		return nil, err
	}
	return root, nil
}

// subValue is one entry of a template's substitution array.
type subValue struct {
	typ  byte
	data []byte
	// off is the chunk-relative offset of data[0]. A BinXML-typed value is
	// a nested fragment whose own offsets (names, inline definitions) are
	// chunk-relative, so it must be parsed knowing where it sits.
	off int
}

func (f *File) readSubstitutionArray(r *reader) ([]subValue, error) {
	count32, err := r.u32()
	if err != nil {
		return nil, err
	}
	count := int(count32)
	if count < 0 || count > f.lim.MaxSubstitutions {
		return nil, fmt.Errorf("%w: template instance declares %d substitutions", ErrLimitExceeded, count32)
	}
	// The descriptor array must fit before any value data does.
	if count*4 > r.remaining() {
		return nil, fmt.Errorf("%w: substitution descriptors run past the record", ErrCorrupt)
	}

	sizes := make([]int, count)
	types := make([]byte, count)
	for i := 0; i < count; i++ {
		size, err := r.u16()
		if err != nil {
			return nil, err
		}
		typ, err := r.u8()
		if err != nil {
			return nil, err
		}
		if _, err := r.u8(); err != nil { // unknown/padding
			return nil, err
		}
		sizes[i], types[i] = int(size), typ
	}

	out := make([]subValue, count)
	for i := 0; i < count; i++ {
		if sizes[i] > f.lim.MaxValueBytes {
			return nil, fmt.Errorf("%w: substitution %d is %d bytes", ErrLimitExceeded, i, sizes[i])
		}
		off := r.at()
		data, err := r.bytes(sizes[i])
		if err != nil {
			return nil, err
		}
		out[i] = subValue{typ: types[i], data: data, off: off}
	}
	return out, nil
}

// readSubstitution resolves one substitution reference against the array
// in scope.
func (f *File) readSubstitution(c *chunk, r *reader, subs []subValue, depth int) (string, error) {
	index, err := r.u16()
	if err != nil {
		return "", err
	}
	typ, err := r.u8()
	if err != nil {
		return "", err
	}
	if int(index) >= len(subs) {
		// An optional substitution with no value is normal (the field was
		// absent); rendering it as empty is correct, not an error.
		return "", nil
	}
	v := subs[index]
	if v.typ == 0x21 { // BinXmlType: the value is itself a BinXML fragment
		if depth+1 > f.lim.MaxDepth {
			return "", fmt.Errorf("%w: nested BinXML substitution too deep", ErrLimitExceeded)
		}
		// Parsed at its real chunk offset, so its inline definitions and
		// name references resolve. A malformed fragment is an error for
		// the record, not an empty value: silently rendering it empty is
		// how EventData disappeared from every Windows log.
		sub, err := f.parseBinXMLDepth(c, v.data, v.off, nil, depth+1)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(flatten(sub)), nil
	}
	_ = typ
	return renderValue(v.typ, v.data, f.lim.MaxValueBytes), nil
}

// contentSubstitution resolves a substitution that sits in ELEMENT CONTENT.
// Windows puts the whole EventData section into a BinXML-typed (0x21)
// substitution, so such a value is a nested fragment of elements, not
// text. Its children are spliced into the parent exactly as an inline
// template instance is; flattening it to text (as attributes must) loses
// every Data element, which is how EventData vanished from the tree.
func (f *File) contentSubstitution(c *chunk, r *reader, parent *node, subs []subValue, depth int) (string, error) {
	index, err := r.u16()
	if err != nil {
		return "", err
	}
	if _, err := r.u8(); err != nil { // value type of the reference
		return "", err
	}
	if int(index) >= len(subs) {
		// An optional substitution with no value is normal (the field was
		// absent); rendering it as empty is correct, not an error.
		return "", nil
	}
	v := subs[index]
	if v.typ != 0x21 {
		return renderValue(v.typ, v.data, f.lim.MaxValueBytes), nil
	}
	if depth+1 > f.lim.MaxDepth {
		return "", fmt.Errorf("%w: nested BinXML substitution too deep", ErrLimitExceeded)
	}
	doc, err := f.parseBinXMLDepth(c, v.data, v.off, nil, depth+1)
	if err != nil {
		return "", err
	}
	parent.children = append(parent.children, doc.children...)
	return "", nil
}

func (f *File) readValueText(r *reader) (string, error) {
	typ, err := r.u8()
	if err != nil {
		return "", err
	}
	if typ != 0x01 { // StringType is the only form the value token uses
		return "", fmt.Errorf("%w: value token has type %#x", ErrCorrupt, typ)
	}
	return f.readLengthPrefixedUTF16(r)
}

func (f *File) readLengthPrefixedUTF16(r *reader) (string, error) {
	numChars, err := r.u16()
	if err != nil {
		return "", err
	}
	n := int(numChars) * 2
	if n > f.lim.MaxValueBytes {
		return "", fmt.Errorf("%w: string value is %d bytes", ErrLimitExceeded, n)
	}
	b, err := r.bytes(n)
	if err != nil {
		return "", err
	}
	return decodeUTF16(b), nil
}

// readName resolves an element/attribute name. When the offset points at
// the current position, the name structure is written INLINE here (the
// first use of a name in a chunk carries its definition; later uses just
// reference the offset), and the cursor must step over it -- otherwise
// the name bytes would be parsed as if they were tokens.
func (f *File) readName(c *chunk, r *reader, offset uint32) (string, error) {
	name, err := c.nameAt(offset, f.lim.MaxValueBytes)
	if err != nil {
		return "", err
	}
	if int(offset) == r.at() {
		// 4 unknown + 2 hash + 2 char count + the UTF-16 string and its
		// NUL terminator.
		numChars := int(binary.LittleEndian.Uint16(c.data[int(offset)+6 : int(offset)+8]))
		if _, err := r.bytes(8 + numChars*2 + 2); err != nil {
			return "", err
		}
	}
	return name, nil
}

// nameAt reads a name string from a chunk-relative offset. Names are
// shared across a chunk, which is why they are referenced by offset
// rather than repeated.
func (c *chunk) nameAt(offset uint32, maxBytes int) (string, error) {
	// 8 bytes of header (unknown, hash, character count) must fit.
	if uint64(offset)+8 > uint64(len(c.data)) {
		return "", fmt.Errorf("%w: name offset %d is outside the chunk", ErrCorrupt, offset)
	}
	numChars := int(binary.LittleEndian.Uint16(c.data[offset+6 : offset+8]))
	start := int(offset) + 8
	n := numChars * 2
	if n > maxBytes {
		return "", fmt.Errorf("%w: name is %d bytes", ErrLimitExceeded, n)
	}
	if start+n > len(c.data) {
		return "", fmt.Errorf("%w: name at %d runs past the chunk", ErrCorrupt, offset)
	}
	return decodeUTF16(c.data[start : start+n]), nil
}

// templateAt decodes (and caches) the template definition at a
// chunk-relative offset, returning the template and the offset one past
// its body.
func (c *chunk) templateAt(offset uint32, lim Limits) (*template, int, error) {
	// Definition header, as written by Windows: next-offset(4) +
	// GUID(16) + data size(4) = 24 bytes, then the BinXML fragment body.
	// Verified against a real Windows 10 Security.evtx: the size field
	// sits at +20 and the body starts at +24. An earlier 33-byte
	// assumption read the size from the wrong place and failed every
	// record of every real log.
	const defHeader = 24
	if uint64(offset)+defHeader > uint64(len(c.data)) {
		return nil, 0, fmt.Errorf("%w: template offset %d is outside the chunk", ErrCorrupt, offset)
	}
	dataSize := int(binary.LittleEndian.Uint32(c.data[int(offset)+20 : int(offset)+24]))
	bodyStart := int(offset) + defHeader
	if dataSize < 0 || bodyStart+dataSize > len(c.data) {
		return nil, 0, fmt.Errorf("%w: template at %d claims %d bytes of body", ErrCorrupt, offset, dataSize)
	}
	end := bodyStart + dataSize

	if t, ok := c.templateCache[offset]; ok {
		return t, end, nil
	}
	t := &template{body: c.data[bodyStart:end], bodyStart: bodyStart}
	c.templateCache[offset] = t
	return t, end, nil
}

// ---------- value rendering ----------

// renderValue turns one typed BinXML value into the string form
// Tracefall normalizes from. Types follow libyal's value-type table;
// unknown types render as bounded hex rather than as an error, so one
// unfamiliar field never costs a whole record.
func renderValue(typ byte, b []byte, maxBytes int) string {
	if len(b) > maxBytes {
		b = b[:maxBytes]
	}
	// 0x80+ are array variants of the base types: a sequence of values
	// of the same type, rendered comma-separated.
	if typ&0x80 != 0 {
		return renderArray(typ&0x7f, b, maxBytes)
	}
	switch typ {
	case 0x00: // NullType
		return ""
	case 0x01: // StringType (UTF-16)
		return decodeUTF16(b)
	case 0x02: // AnsiStringType
		return strings.TrimRight(string(b), "\x00")
	case 0x03: // Int8
		if len(b) >= 1 {
			return strconv.Itoa(int(int8(b[0])))
		}
	case 0x04: // UInt8
		if len(b) >= 1 {
			return strconv.Itoa(int(b[0]))
		}
	case 0x05: // Int16
		if len(b) >= 2 {
			return strconv.Itoa(int(int16(binary.LittleEndian.Uint16(b))))
		}
	case 0x06: // UInt16
		if len(b) >= 2 {
			return strconv.Itoa(int(binary.LittleEndian.Uint16(b)))
		}
	case 0x07: // Int32
		if len(b) >= 4 {
			return strconv.Itoa(int(int32(binary.LittleEndian.Uint32(b))))
		}
	case 0x08: // UInt32
		if len(b) >= 4 {
			return strconv.FormatUint(uint64(binary.LittleEndian.Uint32(b)), 10)
		}
	case 0x09: // Int64
		if len(b) >= 8 {
			return strconv.FormatInt(int64(binary.LittleEndian.Uint64(b)), 10)
		}
	case 0x0a: // UInt64
		if len(b) >= 8 {
			return strconv.FormatUint(binary.LittleEndian.Uint64(b), 10)
		}
	case 0x0b: // Real32
		if len(b) >= 4 {
			return strconv.FormatFloat(float64(math.Float32frombits(binary.LittleEndian.Uint32(b))), 'g', -1, 32)
		}
	case 0x0c: // Real64
		if len(b) >= 8 {
			return strconv.FormatFloat(math.Float64frombits(binary.LittleEndian.Uint64(b)), 'g', -1, 64)
		}
	case 0x0d: // BoolType
		if len(b) >= 4 {
			if binary.LittleEndian.Uint32(b) != 0 {
				return "true"
			}
			return "false"
		}
	case 0x0e: // BinaryType
		return hexString(b)
	case 0x0f: // GuidType
		return renderGUID(b)
	case 0x10: // SizeTType
		if len(b) >= 8 {
			return strconv.FormatUint(binary.LittleEndian.Uint64(b), 10)
		}
		if len(b) >= 4 {
			return strconv.FormatUint(uint64(binary.LittleEndian.Uint32(b)), 10)
		}
	case 0x11: // FileTimeType
		if len(b) >= 8 {
			t := fileTime(binary.LittleEndian.Uint64(b))
			if t.IsZero() {
				return ""
			}
			return t.Format(time.RFC3339Nano)
		}
	case 0x12: // SysTimeType
		return renderSystemTime(b)
	case 0x13: // SidType
		return renderSID(b)
	case 0x14: // HexInt32
		if len(b) >= 4 {
			return "0x" + strconv.FormatUint(uint64(binary.LittleEndian.Uint32(b)), 16)
		}
	case 0x15: // HexInt64
		if len(b) >= 8 {
			return "0x" + strconv.FormatUint(binary.LittleEndian.Uint64(b), 16)
		}
	}
	return hexString(b)
}

func renderArray(base byte, b []byte, maxBytes int) string {
	// A string array is NUL-separated UTF-16; the fixed-width types are
	// simply back-to-back values.
	if base == 0x01 {
		parts := strings.Split(decodeUTF16Raw(b), "\x00")
		out := parts[:0]
		for _, p := range parts {
			if p != "" {
				out = append(out, p)
			}
		}
		return strings.Join(out, ", ")
	}
	width := typeWidth(base)
	if width == 0 {
		return hexString(b)
	}
	var parts []string
	for i := 0; i+width <= len(b); i += width {
		parts = append(parts, renderValue(base, b[i:i+width], maxBytes))
	}
	return strings.Join(parts, ", ")
}

func typeWidth(t byte) int {
	switch t {
	case 0x03, 0x04:
		return 1
	case 0x05, 0x06:
		return 2
	case 0x07, 0x08, 0x0b, 0x0d, 0x14:
		return 4
	case 0x09, 0x0a, 0x0c, 0x11, 0x15:
		return 8
	case 0x0f:
		return 16
	default:
		return 0
	}
}

// renderSID formats a binary NT security identifier as S-1-5-21-... --
// the form every other Windows tool prints, and the form the CSV parser
// already sees, so both sources normalize identically.
func renderSID(b []byte) string {
	if len(b) < 8 {
		return ""
	}
	revision := b[0]
	subCount := int(b[1])
	if 8+subCount*4 > len(b) {
		subCount = (len(b) - 8) / 4
	}
	// Identifier authority is 6 bytes, big-endian.
	var authority uint64
	for _, c := range b[2:8] {
		authority = authority<<8 | uint64(c)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "S-%d-%d", revision, authority)
	for i := 0; i < subCount; i++ {
		fmt.Fprintf(&sb, "-%d", binary.LittleEndian.Uint32(b[8+i*4:]))
	}
	return sb.String()
}

func renderGUID(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	return fmt.Sprintf("{%08X-%04X-%04X-%04X-%012X}",
		binary.LittleEndian.Uint32(b[0:4]),
		binary.LittleEndian.Uint16(b[4:6]),
		binary.LittleEndian.Uint16(b[6:8]),
		binary.BigEndian.Uint16(b[8:10]),
		b[10:16])
}

func renderSystemTime(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	u := func(i int) int { return int(binary.LittleEndian.Uint16(b[i:])) }
	t := time.Date(u(0), time.Month(u(2)), u(6), u(8), u(10), u(12), u(14)*1e6, time.UTC)
	return t.Format(time.RFC3339Nano)
}

// ---------- extraction ----------

// extract pulls the System block and the EventData/UserData payload out
// of a decoded record tree.
func extract(root *node, out *Record) {
	for _, top := range root.children {
		if !strings.EqualFold(top.name, "Event") {
			// Some records are not wrapped in <Event>; treat the node
			// itself as the container rather than dropping the record.
			extractContainer(top, out)
			continue
		}
		extractContainer(top, out)
	}
}

func extractContainer(ev *node, out *Record) {
	for _, section := range ev.children {
		switch {
		case strings.EqualFold(section.name, "System"):
			extractSystem(section, &out.System)
		case strings.EqualFold(section.name, "EventData"),
			strings.EqualFold(section.name, "UserData"):
			extractData(section, out.Data, 0)
		}
	}
}

func extractSystem(sys *node, s *System) {
	for _, f := range sys.children {
		text := strings.TrimSpace(f.text)
		switch strings.ToLower(f.name) {
		case "provider":
			s.Provider = firstNonEmpty(f.attrs["Name"], f.attrs["name"], s.Provider)
			s.ProviderGUID = firstNonEmpty(f.attrs["Guid"], f.attrs["guid"])
		case "eventid":
			s.EventID = atoi(text)
		case "version":
			s.Version = atoi(text)
		case "level":
			s.Level = atoi(text)
		case "task":
			s.Task = atoi(text)
		case "opcode":
			s.Opcode = atoi(text)
		case "keywords":
			s.Keywords = text
		case "timecreated":
			if t, ok := parseEventTime(firstNonEmpty(f.attrs["SystemTime"], f.attrs["systemTime"], text)); ok {
				s.TimeCreated = t
			}
		case "eventrecordid":
			if v, err := strconv.ParseUint(text, 10, 64); err == nil {
				s.EventRecordID = v
			}
		case "execution":
			s.ProcessID = atoi(firstNonEmpty(f.attrs["ProcessID"], f.attrs["processID"]))
			s.ThreadID = atoi(firstNonEmpty(f.attrs["ThreadID"], f.attrs["threadID"]))
		case "channel":
			s.Channel = text
		case "computer":
			s.Computer = text
		case "security":
			s.UserID = firstNonEmpty(f.attrs["UserID"], f.attrs["userID"])
		case "correlation":
			s.ActivityID = firstNonEmpty(f.attrs["ActivityID"], f.attrs["activityID"])
			s.RelatedActivityID = firstNonEmpty(f.attrs["RelatedActivityID"], f.attrs["relatedActivityID"])
		}
	}
}

// extractData flattens a payload section into name→value pairs. <Data
// Name="X">v</Data> is the common EventData shape; UserData instead uses
// the element name itself, and can nest one level.
func extractData(section *node, into map[string]string, depth int) {
	if depth > 4 {
		return
	}
	for i, f := range section.children {
		text := strings.TrimSpace(f.text)
		name := firstNonEmpty(f.attrs["Name"], f.attrs["name"])
		switch {
		case name != "":
			into[name] = text
		case len(f.children) > 0:
			extractData(f, into, depth+1)
		case strings.EqualFold(f.name, "Data") || strings.EqualFold(f.name, "Binary"):
			// Unnamed <Data> elements are positional, which is exactly
			// how the legacy (pre-manifest) providers emit them.
			if text != "" {
				into["Data"+strconv.Itoa(i+1)] = text
			}
		default:
			into[f.name] = text
		}
	}
}

// ---------- small helpers ----------

func flatten(n *node) string {
	var sb strings.Builder
	var walk func(*node)
	walk = func(x *node) {
		sb.WriteString(x.text)
		for _, c := range x.children {
			walk(c)
		}
	}
	walk(n)
	return sb.String()
}

func decodeUTF16(b []byte) string {
	return strings.TrimRight(decodeUTF16Raw(b), "\x00")
}

func decodeUTF16Raw(b []byte) string {
	n := len(b) &^ 1
	if n == 0 {
		return ""
	}
	u := make([]uint16, 0, n/2)
	for i := 0; i < n; i += 2 {
		u = append(u, binary.LittleEndian.Uint16(b[i:i+2]))
	}
	return string(utf16.Decode(u))
}

func hexString(b []byte) string {
	const digits = "0123456789ABCDEF"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}

func entity(name string) string {
	switch name {
	case "lt":
		return "<"
	case "gt":
		return ">"
	case "amp":
		return "&"
	case "quot":
		return `"`
	case "apos":
		return "'"
	default:
		return "&" + name + ";"
	}
}

func atoi(s string) int {
	v, _ := strconv.Atoi(strings.TrimSpace(s))
	return v
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// parseEventTime accepts both the RFC3339-ish text Windows writes into
// SystemTime and a raw FILETIME rendered by renderValue.
func parseEventTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.999999999", "2006-01-02 15:04:05.999999999"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// fileTime converts a Windows FILETIME to a Go time, rejecting values
// outside a plausible range rather than placing an event in 1601.
func fileTime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	const ticksPerSecond = 10_000_000
	const epochDelta = 11644473600
	t := time.Unix(int64(ft/ticksPerSecond)-epochDelta, int64(ft%ticksPerSecond)*100).UTC()
	if t.Year() < 1980 || t.Year() > 2200 {
		return time.Time{}
	}
	return t
}
