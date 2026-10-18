// Package evtxgen builds synthetic Windows Event Log (.evtx) files in
// memory, for TEST FIXTURES ONLY.
//
// Tracefall's EVTX tests need logs whose every field is known exactly
// and that regenerate byte-for-byte on any machine. Real event logs
// cannot serve that purpose: they are large, they carry real hostnames,
// usernames, SIDs and command lines, and they cannot be committed to a
// repository. Every log produced here is entirely invented -- see
// testdata/native_samples/README.md.
//
// The writer emits the same structures a real log uses -- a chunk with a
// CRC, name strings referenced by chunk offset, a template defined once
// and instantiated per record with a substitution array -- because a
// fixture that avoided those paths would not test the reader that has to
// handle them.
//
// It lives outside internal/evtx so no production code can import an
// event-log writer by accident.
package evtxgen

import (
	"encoding/binary"
	"hash/crc32"
	"sort"
	"time"
	"unicode/utf16"
)

const (
	fileHeaderSize  = 4096
	chunkSize       = 65536
	chunkHeaderSize = 512
)

// Event is one synthetic event to write.
type Event struct {
	RecordID  uint64
	Timestamp time.Time
	Provider  string
	Channel   string
	Computer  string
	EventID   int
	Level     int
	Task      int
	Opcode    int
	Keywords  string
	ProcessID int
	ThreadID  int
	UserID    string // a SID string, e.g. "S-1-5-18"
	// Data is the EventData payload as name→value pairs, exactly the
	// shape <Data Name="k">v</Data> produces.
	Data map[string]string
}

// chunkBuilder assembles one chunk: name strings and template
// definitions are written inline inside the first record that uses them
// and referenced by chunk offset from every record after, which is how
// real logs keep themselves compact.
type chunkBuilder struct {
	buf []byte // the whole chunk, indexed from the chunk start

	// nameOffsets records where each name string was written, so the
	// second and later uses reference it by offset instead of repeating
	// it -- exactly what a real chunk does.
	nameOffsets map[string]uint32
}

// Build writes a complete .evtx file containing events. Events are
// packed into as many 64 KiB chunks as they need, so passing enough
// events produces a genuinely multi-chunk file.
func Build(events []Event) []byte {
	out := make([]byte, fileHeaderSize)

	var chunks [][]byte
	remaining := events
	for len(remaining) > 0 {
		c, used := buildChunk(remaining)
		if used == 0 {
			// A single event too large for a chunk would loop forever;
			// fixtures never do this, but refuse rather than hang.
			break
		}
		chunks = append(chunks, c)
		remaining = remaining[used:]
	}
	if len(chunks) == 0 {
		chunks = append(chunks, emptyChunk())
	}

	writeFileHeader(out, len(chunks), lastRecordID(events)+1)
	for _, c := range chunks {
		out = append(out, c...)
	}
	return out
}

func lastRecordID(events []Event) uint64 {
	var max uint64
	for _, e := range events {
		if e.RecordID > max {
			max = e.RecordID
		}
	}
	return max
}

func writeFileHeader(hdr []byte, chunkCount int, nextRecordID uint64) {
	copy(hdr[0:8], "ElfFile\x00")
	binary.LittleEndian.PutUint64(hdr[8:16], 0)                     // first chunk number
	binary.LittleEndian.PutUint64(hdr[16:24], uint64(chunkCount-1)) // last chunk number
	binary.LittleEndian.PutUint64(hdr[24:32], nextRecordID)         // next record identifier
	binary.LittleEndian.PutUint32(hdr[32:36], 128)                  // header size
	binary.LittleEndian.PutUint16(hdr[36:38], 1)                    // minor version
	binary.LittleEndian.PutUint16(hdr[38:40], 3)                    // major version
	binary.LittleEndian.PutUint16(hdr[40:42], fileHeaderSize)       // header block size
	binary.LittleEndian.PutUint32(hdr[42:46], uint32(chunkCount))   // number of chunks
	binary.LittleEndian.PutUint32(hdr[120:124], 0)                  // file flags
	binary.LittleEndian.PutUint32(hdr[124:128], crc32.ChecksumIEEE(hdr[0:120]))
}

func emptyChunk() []byte {
	b := &chunkBuilder{buf: make([]byte, chunkHeaderSize), nameOffsets: map[string]uint32{}}
	return b.finish(0, 0, 0, 0)
}

// buildChunk packs as many events as fit into one chunk, returning the
// chunk and how many events it consumed.
func buildChunk(events []Event) ([]byte, int) {
	b := &chunkBuilder{buf: make([]byte, chunkHeaderSize), nameOffsets: map[string]uint32{}}

	used := 0
	for _, e := range events {
		rec := b.buildRecord(e)
		if len(b.buf)+len(rec) > chunkSize {
			break
		}
		b.buf = append(b.buf, rec...)
		used++
	}
	if used == 0 {
		return nil, 0
	}
	first, last := events[0].RecordID, events[used-1].RecordID
	return b.finish(first, last, first, last), used
}

// finish writes the chunk header (including both CRCs) and pads the
// chunk to its fixed 64 KiB size.
func (b *chunkBuilder) finish(firstNum, lastNum, firstID, lastID uint64) []byte {
	freeSpace := uint32(len(b.buf))

	out := make([]byte, chunkSize)
	copy(out, b.buf)

	copy(out[0:8], "ElfChnk\x00")
	binary.LittleEndian.PutUint64(out[8:16], firstNum)
	binary.LittleEndian.PutUint64(out[16:24], lastNum)
	binary.LittleEndian.PutUint64(out[24:32], firstID)
	binary.LittleEndian.PutUint64(out[32:40], lastID)
	binary.LittleEndian.PutUint32(out[40:44], 128)       // header size
	binary.LittleEndian.PutUint32(out[44:48], freeSpace) // last record data offset
	binary.LittleEndian.PutUint32(out[48:52], freeSpace) // free space offset
	binary.LittleEndian.PutUint32(out[52:56], crc32.ChecksumIEEE(out[chunkHeaderSize:freeSpace]))

	// The chunk CRC covers bytes 0-119 and 128-512 -- deliberately
	// excluding the CRC field itself.
	sum := crc32.Update(0, crc32.IEEETable, out[0:120])
	sum = crc32.Update(sum, crc32.IEEETable, out[128:512])
	binary.LittleEndian.PutUint32(out[124:128], sum)
	return out
}

// buildRecord serializes one event record: header, BinXML body, and the
// trailing size copy.
func (b *chunkBuilder) buildRecord(e Event) []byte {
	// The body's chunk offset is needed up front, because inline name and
	// template definitions are referenced by absolute chunk offset.
	bodyStart := len(b.buf) + 24

	body := b.buildBinXML(e, bodyStart)
	size := 24 + len(body) + 4
	if pad := size % 8; pad != 0 {
		size += 8 - pad
	}

	rec := make([]byte, size)
	copy(rec[0:4], []byte{0x2a, 0x2a, 0x00, 0x00})
	binary.LittleEndian.PutUint32(rec[4:8], uint32(size))
	binary.LittleEndian.PutUint64(rec[8:16], e.RecordID)
	binary.LittleEndian.PutUint64(rec[16:24], toFileTime(e.Timestamp))
	copy(rec[24:], body)
	binary.LittleEndian.PutUint32(rec[size-4:], uint32(size))
	return rec
}

// dataKeys returns an event's payload keys in a fixed order, so a
// fixture is byte-identical every time it is generated.
func dataKeys(e Event) []string {
	keys := make([]string, 0, len(e.Data))
	for k := range e.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// buildBinXML emits a record body. The document is written as a template
// instance whose definition is inline: the template holds the element
// skeleton with substitution holes, and the instance supplies the
// values. That is what a real log does, and it is the path worth
// testing.
func (b *chunkBuilder) buildBinXML(e Event, base int) []byte {
	keys := dataKeys(e)

	// Substitution values, in the order the template refers to them.
	subs := []subValue{
		stringSub(e.Provider),          // 0
		uint16Sub(uint16(e.EventID)),   // 1
		uint8Sub(uint8(e.Level)),       // 2
		uint16Sub(uint16(e.Task)),      // 3
		uint8Sub(uint8(e.Opcode)),      // 4
		stringSub(e.Keywords),          // 5
		fileTimeSub(e.Timestamp),       // 6
		uint64Sub(e.RecordID),          // 7
		uint32Sub(uint32(e.ProcessID)), // 8
		uint32Sub(uint32(e.ThreadID)),  // 9
		stringSub(e.Channel),           // 10
		stringSub(e.Computer),          // 11
		sidSub(e.UserID),               // 12
	}
	for _, k := range keys {
		subs = append(subs, stringSub(e.Data[k]))
	}

	var out []byte
	// Fragment header.
	out = append(out, 0x0f, 0x01, 0x01, 0x00)

	// Template instance token, then the inline template definition.
	out = append(out, 0x0c)
	out = append(out, 0x01)      // version
	out = appendU32(out, 0x1000) // template identifier
	// Inline: the definition starts immediately after this 10-byte
	// instance header (token, version, id, definition offset), so the
	// offset written here is the chunk-relative position just past it.
	defOffset := uint32(base + len(out) + 4)
	out = appendU32(out, defOffset)

	// Definition continues: next-definition offset, GUID, data size.
	out = appendU32(out, 0) // no next definition
	out = append(out, make([]byte, 16)...)
	sizePos := len(out)
	out = appendU32(out, 0) // data size, patched once the body is known

	bodyStart := base + len(out)
	tmpl := b.buildTemplateBody(e, keys, bodyStart)
	out = append(out, tmpl...)
	binary.LittleEndian.PutUint32(out[sizePos:sizePos+4], uint32(len(tmpl)))

	// Instance data: the substitution array.
	out = appendU32(out, uint32(len(subs)))
	for _, s := range subs {
		out = appendU16(out, uint16(len(s.data)))
		out = append(out, s.typ, 0x00)
	}
	for _, s := range subs {
		out = append(out, s.data...)
	}
	return out
}

// buildTemplateBody writes the element skeleton: <Event><System>...
// </System><EventData>...</EventData></Event>, with a substitution in
// each value position.
func (b *chunkBuilder) buildTemplateBody(e Event, keys []string, base int) []byte {
	var out []byte
	emit := func(f func(cur int) []byte) {
		out = append(out, f(base+len(out))...)
	}

	emit(func(cur int) []byte { return []byte{0x0f, 0x01, 0x01, 0x00} }) // fragment header

	// <Event>
	emit(func(cur int) []byte { return b.openElement("Event", cur, false) })
	emit(func(cur int) []byte { return []byte{0x02} }) // close start tag

	// <System>
	emit(func(cur int) []byte { return b.openElement("System", cur, false) })
	emit(func(cur int) []byte { return []byte{0x02} })

	// <Provider Name="..."/>
	emit(func(cur int) []byte { return b.elementWithAttrSub("Provider", "Name", 0, 0x01, cur) })
	emit(func(cur int) []byte { return b.elementWithSub("EventID", 1, 0x06, cur) })
	emit(func(cur int) []byte { return b.elementWithSub("Level", 2, 0x04, cur) })
	emit(func(cur int) []byte { return b.elementWithSub("Task", 3, 0x06, cur) })
	emit(func(cur int) []byte { return b.elementWithSub("Opcode", 4, 0x04, cur) })
	emit(func(cur int) []byte { return b.elementWithSub("Keywords", 5, 0x01, cur) })
	// <TimeCreated SystemTime="..."/>
	emit(func(cur int) []byte { return b.elementWithAttrSub("TimeCreated", "SystemTime", 6, 0x11, cur) })
	emit(func(cur int) []byte { return b.elementWithSub("EventRecordID", 7, 0x0a, cur) })
	// <Execution ProcessID=".." ThreadID=".."/>
	emit(func(cur int) []byte {
		return b.elementWithTwoAttrSubs("Execution", "ProcessID", 8, 0x08, "ThreadID", 9, 0x08, cur)
	})
	emit(func(cur int) []byte { return b.elementWithSub("Channel", 10, 0x01, cur) })
	emit(func(cur int) []byte { return b.elementWithSub("Computer", 11, 0x01, cur) })
	// <Security UserID="..."/>
	emit(func(cur int) []byte { return b.elementWithAttrSub("Security", "UserID", 12, 0x13, cur) })

	emit(func(cur int) []byte { return []byte{0x04} }) // </System>

	// <EventData><Data Name="k">v</Data>...</EventData>
	emit(func(cur int) []byte { return b.openElement("EventData", cur, false) })
	emit(func(cur int) []byte { return []byte{0x02} })
	for i, k := range keys {
		idx := 13 + i
		emit(func(cur int) []byte { return b.dataElement(k, uint16(idx), cur) })
	}
	emit(func(cur int) []byte { return []byte{0x04} }) // </EventData>

	emit(func(cur int) []byte { return []byte{0x04} }) // </Event>
	emit(func(cur int) []byte { return []byte{0x00} }) // end of stream
	return out
}

// openElement emits an open-start-element token, writing the name inline
// the first time it is used and referencing its chunk offset thereafter.
func (b *chunkBuilder) openElement(name string, cur int, hasAttrs bool) []byte {
	token := byte(0x01)
	if hasAttrs {
		token = 0x41
	}
	var out []byte
	out = append(out, token)
	out = appendU16(out, 0xffff) // dependency identifier: not set
	out = appendU32(out, 0)      // data size: readers that need it recompute; fixtures do not rely on it

	if off, ok := b.nameOffsets[name]; ok {
		out = appendU32(out, off)
		return out
	}
	// Inline: the name structure begins immediately after this offset
	// field, so its offset is exactly that position.
	nameOffset := uint32(cur + len(out) + 4)
	out = appendU32(out, nameOffset)
	out = append(out, nameStruct(name)...)
	b.nameOffsets[name] = nameOffset
	return out
}

// elementWithSub emits <Name>%sub%</Name>.
func (b *chunkBuilder) elementWithSub(name string, subIndex uint16, valueType byte, cur int) []byte {
	out := b.openElement(name, cur, false)
	out = append(out, 0x02) // close start tag
	out = append(out, 0x0d) // normal substitution
	out = appendU16(out, subIndex)
	out = append(out, valueType)
	out = append(out, 0x04) // end element
	return out
}

// elementWithAttrSub emits <Name Attr="%sub%"/>.
func (b *chunkBuilder) elementWithAttrSub(name, attr string, subIndex uint16, valueType byte, cur int) []byte {
	out := b.openElement(name, cur, true)
	// Attribute list data size, then one attribute.
	attrStart := cur + len(out) + 4
	var attrs []byte
	attrs = append(attrs, 0x06) // attribute, no more following
	attrs = append(attrs, b.nameRef(attr, attrStart+1)...)
	attrs = append(attrs, 0x0d) // normal substitution
	attrs = appendU16(attrs, subIndex)
	attrs = append(attrs, valueType)

	out = appendU32(out, uint32(len(attrs)))
	out = append(out, attrs...)
	out = append(out, 0x03) // close empty element
	return out
}

// elementWithTwoAttrSubs emits <Name A="%s1%" B="%s2%"/>.
func (b *chunkBuilder) elementWithTwoAttrSubs(name, a string, ai uint16, at byte, bAttr string, bi uint16, bt byte, cur int) []byte {
	out := b.openElement(name, cur, true)
	attrStart := cur + len(out) + 4

	var attrs []byte
	attrs = append(attrs, 0x46) // attribute, MORE follow
	attrs = append(attrs, b.nameRef(a, attrStart+len(attrs))...)
	attrs = append(attrs, 0x0d)
	attrs = appendU16(attrs, ai)
	attrs = append(attrs, at)

	attrs = append(attrs, 0x06) // attribute, last one
	attrs = append(attrs, b.nameRef(bAttr, attrStart+len(attrs))...)
	attrs = append(attrs, 0x0d)
	attrs = appendU16(attrs, bi)
	attrs = append(attrs, bt)

	out = appendU32(out, uint32(len(attrs)))
	out = append(out, attrs...)
	out = append(out, 0x03)
	return out
}

// dataElement emits <Data Name="k">%sub%</Data>.
func (b *chunkBuilder) dataElement(key string, subIndex uint16, cur int) []byte {
	out := b.openElement("Data", cur, true)
	attrStart := cur + len(out) + 4

	var attrs []byte
	attrs = append(attrs, 0x06)
	attrs = append(attrs, b.nameRef("Name", attrStart+1)...)
	// The attribute's value is literal text, not a substitution: the key
	// name is part of the template, the value is what varies.
	attrs = append(attrs, 0x05, 0x01)
	attrs = appendU16(attrs, uint16(len([]rune(key))))
	attrs = append(attrs, encodeUTF16NoNul(key)...)

	out = appendU32(out, uint32(len(attrs)))
	out = append(out, attrs...)
	out = append(out, 0x02) // close start tag
	out = append(out, 0x0d) // normal substitution for the value
	out = appendU16(out, subIndex)
	out = append(out, 0x01) // StringType
	out = append(out, 0x04) // end element
	return out
}

// nameRef emits a 4-byte name offset, writing the name structure inline
// after it if this is the name's first use.
func (b *chunkBuilder) nameRef(name string, cur int) []byte {
	if off, ok := b.nameOffsets[name]; ok {
		return appendU32(nil, off)
	}
	nameOffset := uint32(cur + 4)
	out := appendU32(nil, nameOffset)
	out = append(out, nameStruct(name)...)
	b.nameOffsets[name] = nameOffset
	return out
}

// nameStruct is the on-disk name: 4 unknown, 2 hash, 2 character count,
// then UTF-16 plus a NUL terminator.
func nameStruct(s string) []byte {
	runes := utf16.Encode([]rune(s))
	out := make([]byte, 8)
	binary.LittleEndian.PutUint32(out[0:4], 0)
	binary.LittleEndian.PutUint16(out[4:6], nameHash(s))
	binary.LittleEndian.PutUint16(out[6:8], uint16(len(runes)))
	for _, r := range runes {
		out = appendU16(out, r)
	}
	return append(out, 0x00, 0x00)
}

// nameHash is the format's simple rolling hash. No reader here verifies
// it, but writing the real value keeps fixtures faithful.
func nameHash(s string) uint16 {
	var h uint16
	const mult = uint16(65599 % 65536) // 63; the format's 65599 multiplier truncated to 16 bits
	for _, r := range utf16.Encode([]rune(s)) {
		h = h*mult + r // wraps, as the format intends
	}
	return h
}

// ---------- substitution values ----------

type subValue struct {
	typ  byte
	data []byte
}

func stringSub(s string) subValue { return subValue{typ: 0x01, data: encodeUTF16NoNul(s)} }
func uint8Sub(v uint8) subValue   { return subValue{typ: 0x04, data: []byte{v}} }
func uint16Sub(v uint16) subValue { return subValue{typ: 0x06, data: appendU16(nil, v)} }
func uint32Sub(v uint32) subValue { return subValue{typ: 0x08, data: appendU32(nil, v)} }
func uint64Sub(v uint64) subValue { return subValue{typ: 0x0a, data: appendU64(nil, v)} }

func fileTimeSub(t time.Time) subValue {
	return subValue{typ: 0x11, data: appendU64(nil, toFileTime(t))}
}

// sidSub encodes a SID string such as "S-1-5-21-1-2-3-1001" in its
// binary form, so the reader's SID rendering is exercised against real
// structure rather than a pre-formatted string.
func sidSub(sid string) subValue {
	if sid == "" {
		return subValue{typ: 0x00}
	}
	rev, authority, subs, ok := parseSID(sid)
	if !ok {
		return subValue{typ: 0x00}
	}
	out := make([]byte, 8)
	out[0] = rev
	out[1] = byte(len(subs))
	for i := 0; i < 6; i++ {
		out[2+i] = byte(authority >> (8 * (5 - i)))
	}
	for _, s := range subs {
		out = appendU32(out, s)
	}
	return subValue{typ: 0x13, data: out}
}

func parseSID(sid string) (rev byte, authority uint64, subs []uint32, ok bool) {
	if len(sid) < 4 || sid[0] != 'S' || sid[1] != '-' {
		return 0, 0, nil, false
	}
	parts := splitDash(sid[2:])
	if len(parts) < 2 {
		return 0, 0, nil, false
	}
	rev = byte(parts[0])
	authority = uint64(parts[1])
	for _, p := range parts[2:] {
		subs = append(subs, uint32(p))
	}
	return rev, authority, subs, true
}

func splitDash(s string) []uint64 {
	var out []uint64
	cur, has := uint64(0), false
	for i := 0; i < len(s); i++ {
		if s[i] == '-' {
			if has {
				out = append(out, cur)
			}
			cur, has = 0, false
			continue
		}
		if s[i] < '0' || s[i] > '9' {
			return nil
		}
		cur = cur*10 + uint64(s[i]-'0')
		has = true
	}
	if has {
		out = append(out, cur)
	}
	return out
}

// ---------- deliberately broken fixtures ----------

// Truncate cuts a log short, as happens whenever a log is copied while
// the system is writing to it.
func Truncate(log []byte, keep int) []byte {
	if keep > len(log) {
		keep = len(log)
	}
	out := make([]byte, keep)
	copy(out, log)
	return out
}

// CorruptSignature replaces the file magic, so this is not an EVTX.
func CorruptSignature(log []byte) []byte {
	out := append([]byte(nil), log...)
	copy(out[0:8], "NOTELF\x00\x00")
	return out
}

// CorruptChunkCRC flips a byte inside a chunk's covered region without
// fixing the CRC, so the chunk is detectably damaged. Used to prove that
// a bad chunk is SKIPPED and counted rather than silently trusted.
func CorruptChunkCRC(log []byte, chunkIndex int) []byte {
	out := append([]byte(nil), log...)
	base := fileHeaderSize + chunkIndex*chunkSize
	if base+200 < len(out) {
		out[base+200] ^= 0xff
	}
	return out
}

// CorruptChunkSignature invalidates one chunk's magic.
func CorruptChunkSignature(log []byte, chunkIndex int) []byte {
	out := append([]byte(nil), log...)
	base := fileHeaderSize + chunkIndex*chunkSize
	if base+8 <= len(out) {
		copy(out[base:base+8], "BADCHNK\x00")
	}
	return out
}

// CorruptRecordSize gives the first record in a chunk an impossible
// size, exercising the "implausible record size" guard.
func CorruptRecordSize(log []byte, chunkIndex int) []byte {
	out := append([]byte(nil), log...)
	rec := fileHeaderSize + chunkIndex*chunkSize + chunkHeaderSize
	if rec+8 <= len(out) {
		binary.LittleEndian.PutUint32(out[rec+4:rec+8], 0xfffffff0)
		fixChunkCRC(out, chunkIndex)
	}
	return out
}

// CorruptBinXML rewrites a record's BinXML body with an unknown token,
// so the record fails to parse while its framing stays valid -- the case
// where recovery should keep the OTHER records in the chunk.
func CorruptBinXML(log []byte, chunkIndex int) []byte {
	out := append([]byte(nil), log...)
	body := fileHeaderSize + chunkIndex*chunkSize + chunkHeaderSize + 24
	if body+4 <= len(out) {
		out[body] = 0x3b // not a valid BinXML token
		fixChunkCRC(out, chunkIndex)
	}
	return out
}

// fixChunkCRC recomputes a chunk's CRC after a deliberate edit, so the
// corruption under test is the one intended rather than being masked by
// a CRC failure.
func fixChunkCRC(log []byte, chunkIndex int) {
	base := fileHeaderSize + chunkIndex*chunkSize
	if base+chunkSize > len(log) {
		return
	}
	c := log[base : base+chunkSize]
	sum := crc32.Update(0, crc32.IEEETable, c[0:120])
	sum = crc32.Update(sum, crc32.IEEETable, c[128:512])
	binary.LittleEndian.PutUint32(c[124:128], sum)
}

// ---------- helpers ----------

func appendU16(b []byte, v uint16) []byte {
	var t [2]byte
	binary.LittleEndian.PutUint16(t[:], v)
	return append(b, t[:]...)
}

func appendU32(b []byte, v uint32) []byte {
	var t [4]byte
	binary.LittleEndian.PutUint32(t[:], v)
	return append(b, t[:]...)
}

func appendU64(b []byte, v uint64) []byte {
	var t [8]byte
	binary.LittleEndian.PutUint64(t[:], v)
	return append(b, t[:]...)
}

func encodeUTF16NoNul(s string) []byte {
	var out []byte
	for _, r := range utf16.Encode([]rune(s)) {
		out = appendU16(out, r)
	}
	return out
}

func toFileTime(t time.Time) uint64 {
	if t.IsZero() {
		return 0
	}
	const epochDelta = 11644473600
	return uint64((t.UTC().Unix()+epochDelta)*10_000_000) + uint64(t.Nanosecond()/100)
}
