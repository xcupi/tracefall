// Package esegen builds small, valid ESE databases for tests. It writes only
// what the reader consumes: the file header, a catalog and, per table, a B+tree
// of leaf pages (with one branch page when a table is split across leaves) and
// an optional long value tree. Nothing here is a general ESE writer; it exists
// so the reader's rarely used paths (compression, multi-values, separated long
// values, deleted records, hostile structures) can be exercised and so a test
// can say exactly what it put in.
package esegen

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
)

// Column types, as in JET.
const (
	Bit        = 1
	Uint8      = 2
	Int16      = 3
	Int32      = 4
	Currency   = 5
	Float32    = 6
	Float64    = 7
	DateTime   = 8
	Binary     = 9
	Text       = 10
	LongBinary = 11
	LongText   = 12
	Uint32     = 14
	Int64      = 15
	GUID       = 16
	Uint16     = 17
)

// Tagged value header flags.
const (
	TagLongValue  = 0x01
	TagCompressed = 0x02
	TagSeparated  = 0x04
	TagMulti      = 0x08
	TagTwoValues  = 0x10
	TagNull       = 0x20
)

// Column is a column of a table.
type Column struct {
	ID       uint32
	Name     string
	Type     int
	Codepage uint32 // 1200 = UTF-16LE, 1252 = ASCII/Latin-1
	Flags    uint32
	MaxLen   uint32
	// Default is the value a record that predates the column reads as.
	Default []byte
}

// Tagged is the stored form of one tagged column of a record.
type Tagged struct {
	ID    uint32
	Flags uint8 // header flags; written when the page size has extended info
	Data  []byte
	Null  bool
}

// Record is one row. Fixed and Var map a column ID to its stored bytes; a
// missing fixed ID is null, a missing variable ID is null.
type Record struct {
	Fixed  map[uint32][]byte
	Var    map[uint32][]byte
	Tagged []Tagged
	// Defunct marks the record as deleted but still present.
	Defunct bool
	// Raw, when non-nil, is stored as the record bytes unchanged. Tests use it
	// to put hostile record bodies in a valid page.
	Raw []byte
	// Key orders records in the tree; Build fills it when empty.
	Key []byte
}

// LongValue is an entry of a table's long value tree.
type LongValue struct {
	ID    uint32
	Total uint32
	// Segments are stored in order; each is [offset, bytes].
	Segments []Segment
}

// Segment is one chunk of a long value.
type Segment struct {
	Offset uint32
	Data   []byte
}

// Table is a table to write.
type Table struct {
	Name         string
	Template     string
	Columns      []Column
	Records      []Record
	LongValues   []LongValue
	HasLVTree    bool
	LeafCapacity int // records per leaf page; 0 puts everything in one leaf if it fits
	// CommonKeys stores the prefix shared by every key of a non-root leaf page
	// once, in the page's first tag, as the engine does.
	CommonKeys bool
	// Dropped writes the table's catalog rows as defunct, as when the table was
	// dropped but the space is not yet reclaimed.
	Dropped bool
	// LVLeafCapacity splits the long value tree across leaf pages, with the
	// same key compression when CommonKeys is set.
	LVLeafCapacity int
}

// Options controls the file.
type Options struct {
	PageSize int // 4096 or 32768; 0 means 4096
	State    uint32
	// BrokenCatalog overwrites the catalog root page with zeros, leaving the
	// shadow copy as the only readable one. The shadow is only written when
	// this is set or Shadow is true.
	BrokenCatalog bool
	Shadow        bool
}

type page struct {
	no      uint32
	flags   uint32
	prev    uint32
	next    uint32
	fdp     uint32
	tag0    []byte
	entries []entry
}

type entry struct {
	key     []byte
	data    []byte
	defunct bool
	common  int    // length of the common key prefix taken from tag 0, 0 for none
	raw     []byte // whole tag body, bypassing the key/data layout
}

const (
	flagRoot   = 0x1
	flagLeaf   = 0x2
	flagParent = 0x4
)

type builder struct {
	ps    int
	small bool
	hdr   int
	pages map[uint32]*page
	next  uint32
}

// Build returns the bytes of a database holding the tables.
func Build(tables []Table, o Options) []byte {
	if o.PageSize == 0 {
		o.PageSize = 4096
	}
	b := &builder{ps: o.PageSize, small: o.PageSize <= 8192, pages: map[uint32]*page{}, next: 5}
	b.hdr = 40
	if !b.small {
		b.hdr = 80
	}
	for n := uint32(1); n <= 3; n++ {
		b.pages[n] = &page{no: n}
	}

	type cat struct {
		typ     int
		objid   uint32
		id      uint32
		val     uint32
		flags   uint32
		locale  uint32
		space   uint32
		name    string
		tmpl    string
		defalt  []byte
		recOff  int
		dropped bool
	}
	var rows []cat
	objid := uint32(2)
	for ti := range tables {
		t := &tables[ti]
		t.fill()
		fdp := b.writeTree(t, templateColumns(tables, t))
		rows = append(rows, cat{typ: 1, objid: objid, id: objid, val: fdp, name: t.Name, tmpl: t.Template, dropped: t.Dropped})
		if t.HasLVTree {
			lv := b.writeLV(t)
			rows = append(rows, cat{typ: 4, objid: objid, id: objid + 1, val: lv, name: "LV", dropped: t.Dropped})
		}
		for _, c := range t.Columns {
			rows = append(rows, cat{typ: 2, objid: objid, id: c.ID, val: uint32(c.Type), flags: c.Flags, locale: c.Codepage, space: c.MaxLen, name: c.Name, defalt: c.Default, dropped: t.Dropped})
		}
		objid += 3
	}

	catCols := catalogColumns()
	var recs []Record
	for i, r := range rows {
		fx := map[uint32][]byte{
			1: le32(r.objid), 2: le16(uint16(r.typ)), 3: le32(r.id), 4: le32(r.val), 5: le32(r.space),
			6: le32(r.flags), 7: le32(r.locale), 8: {1}, 9: le16(0), 10: le32(0), 11: le16(0), 12: le32(0),
		}
		v := map[uint32][]byte{128: []byte(r.name)}
		if r.tmpl != "" {
			v[130] = []byte(r.tmpl)
		}
		if len(r.defalt) > 0 {
			v[131] = r.defalt
		}
		recs = append(recs, Record{Fixed: fx, Var: v, Key: be32(uint32(i))})
	}
	cp := &page{no: 4, flags: flagRoot | flagLeaf, fdp: 1}
	for i, r := range recs {
		cp.entries = append(cp.entries, entry{key: r.Key, data: b.encodeRecord(catCols, r), defunct: rows[i].dropped})
	}
	b.pages[4] = cp
	if o.Shadow || o.BrokenCatalog {
		sp := *cp
		sp.no = 24
		b.pages[24] = &sp
	}
	if o.BrokenCatalog {
		b.pages[4] = &page{no: 4}
	}

	max := uint32(0)
	for n := range b.pages {
		if n > max {
			max = n
		}
	}
	out := make([]byte, (int(max)+2)*b.ps)
	b.writeHeader(out, o)
	for n, p := range b.pages {
		copy(out[(int(n)+1)*b.ps:], b.render(p))
	}
	return out
}

// templateColumns are the columns a derived table inherits.
func templateColumns(all []Table, t *Table) []Column {
	if t.Template == "" {
		return nil
	}
	for i := range all {
		if all[i].Name == t.Template {
			return all[i].Columns
		}
	}
	return nil
}

func catalogColumns() []Column {
	return []Column{
		{ID: 1, Type: Int32}, {ID: 2, Type: Int16}, {ID: 3, Type: Int32}, {ID: 4, Type: Int32},
		{ID: 5, Type: Int32}, {ID: 6, Type: Int32}, {ID: 7, Type: Int32}, {ID: 8, Type: Bit},
		{ID: 9, Type: Int16}, {ID: 10, Type: Int32}, {ID: 11, Type: Int16}, {ID: 12, Type: Int32},
		{ID: 128, Type: Text}, {ID: 129, Type: Binary}, {ID: 130, Type: Text}, {ID: 131, Type: Binary},
	}
}

func (t *Table) fill() {
	for i := range t.Records {
		if t.Records[i].Key == nil {
			t.Records[i].Key = be32(uint32(i + 1))
		}
	}
}

func fixedSize(c Column) int {
	switch c.Type {
	case Bit, Uint8:
		return 1
	case Int16, Uint16:
		return 2
	case Int32, Uint32, Float32:
		return 4
	case Int64, Currency, Float64, DateTime:
		return 8
	case GUID:
		return 16
	}
	return int(c.MaxLen)
}

// encodeRecord lays out a record: header, fixed data, null bitmap, variable
// size array, variable data, tagged columns.
func (b *builder) encodeRecord(cols []Column, r Record) []byte {
	if r.Raw != nil {
		return r.Raw
	}
	var fixed, vars []Column
	for _, c := range cols {
		switch {
		case c.ID >= 1 && c.ID <= 127:
			fixed = append(fixed, c)
		case c.ID >= 128 && c.ID <= 255:
			vars = append(vars, c)
		}
	}
	sort.Slice(fixed, func(i, j int) bool { return fixed[i].ID < fixed[j].ID })
	sort.Slice(vars, func(i, j int) bool { return vars[i].ID < vars[j].ID })
	var lastFixed, lastVar uint32
	for _, c := range fixed {
		if _, ok := r.Fixed[c.ID]; ok && c.ID > lastFixed {
			lastFixed = c.ID
		}
	}
	for _, c := range vars {
		if _, ok := r.Var[c.ID]; ok && c.ID > lastVar {
			lastVar = c.ID
		}
	}
	var body bytes.Buffer
	bitmap := make([]byte, (lastFixed+7)/8)
	for _, c := range fixed {
		if c.ID > lastFixed {
			break
		}
		v, ok := r.Fixed[c.ID]
		sz := fixedSize(c)
		if !ok {
			bitmap[(c.ID-1)/8] |= 1 << ((c.ID - 1) % 8)
			v = make([]byte, sz)
		}
		if len(v) != sz {
			panic(fmt.Sprintf("esegen: column %d wants %d bytes, got %d", c.ID, sz, len(v)))
		}
		body.Write(v)
	}
	body.Write(bitmap)
	varOff := 4 + body.Len() // the size array follows the null bitmap
	var sizes, vdata bytes.Buffer
	if lastVar >= 128 {
		end := 0
		for id := uint32(128); id <= lastVar; id++ {
			v, ok := r.Var[id]
			if !ok {
				sizes.Write(le16(uint16(end) | 0x8000))
				continue
			}
			vdata.Write(v)
			end += len(v)
			sizes.Write(le16(uint16(end)))
		}
	}
	out := []byte{byte(lastFixed), byte(lastVar)}
	out = append(out, le16(uint16(varOff))...)
	out = append(out, body.Bytes()...)
	out = append(out, sizes.Bytes()...)
	out = append(out, vdata.Bytes()...)
	out = append(out, b.encodeTagged(r.Tagged)...)
	return out
}

func (b *builder) encodeTagged(ts []Tagged) []byte {
	if len(ts) == 0 {
		return nil
	}
	ts = append([]Tagged(nil), ts...)
	sort.Slice(ts, func(i, j int) bool { return ts[i].ID < ts[j].ID })
	head := 4 * len(ts)
	var data bytes.Buffer
	var table bytes.Buffer
	for _, t := range ts {
		off := head + data.Len()
		w := uint16(off)
		body := t.Data
		if b.small {
			w |= 0x4000 // extended info present
			if t.Null {
				w |= 0x2000
			}
			data.WriteByte(t.Flags)
		} else {
			f := t.Flags
			if t.Null {
				f |= TagNull
			}
			data.WriteByte(f)
		}
		data.Write(body)
		table.Write(le16(uint16(t.ID)))
		table.Write(le16(w))
	}
	return append(table.Bytes(), data.Bytes()...)
}

func (b *builder) leafPage(fdp uint32, ents []entry) *page {
	p := &page{no: b.next, flags: flagLeaf, fdp: fdp, entries: ents}
	b.pages[p.no] = p
	b.next++
	return p
}

// writeTree writes the table's records as a B+tree and returns its root page.
func (b *builder) writeTree(t *Table, extra []Column) uint32 {
	var ents []entry
	cols := append(append([]Column(nil), extra...), t.Columns...)
	for _, r := range t.Records {
		ents = append(ents, entry{key: r.Key, data: b.encodeRecord(cols, r), defunct: r.Defunct})
	}
	return b.treeFromEntries(ents, t.LeafCapacity, t.CommonKeys)
}

func (b *builder) treeFromEntries(ents []entry, capacity int, common bool) uint32 {
	root := &page{no: b.next, flags: flagRoot, fdp: 1}
	b.pages[root.no] = root
	b.next++
	if capacity <= 0 || len(ents) <= capacity {
		root.flags |= flagLeaf
		root.entries = ents
		return root.no
	}
	root.flags |= flagParent
	var prev *page
	for i := 0; i < len(ents); i += capacity {
		j := i + capacity
		if j > len(ents) {
			j = len(ents)
		}
		chunk := append([]entry(nil), ents[i:j]...)
		lp := b.leafPage(1, chunk)
		if common && len(chunk) > 1 {
			n := len(chunk[0].key)
			for _, e := range chunk[1:] {
				k := 0
				for k < n && k < len(e.key) && e.key[k] == chunk[0].key[k] {
					k++
				}
				n = k
			}
			if n > 0 {
				lp.tag0 = append([]byte(nil), chunk[0].key[:n]...)
				for x := range chunk {
					chunk[x].common = n
				}
			}
		}
		if prev != nil {
			prev.next, lp.prev = lp.no, prev.no
		}
		prev = lp
		root.entries = append(root.entries, entry{key: ents[j-1].key, data: le32(lp.no)})
	}
	return root.no
}

func (b *builder) writeLV(t *Table) uint32 {
	var ents []entry
	for _, lv := range t.LongValues {
		key := be32(lv.ID)
		head := append(le32(1), le32(lv.Total)...)
		ents = append(ents, entry{key: key, data: head})
		for _, s := range lv.Segments {
			ents = append(ents, entry{key: append(append([]byte{}, key...), be32(s.Offset)...), data: s.Data})
		}
	}
	sort.SliceStable(ents, func(i, j int) bool { return bytes.Compare(ents[i].key, ents[j].key) < 0 })
	return b.treeFromEntries(ents, t.LVLeafCapacity, t.CommonKeys)
}

func (b *builder) writeHeader(out []byte, o Options) {
	h := out[:b.ps]
	binary.LittleEndian.PutUint32(h[4:], 0x89ABCDEF)
	binary.LittleEndian.PutUint32(h[8:], 0x620)
	binary.LittleEndian.PutUint32(h[12:], 0)
	st := o.State
	if st == 0 {
		st = 3
	}
	binary.LittleEndian.PutUint32(h[52:], st)
	binary.LittleEndian.PutUint32(h[232:], 0x11)
	binary.LittleEndian.PutUint32(h[236:], uint32(b.ps))
	x := uint32(0x89abcdef)
	for i := 4; i+4 <= len(h); i += 4 {
		x ^= binary.LittleEndian.Uint32(h[i:])
	}
	binary.LittleEndian.PutUint32(h[0:], x)
}

// render lays a page out: header, tag 0, entries, tag array at the end.
func (b *builder) render(p *page) []byte {
	buf := make([]byte, b.ps)
	binary.LittleEndian.PutUint32(buf[16:], p.prev)
	binary.LittleEndian.PutUint32(buf[20:], p.next)
	binary.LittleEndian.PutUint32(buf[24:], p.fdp)
	type tg struct {
		body  []byte
		flags uint8
	}
	tags := []tg{{body: p.tag0}}
	if p.flags&flagRoot != 0 && len(p.tag0) == 0 {
		tags[0].body = make([]byte, 16)
	}
	for _, e := range p.entries {
		var fl uint8
		if e.defunct {
			fl |= 0x02
		}
		var body []byte
		switch {
		case e.raw != nil:
			body = e.raw
		case e.common > 0:
			fl |= 0x04
			body = append(le16(uint16(e.common)), le16(uint16(len(e.key)-e.common))...)
			body = append(body, e.key[e.common:]...)
			body = append(body, e.data...)
		default:
			body = append(le16(uint16(len(e.key))), e.key...)
			body = append(body, e.data...)
		}
		if !b.small {
			body = append([]byte(nil), body...)
			binary.LittleEndian.PutUint16(body, binary.LittleEndian.Uint16(body)|uint16(fl)<<13)
		}
		tags = append(tags, tg{body, fl})
	}
	pos := 0
	avail := b.ps - b.hdr
	for i, t := range tags {
		if pos+len(t.body)+4*(i+1) > avail {
			panic(fmt.Sprintf("esegen: page %d overflows (%d tags); lower LeafCapacity", p.no, len(tags)))
		}
		copy(buf[b.hdr+pos:], t.body)
		tp := b.ps - 4*(i+1)
		cb, ib := uint16(len(t.body)), uint16(pos)
		if b.small {
			ib |= uint16(t.flags) << 13
		}
		binary.LittleEndian.PutUint16(buf[tp:], cb)
		binary.LittleEndian.PutUint16(buf[tp+2:], ib)
		pos += len(t.body)
	}
	binary.LittleEndian.PutUint16(buf[34:], uint16(len(tags)))
	binary.LittleEndian.PutUint32(buf[36:], p.flags)
	return buf
}

func le16(v uint16) []byte { b := make([]byte, 2); binary.LittleEndian.PutUint16(b, v); return b }
func le32(v uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b }
func be32(v uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }

// Le32, Le64, U16 are helpers for tests that build fixed values.
func Le32(v uint32) []byte { return le32(v) }
func Le16(v uint16) []byte { return le16(v) }
func Le64(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

// UTF16 encodes s as UTF-16LE.
func UTF16(s string) []byte {
	var b []byte
	for _, r := range s {
		b = append(b, byte(r), byte(r>>8))
	}
	return b
}

// LongValueRef is the stored reference of a separated long value.
func LongValueRef(id uint32) []byte { return le32(id) }

// Multi packs values into the regular multi-value form (an array of u16
// offsets, then the values).
func Multi(vals ...[]byte) []byte {
	head := 2 * len(vals)
	var out, data bytes.Buffer
	for _, v := range vals {
		out.Write(le16(uint16(head + data.Len())))
		data.Write(v)
	}
	return append(out.Bytes(), data.Bytes()...)
}

// TwoValues packs two values in the optimised two-value form.
func TwoValues(a, b []byte) []byte {
	return append(append([]byte{byte(len(a))}, a...), b...)
}
