package ese

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

// ColType is a JET column type.
type ColType uint32

const (
	TypeBit              ColType = 1
	TypeUint8            ColType = 2
	TypeInt16            ColType = 3
	TypeInt32            ColType = 4
	TypeCurrency         ColType = 5
	TypeFloat32          ColType = 6
	TypeFloat64          ColType = 7
	TypeDateTime         ColType = 8
	TypeBinary           ColType = 9
	TypeText             ColType = 10
	TypeLongBinary       ColType = 11
	TypeLongText         ColType = 12
	TypeSLV              ColType = 13
	TypeUint32           ColType = 14
	TypeInt64            ColType = 15
	TypeGUID             ColType = 16
	TypeUint16           ColType = 17
	columnFlagTagged             = 0x2
	columnFlagMulti              = 0x400
	columnFlagCompressed         = 0x10000
	catalogTypeTable             = 1
	catalogTypeColumn            = 2
	catalogTypeLongValue         = 4
)

// Column describes one column of a table, from the catalog.
type Column struct {
	ID       uint32
	Name     string
	Type     ColType
	Flags    uint32
	Codepage uint32
	// Offset is where a fixed column begins, counted from the start of the
	// record's fixed data (the 4-byte record header is not included).
	Offset  int
	MaxLen  int
	Default []byte
}

func (c *Column) fixed() bool    { return c.ID >= 1 && c.ID <= 127 }
func (c *Column) variable() bool { return c.ID >= 128 && c.ID <= 255 }

// fixedSize is the number of bytes a fixed column occupies in a record.
func (c *Column) fixedSize() int {
	switch c.Type {
	case TypeBit, TypeUint8:
		return 1
	case TypeInt16, TypeUint16:
		return 2
	case TypeInt32, TypeUint32, TypeFloat32:
		return 4
	case TypeInt64, TypeCurrency, TypeFloat64, TypeDateTime:
		return 8
	case TypeGUID:
		return 16
	}
	return c.MaxLen
}

// Table is one table of the catalog.
type Table struct {
	Name     string
	ObjID    uint32
	FDP      uint32 // root page of the table's B+tree
	LVFDP    uint32 // root page of its long value tree, 0 when it has none
	Template string
	Columns  []*Column

	db     *DB
	byID   map[uint32]*Column
	byName map[string]*Column
}

// Column returns the column with the given name, or nil.
func (t *Table) Column(name string) *Column { return t.byName[name] }

// Tables lists the catalog's tables in catalog order.
func (db *DB) Tables() []*Table { return db.order }

// Table returns a table by name, or nil.
func (db *DB) Table(name string) *Table { return db.tables[name] }

// the catalog's own schema, which is fixed by the format.
func catalogTable(db *DB) *Table {
	t := &Table{Name: "MSysObjects", db: db, byID: map[uint32]*Column{}, byName: map[string]*Column{}}
	add := func(id uint32, name string, ty ColType, off, max int) {
		c := &Column{ID: id, Name: name, Type: ty, Offset: off, MaxLen: max}
		t.Columns = append(t.Columns, c)
		t.byID[id] = c
		t.byName[name] = c
	}
	add(1, "ObjidTable", TypeInt32, 0, 0)
	add(2, "Type", TypeInt16, 4, 0)
	add(3, "Id", TypeInt32, 6, 0)
	add(4, "ColtypOrPgnoFDP", TypeInt32, 10, 0)
	add(5, "SpaceUsage", TypeInt32, 14, 0)
	add(6, "Flags", TypeInt32, 18, 0)
	add(7, "PagesOrLocale", TypeInt32, 22, 0)
	add(8, "RootFlag", TypeBit, 26, 0)
	add(9, "RecordOffset", TypeInt16, 27, 0)
	add(10, "LCMapFlags", TypeInt32, 29, 0)
	add(11, "KeyMost", TypeInt16, 33, 0)
	add(12, "LVChunkMax", TypeInt32, 35, 0)
	add(128, "Name", TypeText, 0, 0)
	add(129, "Stats", TypeBinary, 0, 0)
	add(130, "TemplateTable", TypeText, 0, 0)
	add(131, "DefaultValue", TypeBinary, 0, 0)
	return t
}

func (db *DB) readCatalog() error {
	cat := catalogTable(db)
	root := uint32(catalogRootPage)
	if err := db.loadCatalog(cat, root); err != nil {
		// The catalog has a shadow copy for exactly this case.
		if err2 := db.loadCatalog(cat, catalogShadowPage); err2 != nil {
			return fmt.Errorf("%w: the catalog and its shadow copy are unreadable: %v", ErrCorrupt, err)
		}
	}
	db.catalogOK = true
	return nil
}

func (db *DB) loadCatalog(cat *Table, root uint32) error {
	type ent struct {
		typ                int
		objid, id, val     uint32
		flags, codepage    uint32
		recOff             int
		name, tmpl, defalt []byte
		spaceUsage         uint32
	}
	var all []ent
	err := db.walk(root, func(p *page, flags uint8, _, data []byte) error {
		if flags&tagFlagDefunct != 0 || data == nil {
			return nil // a dropped table or column, or an entry that cannot be read
		}
		vals, err := cat.decode(p, data)
		if err != nil {
			return nil // one unreadable catalog row does not hide the others
		}
		// positions follow catalogTable: ids 1..12 are 0..11, 128..131 are 12..15
		e := ent{
			typ: int(vals[1].Int()), objid: uint32(vals[0].Int()), id: uint32(vals[2].Int()),
			val: uint32(vals[3].Int()), flags: uint32(vals[5].Int()), codepage: uint32(vals[6].Int()),
			recOff: int(vals[8].Int()), spaceUsage: uint32(vals[4].Int()),
		}
		e.name, e.tmpl, e.defalt = vals[12].Raw, vals[14].Raw, vals[15].Raw
		all = append(all, e)
		return nil
	})
	if err != nil {
		return err
	}
	if len(all) == 0 {
		return fmt.Errorf("%w: the catalog holds no rows", ErrCorrupt)
	}
	db.tables = map[string]*Table{}
	db.order = nil
	byObj := map[uint32]*Table{}
	for _, e := range all {
		if e.typ == catalogTypeTable {
			t := &Table{Name: latin1(e.name), ObjID: e.objid, FDP: e.val, Template: latin1(e.tmpl), db: db,
				byID: map[uint32]*Column{}, byName: map[string]*Column{}}
			byObj[e.objid] = t
			db.tables[t.Name] = t
			db.order = append(db.order, t)
		}
	}
	for _, e := range all {
		t := byObj[e.objid]
		if t == nil {
			continue
		}
		switch e.typ {
		case catalogTypeColumn:
			if len(t.Columns) >= maxColumns {
				continue
			}
			c := &Column{ID: e.id, Name: latin1(e.name), Type: ColType(e.val), Flags: e.flags, Codepage: e.codepage,
				Offset: e.recOff, MaxLen: int(e.spaceUsage), Default: e.defalt}
			t.Columns = append(t.Columns, c)
			t.byID[c.ID] = c
			t.byName[c.Name] = c
		case catalogTypeLongValue:
			t.LVFDP = e.val
		}
	}
	// A derived table inherits the columns of its template table.
	defer func() {
		for _, t := range db.order {
			t.layoutFixed()
		}
	}()
	for _, t := range db.order {
		if t.Template == "" {
			continue
		}
		if tt := db.tables[t.Template]; tt != nil && tt != t {
			for _, c := range tt.Columns {
				if t.byID[c.ID] == nil {
					t.Columns = append(t.Columns, c)
					t.byID[c.ID] = c
					t.byName[c.Name] = c
				}
			}
			if t.LVFDP == 0 {
				t.LVFDP = tt.LVFDP
			}
		}
	}
	return nil
}

// layoutFixed places the fixed columns. They sit back to back in column-ID
// order, so each one begins where the previous ended; the offset the catalog
// records is not used because it counts the record header and the catalogs of
// different engine versions disagree about it.
func (t *Table) layoutFixed() {
	var fixed []*Column
	for _, c := range t.Columns {
		if c.fixed() {
			fixed = append(fixed, c)
		}
	}
	sort.Slice(fixed, func(i, j int) bool { return fixed[i].ID < fixed[j].ID })
	off := 0
	for _, c := range fixed {
		c.Offset = off
		off += c.fixedSize()
	}
}

func latin1(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		sb.WriteRune(rune(c))
	}
	return sb.String()
}

// Value is one column of one row.
type Value struct {
	Col  *Column
	Null bool
	// Raw is the value's bytes, with a long value fetched and compression
	// undone. For a multi-valued column it is nil and Multi holds the values.
	Raw   []byte
	Multi [][]byte
	// Err is set when the value could not be read; the rest of the row is still
	// returned.
	Err error
}

// Row is one record of a table; Values is aligned with Table.Columns.
type Row struct {
	Table  *Table
	Values []Value
	// Defunct is true for a deleted record that is still in the file.
	Defunct bool
}

// Get returns the value of a column by name.
func (r Row) Get(name string) (Value, bool) {
	c := r.Table.byName[name]
	if c == nil {
		return Value{}, false
	}
	for i, tc := range r.Table.Columns {
		if tc == c {
			return r.Values[i], true
		}
	}
	return Value{}, false
}

// Stats counts what a scan of a table met.
type Stats struct {
	Live    int // records in use
	Defunct int // records the engine has marked as no longer used
	// Unreadable is entries in use that could not be decoded as a record.
	Unreadable int
	// DefunctUnreadable is defunct entries too short or too damaged to decode;
	// the engine leaves a few bytes of a deleted record's key behind.
	DefunctUnreadable int
}

// Scan calls fn for every record of the table, in key order, and reports what
// it met. A defunct record is a deleted row whose space has not been reclaimed;
// it is returned with Row.Defunct set so a caller chooses what to do with it.
// An entry that cannot be decoded is counted in Stats.Unreadable and not
// returned: nothing is guessed from it.
func (t *Table) Scan(fn func(Row) error) (Stats, error) {
	var st Stats
	if t.FDP == 0 {
		return st, nil
	}
	err := t.db.walk(t.FDP, func(p *page, flags uint8, _, data []byte) error {
		defunct := flags&tagFlagDefunct != 0
		var vals []Value
		var err error
		if data == nil {
			err = fmt.Errorf("%w: entry cannot be taken apart", ErrCorrupt)
		} else {
			vals, err = t.decode(p, data)
		}
		if err != nil {
			if defunct {
				st.DefunctUnreadable++
			} else {
				st.Unreadable++
			}
			return nil
		}
		if defunct {
			st.Defunct++
		} else {
			st.Live++
		}
		return fn(Row{Table: t, Values: vals, Defunct: defunct})
	})
	return st, err
}

// decode splits one record into the table's columns.
func (t *Table) decode(p *page, rec []byte) ([]Value, error) {
	vals := make([]Value, len(t.Columns))
	for i, c := range t.Columns {
		vals[i] = Value{Col: c, Null: true}
	}
	if len(rec) < 4 {
		return nil, fmt.Errorf("%w: record shorter than its header", ErrCorrupt)
	}
	lastFixed, lastVar := uint32(rec[0]), uint32(rec[1])
	varOff := int(binary.LittleEndian.Uint16(rec[2:4]))
	if varOff < 4 || varOff > len(rec) {
		return nil, fmt.Errorf("%w: variable data offset %d is outside the %d-byte record", ErrCorrupt, varOff, len(rec))
	}
	bitmapLen := int((lastFixed + 7) / 8)
	bitmapStart := varOff - bitmapLen
	if bitmapStart < 4 {
		return nil, fmt.Errorf("%w: null bitmap does not fit", ErrCorrupt)
	}
	bitmap := rec[bitmapStart:varOff]

	nVar := 0
	if lastVar >= 128 {
		nVar = int(lastVar - 127)
	}
	varDataStart := varOff + 2*nVar
	if varDataStart > len(rec) {
		return nil, fmt.Errorf("%w: variable size array runs past the record", ErrCorrupt)
	}
	varEnds := make([]uint16, nVar)
	for i := 0; i < nVar; i++ {
		varEnds[i] = binary.LittleEndian.Uint16(rec[varOff+2*i:])
	}
	taggedStart := varDataStart
	if nVar > 0 {
		taggedStart += int(varEnds[nVar-1] & 0x7FFF)
	}

	// tagged column table
	type tagged struct {
		off      int
		ext      bool
		null     bool
		hdrFlags uint8
		start    int
		end      int
	}
	tags := map[uint32]*tagged{}
	var order []uint32
	if taggedStart+4 <= len(rec) {
		first := binary.LittleEndian.Uint16(rec[taggedStart+2 : taggedStart+4])
		mask := uint16(0x7FFF)
		if t.db.small {
			mask = 0x1FFF
		}
		count := int(first&mask) / 4
		if count > 0 && taggedStart+4*count <= len(rec) {
			ents := make([]*tagged, count)
			ids := make([]uint32, count)
			for i := 0; i < count; i++ {
				id := uint32(binary.LittleEndian.Uint16(rec[taggedStart+4*i:]))
				w := binary.LittleEndian.Uint16(rec[taggedStart+4*i+2:])
				e := &tagged{off: int(w & mask)}
				if t.db.small {
					e.ext = w&0x4000 != 0
					e.null = w&0x2000 != 0
				} else {
					e.ext = true
				}
				ents[i], ids[i] = e, id
			}
			for i, e := range ents {
				e.start = taggedStart + e.off
				if i+1 < count {
					e.end = taggedStart + ents[i+1].off
				} else {
					e.end = len(rec)
				}
				if e.ext && e.start < len(rec) {
					e.hdrFlags = rec[e.start]
					e.start++
					if !t.db.small && e.hdrFlags&0x20 != 0 {
						e.null = true
					}
				}
				if e.start > e.end || e.end > len(rec) {
					e.null, e.start, e.end = true, 0, 0
				}
				tags[ids[i]] = e
				order = append(order, ids[i])
			}
		}
	}

	for i, c := range t.Columns {
		v := &vals[i]
		switch {
		case c.fixed():
			if c.ID > lastFixed {
				useDefault(v, c)
				continue
			}
			bit := int(c.ID - 1)
			if bit/8 < len(bitmap) && bitmap[bit/8]&(1<<(bit%8)) != 0 {
				continue
			}
			off, size := 4+c.Offset, c.fixedSize()
			if size <= 0 || off+size > varOff {
				v.Err = fmt.Errorf("%w: fixed column %q lies outside the record", ErrCorrupt, c.Name)
				continue
			}
			v.Null, v.Raw = false, rec[off:off+size]
		case c.variable():
			idx := int(c.ID) - 128
			if idx >= nVar {
				useDefault(v, c)
				continue
			}
			end := varEnds[idx]
			if end&0x8000 != 0 {
				continue
			}
			start := 0
			if idx > 0 {
				start = int(varEnds[idx-1] & 0x7FFF)
			}
			if start > int(end) || varDataStart+int(end) > len(rec) {
				v.Err = fmt.Errorf("%w: variable column %q lies outside the record", ErrCorrupt, c.Name)
				continue
			}
			v.Null, v.Raw = false, rec[varDataStart+start:varDataStart+int(end)]
		default:
			e := tags[c.ID]
			if e == nil {
				useDefault(v, c)
				continue
			}
			if e.null {
				continue
			}
			t.tagged(v, c, rec[e.start:e.end], e.hdrFlags)
		}
	}
	_ = order
	return vals, nil
}

func useDefault(v *Value, c *Column) {
	if len(c.Default) > 0 {
		v.Null, v.Raw = false, c.Default
	}
}

const (
	tagLongValue  = 0x01
	tagCompressed = 0x02
	tagSeparated  = 0x04
	tagMulti      = 0x08
	tagTwoValues  = 0x10
)

// tagged fills v from the bytes of a tagged column.
func (t *Table) tagged(v *Value, c *Column, b []byte, flags uint8) {
	v.Null = false
	switch {
	case flags&tagMulti != 0:
		parts, err := splitMulti(b, flags)
		if err != nil {
			v.Err = err
			return
		}
		for i, p := range parts {
			if p.separated {
				lv, err := t.longValue(p.data)
				if err != nil {
					v.Err = err
					return
				}
				parts[i].data = lv
			}
		}
		for i, p := range parts {
			d := p.data
			if i == 0 && flags&tagCompressed != 0 {
				dd, err := decompress(d)
				if err != nil {
					v.Err = err
					return
				}
				d = dd
			}
			v.Multi = append(v.Multi, d)
		}
	case flags&tagSeparated != 0:
		lv, err := t.longValue(b)
		if err != nil {
			v.Err = err
			return
		}
		v.Raw = lv
	case flags&tagCompressed != 0:
		d, err := decompress(b)
		if err != nil {
			v.Err = err
			return
		}
		v.Raw = d
	default:
		v.Raw = b
	}
}

type multiPart struct {
	data      []byte
	separated bool
}

// splitMulti cuts a multi-value into its values.
func splitMulti(b []byte, flags uint8) ([]multiPart, error) {
	if flags&tagTwoValues != 0 {
		if len(b) < 1 || 1+int(b[0]) > len(b) {
			return nil, fmt.Errorf("%w: two-value column is cut", ErrCorrupt)
		}
		n := int(b[0])
		return []multiPart{{data: b[1 : 1+n]}, {data: b[1+n:]}}, nil
	}
	if len(b) < 2 {
		return nil, fmt.Errorf("%w: multi-value column is cut", ErrCorrupt)
	}
	first := int(binary.LittleEndian.Uint16(b[0:2]) & 0x7FFF)
	if first%2 != 0 || first == 0 || first > len(b) {
		return nil, fmt.Errorf("%w: multi-value offset array is invalid", ErrCorrupt)
	}
	n := first / 2
	offs := make([]uint16, n+1)
	for i := 0; i < n; i++ {
		offs[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	offs[n] = uint16(len(b))
	out := make([]multiPart, n)
	for i := 0; i < n; i++ {
		s, e := int(offs[i]&0x7FFF), int(offs[i+1]&0x7FFF)
		if s > e || e > len(b) {
			return nil, fmt.Errorf("%w: multi-value offsets run backwards", ErrCorrupt)
		}
		out[i] = multiPart{data: b[s:e], separated: offs[i]&0x8000 != 0}
	}
	return out, nil
}

// longValue fetches a long value from the table's long value tree. ref is the
// identifier as stored in the record.
func (t *Table) longValue(ref []byte) ([]byte, error) {
	if (len(ref) != 4 && len(ref) != 8) || t.LVFDP == 0 {
		return nil, fmt.Errorf("%w: long value reference of %d bytes with no long value tree", ErrCorrupt, len(ref))
	}
	key := make([]byte, len(ref))
	for i := range ref {
		key[len(ref)-1-i] = ref[i]
	}
	var total uint64
	haveHead := false
	type seg struct {
		off  uint32
		data []byte
	}
	var segs []seg
	err := t.db.seek(t.LVFDP, key, func(k, data []byte) (bool, error) {
		if !bytes.HasPrefix(k, key) {
			return false, nil
		}
		switch len(k) - len(key) {
		case 0:
			if len(data) >= 8 {
				total = uint64(binary.LittleEndian.Uint32(data[4:8]))
				haveHead = true
			}
		case 4:
			segs = append(segs, seg{binary.BigEndian.Uint32(k[len(key):]), append([]byte(nil), data...)})
		}
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	if !haveHead || total > maxValueBytes {
		return nil, fmt.Errorf("%w: long value has no usable header or is larger than %d bytes", ErrCorrupt, maxValueBytes)
	}
	out := make([]byte, 0, total)
	for i, s := range segs {
		next := total
		if i+1 < len(segs) {
			next = uint64(segs[i+1].off)
		}
		if uint64(s.off) != uint64(len(out)) || next < uint64(s.off) {
			return nil, fmt.Errorf("%w: long value segments are not contiguous", ErrCorrupt)
		}
		want := next - uint64(s.off)
		d := s.data
		if uint64(len(d)) != want {
			dd, err := decompress(d)
			if err != nil || uint64(len(dd)) != want {
				return nil, fmt.Errorf("%w: long value segment is %d bytes, expected %d", ErrCorrupt, len(d), want)
			}
			d = dd
		}
		out = append(out, d...)
	}
	if uint64(len(out)) != total {
		return nil, fmt.Errorf("%w: long value is %d bytes, header says %d", ErrCorrupt, len(out), total)
	}
	return out, nil
}

// seek descends to the first entry whose key is not smaller than target and
// calls fn on it and on each following entry, across leaf pages, until fn
// returns false.
func (db *DB) seek(root uint32, target []byte, fn func(key, data []byte) (bool, error)) error {
	n := root
	for depth := 0; ; depth++ {
		if depth > maxTreeDepth {
			return fmt.Errorf("%w: tree deeper than %d levels", ErrCorrupt, maxTreeDepth)
		}
		p, err := db.page(n)
		if err != nil {
			return err
		}
		if p.is(pageFlagLeaf) {
			break
		}
		var child uint32
		found := false
		for i := 1; i < len(p.tags); i++ {
			key, data, ok := db.entry(p, i)
			if !ok || len(data) < 4 {
				continue
			}
			child = binary.LittleEndian.Uint32(data[:4])
			if len(key) == 0 || bytes.Compare(key, target) >= 0 {
				found = true
				break
			}
		}
		if !found && child == 0 {
			return nil
		}
		n = child
	}
	seen := map[uint32]bool{}
	for n != 0 {
		if seen[n] {
			return fmt.Errorf("%w: leaf chain loops at page %d", ErrCorrupt, n)
		}
		seen[n] = true
		p, err := db.page(n)
		if err != nil {
			return err
		}
		for i := 1; i < len(p.tags); i++ {
			if p.tags[i].flags&tagFlagDefunct != 0 && db.small {
				continue
			}
			key, data, ok := db.entry(p, i)
			if !ok || bytes.Compare(key, target) < 0 {
				continue
			}
			cont, err := fn(key, data)
			if err != nil || !cont {
				return err
			}
		}
		n = p.next
	}
	return nil
}
