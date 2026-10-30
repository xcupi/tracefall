package defenderhistory

import (
	"encoding/binary"
	"fmt"
	"time"
)

// Record is private raw evidence. It must never be copied to Event.Extra.
type Record struct {
	Entries     []Entry
	DetectionID string
	ThreatID    uint64
	Resources   []Resource
	Times       []Clock
	EOF         int
}
type Resource struct {
	Offset         int
	Following      bool
	Kind, Location string
	Blob           []Value
}
type Value struct {
	Offset, End int
	Key         string
	Type        uint32
	Raw         []byte
	Text        string
	Bits        uint64
}
type Clock struct {
	Role          string
	Offset        int
	Ticks         uint64
	Zero          bool
	UnixSeconds   int64
	Fraction100ns uint32
}

func (c Clock) Time() time.Time {
	if c.Zero {
		return time.Time{}
	}
	return time.Unix(c.UnixSeconds, int64(c.Fraction100ns)*100).UTC()
}

// Decode accepts exactly one modern record. Optional/legacy variants are not
// reparsed heuristically. All offsets are absolute source byte offsets.
func Decode(data []byte) (*Record, error) {
	entries, err := ReadEntries(data)
	if err != nil {
		return nil, err
	}
	c := recordCursor{entries: entries}
	r := &Record{Entries: entries}
	r.ThreatID = c.take(8).Bits
	guid := c.take(30)
	if c.err != nil {
		return nil, c.err
	}
	r.DetectionID = formatGUID(guid.Raw)
	c.magic()
	c.take(21) // literal threat label stays private
	flag1 := c.take(6).Bits
	for i := 0; i < 5; i++ {
		c.take(6)
	} // unknown flags and raw status; no enum inference
	list := c.count(MaxEntries)
	for i := 0; i < list; i++ {
		c.take(6)
	}
	resources := c.count(MaxResources)
	readResources := func(n int, following bool) {
		for i := 0; i < n && c.err == nil; i++ {
			marker := c.magic()
			kind := c.take(21)
			location := c.take(21)
			c.take(6)
			declared := c.take(6)
			blob := c.take(40)
			if c.err != nil {
				return
			}
			if declared.Bits != uint64(len(blob.Raw)) {
				c.err = fmt.Errorf("history: resource blob size at %d", blob.Offset)
				return
			}
			values, e := readNested(blob.Raw, blob.Offset+8)
			if e != nil {
				c.err = e
				return
			}
			r.Resources = append(r.Resources, Resource{Offset: marker.Offset, Following: following, Kind: kind.Text, Location: location.Text, Blob: values})
		}
	}
	readResources(resources, false)
	addTime := func(role string) { e := c.take(10); r.Times = append(r.Times, clock(role, e.Offset, e.Bits)) }
	addTime("last_threat_status_change")
	c.take(5)
	c.take(6)
	c.take(30)
	c.take(6)
	if flag1 == 4 {
		return nil, fmt.Errorf("history: unsupported optional section")
	}
	c.take(6)
	c.take(21)
	c.take(6)
	c.take(21)
	for i := 0; i < 3; i++ {
		c.take(6)
	}
	addTime("initial_detection_time")
	c.take(6)
	addTime("remediation_time")
	c.take(6)
	c.take(0)
	c.take(6)
	c.take(21)
	c.take(6)
	following := c.count(MaxResources - resources)
	readResources(following, true)
	c.take(0)
	for i := 0; i < 4; i++ {
		c.take(6)
	}
	if c.err != nil {
		return nil, c.err
	}
	if c.pos != len(entries) {
		return nil, fmt.Errorf("history: unexpected trailing entries at %d", entries[c.pos].Offset)
	}
	r.EOF = len(data)
	return r, nil
}

type recordCursor struct {
	entries []Entry
	pos     int
	err     error
}

func (c *recordCursor) take(typ uint32) Entry {
	if c.err != nil {
		return Entry{}
	}
	if c.pos >= len(c.entries) {
		c.err = fmt.Errorf("history: incomplete record at entry %d", c.pos)
		return Entry{}
	}
	e := c.entries[c.pos]
	c.pos++
	if e.Type != typ {
		c.err = fmt.Errorf("history: expected type %d at %d, got %d", typ, e.Offset, e.Type)
	}
	return e
}
func (c *recordCursor) magic() Entry {
	e := c.take(21)
	if c.err == nil && e.Text != "Magic.Version:1.2" {
		c.err = fmt.Errorf("history: unsupported magic/version at %d", e.Offset)
	}
	return e
}
func (c *recordCursor) count(cap int) int {
	e := c.take(6)
	if e.Bits > uint64(cap) {
		c.err = fmt.Errorf("history: count exceeds %d at %d", cap, e.Offset)
		return 0
	}
	return int(e.Bits)
}
func formatGUID(b []byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x", binary.LittleEndian.Uint32(b), binary.LittleEndian.Uint16(b[4:]), binary.LittleEndian.Uint16(b[6:]), b[8:10], b[10:])
}
func clock(role string, offset int, ticks uint64) Clock {
	return Clock{Role: role, Offset: offset, Ticks: ticks, Zero: ticks == 0, UnixSeconds: int64(ticks/10000000) - 11644473600, Fraction100ns: uint32(ticks % 10000000)}
}

type blobCursor struct {
	b         []byte
	pos, base int
	err       error
}

func (c *blobCursor) take(n uint64) []byte {
	if c.err != nil {
		return nil
	}
	if n > uint64(len(c.b)-c.pos) {
		c.err = fmt.Errorf("history: nested bounds at %d", c.base+c.pos)
		return nil
	}
	v := c.b[c.pos : c.pos+int(n)]
	c.pos += int(n)
	return v
}
func (c *blobCursor) num() uint32 {
	v := c.take(4)
	if c.err != nil {
		return 0
	}
	return binary.LittleEndian.Uint32(v)
}
func (c *blobCursor) str() string {
	n := c.num()
	v := c.take(uint64(n))
	if c.err != nil {
		return ""
	}
	s, e := decodeWide(v)
	if e != nil {
		c.err = fmt.Errorf("history: nested UTF16 at %d", c.base+c.pos)
	}
	return s
}
func readNested(b []byte, base int) ([]Value, error) {
	if len(b) == 0 {
		return nil, nil
	}
	c := blobCursor{b: b, base: base}
	version := c.num()
	hs := c.num()
	vs := c.num()
	total := c.num()
	c.num() // unknown header bits, retained in the outer raw entry
	if c.err != nil {
		return nil, c.err
	}
	if version != 1 || hs != 20 {
		return nil, fmt.Errorf("history: unsupported nested header at %d", base)
	}
	// values-size includes its own repeated length word when nonempty.
	if total != uint32(len(b)) || uint64(vs)+20 != uint64(total) {
		return nil, fmt.Errorf("history: nested size at %d", base)
	}
	if vs == 0 {
		return nil, nil
	}
	vs2 := c.num()
	if c.err != nil {
		return nil, c.err
	}
	if vs != vs2 {
		return nil, fmt.Errorf("history: nested repeated size at %d", base)
	}
	var out []Value
	for c.pos < len(b) && c.err == nil {
		if len(out) >= MaxNestedValues {
			return nil, fmt.Errorf("history: nested value cap at %d", base+c.pos)
		}
		start := c.pos
		k := c.str()
		typ := c.num()
		v := Value{Offset: base + start, Key: k, Type: typ}
		switch typ {
		case 3:
			v.Bits = uint64(c.num())
		case 4:
			p := c.take(8)
			if c.err == nil {
				v.Bits = binary.LittleEndian.Uint64(p)
			}
		case 5:
			p := c.take(1)
			if c.err == nil {
				v.Bits = uint64(p[0])
			}
		case 6:
			v.Text = c.str()
		case 7:
			n := c.num()
			p := c.take(uint64(n))
			for _, ch := range p {
				if ch > 127 {
					c.err = fmt.Errorf("history: unsupported non-ASCII type7 at %d", base+start)
				}
			}
			v.Text = string(p)
		default:
			return nil, fmt.Errorf("history: unsupported nested type %d at %d", typ, base+start)
		}
		if c.err != nil {
			return nil, c.err
		}
		v.End = base + c.pos
		v.Raw = b[start:c.pos]
		out = append(out, v)
	}
	if c.err != nil {
		return nil, c.err
	}
	return out, nil
}
