// Modified native Go adaptation of mandiant/flare-wmi python-cim/cim,
// revision b0a5a094ff9ca7d7a1c4fc711dc00c74dec4b6b1 (Apache-2.0).
// Changes include bounded readers, strict validation and physical provenance.
// See NOTICE.txt and LICENSE.apache-2.0.txt in this directory.
package wmirepo

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// PropertyDefinition retains the declared class layout and key qualifier.
type PropertyDefinition struct {
	Name           string
	Type           CIMType
	Index, Offset  int
	Key            bool
	MetadataOffset int
}

// ClassDefinition contains record-relative offsets, not inferred timestamps.
type ClassDefinition struct {
	Name, Super, NativeKey       string
	TimestampTicks               uint64
	Properties                   []PropertyDefinition
	Defaults, Region             []byte
	DefaultsOffset, RegionOffset int
	Record                       Record
}

// Structures below adapt the Apache-2.0 flare-wmi layout; see NOTICE.txt.
// A cursor never allocates from an unchecked record-relative size.
type cursor struct {
	b   []byte
	at  int
	err error
}

func (c *cursor) take(n int) []byte {
	if c.err != nil {
		return nil
	}
	if n < 0 || n > len(c.b)-c.at {
		c.err = fmt.Errorf("%w: semantic structure bounds at %d size %d remaining %d", ErrCorrupt, c.at, n, len(c.b)-c.at)
		return nil
	}
	b := c.b[c.at : c.at+n]
	c.at += n
	return b
}
func (c *cursor) u32() uint32 {
	b := c.take(4)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(b)
}
func (c *cursor) region() ([]byte, int) {
	n := c.u32() & 0x7fffffff
	base := c.at
	return c.take(int(n)), base
}
func wmiString(b []byte, offset int) (string, int, error) {
	if offset < 0 || offset >= len(b) {
		return "", 0, fmt.Errorf("%w: name offset", ErrCorrupt)
	}
	if b[offset] != 0 {
		return "", 0, fmt.Errorf("%w: name encoding", ErrUnsupported)
	}
	n := bytes.IndexByte(b[offset+1:], 0)
	if n < 0 || !utf8.Valid(b[offset+1:offset+1+n]) {
		return "", 0, fmt.Errorf("%w: name terminator/UTF8", ErrCorrupt)
	}
	return string(b[offset+1 : offset+1+n]), n + 2, nil
}
func cimType(b []byte) (CIMType, error) {
	if len(b) != 4 {
		return CIMType{}, fmt.Errorf("%w: type bounds", ErrCorrupt)
	}
	// Reserved high bytes are opaque and retained in the record, not type flags.
	if b[1] != 0 && b[1] != 0x20 {
		return CIMType{}, fmt.Errorf("%w: CIM array flag", ErrUnsupported)
	}
	t := CIMType{Code: b[0], Array: b[1] == 0x20}
	_, err := scalarWidth(t.Code)
	return t, err
}
func slotWidth(t CIMType) (int, error) {
	if t.Array {
		_, err := scalarWidth(t.Code)
		return 4, err
	}
	return scalarWidth(t.Code)
}

type qualifier struct {
	ref  uint32
	typ  CIMType
	slot []byte
}

func readQualifiers(c *cursor) ([]qualifier, error) {
	start := c.at
	size := int(c.u32())
	if c.err != nil {
		return nil, c.err
	}
	if size < 4 || size > len(c.b)-start {
		return nil, fmt.Errorf("%w: qualifier list size", ErrCorrupt)
	}
	qcur := cursor{b: c.take(size - 4)}
	out := []qualifier{}
	for qcur.at < len(qcur.b) {
		if len(out) >= 4096 {
			return nil, fmt.Errorf("%w: qualifier count", ErrUnsupported)
		}
		ref := qcur.u32()
		qcur.take(1)
		t, err := cimType(qcur.take(4))
		if err != nil {
			return nil, err
		}
		w, err := slotWidth(t)
		if err != nil {
			return nil, err
		}
		slot := qcur.take(w)
		if qcur.err != nil {
			return nil, qcur.err
		}
		out = append(out, qualifier{ref, t, slot})
	}
	return out, nil
}
func unicodeName(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", fmt.Errorf("%w: UTF16 name length", ErrCorrupt)
	}
	units := make([]uint16, len(b)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	for i := 0; i < len(units); i++ {
		u := units[i]
		if u == 0 {
			return "", fmt.Errorf("%w: embedded name NUL", ErrCorrupt)
		}
		if u >= 0xd800 && u <= 0xdbff {
			if i+1 >= len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
				return "", fmt.Errorf("%w: UTF16 surrogate", ErrCorrupt)
			}
			i++
		} else if u >= 0xdc00 && u <= 0xdfff {
			return "", fmt.Errorf("%w: UTF16 surrogate", ErrCorrupt)
		}
	}
	return string(utf16.Decode(units)), nil
}
func DecodeClass(record Record, nativeKey string) (ClassDefinition, error) {
	out := ClassDefinition{NativeKey: nativeKey, Record: record}
	if len(record.Bytes) > MaxRecord {
		return out, fmt.Errorf("%w: class size", ErrUnsupported)
	}
	c := cursor{b: record.Bytes}
	n := c.u32()
	if n > 4096 {
		return out, fmt.Errorf("%w: superclass length", ErrCorrupt)
	}
	superRaw := c.take(int(n) * 2)
	if c.err != nil {
		return out, c.err
	}
	var err error
	out.Super, err = unicodeName(superRaw)
	if err != nil {
		return out, err
	}
	ticks := c.take(8)
	if c.err != nil {
		return out, c.err
	}
	out.TimestampTicks = binary.LittleEndian.Uint64(ticks)
	dataStart := c.at
	dataLen := c.u32()
	c.take(1)
	nameRef := c.u32()
	defaultsLen := c.u32()
	asciiLen := c.u32()
	if c.err != nil {
		return out, c.err
	}
	if uint64(dataLen) > uint64(len(c.b)-dataStart) {
		return out, fmt.Errorf("%w: class forward length", ErrCorrupt)
	}
	if asciiLen != 4 {
		if asciiLen < 8 || uint64(asciiLen) > uint64(len(c.b)-c.at+4) {
			return out, fmt.Errorf("%w: superclass ASCII length", ErrCorrupt)
		}
		name, width, e := wmiString(c.b, c.at)
		if e != nil {
			return out, e
		}
		c.take(width)
		c.u32()
		if name != out.Super {
			return out, fmt.Errorf("%w: superclass names disagree", ErrCorrupt)
		}
	} else if out.Super != "" {
		return out, fmt.Errorf("%w: absent superclass ASCII name", ErrCorrupt)
	}
	if _, err = readQualifiers(&c); err != nil {
		return out, err
	}
	count := c.u32()
	if c.err != nil {
		return out, c.err
	}
	if count > 4096 || uint64(count) > uint64((len(c.b)-c.at)/8) {
		return out, fmt.Errorf("%w: class property count", ErrCorrupt)
	}
	refs := c.take(int(count) * 8)
	out.DefaultsOffset = c.at
	out.Defaults = c.take(int(defaultsLen))
	out.Region, out.RegionOffset = c.region()
	// The method trailer is opaque: its declared extent includes its length
	// field. It is not a property-value DataRegion. No method is executed or
	// represented as a selected instance by this reader.
	methodSize := c.u32()
	if methodSize != 0 {
		if methodSize < 4 {
			return out, fmt.Errorf("%w: method trailer size", ErrCorrupt)
		}
		c.take(int(methodSize) - 4)
	}
	if c.err != nil {
		return out, c.err
	}
	if c.at != len(c.b) {
		return out, fmt.Errorf("%w: class trailing layout", ErrUnsupported)
	}
	out.Name, _, err = wmiString(out.Region, int(nameRef))
	if err != nil {
		return out, err
	}
	if out.Name == "" {
		return out, fmt.Errorf("%w: empty class name", ErrCorrupt)
	}
	seenNames := map[string]bool{}
	metadataBudget := byteBudget{limit: 1 << 20}
	seenIndices := map[int]bool{}
	for i := 0; i < int(count); i++ {
		nameOff := binary.LittleEndian.Uint32(refs[i*8:])
		metaOff := binary.LittleEndian.Uint32(refs[i*8+4:])
		if nameOff&0x80000000 != 0 {
			return out, fmt.Errorf("%w: builtin property name", ErrUnsupported)
		}
		name, _, e := wmiString(out.Region, int(nameOff))
		if e != nil {
			return out, e
		}
		if uint64(metaOff) > uint64(len(out.Region)) {
			return out, fmt.Errorf("%w: property metadata offset", ErrCorrupt)
		}
		pc := cursor{b: out.Region, at: int(metaOff)}
		typ, e := cimType(pc.take(4))
		if e != nil {
			return out, e
		}
		ix := pc.take(2)
		if pc.err != nil {
			return out, pc.err
		}
		prop := PropertyDefinition{Name: name, Type: typ, Index: int(binary.LittleEndian.Uint16(ix)), Offset: int(pc.u32()), MetadataOffset: out.RegionOffset + int(metaOff)}
		pc.u32()
		quals, e := readQualifiers(&pc)
		if e != nil {
			return out, e
		}
		for _, q := range quals {
			if q.ref == 0x80000001 {
				if q.typ != (CIMType{Code: 11}) {
					return out, fmt.Errorf("%w: key qualifier type", ErrUnsupported)
				}
				v, e := DecodeValue(out.Region, q.slot, q.typ)
				if e != nil {
					return out, e
				}
				prop.Key = v.Value == true
			}
		}
		if len(name) > 4096 {
			return out, fmt.Errorf("%w: property name size", ErrUnsupported)
		}
		if err := metadataBudget.charge(len(name)); err != nil {
			return out, err
		}
		lower := strings.ToLower(name)
		if name == "" || seenNames[lower] || seenIndices[prop.Index] {
			return out, fmt.Errorf("%w: duplicate class property", ErrCorrupt)
		}
		seenNames[lower] = true
		seenIndices[prop.Index] = true
		out.Properties = append(out.Properties, prop)
	}
	return out, nil
}
