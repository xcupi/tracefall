package wmirepo

import (
	"encoding/binary"
	"errors"
	"testing"
)

func appendU32(b []byte, values ...uint32) []byte {
	for _, v := range values {
		b = binary.LittleEndian.AppendUint32(b, v)
	}
	return b
}
func neutralClass() Record {
	// Header: no parent, raw ticks, forward length, opaque byte, class offset,
	// default length, absent ASCII superclass marker. Two declared properties.
	region := []byte("\x00NeutralClass\x00\x00Name\x00\x00Count\x00")
	nameMeta := len(region)
	region = appendU32(region, 8)
	region = binary.LittleEndian.AppendUint16(region, 0)
	region = appendU32(region, 0, 0, 15, 0x80000001)
	region = append(region, 0)
	region = appendU32(region, 11)
	region = binary.LittleEndian.AppendUint16(region, 0xffff)
	countMeta := len(region)
	region = appendU32(region, 19)
	region = binary.LittleEndian.AppendUint16(region, 1)
	region = appendU32(region, 4, 0, 4)
	b := appendU32(nil, 0)
	b = binary.LittleEndian.AppendUint64(b, 123456789)
	b = appendU32(b, 0)
	b = append(b, 0)
	b = appendU32(b, 0, 9, 4, 4, 2, 14, uint32(nameMeta), 20, uint32(countMeta))
	b = append(b, 0)
	b = appendU32(b, 0, 7, uint32(len(region)))
	b = append(b, region...)
	b = appendU32(b, 0)
	binary.LittleEndian.PutUint32(b[12:], uint32(len(b)-12))
	return Record{Bytes: b, Spans: []Span{{File: "OBJECTS.DATA", Offset: 800, Length: len(b)}}}
}

func TestDecodeClassDeclaredLayoutAndKey(t *testing.T) {
	r := neutralClass()
	c, err := DecodeClass(r, "literal-class-key")
	if err != nil {
		t.Fatalf("decode class: %v", err)
	}
	if c.Name != "NeutralClass" || c.Super != "" || c.TimestampTicks != 123456789 || c.NativeKey != "literal-class-key" {
		t.Fatalf("class header not retained: %+v", c)
	}
	if len(c.Properties) != 2 || c.Properties[0].Name != "Name" || !c.Properties[0].Key || c.Properties[0].Type != (CIMType{Code: 8}) || c.Properties[1].Name != "Count" || c.Properties[1].Index != 1 || c.Properties[1].Offset != 4 {
		t.Fatalf("declared metadata: %+v", c.Properties)
	}
	if len(c.Defaults) != 9 || binary.LittleEndian.Uint32(c.Defaults[5:]) != 7 || c.RegionOffset <= c.DefaultsOffset || c.Record.Spans[0] != r.Spans[0] {
		t.Fatal("class data origin lost")
	}
}

func TestDecodeClassInclusiveMethodRegion(t *testing.T) {
	r := neutralClass()
	binary.LittleEndian.PutUint32(r.Bytes[len(r.Bytes)-4:], 12)
	r.Bytes = append(r.Bytes, 0, 0, 0, 0, 0, 0, 0, 0x80)
	binary.LittleEndian.PutUint32(r.Bytes[12:], uint32(len(r.Bytes)-12))
	if c, err := DecodeClass(r, "key"); err != nil || c.Name != "NeutralClass" {
		t.Fatalf("bounded opaque method trailer: %v", err)
	}
}

func TestDecodeClassBoundsAndUnsupportedType(t *testing.T) {
	r := neutralClass()
	for n := 0; n < len(r.Bytes); n++ {
		cut := r
		cut.Bytes = r.Bytes[:n]
		if _, err := DecodeClass(cut, "key"); err == nil {
			t.Fatalf("truncated class accepted at %d", n)
		}
	}
	bad := neutralClass()
	binary.LittleEndian.PutUint32(bad.Bytes[33:], 0xffffffff)
	if _, err := DecodeClass(bad, "key"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("property count: %v", err)
	}
	bad = neutralClass() // Last property metadata starts 22 bytes before method size.
	bad.Bytes[len(bad.Bytes)-22] = 103
	if _, err := DecodeClass(bad, "key"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported CIM type: %v", err)
	}
}
