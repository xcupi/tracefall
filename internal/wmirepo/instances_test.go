package wmirepo

import (
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func neutralInstance(state byte) Record {
	b := make([]byte, 128)
	for i := 0; i < 64; i++ {
		b[2*i] = 'A'
	}
	b = binary.LittleEndian.AppendUint64(b, 111)
	b = binary.LittleEndian.AppendUint64(b, 222)
	b = appendU32(b, 0, 0)
	b = append(b, 0, state)
	b = appendU32(b, 14, 999, 4)
	b = append(b, 1) // no dynamic property metadata
	region := []byte("\x00NeutralClass\x00\x00entry01\x00")
	b = appendU32(b, uint32(len(region)))
	b = append(b, region...)
	// Win7 forward length begins at the length field, after hash and ticks.
	binary.LittleEndian.PutUint32(b[144:], uint32(len(b)-144))
	return Record{Bytes: b, Spans: []Span{{File: "OBJECTS.DATA", Offset: 3000, Length: len(b)}}}
}
func neutralLoad(t *testing.T) func(string) (ClassDefinition, error) {
	t.Helper()
	c, err := DecodeClass(neutralClass(), "class-key")
	if err != nil {
		t.Fatal(err)
	}
	return func(name string) (ClassDefinition, error) {
		if name == c.Name {
			return c, nil
		}
		return ClassDefinition{}, ErrUnsupported
	}
}
func TestLayoutAndInstancePresenceOrigin(t *testing.T) {
	l, err := BuildLayout("NeutralClass", neutralLoad(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Properties) != 2 || l.SlotLength != 8 {
		t.Fatalf("layout: %+v", l)
	}
	o, err := DecodeInstance(neutralInstance(8), "literal-instance-key", l)
	if err != nil {
		t.Fatal(err)
	}
	if o.Class != "NeutralClass" || o.NativeKey != "literal-instance-key" || o.NameHash != strings.Repeat("A", 64) || o.TimestampTicks != ([2]uint64{111, 222}) || !reflect.DeepEqual(o.KeyProperties, map[string]any{"Name": "entry01"}) {
		t.Fatalf("instance identity/ticks: %+v", o)
	}
	name, count := o.Properties["Name"], o.Properties["Count"]
	if name.Value != "entry01" || name.Presence != "explicit" || len(name.StateSpans) != 1 || len(name.ValueSpans) != 1 || name.SlotSpans[0].Offset != 3154 {
		t.Fatalf("explicit field: %+v", name)
	}
	if count.Value != uint32(7) || count.Presence != "default" || count.DefaultClassNativeKey != "class-key" || count.SlotSpans[0].Offset != 858 || len(count.DefaultStateSpans) != 1 {
		t.Fatalf("default field: %+v", count)
	}
	// Bit0 means uninitialized, even if the stale slot would decode successfully.
	o, err = DecodeInstance(neutralInstance(4), "key", l)
	if err != nil {
		t.Fatal(err)
	}
	if p := o.Properties["Count"]; p.Presence != "uninitialized" || p.Value != nil || len(p.SlotSpans) != 0 {
		t.Fatalf("uninitialized value read: %+v", p)
	}
}
func TestLayoutInheritanceAndDefaultOrigin(t *testing.T) {
	base, err := DecodeClass(neutralClass(), "base-key")
	if err != nil {
		t.Fatal(err)
	}
	leaf := base
	leaf.Name = "ChildClass"
	leaf.Super = base.Name
	leaf.NativeKey = "leaf-key"
	leaf.Properties = nil
	leaf.Defaults = append([]byte(nil), base.Defaults...)
	leaf.Defaults[0] = 0x0a
	load := func(n string) (ClassDefinition, error) {
		if n == base.Name {
			return base, nil
		}
		if n == leaf.Name {
			return leaf, nil
		}
		return ClassDefinition{}, ErrUnsupported
	}
	l, err := BuildLayout(leaf.Name, load)
	if err != nil {
		t.Fatal(err)
	}
	// Use a child record with the same encoded length to avoid offset changes.
	leaf.Name = "DerivedClass"
	leaf.Super = base.Name
	load = func(n string) (ClassDefinition, error) {
		if n == base.Name {
			return base, nil
		}
		return leaf, nil
	}
	l, err = BuildLayout(leaf.Name, load)
	if err != nil {
		t.Fatal(err)
	}
	r := neutralInstance(8)
	copy(r.Bytes[len(r.Bytes)-len("\x00NeutralClass\x00\x00entry01\x00")+1:], "DerivedClass")
	o, err := DecodeInstance(r, "key", l)
	if err != nil {
		t.Fatal(err)
	}
	if p := o.Properties["Count"]; p.Value != uint32(7) || p.DefaultClassNativeKey != "base-key" {
		t.Fatalf("inherited default: %+v", p)
	}
	leaf.Super = leaf.Name
	if _, err = BuildLayout(leaf.Name, load); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("inheritance cycle: %v", err)
	}
}
func TestLayoutAndInstanceRejectUnknownOrAmbiguous(t *testing.T) {
	load := neutralLoad(t)
	base, _ := load("NeutralClass")
	for _, change := range []func(*ClassDefinition){func(c *ClassDefinition) { c.Properties[1].Index = 3 }, func(c *ClassDefinition) { c.Properties[1].Offset = 9 }} {
		c := base
		c.Properties = append([]PropertyDefinition(nil), base.Properties...)
		change(&c)
		if _, err := BuildLayout(c.Name, func(string) (ClassDefinition, error) { return c, nil }); err == nil {
			t.Fatal("unvalidated dense/packed layout accepted")
		}
	}
	l, err := BuildLayout(base.Name, load)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Record){func(r *Record) { r.Bytes[167] = 2 }, func(r *Record) { r.Bytes[144] = 1 }, func(r *Record) { r.Bytes[len(r.Bytes)-10] = 'X' }, func(r *Record) { r.Bytes = r.Bytes[:155] }} {
		r := neutralInstance(8)
		change(&r)
		if _, err := DecodeInstance(r, "key", l); err == nil {
			t.Fatal("invalid instance accepted")
		}
	}
	c := base
	c.Defaults = append([]byte(nil), c.Defaults...)
	c.Defaults[0] = 4
	l, err = BuildLayout(c.Name, func(string) (ClassDefinition, error) { return c, nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeInstance(neutralInstance(8), "key", l); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("unavailable default accepted: %v", err)
	}
}
