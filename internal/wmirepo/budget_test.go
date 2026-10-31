package wmirepo

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

func TestByteBudgetRejectsAggregateOverflowBeforeRetention(t *testing.T) {
	b := byteBudget{limit: 7}
	if err := b.charge(7); err != nil || b.used != 7 {
		t.Fatal("exact bounded accounting missing")
	}
	for _, n := range []int{1, -1, int(^uint(0) >> 1)} {
		if err := b.charge(n); err == nil || b.used != 7 {
			t.Fatal("aggregate budget overrun/negative/overflow accepted")
		}
	}
}

func TestValueRepeatedReferencesHaveDecodedByteBudget(t *testing.T) {
	// A small source can reference the same long string many times. Count/record
	// caps alone do not bound the heap of independently decoded copies.
	region := appendU32(nil, 100)
	for range 100 {
		region = appendU32(region, 404)
	}
	region = append(region, 0)
	region = append(region, strings.Repeat("a", 64<<10)...)
	region = append(region, 0)
	_, err := DecodeValue(region, binary.LittleEndian.AppendUint32(nil, 0), CIMType{Code: 8, Array: true})
	if err == nil {
		t.Fatal("repeated string references expanded beyond decoded byte budget")
	}
}

func TestInstanceDecodedAggregateBudget(t *testing.T) {
	const count = 130
	props := []PropertyDefinition{}
	for i := 0; i < count; i++ {
		props = append(props, PropertyDefinition{Name: fmt.Sprintf("Field%03d", i), Index: i, Offset: i * 4, Type: CIMType{Code: 8}})
	}
	b := make([]byte, 128)
	for i := 0; i < 64; i++ {
		b[i*2] = 'A'
	}
	b = appendU32(b, 0, 0, 0, 0, 0, 0)
	b = append(b, 0)
	b = append(b, make([]byte, (count+3)/4)...)
	for range count {
		b = appendU32(b, 14)
	}
	b = appendU32(b, 4)
	b = append(b, 1)
	region := []byte("\x00NeutralClass\x00\x00")
	region = append(region, strings.Repeat("a", 128<<10)...)
	region = append(region, 0)
	b = appendU32(b, uint32(len(region)))
	b = append(b, region...)
	binary.LittleEndian.PutUint32(b[144:], uint32(len(b)-144))
	r := Record{Bytes: b, Spans: []Span{{File: "OBJECTS.DATA", Length: len(b)}}}
	l := Layout{Classes: []ClassDefinition{{Name: "NeutralClass"}}, Properties: props, SlotLength: count * 4}
	if _, err := DecodeInstance(r, "key", l); err == nil {
		t.Fatal("many valid scalar references expanded past per-instance decoded budget")
	}
}
