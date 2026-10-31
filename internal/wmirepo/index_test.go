package wmirepo

import (
	"encoding/binary"
	"testing"
)

// Independently laid out single-key node: header20, opaque4, children8,
// key offset2, definition count2/values4, string count2/offsets4, payload.
func indexNode(key string, child uint32) []byte {
	b := make([]byte, PageSize)
	copy(b, words(0xaccc, 1, 0, 0, 1, 0, child, 0xffffffff))
	binary.LittleEndian.PutUint16(b[32:], 0)
	binary.LittleEndian.PutUint16(b[34:], 2)
	binary.LittleEndian.PutUint16(b[36:], 1)
	binary.LittleEndian.PutUint16(b[38:], 0)
	binary.LittleEndian.PutUint16(b[40:], 1)
	binary.LittleEndian.PutUint16(b[42:], 0)
	binary.LittleEndian.PutUint16(b[44:], uint16(len(key)+1))
	copy(b[46:], key)
	return b
}
func TestIndexLiteralKeysAndSpans(t *testing.T) {
	b := append(make([]byte, PageSize), indexNode("NS_A/CI_B/IL_C.0.7.8", 0)...)
	p := Physical{Index: file(b), IndexMap: Mapping{Entries: [][6]uint32{{0, 0, 0, 1}, {1}}}}
	got, err := p.ReadIndex()
	if err != nil || len(got) != 1 {
		t.Fatalf("index missing: %+v %v", got, err)
	}
	if got[0].Key != "NS_A/CI_B/IL_C.0.7.8" || got[0].Fragments[0].Offset != PageSize+46 {
		t.Fatalf("literal identity lost: %+v", got)
	}
}
func TestIndexOffsetsAreStartsNotStringEnds(t *testing.T) {
	b := append(make([]byte, PageSize), indexNode("key", 0)...)
	// The additional table entry is not a sorted end sentinel.
	binary.LittleEndian.PutUint16(b[PageSize+44:], 0)
	p := Physical{Index: file(b), IndexMap: Mapping{Entries: [][6]uint32{{0, 0, 0, 1}, {1}}}}
	got, err := p.ReadIndex()
	if err != nil || len(got) != 1 || got[0].Key != "key" {
		t.Fatalf("start table misread as extents: %+v %v", got, err)
	}
}
func TestIndexCycleAndTruncationRejected(t *testing.T) {
	b := append(make([]byte, PageSize), indexNode("key", 1)...)
	p := Physical{Index: file(b), IndexMap: Mapping{Entries: [][6]uint32{{0, 0, 0, 1}, {1}}}}
	if _, err := p.ReadIndex(); err == nil {
		t.Fatal("accepted index cycle")
	}
	b[PageSize+46] = 0xff
	if _, err := p.ReadIndex(); err == nil {
		t.Fatal("accepted invalid UTF8")
	}
}
