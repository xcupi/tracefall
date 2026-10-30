package defenderhistory

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func ltv(typ uint32, b []byte) []byte {
	out := make([]byte, 8+((len(b)+7)/8)*8)
	binary.LittleEndian.PutUint32(out, uint32(len(b)))
	binary.LittleEndian.PutUint32(out[4:], typ)
	copy(out[8:], b)
	return out
}
func u32(n uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, n); return b }
func u64(n uint64) []byte { b := make([]byte, 8); binary.LittleEndian.PutUint64(b, n); return b }
func wide(s string) []byte {
	var b []byte
	for _, c := range utf16.Encode([]rune(s)) {
		b = append(b, byte(c), byte(c>>8))
	}
	return b
}
func TestEntriesCheckedLiteralAndBits(t *testing.T) {
	b := append(ltv(0x15, wide("  neutral\t\x00")), ltv(5, u32(0xffffffff))...)
	e, err := ReadEntries(b)
	if err != nil {
		t.Fatalf("valid bounded entries rejected: %v", err)
	}
	if len(e) != 2 || e[0].Text != "  neutral\t" || e[1].Bits != 0xffffffff || e[1].Offset != len(ltv(0x15, wide("  neutral\t\x00"))) || e[1].End != len(b) {
		t.Fatalf("literal/width/span lost: %+v", e)
	}
	for n := 0; n < len(b); n++ {
		if n == e[0].End {
			continue
		}
		if _, err := ReadEntries(b[:n]); err == nil {
			t.Fatalf("truncation %d accepted", n)
		}
	}
	for name, bad := range map[string][]byte{
		"width": ltv(6, []byte{1}), "odd": ltv(0x15, []byte{1}), "surrogate": ltv(0x15, []byte{0, 0xd8}), "unknown-type": ltv(99, nil), "overflow": {255, 255, 255, 255, 6, 0, 0, 0}, "empty": nil,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ReadEntries(bad); err == nil {
				t.Fatal("malformed entry accepted")
			}
		})
	}
	pad := ltv(6, u32(0))
	pad[len(pad)-1] = 1
	if _, err := ReadEntries(pad); err == nil {
		t.Fatal("nonzero padding accepted")
	}
}
