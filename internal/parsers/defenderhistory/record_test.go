package defenderhistory

import (
	"crypto/sha256"
	"fmt"
	"os"
	"testing"
)

func fixture() []byte {
	var b []byte
	add := func(typ uint32, p []byte) { b = append(b, ltv(typ, p)...) }
	num := func(n uint32) { add(6, u32(n)) }
	str := func(s string) { add(21, wide(s+"\x00")) }
	add(8, u64(42))
	add(30, []byte{0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x78, 0x56, 0x90, 0xab, 0xcd, 0xef, 1, 2, 3, 4})
	str("Magic.Version:1.2")
	str("Neutral.Test")
	for i := 0; i < 6; i++ {
		num(0)
	}
	num(0)
	num(2)
	for i := 0; i < 2; i++ {
		str("Magic.Version:1.2")
		str("file")
		str("  private canary resource  ")
		num(0)
		blob := nestedFixture()
		num(uint32(len(blob)))
		add(40, blob)
	}
	add(10, u64(116444736000000001))
	add(5, u32(0xffffffff))
	num(0)
	add(30, make([]byte, 16))
	num(0)
	num(0)
	str("private canary user")
	num(0)
	str("private canary process")
	num(0)
	num(0)
	num(0)
	add(10, u64(0))
	num(0)
	add(10, u64(116444736000000099))
	num(0)
	add(0, u32(99))
	num(0)
	str("private canary group")
	num(0)
	num(0)
	add(0, u32(123))
	for i := 0; i < 4; i++ {
		num(0)
	}
	return b
}
func nestedFixture() []byte {
	var values []byte
	for _, s := range []string{"neutral-secret-canary-A", "neutral-secret-canary-B"} {
		k := wide("RepeatedUnknown")
		values = append(values, u32(uint32(len(k)))...)
		values = append(values, k...)
		values = append(values, u32(7)...)
		values = append(values, u32(uint32(len(s)))...)
		values = append(values, []byte(s)...)
	}
	b := append(u32(1), u32(20)...)
	b = append(b, u32(uint32(len(values)+4))...)
	b = append(b, u32(uint32(len(values)+24))...)
	b = append(b, u32(0)...)
	b = append(b, u32(uint32(len(values)+4))...)
	return append(b, values...)
}
func TestRecordLosslessResourcesClocksAndStrictEOF(t *testing.T) {
	b := fixture()
	r, err := Decode(b)
	if err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}
	if r.DetectionID != "12345678-1234-5678-90ab-cdef01020304" || r.ThreatID != 42 || len(r.Resources) != 2 || r.EOF != len(b) {
		t.Fatalf("identity/count/EOF: %+v", r)
	}
	if r.Resources[0].Location != "  private canary resource  " || len(r.Resources[0].Blob) != 2 || r.Resources[0].Blob[1].Text != "neutral-secret-canary-B" {
		t.Fatal("duplicate keys/resources/literal lost")
	}
	if len(r.Times) != 3 || !r.Times[1].Zero || r.Times[0].UnixSeconds != 0 || r.Times[0].Fraction100ns != 1 || r.Times[2].Fraction100ns != 99 {
		t.Fatalf("FILETIME fidelity: %+v", r.Times)
	}
	for n := 0; n < len(b); n++ {
		if _, err := Decode(b[:n]); err == nil {
			t.Fatalf("truncated record accepted at %d", n)
		}
	}
	if _, err := Decode(append(b, ltv(0, u32(0))...)); err == nil {
		t.Fatal("tail accepted")
	}
}
func TestPublicFixture(t *testing.T) {
	p := os.Getenv("TRACEFALL_REAL_DEFENDER_HISTORY")
	if p == "" {
		t.Skip("public native fixture not configured")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(b)); got != "85a1a3251ea3ec19cf34e79d76c0b4cb0fd7cc7d9eedc08e314eec4ce0822956" {
		t.Fatal("public fixture hash mismatch")
	}
	r, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if r.DetectionID != "6afe33a0-19ba-4fff-892f-b700539d7d63" || len(r.Entries) != 59 || r.EOF != len(b) {
		t.Fatal("public producer fixture mismatch")
	}
	found := false
	for _, res := range r.Resources {
		for _, v := range res.Blob {
			if v.Key == "ThreatTrackingStartTime" {
				found = true
				if v.Bits != 133029417789094421 {
					t.Fatalf("public tracking FILETIME mismatch: %d", v.Bits)
				}
			}
		}
	}
	if !found {
		t.Fatal("public tracking absent")
	}
}
