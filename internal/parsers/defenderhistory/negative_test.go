package defenderhistory

import (
	"encoding/binary"
	"testing"
)

func TestRecordRejectsUnsupportedAndCountCorruption(t *testing.T) {
	original := fixture()
	entries, err := ReadEntries(original)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"version", func(b []byte) { b[entries[2].Offset+8] = 'X' }},
		{"optional", func(b []byte) { binary.LittleEndian.PutUint32(b[entries[4].Offset+8:], 4) }},
		{"list-overflow", func(b []byte) { binary.LittleEndian.PutUint32(b[entries[10].Offset+8:], 0xffffffff) }},
		{"resource-count", func(b []byte) { binary.LittleEndian.PutUint32(b[entries[11].Offset+8:], MaxResources+1) }},
		{"nested-total", func(b []byte) {
			for _, e := range entries {
				if e.Type == 40 {
					binary.LittleEndian.PutUint32(b[e.Offset+8+12:], 0xffffffff)
					return
				}
			}
		}},
		{"nested-unknown-type", func(b []byte) {
			for _, e := range entries {
				if e.Type == 40 {
					p := e.Offset + 8 + 24
					n := int(binary.LittleEndian.Uint32(b[p:]))
					binary.LittleEndian.PutUint32(b[p+4+n:], 99)
					return
				}
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := append([]byte(nil), original...)
			tc.mutate(b)
			r, err := Decode(b)
			if err == nil || r != nil {
				t.Fatal("unsupported/corrupt source accepted")
			}
		})
	}
	if _, err := ReadEntries(make([]byte, MaxFileBytes+1)); err == nil {
		t.Fatal("source cap ignored")
	}
	var many []byte
	for i := 0; i <= MaxEntries; i++ {
		many = append(many, ltv(0, u32(0))...)
	}
	if _, err := ReadEntries(many); err == nil {
		t.Fatal("entry cap ignored")
	}
}
