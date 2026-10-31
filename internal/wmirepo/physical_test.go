package wmirepo

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func words(v ...uint32) []byte {
	b := make([]byte, len(v)*4)
	for i, n := range v {
		binary.LittleEndian.PutUint32(b[i*4:], n)
	}
	return b
}
func file(b []byte) File { return File{bytes.NewReader(b), int64(len(b))} }
func TestRecordFragmentedPhysicalSpans(t *testing.T) {
	b := make([]byte, 4*PageSize)
	copy(b[2*PageSize:], words(7, PageSize-3, 8, 0))
	copy(b[3*PageSize-3:], "abc")
	copy(b, "defgh")
	p := Physical{Data: file(b), DataMap: Mapping{Entries: [][6]uint32{{2}, {0}}}, MapName: "MAPPING1.MAP"}
	r, err := p.ReadRecord("NS_A/CI_B/IL_C.0.7.8")
	if err != nil || string(r.Bytes) != "abcdefgh" || len(r.Spans) != 2 {
		t.Fatalf("record not reconstructed: %+v err=%v", r, err)
	}
	if r.Spans[0].Offset != 3*PageSize-3 || r.Spans[1].Offset != 0 || r.Spans[1].RecordOffset != 3 || r.TOC.Offset != 2*PageSize || r.MappingSpans[1].Offset != 48 || r.SHA256 == "" {
		t.Fatalf("incorrect provenance: %+v", r)
	}
}

func TestRecordRejectsInvalidMetadata(t *testing.T) {
	b := make([]byte, PageSize)
	copy(b, words(7, PageSize-3, 8, 0))
	p := Physical{Data: file(b), DataMap: Mapping{Entries: [][6]uint32{{0}, {0x3fffffff}}}}
	for _, key := range []string{"not-a-record", "NS_A.0.8.8", "NS_A.0.7.9", "NS_A.0.7.0", "NS_A.0.7.999999999999999999999", "NS_A.0.7.8"} {
		if _, err := p.ReadRecord(key); err == nil {
			t.Errorf("accepted %s", key)
		}
	}
}

func TestMappingReadBounded(t *testing.T) {
	b := words(0xabcd, 7, 1, 2, 3, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0xdcba)
	m, end, err := ReadMapping(file(b), 0)
	if err != nil || end != int64(len(b)) || m.Generation != 7 || len(m.Entries) != 2 || m.Entries[0][0] != 2 {
		t.Fatalf("mapping not decoded: %+v end=%d err=%v", m, end, err)
	}
}
