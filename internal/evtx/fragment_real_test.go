package evtx

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"testing"
)

// The optional native source is private and is never copied into the repo.
// The digest is independently derived using Dissect, allocated-record
// boundaries, and physical header FILETIMEs. It certifies this projection,
// not complete UserData flattening or semantic event mapping.
func TestRealLiteralFragment(t *testing.T) {
	path := os.Getenv("TRACEFALL_REAL_EVTX_LITERAL_FRAGMENT")
	if path == "" {
		t.Skip("set TRACEFALL_REAL_EVTX_LITERAL_FRAGMENT for native fragment validation")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	const sourceSHA = "d0f5387bd610b5b0c6cd7c7700d82da6c3faa869a2d1853b7da70536a9919353"
	if fmt.Sprintf("%x", sha256.Sum256(raw)) != sourceSHA {
		t.Fatal("native source SHA mismatch")
	}
	f, err := Open(path, Limits{Strict: true})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	count := 0
	stats, err := f.Walk(func(r Record) error {
		count++
		if r.Offset < 0 || r.Offset+24 > int64(len(raw)) {
			t.Fatal("record offset outside source")
		}
		id := binary.LittleEndian.Uint64(raw[r.Offset+8:])
		ft := binary.LittleEndian.Uint64(raw[r.Offset+16:])
		if id != r.System.EventRecordID || !fileTime(ft).Equal(r.System.TimeCreated) {
			t.Fatal("native ID/time differs from physical header")
		}
		fields := []string{strconv.FormatInt(r.Offset, 10), strconv.FormatUint(r.System.EventRecordID, 10), strconv.FormatUint(ft, 10), r.System.Provider, r.System.Channel, strconv.Itoa(r.System.EventID), r.Data["SubjectName"], r.Data["NotValidAfter"]}
		for _, v := range fields {
			var length [4]byte
			binary.LittleEndian.PutUint32(length[:], uint32(len(v)))
			h.Write(length[:])
			h.Write([]byte(v))
		}
		return nil
	})
	if err != nil || count != 120 || stats.RecordsRead != 120 || stats.RecordsFailed != 0 || stats.ChunksFailed != 0 || stats.ZeroChunks != 14 {
		t.Fatalf("native coverage differs: count=%d stats=%+v err=%v", count, stats, err)
	}
	const expected = "0625a7d3a4b6635146a7c387147062f5c28f1342a2b9a937f808a82edb88e59c"
	if fmt.Sprintf("%x", h.Sum(nil)) != expected {
		t.Fatal("native fields/offset projection differs from independent reader")
	}
	after, err := os.ReadFile(path)
	if err != nil || sha256.Sum256(after) != sha256.Sum256(raw) {
		t.Fatal("native source bytes changed")
	}
}
