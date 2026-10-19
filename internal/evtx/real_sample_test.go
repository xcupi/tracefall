package evtx

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// Regression tests against REAL Windows bytes.
//
// The synthetic fixtures in evtxgen share the author's understanding of the
// format; a decoder and generator that agree with each other can both be
// wrong, which is exactly how an inline-template layout bug went unnoticed
// until a real Windows 10 log was read. These tests therefore run only when
// a real log is supplied:
//
//	TRACEFALL_REAL_EVTX=/path/to/Security.evtx go test ./internal/evtx/ -run Real
//
// Any Security.evtx can be used through TRACEFALL_REAL_EVTX; no sample is shipped.
// (Windows 10, MSEDGEWIN10), extracted with sleuthkit icat from inode 80826.
// It is NOT committed: the repository keeps only synthetic fixtures. Its
// SHA-256 is pinned so the test cannot silently run against another file.
const realSecuritySHA256 = "dd2aef563c0f600ab7a3a49d15c2f3d18b02850afd9a19255dd282d94674765c"

func realSample(t *testing.T) string {
	t.Helper()
	path := os.Getenv("TRACEFALL_REAL_EVTX")
	if path == "" {
		t.Skip("set TRACEFALL_REAL_EVTX to a real Windows Security.evtx to run")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening real sample: %v", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatalf("hashing real sample: %v", err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != realSecuritySHA256 {
		t.Fatalf("real sample sha256 = %s, want %s (wrong file?)", got, realSecuritySHA256)
	}
	return path
}

// Every record of a real, undamaged Security log must decode. Before the
// inline-template fix this read 0 of 4322; a one-line header fix read 4252;
// the remaining failures were BinXML misreads.
func TestReal_SecurityLogDecodesEveryRecord(t *testing.T) {
	path := realSample(t)
	f, err := Open(path, DefaultLimits())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	n := 0
	stats, err := f.Walk(func(Record) error { n++; return nil })
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if stats.ChunksFailed != 0 {
		t.Errorf("chunks failed = %d, want 0", stats.ChunksFailed)
	}
	if stats.RecordsFailed != 0 {
		t.Errorf("records failed = %d (read %d), want 0", stats.RecordsFailed, stats.RecordsRead)
	}
	if n != 4322 {
		t.Errorf("records delivered = %d, want 4322 (every record in the log)", n)
	}
}

// Decoding without an error is not the same as decoding correctly. The
// record header is written by the logger, not by BinXML, so its record ID
// and FILETIME are an independent witness: the decoded System block must
// agree with them for every record, or substitution values are misplaced.
func TestReal_DecodedSystemMatchesRecordHeaders(t *testing.T) {
	path := realSample(t)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading real sample: %v", err)
	}
	f, err := Open(path, DefaultLimits())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	checked, idMismatch, timeMismatch := 0, 0, 0
	var firstBad string
	_, err = f.Walk(func(rec Record) error {
		checked++
		hdrID := binary.LittleEndian.Uint64(raw[rec.Offset+8 : rec.Offset+16])
		hdrFT := binary.LittleEndian.Uint64(raw[rec.Offset+16 : rec.Offset+24])
		hdrTime := time.Unix(0, int64(hdrFT-116444736000000000)*100).UTC()
		if rec.System.EventRecordID != hdrID {
			idMismatch++
			if firstBad == "" {
				firstBad = fmt.Sprintf("offset %d: decoded id %d, header id %d", rec.Offset, rec.System.EventRecordID, hdrID)
			}
		}
		if !rec.System.TimeCreated.Equal(hdrTime) {
			timeMismatch++
			if firstBad == "" {
				firstBad = fmt.Sprintf("offset %d: decoded time %v, header time %v", rec.Offset, rec.System.TimeCreated, hdrTime)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if checked != 4322 {
		t.Fatalf("checked %d records, want 4322", checked)
	}
	if idMismatch != 0 || timeMismatch != 0 {
		t.Errorf("decoded System disagrees with record headers: %d id, %d time (first: %s)", idMismatch, timeMismatch, firstBad)
	}
}

// EventData values are strings that BinXML stores in the record. Each one
// that contains a letter must also appear, as UTF-16LE, in the raw bytes of
// the log: a value that cannot be found there was not read from this file.
// The EventID histogram is logged so a reviewer can compare it with what the
// log is expected to contain.
func TestReal_EventDataStringsExistInRawBytes(t *testing.T) {
	path := realSample(t)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading real sample: %v", err)
	}
	f, err := Open(path, DefaultLimits())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	checked, missing := 0, 0
	var firstMissing string
	missingByKey := map[string]int{}
	ids := map[int]int{}
	_, err = f.Walk(func(rec Record) error {
		ids[rec.System.EventID]++
		for k, v := range rec.Data {
			if !hasLetter(v) || !isLiteralField(k, v) {
				continue
			}
			checked++
			if !bytes.Contains(raw, utf16LE(v)) {
				missing++
				missingByKey[k]++
				if firstMissing == "" {
					firstMissing = fmt.Sprintf("offset %d %s=%q", rec.Offset, k, v)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	t.Logf("EventID histogram (top): %v", topIDs(ids, 12))
	t.Logf("EventData string values checked: %d", checked)
	t.Logf("missing-from-raw by key (top): %v", topKeys(missingByKey, 15))
	if checked == 0 {
		t.Fatal("no EventData strings were decoded; the value path is not exercised")
	}
	if missing != 0 {
		t.Errorf("%d of %d EventData strings are not present in the raw log (first: %s)", missing, checked, firstMissing)
	}
}

func hasLetter(s string) bool {
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return true
		}
	}
	return false
}

func utf16LE(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, u := range utf16.Encode([]rune(s)) {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

func topIDs(m map[int]int, n int) []string {
	type kv struct {
		id int
		c  int
	}
	var all []kv
	for id, c := range m {
		all = append(all, kv{id, c})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].c > all[j].c || (all[i].c == all[j].c && all[i].id < all[j].id) })
	var out []string
	for i, x := range all {
		if i >= n {
			break
		}
		out = append(out, fmt.Sprintf("%d×%d", x.id, x.c))
	}
	return out
}

func topKeys(m map[string]int, n int) []string {
	type kv struct {
		k string
		c int
	}
	var all []kv
	for k, c := range m {
		all = append(all, kv{k, c})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].c > all[j].c || (all[i].c == all[j].c && all[i].k < all[j].k) })
	var out []string
	for i, x := range all {
		if i >= n {
			break
		}
		out = append(out, fmt.Sprintf("%s×%d", x.k, x.c))
	}
	return out
}

// isLiteralField reports whether a value is stored as text in the log. SIDs,
// LogonIds, process/handle IDs, FILETIMEs and hex fields are rendered from
// binary types, so their text form does not appear in the raw bytes and is
// not a fair witness. Everything else is a string and must appear verbatim.
func isLiteralField(key, value string) bool {
	for _, suf := range []string{"Sid", "SID", "LogonId", "Id", "Time", "Label", "Guid", "GUID", "Handle"} {
		if strings.HasSuffix(key, suf) {
			return false
		}
	}
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "S-1-") ||
		(strings.HasPrefix(value, "{") && strings.HasSuffix(value, "}")) { // GUID rendered from binary
		return false
	}
	return true
}
