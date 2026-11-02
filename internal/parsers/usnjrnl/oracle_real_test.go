package usnjrnl_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"tracefall/internal/ntfs"
	"tracefall/internal/parsers"
	"tracefall/internal/parsers/usnjrnl"
)

// TestStream_RealJournalAgainstSecondDecoder compares this parser's decode of any
// standalone $UsnJrnl:$J with a dump made by an independent decoder (dissect.ntfs,
// via oracle_usn.py kept with the verification notes). Set NTFS_ORACLE_USN to the
// journal and NTFS_ORACLE_USN_DUMP to the dump. Only counts are logged.
func TestStream_RealJournalAgainstSecondDecoder(t *testing.T) {
	path, oraclePath := os.Getenv("NTFS_ORACLE_USN"), os.Getenv("NTFS_ORACLE_USN_DUMP")
	if path == "" || oraclePath == "" {
		t.Skip("NTFS_ORACLE_USN and NTFS_ORACLE_USN_DUMP not set")
	}
	raw, err := os.ReadFile(oraclePath)
	if err != nil {
		t.Skipf("oracle not present: %v", err)
	}
	var o struct {
		Agg      map[string]int64 `json:"agg"`
		Versions map[string]int   `json:"versions"`
		First    *int64           `json:"first_nonrecord"`
		MinTS    *int64           `json:"min_ts"`
		MaxTS    *int64           `json:"max_ts"`
		N        int              `json:"n"`
		Sample   []struct {
			Off    int64  `json:"off"`
			Ver    int    `json:"ver"`
			Usn    uint64 `json:"usn"`
			Reason uint32 `json:"reason"`
			Name   string `json:"name"`
			FR     uint64 `json:"fr"`
			PR     uint64 `json:"pr"`
			TS     int64  `json:"ts"`
			Src    uint32 `json:"src"`
			Attrs  uint32 `json:"attrs"`
		} `json:"sample"`
	}
	if err := json.Unmarshal(raw, &o); err != nil {
		t.Fatal(err)
	}
	want := map[int64]int{}
	for i, s := range o.Sample {
		want[s.Off] = i
	}
	cov, err := usnjrnl.New().ParseStream(context.Background(), path, parsers.ParseContext{}, func(parsers.ParseResult) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	ok := func(label string, same bool, got, exp any) {
		if !same {
			t.Errorf("MISMATCH %s: tracefall=%v oracle=%v", label, got, exp)
		} else {
			t.Logf("match %s = %v", label, got)
		}
	}
	ok("records", cov.RecordsRead == o.N, cov.RecordsRead, o.N)
	ok("mapped", cov.Mapped == o.N, cov.Mapped, o.N)
	ok("first non-record offset", (cov.Ntfs.FirstNonRecordOffset == nil) == (o.First == nil) && (o.First == nil || *cov.Ntfs.FirstNonRecordOffset == *o.First), cov.Ntfs.FirstNonRecordOffset != nil, o.First != nil)

	var minTS, maxTS int64
	first := true
	var v2, v3, matched, mismatched, seen, usnEqOffset int
	fields := map[string]int{}
	lim := ntfs.DefaultLimits()
	var nonzeroWords int64
	err = ntfs.ScanUsnJournal(path, ntfs.UsnScanOptions{Strict: true, Limits: lim, NonRecordRegion: func(off int64, n int) { nonzeroWords++ }}, func(r ntfs.UsnRecord) error {
		if r.MajorVersion == 2 {
			v2++
		} else if r.MajorVersion == 3 {
			v3++
		}
		ticks := (r.Timestamp.Unix()+11644473600)*10_000_000 + int64(r.Timestamp.Nanosecond()/100)
		if !r.Timestamp.IsZero() {
			if first || ticks < minTS {
				minTS = ticks
			}
			if first || ticks > maxTS {
				maxTS = ticks
			}
			first = false
		}
		if int64(r.Usn) == r.Offset {
			usnEqOffset++
		}
		i, hit := want[r.Offset]
		if !hit {
			return nil
		}
		seen++
		s := o.Sample[i]
		good := true
		cmp := func(f string, same bool) {
			if !same {
				fields[f]++
				good = false
			}
		}
		cmp("version", int(r.MajorVersion) == s.Ver)
		cmp("usn", r.Usn == s.Usn)
		cmp("reason_mask", r.Reason == s.Reason)
		cmp("name", r.FileName == s.Name)
		cmp("source_info", r.SourceInfo == s.Src)
		cmp("file_attributes", r.FileAttributes == s.Attrs)
		cmp("timestamp", ticks == s.TS)
		cmp("file_reference", r.RawFileReference == fmt.Sprintf("0x%016X", s.FR))
		cmp("parent_reference", r.RawParentReference == fmt.Sprintf("0x%016X", s.PR))
		if good {
			matched++
		} else {
			mismatched++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ok("v2 records", int64(v2) == int64(o.Versions["2"]), v2, o.Versions["2"])
	ok("v3 records", int64(v3) == int64(o.Versions["3"]), v3, o.Versions["3"])
	ok("min/max timestamp", o.MinTS != nil && minTS == *o.MinTS && maxTS == *o.MaxTS, "equal", "equal")
	t.Logf("non-record 8-byte words: tracefall=%d oracle=%d (units differ: tracefall counts nonzero 8-byte words, the oracle counts words whose first 4 bytes are non-zero)", nonzeroWords, o.Agg["nonrecord_words"])
	t.Logf("records whose USN equals their file offset: %d of %d", usnEqOffset, cov.RecordsRead)
	t.Logf("sample: %d records compared field by field: %d identical, %d with at least one differing field", seen, matched, mismatched)
	for f, n := range fields {
		t.Errorf("MISMATCH field class %s: %d records", f, n)
	}
	if seen < 500 {
		t.Errorf("fewer than 500 sampled records compared: %d", seen)
	}
}
