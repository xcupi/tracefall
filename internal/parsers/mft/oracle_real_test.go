package mft_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"tracefall/internal/ntfs"
	"tracefall/internal/parsers"
	"tracefall/internal/parsers/mft"
)

// TestStream_RealMFTAgainstSecondDecoder compares this parser's decode of any
// standalone $MFT with a dump made by an independent decoder (dissect.ntfs, via
// oracle_mft.py kept with the verification notes). Set NTFS_ORACLE_MFT to the
// table and NTFS_ORACLE_MFT_DUMP to the dump. Nothing about the table is
// pinned. Only counts of matches and mismatches are logged, never values.
func TestStream_RealMFTAgainstSecondDecoder(t *testing.T) {
	path, oraclePath := os.Getenv("NTFS_ORACLE_MFT"), os.Getenv("NTFS_ORACLE_MFT_DUMP")
	if path == "" || oraclePath == "" {
		t.Skip("NTFS_ORACLE_MFT and NTFS_ORACLE_MFT_DUMP not set")
	}
	raw, err := os.ReadFile(oraclePath)
	if err != nil {
		t.Skipf("oracle not present: %v", err)
	}
	var o struct {
		RecordSize int `json:"record_size"`
		Slots      int `json:"slots"`
		Agg        map[string]int
		Events     map[string]int `json:"events_by_type"`
		MinNs      *int64         `json:"min_ns"`
		MaxNs      *int64         `json:"max_ns"`
		Sample     []struct {
			N      uint64  `json:"n"`
			InUse  bool    `json:"inuse"`
			Dir    bool    `json:"dir"`
			Base   bool    `json:"base"`
			Seq    uint16  `json:"seq"`
			SI     []int64 `json:"si"`
			Name   *string `json:"name"`
			NS     uint8   `json:"ns"`
			Parent uint64  `json:"parent"`
			PSeq   uint16  `json:"pseq"`
			FN     []int64 `json:"fn"`
			Mapped bool    `json:"mapped"`
		} `json:"sample"`
	}
	if err := json.Unmarshal(raw, &o); err != nil {
		t.Fatal(err)
	}
	want := map[uint64]int{}
	for i, s := range o.Sample {
		want[s.N] = i
	}

	// Pass 1: aggregates through the production stream.
	byType := map[string]int{}
	var minNs, maxNs int64
	first := true
	cov, err := mft.New().ParseStream(context.Background(), path, parsers.ParseContext{}, func(b parsers.ParseResult) error {
		for _, e := range b.Events {
			byType[e.EventType]++
			ns := e.Timestamp.UnixNano()
			if first || ns < minNs {
				minNs = ns
			}
			if first || ns > maxNs {
				maxNs = ns
			}
			first = false
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	check := func(label string, got, exp int) {
		if got != exp {
			t.Errorf("MISMATCH %s: tracefall=%d oracle=%d", label, got, exp)
		} else {
			t.Logf("match %s = %d", label, got)
		}
	}
	check("records_read (FILE slots)", cov.RecordsRead, o.Agg["file_slots"])
	check("mapped base records", cov.Mapped, o.Agg["mapped"])
	check("mapped free records", cov.Ntfs.FreeMapped, o.Agg["mapped_free"])
	check("unmapped non-base", cov.Ntfs.UnmappedNonBase, o.Agg["non_base"])
	check("unmapped base (no name/time)", cov.Ntfs.UnmappedNoName+cov.Ntfs.UnmappedNoTime, o.Agg["unmapped_base"])
	check("emitted events", *cov.EmittedEvents, o.Agg["events"])
	check("created events", byType["filesystem_created"], o.Events["created"])
	check("modified events", byType["filesystem_modified"], o.Events["modified"])
	check("changed events", byType["filesystem_changed"], o.Events["changed"])
	check("accessed events", byType["filesystem_accessed"], o.Events["accessed"])
	if o.MinNs != nil && (minNs != *o.MinNs || maxNs != *o.MaxNs) {
		t.Errorf("MISMATCH time range")
	} else {
		t.Log("match min/max timestamp")
	}

	// Pass 2: field-by-field comparison of the sample through the record decoder.
	var inUse, free, matched, mismatched int
	fields := map[string]int{}
	seen := 0
	lim := ntfs.DefaultLimits()
	lim.MaxRecords = int(lim.MaxFileBytes/512) + 1 // as the stream sets it
	err = ntfs.Scan(path, ntfs.ScanOptions{Strict: true, Limits: lim}, func(r ntfs.Record) error {
		if r.InUse {
			inUse++
		} else {
			free++
		}
		i, ok := want[r.RecordNumber]
		if !ok {
			return nil
		}
		seen++
		s := o.Sample[i]
		bad := func(f string) { fields[f]++ }
		ok2 := true
		cmp := func(f string, same bool) {
			if !same {
				bad(f)
				ok2 = false
			}
		}
		cmp("in_use", r.InUse == s.InUse)
		cmp("is_dir", r.IsDirectory == s.Dir)
		cmp("is_base", r.IsBaseRecord() == s.Base)
		cmp("sequence", r.SequenceNumber == s.Seq)
		if len(s.SI) == 4 {
			got := []int64{nsOf(r.SI.Created), nsOf(r.SI.Modified), nsOf(r.SI.Changed), nsOf(r.SI.Accessed)}
			for k := range got {
				cmp("si_time", got[k] == s.SI[k])
			}
		} else {
			cmp("si_present", !r.HasSI)
		}
		n, hasName := r.BestName()
		cmp("has_name", hasName == (s.Name != nil))
		if hasName && s.Name != nil {
			cmp("name", n.Name == *s.Name)
			cmp("namespace", n.Namespace == s.NS)
			cmp("parent_ref", n.ParentRef == s.Parent)
			cmp("parent_seq", n.ParentSeq == s.PSeq)
			got := []int64{nsOf(n.Times.Created), nsOf(n.Times.Modified), nsOf(n.Times.Changed), nsOf(n.Times.Accessed)}
			for k := range got {
				cmp("fn_time", got[k] == s.FN[k])
			}
		}
		mapped := r.IsBaseRecord() && hasName && r.HasSI && r.SI.Any()
		cmp("mapped", mapped == s.Mapped)
		if ok2 {
			matched++
		} else {
			mismatched++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	check("in-use slots", inUse, o.Agg["in_use"])
	check("free slots", free, o.Agg["free"])
	t.Logf("sample: %d records compared field by field: %d identical, %d with at least one differing field", seen, matched, mismatched)
	for f, n := range fields {
		t.Errorf("MISMATCH field class %s: %d records", f, n)
	}
	if seen < 500 {
		t.Errorf("fewer than 500 sampled records compared: %d", seen)
	}
}

// nsOf is the oracle's convention: an absent or implausible time is 0.
func nsOf(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}
