package evtx

import (
	"os"
	"testing"

	evtxpkg "tracefall/internal/evtx"
)

// Parser-level regression on the same real Security log (see
// internal/evtx/real_sample_test.go for provenance and the SHA-256 pin).
//
// The parser maps only the EventIDs winevent knows (an under-specified event
// is worse than none), so the total event count is not the right yardstick.
// The right one: for every EventID the parser maps, the number of events must
// equal the number of records the decoder read with that ID. A shortfall means
// a mapped record was dropped, which is the silent failure this guards against.
func TestReal_MappedRecordsAreNotDropped(t *testing.T) {
	path := os.Getenv("TRACEFALL_REAL_EVTX")
	if path == "" {
		t.Skip("set TRACEFALL_REAL_EVTX to a real Windows Security.evtx to run")
	}
	mapped := map[int]bool{4624: true, 4648: true, 4672: true, 4688: true}

	decoded := map[int]int{}
	f, err := evtxpkg.Open(path, evtxpkg.DefaultLimits())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := f.Walk(func(rec evtxpkg.Record) error {
		if mapped[rec.System.EventID] {
			decoded[rec.System.EventID]++
		}
		return nil
	}); err != nil {
		t.Fatalf("walk: %v", err)
	}
	f.Close()

	res, err := New().Parse(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := map[int]int{}
	partial := 0
	for _, ev := range res.Events {
		got[ev.EventID]++
		if _, ok := ev.Extra["evtx_partial_parse"]; ok {
			partial++
		}
	}
	if partial != 0 {
		t.Errorf("%d events flagged evtx_partial_parse on a fully readable log", partial)
	}
	for id := range mapped {
		if decoded[id] == 0 {
			t.Errorf("EventID %d: no records decoded, the sample no longer exercises it", id)
			continue
		}
		if got[id] != decoded[id] {
			t.Errorf("EventID %d: %d records decoded but %d events produced", id, decoded[id], got[id])
		}
	}
	t.Logf("mapped records decoded=%v events=%v", decoded, got)
}
