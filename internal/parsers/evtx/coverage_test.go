package evtx

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"tracefall/internal/evtx"
	"tracefall/internal/evtx/evtxgen"
)

func TestCoverage_UntimedMappedRecordSurvivesWithoutInventedDate(t *testing.T) {
	e, ok := toEvent(evtx.Record{System: evtx.System{Channel: "Security", Provider: "Microsoft-Windows-Security-Auditing", EventID: 4624, Computer: "SERVER01"}, Data: map[string]string{"TargetUserName": "alice"}})
	if !ok || !e.Timestamp.IsZero() || e.Extra["timestamp_basis"] != "not_recorded" {
		t.Fatalf("mapped observation lost or dated: %+v %t", e, ok)
	}
}

func TestCoverage_EmptyOutputStillDisclosesCorruptionAndCaps(t *testing.T) {
	base := []evtxgen.Event{{RecordID: 1, Timestamp: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), Provider: "Other", Channel: "Application", EventID: 9001}, {RecordID: 2, Timestamp: time.Date(2025, 1, 1, 0, 1, 0, 0, time.UTC), Provider: "Other", Channel: "Application", EventID: 9002}}
	for _, bad := range []bool{false, true} {
		b := evtxgen.Build(base)
		if bad {
			b = evtxgen.CorruptChunkSignature(b, 0)
		}
		f := filepath.Join(t.TempDir(), "Application.evtx")
		if err := os.WriteFile(f, b, 0600); err != nil {
			t.Fatal(err)
		}
		p := New()
		if !bad {
			p.limits.MaxRecords = 1
		}
		r, err := p.Parse(f)
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Events) != 0 || r.Coverage == nil {
			t.Fatalf("%+v", r)
		}
		if bad && r.Coverage.ChunksFailed != 1 {
			t.Fatalf("lost unreadable-chunk diagnostic: %+v", r.Coverage)
		}
		if !bad && !r.Coverage.LimitReached {
			t.Fatalf("lost record-cap diagnostic: %+v", r.Coverage)
		}
	}
}

func TestCoverage_UnsupportedOnlyLogRetainsCensusWithoutInventedTimeline(t *testing.T) {
	p := filepath.Join(t.TempDir(), "Application.evtx")
	b := evtxgen.Build([]evtxgen.Event{{RecordID: 1, Timestamp: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), Provider: "MSSQLSERVER", Channel: "Application", Computer: "SERVER01", EventID: 18456}})
	if err := os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
	r, err := New().Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Events) != 0 {
		t.Fatal("unsupported observation is not a normalized SQL event")
	}
	if r.Coverage == nil {
		t.Fatal("zero-event parser output lost its coverage diagnostic")
	}
	c := r.Coverage
	if c.RecordsRead != 1 || c.Unmapped != 1 || c.Mapped != 0 || !c.Incomplete() || len(c.ByEvent) != 1 || c.ByEvent[0].EventID != 18456 {
		t.Fatalf("%+v", c)
	}
}
