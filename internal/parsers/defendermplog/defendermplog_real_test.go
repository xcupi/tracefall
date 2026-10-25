package defendermplog

import (
	"os"
	"strconv"
	"testing"

	"tracefall/internal/model"
)

// TRACEFALL_REAL_DEFENDER_MPLOG is the path of a real support log;
// TRACEFALL_REAL_DEFENDER_MPLOG_EXPECT is the count of 'Process creation
// blocked' lines from an independent pass over the raw bytes. A skipped test is
// not a pass.
func TestRealSupportLog(t *testing.T) {
	path := os.Getenv("TRACEFALL_REAL_DEFENDER_MPLOG")
	if path == "" {
		t.Skip("TRACEFALL_REAL_DEFENDER_MPLOG not set")
	}
	want, err := strconv.Atoi(os.Getenv("TRACEFALL_REAL_DEFENDER_MPLOG_EXPECT"))
	if err != nil {
		t.Fatal("TRACEFALL_REAL_DEFENDER_MPLOG_EXPECT must be the independent blocked-line count")
	}
	res, err := New().Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	blocked := 0
	for _, e := range res.Events {
		if e.EventType == model.EventAntimalwareBlock {
			blocked++
			if !e.Timestamp.IsZero() || e.PID != 0 || e.Extra["process_id"] == "" || e.Extra["parent_pid"] == "" || e.Extra["byte_offset"] == "" {
				t.Errorf("record %s: %+v", e.SourceReference, e.Extra)
			}
		}
	}
	if blocked != want {
		t.Errorf("blocked records = %d, independent count %d", blocked, want)
	}
	c := res.Coverage
	if c == nil || c.RecordsFailed != 0 || c.LimitReached {
		t.Errorf("coverage = %+v", c)
	}
}
