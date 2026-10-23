package srum

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strconv"
	"testing"
	"time"

	"tracefall/internal/model"
)

// TestParse_RealSRUDB reads a real Windows 10 SRUDB.dat. Set TRACEFALL_REAL_SRUDB
// to its path; the file is pinned by SHA-256. The expected numbers come from a
// separate pass over the same file with dissect.esedb and plain Python
// (live records only, ids resolved through SruDbIdMapTable, JET date-times
// decoded from their 8 bytes), not from this parser.
func TestParse_RealSRUDB(t *testing.T) {
	path := os.Getenv("TRACEFALL_REAL_SRUDB")
	if path == "" {
		t.Skip("TRACEFALL_REAL_SRUDB not set")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("not present: %v", err)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != "e8af437e965bc19881c0f8d2293d300350f92b7407b1384ef0544de6bb6eab71" {
		t.Fatalf("not the pinned sample: sha256 %s", got)
	}
	res, err := Parser{}.Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	type agg struct {
		n                        int
		apps, users              map[string]bool
		unresolvedA, unresolvedU int
		min, max                 time.Time
		sums                     map[string]int64
	}
	by := map[string]*agg{}
	for _, e := range res.Events {
		a := by[e.EventType]
		if a == nil {
			a = &agg{apps: map[string]bool{}, users: map[string]bool{}, sums: map[string]int64{}}
			by[e.EventType] = a
		}
		a.n++
		if e.Extra["app_resolved"] == "true" {
			a.apps[e.Extra["app"]] = true
		} else {
			a.unresolvedA++
		}
		if e.User != "" {
			a.users[e.User] = true
		} else {
			a.unresolvedU++
		}
		if !e.Timestamp.IsZero() {
			if a.min.IsZero() || e.Timestamp.Before(a.min) {
				a.min = e.Timestamp
			}
			if e.Timestamp.After(a.max) {
				a.max = e.Timestamp
			}
		}
		for _, k := range []string{"foreground_cycle_time", "face_time", "bytes_sent", "bytes_received", "payload_size", "connected_seconds"} {
			if v, ok := e.Extra[k]; ok {
				n, _ := strconv.ParseInt(v, 10, 64)
				a.sums[k] += n
			}
		}
	}
	want := []struct {
		typ                    string
		n, apps, users, ua, uu int
		min, max               string
		sums                   map[string]int64
	}{
		{model.EventSRUMAppUsage, 657, 161, 209, 0, 0, "2023-07-12T06:19:00", "2023-07-14T10:37:00", map[string]int64{"foreground_cycle_time": 8686768410522, "face_time": 12988152820788}},
		{model.EventSRUMNetworkUsage, 114, 43, 5, 4, 4, "2023-07-12T06:19:00", "2023-07-14T10:35:00", map[string]int64{"bytes_sent": 5801645464, "bytes_received": 1125681198}},
		{model.EventSRUMNetworkConnection, 4, 0, 0, 4, 4, "2023-07-12T06:19:00", "2023-07-14T10:36:00", map[string]int64{"connected_seconds": 13761}},
		{model.EventSRUMPushNotification, 5, 3, 1, 0, 0, "2023-07-12T07:06:00", "2023-07-14T10:36:00", map[string]int64{"payload_size": 33658}},
	}
	for _, w := range want {
		a := by[w.typ]
		if a == nil {
			t.Errorf("%s: no events", w.typ)
			continue
		}
		if a.n != w.n || len(a.apps) != w.apps || len(a.users) != w.users || a.unresolvedA != w.ua || a.unresolvedU != w.uu {
			t.Errorf("%s: n=%d apps=%d users=%d unresolved app/user=%d/%d, want %d/%d/%d/%d/%d", w.typ, a.n, len(a.apps), len(a.users), a.unresolvedA, a.unresolvedU, w.n, w.apps, w.users, w.ua, w.uu)
		}
		const layout = "2006-01-02T15:04:05"
		if a.min.Format(layout) != w.min || a.max.Format(layout) != w.max {
			t.Errorf("%s: %s .. %s, want %s .. %s", w.typ, a.min.Format(layout), a.max.Format(layout), w.min, w.max)
		}
		for k, v := range w.sums {
			if a.sums[k] != v {
				t.Errorf("%s: sum %s = %d, want %d", w.typ, k, a.sums[k], v)
			}
		}
	}
	if len(res.Events) != 780 {
		t.Errorf("events = %d, want 780", len(res.Events))
	}
	c := res.Coverage
	if c.RecordsRead != 780+1484+42 || c.Mapped != 780 || c.Unmapped != 1484+42 || c.Undated != 0 || c.RecordsFailed != 0 {
		t.Errorf("coverage = %+v", c)
	}
	if !noteMentions(c, "23 deleted") || !noteMentions(c, "{5C8CF1C7-7257-4F13-B223-970EF5939312}: 1484 records") {
		t.Errorf("notes = %v", c.Notes)
	}
	seen := map[string]bool{}
	for _, e := range res.Events {
		if seen[e.SourceReference] {
			t.Fatalf("source reference %q is used twice", e.SourceReference)
		}
		seen[e.SourceReference] = true
	}
}
