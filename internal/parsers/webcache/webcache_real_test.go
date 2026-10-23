package webcache

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strconv"
	"testing"
	"time"

	"tracefall/internal/model"
)

// TestParse_RealWebCache reads a real Windows 10 WebCacheV01.dat. Set
// TRACEFALL_REAL_WEBCACHE to its path; the file is pinned by SHA-256. The
// expected numbers come from a separate pass over the same file with
// dissect.esedb and plain Python (live records only, Url text split by hand),
// not from this parser.
func TestParse_RealWebCache(t *testing.T) {
	path := os.Getenv("TRACEFALL_REAL_WEBCACHE")
	if path == "" {
		t.Skip("TRACEFALL_REAL_WEBCACHE not set")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("not present: %v", err)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != "ecf84cad43147f2af5e75a43557b8ac744a85a5cfdc5a44685d49de1aab26878" {
		t.Fatalf("not the pinned sample: sha256 %s", got)
	}
	res, err := Parser{}.Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	type agg struct {
		n, access int
		size      int64
		min, max  time.Time
	}
	by := map[string]*agg{}
	hosts := map[string]bool{}
	users := map[string]bool{}
	kinds := map[string]int{}
	status := map[string]int{}
	ctypes := map[string]int{}
	for _, e := range res.Events {
		k := e.Extra["container_name"] + "/" + e.Extra["container_id"]
		a := by[k]
		if a == nil {
			a = &agg{}
			by[k] = a
		}
		a.n++
		n, _ := strconv.Atoi(e.Extra["access_count"])
		a.access += n
		sz, _ := strconv.ParseInt(e.Extra["file_size"], 10, 64)
		a.size += sz
		if !e.Timestamp.IsZero() {
			if a.min.IsZero() || e.Timestamp.Before(a.min) {
				a.min = e.Timestamp
			}
			if e.Timestamp.After(a.max) {
				a.max = e.Timestamp
			}
		}
		if e.NetworkDest != "" {
			hosts[e.NetworkDest] = true
		}
		users[e.User] = true
		kinds[e.Extra["record_kind"]]++
		if s := e.Extra["response_status"]; s != "" {
			status[s]++
		}
		if s := e.Extra["content_type"]; s != "" {
			ctypes[s]++
		}
	}
	const layout = "2006-01-02T15:04:05.000000"
	want := map[string]struct {
		n, access int
		size      int64
		min, max  string
	}{
		"History/2":                  {32, 53, 0, "2023-07-12T06:15:35.716962", "2023-07-12T17:00:10.574324"},
		"MSHist012023071220230713/9": {32, 44, 0, "2023-07-12T06:26:34.615693", "2023-07-12T17:00:10.574324"},
		"Content/1":                  {8, 24, 39366, "2023-07-12T16:59:10.047524", "2023-07-12T18:02:49.354337"},
		"Content/3":                  {7, 7, 86641, "2023-07-12T17:27:42.254457", "2023-07-12T18:07:49.666825"},
	}
	if len(by) != len(want) {
		t.Errorf("containers with events: %d, want %d", len(by), len(want))
	}
	for k, w := range want {
		a := by[k]
		if a == nil {
			t.Errorf("%s: no events", k)
			continue
		}
		if a.n != w.n || a.access != w.access || a.size != w.size || a.min.Format(layout) != w.min || a.max.Format(layout) != w.max {
			t.Errorf("%s: n=%d access=%d size=%d %s..%s, want %+v", k, a.n, a.access, a.size, a.min.Format(layout), a.max.Format(layout), w)
		}
	}
	if len(res.Events) != 79 {
		t.Errorf("events = %d, want 79", len(res.Events))
	}
	if len(hosts) != 9 || len(users) != 1 || !users["OMEN"] {
		t.Errorf("hosts=%d users=%v, want 9 hosts and OMEN only", len(hosts), users)
	}
	if kinds["url"] != 62 || kinds["daily_host"] != 2 || kinds["cache_entry"] != 15 {
		t.Errorf("record kinds = %v", kinds)
	}
	if status["HTTP/1.1 200 OK"] != 5 || status["HTTP/1.1 301 Moved Permanently"] != 1 || status["HTTP/1.1 200 "] != 7 {
		t.Errorf("response status lines = %v", status)
	}
	if ctypes["image/svg+xml"] != 4 || ctypes["application/json; charset=utf-8"] != 4 || ctypes["image/gif"] != 4 {
		t.Errorf("content types = %v", ctypes)
	}
	c := res.Coverage
	if c.Mapped != 79 || c.RecordsRead != 79+6 || c.Unmapped != 6 || c.Undated != 0 || c.RecordsFailed != 0 {
		t.Errorf("coverage = %+v", c)
	}
	for _, s := range []string{"container DOMStore (id 4): 1 records not interpreted", "container DOMStore (id 8): 1 records not interpreted",
		"container BackgroundTransferApi (id 10): 1 records not interpreted", "container BackgroundTransferApi (id 12): 3 records not interpreted"} {
		if !noteMentions(c, s) {
			t.Errorf("missing note %q in %v", s, c.Notes)
		}
	}
	seen := map[string]bool{}
	for _, e := range res.Events {
		if e.ArtifactType != model.ArtifactWebCache || seen[e.SourceReference] {
			t.Fatalf("artifact %s or duplicate source reference %q", e.ArtifactType, e.SourceReference)
		}
		seen[e.SourceReference] = true
	}
}

// The system profile's WebCache in the same collection has no Containers table.
func TestParse_RealWebCacheWithoutContainers(t *testing.T) {
	path := os.Getenv("TRACEFALL_REAL_WEBCACHE_SYSTEM")
	if path == "" {
		t.Skip("TRACEFALL_REAL_WEBCACHE_SYSTEM not set")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("not present: %v", err)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != "18ef4c17dea9445dc1e432212f9bb40e7b3fb747f9c977c5182e0bbc185acff2" {
		t.Fatalf("not the pinned sample: sha256 %s", got)
	}
	res, err := Parser{}.Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 0 || !noteMentions(res.Coverage, "no Containers table") {
		t.Errorf("events=%d notes=%v", len(res.Events), res.Coverage.Notes)
	}
}
