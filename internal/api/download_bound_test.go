package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/report"
)

// leftovers lists what is in a case's reports folder besides finished,
// stored bundles. A spooled timeline or a temporary download in there is a copy
// of a case's data that nothing will ever delete.
func leftovers(t *testing.T, svc *Service, caseID string) []string {
	t.Helper()
	entries, err := os.ReadDir(svc.reportsDir(caseID))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if len(n) > 7 && n[:7] == "report-" && filepath.Ext(n) == ".zip" {
			continue
		}
		out = append(out, n)
	}
	return out
}

// ---- report bundle ----

// The bundle reaches the client from a file with its length and hashes, and
// nothing is left behind on disk.
func TestReportDownload_IsSentFromAFileWithItsHashes(t *testing.T) {
	svc, mux, c := reportCase(t)
	rec := rawGet(t, mux, "/api/cases/"+c.ID+"/report.zip")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.Bytes()
	if got := rec.Header().Get("Content-Length"); got != strconv.Itoa(len(body)) {
		t.Errorf("Content-Length %q, body is %d bytes", got, len(body))
	}
	sum := sha256.Sum256(body)
	if got := rec.Header().Get("X-Tracefall-Bundle-SHA256"); got != hex.EncodeToString(sum[:]) {
		t.Errorf("bundle hash header %q does not match the bytes sent", got)
	}
	files := unzip(t, body)
	if got := rec.Header().Get("X-Tracefall-Report-SHA256"); got != report.SHA256Hex(files["report.html"]) {
		t.Errorf("report hash header %q does not match report.html in the bundle", got)
	}
	var list []report.File
	for n, d := range files {
		list = append(list, report.File{Name: n, Data: d})
	}
	if mm, err := report.Verify(files["manifest.json"], list); err != nil || len(mm) != 0 {
		t.Fatalf("the streamed bundle does not verify: %v %+v", err, mm)
	}
	if left := leftovers(t, svc, c.ID); len(left) != 0 {
		t.Fatalf("a download left files in the case folder: %v", left)
	}
}

// ReportHTML used to leave the spooled timeline behind on every call.
func TestReportHTML_LeavesNoSpoolBehind(t *testing.T) {
	svc, mux, c := reportCase(t)
	for _, path := range []string{"/report.html"} {
		if rec := rawGet(t, mux, "/api/cases/"+c.ID+path); rec.Code != http.StatusOK {
			t.Fatalf("%s: %d", path, rec.Code)
		}
	}
	if left := leftovers(t, svc, c.ID); len(left) != 0 {
		t.Fatalf("rendering the HTML report left files behind: %v", left)
	}
}

// However many people ask for a report at once, no more than the configured
// number of builds run: the memory a burst can take is fixed by the server, not
// by the clients.
func TestReportDownload_ConcurrentBuildsNeverExceedTheLimit(t *testing.T) {
	svc, mux, c := reportCase(t)
	svc.SetHeavyLimit(2)

	const clients = 10
	var wg sync.WaitGroup
	codes := make([]int, clients)
	bodies := make([][]byte, clients)
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := rawGet(t, mux, "/api/cases/"+c.ID+"/report.zip")
			codes[i], bodies[i] = rec.Code, rec.Body.Bytes()
		}(i)
	}
	wg.Wait()
	for i := range codes {
		if codes[i] != http.StatusOK {
			t.Fatalf("client %d: status %d", i, codes[i])
		}
		unzip(t, bodies[i]) // a valid zip
	}
	st := svc.HeavyStats()
	if st.PeakRunning > 2 {
		t.Fatalf("%d builds ran at once, limit 2", st.PeakRunning)
	}
	if st.Admitted != clients || st.Running != 0 || st.Waiting != 0 {
		t.Fatalf("after the burst: %+v", st)
	}
	if st.PeakWaiting == 0 {
		t.Log("no request had to queue; the burst may have been too small to test the limit")
	}
	if left := leftovers(t, svc, c.ID); len(left) != 0 {
		t.Fatalf("files left behind: %v", left)
	}
}

// A request that gives up while queued takes no slot and writes nothing.
func TestReportDownload_ACancelledQueuedRequestTakesNothing(t *testing.T) {
	svc, mux, c := reportCase(t)
	svc.SetHeavyLimit(1)
	hold, err := svc.heavy.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest("GET", "/api/cases/"+c.ID+"/report.zip", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { mux.ServeHTTP(rec, req); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a queued request did not leave when its client did")
	}
	if rec.Body.Len() != 0 {
		t.Errorf("a cancelled request produced a body of %d bytes", rec.Body.Len())
	}
	hold()
	if st := svc.HeavyStats(); st.Running != 0 || st.Waiting != 0 {
		t.Fatalf("slots disturbed: %+v", st)
	}
	if rec := rawGet(t, mux, "/api/cases/"+c.ID+"/report.zip"); rec.Code != http.StatusOK {
		t.Fatalf("the next request failed: %d", rec.Code)
	}
}

// The stored report is streamed, so it supports a ranged read like any file.
func TestReportLatest_IsStreamedAndSupportsRanges(t *testing.T) {
	svc, mux, c := reportCase(t)
	if _, err := svc.GenerateCaseReport(c.ID, "job-test"); err != nil {
		t.Fatal(err)
	}
	full := rawGet(t, mux, "/api/cases/"+c.ID+"/report/latest")
	if full.Code != http.StatusOK || full.Body.Len() < 100 {
		t.Fatalf("full read: %d, %d bytes", full.Code, full.Body.Len())
	}
	req := httptest.NewRequest("GET", "/api/cases/"+c.ID+"/report/latest", nil)
	req.Header.Set("Range", "bytes=0-9")
	part := httptest.NewRecorder()
	mux.ServeHTTP(part, req)
	if part.Code != http.StatusPartialContent || !bytes.Equal(part.Body.Bytes(), full.Body.Bytes()[:10]) {
		t.Fatalf("ranged read: status %d, %q", part.Code, part.Body.Bytes())
	}
	if rec := rawGet(t, mux, "/api/cases/00000000-0000-0000-0000-000000000000/report/latest"); rec.Code != http.StatusNotFound {
		t.Errorf("a case with no report: status %d, want 404", rec.Code)
	}
}

// ---- timeline and lookup ----

func decodeEvents(t *testing.T, b []byte) []model.Event {
	t.Helper()
	var out []model.Event
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("the response is not a JSON array of events: %v\n%.200s", err, b)
	}
	return out
}

// The streamed timeline is the case's events, in time order, as a valid array.
func TestTimeline_StreamedResponseIsTheCasesEvents(t *testing.T) {
	svc, mux, c := reportCase(t)
	rec := rawGet(t, mux, "/api/cases/"+c.ID+"/timeline")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("status %d, type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	got := decodeEvents(t, rec.Body.Bytes())
	want, err := svc.store.ListEvents(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(want) < 10 || len(got) != len(want) {
		t.Fatalf("got %d events, store holds %d", len(got), len(want))
	}
	ids := map[string]bool{}
	for _, e := range got {
		ids[e.ID] = true
	}
	for _, e := range want {
		if !ids[e.ID] {
			t.Fatalf("event %s is missing from the stream", e.ID)
		}
	}
	for i := 1; i < len(got); i++ {
		if got[i].Timestamp.Before(got[i-1].Timestamp) {
			t.Fatalf("events %d and %d are out of time order", i-1, i)
		}
	}

	cols, _ := svc.store.ListCollections(c.ID)
	one := decodeEvents(t, rawGet(t, mux, "/api/cases/"+c.ID+"/timeline?collection="+cols[0].ID).Body.Bytes())
	if len(one) == 0 || len(one) > len(got) {
		t.Fatalf("collection view returned %d of %d events", len(one), len(got))
	}
}

func TestTimeline_ACaseWithNoEventsIsAnEmptyArray(t *testing.T) {
	_, mux, _ := reportCase(t)
	empty := mustCreateCase(t, mux, "Nothing here")
	rec := rawGet(t, mux, "/api/cases/"+empty.ID+"/timeline")
	if rec.Code != http.StatusOK || bytes.TrimSpace(rec.Body.Bytes())[0] != '[' {
		t.Fatalf("status %d, body %q", rec.Code, rec.Body.String())
	}
	if n := len(decodeEvents(t, rec.Body.Bytes())); n != 0 {
		t.Fatalf("%d events in an empty case", n)
	}
}

func lookup(t *testing.T, mux http.Handler, caseID string, ids []string) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, mux, "POST", "/api/cases/"+caseID+"/events/lookup", map[string]any{"ids": ids}, nil)
}

func TestEventsLookup_ReturnsOnlyTheNamedEventsOfThisCase(t *testing.T) {
	svc, mux, c := reportCase(t)
	other := mustCreateCase(t, mux, "Another case")
	discoverPathAndImportAll(t, mux, other.ID, filepath.Join("..", "..", "testdata", "synthetic_case"))

	mine, _ := svc.store.ListEvents(c.ID)
	theirs, _ := svc.store.ListEvents(other.ID)
	if len(mine) < 3 || len(theirs) < 1 {
		t.Fatal("fixture too small")
	}
	ask := []string{mine[0].ID, mine[2].ID, "no-such-event", theirs[0].ID, ""}
	rec := lookup(t, mux, c.ID, ask)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	got := decodeEvents(t, rec.Body.Bytes())
	have := map[string]bool{}
	for _, e := range got {
		have[e.ID] = true
		if e.CaseID != c.ID {
			t.Errorf("event %s belongs to case %s: a lookup read across cases", e.ID, e.CaseID)
		}
	}
	if !have[mine[0].ID] || !have[mine[2].ID] || have[theirs[0].ID] || len(got) != 2 {
		t.Fatalf("got %d events %v", len(got), have)
	}
}

func TestEventsLookup_RefusesMoreThanTheLimit(t *testing.T) {
	_, mux, c := reportCase(t)
	ids := make([]string, MaxEventLookup+1)
	for i := range ids {
		ids[i] = "x" + strconv.Itoa(i)
	}
	if rec := lookup(t, mux, c.ID, ids); rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
	if rec := lookup(t, mux, c.ID, ids[:MaxEventLookup]); rec.Code != http.StatusOK {
		t.Fatalf("exactly the limit: status %d", rec.Code)
	}
}

// ---- export ----

// The export computes the investigations from a stream of events; they must be
// the same ones the investigations endpoint serves.
func TestExport_InvestigationsMatchTheInvestigationsEndpoint(t *testing.T) {
	svc, _, c := reportCase(t)
	exp, err := svc.ExportCase(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	inv, err := svc.Investigations(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(exp.Investigations)
	b, _ := json.Marshal(inv)
	if !bytes.Equal(a, b) {
		t.Fatal("the export's investigations differ from GET /investigations")
	}
	if len(inv) == 0 {
		t.Fatal("fixture produced no investigations; the comparison proves nothing")
	}
}
