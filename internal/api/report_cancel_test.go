package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/report"
)

// phaseRecorder is a context observer: it records every phase a build reaches
// and cancels the context at an exact named point. No sleeps, no globals.
type phaseRecorder struct {
	mu     sync.Mutex
	seen   []string
	count  map[string]int
	cancel context.CancelFunc
	at     string // phase to cancel at ("" = never)
	nth    int    // cancel on the nth occurrence of at (default 1)
}

func newPhaseCtx(at string, nth int) (context.Context, *phaseRecorder) {
	base, cancel := context.WithCancel(context.Background())
	pr := &phaseRecorder{cancel: cancel, at: at, nth: nth, count: map[string]int{}}
	if pr.nth == 0 {
		pr.nth = 1
	}
	return context.WithValue(base, phaseObserverKey{}, func(p string) { pr.observe(p) }), pr
}

func (pr *phaseRecorder) observe(p string) {
	pr.mu.Lock()
	pr.seen = append(pr.seen, p)
	pr.count[p]++
	hit := p == pr.at && pr.count[p] == pr.nth
	pr.mu.Unlock()
	if hit {
		pr.cancel()
	}
}

func (pr *phaseRecorder) last() string {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	if len(pr.seen) == 0 {
		return ""
	}
	return pr.seen[len(pr.seen)-1]
}

func (pr *phaseRecorder) n(p string) int {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	return pr.count[p]
}

func exportAudits(t *testing.T, s *Service, caseID string) int {
	t.Helper()
	log, err := s.store.ListAuditLog(caseID)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, a := range log {
		if a.Action == model.AuditExport {
			n++
		}
	}
	return n
}

// inputDigest hashes the case's events as stored, so a cancelled build can be
// shown not to have altered its inputs.
func inputDigest(t *testing.T, s *Service, caseID string) string {
	t.Helper()
	evs, err := s.store.ListEvents(caseID)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(evs)
	if err != nil {
		t.Fatal(err)
	}
	return report.SHA256Hex(b)
}

func assertCancelClean(t *testing.T, s *Service, caseID string, auditsBefore int, digestBefore string) {
	t.Helper()
	if left := leftovers(t, s, caseID); len(left) != 0 {
		t.Fatalf("a cancelled build left files behind: %v", left)
	}
	if n := exportAudits(t, s, caseID); n != auditsBefore {
		t.Fatalf("a cancelled build recorded issuance: export audits %d -> %d", auditsBefore, n)
	}
	if st := s.HeavyStats(); st.Running != 0 || st.Waiting != 0 {
		t.Fatalf("heavy slot not released exactly once: %+v", st)
	}
	if got := inputDigest(t, s, caseID); got != digestBefore {
		t.Fatal("a cancelled build changed the case's events")
	}
}

// Every phase boundary stops the build: cancelling at a phase means no later
// phase runs, nothing is issued and nothing is left on disk.
func TestReportCancel_StopsAtEveryPhaseBoundary(t *testing.T) {
	svc, _, c := reportCase(t)
	digest := inputDigest(t, svc, c.ID)
	phases := []string{"start", "loaded", "cited", "investigations", "timeline", "attachments", "render", "rendered", "bundle-write", "pre-issue"}
	entry := map[string]func(*Service) error{
		"bundle": func(s *Service) error {
			d, err := s.ReportBundleFile(c.ID)
			if err == nil {
				d.Close()
			}
			return err
		},
		"html": func(s *Service) error { _, _, err := s.ReportHTML(c.ID); return err },
	}
	for name, run := range entry {
		for _, phase := range phases {
			if name == "html" && phase == "bundle-write" {
				continue // the HTML endpoint writes no bundle
			}
			t.Run(name+"/"+phase, func(t *testing.T) {
				ctx, pr := newPhaseCtx(phase, 1)
				defer pr.cancel()
				audits := exportAudits(t, svc, c.ID)
				err := run(svc.WithRequest(ctx))
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancelled at %q: err = %v, want context.Canceled", phase, err)
				}
				if pr.last() != phase {
					t.Fatalf("build kept going after the cancel at %q: last phase %q (seen %v)", phase, pr.last(), pr.seen)
				}
				assertCancelClean(t, svc, c.ID, audits, digest)
			})
		}
	}
}

// Cancelling in the middle of the timeline stream stops at the next event.
func TestReportCancel_DuringTimelineStream(t *testing.T) {
	svc, _, c := reportCase(t)
	digest := inputDigest(t, svc, c.ID)
	ctx, pr := newPhaseCtx("timeline-event", 3)
	defer pr.cancel()
	audits := exportAudits(t, svc, c.ID)
	_, _, err := svc.WithRequest(ctx).ReportHTML(c.ID)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if got := pr.n("timeline-event"); got != 3 {
		t.Fatalf("timeline kept streaming after the cancel: %d events", got)
	}
	if pr.n("timeline") != 0 {
		t.Fatal("timeline phase completed after cancel")
	}
	assertCancelClean(t, svc, c.ID, audits, digest)
}

// Cancelling in the middle of the cited-events stream reaches the cited writer
// through the build, not only through its own tests.
func TestReportCancel_DuringCitedStream(t *testing.T) {
	s, id, now := citedFixture(t)
	ctx, pr := newPhaseCtx("cited-event", 10)
	defer pr.cancel()
	_, err := s.WithRequest(ctx).buildReport(id, now)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if got := pr.n("cited-event"); got != 10 {
		t.Fatalf("cited stream kept going after the cancel: %d events", got)
	}
	entries, _ := os.ReadDir(s.reportsDir(id))
	if len(entries) != 0 {
		t.Fatalf("spool left behind: %d entries", len(entries))
	}
}

// After the issuance record is written the report stands: a cancel that lands
// later does not turn a committed issuance into an error.
func TestReportCancel_AfterIssuanceTheReportStands(t *testing.T) {
	svc, _, c := reportCase(t)
	ctx, pr := newPhaseCtx("issued", 1)
	defer pr.cancel()
	before := exportAudits(t, svc, c.ID)
	d, err := svc.WithRequest(ctx).ReportBundleFile(c.ID)
	if err != nil {
		t.Fatalf("a cancel after issuance failed the request: %v", err)
	}
	if n := exportAudits(t, svc, c.ID); n != before+1 {
		t.Fatalf("issuance records %d -> %d, want exactly one", before, n)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if left := leftovers(t, svc, c.ID); len(left) != 0 {
		t.Fatalf("files left behind: %v", left)
	}
}

// The ZIP stream stops mid-write once the context is done.
func TestReportCancel_InsideZIPWrite(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	big := make([]byte, 4<<20)
	for i := range big { // incompressible-ish synthetic bytes
		big[i] = byte(i*131 + i>>8*17)
	}
	b := reportBuild{HTML: []byte("<html></html>"), ManifestJSON: []byte("{}"), Files: []report.File{report.NewFile("big.bin", big)}}
	sink := &cancelAfterWrite{cancel: cancel}
	err := writeBundleTo(ctx, sink, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), b)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if sink.n > 1<<20 {
		t.Fatalf("the ZIP writer kept writing after cancel: %d bytes", sink.n)
	}
}

type cancelAfterWrite struct {
	cancel context.CancelFunc
	n      int
}

func (c *cancelAfterWrite) Write(p []byte) (int, error) {
	c.n += len(p)
	c.cancel()
	return len(p), nil
}

// An unchanged successful build, observed or not, is byte-identical.
func TestReportCancel_SuccessIsByteIdentical(t *testing.T) {
	svc, _, c := reportCase(t)
	now := time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC)
	a, err := svc.buildReport(c.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	defer a.release()
	ctx, pr := newPhaseCtx("", 0)
	defer pr.cancel()
	b, err := svc.WithRequest(ctx).buildReport(c.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	defer b.release()
	if !bytes.Equal(a.HTML, b.HTML) || !bytes.Equal(a.ManifestJSON, b.ManifestJSON) {
		t.Fatal("request-bound build differs from the plain build")
	}
	if len(a.Files) != len(b.Files) {
		t.Fatal("attachment count differs")
	}
	for i := range a.Files {
		if a.Files[i].Name != b.Files[i].Name || a.Files[i].SHA256 != b.Files[i].SHA256 || a.Files[i].Size != b.Files[i].Size {
			t.Fatalf("attachment %s differs", a.Files[i].Name)
		}
	}
}

// A queued request that leaves gets no error page, for every report endpoint.
func TestReportCancel_QueuedClientGetsNoErrorPage(t *testing.T) {
	svc, mux, c := reportCase(t)
	svc.SetHeavyLimit(1)
	hold, err := svc.heavy.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/report.html", "/report.zip", "/report.pdf"} {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		req := httptest.NewRequest("GET", "/api/cases/"+c.ID+path, nil).WithContext(ctx)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Body.Len() != 0 {
			t.Errorf("%s: cancelled client got a body: %q", path, rec.Body.String())
		}
	}
	hold()
	if st := svc.HeavyStats(); st.Running != 0 || st.Waiting != 0 {
		t.Fatalf("slots disturbed: %+v", st)
	}
}

// A cancel after the slot is held (mid-build) also gets no error page, and the
// PDF path never reaches the renderer.
func TestReportCancel_MidBuildClientGetsNoErrorPage(t *testing.T) {
	svc, mux, c := reportCase(t)
	digest := inputDigest(t, svc, c.ID)
	for _, path := range []string{"/report.html", "/report.zip", "/report.pdf"} {
		t.Run(path, func(t *testing.T) {
			ctx, pr := newPhaseCtx("timeline", 1)
			defer pr.cancel()
			audits := exportAudits(t, svc, c.ID)
			req := httptest.NewRequest("GET", "/api/cases/"+c.ID+path, nil).WithContext(ctx)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Body.Len() != 0 {
				t.Fatalf("cancelled client got a body (status %d): %q", rec.Code, rec.Body.String())
			}
			if pr.n("pdf") != 0 || pr.n("render") != 0 {
				t.Fatalf("work continued after cancel: %v", pr.seen)
			}
			assertCancelClean(t, svc, c.ID, audits, digest)
		})
	}
}

// Parent cancellation racing the build, from many requests at once, releases
// every slot exactly once and corrupts nothing. Run with -race.
func TestReportCancel_ConcurrentCancelsReleaseEverySlotOnce(t *testing.T) {
	svc, _, c := reportCase(t)
	svc.SetHeavyLimit(2)
	digest := inputDigest(t, svc, c.ID)
	phases := []string{"start", "loaded", "cited", "investigations", "timeline", "timeline-event", "render", "pre-issue", ""}
	var wg sync.WaitGroup
	var ok, cancelled atomic.Int32
	for i := 0; i < 18; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, pr := newPhaseCtx(phases[i%len(phases)], 1)
			defer pr.cancel()
			if i%3 == 0 { // a parent that is cancelled from outside, racing the build
				go pr.cancel()
			}
			d, err := svc.WithRequest(ctx).ReportBundleFile(c.ID)
			switch {
			case err == nil:
				ok.Add(1)
				d.Close()
			case errors.Is(err, context.Canceled):
				cancelled.Add(1)
			default:
				t.Errorf("request %d: unexpected error %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	if cancelled.Load() == 0 {
		t.Fatal("no request was cancelled; the test proves nothing")
	}
	if st := svc.HeavyStats(); st.Running != 0 || st.Waiting != 0 {
		t.Fatalf("slots not all released: %+v", st)
	}
	if left := leftovers(t, svc, c.ID); len(left) != 0 {
		t.Fatalf("files left behind: %v", left)
	}
	if got := inputDigest(t, svc, c.ID); got != digest {
		t.Fatal("events changed")
	}
}

// statusRecorder notes whether the handler wrote anything to the client.
type statusRecorder struct {
	http.ResponseWriter
	mu     sync.Mutex
	status int
	bytes  int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.mu.Lock()
	s.status = code
	s.mu.Unlock()
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(p []byte) (int, error) {
	s.mu.Lock()
	s.bytes += len(p)
	s.mu.Unlock()
	return s.ResponseWriter.Write(p)
}

// A real HTTP client that disconnects mid-build: the server stops the build,
// answers nothing, leaves nothing on disk, and the listener closes cleanly.
func TestReportCancel_RealHTTPDisconnect(t *testing.T) {
	svc, _, c := reportCase(t)
	digest := inputDigest(t, svc, c.ID)
	audits := exportAudits(t, svc, c.ID)
	inner := routerFor(svc)
	reached := make(chan struct{})
	finished := make(chan *statusRecorder, 1)
	var once sync.Once
	front := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w}
		observer := func(p string) {
			if p != "timeline" {
				return
			}
			once.Do(func() { close(reached) })
			// Barrier: hold the build here until the server has noticed the
			// client is gone. No sleeps.
			select {
			case <-r.Context().Done():
			case <-time.After(20 * time.Second):
			}
		}
		r = r.WithContext(context.WithValue(r.Context(), phaseObserverKey{}, observer))
		inner.ServeHTTP(rec, r)
		finished <- rec
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: front}
	served := make(chan struct{})
	go func() { _ = srv.Serve(ln); close(served) }()

	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+ln.Addr().String()+"/api/cases/"+c.ID+"/report.zip", nil)
	errc := make(chan error, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		errc <- err
	}()
	<-reached
	cancel()
	<-errc
	var rec *statusRecorder
	select {
	case rec = <-finished:
	case <-time.After(30 * time.Second):
		t.Fatal("the handler did not finish after the client left")
	}
	if rec.bytes != 0 || (rec.status != 0 && rec.status != http.StatusOK) {
		t.Fatalf("handler answered a departed client: status %d, %d bytes", rec.status, rec.bytes)
	}
	assertCancelClean(t, svc, c.ID, audits, digest)

	shutdown, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	if err := srv.Shutdown(shutdown); err != nil {
		t.Fatal(err)
	}
	<-served
	if conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second); err == nil {
		conn.Close()
		t.Fatal("listener still open after shutdown")
	}
	if strings.Contains(ln.Addr().String(), ":8080") {
		t.Fatal("used the default port")
	}
}
