package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"tracefall/internal/enrich/virustotal"
	"tracefall/internal/model"
)

const (
	hA = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" // sha256, known
	hB = "3395856ce81f2b7382dee72602f798b642f14140"                         // sha1, not found
	hC = "44d88612fea8a8f36de82e1278abb02f"                                 // md5, server error
	hD = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // sha256, only in an excluded field
)

const vtKnown = `{"data":{"attributes":{"last_analysis_stats":{"malicious":60,"suspicious":0,"harmless":0,"undetected":8,"timeout":0,"failure":0,"type-unsupported":0},
 "type_description":"EICAR","meaningful_name":"eicar.com","sha256":"` + hA + `","popular_threat_classification":{"suggested_threat_label":"virus.eicar"}}}}`

type vtStub struct {
	mu       sync.Mutex
	hits     []string // "METHOD path"
	answers  map[string]func(w http.ResponseWriter)
	delay    time.Duration
	srv      *httptest.Server
	badShape []string
}

func newVTStub(t *testing.T, svc *Service) *vtStub {
	t.Helper()
	s := &vtStub{answers: map[string]func(http.ResponseWriter){}}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.hits = append(s.hits, r.Method+" "+r.URL.Path)
		if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/api/v3/files/") || r.URL.RawQuery != "" || r.ContentLength > 0 {
			s.badShape = append(s.badShape, r.Method+" "+r.URL.RequestURI())
		}
		d := s.delay
		s.mu.Unlock()
		if d > 0 {
			time.Sleep(d)
		}
		h := strings.TrimPrefix(r.URL.Path, "/api/v3/files/")
		if f := s.answers[h]; f != nil {
			f(w)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(s.srv.Close)
	c := virustotal.New("stub-key")
	c.BaseURL = s.srv.URL
	c.Interval = 0
	svc.SetVirusTotal(c)
	return s
}

func (s *vtStub) count() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.hits) }

func ok(body string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) { _, _ = w.Write([]byte(body)) }
}
func status(code int, body string, hdr map[string]string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		for k, v := range hdr {
			w.Header().Set(k, v)
		}
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}
}

// caseWithHashes creates a case whose events carry the given extra fields.
func caseWithHashes(t *testing.T, svc *Service, mux http.Handler, extras ...map[string]string) string {
	t.Helper()
	c := createTestCase(t, mux, "Enrichment "+t.Name())
	col := model.Collection{ID: "11111111-2222-4333-8444-555555555555", CaseID: c.ID, SourceType: model.SourceTypeDiskImage, IngestionStatus: model.CollectionStatusPending}
	sf := model.SourceFile{ID: "sf-1", CaseID: c.ID, CollectionID: col.ID, OriginalFilename: "Amcache.hve", Path: "Windows/AppCompat/Programs/Amcache.hve",
		ImportStatus: model.SourceFileImported, Supported: true, Parser: "registry@1", ArtifactType: "registry_hive"}
	if err := svc.store.CreateCollectionWithSourceFiles(col, []model.SourceFile{sf}); err != nil {
		t.Fatal(err)
	}
	var evs []model.Event
	for i, x := range extras {
		id := "ev-" + string(rune('a'+i))
		evs = append(evs, model.Event{ID: id, CaseID: c.ID, CollectionID: col.ID, SourceFileID: sf.ID, Timestamp: time.Date(2026, 3, 14, 9, i, 0, 0, time.UTC),
			EventType: "test", DedupHash: "d-" + id, Extra: x})
	}
	if err := svc.store.SaveEvents(evs); err != nil {
		t.Fatal(err)
	}
	return c.ID
}

func setLevel(t *testing.T, mux http.Handler, id, level string) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, mux, "PUT", "/api/cases/"+id+"/egress", map[string]string{"level": level}, nil)
}

func waitRun(t *testing.T, svc *Service, id string) VTRunStatus {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		st, err := svc.VirusTotalStatus(id)
		if err != nil {
			t.Fatal(err)
		}
		if st.Run != nil && st.Run.State != "running" {
			return *st.Run
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the run did not end")
	return VTRunStatus{}
}

func auditActions(t *testing.T, svc *Service, id string) []model.AuditEvent {
	t.Helper()
	a, err := svc.store.ListAuditLog(id)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestEgress_DefaultsToNoneAndChangesAreAudited(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	id := caseWithHashes(t, svc, mux, map[string]string{"sha1": hB})

	var got struct {
		Level   string `json:"level"`
		Options []struct {
			Level      string `json:"level"`
			Selectable bool   `json:"selectable"`
		} `json:"options"`
	}
	if rec := doJSON(t, mux, "GET", "/api/cases/"+id+"/egress", nil, &got); rec.Code != 200 || got.Level != "none" {
		t.Fatalf("default: %d %+v", rec.Code, got)
	}
	sel := map[string]bool{}
	for _, o := range got.Options {
		sel[o.Level] = o.Selectable
	}
	if !sel["none"] || !sel["hashes"] || !sel["pseudonymized"] || sel["full"] {
		t.Errorf("selectable options = %v", sel)
	}
	if rec := setLevel(t, mux, id, "hashes"); rec.Code != 200 {
		t.Fatalf("set hashes: %d %s", rec.Code, rec.Body.String())
	}
	if rec := setLevel(t, mux, id, "hashes"); rec.Code != 200 {
		t.Fatalf("set hashes again: %d", rec.Code)
	}
	if rec := setLevel(t, mux, id, "full"); rec.Code != 400 {
		t.Errorf("a reserved level must be refused: %d", rec.Code)
	}
	if rec := setLevel(t, mux, id, "everything"); rec.Code != 400 {
		t.Errorf("an unknown level must be refused: %d", rec.Code)
	}
	if rec := setLevel(t, mux, "no-such-case", "hashes"); rec.Code != 404 {
		t.Errorf("unknown case: %d", rec.Code)
	}
	lvl, _ := svc.EgressLevel(id)
	if lvl != "hashes" {
		t.Errorf("level = %s", lvl)
	}
	changes := 0
	for _, a := range auditActions(t, svc, id) {
		if a.Action == model.AuditEgressChanged {
			changes++
			if !strings.Contains(a.Summary, "from none to hashes") {
				t.Errorf("audit summary %q", a.Summary)
			}
		}
	}
	if changes != 1 {
		t.Errorf("%d egress changes recorded, want exactly 1 (setting the same level again is not a change)", changes)
	}
	// a stored value that is not a level means nothing may leave
	if err := svc.store.SetSetting("egress:"+id, "wide-open"); err != nil {
		t.Fatal(err)
	}
	if lvl, _ := svc.EgressLevel(id); lvl != "none" {
		t.Errorf("a corrupt stored level must read as none, got %s", lvl)
	}
}

func TestVirusTotalCandidates_OnlyFileHashFieldsAndOnlyValidHashes(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	id := caseWithHashes(t, svc, mux,
		map[string]string{"sha1": strings.ToUpper(hB), "content_sha256": hA},
		map[string]string{"sha1": hB, "ntlm_hash": hD, "sql_record_sha256": hD, "boot_key_source_sha256": hD, "sha1_raw": hD},
		map[string]string{"sha256": "not-a-hash", "md5": "d41d8cd98f00b204e9800998ecf8427e", "sha1": "0000000000000000000000000000000000000000"},
		map[string]string{"response_sha256": hA, "md5": hC},
	)
	got, err := svc.VirusTotalCandidates(id)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{hA: "sha256", hB: "sha1", hC: "md5"}
	if len(got) != len(want) {
		t.Fatalf("candidates = %+v", got)
	}
	for _, c := range got {
		if want[c.Hash] != c.Type {
			t.Errorf("unexpected candidate %+v", c)
		}
		if c.Hash == hD {
			t.Errorf("a hash from a field that is not a file hash was taken")
		}
	}
	for _, c := range got {
		switch c.Hash {
		case hA:
			if len(c.EventIDs) != 2 || c.EventIDs[0] != "ev-a" || c.EventIDs[1] != "ev-d" {
				t.Errorf("sha256 events = %v", c.EventIDs)
			}
		case hB:
			if len(c.EventIDs) != 2 {
				t.Errorf("sha1 events = %v (an uppercase value is the same hash)", c.EventIDs)
			}
		}
	}
}

func TestVirusTotal_RefusedAtLevelNoneAndNothingIsSent(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newVTStub(t, svc)
	id := caseWithHashes(t, svc, mux, map[string]string{"sha256": hA})
	rec := doJSON(t, mux, "POST", "/api/cases/"+id+"/enrich/virustotal", nil, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", rec.Code, rec.Body.String())
	}
	time.Sleep(50 * time.Millisecond)
	if stub.count() != 0 {
		t.Errorf("%d request(s) were sent although the case's egress level is none", stub.count())
	}
	for _, a := range auditActions(t, svc, id) {
		if a.Action == model.AuditEnrichmentSent {
			t.Errorf("a refused request must not be recorded as sent: %+v", a)
		}
	}
	// status is readable and says why
	var st struct {
		Status VTStatus `json:"status"`
	}
	doJSON(t, mux, "GET", "/api/cases/"+id+"/enrich/virustotal", nil, &st)
	if st.Status.Allowed || st.Status.EgressLevel != "none" || st.Status.Candidates != 1 || !st.Status.Configured {
		t.Errorf("status = %+v", st.Status)
	}
	if stub.count() != 0 {
		t.Errorf("reading the status sent a request")
	}
}

func TestVirusTotal_NotConfigured(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	id := caseWithHashes(t, svc, mux, map[string]string{"sha256": hA})
	setLevel(t, mux, id, "hashes")
	if rec := doJSON(t, mux, "POST", "/api/cases/"+id+"/enrich/virustotal", nil, nil); rec.Code != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501: %s", rec.Code, rec.Body.String())
	}
	svc.SetVirusTotal(virustotal.New("   "))
	if rec := doJSON(t, mux, "POST", "/api/cases/"+id+"/enrich/virustotal", nil, nil); rec.Code != http.StatusNotImplemented {
		t.Errorf("a blank key: status = %d", rec.Code)
	}
}

func TestVirusTotal_RunStoresAnswersSendsOnlyHashesAndIsAudited(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newVTStub(t, svc)
	stub.answers[hA] = ok(vtKnown)
	stub.answers[hC] = status(500, "boom", nil)
	id := caseWithHashes(t, svc, mux,
		map[string]string{"sha256": hA, "ntlm_hash": hD},
		map[string]string{"sha1": hB},
		map[string]string{"md5": hC},
	)
	setLevel(t, mux, id, "hashes")

	rec := doJSON(t, mux, "POST", "/api/cases/"+id+"/enrich/virustotal", nil, nil)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	run := waitRun(t, svc, id)
	if run.State != "finished" || run.Total != 3 || run.Done != 3 || run.Found != 1 || run.NotFound != 1 || run.Errors != 1 {
		t.Fatalf("run = %+v", run)
	}
	if len(stub.badShape) != 0 {
		t.Errorf("requests that were not a plain GET of a file hash: %v", stub.badShape)
	}
	sent := map[string]bool{}
	for _, h := range stub.hits {
		sent[strings.TrimPrefix(h, "GET /api/v3/files/")] = true
	}
	if len(sent) != 3 || !sent[hA] || !sent[hB] || !sent[hC] || sent[hD] {
		t.Errorf("hashes sent = %v", sent)
	}

	res, _ := svc.VirusTotalResults(id)
	by := map[string]VTResult{}
	for _, r := range res {
		by[r.Indicator] = r
	}
	if r := by[hA]; r.Status != "found" || r.Result == nil || r.Result.Malicious != 60 || r.Result.ThreatLabel != "virus.eicar" || len(r.EventIDs) != 1 || r.EventIDs[0] != "ev-a" {
		t.Errorf("known: %+v", r)
	}
	if r := by[hB]; r.Status != "not_found" || r.Result == nil || r.Result.Found {
		t.Errorf("not found: %+v", r)
	}
	if r := by[hC]; r.Status != "error" || r.Error == "" || r.Result != nil {
		t.Errorf("error: %+v", r)
	}

	var sentAudit, doneAudit *model.AuditEvent
	for _, a := range auditActions(t, svc, id) {
		a := a
		switch a.Action {
		case model.AuditEnrichmentSent:
			sentAudit = &a
		case model.AuditEnrichmentFinished:
			doneAudit = &a
		}
	}
	if sentAudit == nil || !strings.Contains(sentAudit.Summary, "Sending 3 file hash(es)") || !strings.Contains(sentAudit.Summary, "no file name, path, host, user or case detail") || !strings.Contains(sentAudit.Summary, "SHA-256 of the sorted list") {
		t.Errorf("sent audit: %+v", sentAudit)
	}
	if doneAudit == nil || !strings.Contains(doneAudit.Summary, "finished") || !strings.Contains(doneAudit.Summary, "1 not found") || !strings.Contains(doneAudit.Summary, "1 errors") {
		t.Errorf("finished audit: %+v", doneAudit)
	}

	// a second run looks up only what was not answered: the error is retried
	before := stub.count()
	stub.answers[hC] = ok(vtKnown)
	if rec := doJSON(t, mux, "POST", "/api/cases/"+id+"/enrich/virustotal", nil, nil); rec.Code != http.StatusAccepted {
		t.Fatalf("second start: %d %s", rec.Code, rec.Body.String())
	}
	run = waitRun(t, svc, id)
	if run.Total != 1 || stub.count()-before != 1 || stub.hits[len(stub.hits)-1] != "GET /api/v3/files/"+hC {
		t.Errorf("second run %+v, extra requests %d", run, stub.count()-before)
	}
	// a third finds nothing to do and sends nothing
	before = stub.count()
	if rec := doJSON(t, mux, "POST", "/api/cases/"+id+"/enrich/virustotal", nil, nil); rec.Code != http.StatusAccepted {
		t.Fatalf("third start: %d", rec.Code)
	}
	run = waitRun(t, svc, id)
	if run.Total != 0 || run.Reason != "nothing left to look up" || stub.count() != before {
		t.Errorf("third run %+v, extra requests %d", run, stub.count()-before)
	}
}

func TestVirusTotal_RunStopsOnARefusedKeyAndOnTheDailyQuota(t *testing.T) {
	for name, tc := range map[string]struct {
		ans    func(http.ResponseWriter)
		reason string
	}{
		"key refused": {status(401, `{"error":{"code":"WrongCredentialsError"}}`, nil), "refused the API key"},
		"daily quota": {status(429, `{"error":{"code":"QuotaExceededError"}}`, nil), "daily quota"},
	} {
		mux, svc := newTestRouterWithService(t)
		stub := newVTStub(t, svc)
		stub.answers[hA], stub.answers[hB] = tc.ans, tc.ans
		id := caseWithHashes(t, svc, mux, map[string]string{"sha256": hA}, map[string]string{"sha1": hB})
		setLevel(t, mux, id, "hashes")
		if rec := doJSON(t, mux, "POST", "/api/cases/"+id+"/enrich/virustotal", nil, nil); rec.Code != 202 {
			t.Fatalf("%s: %d", name, rec.Code)
		}
		run := waitRun(t, svc, id)
		if run.State != "stopped" || !strings.Contains(run.Reason, tc.reason) {
			t.Errorf("%s: run = %+v", name, run)
		}
		if stub.count() != 1 {
			t.Errorf("%s: %d requests; a run that is refused must stop, not keep asking", name, stub.count())
		}
	}
}

func TestVirusTotal_ARateLimitIsWaitedOutOnce(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newVTStub(t, svc)
	calls := 0
	stub.answers[hA] = func(w http.ResponseWriter) {
		calls++
		if calls == 1 {
			status(429, `{"error":{"code":"TooManyRequestsError"}}`, map[string]string{"Retry-After": "1"})(w)
			return
		}
		ok(vtKnown)(w)
	}
	id := caseWithHashes(t, svc, mux, map[string]string{"sha256": hA})
	setLevel(t, mux, id, "hashes")
	doJSON(t, mux, "POST", "/api/cases/"+id+"/enrich/virustotal", nil, nil)
	run := waitRun(t, svc, id)
	if run.State != "finished" || run.Found != 1 || calls != 2 {
		t.Errorf("run = %+v after %d calls", run, calls)
	}
}

func TestVirusTotal_CancelStopsTheRunAndKeepsWhatWasAnswered(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newVTStub(t, svc)
	stub.answers[hA] = ok(vtKnown)
	stub.delay = 150 * time.Millisecond
	id := caseWithHashes(t, svc, mux, map[string]string{"sha256": hA}, map[string]string{"sha1": hB}, map[string]string{"md5": hC})
	setLevel(t, mux, id, "hashes")
	doJSON(t, mux, "POST", "/api/cases/"+id+"/enrich/virustotal", nil, nil)
	time.Sleep(200 * time.Millisecond)
	if rec := doJSON(t, mux, "POST", "/api/cases/"+id+"/enrich/virustotal/cancel", nil, nil); rec.Code != 204 {
		t.Fatalf("cancel: %d", rec.Code)
	}
	run := waitRun(t, svc, id)
	if run.State != "cancelled" || run.Done >= 3 {
		t.Errorf("run = %+v", run)
	}
	res, _ := svc.VirusTotalResults(id)
	for _, r := range res {
		if r.Status == "error" {
			t.Errorf("a cancelled request was stored as an error answer: %+v", r)
		}
	}
	if len(res) != run.Done {
		t.Errorf("%d stored answers for %d done", len(res), run.Done)
	}
}

func TestVirusTotal_OneRunAtATimeAndTheDailyAllowance(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newVTStub(t, svc)
	stub.delay = 300 * time.Millisecond
	id := caseWithHashes(t, svc, mux, map[string]string{"sha256": hA}, map[string]string{"sha1": hB})
	setLevel(t, mux, id, "hashes")
	if rec := doJSON(t, mux, "POST", "/api/cases/"+id+"/enrich/virustotal", nil, nil); rec.Code != 202 {
		t.Fatalf("first: %d", rec.Code)
	}
	if rec := doJSON(t, mux, "POST", "/api/cases/"+id+"/enrich/virustotal", nil, nil); rec.Code != http.StatusConflict {
		t.Errorf("a second start while running: %d", rec.Code)
	}
	waitRun(t, svc, id)

	// the day's allowance, used up by requests made for any case
	id2 := caseWithHashes2(t, svc, mux)
	setLevel(t, mux, id2, "hashes")
	old := vtDailyLimit
	vtDailyLimit = 5
	defer func() { vtDailyLimit = old }()
	for i := 0; i < vtDailyLimit; i++ {
		if err := svc.store.RecordProviderRequest(model.EnrichmentVirusTotal, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
	before := stub.count()
	rec := doJSON(t, mux, "POST", "/api/cases/"+id2+"/enrich/virustotal", nil, nil)
	if rec.Code != http.StatusConflict || stub.count() != before || !strings.Contains(rec.Body.String(), "daily") {
		t.Errorf("status = %d body %s, extra requests = %d: with the allowance used up nothing may be sent", rec.Code, rec.Body.String(), stub.count()-before)
	}
}

// caseWithHashes2 makes a second case with one hash that nothing has answered.
func caseWithHashes2(t *testing.T, svc *Service, mux http.Handler) string {
	t.Helper()
	c := createTestCase(t, mux, "Second "+t.Name())
	col := model.Collection{ID: "22222222-3333-4444-8555-666666666666", CaseID: c.ID, SourceType: model.SourceTypeDiskImage, IngestionStatus: model.CollectionStatusPending}
	sf := model.SourceFile{ID: "sf-2", CaseID: c.ID, CollectionID: col.ID, OriginalFilename: "a", Path: "a", ImportStatus: model.SourceFileImported, Supported: true, Parser: "p", ArtifactType: "registry_hive"}
	if err := svc.store.CreateCollectionWithSourceFiles(col, []model.SourceFile{sf}); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]string{"sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01"})
	var extra map[string]string
	_ = json.Unmarshal(b, &extra)
	if err := svc.store.SaveEvents([]model.Event{{ID: "ev-z", CaseID: c.ID, CollectionID: col.ID, SourceFileID: sf.ID, Timestamp: time.Now().UTC(), EventType: "test", DedupHash: "dz", Extra: extra}}); err != nil {
		t.Fatal(err)
	}
	return c.ID
}
