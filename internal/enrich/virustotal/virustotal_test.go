package virustotal

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	sha256a = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
	sha1a   = "3395856ce81f2b7382dee72602f798b642f14140"
	md5a    = "44d88612fea8a8f36de82e1278abb02f"
	testKey = "test-key-not-a-real-credential"
)

type seen struct {
	mu       sync.Mutex
	requests []*http.Request
	bodies   []string
}

func (s *seen) add(r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	s.requests = append(s.requests, r)
	s.bodies = append(s.bodies, string(b))
	s.mu.Unlock()
}

func (s *seen) n() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.requests) }

func server(t *testing.T, status int, body string, hdr map[string]string) (*Client, *seen) {
	t.Helper()
	s := &seen{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.add(r)
		for k, v := range hdr {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(ts.Close)
	c := New(testKey)
	c.BaseURL = ts.URL
	c.Interval = 0
	return c, s
}

const foundBody = `{"data":{"type":"file","attributes":{
 "last_analysis_stats":{"malicious":62,"suspicious":1,"harmless":0,"undetected":9,"timeout":2,"failure":0,"type-unsupported":5},
 "type_description":"EICAR virus test files","meaningful_name":"eicar.com","reputation":-12,
 "sha256":"275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F",
 "first_submission_date":1262304000,"last_analysis_date":1767225600,
 "popular_threat_classification":{"suggested_threat_label":"virus.eicar/test"}}}}`

func TestValidHash(t *testing.T) {
	good := []string{sha256a, sha1a, md5a}
	for _, g := range good {
		if !ValidHash(g) {
			t.Errorf("%q should be a hash", g)
		}
	}
	bad := []string{"", strings.ToUpper(sha256a), sha256a[:63], sha256a + "0", sha1a[:39], "../" + sha1a, "a.exe", "C:\\Windows\\a.exe",
		sha256a + "?x=1", sha256a + "/", " " + sha256a, sha256a + "\n", "https://example.com/" + md5a, strings.Repeat("g", 64), "host01"}
	for _, b := range bad {
		if ValidHash(b) {
			t.Errorf("%q must not be accepted as a hash", b)
		}
	}
	if HashType(sha256a) != "sha256" || HashType(sha1a) != "sha1" || HashType(md5a) != "md5" || HashType("x") != "" {
		t.Errorf("hash types")
	}
}

func TestLookup_FoundIsParsedAndOnlyTheHashAndKeyAreSent(t *testing.T) {
	c, s := server(t, 200, foundBody, nil)
	r, err := c.Lookup(context.Background(), sha256a)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Found || r.Malicious != 62 || r.Suspicious != 1 || r.Undetected != 9 || r.Harmless != 0 || r.Timeout != 2 || r.TypeUnsupported != 5 || r.Engines() != 72 {
		t.Errorf("stats: %+v", r)
	}
	if r.TypeDescription != "EICAR virus test files" || r.MeaningfulName != "eicar.com" || r.ThreatLabel != "virus.eicar/test" || r.Reputation != -12 || r.SHA256 != sha256a {
		t.Errorf("attributes: %+v", r)
	}
	if r.FirstSubmission != "2010-01-01T00:00:00Z" || r.LastAnalysis != "2026-01-01T00:00:00Z" || r.Link != "https://www.virustotal.com/gui/file/"+sha256a {
		t.Errorf("dates/link: %+v", r)
	}
	if s.n() != 1 {
		t.Fatalf("requests = %d", s.n())
	}
	req := s.requests[0]
	if req.Method != http.MethodGet || req.URL.Path != "/api/v3/files/"+sha256a || req.URL.RawQuery != "" || s.bodies[0] != "" {
		t.Errorf("request: %s %s ?%s body=%q", req.Method, req.URL.Path, req.URL.RawQuery, s.bodies[0])
	}
	if req.Header.Get("x-apikey") != testKey {
		t.Errorf("the key is not sent as x-apikey")
	}
	for k := range req.Header {
		switch strings.ToLower(k) {
		case "x-apikey", "accept", "user-agent", "accept-encoding":
		default:
			t.Errorf("unexpected request header %q: nothing but the key and standard transport headers may be sent", k)
		}
	}
	if len(req.Cookies()) != 0 {
		t.Errorf("cookies were sent")
	}
}

func TestLookup_NotFoundIsAnAnswerNotAnError(t *testing.T) {
	c, _ := server(t, 404, `{"error":{"code":"NotFoundError"}}`, nil)
	r, err := c.Lookup(context.Background(), md5a)
	if err != nil || r.Found || r.Link == "" {
		t.Errorf("r=%+v err=%v", r, err)
	}
}

func TestLookup_Refusals(t *testing.T) {
	for _, code := range []int{401, 403} {
		c, _ := server(t, code, `{"error":{"code":"WrongCredentialsError"}}`, nil)
		if _, err := c.Lookup(context.Background(), sha1a); !errors.Is(err, ErrAuth) {
			t.Errorf("%d: err = %v", code, err)
		}
	}
	c, _ := server(t, 429, `{"error":{"code":"TooManyRequestsError"}}`, map[string]string{"Retry-After": "42"})
	_, err := c.Lookup(context.Background(), sha1a)
	var q *QuotaError
	if !errors.As(err, &q) || q.RetryAfter != 42*time.Second || q.Daily {
		t.Errorf("rate limit: %v", err)
	}
	c, _ = server(t, 429, `{"error":{"code":"QuotaExceededError"}}`, nil)
	if _, err := c.Lookup(context.Background(), sha1a); !errors.As(err, &q) || !q.Daily {
		t.Errorf("daily quota: %v", err)
	}
	c, _ = server(t, 500, `boom `+testKey, nil)
	if _, err := c.Lookup(context.Background(), sha1a); err == nil || strings.Contains(err.Error(), testKey) {
		t.Errorf("server error: %v", err)
	}
}

func TestLookup_NothingButAHashEverReachesTheNetwork(t *testing.T) {
	c, s := server(t, 200, foundBody, nil)
	for _, bad := range []string{"", strings.ToUpper(sha256a), sha256a + "?x=1", "../../etc/passwd", "evil.exe", "C:\\Users\\alice\\secret.docx", "alice", "https://x.example/" + md5a, md5a + "\n"} {
		if _, err := c.Lookup(context.Background(), bad); !errors.Is(err, ErrNotAHash) {
			t.Errorf("%q: err = %v", bad, err)
		}
	}
	if s.n() != 0 {
		t.Errorf("%d requests were made for things that are not hashes", s.n())
	}
}

func TestLookup_WithoutAKeyNothingIsSent(t *testing.T) {
	c, s := server(t, 200, foundBody, nil)
	c.Key = "  "
	if _, err := c.Lookup(context.Background(), sha256a); !errors.Is(err, ErrNotConfigured) || s.n() != 0 {
		t.Errorf("err=%v requests=%d", err, s.n())
	}
	var nilClient *Client
	if nilClient.Configured() {
		t.Errorf("a nil client is not configured")
	}
}

func TestLookup_RequestsAreSpacedAndACancelledWaitSendsNothing(t *testing.T) {
	c, s := server(t, 200, foundBody, nil)
	c.Interval = 80 * time.Millisecond
	start := time.Now()
	for i := 0; i < 3; i++ {
		if _, err := c.Lookup(context.Background(), sha256a); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d < 160*time.Millisecond {
		t.Errorf("three lookups took %v: the free-tier spacing was not applied", d)
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.Interval = time.Hour
	cancel()
	before := s.n()
	if _, err := c.Lookup(ctx, sha256a); !errors.Is(err, context.Canceled) || s.n() != before {
		t.Errorf("err=%v extra requests=%d", err, s.n()-before)
	}
}

type failingTransport struct{ msg string }

func (f failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New(f.msg)
}

func TestLookup_TheKeyNeverAppearsInAnError(t *testing.T) {
	c := New(testKey)
	c.Interval = 0
	c.HTTP = &http.Client{Transport: failingTransport{"dial failed with header x-apikey: " + testKey}}
	_, err := c.Lookup(context.Background(), sha256a)
	if err == nil || strings.Contains(err.Error(), testKey) {
		t.Errorf("err = %v", err)
	}
}

func TestLookup_AnswersThatAreNotAnalysesAreRefused(t *testing.T) {
	for name, body := range map[string]string{"not json": "<html>", "empty": `{}`, "empty data": `{"data":{"attributes":{}}}`} {
		c, _ := server(t, 200, body, nil)
		if r, err := c.Lookup(context.Background(), sha256a); err == nil {
			t.Errorf("%s was accepted: %+v", name, r)
		}
	}
}

func TestLookup_ACancelledRequestStillIsContextCanceled(t *testing.T) {
	c2 := New(testKey)
	c2.Interval = 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(300 * time.Millisecond) }))
	defer ts.Close()
	c2.BaseURL = ts.URL
	ctx2, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()
	if _, err := c2.Lookup(ctx2, sha256a); !errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), testKey) {
		t.Errorf("in-flight cancellation: %v", err)
	}
}
