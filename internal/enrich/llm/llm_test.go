package llm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testKey = "test-key-not-a-real-credential"

type seen struct {
	method string
	path   string
	auth   string
	hdr    http.Header
	body   []byte
	n      int
}

func serve(t *testing.T, status int, body string, hdr map[string]string) (*Client, *seen) {
	t.Helper()
	s := &seen{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.n++
		s.method, s.path, s.auth, s.hdr = r.Method, r.URL.Path, r.Header.Get("Authorization"), r.Header.Clone()
		s.body, _ = io.ReadAll(r.Body)
		for k, v := range hdr {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(ts.Close)
	return New(ts.URL, testKey, "test-model"), s
}

const okBody = `{"model":"test-model-2026","choices":[{"message":{"role":"assistant","content":"F1 matters. [F1]"},"finish_reason":"stop"}],"usage":{"prompt_tokens":120,"completion_tokens":9}}`

func TestChat_SendsExactlyTheMessagesAndTheKeyAndNothingElse(t *testing.T) {
	c, s := serve(t, 200, okBody, nil)
	r, err := c.Chat(context.Background(), []Message{{"system", "be careful"}, {"user", "facts"}})
	if err != nil {
		t.Fatal(err)
	}
	if r.Content != "F1 matters. [F1]" || r.Model != "test-model-2026" || r.PromptTokens != 120 || r.CompletionTokens != 9 {
		t.Errorf("result = %+v", r)
	}
	if s.method != "POST" || s.path != "/chat/completions" || s.auth != "Bearer "+testKey {
		t.Errorf("request: %s %s auth=%q", s.method, s.path, s.auth)
	}
	var sent map[string]any
	if err := json.Unmarshal(s.body, &sent); err != nil {
		t.Fatal(err)
	}
	for k := range sent {
		switch k {
		case "model", "messages", "temperature", "max_tokens", "stream":
		default:
			t.Errorf("unexpected field %q in the request body", k)
		}
	}
	if sent["model"] != "test-model" || sent["temperature"] != float64(0) || sent["stream"] != false {
		t.Errorf("body = %v", sent)
	}
	msgs := sent["messages"].([]any)
	if len(msgs) != 2 || msgs[1].(map[string]any)["content"] != "facts" {
		t.Errorf("messages = %v", msgs)
	}
	for k := range s.hdr {
		switch strings.ToLower(k) {
		case "authorization", "content-type", "accept", "user-agent", "accept-encoding", "content-length":
		default:
			t.Errorf("unexpected header %q", k)
		}
	}
}

func TestChat_NothingIsSentWithoutAKeyAndAModel(t *testing.T) {
	c, s := serve(t, 200, okBody, nil)
	for _, bad := range []*Client{{BaseURL: c.BaseURL, Key: "", Model: "m", HTTP: c.HTTP}, {BaseURL: c.BaseURL, Key: "  ", Model: "m", HTTP: c.HTTP}, {BaseURL: c.BaseURL, Key: "k", Model: "", HTTP: c.HTTP}, nil} {
		if _, err := bad.Chat(context.Background(), []Message{{"user", "x"}}); !errors.Is(err, ErrNotConfigured) {
			t.Errorf("err = %v", err)
		}
	}
	if s.n != 0 {
		t.Errorf("%d request(s) were sent from an unconfigured client", s.n)
	}
}

func TestChat_Refusals(t *testing.T) {
	for _, code := range []int{401, 403} {
		c, _ := serve(t, code, `{"error":{"message":"bad key"}}`, nil)
		if _, err := c.Chat(context.Background(), []Message{{"user", "x"}}); !errors.Is(err, ErrAuth) {
			t.Errorf("%d: %v", code, err)
		}
	}
	c, _ := serve(t, 429, `{}`, nil)
	var rl *RateLimitError
	if _, err := c.Chat(context.Background(), []Message{{"user", "x"}}); !errors.As(err, &rl) {
		t.Errorf("rate limit: %v", err)
	}
	c, _ = serve(t, 500, `{"error":{"message":"overloaded `+testKey+`   now"}}`, nil)
	_, err := c.Chat(context.Background(), []Message{{"user", "x"}})
	if err == nil || strings.Contains(err.Error(), testKey) || !strings.Contains(err.Error(), "HTTP 500") || !strings.Contains(err.Error(), "overloaded [key] now") {
		t.Errorf("server error: %v", err)
	}
	c, _ = serve(t, 500, `{"error":{"message":"`+strings.Repeat("x", 1000)+`"}}`, nil)
	if _, err := c.Chat(context.Background(), []Message{{"user", "x"}}); err == nil || len(err.Error()) > 260 {
		t.Errorf("a provider message must be bounded: %v", err)
	}
}

func TestChat_AnswersThatCannotBeUsedAreRefused(t *testing.T) {
	for name, body := range map[string]string{
		"not json":  "<html>",
		"no choice": `{"choices":[]}`,
		"empty":     `{"choices":[{"message":{"role":"assistant","content":"  "},"finish_reason":"stop"}]}`,
		"too long":  `{"choices":[{"message":{"role":"assistant","content":"` + strings.Repeat("a", 70000) + `"},"finish_reason":"stop"}]}`,
	} {
		c, _ := serve(t, 200, body, nil)
		if r, err := c.Chat(context.Background(), []Message{{"user", "x"}}); err == nil {
			t.Errorf("%s was accepted: %.40q", name, r.Content)
		}
	}
	c, _ := serve(t, 200, `{"choices":[{"message":{"role":"assistant","content":"half a thou"},"finish_reason":"length"}]}`, nil)
	if _, err := c.Chat(context.Background(), []Message{{"user", "x"}}); !errors.Is(err, ErrTruncated) {
		t.Errorf("a truncated answer must not be used: %v", err)
	}
}

func TestChat_ARedirectIsNotFollowedAndNothingIsSentToTheOtherHost(t *testing.T) {
	other := &seen{}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { other.n++; other.auth = r.Header.Get("Authorization") }))
	defer target.Close()
	c, _ := serve(t, 307, "", map[string]string{"Location": target.URL + "/steal"})
	_, err := c.Chat(context.Background(), []Message{{"user", "secret text"}})
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Errorf("err = %v", err)
	}
	if other.n != 0 || other.auth != "" {
		t.Errorf("the redirect target received %d request(s), auth %q", other.n, other.auth)
	}
}

type failingTransport struct{ msg string }

func (f failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New(f.msg)
}

func TestChat_TheKeyNeverAppearsInAnErrorAndCancellationStaysRecognisable(t *testing.T) {
	c := New("http://127.0.0.1:1", testKey, "m")
	c.HTTP = &http.Client{Transport: failingTransport{"dial: Authorization: Bearer " + testKey}}
	_, err := c.Chat(context.Background(), []Message{{"user", "x"}})
	if err == nil || strings.Contains(err.Error(), testKey) {
		t.Errorf("err = %v", err)
	}
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(300 * time.Millisecond) }))
	defer slow.Close()
	c2 := New(slow.URL, testKey, "m")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c2.Chat(ctx, []Message{{"user", "x"}}); !errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), testKey) {
		t.Errorf("in-flight cancellation: %v", err)
	}
}

func TestDestination_SaysWhereTextGoesAndWhetherThatIsThisMachine(t *testing.T) {
	for _, tc := range []struct {
		base  string
		host  string
		local bool
	}{
		{"https://api.deepseek.com", "api.deepseek.com", false},
		{"https://api.deepseek.com/v1", "api.deepseek.com", false},
		{"http://127.0.0.1:8080", "127.0.0.1", true},
		{"http://localhost:8080/v1", "localhost", true},
		{"http://[::1]:8080", "::1", true},
		{"http://192.168.1.9:8080", "192.168.1.9", false},
		{"http://localhost.evil.example", "localhost.evil.example", false},
	} {
		h, l := New(tc.base, "k", "m").Destination()
		if h != tc.host || l != tc.local {
			t.Errorf("%s -> %q local=%v, want %q local=%v", tc.base, h, l, tc.host, tc.local)
		}
	}
	if h, _ := New("", "k", "m").Destination(); h != "api.deepseek.com" {
		t.Errorf("default = %q", h)
	}
	if h, l := (*Client)(nil).Destination(); h != "" || l {
		t.Errorf("nil client")
	}
}

func TestChat_RateLimitHonoursRetryAfterWithinReason(t *testing.T) {
	for hdr, want := range map[string]time.Duration{"2": 2 * time.Second, "0": 0, "": 30 * time.Second, "soon": 30 * time.Second, "-5": 30 * time.Second, "99999": 30 * time.Second} {
		c, _ := serve(t, 429, `{}`, map[string]string{"Retry-After": hdr})
		var rl *RateLimitError
		if _, err := c.Chat(context.Background(), []Message{{"user", "x"}}); !errors.As(err, &rl) || rl.RetryAfter != want {
			t.Errorf("Retry-After %q: %v", hdr, err)
		}
	}
}
