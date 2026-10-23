// Package llm is a client for an OpenAI-compatible chat completions endpoint.
//
// That one shape is spoken by DeepSeek, OpenAI, Gemini's compatibility
// endpoint, OpenRouter and local servers such as llama.cpp, so choosing a
// provider is configuration, not code.
//
// The client only transports text. What may be put in that text is decided
// before it gets here (internal/pseudonym, internal/narrative, and the egress
// level of the case); the client neither inspects nor logs it. It never
// follows a redirect to another host, never sends anything but the request it
// is given, and removes the key from every error it returns.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultBaseURL is DeepSeek's. A model name has no safe default: names
	// change, and asking for one that no longer exists should be an error the
	// operator sees, not something guessed here.
	DefaultBaseURL = "https://api.deepseek.com"
	maxBody        = 4 << 20
	maxOutput      = 64 << 10
)

var (
	// ErrNotConfigured: no API key or no model name.
	ErrNotConfigured = errors.New("llm: not configured (an API key and a model name are required)")
	// ErrAuth: the key was refused.
	ErrAuth = errors.New("llm: the API key was refused")
	// ErrTruncated: the model stopped because it ran out of room, so its
	// answer ends mid-thought and is not used.
	ErrTruncated = errors.New("llm: the answer was cut off at the length limit")
)

// RateLimitError means the provider asked for slower requests.
type RateLimitError struct{ RetryAfter time.Duration }

func (e *RateLimitError) Error() string { return "llm: rate limit hit" }

// Chatter is anything that can turn messages into a model's answer: a chat
// completions endpoint (Client), or the Codex CLI signed in with a ChatGPT
// account (CodexCLI). The rest of the program depends on this, not on either.
type Chatter interface {
	// Chat sends the messages and returns the answer.
	Chat(ctx context.Context, msgs []Message) (Result, error)
	// Configured reports whether anything can be sent at all.
	Configured() bool
	// Destination says where text goes and whether that is this machine.
	Destination() (host string, local bool)
	// ModelName is the model asked, or a description when it is the provider's default.
	ModelName() string
	// Notice is a sentence about how this provider handles what it receives,
	// shown to the analyst before they acknowledge sending anything. May be empty.
	Notice() string
}

// None is the Chatter of a server with no model configured.
type None struct{}

func (None) Chat(context.Context, []Message) (Result, error) { return Result{}, ErrNotConfigured }
func (None) Configured() bool                                { return false }
func (None) Destination() (string, bool)                     { return "", false }
func (None) ModelName() string                               { return "" }
func (None) Notice() string                                  { return "" }

// Notice: a chat completions endpoint has no general statement to make about
// its provider's data handling; the analyst has to know their provider.
func (c *Client) Notice() string { return "" }

var _ Chatter = (*Client)(nil)

// Message is one chat message.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Result is a model's answer.
type Result struct {
	Content          string
	Model            string
	PromptTokens     int
	CompletionTokens int
}

// Client talks to one endpoint with one key.
type Client struct {
	BaseURL   string
	Key       string
	Model     string
	HTTP      *http.Client
	MaxTokens int
}

// New returns a client. An empty key or model leaves it unconfigured.
func New(baseURL, key, model string) *Client {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = DefaultBaseURL
	}
	c := &Client{BaseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"), Key: strings.TrimSpace(key), Model: strings.TrimSpace(model), MaxTokens: 2048}
	c.HTTP = &http.Client{
		Timeout: 3 * time.Minute,
		// A redirect would carry the key and the text to another host.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return c
}

// Configured reports whether the client has what it needs to send anything.
func (c *Client) Configured() bool {
	return c != nil && strings.TrimSpace(c.Key) != "" && strings.TrimSpace(c.Model) != ""
}

// Destination says where text goes: the host of the endpoint and whether it is
// this machine. Nothing else about the endpoint is exposed.
func (c *Client) Destination() (host string, local bool) {
	if c == nil {
		return "", false
	}
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.Hostname() == "" {
		return "(unparsable address)", false
	}
	h := u.Hostname()
	if strings.EqualFold(h, "localhost") {
		return h, true
	}
	if ip := net.ParseIP(h); ip != nil && ip.IsLoopback() {
		return h, true
	}
	return h, false
}

// ModelName is the configured model.
func (c *Client) ModelName() string {
	if c == nil {
		return ""
	}
	return c.Model
}

type chatRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Temperature float64   `json:"temperature"`
	MaxTokens   int       `json:"max_tokens"`
	Stream      bool      `json:"stream"`
}

type chatResponse struct {
	Model   string `json:"model"`
	Choices []struct {
		Message      Message `json:"message"`
		FinishReason string  `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

// Chat sends the messages and returns the model's answer. Temperature is 0:
// a summary of evidence should not vary between runs for no reason.
func (c *Client) Chat(ctx context.Context, msgs []Message) (Result, error) {
	if !c.Configured() {
		return Result{}, ErrNotConfigured
	}
	body, err := json.Marshal(chatRequest{Model: c.Model, Messages: msgs, Temperature: 0, MaxTokens: c.MaxTokens})
	if err != nil {
		return Result{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.Key))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("llm: %w", scrub(err, c.Key))
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return Result{}, fmt.Errorf("llm: reading the answer: %w", err)
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return Result{}, ErrAuth
	case resp.StatusCode == http.StatusTooManyRequests:
		wait := 30 * time.Second
		if n, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); err == nil && n >= 0 && n <= 300 {
			wait = time.Duration(n) * time.Second
		}
		return Result{}, &RateLimitError{RetryAfter: wait}
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return Result{}, fmt.Errorf("llm: the endpoint redirected (HTTP %d); redirects are not followed", resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		// the provider's explanation is useful and carries none of our text,
		// but it is bounded and shown as a quoted fragment, never parsed
		return Result{}, fmt.Errorf("llm: HTTP %d%s", resp.StatusCode, providerMessage(raw, c.Key))
	}
	var out chatResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return Result{}, fmt.Errorf("llm: the answer is not the expected JSON: %w", err)
	}
	if len(out.Choices) == 0 {
		return Result{}, errors.New("llm: the answer holds no choice")
	}
	ch := out.Choices[0]
	if ch.FinishReason == "length" {
		return Result{}, ErrTruncated
	}
	content := ch.Message.Content
	if len(content) > maxOutput {
		return Result{}, errors.New("llm: the answer is larger than allowed")
	}
	if strings.TrimSpace(content) == "" {
		return Result{}, errors.New("llm: the answer is empty")
	}
	return Result{Content: content, Model: out.Model, PromptTokens: out.Usage.PromptTokens, CompletionTokens: out.Usage.CompletionTokens}, nil
}

// providerMessage extracts a short error message, without the key.
func providerMessage(raw []byte, key string) string {
	var e struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &e) != nil || e.Error.Message == "" {
		return ""
	}
	m := strings.Join(strings.Fields(e.Error.Message), " ")
	if key != "" {
		m = strings.ReplaceAll(m, key, "[key]")
	}
	if r := []rune(m); len(r) > 160 {
		m = string(r[:160]) + "..."
	}
	return ": " + m
}

type scrubbed struct {
	msg string
	err error
}

func (e scrubbed) Error() string { return e.msg }
func (e scrubbed) Unwrap() error { return e.err }

// scrub removes the key from an error that quotes the request, keeping the
// error recognisable (context.Canceled stays context.Canceled).
func scrub(err error, key string) error {
	if strings.TrimSpace(key) == "" {
		return err
	}
	return scrubbed{msg: strings.ReplaceAll(err.Error(), strings.TrimSpace(key), "[key]"), err: err}
}
