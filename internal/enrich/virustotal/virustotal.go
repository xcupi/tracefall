// Package virustotal looks file hashes up on VirusTotal.
//
// It does one thing: GET /api/v3/files/{hash} for a hash that is MD5, SHA-1 or
// SHA-256 in lowercase hex. It never uploads a file, never submits a URL,
// never sends a name, path or case detail, and refuses anything that is not a
// hash before a request is built, so the only thing that can leave through it
// is a hash.
//
// The answer is the opinion of an outside service at the time it was asked. It
// is not evidence about the case and nothing here changes a finding because of
// it. "Not found" means VirusTotal has not been given the file; it does not
// mean the file is safe.
//
// The free API allows 4 requests per minute; the client spaces its requests
// accordingly and the caller applies the daily limit.
package virustotal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	DefaultBaseURL = "https://www.virustotal.com"
	// DefaultInterval keeps a free key under 4 requests per minute.
	DefaultInterval = 15500 * time.Millisecond
	maxBody         = 1 << 20
)

var (
	// ErrNotConfigured: no API key.
	ErrNotConfigured = errors.New("virustotal: no API key is configured")
	// ErrAuth: the key was refused.
	ErrAuth = errors.New("virustotal: the API key was refused")
	// ErrNotAHash: the indicator is not a hash, and nothing was sent.
	ErrNotAHash = errors.New("virustotal: not a lowercase hex MD5, SHA-1 or SHA-256")
)

// QuotaError means VirusTotal said the quota is used up.
type QuotaError struct {
	RetryAfter time.Duration
	Daily      bool
}

func (e *QuotaError) Error() string {
	if e.Daily {
		return "virustotal: daily quota used up"
	}
	return "virustotal: rate limit hit"
}

var hashRe = regexp.MustCompile(`^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$`)

// ValidHash reports whether s is a lowercase hex MD5, SHA-1 or SHA-256, and
// nothing else: this is the check that stands between the case and the network.
func ValidHash(s string) bool { return hashRe.MatchString(s) }

// HashType names the kind of a valid hash.
func HashType(s string) string {
	switch len(s) {
	case 32:
		return "md5"
	case 40:
		return "sha1"
	case 64:
		return "sha256"
	}
	return ""
}

// Result is what VirusTotal said about one hash.
type Result struct {
	// Found is false when VirusTotal has never seen the file.
	Found bool `json:"found"`

	Malicious       int `json:"malicious"`
	Suspicious      int `json:"suspicious"`
	Harmless        int `json:"harmless"`
	Undetected      int `json:"undetected"`
	Timeout         int `json:"timeout"`
	Failure         int `json:"failure"`
	TypeUnsupported int `json:"type_unsupported"`

	TypeDescription string `json:"type_description,omitempty"`
	MeaningfulName  string `json:"meaningful_name,omitempty"`
	ThreatLabel     string `json:"threat_label,omitempty"`
	Reputation      int    `json:"reputation"`
	SHA256          string `json:"sha256,omitempty"`
	FirstSubmission string `json:"first_submission,omitempty"`
	LastAnalysis    string `json:"last_analysis,omitempty"`
	Link            string `json:"link"`
}

// Engines is how many engines produced a verdict.
func (r Result) Engines() int {
	return r.Malicious + r.Suspicious + r.Harmless + r.Undetected
}

// Client is a VirusTotal API client for one key.
type Client struct {
	BaseURL  string
	Key      string
	HTTP     *http.Client
	Interval time.Duration

	mu   sync.Mutex
	last time.Time
}

// New returns a client for the key. An empty key is allowed: Lookup then
// returns ErrNotConfigured.
func New(key string) *Client {
	return &Client{BaseURL: DefaultBaseURL, Key: strings.TrimSpace(key), HTTP: &http.Client{Timeout: 30 * time.Second}, Interval: DefaultInterval}
}

// Configured reports whether there is a key. The key is never exposed.
func (c *Client) Configured() bool { return c != nil && strings.TrimSpace(c.Key) != "" }

// wait spaces requests by Interval. It returns early with the context's error.
func (c *Client) wait(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.last.IsZero() && c.Interval > 0 {
		if d := time.Until(c.last.Add(c.Interval)); d > 0 {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-t.C:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	c.last = time.Now()
	return nil
}

// Lookup asks about one hash.
func (c *Client) Lookup(ctx context.Context, hash string) (Result, error) {
	if !c.Configured() {
		return Result{}, ErrNotConfigured
	}
	if !ValidHash(hash) {
		return Result{}, ErrNotAHash
	}
	if err := c.wait(ctx); err != nil {
		return Result{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.BaseURL, "/")+"/api/v3/files/"+hash, nil)
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("x-apikey", strings.TrimSpace(c.Key))
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("virustotal: %w", scrub(err, c.Key))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return Result{}, fmt.Errorf("virustotal: reading the answer: %w", err)
	}
	link := "https://www.virustotal.com/gui/file/" + hash
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return Result{Found: false, Link: link}, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return Result{}, ErrAuth
	case http.StatusTooManyRequests:
		q := &QuotaError{RetryAfter: 60 * time.Second}
		if s := resp.Header.Get("Retry-After"); s != "" {
			if n, err := strconv.Atoi(s); err == nil && n > 0 {
				q.RetryAfter = time.Duration(n) * time.Second
			}
		}
		var e struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if json.Unmarshal(body, &e) == nil && e.Error.Code == "QuotaExceededError" {
			q.Daily = true
		}
		return Result{}, q
	default:
		return Result{}, fmt.Errorf("virustotal: HTTP %d", resp.StatusCode)
	}
	return parse(body, link)
}

// scrub removes the key from an error that happens to quote the request.
func scrub(err error, key string) error {
	if key == "" {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), key, "[key]"))
}

func parse(body []byte, link string) (Result, error) {
	var d struct {
		Data struct {
			Attributes struct {
				Stats struct {
					Malicious       int `json:"malicious"`
					Suspicious      int `json:"suspicious"`
					Harmless        int `json:"harmless"`
					Undetected      int `json:"undetected"`
					Timeout         int `json:"timeout"`
					Failure         int `json:"failure"`
					TypeUnsupported int `json:"type-unsupported"`
				} `json:"last_analysis_stats"`
				TypeDescription string `json:"type_description"`
				MeaningfulName  string `json:"meaningful_name"`
				Reputation      int    `json:"reputation"`
				SHA256          string `json:"sha256"`
				FirstSubmission int64  `json:"first_submission_date"`
				LastAnalysis    int64  `json:"last_analysis_date"`
				Threat          struct {
					Label string `json:"suggested_threat_label"`
				} `json:"popular_threat_classification"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &d); err != nil {
		return Result{}, fmt.Errorf("virustotal: the answer is not the expected JSON: %w", err)
	}
	a := d.Data.Attributes
	r := Result{Found: true, Link: link,
		Malicious: a.Stats.Malicious, Suspicious: a.Stats.Suspicious, Harmless: a.Stats.Harmless, Undetected: a.Stats.Undetected,
		Timeout: a.Stats.Timeout, Failure: a.Stats.Failure, TypeUnsupported: a.Stats.TypeUnsupported,
		TypeDescription: a.TypeDescription, MeaningfulName: a.MeaningfulName, ThreatLabel: a.Threat.Label, Reputation: a.Reputation, SHA256: strings.ToLower(a.SHA256)}
	if a.FirstSubmission > 0 {
		r.FirstSubmission = time.Unix(a.FirstSubmission, 0).UTC().Format(time.RFC3339)
	}
	if a.LastAnalysis > 0 {
		r.LastAnalysis = time.Unix(a.LastAnalysis, 0).UTC().Format(time.RFC3339)
	}
	if r.Engines() == 0 && r.SHA256 == "" {
		return Result{}, errors.New("virustotal: the answer holds no analysis")
	}
	return r, nil
}
