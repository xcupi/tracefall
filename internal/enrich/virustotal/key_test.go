package virustotal

import (
	"testing"
	"time"
)

func TestReplacingKeyPreservesRateLimitClock(t *testing.T) {
	c := New("old-key")
	c.last = time.Now()
	c.Interval = time.Minute
	c.BaseURL = "http://stub.invalid"
	next := c.WithKey("new-key")
	if next.Key != "new-key" || next.last != c.last || next.Interval != c.Interval || next.BaseURL != c.BaseURL || next.HTTP != c.HTTP {
		t.Fatal("key replacement reset client/limiter state")
	}
	if c.Key != "old-key" {
		t.Fatal("replacement mutated an in-flight client")
	}
	empty := (*Client)(nil).WithKey("new-key")
	if !empty.Configured() {
		t.Fatal("nil replacement unavailable")
	}
}
