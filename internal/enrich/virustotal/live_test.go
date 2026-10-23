package virustotal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"time"
)

// TestLive_RealVirusTotal talks to the real service. It runs only when
// TRACEFALL_VT_API_KEY is set, makes two requests (a free key allows 4 a
// minute) and sends two hashes: the EICAR test file's, which every engine
// knows, and one of a string nobody has uploaded.
func TestLive_RealVirusTotal(t *testing.T) {
	key := os.Getenv("TRACEFALL_VT_API_KEY")
	if key == "" {
		t.Skip("TRACEFALL_VT_API_KEY not set")
	}
	c := New(key)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	const eicar = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" // sha256 of the EICAR test file
	r, err := c.Lookup(ctx, eicar)
	if err != nil {
		t.Fatalf("EICAR: %v", err)
	}
	t.Logf("EICAR: found=%v malicious=%d suspicious=%d harmless=%d undetected=%d engines=%d type=%q name=%q label=%q first=%s last=%s",
		r.Found, r.Malicious, r.Suspicious, r.Harmless, r.Undetected, r.Engines(), r.TypeDescription, r.MeaningfulName, r.ThreatLabel, r.FirstSubmission, r.LastAnalysis)
	if !r.Found || r.Malicious < 10 || r.SHA256 != eicar || r.Link == "" {
		t.Errorf("the EICAR file should be known and widely detected: %+v", r)
	}

	sum := sha256.Sum256([]byte("tracefall live test: a string that was never uploaded " + time.Now().UTC().Format(time.RFC3339Nano)))
	unknown := hex.EncodeToString(sum[:])
	r2, err := c.Lookup(ctx, unknown)
	if err != nil {
		t.Fatalf("unknown hash: %v", err)
	}
	t.Logf("unknown: found=%v", r2.Found)
	if r2.Found {
		t.Errorf("a hash of a never-uploaded string was reported as known: %+v", r2)
	}
}
