package srum

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"strconv"
	"testing"
	"tracefall/internal/parsers"
)

func TestRealStreamComplete(t *testing.T) {
	path := os.Getenv("TRACEFALL_REAL_SRUM_STREAM")
	if path == "" {
		t.Skip("TRACEFALL_REAL_SRUM_STREAM not set")
	}
	hash := func() string {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		h := sha256.New()
		if _, err = io.Copy(h, f); err != nil {
			t.Fatal(err)
		}
		return fmt.Sprintf("%x", h.Sum(nil))
	}
	expectedHash := os.Getenv("TRACEFALL_REAL_SRUM_STREAM_SHA256")
	if len(expectedHash) != 64 || hash() != expectedHash {
		t.Fatal("source hash mismatch")
	}
	defer func() {
		if hash() != expectedHash {
			t.Error("source bytes changed")
		}
	}()
	expected := func(env string) int {
		n, err := strconv.Atoi(os.Getenv(env))
		if err != nil || n < 1 {
			t.Fatalf("set positive independent %s", env)
		}
		return n
	}
	read, mapped := expected("TRACEFALL_REAL_SRUM_STREAM_RECORDS"), expected("TRACEFALL_REAL_SRUM_STREAM_MAPPED")
	emitted := 0
	cov, err := New().ParseStream(context.Background(), path, parsers.ParseContext{}, func(b parsers.ParseResult) error {
		emitted += len(b.Events)
		if len(b.Events) > 128 || len(b.Raw) != len(b.Events) {
			t.Fatal("unbounded/unpaired")
		}
		for i, e := range b.Events {
			if e.SourceReference == "" || e.SourceReference != b.Raw[i].SourceReference {
				t.Fatal("reference mismatch")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("stream failed: %v %+v", err, cov)
	}
	if cov.RecordsRead != read || cov.Mapped != mapped || emitted != mapped || cov.RecordsFailed != 0 || cov.LimitReached {
		t.Fatalf("incomplete census: %+v emitted %d want %d/%d", cov, emitted, read, mapped)
	}
	t.Logf("records_read=%d mapped=%d unmapped=%d emitted=%d", cov.RecordsRead, cov.Mapped, cov.Unmapped, emitted)
}
