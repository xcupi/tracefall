package evtx_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"strconv"
	"testing"
	"tracefall/internal/parsers"
	parser "tracefall/internal/parsers/evtx"
)

func TestRealStreamComplete(t *testing.T) {
	path := os.Getenv("TRACEFALL_REAL_EVTX_STREAM")
	if path == "" {
		t.Skip("TRACEFALL_REAL_EVTX_STREAM not set")
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
	expectedHash := os.Getenv("TRACEFALL_REAL_EVTX_STREAM_SHA256")
	if len(expectedHash) != 64 || hash() != expectedHash {
		t.Fatal("source hash mismatch")
	}
	defer func() {
		if hash() != expectedHash {
			t.Error("source bytes changed")
		}
	}()
	read, err := strconv.Atoi(os.Getenv("TRACEFALL_REAL_EVTX_STREAM_RECORDS"))
	if err != nil || read < 1 {
		t.Fatal("set independent positive TRACEFALL_REAL_EVTX_STREAM_RECORDS")
	}
	emitted := 0
	cov, err := parser.New().ParseStream(context.Background(), path, parsers.ParseContext{}, func(b parsers.ParseResult) error {
		emitted += len(b.Events)
		if len(b.Events) > 128 || len(b.Raw) != len(b.Events) {
			t.Fatal("unbounded/unpaired")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("stream failed: %v %+v", err, cov)
	}
	if cov.RecordsRead != read || cov.Mapped != emitted || cov.RecordsFailed != 0 || cov.ChunksFailed != 0 || cov.LimitReached {
		t.Fatalf("incomplete census: %+v emitted %d want read %d", cov, emitted, read)
	}
	t.Logf("records_read=%d mapped=%d unmapped=%d emitted=%d", cov.RecordsRead, cov.Mapped, cov.Unmapped, emitted)
}
