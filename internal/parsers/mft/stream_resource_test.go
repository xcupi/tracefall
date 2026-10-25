package mft

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
	"tracefall/internal/ntfs"
	"tracefall/internal/ntfs/mftgen"
	"tracefall/internal/parsers"
)

func TestStreamResourceLimitsAreNotCorruptEvidence(t *testing.T) {
	times := mftgen.Times{Created: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	files := append(mftgen.SystemRecords(times), mftgen.File{RecordNumber: 64, SequenceNumber: 1, SI: times, Names: []mftgen.Name{{Name: "long-name.txt", Namespace: 1, ParentRef: 5, ParentSeq: 5}, {Name: "SHORT.TXT", Namespace: 2, ParentRef: 5, ParentSeq: 5}}})
	path := filepath.Join(t.TempDir(), "$MFT")
	if err := os.WriteFile(path, mftgen.Build(files), 0600); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"bytes", "names", "characters"} {
		t.Run(kind, func(t *testing.T) {
			p := New()
			switch kind {
			case "bytes":
				p.limits.MaxFileBytes = 1024
			case "names":
				p.limits.MaxNamesPerRecord = 1
			case "characters":
				p.limits.MaxNameChars = 7
			}
			cov, err := p.ParseStream(context.Background(), path, parsers.ParseContext{}, func(parsers.ParseResult) error { t.Fatal("limited source emitted a batch"); return nil })
			if !errors.Is(err, ntfs.ErrLimitExceeded) || !cov.LimitReached || cov.RecordsFailed != 0 {
				t.Fatalf("reader resource ceiling mislabelled as source damage: %+v %v", cov, err)
			}
		})
	}
}
