package usnjrnl_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"tracefall/internal/model"
	"tracefall/internal/ntfs/mftgen"
	"tracefall/internal/parsers"
	"tracefall/internal/parsers/usnjrnl"
)

func TestStreamBoundedParity(t *testing.T) {
	p := usnjrnl.New()
	sp, ok := any(p).(parsers.StreamingParser)
	if !ok {
		t.Fatal("USN parser lacks bounded stream")
	}
	entries := make([]mftgen.UsnEntry, 513)
	for i := range entries {
		entries[i] = mftgen.UsnEntry{FileRecord: 64, FileSequence: 2, ParentRecord: 5, Usn: uint64(i + 1), Timestamp: base, Reason: mftgen.ReasonFileCreate, FileName: "same.txt"}
	}
	path := write(t, journal(entries...))
	legacy, err := p.Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	var got parsers.ParseResult
	calls := 0
	cov, err := sp.ParseStream(context.Background(), path, parsers.ParseContext{}, func(b parsers.ParseResult) error {
		calls++
		if len(b.Events) > 128 || len(b.Events) != len(b.Raw) {
			t.Fatal("unbounded/unpaired batch")
		}
		for i, e := range b.Events {
			if e.SourceReference != b.Raw[i].SourceReference || e.Host != "" {
				t.Fatal("source pairing/attribution")
			}
		}
		got.Events = append(got.Events, b.Events...)
		got.Raw = append(got.Raw, b.Raw...)
		return nil
	})
	if err != nil || cov.RecordsRead != 513 || cov.Mapped != 513 || calls < 5 {
		t.Fatalf("coverage=%+v calls=%d err=%v", cov, calls, err)
	}
	if !reflect.DeepEqual(got, legacy) {
		t.Fatal("stream changed record fidelity")
	}
	stop := errors.New("sink stopped")
	calls = 0
	cov, err = sp.ParseStream(context.Background(), path, parsers.ParseContext{}, func(parsers.ParseResult) error { calls++; return stop })
	if !errors.Is(err, stop) || calls != 1 || cov.RecordsFailed != 0 {
		t.Fatalf("sink failure misclassified: %+v %v", cov, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = sp.ParseStream(ctx, path, parsers.ParseContext{}, func(parsers.ParseResult) error { t.Fatal("cancelled emission"); return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	_ = model.ArtifactUsnJournal
}
