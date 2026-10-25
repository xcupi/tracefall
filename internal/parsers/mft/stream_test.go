package mft_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"tracefall/internal/ntfs/mftgen"
	"tracefall/internal/parsers"
	"tracefall/internal/parsers/mft"
)

func TestStreamBoundedParity(t *testing.T) {
	p := mft.New()
	sp, ok := any(p).(parsers.StreamingParser)
	if !ok {
		t.Fatal("MFT parser lacks bounded stream")
	}
	var files []mftgen.File
	for i := 0; i < 100; i++ {
		files = append(files, mftgen.File{RecordNumber: uint64(64 + i), SequenceNumber: 2, InUse: i%2 == 0, SI: si(), Names: []mftgen.Name{{Name: "file.txt", Namespace: 1, ParentRef: 40, ParentSeq: 1}}})
	}
	path := write(t, table(files...))
	legacy, err := p.Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	var got parsers.ParseResult
	calls := 0
	cov, err := sp.ParseStream(context.Background(), path, parsers.ParseContext{}, func(b parsers.ParseResult) error {
		calls++
		if len(b.Events) > 128 || len(b.Events) != len(b.Raw) {
			t.Fatal("batch bound/pairing")
		}
		for i, e := range b.Events {
			if e.SourceReference != b.Raw[i].SourceReference {
				t.Fatal("pairing")
			}
		}
		got.Events = append(got.Events, b.Events...)
		got.Raw = append(got.Raw, b.Raw...)
		return nil
	})
	if err != nil || calls < 4 || cov.Mapped != len(got.Events)/4 {
		t.Fatalf("coverage %+v calls %d: %v", cov, calls, err)
	}
	// Streaming adds physical-location metadata; all legacy fields and raw
	// source bytes remain identical for a valid, sequence-matching tree.
	for i := range got.Events {
		delete(got.Events[i].Extra, "mft_record_offset")
		delete(got.Events[i].Extra, "mft_record_size")
	}
	if !reflect.DeepEqual(got, legacy) {
		t.Fatal("record fidelity changed")
	}
	stop := errors.New("sink")
	cov, err = sp.ParseStream(context.Background(), path, parsers.ParseContext{}, func(parsers.ParseResult) error { return stop })
	if !errors.Is(err, stop) || cov.RecordsFailed != 0 {
		t.Fatal("sink failure", cov, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = sp.ParseStream(ctx, path, parsers.ParseContext{}, func(parsers.ParseResult) error { t.Fatal("cancelled emit"); return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func TestStreamRejectsReusedParent(t *testing.T) {
	sp, ok := any(mft.New()).(parsers.StreamingParser)
	if !ok {
		t.Fatal("MFT parser lacks bounded stream")
	}
	path := write(t, table(mftgen.File{RecordNumber: 64, SequenceNumber: 2, SI: si(), Names: []mftgen.Name{{Name: "old.txt", Namespace: 1, ParentRef: 40, ParentSeq: 9}}}))
	_, err := sp.ParseStream(context.Background(), path, parsers.ParseContext{}, func(b parsers.ParseResult) error {
		for _, e := range b.Events {
			if e.Extra["file_name"] == "old.txt" && (!strings.Contains(e.FilePath, "unresolved") || e.Extra["path_resolution"] == "") {
				t.Fatal("linked to reused parent")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
