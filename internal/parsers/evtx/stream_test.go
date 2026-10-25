package evtx_test

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	rawevtx "tracefall/internal/evtx"
	"tracefall/internal/evtx/evtxgen"
	"tracefall/internal/parsers"
	parser "tracefall/internal/parsers/evtx"
)

func TestStreamBoundsDecodedBatchBytes(t *testing.T) {
	rows := make([]evtxgen.Event, 140)
	for i := range rows {
		rows[i] = ev("Security", "Microsoft-Windows-Security-Auditing", 4624, map[string]string{"TargetUserName": "alice", "Details": strings.Repeat("a", 16000)})
		rows[i].RecordID = uint64(i + 1)
	}
	path := writeLog(t, rows)
	count := 0
	_, err := parser.New().ParseStream(context.Background(), path, parsers.ParseContext{}, func(b parsers.ParseResult) error {
		total := 0
		for _, r := range b.Raw {
			total += len(r.Raw)
		}
		if total > 1<<20 {
			t.Fatalf("decoded batch retains %d raw bytes", total)
		}
		count += len(b.Events)
		return nil
	})
	if err != nil || count != len(rows) {
		t.Fatal(err, count)
	}
}

func TestStreamRejectsBrokenRecordSignature(t *testing.T) {
	path := writeLog(t, []evtxgen.Event{ev("Security", "Microsoft-Windows-Security-Auditing", 4624, map[string]string{"TargetUserName": "alice"})})
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[4096+512] = 0
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	cov, err := parser.New().ParseStream(context.Background(), path, parsers.ParseContext{}, func(parsers.ParseResult) error { return nil })
	if !errors.Is(err, rawevtx.ErrCorrupt) || cov.RecordsFailed == 0 {
		t.Fatalf("broken record framing certified complete: %v %+v", err, cov)
	}
}

func TestStreamAccountsForZeroPreallocatedChunks(t *testing.T) {
	path := writeLog(t, []evtxgen.Event{ev("Security", "Microsoft-Windows-Security-Auditing", 4624, map[string]string{"TargetUserName": "alice"})})
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write(make([]byte, 65536)); err != nil {
		t.Fatal(err)
	}
	f.Close()
	cov, err := parser.New().ParseStream(context.Background(), path, parsers.ParseContext{}, func(parsers.ParseResult) error { return nil })
	if err != nil || cov.RecordsRead != 1 || cov.ChunksFailed != 0 || !strings.Contains(strings.Join(cov.Notes, ";"), "1 zero-filled preallocated chunks") {
		t.Fatalf("preallocation not accounted: %v %+v", err, cov)
	}
}

func TestStreamCountsPhysicalChunksBeyondHeaderClaim(t *testing.T) {
	first := ev("Security", "Microsoft-Windows-Security-Auditing", 4624, map[string]string{"TargetUserName": "alice"})
	path := writeLog(t, []evtxgen.Event{first})
	first.RecordID = 2
	data := evtxgen.Build([]evtxgen.Event{first})
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write(data[4096:]); err != nil {
		t.Fatal(err)
	}
	f.Close()
	count := 0
	cov, err := parser.New().ParseStream(context.Background(), path, parsers.ParseContext{}, func(b parsers.ParseResult) error { count += len(b.Events); return nil })
	if err != nil || cov.RecordsRead != 2 || count != 2 {
		t.Fatalf("physical records hidden by header claim: %v %+v emitted=%d", err, cov, count)
	}
}

func TestStreamRejectsPartialChunk(t *testing.T) {
	path := writeLog(t, []evtxgen.Event{ev("Security", "Microsoft-Windows-Security-Auditing", 4624, map[string]string{"TargetUserName": "alice"})})
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	f.Close()
	_, err = parser.New().ParseStream(context.Background(), path, parsers.ParseContext{}, func(parsers.ParseResult) error { return nil })
	if !errors.Is(err, rawevtx.ErrCorrupt) {
		t.Fatalf("partial physical chunk certified complete: %v", err)
	}
}

func TestStreamBoundedParity(t *testing.T) {
	rows := make([]evtxgen.Event, 513)
	for i := range rows {
		rows[i] = ev("Security", "Microsoft-Windows-Security-Auditing", 4624, map[string]string{"TargetUserName": "alice"})
		rows[i].RecordID = uint64(i + 1)
	}
	path := writeLog(t, rows)
	legacy, err := parser.New().Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	sp, ok := any(parser.New()).(parsers.StreamingParser)
	if !ok {
		t.Fatal("EVTX import has no bounded streaming path")
	}
	var got parsers.ParseResult
	batches := 0
	cov, err := sp.ParseStream(context.Background(), path, parsers.ParseContext{}, func(b parsers.ParseResult) error {
		batches++
		if len(b.Events) > 128 || len(b.Events) != len(b.Raw) {
			t.Fatal("unbounded/unpaired batch")
		}
		got.Events = append(got.Events, b.Events...)
		got.Raw = append(got.Raw, b.Raw...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if batches < 5 || !reflect.DeepEqual(got.Events, legacy.Events) || !reflect.DeepEqual(got.Raw, legacy.Raw) {
		t.Fatal("stream not equivalent and bounded")
	}
	if cov.RecordsRead != 513 || cov.Mapped != 513 || cov.RecordsFailed != 0 {
		t.Fatalf("coverage %+v", cov)
	}
	stop := errors.New("sink stopped")
	cov, err = sp.ParseStream(context.Background(), path, parsers.ParseContext{}, func(parsers.ParseResult) error { return stop })
	if !errors.Is(err, stop) || cov.RecordsFailed != 0 {
		t.Fatalf("sink classified as evidence failure: %v %+v", err, cov)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = sp.ParseStream(ctx, path, parsers.ParseContext{}, func(parsers.ParseResult) error { t.Fatal("cancelled sink called"); return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation %v", err)
	}
}
