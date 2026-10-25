package srum

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"tracefall/internal/ese/esegen"
	"tracefall/internal/parsers"
)

func TestStreamBoundedParity(t *testing.T) {
	rows := make([]esegen.Record, 513)
	for i := range rows {
		rows[i] = appRow(i+1, ole(t0), 1, 5, 1, 2, 3, 4, 5)
	}
	table := appTable(rows...)
	table.LeafCapacity = 16
	path := write(t, []esegen.Table{standardIDs(), table}, esegen.Options{})
	legacy, err := New().Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	sp, ok := any(New()).(parsers.StreamingParser)
	if !ok {
		t.Fatal("SRUM import has no bounded streaming path")
	}
	var got parsers.ParseResult
	batches := 0
	cov, err := sp.ParseStream(context.Background(), path, parsers.ParseContext{}, func(b parsers.ParseResult) error {
		batches++
		if len(b.Events) > 128 || len(b.Events) != len(b.Raw) {
			t.Fatalf("unbounded/unpaired batch: %d/%d", len(b.Events), len(b.Raw))
		}
		got.Events = append(got.Events, b.Events...)
		got.Raw = append(got.Raw, b.Raw...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if batches < 5 || !reflect.DeepEqual(got.Events, legacy.Events) || !reflect.DeepEqual(got.Raw, legacy.Raw) {
		t.Fatal("stream differs from legacy or does not batch")
	}
	if cov.Mapped != 513 || cov.RecordsRead != 513 || cov.RecordsFailed != 0 {
		t.Fatalf("coverage: %+v", cov)
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
		t.Fatalf("cancellation: %v", err)
	}
}
