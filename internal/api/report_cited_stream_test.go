package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"testing"
	"time"
	"tracefall/internal/model"
)

func TestReport_CitedStreamMatchesMarshalIndent(t *testing.T) {
	cases := [][]model.Event{nil, {}, {{ID: "<>&\"\n\x00\u2028\u2029\xff", Extra: nil}}, {{ID: "a", Extra: map[string]string{}}, {ID: "a", Extra: map[string]string{"z": "\xff<&", "a": "é\t\r"}}}}
	for _, events := range cases {
		var got bytes.Buffer
		each := func(fn func(model.Event) error) error {
			for _, e := range events {
				if err := fn(e); err != nil {
					return err
				}
			}
			return nil
		}
		n, err := writeCitedJSON(context.Background(), &got, each)
		if err != nil {
			t.Fatal(err)
		}
		nonnil := append([]model.Event{}, events...)
		want, err := json.MarshalIndent(nonnil, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if n != len(events) || !bytes.Equal(got.Bytes(), want) {
			t.Fatalf("byte contract: rows=%d got=%q want=%q", n, got.Bytes(), want)
		}
	}
}

func TestReport_CitedFetchBoundAndMultiplicity(t *testing.T) {
	ids := []string{" ", " id-000 ", "id-000"}
	for i := 0; i < 1020; i++ {
		ids = append(ids, fmt.Sprintf("id-%03d", i))
	}
	ids = append(ids, "id-000", "foreign", "missing")
	calls := 0
	fetch := func(batch []string) ([]model.Event, error) {
		calls++
		if len(batch) > 500 {
			t.Fatalf("unbounded fetch: %d", len(batch))
		}
		out := []model.Event{}
		for i := len(batch) - 1; i >= 0; i-- {
			id := batch[i]
			if id == "missing" {
				continue
			}
			c := "case"
			if id == "foreign" {
				c = "other"
			}
			out = append(out, model.Event{ID: id, CaseID: c})
		}
		return out, nil
	}
	got := []string{}
	n, err := forEachReportCited(context.Background(), "case", ids, fetch, func(e model.Event) error { got = append(got, e.ID); return nil })
	if err != nil {
		t.Fatal(err)
	}
	normalized := []string{}
	for _, id := range ids {
		if id != " " {
			if id == " id-000 " {
				id = "id-000"
			}
			normalized = append(normalized, id)
		}
	}
	want := []string{}
	for start := 0; start < len(normalized); start += 500 {
		seen := map[string]bool{}
		end := start + 500
		if end > len(normalized) {
			end = len(normalized)
		}
		for _, id := range normalized[start:end] {
			if !seen[id] && id != "missing" && id != "foreign" {
				want = append(want, id)
				seen[id] = true
			}
		}
	}
	sort.Strings(want)
	if n != len(want) || fmt.Sprint(got) != fmt.Sprint(want) || calls != 3 {
		t.Fatalf("bounded/multiset mismatch rows=%d want=%d calls=%d", n, len(want), calls)
	}
}

type citedShortWriter struct{}

func (citedShortWriter) Write(p []byte) (int, error) { return 0, nil }

func TestReport_CitedStreamErrorsAndCancellation(t *testing.T) {
	each := func(fn func(model.Event) error) error { return fn(model.Event{ID: "a"}) }
	if _, err := writeCitedJSON(context.Background(), citedShortWriter{}, each); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := writeCitedJSON(ctx, io.Discard, each); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled writer succeeded: %v", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	fetch := func(ids []string) ([]model.Event, error) {
		cancel()
		return []model.Event{{ID: ids[0], CaseID: "case"}}, nil
	}
	visited := false
	if _, err := forEachReportCited(ctx, "case", []string{"a"}, fetch, func(model.Event) error { visited = true; return nil }); !errors.Is(err, context.Canceled) || visited {
		t.Fatalf("cancel guard lost: err=%v visited=%t", err, visited)
	}
	invalid := func(fn func(model.Event) error) error {
		return fn(model.Event{Timestamp: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)})
	}
	if _, err := writeCitedJSON(context.Background(), io.Discard, invalid); err == nil {
		t.Fatal("custom JSON error swallowed")
	}
	sentinel := errors.New("source failed")
	if _, err := writeCitedJSON(context.Background(), io.Discard, func(func(model.Event) error) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatal("source error swallowed")
	}
}
