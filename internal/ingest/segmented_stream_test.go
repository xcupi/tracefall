package ingest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tracefall/internal/parsers"
	"tracefall/internal/parsers/mssql"
)

func segLog(t *testing.T, lines int) (root, path string) {
	t.Helper()
	root = t.TempDir()
	path = filepath.Join(root, "ERRORLOG")
	var b strings.Builder
	for i := 0; i < lines; i++ {
		fmt.Fprintf(&b, "2025-01-02 03:04:05.00 Server message number %d\n", i)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0600); err != nil {
		t.Fatal(err)
	}
	return root, path
}

func selfExe(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

// The cumulative output cap is a whole-source limit. In segmented mode each
// consumed frame is durable, so only one run between frames is bounded: a
// source far larger than the cap streams to EOF with exact counts.
func TestSegmentedStreamOutputCapBoundsARunNotTheSource(t *testing.T) {
	root, path := segLog(t, 20000)
	const smallCap = 300 << 10
	count := func(ctx context.Context) (int, error) {
		n := 0
		_, err := (Subprocess{Exe: selfExe(t), MaxOutputBytes: smallCap}).RunStream(ctx, mssql.New(), root, path, parsers.ParseContext{}, func(b parsers.ParseResult) error {
			n += len(b.Events)
			return nil
		})
		return n, err
	}
	var failure *ProcessFailure
	if _, err := count(context.Background()); !errors.As(err, &failure) || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("whole-source mode must keep the cumulative cap, got %v", err)
	}
	n, err := count(WithSegmentedStream(context.Background()))
	if err != nil || n != 20000 {
		t.Fatalf("segmented mode: events=%d err=%v, want 20000 and no error", n, err)
	}
}

// The deadline of a segmented stream restarts after every consumed frame.
func TestSegmentedStreamDeadlineIsProgressBased(t *testing.T) {
	root, path := segLog(t, 2000) // 16 batches of <=128 events
	slow := func(parsers.ParseResult) error { time.Sleep(100 * time.Millisecond); return nil }
	sub := Subprocess{Exe: selfExe(t), Timeout: 600 * time.Millisecond}
	started := time.Now()
	_, err := sub.RunStream(context.Background(), mssql.New(), root, path, parsers.ParseContext{}, slow)
	var failure *ProcessFailure
	if !errors.As(err, &failure) || !strings.Contains(err.Error(), "time limit") {
		t.Fatalf("whole-source mode must keep the absolute deadline, got %v after %s", err, time.Since(started))
	}
	started = time.Now()
	cov, err := sub.RunStream(WithSegmentedStream(context.Background()), mssql.New(), root, path, parsers.ParseContext{}, slow)
	if err != nil {
		t.Fatalf("segmented mode must not hit an absolute deadline: %v", err)
	}
	if cov.RecordsRead != 2000 {
		t.Fatalf("records read = %d, want 2000", cov.RecordsRead)
	}
	if time.Since(started) <= 600*time.Millisecond {
		t.Fatalf("test did not exceed the absolute deadline (%s); it proves nothing", time.Since(started))
	}
}

// A consumer that stops making durable progress is still stopped.
func TestSegmentedStreamStallIsStopped(t *testing.T) {
	root, path := segLog(t, 2000)
	calls := 0
	_, err := (Subprocess{Exe: selfExe(t), Timeout: 300 * time.Millisecond}).RunStream(WithSegmentedStream(context.Background()), mssql.New(), root, path, parsers.ParseContext{}, func(parsers.ParseResult) error {
		calls++
		if calls == 2 {
			time.Sleep(900 * time.Millisecond) // no progress for longer than the stall limit
		}
		return nil
	})
	var failure *ProcessFailure
	if !errors.As(err, &failure) || !strings.Contains(err.Error(), "no durable progress") {
		t.Fatalf("stall must be a disclosed process failure, got %v", err)
	}
}

// Even steady progress has a (generous, configurable) ceiling.
func TestSegmentedStreamSafetyCeiling(t *testing.T) {
	root, path := segLog(t, 2000)
	_, err := (Subprocess{Exe: selfExe(t), Timeout: 5 * time.Second, SegmentedCeiling: 500 * time.Millisecond}).RunStream(WithSegmentedStream(context.Background()), mssql.New(), root, path, parsers.ParseContext{}, func(parsers.ParseResult) error {
		time.Sleep(100 * time.Millisecond)
		return nil
	})
	var failure *ProcessFailure
	if !errors.As(err, &failure) || !strings.Contains(err.Error(), "safety ceiling") {
		t.Fatalf("ceiling must be a disclosed process failure, got %v", err)
	}
}

// Analyst cancellation still wins and is reported as such, not as a stall.
func TestSegmentedStreamCancellationIsNotAStall(t *testing.T) {
	root, path := segLog(t, 2000)
	ctx, cancel := context.WithCancel(WithSegmentedStream(context.Background()))
	n := 0
	_, err := (Subprocess{Exe: selfExe(t), Timeout: 5 * time.Second}).RunStream(ctx, mssql.New(), root, path, parsers.ParseContext{}, func(parsers.ParseResult) error {
		n++
		if n == 2 {
			cancel()
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}
