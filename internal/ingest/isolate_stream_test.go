package ingest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
	"tracefall/internal/parsers"
	"tracefall/internal/parsers/mssql"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "parse-worker" {
		out := os.Stdout
		os.Stdout = os.Stderr
		if err := WorkerMain(os.Stdin, out, func(error) (string, string) { return "parse_error", "parse failed" }); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestStreamStampsEvidence(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "ERRORLOG")
	if err := os.WriteFile(path, []byte("2025-01-02 03:04:05.00 Server message\n"), 0600); err != nil {
		t.Fatal(err)
	}
	n := 0
	_, err := ParseFileStream(context.Background(), "case01", "collection01", "source01", root, "ERRORLOG", mssql.New(), parsers.ParseContext{}, func(b ParsedFile) error {
		for i, e := range b.Events {
			n++
			if e.ID == "" || e.RawEvidenceID != b.Raw[i].ID || e.CaseID != "case01" || e.CollectionID != "collection01" || e.SourceFileID != "source01" || b.Raw[i].SourceFileID != "source01" || e.FilePath != "ERRORLOG" {
				t.Fatalf("lost identity: %+v", e)
			}
		}
		return nil
	})
	if err != nil || n != 1 {
		t.Fatalf("emitted=%d err=%v", n, err)
	}
}

func TestSubprocessStreamParity(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "ERRORLOG")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 300; i++ {
		fmt.Fprintln(f, "2025-01-02 03:04:05.00 Server message")
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	cov, err := (Subprocess{Exe: exe}).RunStream(context.Background(), mssql.New(), root, path, parsers.ParseContext{}, func(b parsers.ParseResult) error {
		if len(b.Events) > 128 {
			t.Fatal("unbounded batch")
		}
		n += len(b.Events)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 300 || cov.RecordsRead != 300 {
		t.Fatalf("got emitted=%d coverage=%+v", n, cov)
	}
}

func TestSubprocessStreamGarbledIsProcessFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "worker")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf 'garbage\\n'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	_, err := (Subprocess{Exe: path}).RunStream(context.Background(), mssql.New(), "", "unused", parsers.ParseContext{}, func(parsers.ParseResult) error { return nil })
	var failure *ProcessFailure
	if !errors.As(err, &failure) {
		t.Fatalf("garbled protocol must be a worker failure, got %T: %v", err, err)
	}
}

func TestSubprocessStreamStopsForConsumerAndOutputBudget(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "ERRORLOG")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 300; i++ {
		fmt.Fprintln(file, "2025-01-02 03:04:05.00 Server message")
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	stop := errors.New("consumer stopped")
	calls := 0
	_, err = (Subprocess{Exe: exe}).RunStream(context.Background(), mssql.New(), root, path, parsers.ParseContext{}, func(parsers.ParseResult) error { calls++; return stop })
	if !errors.Is(err, stop) || calls != 1 {
		t.Fatalf("consumer cancellation err=%v calls=%d", err, calls)
	}
	_, err = (Subprocess{Exe: exe, MaxOutputBytes: 1024}).RunStream(context.Background(), mssql.New(), root, path, parsers.ParseContext{}, func(parsers.ParseResult) error { return nil })
	var failure *ProcessFailure
	if !errors.As(err, &failure) {
		t.Fatalf("output cap must fail worker: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = (Subprocess{Exe: exe}).RunStream(ctx, mssql.New(), root, path, parsers.ParseContext{}, func(parsers.ParseResult) error { t.Fatal("cancelled parse emitted"); return nil })
	if err == nil {
		t.Fatal("accepted cancelled stream")
	}
}

func TestSubprocessStreamBackpressure(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "ERRORLOG")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1000; i++ {
		fmt.Fprintln(f, "2025-01-02 03:04:05.00 Server message")
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	stop := errors.New("consumer stopped")
	go func() {
		_, err := (Subprocess{Exe: exe}).RunStream(ctx, mssql.New(), root, path, parsers.ParseContext{}, func(parsers.ParseResult) error { close(entered); <-release; return stop })
		done <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("sink was never called")
	}
	select {
	case err := <-done:
		t.Fatalf("producer completed while sink blocked: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	close(release)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("consumer cancellation was ignored")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("cancelled worker did not stop")
	}
}
