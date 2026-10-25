package mssql

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"tracefall/internal/parsers"
	"unicode/utf16"
)

func TestStreamMatchesLegacy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ERRORLOG")
	text := "2025-01-02 03:04:05.00 Server Microsoft SQL Server\r\n2025-01-02 03:04:06.00 Logon Login failed for user 'alice'. [CLIENT: 203.0.113.5]\r\n detail\r\n2025-01-02 03:04:07.00 Server Server name is 'host01\\INSTANCE'.\r\n"
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	pc := parsers.ParseContext{EvidencePath: "logs/ERRORLOG"}
	want, err := New().ParseWithContext(path, pc)
	if err != nil {
		t.Fatal(err)
	}
	var got parsers.ParseResult
	cov, err := New().ParseStream(context.Background(), path, pc, func(b parsers.ParseResult) error {
		got.Events = append(got.Events, b.Events...)
		got.Raw = append(got.Raw, b.Raw...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stream mismatch: got %d events/%d raw; want %d/%d", len(got.Events), len(got.Raw), len(want.Events), len(want.Raw))
	}
	if cov.RecordsRead != 3 || cov.Mapped != 3 || cov.Undated != 3 || cov.LimitReached {
		t.Fatalf("coverage: %+v", cov)
	}
}

func TestStreamLargeFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ERRORLOG")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	// Independent generator: >64 MiB without a giant fixture or allocation.
	line := "2025-01-02 03:04:05.00 Server " + strings.Repeat("x", 1000) + "\n"
	const count = 66000
	for i := 0; i < count; i++ {
		if _, err = f.WriteString(line); err != nil {
			t.Fatal(err)
		}
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	n := 0
	cov, err := New().ParseStream(context.Background(), path, parsers.ParseContext{}, func(b parsers.ParseResult) error {
		if len(b.Events) > 128 {
			t.Fatalf("unbounded batch: %d", len(b.Events))
		}
		n += len(b.Events)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != count || cov.RecordsRead != count {
		t.Fatalf("got %d emitted/%d read, want %d", n, cov.RecordsRead, count)
	}
}

func TestStreamMalformedIsNotLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ERRORLOG")
	if err := os.WriteFile(path, []byte{255, 254, 0}, 0600); err != nil {
		t.Fatal(err)
	}
	cov, err := New().ParseStream(context.Background(), path, parsers.ParseContext{}, func(parsers.ParseResult) error { return nil })
	if err == nil || cov.LimitReached || cov.RecordsFailed != 1 {
		t.Fatalf("malformed encoding must not masquerade as resource limit: error=%v coverage=%+v", err, cov)
	}
}

func TestStreamEncodingParity(t *testing.T) {
	for _, wide := range []bool{false, true} {
		for _, agent := range []bool{false, true} {
			text := "2025-01-02 03:04:05Z Server message 😀\n\ufeffcontinuation\n2025-01-02 03:04:06+07:00 Server Server name is 'host01'."
			if agent {
				text = "2025-01-02 03:04:05 - ? [100] message 😀\n\ufeffcontinuation\n2025-01-02 03:04:06 - + [101] final"
			}
			data := []byte(text)
			if wide {
				data = []byte{255, 254}
				for _, u := range utf16.Encode([]rune(text)) {
					data = binary.LittleEndian.AppendUint16(data, u)
				}
			}
			path := filepath.Join(t.TempDir(), "log")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			p := Parser{Agent: agent}
			want, err := p.Parse(path)
			if err != nil {
				t.Fatal(err)
			}
			var got parsers.ParseResult
			_, err = p.ParseStream(context.Background(), path, parsers.ParseContext{}, func(b parsers.ParseResult) error {
				got.Events = append(got.Events, b.Events...)
				got.Raw = append(got.Raw, b.Raw...)
				return nil
			})
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("encoding parity wide=%v agent=%v err=%v", wide, agent, err)
			}
		}
	}
}

func TestStreamSinkFailureIsNotDamagedEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ERRORLOG")
	text := strings.Repeat("2025-01-02 03:04:05.00 Server message\n", 300)
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	stop := errors.New("consumer stopped")
	calls := 0
	cov, err := New().ParseStream(context.Background(), path, parsers.ParseContext{}, func(parsers.ParseResult) error { calls++; return stop })
	if !errors.Is(err, stop) || calls != 1 || cov.RecordsFailed != 0 || len(cov.Notes) == 0 {
		t.Fatalf("sink failure error=%v calls=%d coverage=%+v", err, calls, cov)
	}
}

func TestStreamCancellationAndRecordBounds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ERRORLOG")
	if err := os.WriteFile(path, []byte("2025-01-02 03:04:05.00 Server "+strings.Repeat("x", streamRecordBytes)), 0600); err != nil {
		t.Fatal(err)
	}
	cov, err := New().ParseStream(context.Background(), path, parsers.ParseContext{}, func(parsers.ParseResult) error { t.Fatal("oversized record emitted"); return nil })
	if err == nil || !cov.LimitReached {
		t.Fatalf("record limit error=%v coverage=%+v", err, cov)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cov, err = New().ParseStream(ctx, path, parsers.ParseContext{}, func(parsers.ParseResult) error { t.Fatal("cancelled record emitted"); return nil })
	if !errors.Is(err, context.Canceled) || !cov.LimitReached {
		t.Fatalf("cancel error=%v coverage=%+v", err, cov)
	}
}

func TestStreamRecordExactBoundary(t *testing.T) {
	prefix := "2025-01-02 03:04:05.00 Server "
	for _, extra := range []int{0, 1} {
		path := filepath.Join(t.TempDir(), "ERRORLOG")
		data := prefix + strings.Repeat("x", streamRecordBytes-len(prefix)-1+extra) + "\n" + prefix + "next\n"
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		emitted := 0
		cov, err := New().ParseStream(context.Background(), path, parsers.ParseContext{}, func(b parsers.ParseResult) error { emitted += len(b.Events); return nil })
		if extra == 0 && (err != nil || emitted != 2) {
			t.Fatalf("exact boundary: error=%v emitted=%d", err, emitted)
		}
		if extra == 1 && (err == nil || emitted != 0 || !cov.LimitReached) {
			t.Fatalf("over boundary: error=%v emitted=%d coverage=%+v", err, emitted, cov)
		}
	}
}
