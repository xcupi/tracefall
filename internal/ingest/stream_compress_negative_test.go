package ingest

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"testing"
	"tracefall/internal/parsers"
	"tracefall/internal/parsers/mssql"
)

func TestStreamRejectsCorruptOrOversizedCompressedFrames(t *testing.T) {
	for _, kind := range []string{"gzip", "crc", "json", "expansion", "mixed-terminal"} {
		t.Run(kind, func(t *testing.T) {
			data := []byte(`{"Events":[],"Raw":[]}`)
			if kind == "json" {
				data = []byte(`{`)
			}
			if kind == "expansion" {
				data = bytes.Repeat([]byte("x"), (16<<20)+1)
			}
			var buf bytes.Buffer
			z := gzip.NewWriter(&buf)
			if _, err := z.Write(data); err != nil {
				t.Fatal(err)
			}
			if err := z.Close(); err != nil {
				t.Fatal(err)
			}
			packed := buf.Bytes()
			if kind == "gzip" {
				packed = []byte("not gzip")
			}
			if kind == "crc" {
				packed[len(packed)-8] ^= 1
			}
			frame := map[string]any{"compressed_batch": packed}
			if kind == "mixed-terminal" {
				frame["done"] = true
			}
			encoded, err := json.Marshal(frame)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			_, err = (Subprocess{Exe: writePackedWorker(t, encoded)}).RunStream(context.Background(), mssql.New(), "", "unused", parsers.ParseContext{}, func(parsers.ParseResult) error { calls++; return nil })
			if err == nil || calls != 0 {
				t.Fatalf("accepted %s frame: calls=%d err=%v", kind, calls, err)
			}
		})
	}
}
