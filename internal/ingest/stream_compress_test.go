package ingest

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
	"tracefall/internal/parsers/mssql"
)

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
func writePackedWorker(t *testing.T, frame []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "worker")
	script := "#!/bin/sh\nprintf '%s\\n' '" + string(frame) + "' '{\"done\":true,\"coverage\":{\"records_read\":1,\"mapped\":1,\"undated\":1}}'\n"
	if err := os.WriteFile(p, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestStreamCompressedBatchPreservesGuards(t *testing.T) {
	for _, paired := range []bool{true, false} {
		b := parsers.ParseResult{Events: []model.Event{{SourceReference: "usn:128:0"}}, Raw: []model.RawEvidence{{SourceReference: "usn:128:0", Raw: "unchanged"}}}
		if !paired {
			b.Raw[0].SourceReference = "wrong"
		}
		data, _ := json.Marshal(b)
		var buf bytes.Buffer
		z := gzip.NewWriter(&buf)
		z.Write(data)
		z.Close()
		encoded, _ := json.Marshal(map[string]any{"compressed_batch": buf.Bytes()})
		var f streamFrame
		json.Unmarshal(encoded, &f)
		// Independent fake worker emits the packed frame; callback compares decoded bytes.
		path := writePackedWorker(t, encoded)
		calls := 0
		_, err := (Subprocess{Exe: path}).RunStream(context.Background(), mssql.New(), "", "unused", parsers.ParseContext{}, func(got parsers.ParseResult) error {
			calls++
			if !bytes.Equal(mustJSON(got), data) {
				t.Fatal("compressed batch changed evidence")
			}
			return nil
		})
		if paired && (err != nil || calls != 1) {
			t.Fatalf("packed stream rejected: %v calls %d", err, calls)
		}
		if !paired && (err == nil || calls != 0) {
			t.Fatalf("packed mismatch accepted: %v calls %d", err, calls)
		}
	}
}
