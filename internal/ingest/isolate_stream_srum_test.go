package ingest

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"tracefall/internal/ese/esegen"
)

func TestSRUMWorkerCompressedBatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "SRUDB.dat")
	b := esegen.Build([]esegen.Table{{Name: "SruDbIdMapTable", Columns: []esegen.Column{{ID: 1, Name: "IdIndex", Type: esegen.Int32}}}, {Name: "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}", Columns: []esegen.Column{{ID: 1, Name: "AutoIncId", Type: esegen.Int32}}, Records: []esegen.Record{{Fixed: map[uint32][]byte{1: esegen.Le32(1)}}}}}, esegen.Options{})
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	req, _ := json.Marshal(workerRequest{Parser: "srum@1", Path: path, Stream: true})
	var out bytes.Buffer
	if err := WorkerMain(bytes.NewReader(req), &out, func(error) (string, string) { return "error", "error" }); err != nil {
		t.Fatal(err)
	}
	var f streamFrame
	if err := json.NewDecoder(&out).Decode(&f); err != nil {
		t.Fatal(err)
	}
	if len(f.CompressedBatch) == 0 {
		t.Fatalf("SRUM transport not compressed: %+v", f)
	}
}
