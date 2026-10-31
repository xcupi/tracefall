package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
	"tracefall/internal/ingest"
	"tracefall/internal/parsers"
	"tracefall/internal/parsers/wmirepository"
	"tracefall/internal/wmirepo"
)

func TestWMIRepositoryPublicWorker(t *testing.T) {
	dir := os.Getenv("TRACEFALL_REAL_WMI_REPOSITORY")
	if dir == "" {
		t.Skip("set TRACEFALL_REAL_WMI_REPOSITORY for pinned public worker proof")
	}
	hashes := map[string]string{"INDEX.BTR": "e8ead6077adef0f76a396fd67ac927904488332cac21aa4b4f938ed3d31466c7", "OBJECTS.DATA": "00e69cf03327b57a8ab39c6807c2c51f168881d899487e0567b0652318caf232", "MAPPING1.MAP": "979bfbab082cacb7b55d5f8f5141ed4f3bd3235905f3afe246293e07c9742f1d", "MAPPING2.MAP": "8cb1d364b1291cb38ef5275fbda5fb79e2e237b33057009fcc95207571148d36", "MAPPING3.MAP": "d4df3f53fc230ff7d57d865d6f8d97233dcce97d64bf034969bcbed883f6088d"}
	ctx := parsers.ParseContext{EvidenceRoot: dir, EvidencePath: "OBJECTS.DATA"}
	for name, sha := range hashes {
		ctx.BundleFiles = append(ctx.BundleFiles, parsers.BundleFile{Role: name, Path: name, SourceFileID: "public-" + name, SHA256: sha})
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	got, err := (ingest.Subprocess{Exe: exe, MemoryMB: 4096, Timeout: time.Minute, Sandbox: ingest.FindSandbox()}).Run(wmirepository.New(), dir, filepath.Join(dir, "OBJECTS.DATA"), ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Events) != 3 || len(got.Raw) != 3 {
		t.Fatal("public worker object parity")
	}
	fields := 0
	for _, raw := range got.Raw {
		var native struct{ Object wmirepo.Instance }
		if err := json.Unmarshal([]byte(raw.Raw), &native); err != nil {
			t.Fatal(err)
		}
		fields += len(native.Object.Properties)
	}
	if fields != 26 {
		t.Fatalf("public worker property census=%d", fields)
	}
	t.Logf("isolated native public worker: objects=%d fields=%d; all5 admitted file digests pinned", len(got.Events), fields)
}
