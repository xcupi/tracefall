package volatility

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"tracefall/internal/memory"
	"tracefall/internal/model"
)

const realFilescanPin = "a9b503c0421220a2338f5a8b6dee3d3ac8131aeab988eb6478754c2537931c46"

// The JSON that windows.filescan printed for a real Windows 10 memory image
// (Volatility 3 2.28.2, -r json). Set TRACEFALL_REAL_FILESCAN to that file to
// run. The image and the output are not in the repository; the output's
// SHA-256 is pinned. The expected counts come from a separate pass over the
// same JSON written in another language, using the same stated rules: 5577
// rows; 90 listed (distinct, runnable/document/archive/data types outside
// operating-system and installed-software locations); 2080 in those
// locations; 2880 of other types; 512 whose names are pool garbage.
func TestRealFilescan(t *testing.T) {
	path := os.Getenv("TRACEFALL_REAL_FILESCAN")
	if path == "" {
		t.Skip("set TRACEFALL_REAL_FILESCAN to real windows.filescan JSON output to run")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != realFilescanPin {
		t.Fatal("this is not the output these counts were taken from")
	}
	rows, err := memory.ParseRows(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 5577 {
		t.Fatalf("rows = %d, want 5577", len(rows))
	}
	a := baseAnalysis()
	a.Plugins = append(a.Plugins, memory.PluginResult{Logical: "filescan", Plugin: "windows.filescan.FileScan", Status: memory.StatusOK, Rows: rows})
	evs := parseAll(t, a)

	files := byType(evs, model.EventMemoryFile)
	if len(files) != 90 {
		t.Errorf("listed %d file objects, want 90", len(files))
	}
	snap := byType(evs, model.EventMemorySnapshot)[0]
	want := "listed 90; not listed: 2080 in operating-system or installed-software locations, 2880 of other types, 512 unreadable names"
	if snap.Extra["file_objects"] != want {
		t.Errorf("file_objects = %q\nwant         %q", snap.Extra["file_objects"], want)
	}
	seen := map[string]bool{}
	for _, f := range files {
		l := strings.ToLower(f.FilePath)
		if seen[l] {
			t.Errorf("%s listed twice", f.FilePath)
		}
		seen[l] = true
		if !strings.HasPrefix(f.FilePath, `\`) || strings.ContainsRune(f.FilePath, 0xFFFF) {
			t.Errorf("implausible name %q", f.FilePath)
		}
	}
}
