package memory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"time"
)

const realRecoverFilescanPin = "a9b503c0421220a2338f5a8b6dee3d3ac8131aeab988eb6478754c2537931c46"

// Reads files back out of a real 2 GiB Windows 10 memory image with a real
// Volatility 3 2.28.2, inside the sandbox. Set TRACEFALL_REAL_MEMORY_IMAGE to
// the image, TRACEFALL_VOLATILITY to vol, and TRACEFALL_REAL_FILESCAN to the
// JSON that windows.filescan printed for that image (SHA-256 pinned). The
// image and symbols are not in the repository.
//
// The expected numbers are from running the same plugin by hand: of the first
// 60 runnable files outside the operating system's locations, 25 had pages in
// memory and 35 did not. One recovered DLL was also parsed by a separate
// script (struct unpacking, no PE library): machine, section names and the
// DLL flag matched the report.
func TestRealRecoverFiles(t *testing.T) {
	image, vol, scan := os.Getenv("TRACEFALL_REAL_MEMORY_IMAGE"), os.Getenv("TRACEFALL_VOLATILITY"), os.Getenv("TRACEFALL_REAL_FILESCAN")
	if image == "" || vol == "" || scan == "" {
		t.Skip("set TRACEFALL_REAL_MEMORY_IMAGE, TRACEFALL_VOLATILITY and TRACEFALL_REAL_FILESCAN to run")
	}
	raw, err := os.ReadFile(scan)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != realRecoverFilescanPin {
		t.Fatal("this is not the filescan output these counts were taken from")
	}
	rows, err := ParseRows(raw)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewRunner(Config{Vol: vol, CacheDir: t.TempDir(), Timeout: 20 * time.Minute})
	if err != nil {
		t.Skipf("no usable runner: %v", err)
	}
	avail, err := r.Plugins(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	files, note := r.Recover(context.Background(), image, rows, avail, nil)
	if note != "" || len(files) != 60 {
		t.Fatalf("note %q, %d files", note, len(files))
	}
	counts := map[string]int{}
	pe := 0
	for _, f := range files {
		counts[f.Status]++
		for _, p := range f.Parts {
			if want := int((p.Size + 4095) / 4096); p.TotalPages != want {
				t.Errorf("%s: %d pages for %d bytes, want %d", f.Name, p.TotalPages, p.Size, want)
			}
			if p.ZeroPages > p.TotalPages {
				t.Errorf("%s: %d blank pages of %d", f.Name, p.ZeroPages, p.TotalPages)
			}
			if p.Report.PE != nil {
				pe++
				if len(p.Report.PE.Sections) == 0 || p.Report.PE.Machine == "" {
					t.Errorf("%s: a PE with no sections or machine: %+v", f.Name, p.Report.PE)
				}
			}
		}
	}
	if counts[RecoveredOK] != 25 || counts[RecoveredNone] != 35 || counts[RecoveredFailed] != 0 {
		t.Errorf("outcomes %v, want 25 recovered, 35 not in memory, 0 failed", counts)
	}
	if pe == 0 {
		t.Error("no recovered part parsed as a PE")
	}
}
