package pshistory

import (
	"os"
	"path/filepath"
	"testing"
)

// The dedup rule for undated events includes the line reference, so a
// command typed twice in a PowerShell history must stay two events. Before
// the fix, identical lines collapsed into one at store time.
func TestParse_RepeatedCommandsAreDistinctIdentities(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ConsoleHost_history.txt")
	if err := os.WriteFile(p, []byte("Get-Process\nGet-Process\nwhoami\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := New().Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 3 {
		t.Fatalf("events = %d, want 3", len(res.Events))
	}
	a, b := res.Events[0], res.Events[1]
	if a.CommandLine != b.CommandLine {
		t.Fatalf("fixture broken: %q vs %q", a.CommandLine, b.CommandLine)
	}
	if a.ComputeDedupHash() == b.ComputeDedupHash() {
		t.Fatal("two identical PowerShell history lines share one identity; the second would be silently lost")
	}
}
