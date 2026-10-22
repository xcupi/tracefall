package regf_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"tracefall/internal/regf"
)

func TestSiblingLogs_FindsTheLogsOfAHiveWhateverTheirCase(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"SOFTWARE", "SOFTWARE.LOG1", "software.log2", "SOFTWARE.LOG", "SOFTWARE.blf", "SYSTEM.LOG1", "SOFTWAREX.LOG1", "other.txt"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got := regf.SiblingLogs(filepath.Join(dir, "SOFTWARE"))
	want := []string{filepath.Join(dir, "SOFTWARE.LOG"), filepath.Join(dir, "SOFTWARE.LOG1"), filepath.Join(dir, "software.log2")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if regf.SiblingLogs(filepath.Join(dir, "missing", "SOFTWARE")) != nil {
		t.Error("a missing directory has no logs")
	}
}
