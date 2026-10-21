package scheduledtasks

import (
	"os"
	"path/filepath"
	"testing"

	"tracefall/internal/parsers"
)

const minimalTask = `<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Actions><Exec><Command>C:\Tools\run.exe</Command></Exec></Actions>
</Task>`

// The task's namespace path comes from the evidence-relative path. The
// server's absolute path depends on where the evidence was stored and must
// neither reach the event nor change its identity.
func TestParse_TaskPathUsesTheEvidencePathNotTheServerPath(t *testing.T) {
	write := func(root string) string {
		p := filepath.Join(root, "x", "Tasks", "decoy", "Vendor", "Nightly Job")
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(minimalTask), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ctx := parsers.ParseContext{EvidencePath: "Windows/System32/Tasks/Vendor/Nightly Job"}
	var paths []string
	for i := 0; i < 2; i++ {
		res, err := New().ParseWithContext(write(t.TempDir()), ctx)
		if err != nil || len(res.Events) != 1 {
			t.Fatalf("err=%v events=%d", err, len(res.Events))
		}
		paths = append(paths, res.Events[0].Extra["task_path"])
	}
	want := `\Vendor\Nightly Job`
	if paths[0] != want || paths[1] != want {
		t.Fatalf("task_path = %q / %q, want %q regardless of the storage location", paths[0], paths[1], want)
	}
	// Without a context only the task's own name is known.
	res, err := New().Parse(write(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Events[0].Extra["task_path"]; got != `\Nightly Job` {
		t.Fatalf("no context: task_path = %q, want only the task name", got)
	}
}
