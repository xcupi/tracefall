package scheduledtasks

import (
	"os"
	"path/filepath"
	"testing"
	"tracefall/internal/parsers"
)

func TestTaskIdentity_LocalRegistrationReading(t *testing.T) {
	var hashes []string
	for _, date := range []string{"2026-01-15T09:00:00", "2026-01-16T09:00:00"} {
		p := filepath.Join(t.TempDir(), "Tasks", "Task01")
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(`<Task><RegistrationInfo><Date>`+date+`</Date></RegistrationInfo></Task>`), 0600); err != nil {
			t.Fatal(err)
		}
		r, err := New().Parse(p)
		if err != nil {
			t.Fatal(err)
		}
		hashes = append(hashes, r.Events[0].ComputeDedupHash())
	}
	if hashes[0] == hashes[1] {
		t.Fatal("different original local registration readings collapsed after removing invented UTC")
	}
}

func TestTaskIdentity_NamespaceSurvivesEqualCommands(t *testing.T) {
	for _, date := range []string{"", "2026-01-15T09:00:00Z"} {
		t.Run(date, func(t *testing.T) {
			root := t.TempDir()
			hashes := map[string]bool{}
			for _, folder := range []string{"Group01", "Group02"} {
				p := filepath.Join(root, "Tasks", folder, "Task01")
				if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(`<Task><RegistrationInfo><Date>`+date+`</Date></RegistrationInfo><Actions><Exec><Command>cmd.exe</Command></Exec></Actions></Task>`), 0600); err != nil {
					t.Fatal(err)
				}
				r, err := New().ParseWithContext(p, parsers.ParseContext{EvidencePath: "Windows/System32/Tasks/" + folder + "/Task01"})
				if err != nil {
					t.Fatal(err)
				}
				if len(r.Events) != 1 {
					t.Fatal("missing task")
				}
				hashes[r.Events[0].ComputeDedupHash()] = true
			}
			if len(hashes) != 2 {
				t.Fatal("different Task Scheduler namespace objects collapsed")
			}
		})
	}
}
