package recmd

import (
	"os"
	"path/filepath"
	"testing"

	"tracefall/internal/model"
)

func TestDetect(t *testing.T) {
	p := New()
	if !p.Detect("RECmd/20260115_RECmd_Batch_RunKeys_Output.csv") {
		t.Error("expected RECmd output file to be detected")
	}
	if p.Detect("PECmd/20260115_PECmd_Output.csv") {
		t.Error("expected PECmd output file not to be detected")
	}
}

func TestParse(t *testing.T) {
	csv := `HivePath,KeyPath,ValueName,ValueData,LastWriteTimestamp
C:\Users\jdoe\NTUSER.DAT,Software\Microsoft\Windows\CurrentVersion\Run,WindowsUpdateHelper,"C:\Users\jdoe\AppData\Local\Temp\update.exe",2026-01-15T09:16:02.0000000Z
C:\Users\jdoe\NTUSER.DAT,Software\Microsoft\Windows\CurrentVersion\Run,OneDriveSync,"""C:\Program Files\Microsoft OneDrive\OneDrive.exe"" /background",2025-11-02T08:00:00.0000000Z
`
	dir := t.TempDir()
	path := filepath.Join(dir, "20260115_RECmd_Batch_RunKeys_Output.csv")
	if err := os.WriteFile(path, []byte(csv), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := New().Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want 2", len(res.Events))
	}

	e1 := res.Events[0]
	if e1.EventType != model.EventRegistryRunKey {
		t.Errorf("event type = %q, want %q", e1.EventType, model.EventRegistryRunKey)
	}
	if e1.User != "jdoe" {
		t.Errorf("user = %q, want jdoe (parsed from HivePath)", e1.User)
	}
	if e1.ProcessName != "update.exe" {
		t.Errorf("process_name = %q, want update.exe", e1.ProcessName)
	}
	if e1.RegistryPath != `Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdateHelper` {
		t.Errorf("registry_path = %q", e1.RegistryPath)
	}

	e2 := res.Events[1]
	if e2.ProcessName != "onedrive.exe" {
		t.Errorf("process_name = %q, want onedrive.exe (quoted path with args must resolve correctly)", e2.ProcessName)
	}
}

func TestUserFromHivePath(t *testing.T) {
	cases := map[string]string{
		`C:\Users\jdoe\NTUSER.DAT`:            "jdoe",
		`C:\Windows\System32\config\SOFTWARE`: "",
		``:                                    "",
	}
	for in, want := range cases {
		if got := userFromHivePath(in); got != want {
			t.Errorf("userFromHivePath(%q) = %q, want %q", in, got, want)
		}
	}
}
