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

// TestParse_Phase4RegistryPersistenceClassification confirms non-Run-key
// persistence locations (Winlogon, IFEO, AppInit_DLLs, service ImagePath)
// are classified as EventRegistryPersistence with the specific kind
// recorded, while an unrecognized key path falls back to the Phase 1
// behavior (EventRegistryRunKey) rather than being dropped -- this
// parser's input is already scoped by RECmd's own batch definition, so a
// row this classifier doesn't specifically recognize is still real
// evidence, not noise (see evtxcsv's broader, unscoped Sysmon registry
// stream for the contrasting case where unrecognized rows ARE dropped).
func TestParse_Phase4RegistryPersistenceClassification(t *testing.T) {
	csv := `HivePath,KeyPath,ValueName,ValueData,LastWriteTimestamp
C:\Windows\System32\config\SOFTWARE,Software\Microsoft\Windows NT\CurrentVersion\Winlogon,Shell,"explorer.exe, C:\Users\Public\bad.exe",2026-01-15T09:16:05.0000000Z
C:\Windows\System32\config\SOFTWARE,Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe,Debugger,"C:\Windows\System32\cmd.exe",2026-01-15T09:16:10.0000000Z
C:\Windows\System32\config\SYSTEM,System\CurrentControlSet\Services\WeirdSvc,ImagePath,"C:\Users\Public\weirdsvc.exe",2026-01-15T09:16:15.0000000Z
C:\Windows\System32\config\SOFTWARE,Software\SomeVendor\App\Config,LastRunVersion,"1.2.3",2026-01-15T09:16:20.0000000Z
`
	dir := t.TempDir()
	path := filepath.Join(dir, "20260115_RECmd_Batch_Output.csv")
	if err := os.WriteFile(path, []byte(csv), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := New().Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Events) != 4 {
		t.Fatalf("got %d events, want 4", len(res.Events))
	}

	winlogon := res.Events[0]
	if winlogon.EventType != model.EventRegistryPersistence || winlogon.Extra["registry_persistence_type"] != "winlogon" {
		t.Errorf("event 0: type=%q kind=%q, want %q/winlogon", winlogon.EventType, winlogon.Extra["registry_persistence_type"], model.EventRegistryPersistence)
	}

	ifeo := res.Events[1]
	if ifeo.EventType != model.EventRegistryPersistence || ifeo.Extra["registry_persistence_type"] != "ifeo" {
		t.Errorf("event 1: type=%q kind=%q, want %q/ifeo", ifeo.EventType, ifeo.Extra["registry_persistence_type"], model.EventRegistryPersistence)
	}

	svc := res.Events[2]
	if svc.EventType != model.EventRegistryPersistence || svc.Extra["registry_persistence_type"] != "service_image_path" {
		t.Errorf("event 2: type=%q kind=%q, want %q/service_image_path", svc.EventType, svc.Extra["registry_persistence_type"], model.EventRegistryPersistence)
	}

	unrecognized := res.Events[3]
	if unrecognized.EventType != model.EventRegistryRunKey {
		t.Errorf("event 3 (unrecognized key) type = %q, want fallback %q", unrecognized.EventType, model.EventRegistryRunKey)
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
