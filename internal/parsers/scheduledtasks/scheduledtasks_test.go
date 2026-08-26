package scheduledtasks

import (
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"

	"tracefall/internal/model"
)

func TestDetect(t *testing.T) {
	p := New()
	cases := map[string]bool{
		"Tasks/MyTask.xml":               true, // root-level Tasks dir (regression: no leading slash)
		"C/Windows/System32/Tasks/x.xml": true,
		"C/Windows/System32/tasks/x.xml": true, // case-insensitive
		"RECmd/output.csv":               false,
		"Tasks/notxml.txt":               false,
	}
	for path, want := range cases {
		if got := p.Detect(path); got != want {
			t.Errorf("Detect(%q) = %v, want %v", path, got, want)
		}
	}
}

const sampleTaskXML = `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2026-01-15T09:17:30.0000000</Date>
    <Author>CORP\jdoe</Author>
  </RegistrationInfo>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-21-111-222-333-1001</UserId>
    </Principal>
  </Principals>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Users\jdoe\AppData\Local\Temp\update.exe</Command>
      <Arguments>-silent</Arguments>
    </Exec>
  </Actions>
</Task>
`

// writeUTF16 writes content as UTF-16LE with a BOM, matching how real
// Task Scheduler XML (and KAPE's collection of it) is actually encoded.
func writeUTF16(t *testing.T, path, content string) {
	t.Helper()
	units := utf16.Encode([]rune(content))
	buf := make([]byte, 0, 2+len(units)*2)
	buf = append(buf, 0xFF, 0xFE)
	for _, u := range units {
		buf = append(buf, byte(u), byte(u>>8))
	}
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestParseUTF16(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "MicrosoftEdgeUpdateTaskUserS.xml")
	writeUTF16(t, path, sampleTaskXML)

	res, err := New().Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(res.Events))
	}
	e := res.Events[0]
	if e.EventType != model.EventScheduledTaskCreate {
		t.Errorf("event type = %q, want %q", e.EventType, model.EventScheduledTaskCreate)
	}
	if e.User != `CORP\jdoe` {
		t.Errorf("user = %q, want CORP\\jdoe (Author should be preferred over raw SID)", e.User)
	}
	if e.ProcessName != "update.exe" {
		t.Errorf("process_name = %q, want update.exe", e.ProcessName)
	}
	if e.CommandLine != `C:\Users\jdoe\AppData\Local\Temp\update.exe -silent` {
		t.Errorf("command_line = %q", e.CommandLine)
	}
	if e.Extra["task_name"] != "MicrosoftEdgeUpdateTaskUserS" {
		t.Errorf("task_name = %q", e.Extra["task_name"])
	}
}

// TestParse_Phase4RunLevelAndTaskPath covers the two new fields Phase 4A
// added: Principal/RunLevel (a genuine privilege-escalation signal when
// "HighestAvailable") and the reconstructed Task Scheduler namespace path
// (derived from where KAPE preserved the file under a "Tasks" root, since
// Parse only receives an absolute path).
func TestParse_Phase4RunLevelAndTaskPath(t *testing.T) {
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Date>2026-01-15T09:17:30.0000000</Date><Author>CORP\jdoe</Author></RegistrationInfo>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-21-111-222-333-1001</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Actions Context="Author"><Exec><Command>C:\Users\Public\bad.exe</Command></Exec></Actions>
</Task>`
	dir := t.TempDir()
	tasksDir := filepath.Join(dir, "C", "Windows", "System32", "Tasks", "Microsoft", "Windows", "UpdateOrchestrator")
	if err := os.MkdirAll(tasksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(tasksDir, "Schedule Scan.xml")
	if err := os.WriteFile(path, []byte(xml), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := New().Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(res.Events))
	}
	e := res.Events[0]
	if e.Extra["run_level"] != "HighestAvailable" {
		t.Errorf("run_level = %q, want HighestAvailable", e.Extra["run_level"])
	}
	wantPath := `\Microsoft\Windows\UpdateOrchestrator\Schedule Scan`
	if e.Extra["task_path"] != wantPath {
		t.Errorf("task_path = %q, want %q", e.Extra["task_path"], wantPath)
	}
	if e.Extra["principal_user_id"] != "S-1-5-21-111-222-333-1001" {
		t.Errorf("principal_user_id = %q", e.Extra["principal_user_id"])
	}
}

// A task with no "Tasks" segment in its path (e.g. an isolated test
// fixture, or an unusual collection layout) must still parse successfully
// and fall back to a bare "\"+taskName rather than erroring.
func TestParse_TaskPathFallsBackWithoutTasksSegment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "StandaloneTask.xml")
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Date>2026-01-15T09:17:30.0000000</Date><Author>SYSTEM</Author></RegistrationInfo>
  <Actions Context="Author"><Exec><Command>C:\Windows\System32\cleanmgr.exe</Command></Exec></Actions>
</Task>`
	if err := os.WriteFile(path, []byte(xml), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := New().Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if res.Events[0].Extra["task_path"] != `\StandaloneTask` {
		t.Errorf("task_path = %q, want \\StandaloneTask", res.Events[0].Extra["task_path"])
	}
}

func TestParseUTF8Fallback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "PlainUTF8Task.xml")
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Date>2026-01-15T10:00:00.0000000</Date><Author>SYSTEM</Author></RegistrationInfo>
  <Actions Context="Author"><Exec><Command>C:\Windows\System32\cleanmgr.exe</Command></Exec></Actions>
</Task>`
	if err := os.WriteFile(path, []byte(xml), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := New().Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Events) != 1 || res.Events[0].ProcessName != "cleanmgr.exe" {
		t.Fatalf("unexpected result: %+v", res)
	}
}
