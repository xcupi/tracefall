package scheduledtasks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeTask_ConfigurationRetention(t *testing.T) {
	const text = `<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Principals><Principal id="p1"><GroupId>S-1-5-32-545</GroupId><LogonType>Group</LogonType><RunLevel>HighestAvailable</RunLevel></Principal><Principal id="p2"><UserId>alice</UserId></Principal></Principals><Actions Context="p1"><Exec><Command>cmd.exe</Command><Arguments>/c echo first</Arguments><WorkingDirectory>C:\Work</WorkingDirectory></Exec><Exec><Command>second.exe</Command></Exec><ComHandler><ClassId>{00000000-0000-0000-0000-000000000001}</ClassId><Data>retained</Data></ComHandler></Actions></Task>`
	p := filepath.Join(t.TempDir(), "Task01.v2")
	if err := os.WriteFile(p, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := New().Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Events) != 1 {
		t.Fatalf("lost undated configuration: %+v", r)
	}
	e := r.Events[0]
	if !e.Timestamp.IsZero() {
		t.Fatal("undated configuration was dated")
	}
	if e.Extra["task_name"] != "Task01.v2" {
		t.Errorf("lost native task name: %v", e.Extra)
	}
	for _, v := range []string{"second.exe", "WorkingDirectory", "ComHandler"} {
		if !strings.Contains(e.Extra["task_actions_xml"], v) {
			t.Errorf("lost action %s", v)
		}
	}
	for _, v := range []string{"GroupId", "LogonType", "p2"} {
		if !strings.Contains(e.Extra["task_principals_xml"], v) {
			t.Errorf("lost principal %s", v)
		}
	}
	if e.Extra["evidence_kind"] != "task_configuration" || !strings.Contains(e.Extra["evidence_meaning"], "not execution") {
		t.Errorf("configuration meaning not explicit: %v", e.Extra)
	}
	if len(r.Raw) != 1 || r.Raw[0].Raw != text {
		t.Fatal("full task XML not retained")
	}
}

func TestNativeTask_DetectExtensionless(t *testing.T) {
	for _, p := range []string{"Tasks/Task01", "Windows/System32/Tasks/Microsoft/Task01", `Windows\System32\Tasks\Task01`} {
		if !New().Detect(p) {
			t.Errorf("native task not discovered: %s", p)
		}
	}
}

func TestNativeTask_RejectNonTaskXML(t *testing.T) {
	p := filepath.Join(t.TempDir(), "Task01.xml")
	if err := os.WriteFile(p, []byte(`<Document><Actions/></Document>`), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := New().Parse(p)
	if err == nil && len(r.Events) > 0 {
		t.Fatal("non-task XML emitted a task configuration")
	}
}
