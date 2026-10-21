package scheduledtasks

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParse_AuthorThatIsAResourceReferenceIsNotAUser(t *testing.T) {
	xml := `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>$(@%SystemRoot%\system32\example.dll,-101)</Author></RegistrationInfo>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId></Principal></Principals>
  <Actions><Exec><Command>%windir%\system32\example.exe</Command></Exec></Actions>
</Task>`
	dir := filepath.Join(t.TempDir(), "Tasks", "Vendor")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(dir, "Example Task")
	if err := os.WriteFile(f, []byte(xml), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := New().Parse(f)
	if err != nil || len(res.Events) != 1 {
		t.Fatalf("err=%v events=%d", err, len(res.Events))
	}
	if got := res.Events[0].User; got != "S-1-5-18" {
		t.Errorf("user = %q, want the principal SID, not a resource reference", got)
	}
}
