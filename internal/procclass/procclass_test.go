package procclass

import "testing"

func TestIsOffice(t *testing.T) {
	if !IsOffice("winword.exe") {
		t.Error("winword.exe should be classified as Office")
	}
	if IsOffice("notepad.exe") {
		t.Error("notepad.exe should not be classified as Office")
	}
}

func TestIsPowerShell(t *testing.T) {
	if !IsPowerShell("powershell.exe") || !IsPowerShell("pwsh.exe") {
		t.Error("powershell.exe and pwsh.exe should be classified as PowerShell hosts")
	}
	if IsPowerShell("cmd.exe") {
		t.Error("cmd.exe should not be classified as a PowerShell host")
	}
}

func TestIsScriptHost(t *testing.T) {
	if !IsScriptHost("mshta.exe") || !IsScriptHost("cmd.exe") {
		t.Error("mshta.exe and cmd.exe should be classified as script hosts")
	}
}

func TestHasSuspiciousPath(t *testing.T) {
	cases := map[string]bool{
		`C:\Users\jdoe\AppData\Local\Temp\update.exe`: true,
		`C:\Windows\System32\cmd.exe`:                 false,
		`C:\Program Files\Vendor\app.exe`:             false,
		`C:\ProgramData\evil.exe`:                     true,
	}
	for path, want := range cases {
		if got := HasSuspiciousPath(path); got != want {
			t.Errorf("HasSuspiciousPath(%q) = %v, want %v", path, got, want)
		}
	}
}
