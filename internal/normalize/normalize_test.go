package normalize

import "testing"

func TestTimestamp(t *testing.T) {
	cases := []struct {
		in    string
		valid bool
	}{
		{"2026-01-15T09:14:47.0000000Z", true},
		{"2026-01-15T09:14:47.123", true}, // Task Scheduler style, no offset
		{"2026-01-15T09:14:47Z", true},    // RFC3339
		{"2026-01-15 09:14:47", true},     // space-separated
		{"", false},
		{"not-a-time", false},
	}
	for _, c := range cases {
		got, ok := Timestamp(c.in)
		if ok != c.valid {
			t.Errorf("Timestamp(%q) valid=%v, want %v", c.in, ok, c.valid)
			continue
		}
		if ok && got.Location().String() != "UTC" {
			t.Errorf("Timestamp(%q) = %v, want UTC location", c.in, got)
		}
	}
}

func TestProcessName(t *testing.T) {
	cases := map[string]string{
		`C:\Windows\System32\cmd.exe`:                                 "cmd.exe",
		`C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE`: "winword.exe",
		``: "",
	}
	for in, want := range cases {
		if got := ProcessName(in); got != want {
			t.Errorf("ProcessName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExecutableFromCommandLine(t *testing.T) {
	cases := map[string]string{
		`"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background`: "onedrive.exe",
		`C:\Windows\System32\cmd.exe /c dir`:                             "cmd.exe",
		`powershell.exe -nop -enc AAAA`:                                  "powershell.exe",
	}
	for in, want := range cases {
		if got := ExecutableFromCommandLine(in); got != want {
			t.Errorf("ExecutableFromCommandLine(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHost(t *testing.T) {
	if got := Host(" wkstn-042 "); got != "WKSTN-042" {
		t.Errorf("Host() = %q, want WKSTN-042", got)
	}
}

func TestUser(t *testing.T) {
	if got := User("-"); got != "" {
		t.Errorf("User(%q) = %q, want empty", "-", got)
	}
	if got := User("jdoe"); got != "jdoe" {
		t.Errorf("User(jdoe) = %q, want jdoe", got)
	}
}

func TestInt64(t *testing.T) {
	if got := Int64("42"); got != 42 {
		t.Errorf("Int64(42) = %d, want 42", got)
	}
	if got := Int64("not-a-number"); got != 0 {
		t.Errorf("Int64(garbage) = %d, want 0", got)
	}
}
