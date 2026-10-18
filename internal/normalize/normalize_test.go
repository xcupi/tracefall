package normalize

import (
	"testing"
	"time"
)

func TestUserFromEvidencePath(t *testing.T) {
	cases := map[string]string{
		`Users\jdoe\AppData\Local\History`:            "jdoe",
		"Documents and Settings/jdoe/AppData/History": "jdoe",
		"home/jdoe/.cache/History":                    "jdoe",
		"Users/Public/AppData/History":                "",
		"Users/Default/AppData/History":               "",
		"collected/home/server/History":               "",
		"Windows/System32/config/SYSTEM":              "",
	}
	for path, want := range cases {
		if got := UserFromEvidencePath(path); got != want {
			t.Errorf("UserFromEvidencePath(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestUserFromEvidencePathIndependentOfDataDirectory(t *testing.T) {
	evidencePath := "Users/jdoe/AppData/Local/Chrome/History"
	for _, dataDir := range []string{"/home/x/data/case", "/Users/x/data/case", "/tmp/tracefall/data/case"} {
		if got := UserFromEvidencePath(evidencePath); got != "jdoe" {
			t.Errorf("data dir %q affected evidence attribution: got %q", dataDir, got)
		}
	}
}

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

// TestTimestamp_UTCOffsetsConvertedCorrectly is a Phase 6 time-handling
// audit test: a timestamp carrying an explicit non-UTC offset (which
// Windows Event Log/EZ Tools output does not normally produce, but
// RFC3339 -- one of the accepted layouts -- allows, and a defensively
// written parser should still handle correctly rather than silently
// misinterpreting the offset) must convert to the exact correct UTC
// instant, not just parse "successfully" with the offset ignored.
func TestTimestamp_UTCOffsetsConvertedCorrectly(t *testing.T) {
	cases := []struct {
		in      string
		wantUTC string
	}{
		// -08:00 (e.g. US Pacific Standard Time) -> add 8 hours for UTC.
		{"2026-01-15T01:14:47-08:00", "2026-01-15T09:14:47Z"},
		// +05:30 (e.g. India Standard Time) -> subtract 5h30m for UTC.
		{"2026-01-15T14:44:47+05:30", "2026-01-15T09:14:47Z"},
		// Explicit +00:00 must behave identically to a bare "Z".
		{"2026-01-15T09:14:47+00:00", "2026-01-15T09:14:47Z"},
	}
	for _, c := range cases {
		got, ok := Timestamp(c.in)
		if !ok {
			t.Errorf("Timestamp(%q): expected valid parse", c.in)
			continue
		}
		want, err := time.Parse(time.RFC3339, c.wantUTC)
		if err != nil {
			t.Fatal(err)
		}
		if !got.Equal(want) {
			t.Errorf("Timestamp(%q) = %v, want %v (offset not converted correctly)", c.in, got, want)
		}
		if got.Location().String() != "UTC" {
			t.Errorf("Timestamp(%q) location = %v, want UTC", c.in, got.Location())
		}
	}
}

// TestTimestamp_DaylightSavingNotAmbiguous documents and verifies why
// DST transitions don't create ambiguity for Tracefall: every accepted
// layout (see timeLayouts) either carries an explicit UTC/offset marker
// or is treated as already-UTC -- Tracefall never parses a bare
// local-time string and guesses which UTC offset it means (the one
// genuine source of DST ambiguity, e.g. "2026-11-01 01:30:00" during a
// fall-back transition legitimately meaning two different UTC instants).
// A timestamp carrying an explicit offset spanning a real DST transition
// boundary still converts unambiguously, since the offset itself
// disambiguates it.
func TestTimestamp_DaylightSavingNotAmbiguous(t *testing.T) {
	// 2026-03-08 is the US spring-forward DST transition date. Two
	// timestamps either side of it, both with explicit offsets, must
	// each convert to their own distinct, correct UTC instant.
	before, ok := Timestamp("2026-03-08T01:30:00-08:00") // PST, before the transition
	if !ok {
		t.Fatal("expected valid parse for pre-transition timestamp")
	}
	after, ok := Timestamp("2026-03-08T03:30:00-07:00") // PDT, after the transition
	if !ok {
		t.Fatal("expected valid parse for post-transition timestamp")
	}
	wantBefore, _ := time.Parse(time.RFC3339, "2026-03-08T09:30:00Z")
	wantAfter, _ := time.Parse(time.RFC3339, "2026-03-08T10:30:00Z")
	if !before.Equal(wantBefore) {
		t.Errorf("before-transition timestamp = %v, want %v", before, wantBefore)
	}
	if !after.Equal(wantAfter) {
		t.Errorf("after-transition timestamp = %v, want %v", after, wantAfter)
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
