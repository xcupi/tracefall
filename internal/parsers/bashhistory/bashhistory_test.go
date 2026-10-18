package bashhistory

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

func writeFile(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDetect_OnlyTheShellHistoryName(t *testing.T) {
	p := New()
	for _, ok := range []string{".bash_history", "root/.bash_history", `[root]\root\.bash_history`, "home/alice/.BASH_HISTORY"} {
		if !p.Detect(ok) {
			t.Errorf("Detect(%q) = false, want true", ok)
		}
	}
	for _, no := range []string{"bash_history.txt", "history", ".zsh_history", "ConsoleHost_history.txt", ".bash_history.bak"} {
		if p.Detect(no) {
			t.Errorf("Detect(%q) = true, want false", no)
		}
	}
	if p.DetectContent([]byte("ls -la\n")) {
		t.Error("DetectContent claimed a plain text file; history has no signature and must not be sniffed")
	}
}

func TestParse_WithoutEpochLinesEventsAreUndated(t *testing.T) {
	body := "ls -la\n\ncat /etc/shadow\n   \nwhoami\n"
	res, err := New().Parse(writeFile(t, ".bash_history", body))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 3 {
		t.Fatalf("events = %d, want 3 (blank lines are not commands)", len(res.Events))
	}
	for i, ev := range res.Events {
		if !ev.Timestamp.IsZero() {
			t.Errorf("event %d has timestamp %v; a history with no epoch lines must stay undated", i, ev.Timestamp)
		}
		if ev.Extra["timestamp_known"] != "false" {
			t.Errorf("event %d timestamp_known = %q, want false", i, ev.Extra["timestamp_known"])
		}
		if ev.EventType != model.EventBashHistoryCommand || ev.ArtifactType != model.ArtifactBashHistory {
			t.Errorf("event %d type/artifact = %q/%q", i, ev.EventType, ev.ArtifactType)
		}
	}
	// Line numbers count blank lines, so the reference matches what an
	// examiner sees opening the file.
	if got := res.Events[1].SourceReference; got != "line:3" {
		t.Errorf("third command source reference = %q, want line:3", got)
	}
	if got := res.Events[2].CommandLine; got != "whoami" {
		t.Errorf("last command = %q, want whoami", got)
	}
}

func TestParse_EpochLineSetsTheTimestampForOnlyTheNextCommand(t *testing.T) {
	// 1634550000 is 2021-10-18T09:40:00Z (checked with time.Unix below)
	body := "#1634550000\nsystemctl start postgresql\nmsfconsole\n#1634550060\nwhoami\n"
	res, err := New().Parse(writeFile(t, ".bash_history", body))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 3 {
		t.Fatalf("events = %d, want 3", len(res.Events))
	}
	want := []time.Time{
		time.Unix(1634550000, 0).UTC(),
		{}, // the second command has no epoch line of its own
		time.Unix(1634550060, 0).UTC(),
	}
	for i, ev := range res.Events {
		if !ev.Timestamp.Equal(want[i]) && !(want[i].IsZero() && ev.Timestamp.IsZero()) {
			t.Errorf("event %d timestamp = %v, want %v", i, ev.Timestamp, want[i])
		}
	}
	if res.Events[0].Extra["timestamp_known"] != "true" || res.Events[1].Extra["timestamp_known"] != "false" {
		t.Errorf("timestamp_known flags wrong: %q, %q", res.Events[0].Extra["timestamp_known"], res.Events[1].Extra["timestamp_known"])
	}
}

func TestParse_HashPrefixedCommandIsNotATimestamp(t *testing.T) {
	// A real comment that is not all digits must stay a command, and a
	// digit-only "#" line is a timestamp, never a command.
	body := "# check the box\n#12x\n#1634550000\nid\n"
	res, err := New().Parse(writeFile(t, ".bash_history", body))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 3 {
		t.Fatalf("events = %d, want 3 (two comments plus id)", len(res.Events))
	}
	if res.Events[0].CommandLine != "# check the box" || res.Events[1].CommandLine != "#12x" {
		t.Errorf("comments were mangled: %q, %q", res.Events[0].CommandLine, res.Events[1].CommandLine)
	}
	if res.Events[2].Timestamp.IsZero() {
		t.Error("the command after the epoch line lost its timestamp")
	}
}

func TestParse_NeverUsesTheFileModificationTime(t *testing.T) {
	p := writeFile(t, ".bash_history", "id\n")
	old := time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	res, err := New().Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Events[0].Timestamp.IsZero() {
		t.Errorf("mtime %v leaked into the event as %v", old, res.Events[0].Timestamp)
	}
}

func TestParse_InvalidUTF8IsKeptNotDropped(t *testing.T) {
	res, err := New().Parse(writeFile(t, ".bash_history", "echo \xff\xfe\nls\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 2 {
		t.Fatalf("events = %d, want 2; a line with bad bytes must not be lost", len(res.Events))
	}
	if !strings.Contains(res.Events[0].CommandLine, "\uFFFD") {
		t.Errorf("bad bytes were not replaced: %q", res.Events[0].CommandLine)
	}
}

func TestLinuxUserFromEvidencePath(t *testing.T) {
	cases := map[string]string{
		"Horcrux.E01:[ext4]/[root]/root/.bash_history": "root",
		"img/[root]/home/alice/.bash_history":          "alice",
		"img/[root]/home/alice/projects/.bash_history": "alice",
		"home/bob/.bash_history":                       "bob",
		`img\home\carol\.bash_history`:                 "carol",
		"/abs/path/home/dave/.bash_history":            "", // absolute server paths are never attributed
		"C:/Users/eve/.bash_history":                   "", // Windows layout is not a Linux home
		"img/var/log/.bash_history":                    "", // no account in the path
		"img/home/.bash_history":                       "", // "home" is the file's parent, not an account
		"":                                             "",
	}
	for in, want := range cases {
		if got := linuxUserFromEvidencePath(in); got != want {
			t.Errorf("linuxUserFromEvidencePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseWithContext_AttributesUserAndRecordsWhy(t *testing.T) {
	p := writeFile(t, ".bash_history", "id\n")
	res, err := New().ParseWithContext(p, parsers.ParseContext{EvidencePath: "img/[root]/home/alice/.bash_history"})
	if err != nil {
		t.Fatal(err)
	}
	ev := res.Events[0]
	if ev.User != "alice" || ev.Extra["user_from_path"] != "alice" {
		t.Errorf("user = %q, user_from_path = %q, want alice", ev.User, ev.Extra["user_from_path"])
	}
	if !strings.Contains(ev.Extra["records_execution"], "false") {
		t.Error("the event must say it does not prove execution")
	}
}

// Real-sample test: the Insider Linux image's root .bash_history. Skipped
// unless TRACEFALL_REAL_BASH points at an extracted copy. The sample is
// not committed; the SHA-256 pins that the test runs on the exact file.
func TestReal_RootBashHistory(t *testing.T) {
	path := os.Getenv("TRACEFALL_REAL_BASH")
	if path == "" {
		t.Skip("set TRACEFALL_REAL_BASH to an extracted root .bash_history to run")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	const wantSHA = "72bf674c19303326c0c9b52e49418a29c1ed8761b8f128c29bdf41e23e570cc4"
	if got := hex.EncodeToString(sum[:]); got != wantSHA {
		t.Fatalf("sample sha256 = %s, want %s: this is not the pinned sample", got, wantSHA)
	}
	res, err := New().ParseWithContext(path, parsers.ParseContext{EvidencePath: "Horcrux.E01:[ext4]/[root]/root/.bash_history"})
	if err != nil {
		t.Fatal(err)
	}
	// 95 non-blank lines, and the file has no epoch lines, so none is dated.
	if len(res.Events) != 95 {
		t.Fatalf("events = %d, want 95 (one per non-blank line)", len(res.Events))
	}
	for _, ev := range res.Events {
		if !ev.Timestamp.IsZero() || ev.User != "root" {
			t.Fatalf("event %q: timestamp %v user %q, want undated and root", ev.CommandLine, ev.Timestamp, ev.User)
		}
	}
	if res.Events[0].CommandLine != "msfconsole" || res.Events[len(res.Events)-1].CommandLine != "pwd" {
		t.Errorf("first/last command = %q / %q, want msfconsole / pwd",
			res.Events[0].CommandLine, res.Events[len(res.Events)-1].CommandLine)
	}
}
