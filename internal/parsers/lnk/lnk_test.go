package lnk_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
	parser "tracefall/internal/parsers/lnk"
	"tracefall/internal/shelllink/lnkgen"
)

var at = time.Date(2026, 2, 11, 8, 30, 0, 0, time.UTC)

func write(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Detection is structural only: no filename is ever claimed.
func TestParser_DetectionIsStructuralOnly(t *testing.T) {
	p := parser.New()
	for _, name := range []string{
		"report.lnk", "Recent/report.lnk", "anything.bin", "a/b/c.LNK", "",
	} {
		if p.Detect(name) {
			t.Errorf("%q was claimed by filename", name)
		}
	}
	if !p.DetectContent(lnkgen.Build(lnkgen.Link{Unicode: true, Write: at})) {
		t.Error("a real shortcut was not content-detected")
	}
	for name, data := range map[string][]byte{
		"text":  []byte(strings.Repeat("not a shortcut ", 40)),
		"zeros": make([]byte, 512),
		"short": {0x4C, 0x00, 0x00},
		"empty": {},
	} {
		if p.DetectContent(data) {
			t.Errorf("%q was content-detected as a shortcut", name)
		}
	}
	if p.ArtifactType() != model.ArtifactLNK {
		t.Errorf("artifact type = %q", p.ArtifactType())
	}
}

// One event per recorded timestamp, and none for the ones absent.
func TestParser_OneEventPerRecordedTimestamp(t *testing.T) {
	cases := map[string]struct {
		link lnkgen.Link
		want int
	}{
		"all three":     {lnkgen.Link{Unicode: true, Creation: at, Write: at, Access: at}, 3},
		"write only":    {lnkgen.Link{Unicode: true, Write: at}, 1},
		"creation only": {lnkgen.Link{Unicode: true, Creation: at}, 1},
		"none":          {lnkgen.Link{Unicode: true, Name: "x"}, 0},
	}
	for label, tc := range cases {
		res, err := parser.New().Parse(write(t, "a.lnk", lnkgen.Build(tc.link)))
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if len(res.Events) != tc.want {
			t.Errorf("%s: got %d events, want %d", label, len(res.Events), tc.want)
		}
		// Events pair 1:1 with raw records; a shortcut with no events
		// still keeps one metadata record.
		if tc.want == 0 && len(res.Raw) != 1 {
			t.Errorf("%s: got %d raw records, want 1 metadata record", label, len(res.Raw))
		}
		if tc.want > 0 && len(res.Raw) != tc.want {
			t.Errorf("%s: %d events but %d raw records", label, len(res.Events), len(res.Raw))
		}
	}
}

// Nothing in the output may read as execution.
func TestParser_NeverClaimsExecution(t *testing.T) {
	res, err := parser.New().Parse(write(t, "a.lnk", lnkgen.Build(lnkgen.Link{
		Unicode: true, Creation: at, Write: at, Access: at,
		LocalBasePath: `C:\Windows\System32\cmd.exe`, Arguments: "/c whoami",
	})))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range res.Events {
		for _, banned := range []string{"execution", "process_create", "prefetch", "_run"} {
			if strings.Contains(e.EventType, banned) {
				t.Errorf("event type %q reads as execution", e.EventType)
			}
		}
		if e.ProcessName != "" || e.ProcessPath != "" || e.CommandLine != "" {
			t.Errorf("a shortcut populated a process field: name=%q path=%q cmdline=%q",
				e.ProcessName, e.ProcessPath, e.CommandLine)
		}
		// The arguments ARE recorded -- as shortcut metadata, in extra,
		// not as a command line that was run.
		if e.Extra["command_line_arguments"] != "/c whoami" {
			t.Errorf("the shortcut's arguments were not recorded: %q", e.Extra["command_line_arguments"])
		}
	}
}

// Determinism.
func TestParser_IsDeterministic(t *testing.T) {
	path := write(t, "a.lnk", lnkgen.Build(lnkgen.Link{
		Unicode: true, Creation: at, Write: at, Access: at,
		LocalBasePath: `C:\Users\j\a.txt`, DriveType: 3, VolumeSerial: 0xAABBCCDD,
		IDList: []lnkgen.Item{{Kind: "volume", Name: `C:\`}, {Kind: "file", Name: "a.txt"}},
	}))
	p := parser.New()
	first, err := p.Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := p.Parse(path)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if len(again.Events) != len(first.Events) {
			t.Fatalf("run %d: %d events vs %d", i, len(again.Events), len(first.Events))
		}
		for j := range first.Events {
			if again.Events[j].SourceReference != first.Events[j].SourceReference ||
				!again.Events[j].Timestamp.Equal(first.Events[j].Timestamp) {
				t.Fatalf("run %d event %d differed", i, j)
			}
			if again.Raw[j].Raw != first.Raw[j].Raw {
				t.Fatalf("run %d raw %d differed", i, j)
			}
		}
	}
}

// A file that is not a shortcut is refused by name, not by crashing.
func TestParser_RefusesNonShortcuts(t *testing.T) {
	_, err := parser.New().Parse(write(t, "a.lnk", []byte("plain text pretending to be a shortcut")))
	if err == nil {
		t.Fatal("a text file parsed as a shortcut")
	}
	if !strings.Contains(err.Error(), "not a Windows shortcut") {
		t.Errorf("the error does not name the problem: %v", err)
	}
}
