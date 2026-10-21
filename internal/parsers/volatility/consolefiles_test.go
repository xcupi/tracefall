package volatility

import (
	"strings"
	"testing"
	"time"

	"tracefall/internal/memory"
	"tracefall/internal/model"
	"tracefall/internal/payload"
)

// Rows follow what windows.cmdscan, windows.consoles and windows.filescan
// printed for a real image (flattened the way memory.ParseRows flattens the
// renderer's tree): a row per property, the command text in Data, and a
// property named ..._Command_<n>.

func consoleRows() []row {
	return []row{
		{"PID": 728.0, "Process": "conhost.exe", "ConsoleInfo": 1.0, "Property": "_COMMAND_HISTORY", "Data": "None"},
		{"PID": 728.0, "Process": "conhost.exe", "ConsoleInfo": 1.0, "Property": "_COMMAND_HISTORY.Application", "Data": "cmd.exe"},
		{"PID": 728.0, "Process": "conhost.exe", "ConsoleInfo": 1.0, "Property": "_COMMAND_HISTORY.CommandCount", "Data": "2"},
		{"PID": 728.0, "Process": "conhost.exe", "ConsoleInfo": 1.0, "Property": "_COMMAND_HISTORY.CommandBucket_Command_0", "Data": "whoami"},
		{"PID": 728.0, "Process": "conhost.exe", "ConsoleInfo": 1.0, "Property": "_COMMAND_HISTORY.CommandBucket_Command_1", "Data": "net user alice P@ss /add"},
	}
}

func consolesPluginRows() []row {
	return []row{
		{"PID": 728.0, "Process": "conhost.exe", "Property": "_CONSOLE_INFORMATION", "Data": "None"},
		{"PID": 728.0, "Process": "conhost.exe", "Property": "_CONSOLE_INFORMATION.OriginalTitle", "Data": "C:\\Windows\\system32\\cmd.exe"},
		{"PID": 728.0, "Process": "conhost.exe", "Property": "_CONSOLE_INFORMATION.HistoryList.CommandHistory_0_Application", "Data": "cmd.exe"},
		{"PID": 728.0, "Process": "conhost.exe", "Property": "_CONSOLE_INFORMATION.HistoryList.CommandHistory_0_Command_0", "Data": "whoami"},
		{"PID": 728.0, "Process": "conhost.exe", "Property": "_CONSOLE_INFORMATION.HistoryList.CommandHistory_0_Command_1", "Data": "net user alice P@ss /add"},
		{"PID": 728.0, "Process": "conhost.exe", "Property": "_CONSOLE_INFORMATION.ScreenBuffer_0.Dump", "Data": "C:\\>whoami\ncorp\\bob\n\nC:\\>"},
	}
}

func withPlugins(extra ...memory.PluginResult) memory.Analysis {
	a := baseAnalysis()
	a.Plugins = append(a.Plugins, extra...)
	return a
}

func TestConsoles_CommandsFromBothPluginsAreEmittedOnce(t *testing.T) {
	a := withPlugins(ok("cmdscan", "windows.cmdscan.CmdScan", consoleRows()...), ok("consoles", "windows.consoles.Consoles", consolesPluginRows()...))
	evs := parseAll(t, a)
	cmds := byType(evs, model.EventMemoryConsole)
	if len(cmds) != 2 {
		t.Fatalf("got %d commands, want 2 (the same history seen by both plugins)", len(cmds))
	}
	for _, c := range cmds {
		if c.PID != 728 || c.ProcessName != "conhost.exe" || c.Extra["found_by"] != "cmdscan,consoles" || c.Extra["timestamp_basis"] != "memory_snapshot" ||
			c.Extra["console_application"] != "cmd.exe" || c.Extra["console_title"] != `C:\Windows\system32\cmd.exe` {
			t.Errorf("event %+v", c)
		}
		if c.Timestamp.IsZero() {
			t.Error("a command with no time of its own is dated to the capture, which the basis says")
		}
	}
	if cmds[0].CommandLine != "whoami" || cmds[1].CommandLine != "net user alice P@ss /add" {
		t.Errorf("order or text: %q %q", cmds[0].CommandLine, cmds[1].CommandLine)
	}
	scr := byType(evs, model.EventMemoryConsoleScreen)
	if len(scr) != 1 || !strings.Contains(scr[0].Extra["screen_text"], "corp\\bob") || scr[0].Extra["screen_lines"] != "4" {
		t.Fatalf("screen: %+v", scr)
	}
}

func TestConsoles_NoCommandsExplainsWhy(t *testing.T) {
	// No conhost.exe in the process list: the plugins cannot read this OS's consoles.
	a := withPlugins(ok("cmdscan", "windows.cmdscan.CmdScan"), ok("consoles", "windows.consoles.Consoles"))
	snap := byType(parseAll(t, a), model.EventMemorySnapshot)[0]
	if !strings.Contains(snap.Extra["console_note"], "No conhost.exe") || !strings.Contains(snap.Extra["console_note"], "does not mean none were typed") {
		t.Errorf("note: %q", snap.Extra["console_note"])
	}
	// With a conhost.exe but nothing in it, the note is the other one.
	a = withPlugins(ok("cmdscan", "windows.cmdscan.CmdScan"))
	for i := range a.Plugins {
		if a.Plugins[i].Logical == "pslist" {
			a.Plugins[i].Rows = append(a.Plugins[i].Rows, row{"PID": 728.0, "PPID": 4.0, "ImageFileName": "conhost.exe", "CreateTime": "2026-02-01T09:00:00+00:00", "ExitTime": nil})
		}
	}
	snap = byType(parseAll(t, a), model.EventMemorySnapshot)[0]
	if !strings.Contains(snap.Extra["console_note"], "not evidence that nothing was typed") {
		t.Errorf("note: %q", snap.Extra["console_note"])
	}
}

func TestConsoles_AnUnreadableConsoleIsCounted(t *testing.T) {
	a := withPlugins(ok("consoles", "windows.consoles.Consoles", row{"PID": 728.0, "Process": "conhost.exe", "Property": "_CONSOLE_INFORMATION", "Data": "Console Information Not Found"}))
	snap := byType(parseAll(t, a), model.EventMemorySnapshot)[0]
	if !strings.Contains(snap.Extra["console_note"], "1 console(s) were found but their structures could not be read") {
		t.Errorf("note: %q", snap.Extra["console_note"])
	}
}

func TestFileObjects_OnlyWorthwhileFilesAreListedAndTheRestIsCounted(t *testing.T) {
	a := withPlugins(ok("filescan", "windows.filescan.FileScan",
		row{"Name": `\Users\alice\Downloads\Updater.EXE`, "Offset": 4096.0},
		row{"Name": `\users\alice\downloads\updater.exe`, "Offset": 8192.0}, // the same file again
		row{"Name": `\Users\alice\Documents\plan.docx`, "Offset": 9000.0},
		row{"Name": `\Windows\System32\kernel32.dll`, "Offset": 1.0},
		row{"Name": `\Windows\Fonts\seguisb.ttf`, "Offset": 2.0},
		row{"Name": `\Users\alice\AppData\Local\x\cache.dat`, "Offset": 3.0},
		row{"Name": "\ueba8\u765c\ube8e\uffff", "Offset": 4.0},
		row{"Name": `\Program Files\App\app.exe`, "Offset": 5.0},
	))
	evs := parseAll(t, a)
	files := byType(evs, model.EventMemoryFile)
	if len(files) != 2 {
		t.Fatalf("got %d: %+v", len(files), files)
	}
	if files[0].FilePath != `\Users\alice\Downloads\Updater.EXE` || files[0].Extra["file_object_offset"] != "0x1000" {
		t.Errorf("%+v", files[0])
	}
	snap := byType(evs, model.EventMemorySnapshot)[0]
	want := "listed 2; not listed: 3 in operating-system or installed-software locations, 1 of other types, 1 unreadable names"
	if snap.Extra["file_objects"] != want {
		t.Errorf("file_objects = %q\nwant        %q", snap.Extra["file_objects"], want)
	}
	if !strings.Contains(files[0].Extra["observation"], "carries no content hash") {
		t.Errorf("a file object must not look like a hashed file: %q", files[0].Extra["observation"])
	}
}

func recoveredAnalysis() memory.Analysis {
	a := withPlugins()
	rep := payload.Report{Type: "Windows executable (MZ)", Size: 7168, SHA256: strings.Repeat("ab", 32), MD5: strings.Repeat("cd", 16), SHA1: strings.Repeat("ef", 20), Entropy: 5.5,
		PE: &payload.PEInfo{Machine: "amd64", Subsystem: "console", ImportCount: 4, ImportDLLs: []string{"kernel32.dll", "ws2_32.dll"},
			InjectionAPIs: []string{"WriteProcessMemory"}, ClaimedBuild: time.Date(2020, 9, 1, 0, 0, 0, 0, time.UTC)},
		Indicators: []payload.Indicator{{ID: "imports_injection_apis", Detail: "imports WriteProcessMemory"}, {ID: "no_signature_directory", Detail: "carries no Authenticode signature directory"}},
		Strings:    payload.StringHits{URLs: []string{"http://203.0.113.9/x"}},
	}
	a.Recovered = []memory.RecoveredFile{
		{Name: `\Tools\a.exe`, FileObject: 4096, Status: memory.RecoveredOK, Parts: []memory.RecoveredPart{
			{Cache: "DataSectionObject", Size: 7168, Report: rep}, {Cache: "ImageSectionObject", Size: 8192, Report: payload.Report{Type: "Windows executable (MZ)", Size: 8192, SHA256: strings.Repeat("12", 32)}}}},
		{Name: `\Tools\gone.exe`, Status: memory.RecoveredNone},
		{Name: `\Tools\huge.exe`, Status: memory.RecoveredTooLarge, Parts: []memory.RecoveredPart{{Cache: "DataSectionObject", Size: 1 << 30}}},
		{Name: `\Tools\bad.exe`, Status: memory.RecoveredFailed, Error: "boom"},
	}
	return a
}

func TestRecoveredFiles_BecomeContentEventsWithTheirCaveat(t *testing.T) {
	evs := parseAll(t, recoveredAnalysis())
	c := byType(evs, model.EventMemoryFileContent)
	if len(c) != 2 {
		t.Fatalf("got %d content events, want 2 (one per part that has content)", len(c))
	}
	e := c[0]
	for k, want := range map[string]string{
		"sha256": strings.Repeat("ab", 32), "memory_cache": "DataSectionObject", "file_signature": "Windows executable (MZ)", "pe_machine": "amd64",
		"pe_injection_apis": "WriteProcessMemory", "indicators": "imports_injection_apis,no_signature_directory", "strings_urls": "http://203.0.113.9/x",
		"pe_claimed_build_time": "2020-09-01T00:00:00Z", "timestamp_basis": "memory_snapshot",
	} {
		if e.Extra[k] != want {
			t.Errorf("Extra[%s] = %q, want %q", k, e.Extra[k], want)
		}
	}
	for _, want := range []string{"not necessarily the hash of the file on disk"} {
		if !strings.Contains(e.Extra["observation"], want) {
			t.Errorf("observation lacks %q", want)
		}
	}
	if !strings.Contains(e.Extra["indicator_meaning"], "none is a verdict") || !strings.Contains(e.Extra["pe_claimed_build_note"], "set to anything") {
		t.Errorf("caveats missing: %v", e.Extra)
	}
	if e.FilePath != `\Tools\a.exe` {
		t.Errorf("path %q", e.FilePath)
	}
	snap := byType(evs, model.EventMemorySnapshot)[0]
	if snap.Extra["file_recovery"] != "tried 4 file(s): 1 recovered, 1 not in memory (not cached or already released), 1 too large to read, 1 failed" {
		t.Errorf("file_recovery = %q", snap.Extra["file_recovery"])
	}
}

func TestRecoveredFiles_NoSnapshotTimeMeansNoDatedEvents(t *testing.T) {
	a := recoveredAnalysis()
	a.Info = map[string]string{}
	if c := byType(parseAll(t, a), model.EventMemoryFileContent); len(c) != 0 {
		t.Errorf("events dated to a snapshot that has no time: %d", len(c))
	}
}

func TestRecoveredFiles_ASparseDumpWithholdsIndicatorsAboutAbsence(t *testing.T) {
	a := withPlugins()
	rep := payload.Report{Type: "Windows executable (MZ)", Size: 40960, SHA256: strings.Repeat("ab", 32), PE: &payload.PEInfo{Machine: "x86", ImportCount: 0},
		Indicators: []payload.Indicator{{ID: "very_few_imports", Detail: "only 0"}, {ID: "no_signature_directory", Detail: "none"}, {ID: "imports_injection_apis", Detail: "imports X"}}}
	a.Recovered = []memory.RecoveredFile{{Name: `\Tools\a.dll`, Status: memory.RecoveredOK, Parts: []memory.RecoveredPart{{Cache: "ImageSectionObject", Size: 40960, ZeroPages: 9, TotalPages: 10, Report: rep}}}}
	e := byType(parseAll(t, a), model.EventMemoryFileContent)[0]
	if e.Extra["sparse"] != "true" || e.Extra["zero_pages"] != "9 of 10" || e.Extra["indicators"] != "imports_injection_apis" ||
		e.Extra["indicators_withheld"] != "very_few_imports,no_signature_directory" {
		t.Errorf("%v", e.Extra)
	}
	// A file that is whole keeps every indicator.
	a.Recovered[0].Parts[0].ZeroPages = 0
	e = byType(parseAll(t, a), model.EventMemoryFileContent)[0]
	if e.Extra["sparse"] != "" || !strings.Contains(e.Extra["indicators"], "very_few_imports") {
		t.Errorf("%v", e.Extra)
	}
	// Nothing recognised in the first bytes.
	a.Recovered[0].Parts[0].Report.Type = ""
	e = byType(parseAll(t, a), model.EventMemoryFileContent)[0]
	if e.Extra["file_signature"] != "unknown" {
		t.Errorf("%v", e.Extra)
	}
}
