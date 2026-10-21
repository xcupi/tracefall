package volatility

import (
	"strings"
	"testing"

	"tracefall/internal/memory"
	"tracefall/internal/model"
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
