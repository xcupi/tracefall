package model

import "testing"

// Undated artifacts (shell histories) have no timestamp to tell two events
// apart, so identity must come from the command text AND its position in
// the file. These pin both halves of that rule.

// undatedCommand is any timestamp-less command artifact. PowerShell history
// is used because it predates the Linux parsers and is undated the same way.
func undatedCommand(ref, cmd string) Event {
	return Event{
		EventType:       EventPowerShellHistoryCommand,
		User:            "root",
		ProcessName:     "powershell.exe",
		FilePath:        "ConsoleHost_history.txt",
		ArtifactType:    ArtifactPowerShellHistory,
		CommandLine:     cmd,
		SourceReference: ref,
	}
}

// A command typed twice in one history file is two events. Before this rule
// the hash ignored the line number, so "ls" typed 11 times became one event
// and 25 of the Insider image's 95 history lines were silently lost.
func TestDedupHash_RepeatedUndatedCommandStaysTwoEvents(t *testing.T) {
	a := undatedCommand("line:3", "ls")
	b := undatedCommand("line:17", "ls")
	if a.ComputeDedupHash() == b.ComputeDedupHash() {
		t.Fatal("the same command on two different lines produced one identity; repeated history lines would be lost")
	}
}

// Re-importing the same file must still deduplicate: the same line gives the
// same identity, so cross-collection dedup of one artifact keeps working.
func TestDedupHash_SameUndatedLineIsStableAcrossImports(t *testing.T) {
	a := undatedCommand("line:3", "ls")
	b := undatedCommand("line:3", "ls")
	if a.ComputeDedupHash() != b.ComputeDedupHash() {
		t.Fatal("the same undated line produced a different identity on re-import; cross-collection dedup is broken")
	}
}

// The line rule must not reach timestamped events, which is what the rest of
// the evidence depends on (see TestDedupHash_TimestampedEventsAreUnaffected...).
func TestDedupHash_TimestampedEventIgnoresSourceReference(t *testing.T) {
	ts := undatedCommand("line:1", "ls")
	ts.Timestamp = ts.Timestamp.AddDate(2021, 0, 0)
	other := ts
	other.SourceReference = "line:99"
	if ts.ComputeDedupHash() != other.ComputeDedupHash() {
		t.Fatal("a timestamped event's identity changed with its source reference; existing evidence would re-key")
	}
}
