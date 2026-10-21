package model

import (
	"testing"
	"time"
)

func sampleEvent() Event {
	return Event{
		EventType:         EventProcessCreate,
		Timestamp:         time.Date(2026, 1, 15, 9, 14, 47, 0, time.UTC),
		Host:              "WKSTN-042",
		User:              "jdoe",
		ProcessName:       "powershell.exe",
		ParentProcessName: "winword.exe",
		PID:               7984,
		PPID:              6700,
		ArtifactType:      ArtifactWindowsEventLog,
		EventID:           4688,
		// Deliberately different across the two "same event" instances
		// this gets compared against in tests -- provenance/identity
		// fields must not affect the hash.
		CaseID:       "case-a",
		CollectionID: "collection-a",
		SourceFileID: "sf-a",
		Parser:       "evtxcsv@1",
		Confidence:   1.0,
		CommandLine:  "powershell.exe -enc AAAA",
	}
}

func TestDedupHash_IdenticalIdentityFieldsMatch(t *testing.T) {
	a := sampleEvent()
	b := sampleEvent()
	// The same Windows record re-collected with different provenance.
	// Its command/script content must remain identical.
	b.CaseID = "case-b"
	b.CollectionID = "collection-b"
	b.SourceFileID = "sf-b"
	b.RawEvidenceID = "raw-b"
	b.SourceReference = "row:99"
	b.CommandLine = a.CommandLine

	if a.ComputeDedupHash() != b.ComputeDedupHash() {
		t.Errorf("expected matching hashes for the same real-world event with different provenance:\na=%s\nb=%s", a.ComputeDedupHash(), b.ComputeDedupHash())
	}
}

func TestDedupHash_DifferByTimestamp(t *testing.T) {
	a := sampleEvent()
	b := sampleEvent()
	b.Timestamp = a.Timestamp.Add(1 * time.Second)
	if a.ComputeDedupHash() == b.ComputeDedupHash() {
		t.Error("expected different hashes for events differing only by timestamp")
	}
}

func TestDedupHash_DifferByHost(t *testing.T) {
	a := sampleEvent()
	b := sampleEvent()
	b.Host = "OTHER-HOST"
	if a.ComputeDedupHash() == b.ComputeDedupHash() {
		t.Error("expected different hashes for events on different hosts")
	}
}

func TestDedupHash_DifferByPID(t *testing.T) {
	a := sampleEvent()
	b := sampleEvent()
	b.PID = 1111
	if a.ComputeDedupHash() == b.ComputeDedupHash() {
		t.Error("expected different hashes for events with different PIDs")
	}
}

func TestDedupHash_HostCaseInsensitive(t *testing.T) {
	a := sampleEvent()
	b := sampleEvent()
	a.Host = "wkstn-042"
	b.Host = "WKSTN-042"
	if a.ComputeDedupHash() != b.ComputeDedupHash() {
		t.Error("expected host comparison to be case-insensitive")
	}
}

func TestDedupHash_DifferByFilePath(t *testing.T) {
	a := sampleEvent()
	a.EventType = EventRegistryRunKey
	a.FilePath = `C:\Temp\update.exe`
	b := sampleEvent()
	b.EventType = EventRegistryRunKey
	b.FilePath = `C:\Temp\other.exe`
	if a.ComputeDedupHash() == b.ComputeDedupHash() {
		t.Error("expected different hashes for events with different file paths")
	}
}

func TestDedupHash_NoDelimiterCollision(t *testing.T) {
	// Two different field-boundary splits that would produce the same
	// naive concatenation ("AB" + "C" vs "A" + "BC") must still hash
	// differently -- this is exactly what the unit-separator join
	// exists to prevent.
	a := sampleEvent()
	a.ProcessName = "AB"
	a.ParentProcessName = "C"
	b := sampleEvent()
	b.ProcessName = "A"
	b.ParentProcessName = "BC"
	if a.ComputeDedupHash() == b.ComputeDedupHash() {
		t.Error("expected different hashes; a naive delimiter-free join would have collided these")
	}
}

// ---------------- Phase 10A: timestamp-less artifacts ----------------

// The zero-time rule must be invisible to unrelated timestamped artifacts.
// Windows Event Logs intentionally include command/script content now.
func TestDedupHash_NonWindowsTimestampedEventsAreUnaffectedByTheZeroTimeRule(t *testing.T) {
	base := Event{
		EventType:    EventProcessCreate,
		Timestamp:    time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC),
		Host:         "WKSTN-042",
		User:         "jdoe",
		ProcessName:  "powershell.exe",
		ArtifactType: ArtifactPrefetch,
	}
	withCmd := base
	withCmd.CommandLine = "powershell.exe -enc AAAA"
	other := base
	other.CommandLine = "completely different command"

	// Same real event, different command-line rendering -> same identity.
	if base.ComputeDedupHash() != withCmd.ComputeDedupHash() {
		t.Error("adding a command line changed the identity of a timestamped event")
	}
	if withCmd.ComputeDedupHash() != other.ComputeDedupHash() {
		t.Error("command line is affecting the identity of timestamped events; it must not")
	}
}

// With no timestamp, the command text is the only thing distinguishing
// two records, so it MUST take part in the identity or the history
// collapses to one event.
func TestDedupHash_TimestamplessEventsAreDistinguishedByCommand(t *testing.T) {
	base := Event{
		EventType:    EventPowerShellScript,
		Host:         "WKSTN-042",
		User:         "jdoe",
		ArtifactType: ArtifactPowerShellHistory,
	}
	a, b, dup := base, base, base
	a.CommandLine = "Get-Process"
	b.CommandLine = "whoami /priv"
	dup.CommandLine = "Get-Process"

	if a.ComputeDedupHash() == b.ComputeDedupHash() {
		t.Error("two different timestamp-less commands collapsed to one identity -- history would be lost")
	}
	if a.ComputeDedupHash() != dup.ComputeDedupHash() {
		t.Error("the same timestamp-less command produced two identities; re-collection would duplicate it")
	}
}
