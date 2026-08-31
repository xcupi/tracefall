package model

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

// unitSep is used to join identity fields before hashing. It's not a
// character normalized event field values can plausibly contain, which
// keeps the join unambiguous (unlike e.g. joining with "|", which a
// command line or file path could legitimately contain).
const unitSep = "\x1f"

// ComputeDedupHash computes a stable identity for an event based on the fields
// that describe *what happened*, not *where Tracefall heard about it
// from*: event type, timestamp, host, user, process (name, parent name,
// PID, PPID), file path, registry path, artifact type, Windows event ID,
// and network destination. Two normalized events with the same hash are
// treated as the same real-world observation.
//
// Deliberately excluded: CommandLine/script text. Host+process+PID+an
// exact timestamp already pin down a specific execution as precisely as
// anything short of a cryptographic content hash could; a legitimate
// re-collection of the same event (e.g. a second KAPE triage recollecting
// unrolled Windows Event Log records) reproduces the same CommandLine
// byte-for-byte anyway, so including it buys no extra precision for that
// case, while excluding it keeps the hash cheap to reason about and
// insensitive to a parser field that can be arbitrarily large (an
// encoded PowerShell command). CaseID and CollectionID are also excluded
// on purpose: identity is about the event itself, and hashing in
// CollectionID would defeat cross-collection deduplication entirely,
// which is the whole point of this function existing.
//
// Fields not part of an event's identity in any artifact type (e.g.
// Provider, Confidence, Extra) are excluded too -- widening the identity
// key only risks two observations of the same real event failing to
// match due to incidental parser differences.
func (e Event) ComputeDedupHash() string {
	parts := []string{
		e.EventType,
		e.Timestamp.UTC().Format("2006-01-02T15:04:05.000000000Z"),
		strings.ToUpper(strings.TrimSpace(e.Host)),
		e.User,
		e.ProcessName,
		e.ParentProcessName,
		strconv.FormatInt(e.PID, 10),
		strconv.FormatInt(e.PPID, 10),
		e.FilePath,
		e.RegistryPath,
		e.ArtifactType,
		strconv.Itoa(e.EventID),
		e.NetworkDest,
		strconv.Itoa(e.NetworkDestPort),
	}
	// Timestamp-less artifacts (Phase 10A).
	//
	// The exclusion of CommandLine above rests on one assumption, stated
	// in that paragraph: that "host + process + PID + an EXACT TIMESTAMP
	// already pin down a specific execution". For an artifact that
	// records no timestamp at all, that assumption does not hold -- every
	// command in a PowerShell ConsoleHost_history file shares the same
	// (zero) time, the same host, the same user and the same event type,
	// so without the command text they would all collapse into a single
	// event and the rest of the history would be silently lost.
	//
	// CommandLine is therefore included ONLY when there is no timestamp
	// to identify the event by. This cannot change the hash of any event
	// that has a real timestamp -- which is every event produced by every
	// other artifact -- so existing evidence keeps its identity exactly.
	// TestDedupHash_TimestampedEventsAreUnaffectedByTheZeroTimeRule pins
	// that down.
	if e.Timestamp.IsZero() {
		parts = append(parts, e.CommandLine)
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, unitSep)))
	return hex.EncodeToString(sum[:])
}
