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
// CaseID, CollectionID, source file identity, Parser and Confidence do not
// identify what happened and are excluded. Most Extra metadata is excluded
// too: renderer/recovery notes must not split recollections. Artifact-scoped
// exceptions below retain Windows record/session/object/script identity,
// task namespace/local registration readings, and memory object attributes.
// CommandLine is retained for Windows events and undated artifacts; unrelated
// timestamped artifacts preserve their historical identity unchanged.
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
	// A timestamp can help distinguish executions. For an artifact that
	// records no timestamp at all, that assumption does not hold -- every
	// command in a PowerShell ConsoleHost_history file shares the same
	// (zero) time, the same host, the same user and the same event type,
	// so without the command text they would all collapse into a single
	// event and the rest of the history would be silently lost.
	//
	// This historical zero-time rule does not affect timestamped hashes.
	// Windows Event Logs separately require command/script content below.
	//
	// The source reference (the line or record number) is included too.
	// Without it a command typed twice in one history file -- "ls" eleven
	// times in one shell history -- collapses into a single
	// event, and 25 of its 95 lines were silently lost. Re-importing the
	// same file yields the same line numbers, so cross-collection
	// deduplication of the same artifact still holds; two different lines
	// that happen to read the same stay two events.
	if e.Timestamp.IsZero() {
		parts = append(parts, e.CommandLine, e.SourceReference)
	}
	// Windows records can tie on time, user and host. Keep the recorded
	// channel/record number and semantic object/session/fragment identity,
	// never CSV row position, source path or collection identity. Explicit
	// metadata keys avoid hashing renderer/recovery notes or native-only
	// System metadata. Unrelated artifact hashes remain unchanged.
	if e.ArtifactType == ArtifactWindowsEventLog {
		parts = append(parts, strings.ToLower(strings.TrimSpace(e.Provider)), e.NetworkSource, e.CommandLine)
		for _, key := range []string{
			"evtx_record_id", "target_domain", "subject_domain", "logon_id", "subject_logon_id",
			"target_user_sid", "target_user_name", "linked_logon_id", "logon_type",
			"object_type", "object_name", "object_domain", "object_sid", "member", "member_sid",
			"actor_domain", "actor_sid", "script_block_id", "message_number",
		} {
			parts = append(parts, e.Extra[key])
		}
	}
	// History identity is the recorded detection plus its complete stateful
	// source content, not a filename or collection. Keep identifiers literal:
	// parser GUIDs are canonical, while malformed synthetic IDs stay distinct.
	if e.ArtifactType == ArtifactDefenderHistory {
		parts = append(parts, e.Extra["detection_id"], e.Extra["source_sha256"])
	}
	// A task namespace path identifies the configured object, not an import
	// path. Equal commands in distinct tasks are distinct configurations.
	if e.ArtifactType == ArtifactScheduledTask {
		parts = append(parts, e.Extra["task_path"], e.Extra["timestamp_local"])
		if e.Timestamp.IsZero() && e.Extra["timestamp_local"] == "" {
			parts = append(parts, e.Extra["timestamp_original"])
		}
	}
	// SQL text records can tie on timestamps, including explicit instants.
	// Keep per-file ordinal and recorded source/message identity for SQL only.
	if e.ArtifactType == ArtifactMSSQLLog || e.ArtifactType == ArtifactSQLAgentLog {
		parts = append(parts, e.SourceReference, e.Extra["timestamp_local"], e.Extra["message"], e.Extra["instance"], e.Extra["sql_source"], e.Extra["agent_message_id"])
	}
	// NTFS records can share names and timestamps, including reused MFT slots.
	// Recorded record/sequence (MFT) or USN/offset (journal) distinguishes them;
	// collection and storage path do not, so recollections still deduplicate.
	if e.ArtifactType == ArtifactMFT || e.ArtifactType == ArtifactUsnJournal {
		parts = append(parts, e.SourceReference, e.Extra["mft_file_reference"])
	}
	// Journal entries are timestamped at microsecond resolution, so two
	// entries from the same process in the same microsecond would collapse
	// under the timestamped rule above. The per-file sequence number is what
	// tells them apart; it is included for this artifact only.
	if e.ArtifactType == ArtifactJournal {
		parts = append(parts, e.SourceReference)
	}
	// grafana.db keeps whole seconds, so rows of one table tie on type, time,
	// user and file. The table row ("login_attempt:id=3") is the record's
	// identity; the same database collected twice yields the same rows.
	if e.ArtifactType == ArtifactGrafanaDB {
		parts = append(parts, e.SourceReference)
	}
	// SRUM writes a row per application per interval, and services and packages
	// have no process name, so rows tie on type, time and user. The row's table
	// and AutoIncId (the source reference) identify it, and they are the same
	// when the same database is collected again.
	if e.ArtifactType == ArtifactSRUM || e.ArtifactType == ArtifactWebCache {
		parts = append(parts, e.SourceReference)
	}
	// Most Extra fields are interpretation or renderer metadata, not identity.
	// Memory observations are the exception: a PID at snapshot time may own
	// many regions, services and sockets. Include their explicit object fields
	// (never the source row index), so distinct objects survive while genuine
	// repeated observations still deduplicate. The artifact guard leaves every
	// historical non-memory hash unchanged, including network log events.
	if e.ArtifactType == ArtifactMemoryAnalysis {
		switch e.EventType {
		case EventMemoryInjection:
			parts = append(parts, e.Extra["start_vpn"], e.Extra["end_vpn"])
		case EventMemoryService:
			parts = append(parts, e.Extra["service_name"], e.Extra["state"],
				e.Extra["start_type"], e.Extra["service_type"], e.Extra["binary_registry"], e.Extra["dll"])
		case EventNetworkConnection, EventNetworkListener:
			parts = append(parts, e.NetworkSource, e.Extra["local_port"],
				e.Extra["protocol"], e.Extra["state"])
		}
	}
	// SQL configuration values and SQL-provider insertion data are evidence
	// identity, not renderer metadata. Leave unrelated historical hashes alone.
	if e.ArtifactType == ArtifactSQLInstance {
		parts = append(parts, e.Extra["registry_value_data"], e.Extra["instance_id"])
	}
	if e.ArtifactType == ArtifactWindowsEventLog && (e.EventType == EventSQLMessage || e.EventType == EventSQLAgentMessage || e.EventType == EventSQLLoginFailed || e.EventType == EventSQLLoginSuccess) {
		parts = append(parts, e.Extra["sql_record_data"])
	}
	// SQL observations can tie; preserve source content and ordinal/span.
	// Collection IDs and runtime/renderer notes do not split recollections.
	if e.ArtifactType == ArtifactMSSQLExtendedEvents || e.ArtifactType == ArtifactMSSQLAudit {
		parts = append(parts, e.SourceReference, e.Extra["sql_source_sha256"], e.Extra["sql_record_sha256"])
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, unitSep)))
	return hex.EncodeToString(sum[:])
}
