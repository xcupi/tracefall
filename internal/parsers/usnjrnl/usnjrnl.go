// Package usnjrnl turns NTFS USN change journal records into normalized
// timeline events.
//
// # One event per record
//
// A USN record carries a reason MASK, not a single reason: a file that
// was extended and then closed produces one record with two bits set.
// This emits ONE event per record, typed by the most significant reason
// present, and carries the complete decoded mask on the event. Emitting
// one event per bit would multiply a single observed change into several
// timeline entries that the journal never recorded.
//
// The raw mask travels too, as both hex and flag names, so an examiner
// can always check the translation against what the journal said.
//
// # Distinct from $MFT events
//
// The $MFT says what a file's metadata is NOW. The journal says the
// volume observed a change THEN -- including for files since deleted.
// They are different claims from different sources, so they use
// different event types and every event records which source it came
// from. Nothing here deduplicates against $MFT events: two sources
// independently attesting to the same file is evidence, not duplication.
//
// # No actor
//
// A USN record names no user, process or executable. None is inferred.
package usnjrnl

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"tracefall/internal/model"
	"tracefall/internal/ntfs"
	"tracefall/internal/parsers"
)

const parserName = "ntfs_usnjrnl@1"

// DefaultMaxEvents bounds one journal's contribution to the timeline. A
// production $J holds millions of records; beyond this ceiling the
// parser stops and reports how far it got rather than silently
// truncating.
const DefaultMaxEvents = 300_000

// Parser implements parsers.ArtifactParser and parsers.ContentDetector.
type Parser struct {
	limits    ntfs.Limits
	maxEvents int
	cancelled func() bool
}

func New() *Parser { return &Parser{limits: ntfs.DefaultLimits(), maxEvents: DefaultMaxEvents} }

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactUsnJournal }

// Detect matches the journal's reserved NTFS names.
//
// The $J data stream is extracted under a handful of conventional names
// depending on the acquisition tool: "$UsnJrnl:$J", "$UsnJrnl_$J",
// "$J" alone, or "$Extend/$UsnJrnl". Matching those and nothing broader
// is what stops an arbitrary file being claimed as a change journal.
func (Parser) Detect(relPath string) bool {
	lower := strings.ToLower(filepath.ToSlash(relPath))
	base := strings.ToLower(filepath.Base(lower))
	switch base {
	case "$usnjrnl:$j", "$usnjrnl_$j", "$usnjrnl.$j", "$j", "usnjrnl_$j", "$usnjrnl":
		return true
	}
	// "$Extend/$UsnJrnl..." in any casing.
	return strings.Contains(lower, "$extend/$usnjrnl")
}

// DetectContent identifies a journal by the structure of its records, so
// one collected under an unrecognized name is still found.
func (Parser) DetectContent(header []byte) bool { return ntfs.SniffUsnJournal(header) }

// Parse reads one $UsnJrnl:$J and emits change events.
func (p Parser) Parse(absPath string) (parsers.ParseResult, error) {
	source := filepath.Base(absPath)
	var out parsers.ParseResult
	var (
		records, skipped int
		truncated        bool
		warnings         []string
	)

	err := ntfs.ScanUsnJournal(absPath, ntfs.UsnScanOptions{
		Limits: p.limits, Cancelled: p.cancelled,
	}, func(r ntfs.UsnRecord) error {
		records++
		if len(r.Warnings) > 0 && len(warnings) < 25 {
			warnings = append(warnings, fmt.Sprintf("record at offset %d (USN %d): %s",
				r.Offset, r.Usn, strings.Join(r.Warnings, "; ")))
		}
		// A record with no usable time cannot be placed on a timeline,
		// and inventing one is not an option.
		if r.Timestamp.IsZero() {
			skipped++
			return nil
		}
		// A record this build cannot decode contributes nothing; it is
		// counted and reported instead.
		if r.MajorVersion != 2 && r.MajorVersion != 3 {
			skipped++
			return nil
		}
		if len(out.Events) >= p.maxEvents {
			truncated = true
			return nil
		}
		ev, raw := p.eventFor(r, source)
		out.Events = append(out.Events, ev)
		out.Raw = append(out.Raw, raw)
		return nil
	})
	if err != nil {
		return parsers.ParseResult{}, fmt.Errorf("usnjrnl: %w", err)
	}

	if truncated {
		warnings = append(warnings, fmt.Sprintf(
			"the event ceiling of %d was reached after %d records; the timeline covers only the records before that point",
			p.maxEvents, records))
	}
	if len(warnings) > 0 || skipped > 0 {
		blob, _ := json.Marshal(map[string]any{
			"parser":                parserName,
			"source_file":           source,
			"records_read":          records,
			"records_without_event": skipped,
			"truncated":             truncated,
			"warnings":              warnings,
		})
		out.Raw = append(out.Raw, model.RawEvidence{
			SourceReference: "usnjrnl:parse-report",
			Raw:             string(blob),
		})
	}
	return out, nil
}

// eventTypeFor maps a reason mask to one event type.
//
// Ordered by forensic significance, most decisive first: a record that
// both creates and closes a file is a creation. CLOSE and the various
// *_CHANGE bits are modifiers rather than operations, so they only
// decide the type when nothing stronger is present.
func eventTypeFor(reason uint32) (string, string) {
	switch {
	case reason&ntfs.UsnReasonFileDelete != 0:
		return model.EventUsnDelete, "FILE_DELETE"
	case reason&ntfs.UsnReasonFileCreate != 0:
		return model.EventUsnCreate, "FILE_CREATE"
	case reason&(ntfs.UsnReasonRenameOldName|ntfs.UsnReasonRenameNewName) != 0:
		return model.EventUsnRename, "RENAME"
	case reason&(ntfs.UsnReasonDataOverwrite|ntfs.UsnReasonDataExtend|ntfs.UsnReasonDataTruncation|
		ntfs.UsnReasonNamedDataOverwrite|ntfs.UsnReasonNamedDataExtend|ntfs.UsnReasonNamedDataTruncation) != 0:
		return model.EventUsnModify, "DATA_CHANGE"
	}
	// Everything else -- security, EA, basic info, hard link, reparse,
	// stream, compression, or a bare CLOSE -- is a metadata change.
	return model.EventUsnMetadataChange, "METADATA_CHANGE"
}

func (p Parser) eventFor(r ntfs.UsnRecord, source string) (model.Event, model.RawEvidence) {
	eventType, classification := eventTypeFor(r.Reason)
	reasons := r.ReasonNames()

	extra := map[string]string{
		"usn":                   strconv.FormatUint(r.Usn, 10),
		"usn_reason_flags":      strings.Join(reasons, "|"),
		"usn_reason_hex":        fmt.Sprintf("0x%08X", r.Reason),
		"usn_classification":    classification,
		"usn_record_version":    fmt.Sprintf("%d.%d", r.MajorVersion, r.MinorVersion),
		"usn_record_offset":     strconv.FormatInt(r.Offset, 10),
		"mft_file_reference":    fmt.Sprintf("%d-%d", r.FileReference, r.FileSequence),
		"mft_record_number":     strconv.FormatUint(r.FileReference, 10),
		"parent_mft_record":     strconv.FormatUint(r.ParentReference, 10),
		"parent_file_reference": fmt.Sprintf("%d-%d", r.ParentReference, r.ParentSequence),
		"raw_file_reference":    r.RawFileReference,
		"raw_parent_reference":  r.RawParentReference,
		"file_name":             r.FileName,
		"filesystem":            "NTFS",
		// The SOURCE is stated on every event. An examiner comparing a
		// journal entry with an $MFT entry for the same file must be
		// able to tell them apart at a glance.
		"event_source":    "NTFS USN change journal ($UsnJrnl:$J)",
		"usn_source_file": source,
		"record_type":     recordKind(r.FileAttributes),
		// What this row does and does not show.
		"evidence_caveat": "A USN record states that the volume recorded a change to this file name and which reasons it recorded; it does not state who or what made the change, and it does not describe what the content became.",
	}
	if names := ntfs.UsnSourceNames(r.SourceInfo); len(names) > 0 {
		extra["usn_source_info"] = strings.Join(names, "|")
		extra["usn_source_info_hex"] = fmt.Sprintf("0x%08X", r.SourceInfo)
	}
	if r.SecurityID != 0 {
		extra["security_id"] = strconv.FormatUint(uint64(r.SecurityID), 10)
	}
	if attrs := ntfs.FileAttributeNames(r.FileAttributes); len(attrs) > 0 {
		extra["file_attributes"] = strings.Join(attrs, "|")
	}
	extra["file_attributes_hex"] = fmt.Sprintf("0x%08X", r.FileAttributes)
	if len(r.Warnings) > 0 {
		extra["parse_warnings"] = strings.Join(r.Warnings, "; ")
	}
	// A rename is only half a story on its own; say which half.
	switch {
	case r.Reason&ntfs.UsnReasonRenameOldName != 0:
		extra["rename_role"] = "old name (the name the file had before the rename)"
	case r.Reason&ntfs.UsnReasonRenameNewName != 0:
		extra["rename_role"] = "new name (the name the file was given)"
	}

	ref := fmt.Sprintf("usn:%d:%d", r.Usn, r.Offset)
	ev := model.Event{
		Timestamp:    r.Timestamp.UTC(),
		EventType:    eventType,
		ArtifactType: model.ArtifactUsnJournal,
		Parser:       parserName,
		// The journal records a name, not a path: resolving it needs the
		// $MFT's directory tree, which this artifact does not contain.
		// The parent reference is preserved so an examiner can make that
		// join deliberately rather than having it guessed here.
		FilePath: r.FileName,
		// No Host, User, ProcessName or CommandLine: the journal records
		// none of them.
		//
		// 0.85: a journal entry is a direct filesystem observation with a
		// reliable time, but it names a change without naming a cause.
		Confidence:      0.85,
		SourceReference: ref,
		Extra:           extra,
	}

	blob, _ := json.Marshal(map[string]any{
		"usn":                  r.Usn,
		"record_offset":        r.Offset,
		"record_length":        r.Length,
		"version":              fmt.Sprintf("%d.%d", r.MajorVersion, r.MinorVersion),
		"timestamp":            r.Timestamp.UTC().Format("2006-01-02T15:04:05.9999999Z"),
		"reason_hex":           fmt.Sprintf("0x%08X", r.Reason),
		"reason_flags":         reasons,
		"source_info_hex":      fmt.Sprintf("0x%08X", r.SourceInfo),
		"source_info_flags":    ntfs.UsnSourceNames(r.SourceInfo),
		"security_id":          r.SecurityID,
		"file_attributes_hex":  fmt.Sprintf("0x%08X", r.FileAttributes),
		"file_attributes":      ntfs.FileAttributeNames(r.FileAttributes),
		"file_name":            r.FileName,
		"file_reference":       r.RawFileReference,
		"parent_reference":     r.RawParentReference,
		"mft_record_number":    r.FileReference,
		"mft_sequence_number":  r.FileSequence,
		"parent_record_number": r.ParentReference,
		"warnings":             r.Warnings,
	})
	return ev, model.RawEvidence{SourceReference: ref, Raw: string(blob)}
}

func recordKind(attr uint32) string {
	if ntfs.IsDirectoryAttr(attr) {
		return "directory"
	}
	return "file"
}
