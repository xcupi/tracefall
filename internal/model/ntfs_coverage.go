package model

import (
	"fmt"
	"strings"
)

// NTFS source kinds recorded in NtfsCoverage.Source.
const (
	NtfsSourceMFT     = "mft"
	NtfsSourceUSN     = "usn"
	NtfsSourceLogFile = "logfile"
)

// Failure classes recorded when an NTFS source produced nothing usable.
const (
	NtfsFailureNotAJournal = "not_a_usn_journal"
	NtfsFailureNotAnMFT    = "not_an_mft"
	NtfsFailureNotALogFile = "not_a_logfile"
	NtfsFailureCorrupt     = "corrupt"
	NtfsFailureUnsupported = "unsupported_version"
	NtfsFailureLimit       = "limit"
	NtfsFailureOther       = "other"
)

// NtfsCoverage is the filesystem-specific part of ParseCoverage for $MFT,
// $UsnJrnl:$J and $LogFile. It carries counters only, never evidence values.
// A nil NtfsCoverage means "not recorded" (an import made before it existed).
type NtfsCoverage struct {
	Source string `json:"source"`

	// $MFT. ZeroSlots are all-zero record slots that were skipped and are not
	// part of records_read. FreeMapped counts mapped records the table marks
	// as not in use; they are still emitted, labelled as free.
	ZeroSlots            int `json:"zero_slots,omitempty"`
	FreeMapped           int `json:"free_mapped,omitempty"`
	UnmappedNonBase      int `json:"unmapped_non_base,omitempty"`
	UnmappedNoName       int `json:"unmapped_no_name,omitempty"`
	UnmappedNoTime       int `json:"unmapped_no_time,omitempty"`
	AttributeListRecords int `json:"attribute_list_records,omitempty"`

	// $UsnJrnl:$J.
	UnmappedUndated      int    `json:"unmapped_undated,omitempty"`
	UnmappedUnsupported  int    `json:"unmapped_unsupported_version,omitempty"`
	NonRecordBytes       int64  `json:"non_record_bytes,omitempty"`
	FirstNonRecordOffset *int64 `json:"first_non_record_offset,omitempty"`

	// $LogFile. LogRecords were decoded; only LogRecordsRetained of them are kept
	// as per-record detail.
	LogRecords         int `json:"log_records,omitempty"`
	LogRecordsRetained int `json:"log_records_retained,omitempty"`

	// Failed marks a source that produced no usable result; FailureClass says
	// why and FailureOffset where in the file when known.
	Failed        bool   `json:"failed,omitempty"`
	FailureClass  string `json:"failure_class,omitempty"`
	FailureOffset *int64 `json:"failure_offset,omitempty"`
}

// IsNtfsArtifact reports whether an artifact type is one of the three NTFS
// metadata sources that carry NtfsCoverage.
func IsNtfsArtifact(artifactType string) bool {
	return artifactType == ArtifactMFT || artifactType == ArtifactUsnJournal || artifactType == ArtifactLogFile
}

// NtfsFailedWithoutDetail is the sentence for an NTFS source that failed
// before any coverage could be recorded (a crashed or killed worker).
const NtfsFailedWithoutDetail = "FAILED: this source produced no events; it is not evidence of no activity (NTFS coverage detail: not recorded)"

var ntfsFailureText = map[string]string{
	NtfsFailureNotAJournal: "the file is not a USN change journal ($UsnJrnl:$J): no structurally valid journal record was found",
	NtfsFailureNotAnMFT:    "the file is not an $MFT: no coherent FILE record was found",
	NtfsFailureNotALogFile: "the file is not an NTFS $LogFile: no coherent restart page was found",
	NtfsFailureCorrupt:     "the structure is damaged and was refused rather than guessed at",
	NtfsFailureUnsupported: "the record version is not decoded by this build",
	NtfsFailureLimit:       "a safety limit was reached",
	NtfsFailureOther:       "the parser stopped with an error",
}

var ntfsSourceLabel = map[string]string{NtfsSourceMFT: "$MFT", NtfsSourceUSN: "$UsnJrnl:$J", NtfsSourceLogFile: "$LogFile"}

// NtfsSummary renders NtfsCoverage as plain sentences, or "" when the source
// has no NTFS detail (so an older import never reads as complete). Counters
// only; it never repeats evidence text and never states more than the
// counters say.
func (c *ParseCoverage) NtfsSummary() string {
	if c == nil || c.Ntfs == nil {
		return ""
	}
	n := c.Ntfs
	label := ntfsSourceLabel[n.Source]
	if label == "" {
		label = "NTFS source"
	}
	var parts []string
	emitted := c.Mapped
	if c.EmittedEvents != nil {
		emitted = *c.EmittedEvents
	}
	if n.Failed {
		s := fmt.Sprintf("%s: FAILED, this source produced no events; it is not evidence of no activity", label)
		if why := ntfsFailureText[n.FailureClass]; why != "" {
			s += " (" + why
			if n.FailureOffset != nil {
				s += fmt.Sprintf("; at offset %d", *n.FailureOffset)
			}
			s += ")"
		}
		parts = append(parts, s)
	}
	switch n.Source {
	case NtfsSourceLogFile:
		parts = append(parts, fmt.Sprintf("%s: %d log records decoded, %d kept as detail; log records carry no timestamp, so this is transaction metadata and not a timeline (%d events)", label, n.LogRecords, n.LogRecordsRetained, emitted))
	default:
		line := fmt.Sprintf("%s: %d records read, %d mapped, %d unmapped, %d events emitted", label, c.RecordsRead, c.Mapped, c.Unmapped, emitted)
		parts = append(parts, line)
		var why []string
		add := func(k int, text string) {
			if k > 0 {
				why = append(why, fmt.Sprintf("%d %s", k, text))
			}
		}
		add(n.UnmappedNonBase, "extension (non-base) records, which belong to a base record")
		add(n.UnmappedNoName, "without a file name")
		add(n.UnmappedNoTime, "without a standard-information time")
		add(n.UnmappedUndated, "without a usable timestamp")
		add(n.UnmappedUnsupported, "of a record version not decoded")
		if len(why) > 0 {
			parts = append(parts, "unmapped because: "+strings.Join(why, "; "))
		}
		if n.ZeroSlots > 0 {
			parts = append(parts, fmt.Sprintf("%d empty slots were skipped and are not counted as records", n.ZeroSlots))
		}
		if n.FreeMapped > 0 {
			parts = append(parts, fmt.Sprintf("%d mapped records are marked free (not in use); they are emitted labelled as free, and a free record is not a deletion time", n.FreeMapped))
		}
		if n.AttributeListRecords > 0 {
			parts = append(parts, fmt.Sprintf("%d records with an attribute list, whose names and sizes may be incomplete", n.AttributeListRecords))
		}
	}
	if n.NonRecordBytes > 0 {
		s := fmt.Sprintf("%d bytes were not decoded as journal records", n.NonRecordBytes)
		if n.FirstNonRecordOffset != nil {
			s += fmt.Sprintf(" (first at offset %d)", *n.FirstNonRecordOffset)
		}
		parts = append(parts, s+"; source coverage is not complete")
	}
	if c.LimitReached {
		parts = append(parts, "reading stopped at a safety limit; the rest of the source was not read")
	}
	return strings.Join(parts, "; ")
}

// incomplete reports whether the NTFS detail itself says part of the source
// was not decoded: a failure or bytes that are not journal records. Free
// records and empty slots are normal and do not make a source incomplete.
func (n *NtfsCoverage) incomplete() bool {
	return n != nil && (n.Failed || n.NonRecordBytes > 0)
}
