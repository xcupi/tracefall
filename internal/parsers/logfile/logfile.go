// Package logfile parses the NTFS transaction log ($LogFile) and records
// what it validated, WITHOUT synthesizing filesystem events.
//
// # Why this parser emits no timeline events
//
// Two independent reasons, either of which would be sufficient.
//
// First: a LOG_RECORD_HEADER carries no timestamp. There is no time
// field anywhere in the structure. Placing a record on a timeline would
// mean borrowing a time from somewhere else -- the enclosing page, the
// restart area, a neighbouring record -- and presenting it as when the
// operation happened. That is inventing evidence.
//
// Second: a log record describes a byte-level mutation ("set these bytes
// in this attribute of this MFT record"), not a file operation.
// Recovering "the user deleted X" requires replaying the log against
// volume state, tracking the open-attribute table across pages, and
// resolving records that span a circular buffer that wraps. Each step
// can fail quietly, and a quiet failure here is a fabricated event on a
// forensic timeline.
//
// So the parser validates and records STRUCTURE: restart areas, LSN
// ranges, client records, transaction identifiers, and the distribution
// of redo/undo operations. That answers real questions -- was the volume
// mounted dirty, how much history does the log retain, what kind of
// activity dominates it -- without asserting anything the log does not
// state.
//
// The parsed metadata is stored as raw evidence against the source file,
// so it is available for inspection and export even though it produces
// no timeline entries.
package logfile

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"tracefall/internal/model"
	"tracefall/internal/ntfs"
	"tracefall/internal/parsers"
)

const parserName = "ntfs_logfile@1"

// DefaultMaxRecordsRetained bounds how many individual log records are
// written out as raw evidence. The summary counts every record scanned
// regardless; this only bounds the per-record detail.
const DefaultMaxRecordsRetained = 5000

// Parser implements parsers.ArtifactParser and parsers.ContentDetector.
type Parser struct {
	limits     ntfs.Limits
	maxRecords int
	cancelled  func() bool
}

func New() *Parser {
	return &Parser{limits: ntfs.DefaultLimits(), maxRecords: DefaultMaxRecordsRetained}
}

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactLogFile }

// Detect matches the reserved NTFS name.
func (Parser) Detect(relPath string) bool {
	base := strings.ToLower(filepath.Base(filepath.ToSlash(relPath)))
	return base == "$logfile" || base == "$logfile.bin" || base == "logfile"
}

// DetectContent identifies a log by a coherent restart page.
func (Parser) DetectContent(header []byte) bool { return ntfs.SniffLogFile(header) }

// Parse validates the log and records its metadata.
//
// It returns NO events. That is the point: see the package comment.
func (p Parser) Parse(absPath string) (parsers.ParseResult, error) {
	source := filepath.Base(absPath)
	var out parsers.ParseResult
	retained := 0

	summary, err := ntfs.ScanLogFile(absPath, ntfs.LogScanOptions{
		Limits:             p.limits,
		Cancelled:          p.cancelled,
		MaxRecordsRetained: p.maxRecords,
	}, func(page ntfs.LogPage, r ntfs.LogRecord) error {
		retained++
		blob, _ := json.Marshal(map[string]any{
			"lsn":                  r.ThisLSN,
			"client_previous_lsn":  r.ClientPreviousLSN,
			"client_undo_next_lsn": r.ClientUndoNextLSN,
			"transaction_id":       r.TransactionID,
			"record_type":          r.RecordType,
			"flags":                r.Flags,
			"redo_operation":       r.RedoName(),
			"redo_operation_code":  r.RedoOperation,
			"redo_length":          r.RedoLength,
			"undo_operation":       r.UndoName(),
			"undo_operation_code":  r.UndoOperation,
			"undo_length":          r.UndoLength,
			"target_attribute":     r.TargetAttribute,
			"target_vcn":           r.TargetVCN,
			"target_lcn":           r.TargetLCN,
			"lcns_to_follow":       r.LCNsToFollow,
			"client_data_length":   r.ClientDataLength,
			"page_offset":          page.PageOffset,
			"record_offset":        r.Offset,
			"warnings":             r.Warnings,
			// Stated on every record so nobody reading the export later
			// mistakes this for a timeline entry.
			"timestamp": nil,
			"note":      "NTFS $LogFile records carry no timestamp; this is transaction metadata, not a timeline event",
		})
		out.Raw = append(out.Raw, model.RawEvidence{
			SourceReference: fmt.Sprintf("logfile:lsn:%d:%d", r.ThisLSN, r.Offset),
			Raw:             string(blob),
		})
		return nil
	})
	if err != nil {
		return parsers.ParseResult{}, fmt.Errorf("logfile: %w", err)
	}

	out.Raw = append(out.Raw, model.RawEvidence{
		SourceReference: "logfile:summary",
		Raw:             summaryBlob(summary, source, retained),
	})
	return out, nil
}

// summaryBlob renders the validated structure of the whole log.
func summaryBlob(s ntfs.LogFileSummary, source string, retained int) string {
	restarts := make([]map[string]any, 0, len(s.RestartAreas))
	for _, a := range s.RestartAreas {
		clients := make([]map[string]any, 0, len(a.Clients))
		for _, c := range a.Clients {
			clients = append(clients, map[string]any{
				"name": c.Name, "oldest_lsn": c.OldestLSN,
				"client_restart_lsn": c.ClientRestartLSN, "sequence_number": c.SequenceNumber,
			})
		}
		restarts = append(restarts, map[string]any{
			"page_offset":            a.PageOffset,
			"signature":              a.Signature,
			"version":                fmt.Sprintf("%d.%d", a.MajorVersion, a.MinorVersion),
			"current_lsn":            a.CurrentLSN,
			"chkdsk_lsn":             a.ChkdskLSN,
			"system_page_size":       a.SystemPageSize,
			"log_page_size":          a.LogPageSize,
			"log_file_size":          a.FileSize,
			"sequence_number_bits":   a.SequenceBits,
			"log_record_header_size": a.RecordHeaderLen,
			"log_page_data_offset":   a.LogPageDataOff,
			"restart_flags":          a.Flags,
			"clients":                clients,
			"warnings":               a.Warnings,
		})
	}
	blob, _ := json.Marshal(map[string]any{
		"parser":                parserName,
		"source_file":           source,
		"file_size":             s.FileSize,
		"log_page_size":         s.PageSize,
		"pages_scanned":         s.PagesScanned,
		"valid_pages":           s.ValidPages,
		"log_records_parsed":    s.RecordsParsed,
		"log_records_retained":  retained,
		"distinct_transactions": len(s.TransactionIDs),
		"lsn_range": map[string]any{
			"min": s.MinLSN, "max": s.MaxLSN,
		},
		"restart_areas":   restarts,
		"redo_operations": topOperations(s.RedoCounts),
		"undo_operations": topOperations(s.UndoCounts),
		"warnings":        s.Warnings,
		"timeline_events": 0,
		"why_no_timeline_events": "NTFS $LogFile records carry no timestamp field, and a log record describes a " +
			"byte-level metadata mutation rather than a file operation. Producing timeline events would require " +
			"borrowing a time the record does not contain and reconstructing operations that cannot be recovered " +
			"reliably from the log alone. The validated transaction metadata is recorded here instead.",
	})
	return string(blob)
}

// topOperations renders an operation tally in a stable order, so
// repeated parses of the same log produce byte-identical output.
func topOperations(counts map[string]int) []map[string]any {
	names := make([]string, 0, len(counts))
	for n := range counts {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool {
		if counts[names[i]] != counts[names[j]] {
			return counts[names[i]] > counts[names[j]]
		}
		return names[i] < names[j]
	})
	out := make([]map[string]any, 0, len(names))
	for _, n := range names {
		out = append(out, map[string]any{"operation": n, "count": counts[n]})
	}
	return out
}
