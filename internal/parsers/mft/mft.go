// Package mft turns NTFS $MFT records into normalized filesystem events.
//
// It reads the table via internal/ntfs and emits one event per RECORDED
// TIMESTAMP, not one per file: NTFS keeps four independent times per
// record and each is a separate observation about the file. A single
// "filesystem" event carrying four time fields would be unfilterable and
// unplottable, which is the opposite of what a timeline is for.
//
// # What is asserted, and what is not
//
// These events are statements about the FILESYSTEM's record of a file.
// NTFS records no user, no process and no parent process, so those
// fields are left empty -- inventing them from a path (guessing a user
// from \Users\jdoe\, say) would fabricate forensic facts that the
// evidence does not contain.
//
// Nothing here is a finding. A file existing in the MFT is not
// suspicious; it is the normal state of every file on the volume.
// Detection and correlation consume these events downstream and reach
// their own conclusions.
//
// # Volume
//
// A real $MFT holds hundreds of thousands of records, and four events
// each would overwhelm both the database and the analyst. The parser is
// therefore bounded by an explicit event ceiling and reports, as a
// parser warning, exactly how much of the table it covered. Truncating
// loudly is the honest option; silently emitting a partial timeline
// dressed as a complete one is not.
package mft

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/ntfs"
	"tracefall/internal/parsers"
)

const parserName = "ntfs_mft@1"

// DefaultMaxEvents bounds how many filesystem events one $MFT may
// contribute. At four events per record this covers 50,000 files, which
// is a substantial volume's worth of timeline; beyond it the parser
// stops and says so.
const DefaultMaxEvents = 200_000

// Parser implements parsers.ArtifactParser and parsers.ContentDetector.
type Parser struct {
	limits    ntfs.Limits
	maxEvents int
	// cancelled is consulted between records so a long table can be
	// stopped. Set by WithCancellation; nil means never cancelled.
	cancelled func() bool
}

func New() *Parser {
	return &Parser{limits: ntfs.DefaultLimits(), maxEvents: DefaultMaxEvents}
}

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactMFT }

// Detect matches the $MFT by name.
//
// Deliberately narrow. "$MFT" is a reserved NTFS metafile name, so a
// file called that is one; matching anything broader -- every file under
// a volume root, say -- would classify ordinary files as the master file
// table and put invented filesystem events on a timeline. Content
// detection catches a table collected under another name.
func (Parser) Detect(relPath string) bool {
	base := strings.ToLower(filepath.Base(relPath))
	return base == "$mft" || base == "$mft.copy0" || base == "mft" ||
		strings.HasSuffix(base, ".mft")
}

// DetectContent identifies an $MFT by the structure of its first record,
// so a table renamed during collection is still found. ntfs.Sniff is
// strict about self-consistency for exactly this reason.
func (Parser) DetectContent(header []byte) bool { return ntfs.Sniff(header) }

// Parse reads one $MFT and emits filesystem events.
func (p Parser) Parse(absPath string) (parsers.ParseResult, error) {
	// Pass one: index directories so paths can be reconstructed.
	//
	// Two passes, because a file's parent directory record may appear
	// anywhere in the table -- including after the file itself -- and
	// only directories are retained, which is what keeps the index
	// bounded on a large volume.
	index, err := ntfs.BuildDirectoryIndex(absPath, ntfs.ScanOptions{
		Limits: p.limits, Cancelled: p.cancelled,
	})
	if err != nil {
		return parsers.ParseResult{}, fmt.Errorf("ntfs: indexing directories: %w", err)
	}

	source := filepath.Base(absPath)
	var out parsers.ParseResult
	var (
		records, skippedSlack, withWarnings int
		truncated                           bool
		warnings                            []string
	)

	serr := ntfs.Scan(absPath, ntfs.ScanOptions{Limits: p.limits, Cancelled: p.cancelled}, func(r ntfs.Record) error {
		records++
		if len(r.Warnings) > 0 {
			withWarnings++
			// Keep a bounded sample: an examiner needs to know warnings
			// occurred and see examples, not read a hundred thousand.
			if len(warnings) < 25 {
				name := "<unnamed>"
				if n, ok := r.BestName(); ok {
					name = n.Name
				}
				warnings = append(warnings,
					fmt.Sprintf("record %d (%s): %s", r.RecordNumber, name, strings.Join(r.Warnings, "; ")))
			}
		}
		// An extension record has no independent identity; its
		// timestamps belong to its base record and emitting them again
		// would double-count the same file.
		if !r.IsBaseRecord() {
			return nil
		}
		name, ok := r.BestName()
		if !ok {
			skippedSlack++
			return nil
		}
		if !r.HasSI || !r.SI.Any() {
			// No usable time means no point on a timeline. The record is
			// counted, not invented.
			skippedSlack++
			return nil
		}
		if len(out.Events) >= p.maxEvents {
			truncated = true
			return nil
		}

		fullPath, complete := index.Path(name.ParentRef, name.Name)
		events, raw := p.eventsFor(r, name, fullPath, complete, source)
		out.Events = append(out.Events, events...)
		out.Raw = append(out.Raw, raw...)
		return nil
	})
	if serr != nil {
		return parsers.ParseResult{}, fmt.Errorf("ntfs: %w", serr)
	}

	if truncated {
		warnings = append(warnings, fmt.Sprintf(
			"the event ceiling of %d was reached; %d records were read and the timeline covers only the records before that point",
			p.maxEvents, records))
	}
	_ = withWarnings
	if len(warnings) > 0 {
		// Warnings ride on the raw evidence record so they are stored
		// with the collection rather than only logged.
		blob, _ := json.Marshal(map[string]any{
			"parser":                              parserName,
			"source_file":                         source,
			"records_read":                        records,
			"records_with_warnings":               withWarnings,
			"records_without_usable_time_or_name": skippedSlack,
			"truncated":                           truncated,
			"warnings":                            warnings,
		})
		out.Raw = append(out.Raw, model.RawEvidence{
			SourceReference: "mft:parse-report",
			Raw:             string(blob),
		})
	}
	return out, nil
}

// timestampKind pairs an NTFS timestamp with the event type that says
// what it means. Ordered so a file's own history reads chronologically
// in the common case.
type timestampKind struct {
	at        time.Time
	eventType string
	label     string
}

// eventsFor turns one record into up to four events.
func (p Parser) eventsFor(r ntfs.Record, name ntfs.FileName, fullPath string, pathComplete bool, source string) ([]model.Event, []model.RawEvidence) {
	kinds := []timestampKind{
		{r.SI.Created, model.EventFilesystemCreated, "created"},
		{r.SI.Modified, model.EventFilesystemModified, "modified"},
		{r.SI.Changed, model.EventFilesystemChanged, "changed"},
		{r.SI.Accessed, model.EventFilesystemAccessed, "accessed"},
	}

	base := map[string]string{
		"mft_record_number":   strconv.FormatUint(r.RecordNumber, 10),
		"mft_sequence_number": strconv.FormatUint(uint64(r.SequenceNumber), 10),
		// The full file reference, which is what uniquely identifies a
		// file over time -- a record number alone is reused.
		"mft_file_reference":  fmt.Sprintf("%d-%d", r.RecordNumber, r.SequenceNumber),
		"filesystem":          "NTFS",
		"timestamp_source":    "$STANDARD_INFORMATION",
		"file_name":           name.Name,
		"file_name_namespace": ntfs.NamespaceLabel(name.Namespace),
		"parent_mft_record":   strconv.FormatUint(name.ParentRef, 10),
		"allocation_state":    allocationState(r),
		"record_type":         recordType(r),
		"mft_source_file":     source,
	}
	// What this row does and does not show. $STANDARD_INFORMATION times are
	// writable by ordinary software, so they are an observation of what the
	// table says, not proof of when something happened.
	caveat := "These times are the filesystem's own record: $STANDARD_INFORMATION times can be set by software (timestomping), so they are what the table says, not proof of when the event happened; $FILE_NAME times are context for comparison, not separate events."
	if !r.InUse {
		caveat += " This record is marked free (not in use): a free record is not a deletion instant and is not a statement that, or when, the file was removed."
	}
	base["evidence_caveat"] = caveat
	if !pathComplete {
		base["path_resolution"] = "incomplete: the parent directory chain could not be walked to the volume root"
	}
	if r.HardLinkCount > 0 {
		base["hard_link_count"] = strconv.FormatUint(uint64(r.HardLinkCount), 10)
	}
	if r.SizeKnown {
		base["file_size_bytes"] = strconv.FormatUint(r.LogicalSize, 10)
		base["allocated_size_bytes"] = strconv.FormatUint(r.PhysicalSize, 10)
		if r.DataResident {
			base["data_residency"] = "resident (content stored inside the MFT record)"
		} else {
			base["data_residency"] = "non-resident"
		}
	}
	if r.HasAttributeList {
		base["attribute_list"] = "present: this record's attributes overflow into extension records, so its size and name set may be incomplete"
	}
	// $FILE_NAME's own timestamps, carried as CONTEXT rather than as
	// separate events. They are what a $SI comparison is made against;
	// emitting them as four more timeline points would double every
	// file, while dropping them would discard the comparison entirely.
	if name.Times.Any() {
		base["fn_created"] = fmtTime(name.Times.Created)
		base["fn_modified"] = fmtTime(name.Times.Modified)
		base["fn_changed"] = fmtTime(name.Times.Changed)
		base["fn_accessed"] = fmtTime(name.Times.Accessed)
	}
	if len(r.Names) > 1 {
		var others []string
		for _, n := range r.Names {
			if n.Name != name.Name {
				others = append(others, fmt.Sprintf("%s [%s]", n.Name, ntfs.NamespaceLabel(n.Namespace)))
			}
		}
		sort.Strings(others)
		base["other_file_names"] = strings.Join(others, "; ")
	}
	if len(r.Warnings) > 0 {
		base["parse_warnings"] = strings.Join(r.Warnings, "; ")
	}

	var events []model.Event
	var raws []model.RawEvidence
	for _, k := range kinds {
		if k.at.IsZero() {
			continue
		}
		extra := make(map[string]string, len(base)+1)
		for key, v := range base {
			extra[key] = v
		}
		extra["timestamp_meaning"] = timestampMeaning(k.label)

		ref := fmt.Sprintf("mft:%d-%d:%s", r.RecordNumber, r.SequenceNumber, k.label)
		// ONE raw record per event, keyed by the SAME source reference.
		//
		// The import pairs an event to its raw evidence by this string
		// (see Service.EventProvenance, which resolves through
		// Event.RawEvidenceID). Emitting a single record-level raw and
		// four events pointing at a reference it does not carry left
		// every filesystem event with unresolvable provenance -- the
		// detail panel reported an internal error. The record JSON is
		// therefore repeated per timestamp, exactly as the Prefetch
		// parser repeats a file's detail across its retained runs.
		raws = append(raws, model.RawEvidence{
			SourceReference: ref,
			Raw:             recordBlob(r, name, fullPath, pathComplete, k.label),
		})
		ev := model.Event{
			Timestamp:    k.at.UTC(),
			EventType:    k.eventType,
			ArtifactType: model.ArtifactMFT,
			Parser:       parserName,
			// FilePath carries the reconstructed path, matching how the
			// other parsers use the field.
			FilePath: fullPath,
			// Host, User, ProcessName and the rest are deliberately
			// EMPTY. NTFS records none of them, and deriving a user from
			// a path would be a guess presented as evidence.
			//
			// $MFT timestamps are reliable filesystem metadata, but they
			// are also the most commonly forged artifact on a volume --
			// hence 0.8 rather than the 0.9 an execution artifact gets.
			Confidence:      0.8,
			SourceReference: ref,
			Extra:           extra,
		}
		events = append(events, ev)
	}
	return events, raws
}

// recordBlob renders the full record behind one event. It names which
// timestamp this event represents, so the raw evidence is self-describing
// rather than four identical copies.
func recordBlob(r ntfs.Record, name ntfs.FileName, fullPath string, pathComplete bool, which string) string {
	blob, _ := json.Marshal(map[string]any{
		"mft_record_number":     r.RecordNumber,
		"mft_sequence_number":   r.SequenceNumber,
		"event_timestamp_field": which,
		"path":                  fullPath,
		"path_complete":         pathComplete,
		"in_use":                r.InUse,
		"is_directory":          r.IsDirectory,
		"hard_link_count":       r.HardLinkCount,
		"best_name":             name.Name,
		"standard_information": map[string]string{
			"created": fmtTime(r.SI.Created), "modified": fmtTime(r.SI.Modified),
			"changed": fmtTime(r.SI.Changed), "accessed": fmtTime(r.SI.Accessed),
		},
		"file_names": fileNameBlobs(r.Names),
		"size":       sizeBlob(r),
		"warnings":   r.Warnings,
	})
	return string(blob)
}

func fileNameBlobs(names []ntfs.FileName) []map[string]any {
	out := make([]map[string]any, 0, len(names))
	for _, n := range names {
		out = append(out, map[string]any{
			"name": n.Name, "namespace": ntfs.NamespaceLabel(n.Namespace),
			"parent_record": n.ParentRef,
			"created":       fmtTime(n.Times.Created), "modified": fmtTime(n.Times.Modified),
			"changed": fmtTime(n.Times.Changed), "accessed": fmtTime(n.Times.Accessed),
		})
	}
	return out
}

func sizeBlob(r ntfs.Record) map[string]any {
	if !r.SizeKnown {
		return map[string]any{"known": false}
	}
	return map[string]any{
		"known": true, "logical": r.LogicalSize, "allocated": r.PhysicalSize,
		"resident": r.DataResident,
	}
}

func allocationState(r ntfs.Record) string {
	if r.InUse {
		return "in use"
	}
	// "Not in use" is what the filesystem records. Whether the file was
	// deleted, or the record was simply never committed, is not
	// something the MFT states -- so neither does this.
	return "not in use (record marked free)"
}

func recordType(r ntfs.Record) string {
	if r.IsDirectory {
		return "directory"
	}
	return "file"
}

func timestampMeaning(label string) string {
	switch label {
	case "created":
		return "$STANDARD_INFORMATION creation time as recorded (the attribute user-level tools can change; not proof of when the file first existed)"
	case "modified":
		return "$STANDARD_INFORMATION modification time as recorded (the attribute user-level tools can change; not proof of when content was last written)"
	case "changed":
		return "$STANDARD_INFORMATION MFT change time (record metadata last changed)"
	case "accessed":
		return "$STANDARD_INFORMATION access time (may be disabled by policy on the volume)"
	}
	return label
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02T15:04:05.9999999Z")
}
