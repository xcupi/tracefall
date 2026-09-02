// Package recyclebin turns Windows Recycle Bin $I metadata records into
// normalized evidence.
//
// # What this parser asserts
//
// That a file with a given original path and size was moved to the
// Recycle Bin at a recorded moment. That is the whole claim.
//
// It is NOT the file's last-write time, NOT its creation time, and NOT
// evidence that anything ran. The event type says "deletion" and the
// record says so in words, because a deletion timestamp read as a
// modification time would misdate an entire reconstruction.
//
// # $I is not $R
//
// The content of the deleted file lives in the paired $R file, which
// this parser never opens. Where the $R file is present beside the $I
// record in the collection, that pairing is reported as an observation
// about the evidence -- "the paired file was collected, at this size" --
// and never as a claim about the content. Where it is absent, the record
// says which file WOULD pair rather than implying anything about it.
package recyclebin

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
	rb "tracefall/internal/recyclebin"
)

const parserName = "recyclebin@1"

// Parser implements parsers.ArtifactParser and parsers.ContentDetector.
type Parser struct {
	limits rb.Limits
}

func New() *Parser { return &Parser{limits: rb.DefaultLimits()} }

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactRecycleBin }

// Detect deliberately matches NOTHING by filename.
//
// A "$I" prefix is not evidence that a file is a metadata record --
// anything can be named that, and a record carried out of an image may
// arrive renamed. Claiming files by prefix would also classify a
// mislabelled file as supported and then fail to parse it, reporting a
// parse failure where the honest answer is "this is not an $I record".
// Detection is structural only; see DetectContent.
func (Parser) Detect(string) bool { return false }

// DetectContent identifies a record by its version word, a plausible
// deletion FILETIME, and a path field that begins like a Windows path --
// all three together, because no one of them is distinctive alone.
func (Parser) DetectContent(header []byte) bool { return rb.Sniff(header) }

// Parse reads one $I record.
func (p Parser) Parse(absPath string) (parsers.ParseResult, error) {
	rec, err := rb.ParseFile(absPath, p.limits)
	if err != nil {
		return parsers.ParseResult{}, fmt.Errorf("recyclebin: %w", err)
	}
	sourceName := filepath.Base(absPath)
	pair := rb.ResolvePair(absPath)

	extra := map[string]string{
		"recycle_bin_record": sourceName,
		"source_file":        sourceName,
		"record_version":     strconv.FormatUint(rec.Version, 10),
		"record_version_name": map[uint64]string{
			rb.Version1: "version 1 (Windows Vista - 8.1)",
			rb.Version2: "version 2 (Windows 10 and later)",
		}[rec.Version],
		"original_path": rec.OriginalPath,
		"original_name": rec.OriginalName(),
		"original_size": strconv.FormatUint(rec.OriginalSize, 10),
		// Stated on EVERY record, because a deletion time read as a
		// write time would misdate a whole reconstruction.
		"evidence_meaning": "Recycle Bin metadata: this file was moved to the Recycle Bin at the recorded time. " +
			"That time is NOT the file's last-write or creation time, and this record is NOT evidence that the " +
			"file was executed. The deleted content is in the paired $R file, which Tracefall does not read.",
		"artifact_class": "Recycle Bin metadata ($I record)",
	}
	if dir := rec.OriginalDirectory(); dir != "" {
		extra["original_directory"] = dir
	}
	// The per-user Recycle Bin directory is named for the owning SID.
	// Recorded verbatim as a PATH COMPONENT, not resolved to an account:
	// mapping a SID to a username needs the registry, and guessing would
	// attribute a deletion to the wrong person.
	if sid := sidFromPath(absPath); sid != "" {
		extra["recycle_bin_sid"] = sid
	}
	// The $R pairing, stated as what it is in each case.
	if pair.Name != "" {
		extra["paired_r_file"] = pair.Name
		if pair.Found {
			extra["paired_r_file_status"] = "present in this collection"
			extra["paired_r_file_size"] = strconv.FormatInt(pair.SizeBytes, 10)
		} else {
			extra["paired_r_file_status"] = "not present in this collection; the deleted content was not collected here"
		}
	}
	if len(rec.Warnings) > 0 {
		extra["parse_warnings"] = strings.Join(rec.Warnings, "; ")
	}

	raw, _ := json.Marshal(map[string]any{
		"i_file":              sourceName,
		"record_version":      rec.Version,
		"original_path":       rec.OriginalPath,
		"original_name":       rec.OriginalName(),
		"original_directory":  rec.OriginalDirectory(),
		"original_size_bytes": rec.OriginalSize,
		"deletion_time":       timeOrNil(rec.DeletionTime),
		"declared_path_chars": rec.PathChars,
		"recycle_bin_sid":     sidFromPath(absPath),
		"paired_r_file":       pairJSON(pair),
		"content_extracted":   false,
		"warnings":            rec.Warnings,
		"evidence_meaning": "Recycle Bin deletion metadata; the timestamp is the deletion time, " +
			"not a write or execution time",
	})

	// One event: an $I record carries exactly one timestamp.
	if rec.DeletionTime.IsZero() {
		// A record whose deletion time is absent or implausible still
		// names a path and a size. It is kept as structured evidence
		// rather than placed on a timeline with an invented time.
		return parsers.ParseResult{Raw: []model.RawEvidence{{
			SourceReference: "recyclebin:metadata",
			Raw:             string(raw),
		}}}, nil
	}

	evExtra := make(map[string]string, len(extra)+2)
	for k, v := range extra {
		evExtra[k] = v
	}
	evExtra["timestamp_meaning"] = "Recycle Bin deletion time"
	evExtra["timestamp_source"] = "$I record DeletionTime (Windows FILETIME)"

	ref := "recyclebin:" + sourceName
	return parsers.ParseResult{
		Events: []model.Event{{
			Timestamp:    rec.DeletionTime.UTC(),
			EventType:    model.EventRecycleBinDeletion,
			ArtifactType: model.ArtifactRecycleBin,
			Parser:       parserName,
			// FilePath is the file that was deleted -- the subject of the
			// event -- which is what makes this row searchable by the
			// path an investigator actually knows.
			FilePath: rec.OriginalPath,
			// No User: the per-user Recycle Bin directory is named for a
			// SID, and mapping that to an account needs the registry.
			// The SID is preserved verbatim below instead.
			//
			// 1.0: the record states the deletion time directly. Unlike a
			// cache or a shortcut, there is no inference between the
			// artifact and the claim.
			Confidence:      1.0,
			SourceReference: ref,
			Extra:           evExtra,
		}},
		Raw: []model.RawEvidence{{SourceReference: ref, Raw: string(raw)}},
	}, nil
}

// sidFromPath returns the owning SID from a $Recycle.Bin path, when the
// collection preserved the directory structure. It matches the SID's own
// documented shape rather than "any directory above the file", so an
// unrelated path never yields one.
func sidFromPath(path string) string {
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if strings.HasPrefix(part, "S-1-") && strings.Count(part, "-") >= 3 {
			return part
		}
	}
	return ""
}

func pairJSON(p rb.PairedRFile) any {
	if p.Name == "" {
		return nil
	}
	m := map[string]any{"name": p.Name, "present_in_collection": p.Found}
	if p.Found {
		m["size_bytes"] = p.SizeBytes
	}
	return m
}

func timeOrNil(t interface{ IsZero() bool }) any {
	type formatter interface{ Format(string) string }
	if t.IsZero() {
		return nil
	}
	if f, ok := t.(formatter); ok {
		return f.Format("2006-01-02T15:04:05Z")
	}
	return nil
}
