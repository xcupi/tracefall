// Package recyclebincontent turns a Windows Recycle Bin $R file -- the
// CONTENT of a deleted file -- into normalized evidence.
//
// # The one artifact that describes nothing about itself
//
// Every other artifact Tracefall parses is self-describing: an event log
// declares its records, a shortcut its target, an $I record its path and
// deletion time. A $R file declares nothing. It is a byte-for-byte copy
// of whatever the deleted file was, renamed to an identifier. Its name
// is not the deleted file's name, its extension is carried over but its
// stem is not, and it holds no timestamp, no path and no header.
//
// So every fact this parser reports about WHAT the content is comes from
// the paired $I record, and every fact about the content ITSELF -- its
// size on disk, its hash -- is measured here. The two are kept in
// separate fields with separate provenance, and nothing is copied from
// one into the other:
//
//	from the $I record   original_path, original_name, deletion_time,
//	                     original_size, record_version, the SID
//	measured from $R     recovered_size, recovered_sha256
//
// # What "recovered" means, and when it is not claimed
//
// It means the bytes were read to completion and hashed. It is not
// claimed when the file could not be opened, could not be read through,
// or was above the hashing ceiling -- each of those is reported as its
// own status with no digest attached, because a hash of a partial read
// identifies nothing an examiner could verify.
//
// # No timeline event
//
// The deletion already has one, emitted by the $I parser from the
// timestamp the $I record actually carries. A $R file records no time of
// its own, and borrowing the $I's to place a second row at the same
// moment would put one deletion on the timeline twice. This parser
// therefore produces structured evidence and no events -- the recovered
// content is an attribute of a deletion, not a separate moment in it.
package recyclebincontent

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
	rb "tracefall/internal/recyclebin"
)

const parserName = "recyclebincontent@1"

// maxHashBytes bounds what will be read to produce a hash. A deleted
// file can be arbitrarily large; above this its size is recorded and its
// content is left alone rather than streaming a multi-gigabyte read
// during a triage import.
const maxHashBytes = 2 << 30 // 2 GiB

// Parser implements parsers.ArtifactParser.
type Parser struct {
	limits rb.Limits
}

func New() *Parser { return &Parser{limits: rb.DefaultLimits()} }

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactRecycleBinContent }

// Detect matches the $R naming rule inside a Recycle Bin directory.
//
// This is the one artifact in Tracefall that CANNOT be content-detected,
// and not for want of trying: a $R file's content is the deleted file's
// content, so it has whatever signature that file had -- a PDF header, a
// PE header, nothing at all. Detecting it by content would mean claiming
// every PDF in a collection.
//
// What identifies it is its position and its name, both of which the
// format defines exactly: a "$R" prefix, in a $Recycle.Bin or RECYCLER
// directory. The claim is then VALIDATED at parse time by resolving and
// parsing the paired $I record -- so a file wearing the name without the
// pairing is reported as an orphan rather than presented as a recovered
// deleted file. See Parse.
func (Parser) Detect(relPath string) bool {
	lower := strings.ToLower(filepath.ToSlash(relPath))
	if !strings.Contains(lower, "$recycle.bin/") && !strings.Contains(lower, "recycler/") {
		return false
	}
	base := filepath.Base(lower)
	// "$R" alone is not a pair identifier; a real one carries the
	// identifier that ties it to its $I.
	return strings.HasPrefix(base, "$r") && len(base) > 2
}

// DetectContent always returns false. See Detect: a $R file's bytes are
// the deleted file's bytes and identify nothing about the artifact.
func (Parser) DetectContent([]byte) bool { return false }

// Parse resolves a $R file's metadata from its paired $I record and
// measures its content.
//
// It never returns an error for a $R file that is genuinely a $R file.
// A missing pair, an unreadable pair and an unreadable content file are
// all real, distinct forensic findings about the evidence, and each is
// recorded as such -- reporting them as parse failures would file a
// truthful observation under "Tracefall could not read this".
func (p Parser) Parse(absPath string) (parsers.ParseResult, error) {
	sourceName := filepath.Base(absPath)

	// The content: measured here, from this file, and nowhere else.
	content := rb.ReadContent(absPath, maxHashBytes)
	// The metadata: resolved from the paired $I, and nowhere else.
	pair := rb.ResolveIRecord(absPath, p.limits)

	warnings := append([]string(nil), content.Warnings...)
	status := "orphan"

	switch {
	case pair.Valid():
		status = "resolved"
		rec := pair.Record
		if rec.DeletionTime.IsZero() {
			warnings = append(warnings,
				"the paired $I record carried no usable deletion time, so this content has no recorded deletion moment")
		}
		// Size comparison: both values kept, neither adjusted. Only
		// meaningful where the file was actually measured.
		if content.Status == rb.ContentRecovered || content.Status == rb.ContentTooLarge {
			if _, warning := rb.CompareSize(rec.OriginalSize, content.SizeBytes); warning != "" {
				warnings = append(warnings, warning)
			}
		}
		warnings = append(warnings, rec.Warnings...)

	case pair.Found:
		// The $I is there and is not a record. The content is real; its
		// identity is not recoverable, and that is what gets reported.
		status = "invalid"
		warnings = append(warnings, "the paired $I file is present but could not be read as a metadata record; "+
			"this file's original path, name and deletion time are not recoverable from the evidence collected")

	default:
		warnings = append(warnings, "no paired $I record was collected, so this file's original path, name and "+
			"deletion time are unknown; its content is present and hashed, and nothing about its identity is inferred")
	}

	sizeMatches := any(nil)
	if pair.Valid() && (content.Status == rb.ContentRecovered || content.Status == rb.ContentTooLarge) {
		matches, _ := rb.CompareSize(pair.Record.OriginalSize, content.SizeBytes)
		sizeMatches = matches
	}

	raw, _ := json.Marshal(map[string]any{
		"r_file":          sourceName,
		"artifact":        "Recycle Bin recovered content",
		"pairing_status":  status,
		"paired_i_file":   nilIfEmpty(pair.IName),
		"recycle_bin_sid": nilIfEmpty(sidFromPath(absPath)),
		// Measured from THIS file.
		"content": map[string]any{
			"status":         string(content.Status),
			"recovered_size": content.SizeBytes,
			"sha256":         nilIfEmpty(content.SHA256),
			"read_error":     nilIfEmpty(content.ReadError),
			"measured_from":  sourceName,
		},
		// Taken from the paired $I record. Null throughout when the
		// pairing did not resolve -- never guessed from the filename.
		"metadata": metadataJSON(pair),
		// Whether the size the deletion recorded matches what the
		// collection holds. Null when there is nothing to compare.
		"size_matches_record": sizeMatches,
		"warnings":            warnings,
		// The provenance statement, on every record. A $R file is the one
		// artifact whose every identifying fact is borrowed, and saying so
		// is what stops the borrowed facts being read as its own.
		"evidence_meaning": "recovered deleted content: this file holds the CONTENT of a file that was sent to " +
			"the Recycle Bin. It carries no metadata of its own -- the original path, name and deletion time " +
			"come from the paired $I record named above, and the size and SHA-256 under \"content\" are measured " +
			"from this file. This record is not evidence that anything was executed.",
	})

	// One record, no events. See the package comment.
	return parsers.ParseResult{
		Raw: []model.RawEvidence{{
			SourceReference: "recyclebin-content:" + sourceName,
			Raw:             string(raw),
		}},
	}, nil
}

func metadataJSON(p rb.PairedRecord) any {
	if !p.Valid() {
		return map[string]any{
			"resolved":      false,
			"source":        nilIfEmpty(p.IName),
			"why":           errString(p.Err),
			"original_path": nil,
			"deletion_time": nil,
			"original_size": nil,
		}
	}
	rec := p.Record
	return map[string]any{
		"resolved":           true,
		"source":             p.IName,
		"original_path":      rec.OriginalPath,
		"original_name":      rec.OriginalName(),
		"original_directory": nilIfEmpty(rec.OriginalDirectory()),
		"original_size":      rec.OriginalSize,
		"deletion_time":      timeOrNil(rec.DeletionTime),
		"record_version":     rec.Version,
	}
}

func errString(err error) any {
	if err == nil {
		return nil
	}
	return err.Error()
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
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

// sidFromPath returns the owning SID from a $Recycle.Bin path, matching
// the $I parser's rule exactly so the same fact reads the same way on
// both halves of a pair. A path component, never resolved to an account.
func sidFromPath(path string) string {
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if strings.HasPrefix(part, "S-1-") && strings.Count(part, "-") >= 3 {
			return part
		}
	}
	return ""
}
