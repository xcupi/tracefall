// Package prefetchraw parses raw Windows Prefetch (.pf) files into
// normalized events, reading the binary format directly via
// internal/prefetch rather than depending on PECmd having been run.
//
// Both container forms are read: an uncompressed SCCA file and a Windows
// 10/11 MAM (LZXPRESS Huffman) compressed one produce identical events
// for identical content -- decompression happens inside
// internal/prefetch and is invisible here, which is what keeps a single
// normalization path.
//
// It normalizes to the SAME event type, artifact type and field shape
// the PECmd CSV parser produces (internal/parsers/pecmd), so the same
// execution reported by either source describes one event rather than
// two -- the precedent set by internal/parsers/winevent for event logs.
//
// One event is emitted per RECORDED EXECUTION, not per file. A Windows 8
// or later Prefetch file retains up to eight execution times, and each is
// a distinct observed run: collapsing them into one event would discard
// seven real observations, and emitting a single event with a list would
// leave seven executions off the timeline.
package prefetchraw

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
	"tracefall/internal/prefetch"
)

const parserName = "prefetch@1"

// Parser implements parsers.ArtifactParser and parsers.ContentDetector
// for raw .pf files.
type Parser struct {
	limits prefetch.Limits
}

func New() *Parser { return &Parser{limits: prefetch.DefaultLimits()} }

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactPrefetch }

// Detect matches the .pf extension -- the fast path only. A .pf that is
// not really Prefetch is rejected at parse time, and a Prefetch file
// under another name is still found by DetectContent.
func (Parser) Detect(relPath string) bool {
	return strings.HasSuffix(strings.ToLower(filepath.Base(relPath)), ".pf")
}

// DetectContent identifies Prefetch by its SCCA signature.
//
// It deliberately does NOT accept a bare MAM container. MAM is a general
// Windows compression wrapper, not a Prefetch format: the application
// compatibility databases that sit in the very same directory
// (AgGlGlobalHistory.db, ResPriHMStaticDb.ebd and their siblings) use
// it too. Accepting MAM here catalogued seven of those as Prefetch in
// one real image and failed every one with "unsupported compression
// method" -- a message about files that were never Prefetch.
//
// A compressed Prefetch file is still recognized: by its .pf name, via
// Detect, confirmed by ConfirmContent below.
func (Parser) DetectContent(header []byte) bool { return prefetch.SniffUncompressed(header) }

// ConfirmContent backs the .pf name match with the bytes, so a file that
// merely carries the extension is not claimed and then reported as
// broken Prefetch. Either container is accepted here -- what is INSIDE a
// MAM container is checked after decompression, which is the only place
// it can be.
func (Parser) ConfirmContent(header []byte) bool { return prefetch.Sniff(header) }

// Parse reads one .pf file and emits an event per recorded execution.
func (p Parser) Parse(absPath string) (parsers.ParseResult, error) {
	pf, err := prefetch.Parse(absPath, p.limits)
	if err != nil {
		return parsers.ParseResult{}, fmt.Errorf("prefetch: %w", err)
	}

	// A Prefetch file with no usable execution time cannot be placed on
	// a timeline. Rather than invent one (the file's own mtime is when it
	// was COLLECTED, not when the program ran), the file is reported as
	// producing no events -- the same rule every other parser follows.
	if len(pf.LastRunTimes) == 0 {
		return parsers.ParseResult{}, nil
	}

	exe := strings.ToLower(strings.TrimSpace(pf.ExecutableName))
	sourceName := filepath.Base(absPath)

	var out parsers.ParseResult
	for i, runAt := range pf.LastRunTimes {
		extra := map[string]string{
			"prefetch_version":      strconv.FormatUint(uint64(pf.Version), 10),
			"prefetch_hash":         fmt.Sprintf("%08X", pf.PrefetchHash),
			"run_count":             strconv.FormatUint(uint64(pf.RunCount), 10),
			"prefetch_source_file":  sourceName,
			"executable_name":       pf.ExecutableName,
			"recorded_run_index":    strconv.Itoa(i),
			"recorded_runs_in_file": strconv.Itoa(len(pf.LastRunTimes)),
		}
		if pf.ExecutablePath != "" {
			extra["executable_path"] = pf.ExecutablePath
		}
		// How the evidence was STORED, recorded additively so existing
		// consumers are unaffected. It is chain-of-custody detail, not a
		// judgement: a Windows 10/11 host compresses every Prefetch file,
		// so this says nothing whatsoever about the program that ran and
		// nothing downstream treats it as a signal.
		if pf.Compressed {
			extra["prefetch_container"] = "MAM (LZXPRESS Huffman)"
			extra["prefetch_compressed_bytes"] = strconv.Itoa(pf.CompressedSize)
			extra["prefetch_uncompressed_bytes"] = strconv.Itoa(pf.UncompressedSize)
		}
		if len(pf.Filenames) > 0 {
			// Extra is triage metadata, not a blob store: the count plus a
			// bounded sample, with the complete list preserved in the raw
			// evidence record. This mirrors what the PECmd parser keeps.
			extra["files_loaded_count"] = strconv.Itoa(len(pf.Filenames))
			extra["files_loaded_sample"] = truncateList(pf.Filenames, 500)
		}
		if len(pf.Volumes) > 0 {
			extra["volume_device_path"] = pf.Volumes[0].DevicePath
			extra["volume_serial"] = fmt.Sprintf("%08X", pf.Volumes[0].SerialNumber)
			if !pf.Volumes[0].CreationTime.IsZero() {
				extra["volume_created"] = pf.Volumes[0].CreationTime.UTC().Format("2006-01-02T15:04:05Z")
			}
		}
		if i > 0 {
			// Only the newest entry is the "last run"; the rest are
			// earlier retained executions, and saying so prevents them
			// being read as seven separate most-recent runs.
			extra["run_position"] = "earlier retained execution"
		}

		ev := model.Event{
			Timestamp:   runAt.UTC(),
			EventType:   model.EventPrefetchExecution,
			ProcessName: exe,
			ProcessPath: pf.ExecutablePath,
			// FilePath carries the artifact this event came from, matching
			// the PECmd parser's field usage.
			FilePath:     sourceName,
			ArtifactType: model.ArtifactPrefetch,
			Parser:       parserName,
			// Prefetch records that a program ran at approximately this
			// time; it is not an exact execution timestamp. The same 0.9
			// the PECmd parser uses, for the same reason.
			Confidence:      0.9,
			SourceReference: "run:" + strconv.Itoa(i),
			Extra:           extra,
		}

		rawJSON, _ := json.Marshal(map[string]any{
			"version":         pf.Version,
			"executable_name": pf.ExecutableName,
			"executable_path": pf.ExecutablePath,
			"prefetch_hash":   fmt.Sprintf("%08X", pf.PrefetchHash),
			"run_count":       pf.RunCount,
			"run_time":        runAt.UTC(),
			"all_run_times":   pf.LastRunTimes,
			"filenames":       pf.Filenames,
			"volumes":         pf.Volumes,
		})
		out.Events = append(out.Events, ev)
		out.Raw = append(out.Raw, model.RawEvidence{SourceReference: ev.SourceReference, Raw: string(rawJSON)})
	}
	return out, nil
}

// truncateList joins values, bounding the result so one artifact cannot
// put an unbounded string into Extra.
func truncateList(values []string, max int) string {
	joined := strings.Join(values, "; ")
	if len(joined) <= max {
		return joined
	}
	return joined[:max] + "..."
}
