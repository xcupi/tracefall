// Package ingest walks a KAPE-like evidence directory, detects which
// parser (if any) handles each file, and assembles the parsed output into
// case-scoped SourceFile/Event/RawEvidence records ready for storage.
// This is the only place parser output gets IDs and a CaseID stamped onto
// it -- parsers themselves stay case-agnostic and storage-agnostic.
package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
	"tracefall/internal/parsers/evtxcsv"
	"tracefall/internal/parsers/pecmd"
	"tracefall/internal/parsers/recmd"
	"tracefall/internal/parsers/scheduledtasks"
)

// Registry is the ordered list of known artifact parsers. Adding support
// for a new KAPE artifact means writing a parsers.ArtifactParser
// implementation and appending it here; ingestion, detection, and storage
// all work unmodified.
func Registry() []parsers.ArtifactParser {
	return []parsers.ArtifactParser{
		evtxcsv.New(),
		pecmd.New(),
		recmd.New(),
		scheduledtasks.New(),
	}
}

// Result is the full output of ingesting one evidence root directory.
type Result struct {
	SourceFiles []model.SourceFile
	Events      []model.Event
	Raw         []model.RawEvidence
	Skipped     []string    // relative paths that matched no parser
	Errors      []FileError // relative paths a matched parser failed on
}

type FileError struct {
	Path string
	Err  error
}

// Walk discovers every regular file under root, matches it against the
// parser registry (first match wins), and parses it. Files matching no
// parser are recorded in Result.Skipped rather than failing the ingest --
// a real KAPE package routinely contains far more files than Phase 1 has
// parsers for, and that's expected, not an error.
//
// collectionID identifies which of the case's evidence collections this
// walk belongs to (see internal/model.Collection) -- a case can be
// ingested from more than one KAPE package over time, and every
// SourceFile/Event this produces is stamped with it so later evidence
// can always be traced back to which collection it came from.
// Deduplicating events *across* collections is deliberately not this
// package's job: Walk has no visibility into what's already stored for
// the case, so that happens one layer up, in internal/api.Service.
func Walk(caseID, collectionID, root string, registry []parsers.ArtifactParser) (Result, error) {
	var res Result

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		relPath, relErr := filepath.Rel(root, path)
		if relErr != nil {
			relPath = path
		}
		relPath = filepath.ToSlash(relPath)

		var matched parsers.ArtifactParser
		for _, p := range registry {
			if p.Detect(relPath) {
				matched = p
				break
			}
		}
		if matched == nil {
			res.Skipped = append(res.Skipped, relPath)
			return nil
		}

		parsed, perr := matched.Parse(path)
		if perr != nil {
			res.Errors = append(res.Errors, FileError{Path: relPath, Err: perr})
			return nil
		}

		sf := model.SourceFile{
			ID:           uuid.NewString(),
			CaseID:       caseID,
			CollectionID: collectionID,
			Path:         relPath,
			ArtifactType: matched.ArtifactType(),
			Parser:       matched.Name(),
			RowCount:     len(parsed.Events),
			SHA256:       sha256File(path),
			IngestedAt:   time.Now().UTC(),
		}
		res.SourceFiles = append(res.SourceFiles, sf)

		for i := range parsed.Events {
			ev := parsed.Events[i]
			ev.ID = uuid.NewString()
			ev.CaseID = caseID
			ev.CollectionID = collectionID
			ev.SourceFileID = sf.ID

			if i < len(parsed.Raw) {
				raw := parsed.Raw[i]
				raw.ID = uuid.NewString()
				raw.CaseID = caseID
				raw.SourceFileID = sf.ID
				ev.RawEvidenceID = raw.ID
				res.Raw = append(res.Raw, raw)
			}

			res.Events = append(res.Events, ev)
		}
		return nil
	})
	if err != nil {
		return res, fmt.Errorf("ingest: walking %s: %w", root, err)
	}

	backfillHost(res.Events)
	return res, nil
}

// backfillHost fills in Host on events that don't carry one natively.
// Some artifact formats (Prefetch, registry hives) don't record a
// hostname at all -- Phase 1 assumes one KAPE evidence package
// corresponds to one host, so any event missing a host inherits the
// dominant host seen among events that do carry one (Windows Event Log
// records always do). Leaving Host blank instead would silently make
// host-scoped correlation (internal/correlate) match those events
// against each other by their shared emptiness rather than by any real
// evidence -- a multi-host case is a Phase 2 concern, noted in
// ARCHITECTURE.md.
func backfillHost(events []model.Event) {
	counts := map[string]int{}
	for _, e := range events {
		if e.Host != "" {
			counts[e.Host]++
		}
	}
	if len(counts) == 0 {
		return
	}
	var dominant string
	best := -1
	for host, n := range counts {
		if n > best || (n == best && host < dominant) {
			dominant, best = host, n
		}
	}
	for i := range events {
		if events[i].Host == "" {
			events[i].Host = dominant
		}
	}
}

func sha256File(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}
