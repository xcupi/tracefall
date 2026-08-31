// Package ingest walks a KAPE-like evidence directory, detects which
// parser (if any) handles each file, and assembles the parsed output into
// case-scoped SourceFile/Event/RawEvidence records ready for storage.
// This is the only place parser output gets IDs and a CaseID stamped onto
// it -- parsers themselves stay case-agnostic and storage-agnostic.
//
// Discovery and parsing are deliberately separate operations (see
// Discover and ParseFile below): internal/api.Service catalogs every file
// in a newly-added evidence package as soon as it's discovered, before
// parsing anything, so an investigator can select exactly which files
// become evidence -- see docs/data-model.md's "Evidence selection
// workflow" section for why.
package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/google/uuid"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
	"tracefall/internal/parsers/browserhistory"
	evtxnative "tracefall/internal/parsers/evtx"
	"tracefall/internal/parsers/evtxcsv"
	"tracefall/internal/parsers/pecmd"
	"tracefall/internal/parsers/prefetchraw"
	"tracefall/internal/parsers/pshistory"
	"tracefall/internal/parsers/recmd"
	"tracefall/internal/parsers/registry"
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
		// Phase 9: native Windows artifacts. Ordered after the EZ Tools
		// CSV parsers so a KAPE collection containing both an EvtxECmd
		// export and the .evtx it came from classifies each by its own
		// most specific match. Both of these also implement
		// parsers.ContentDetector, so they still find a hive or an event
		// log that arrives under an unrecognized name.
		evtxnative.New(),
		registry.New(),
		// Phase 10A. Ordered after the EZ Tools CSV parsers for the same
		// reason: a collection holding both PECmd output and the .pf it
		// came from classifies each by its own most specific match.
		prefetchraw.New(),
		pshistory.New(),
		browserhistory.New(),
	}
}

// DiscoveredFile is one file found while cataloging an evidence root --
// classified and hashed, but not yet parsed. See Discover.
type DiscoveredFile struct {
	Path         string // relative to the evidence root, forward-slash
	OriginalName string // basename
	ArtifactType string // "" if no parser recognizes this file
	Parser       string // "" if no parser recognizes this file
	Supported    bool
	SizeBytes    int64
	SHA256       string
}

// Discover walks every regular file under root and classifies each one
// against the parser registry (first match wins), without parsing any of
// them. This is the first phase of adding evidence: it produces the
// catalog an investigator selects from (see internal/api.Service's
// discovery methods) -- Parse/import happens later, only for the files
// actually selected, via ParseFile.
func Discover(root string, registry []parsers.ArtifactParser) ([]DiscoveredFile, error) {
	var out []DiscoveredFile
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
		// Nothing recognized the name. Native Windows artifacts are
		// identified by content instead -- a hive copied out of a triage
		// image may be called anything, and a .evtx extension proves
		// nothing about what is inside. See parsers.ContentDetector.
		if matched == nil {
			header := readHeader(path, parsers.SniffLength)
			if len(header) > 0 {
				for _, p := range registry {
					if cd, ok := p.(parsers.ContentDetector); ok && cd.DetectContent(header) {
						matched = p
						break
					}
				}
			}
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		df := DiscoveredFile{
			Path:         relPath,
			OriginalName: filepath.Base(relPath),
			SizeBytes:    info.Size(),
			SHA256:       sha256File(path),
		}
		if matched != nil {
			df.ArtifactType = matched.ArtifactType()
			df.Parser = matched.Name()
			df.Supported = true
		}
		out = append(out, df)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("ingest: discovering %s: %w", root, err)
	}
	return out, nil
}

// ParsedFile is the result of parsing exactly one already-discovered
// file -- the events/raw records it produced, ready for deduplication
// and storage.
type ParsedFile struct {
	Events []model.Event
	Raw    []model.RawEvidence
}

// ParseFile parses one file at root/relPath with p, stamping every
// resulting Event/RawEvidence with caseID/collectionID/sourceFileID.
//
// It deliberately does NOT fill in a missing Host. Some artifact formats
// (Prefetch, registry hives) never record a hostname at all, so their
// events arrive here blank -- but this function only ever sees ONE file,
// which is not enough context to resolve that correctly: the host is
// usually only knowable from a sibling file in the same collection (an
// EvtxECmd CSV, say). Deciding it here would make the result depend on
// which file happened to be parsed first. Host resolution is therefore
// the ingestion/service layer's job, done once per import batch over the
// complete picture -- see internal/api.Service.enrichBatchHosts.
func ParseFile(caseID, collectionID, sourceFileID, root, relPath string, p parsers.ArtifactParser) (ParsedFile, error) {
	abs := filepath.Join(root, filepath.FromSlash(relPath))
	parsed, err := p.Parse(abs)
	if err != nil {
		return ParsedFile{}, err
	}

	events := make([]model.Event, len(parsed.Events))
	raw := make([]model.RawEvidence, 0, len(parsed.Raw))
	for i := range parsed.Events {
		ev := parsed.Events[i]
		ev.ID = uuid.NewString()
		ev.CaseID = caseID
		ev.CollectionID = collectionID
		ev.SourceFileID = sourceFileID

		if i < len(parsed.Raw) {
			r := parsed.Raw[i]
			r.ID = uuid.NewString()
			r.CaseID = caseID
			r.SourceFileID = sourceFileID
			ev.RawEvidenceID = r.ID
			raw = append(raw, r)
		}
		events[i] = ev
	}
	return ParsedFile{Events: events, Raw: raw}, nil
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

// readHeader reads up to n leading bytes of a file for content sniffing.
// A file that cannot be opened simply yields no header and stays
// unclassified, which is the same outcome as not matching -- discovery
// must not fail a whole collection over one unreadable file.
func readHeader(path string, n int) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	buf := make([]byte, n)
	read, err := io.ReadFull(f, buf)
	if read == 0 && err != nil {
		return nil
	}
	return buf[:read]
}
