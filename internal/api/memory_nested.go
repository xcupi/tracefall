package api

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"tracefall/internal/memory"
)

// RelatedCollection is a memory image found inside an evidence folder, and
// what became of it.
type RelatedCollection struct {
	CollectionID string `json:"collection_id,omitempty"`
	// Path is relative to the folder.
	Path string `json:"path"`
	// Status is "discovered" (its own collection now exists, ready to
	// import) or "not_analyzed" (Note says why).
	Status string `json:"status"`
	Note   string `json:"note,omitempty"`
}

// maxNestedMemoryImages bounds how many images one folder may spawn.
const maxNestedMemoryImages = 8

// nestedMemoryCandidate decides whether a file inside a folder is a memory
// image. Known magics are decisive. Of the file-name hints only the
// memory-specific ones count: .dmp, .dump and .raw are everywhere in a triage
// folder (crash dumps, raw exports) and are taken as memory only when a path
// is given on its own, never from inside a folder.
func nestedMemoryCandidate(path, name string) bool {
	if !sniffMemoryImage(path, name) {
		return false
	}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".dmp", ".dump", ".raw":
		return hasMemoryMagic(path)
	}
	return true
}

func hasMemoryMagic(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var h [8]byte
	n, _ := f.ReadAt(h[:], 0)
	b := string(h[:n])
	return strings.HasPrefix(b, "EMiL") || strings.HasPrefix(b, "PAGEDU") || (strings.HasPrefix(b, "\x7fELF") && n >= 8)
}

// discoverNestedMemoryImages gives every memory image found in a folder its
// own collection. A memory image is analysed by Volatility as a whole, so it
// cannot be one file among a folder's artifacts; leaving it in the folder
// catalogue as an unrecognised file would drop the most valuable evidence in
// the package without a word. Failures never fail the folder: each image that
// could not be analysed is reported with the reason.
func (s *Service) discoverNestedMemoryImages(caseID, root string) []RelatedCollection {
	var found []string
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		if nestedMemoryCandidate(p, d.Name()) {
			found = append(found, p)
		}
		return nil
	})
	sort.Strings(found)
	var out []RelatedCollection
	for i, p := range found {
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			rel = p
		}
		rc := RelatedCollection{Path: filepath.ToSlash(rel)}
		if i >= maxNestedMemoryImages {
			rc.Status, rc.Note = "not_analyzed", "more memory images than one folder may add; add this one by path on its own"
			out = append(out, rc)
			continue
		}
		res, err := s.discoverMemoryImageFromPath(caseID, p)
		switch {
		case err == nil:
			rc.Status, rc.CollectionID = "discovered", res.Collection.ID
		case errors.Is(err, ErrMemoryNotConfigured):
			rc.Status, rc.Note = "not_analyzed", err.Error()
		case errors.Is(err, memory.ErrSymbols), errors.Is(err, memory.ErrUnrecognised), errors.Is(err, memory.ErrTimeout):
			rc.Status, rc.Note = "not_analyzed", err.Error()
		default:
			rc.Status, rc.Note = "not_analyzed", err.Error()
		}
		out = append(out, rc)
	}
	return out
}
