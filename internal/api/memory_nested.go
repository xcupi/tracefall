package api

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"tracefall/internal/memory"
	"tracefall/internal/model"
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

// minNestedDumpBytes is the smallest .dmp/.dump/.raw taken as a memory image
// from inside a folder.
const minNestedDumpBytes = 64 << 20

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
		// A kernel minidump or a process dump carries the same magic as a full
		// dump. Only a file large enough to hold physical memory counts.
		st, err := os.Stat(path)
		return err == nil && st.Size() >= minNestedDumpBytes && hasMemoryMagic(path)
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
	// Largest first, so a real image is never crowded out of the cap by
	// smaller files; ties by path keep the order deterministic.
	size := func(p string) int64 {
		if st, err := os.Stat(p); err == nil {
			return st.Size()
		}
		return 0
	}
	sort.Slice(found, func(i, j int) bool {
		if a, b := size(found[i]), size(found[j]); a != b {
			return a > b
		}
		return found[i] < found[j]
	})
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

// nestedMemoryCollections lists the memory-image collections of a case that
// were discovered from inside folder: collections whose source path lies under
// it and whose catalogue entry has not been imported yet.
func (s *Service) nestedMemoryCollections(caseID, folder string) []RelatedCollection {
	if folder == "" {
		return nil
	}
	cols, err := s.store.ListCollections(caseID)
	if err != nil {
		return nil
	}
	if resolved, err := filepath.EvalSymlinks(folder); err == nil {
		folder = resolved // collections record the resolved path
	}
	prefix := filepath.Clean(folder) + string(filepath.Separator)
	var out []RelatedCollection
	for _, c := range cols {
		if c.SourceType != model.SourceTypeMemoryImage || !strings.HasPrefix(filepath.Clean(c.OriginalFilename), prefix) {
			continue
		}
		files, err := s.store.ListSourceFilesByCollection(c.ID)
		if err != nil {
			continue
		}
		pending := false
		for _, sf := range files {
			if sf.ImportStatus == model.SourceFileDiscovered {
				pending = true
			}
		}
		if !pending {
			continue
		}
		rel, _ := filepath.Rel(folder, c.OriginalFilename)
		out = append(out, RelatedCollection{CollectionID: c.ID, Path: filepath.ToSlash(rel), Status: "discovered"})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}
