package wmirepo

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sort"
)

var ErrMissingBundle = errors.New("WMI repository bundle is incomplete or not admitted")

type FileDigest struct {
	Name, SHA256 string
	Size         int64
}
type BundleResult struct {
	Snapshot          Snapshot
	Files             []FileDigest
	MappingName       string
	MappingGeneration uint32
}

// BundleRole recognizes exact repository member names, not string hits.
func BundleRole(name string) bool {
	switch name {
	case "OBJECTS.DATA", "INDEX.BTR", "MAPPING1.MAP", "MAPPING2.MAP", "MAPPING3.MAP":
		return true
	}
	return false
}
func ReadBundle(files map[string]File) (BundleResult, error) {
	out := BundleResult{}
	names := []string{}
	for name, f := range files {
		if !BundleRole(name) {
			return out, fmt.Errorf("%w: unrecognized bundle role", ErrUnsupported)
		}
		if f.Reader == nil || f.Size <= 0 || f.Size > 64<<30 {
			return out, fmt.Errorf("%w: bundle member size/reader", ErrUnsupported)
		}
		names = append(names, name)
	}
	if _, ok := files["OBJECTS.DATA"]; !ok {
		return out, ErrMissingBundle
	}
	if _, ok := files["INDEX.BTR"]; !ok {
		return out, ErrMissingBundle
	}
	sort.Strings(names)
	candidates := []MappingCandidate{}
	for _, name := range []string{"MAPPING1.MAP", "MAPPING2.MAP", "MAPPING3.MAP"} {
		f, ok := files[name]
		if !ok {
			continue
		}
		dm, end, err := ReadMapping(f, 0)
		if err != nil {
			return out, err
		}
		im, _, err := ReadMapping(f, end)
		if err != nil {
			return out, err
		}
		candidates = append(candidates, MappingCandidate{Name: name, Data: dm, Index: im})
	}
	if len(candidates) == 0 {
		return out, ErrMissingBundle
	}
	chosen, err := SelectMapping(candidates)
	if err != nil {
		return out, err
	}
	p := Physical{Data: files["OBJECTS.DATA"], Index: files["INDEX.BTR"], DataMap: chosen.Data, IndexMap: chosen.Index, MapName: chosen.Name}
	keys, err := p.ReadIndex()
	if err != nil {
		return out, err
	}
	out.Snapshot, err = (SemanticReader{Keys: keys, ReadRecord: p.ReadRecord}).ReadSelected()
	if err != nil {
		return out, err
	}
	out.MappingName = chosen.Name
	out.MappingGeneration = chosen.Data.Generation
	buffer := make([]byte, 64<<10)
	for _, name := range names {
		f := files[name]
		h := sha256.New()
		n, err := io.CopyBuffer(h, io.NewSectionReader(f.Reader, 0, f.Size), buffer)
		if err != nil || n != f.Size {
			return BundleResult{}, fmt.Errorf("%w: hashing repository member", ErrCorrupt)
		}
		out.Files = append(out.Files, FileDigest{Name: name, SHA256: fmt.Sprintf("%x", h.Sum(nil)), Size: f.Size})
	}
	return out, nil
}
