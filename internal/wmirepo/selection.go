package wmirepo

import (
	"fmt"
	"sort"
)

// MappingCandidate retains both translations from one coherent mapping file.
type MappingCandidate struct {
	Name        string
	Data, Index Mapping
}

func SelectMapping(candidates []MappingCandidate) (MappingCandidate, error) {
	if len(candidates) == 0 {
		return MappingCandidate{}, fmt.Errorf("%w: missing mapping bundle", ErrUnsupported)
	}
	if len(candidates) > 3 {
		return MappingCandidate{}, fmt.Errorf("%w: mapping candidate count", ErrUnsupported)
	}
	ordered := append([]MappingCandidate(nil), candidates...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Name < ordered[j].Name })
	var selected MappingCandidate
	for _, c := range ordered {
		if c.Data.Generation != c.Index.Generation || len(c.Data.Entries) == 0 || len(c.Index.Entries) == 0 {
			return MappingCandidate{}, fmt.Errorf("%w: incoherent mapping candidate", ErrCorrupt)
		}
		if selected.Name == "" || c.Data.Generation > selected.Data.Generation {
			selected = c
		}
	}
	equivalent := func(a, b Mapping) bool {
		if len(a.Entries) != len(b.Entries) {
			return false
		}
		for i := range a.Entries {
			if a.Entries[i][0]&0x3fffffff != b.Entries[i][0]&0x3fffffff {
				return false
			}
		}
		return true
	}
	for _, c := range ordered {
		if c.Data.Generation == selected.Data.Generation && (!equivalent(c.Data, selected.Data) || !equivalent(c.Index, selected.Index) || c.Index.Entries[0][3] != selected.Index.Entries[0][3]) {
			return MappingCandidate{}, fmt.Errorf("%w: ambiguous equal-generation mappings", ErrUnsupported)
		}
	}
	return selected, nil
}
