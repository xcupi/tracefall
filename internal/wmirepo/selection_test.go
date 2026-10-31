package wmirepo

import (
	"errors"
	"testing"
)

func candidate(name string, generation, physical, root uint32) MappingCandidate {
	return MappingCandidate{Name: name, Data: Mapping{Generation: generation, Entries: [][6]uint32{{physical}}}, Index: Mapping{Generation: generation, Entries: [][6]uint32{{0, 0, 0, root}}}}
}
func TestSelectMappingGenerationAndEquivalentTies(t *testing.T) {
	a, b, c := candidate("MAPPING1.MAP", 8, 2, 3), candidate("MAPPING2.MAP", 7, 1, 1), candidate("MAPPING3.MAP", 8, 2, 3)
	got, err := SelectMapping([]MappingCandidate{c, b, a})
	if err != nil || got.Name != a.Name {
		t.Fatalf("not deterministic coherent generation selection: %+v %v", got, err)
	}
}
func TestSelectMappingRejectsAmbiguity(t *testing.T) {
	a := candidate("MAPPING1.MAP", 8, 2, 3)
	for _, b := range []MappingCandidate{candidate("MAPPING2.MAP", 8, 1, 3), candidate("MAPPING2.MAP", 8, 2, 4)} {
		if _, err := SelectMapping([]MappingCandidate{a, b}); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("ambiguous generation accepted: %v", err)
		}
	}
	a.Index.Generation = 9
	if _, err := SelectMapping([]MappingCandidate{a}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("incoherent generation accepted: %v", err)
	}
	if _, err := SelectMapping(nil); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("missing bundle accepted: %v", err)
	}
}
