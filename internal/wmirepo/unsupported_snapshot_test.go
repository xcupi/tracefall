package wmirepo

import (
	"errors"
	"testing"
)

func TestSelectedUnrecognizedRepositoryIsNotSuccessfulZero(t *testing.T) {
	for _, keys := range [][]IndexKey{nil, {{Key: "A/B"}}, {{Key: fixtureID("NS_", `root\branch`) + "/" + fixtureID("CD_", "OtherClass") + ".0.1.200"}}} {
		s := SemanticReader{Keys: keys, ReadRecord: func(string) (Record, error) { t.Fatal("unexpected read"); return Record{}, nil }}
		if _, err := s.ReadSelected(); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("unrecognized repository accepted as zero: err=%v", err)
		}
	}
}

func TestSelectedRecognizedSchemaWithNoInstancesIsMeasuredZero(t *testing.T) {
	s, records := semanticFixture()
	s.Keys = []IndexKey{s.Keys[0]}
	s.ReadRecord = func(k string) (Record, error) { return records[k], nil }
	snap, err := s.ReadSelected()
	if err != nil || len(snap.Objects) != 0 {
		t.Fatalf("recognized zero lost: %+v %v", snap, err)
	}
	known := false
	for _, c := range snap.Coverage {
		if c.Class == "__EventFilter" && c.Status == "no_indexed_instances" {
			known = true
		}
	}
	if !known {
		t.Fatal("zero lacks recognized-schema coverage")
	}
}
