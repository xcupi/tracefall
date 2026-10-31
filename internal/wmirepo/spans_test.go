package wmirepo

import "testing"

func TestSpanProjectionAcrossMappedPages(t *testing.T) {
	spans := []Span{{File: "OBJECTS.DATA", Offset: 24573, Length: 3}, {File: "OBJECTS.DATA", Offset: 0, Length: 5, RecordOffset: 3}}
	got, err := Project(spans, 2, 4)
	if err != nil || len(got) != 2 {
		t.Fatalf("projection missing: %+v %v", got, err)
	}
	if got[0].Offset != 24575 || got[0].Length != 1 || got[1].Offset != 0 || got[1].Length != 3 || got[1].RecordOffset != 3 {
		t.Fatalf("projection incorrect: %+v", got)
	}
}
func TestSpanProjectionRejectsIncompleteOrOverlappingCoverage(t *testing.T) {
	for _, spans := range [][]Span{nil, {{File: "x", Length: 1}}, {{File: "x", Length: 4}, {File: "x", Length: 4}}} {
		if _, err := Project(spans, 0, 4); err == nil {
			t.Fatal("accepted incomplete/overlapping coverage")
		}
	}
	if _, err := Project(nil, -1, 2); err == nil {
		t.Fatal("accepted negative offset")
	}
}
