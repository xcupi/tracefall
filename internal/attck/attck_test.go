package attck

import "testing"

func TestLookup(t *testing.T) {
	tech, ok := Lookup("T1059.001")
	if !ok {
		t.Fatal("expected T1059.001 to be found")
	}
	if tech.Name == "" || tech.Tactic == "" || tech.URL == "" {
		t.Errorf("technique missing fields: %+v", tech)
	}

	if _, ok := Lookup("T9999.999"); ok {
		t.Error("expected unknown technique ID to not be found")
	}
}

func TestResolve_SkipsUnknownIDs(t *testing.T) {
	got := Resolve([]string{"T1059.001", "T9999.999", "T1547.001"})
	if len(got) != 2 {
		t.Fatalf("got %d resolved techniques, want 2 (unknown ID should be skipped, not error)", len(got))
	}
}

func TestAll_NonEmpty(t *testing.T) {
	if len(All()) == 0 {
		t.Error("expected the registry to contain at least one technique")
	}
}

// TestPhase4Techniques_Resolve confirms every Phase 4 addition is
// actually registered and fully populated -- a rule referencing an
// unregistered ID would silently vanish from Resolve rather than error
// (see Resolve's doc comment), so this is the test that would catch a
// typo'd technique ID in internal/detect/rules.go.
func TestPhase4Techniques_Resolve(t *testing.T) {
	ids := []string{
		"T1059.003", "T1059.005", "T1059.007", "T1543.003",
		"T1218.005", "T1547.004", "T1546.012", "T1021.001",
	}
	got := Resolve(ids)
	if len(got) != len(ids) {
		t.Fatalf("got %d resolved techniques, want %d (%v)", len(got), len(ids), ids)
	}
	for _, tech := range got {
		if tech.Name == "" || tech.Tactic == "" || tech.URL == "" {
			t.Errorf("technique %q missing fields: %+v", tech.ID, tech)
		}
	}
}
