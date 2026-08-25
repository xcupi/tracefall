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
