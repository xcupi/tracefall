package egress

import "testing"

func TestParseAndOrder(t *testing.T) {
	for in, want := range map[string]Level{"none": None, " Hashes ": Hashes, "PSEUDONYMIZED": Pseudonymized, "full": Full} {
		got, err := Parse(in)
		if err != nil || got != want {
			t.Errorf("Parse(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "all", "hash", "yes"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) accepted", bad)
		}
	}
	if !Hashes.AtLeast(None) || !Hashes.AtLeast(Hashes) || Hashes.AtLeast(Pseudonymized) || None.AtLeast(Hashes) || !Full.AtLeast(Hashes) {
		t.Errorf("ordering is wrong")
	}
	if Level("bogus").AtLeast(Hashes) || !Level("bogus").AtLeast(None) {
		t.Errorf("an unknown level must allow nothing beyond none")
	}
}

func TestOnlyLevelsSomethingUsesAreSelectable(t *testing.T) {
	if !None.Selectable() || !Hashes.Selectable() || Pseudonymized.Selectable() || Full.Selectable() {
		t.Errorf("selectable: none=%v hashes=%v pseudonymized=%v full=%v", None.Selectable(), Hashes.Selectable(), Pseudonymized.Selectable(), Full.Selectable())
	}
	for _, l := range []Level{None, Hashes, Pseudonymized, Full} {
		if l.Describe() == "" {
			t.Errorf("%s has no description", l)
		}
	}
}
