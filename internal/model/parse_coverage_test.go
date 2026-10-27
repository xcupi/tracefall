package model

import "testing"

func TestParseCoverageMeasured(t *testing.T) {
	var nilCov *ParseCoverage
	n := 0
	for name, tc := range map[string]struct {
		c    *ParseCoverage
		want bool
	}{
		"nil":                 {nilCov, false},
		"companion label":     {&ParseCoverage{CompanionOf: "vol1/SYSTEM"}, false},
		"recorded zero":       {&ParseCoverage{}, true},
		"records":             {&ParseCoverage{RecordsRead: 2}, true},
		"companion with note": {&ParseCoverage{CompanionOf: "vol1/SYSTEM", Notes: []string{"x"}}, true},
		"hive replay":         {&ParseCoverage{HiveReplay: &HiveReplay{State: "clean"}}, true},
		"emitted":             {&ParseCoverage{EmittedEvents: &n}, true},
	} {
		if got := tc.c.Measured(); got != tc.want {
			t.Errorf("%s: Measured = %v, want %v", name, got, tc.want)
		}
	}
}
