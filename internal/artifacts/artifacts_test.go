package artifacts_test

import (
	"testing"

	"tracefall/internal/artifacts"
	"tracefall/internal/ingest"
	"tracefall/internal/model"
)

func registry() *artifacts.Registry { return artifacts.NewRegistry(ingest.Registry()) }

// The registry must describe THIS build. Deriving support from the live
// parser registry is what stops the capability list drifting away from
// what the code can actually parse -- so the test asserts the relationship,
// not a hardcoded list that would need editing alongside every new parser.
func TestRegistry_SupportedMatchesTheParserRegistry(t *testing.T) {
	r := registry()

	parserTypes := map[string]bool{}
	for _, p := range ingest.Registry() {
		parserTypes[p.ArtifactType()] = true
	}
	supported := r.Supported()
	if len(supported) != len(parserTypes) {
		t.Errorf("registry lists %d supported classes, but the parser registry produces %d distinct artifact types",
			len(supported), len(parserTypes))
	}
	for _, c := range supported {
		if !c.Supported {
			t.Errorf("%q is in Supported() but has Supported=false", c.Label)
		}
		if !parserTypes[c.ArtifactType] {
			t.Errorf("%q claims artifact type %q, which no registered parser produces", c.Label, c.ArtifactType)
		}
		if c.Parser == "" {
			t.Errorf("%q is supported but names no parser", c.Label)
		}
		if c.Label == "" || c.FamilyLabel == "" {
			t.Errorf("%q has an empty label/family label: %+v", c.ArtifactType, c)
		}
	}
}

func TestClassify_SupportedFile(t *testing.T) {
	r := registry()
	c := r.Classify("Windows/System32/winevt/Logs/Security.evtx", model.ArtifactWindowsEventLog)

	if !c.Supported {
		t.Error("a file a parser claimed is not marked supported")
	}
	if c.Priority != artifacts.PriorityCritical {
		t.Errorf("priority = %q, want critical for an event log", c.Priority)
	}
	if c.Reason != "" {
		t.Errorf("a supported artifact carries an unsupported reason: %q", c.Reason)
	}
	if !c.Recommended() {
		t.Error("a supported critical artifact should be recommended")
	}
}

// The requirement that most matters in this package: PRIORITY IS NOT
// SUPPORT. An artifact Tracefall cannot parse can still be high-value,
// and saying so is the point -- it tells an investigator what is being
// missed rather than hiding it.
func TestClassify_UnsupportedArtifactKeepsItsRealPriority(t *testing.T) {
	r := registry()

	cases := []struct {
		path         string
		wantLabel    string
		wantPriority artifacts.Priority
		wantFamily   artifacts.Family
	}{
		{"Windows/Prefetch/CMD.EXE-A1B2C3D4.pf", "Prefetch (raw .pf)", artifacts.PriorityHigh, artifacts.FamilyPrefetch},
		{"C/$MFT", "NTFS $MFT", artifacts.PriorityHigh, artifacts.FamilyFileSystem},
		{"Windows/appcompat/Programs/Amcache.hve", "Amcache hive", artifacts.PriorityHigh, artifacts.FamilyExecution},
		{"Windows/System32/sru/SRUDB.dat", "SRUM database", artifacts.PriorityHigh, artifacts.FamilyExecution},
		{"Users/j/AppData/.../PSReadline/ConsoleHost_history.txt", "PowerShell console history", artifacts.PriorityHigh, artifacts.FamilyPowerShell},
		{"Windows/Logs/CBS/CBS.log", "Log file", artifacts.PriorityLow, artifacts.FamilyLog},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			c := r.Classify(tc.path, "") // "" == no parser claimed it
			if c.Supported {
				t.Error("classified as supported, but no parser claimed it")
			}
			if c.Label != tc.wantLabel {
				t.Errorf("label = %q, want %q", c.Label, tc.wantLabel)
			}
			if c.Priority != tc.wantPriority {
				t.Errorf("priority = %q, want %q", c.Priority, tc.wantPriority)
			}
			if c.Family != tc.wantFamily {
				t.Errorf("family = %q, want %q", c.Family, tc.wantFamily)
			}
			if c.Reason == "" {
				t.Error("an unsupported artifact must explain why it cannot be parsed")
			}
			// High priority AND unsupported is a valid, useful state --
			// but never "recommended", because selecting it would do
			// nothing.
			if c.Recommended() {
				t.Error("an unsupported artifact must never be recommended for import")
			}
		})
	}
}

// A raw Prefetch file is HIGH priority and unsupported, while PECmd's CSV
// export of the same evidence is HIGH priority and supported. Both facts
// must be expressible at once -- that is the whole distinction.
func TestClassify_SameFamilySupportedAndUnsupported(t *testing.T) {
	r := registry()

	raw := r.Classify("Windows/Prefetch/CMD.EXE-A1B2C3D4.pf", "")
	viaCSV := r.Classify("PECmd/20260301_PECmd_Output.csv", model.ArtifactPrefetch)

	if raw.Family != viaCSV.Family {
		t.Errorf("raw Prefetch family %q != PECmd family %q; an investigator filtering by family expects both",
			raw.Family, viaCSV.Family)
	}
	if raw.Supported {
		t.Error("raw .pf must not be marked supported")
	}
	if !viaCSV.Supported {
		t.Error("PECmd CSV output must be marked supported")
	}
	if raw.Priority != artifacts.PriorityHigh || viaCSV.Priority != artifacts.PriorityHigh {
		t.Errorf("priorities differ by support (%q vs %q); priority describes the artifact, not the parser",
			raw.Priority, viaCSV.Priority)
	}
}

func TestClassify_UnknownFileIsHonest(t *testing.T) {
	c := registry().Classify("Windows/Fonts/segoeui.ttf", "")
	if c.Supported {
		t.Error("an unknown file classified as supported")
	}
	if c.Priority != artifacts.PriorityUnknown {
		t.Errorf("priority = %q, want unknown -- guessing a priority for an unrecognized file would be fabrication", c.Priority)
	}
	if c.Reason == "" {
		t.Error("expected an explanation")
	}
}

// An artifact type from an older build whose parser is gone must be
// reported as unsupported rather than silently claiming support.
func TestClassify_RetiredArtifactTypeIsNotClaimedSupported(t *testing.T) {
	c := registry().Classify("something.dat", "artifact_from_a_future_build")
	if c.Supported {
		t.Error("an artifact type with no registered parser was claimed as supported")
	}
	if c.Reason == "" {
		t.Error("expected an explanation for the retired artifact type")
	}
}

func TestClassify_IsCaseInsensitive(t *testing.T) {
	r := registry()
	lower := r.Classify("windows/prefetch/cmd.exe-a1b2c3d4.pf", "")
	upper := r.Classify("WINDOWS/PREFETCH/CMD.EXE-A1B2C3D4.PF", "")
	if lower.Label != upper.Label {
		t.Errorf("case changed the classification: %q vs %q", lower.Label, upper.Label)
	}
}

// Windows paths arrive with backslashes from some containers.
func TestClassify_HandlesBackslashPaths(t *testing.T) {
	c := registry().Classify(`Windows\Prefetch\CMD.EXE-A1B2C3D4.pf`, "")
	if c.Label != "Prefetch (raw .pf)" {
		t.Errorf("label = %q; a backslash path must classify the same as a forward-slash one", c.Label)
	}
}

func TestUnsupported_ListsEveryKnownGapWithAReason(t *testing.T) {
	list := registry().Unsupported()
	if len(list) == 0 {
		t.Fatal("no unsupported artifact classes documented")
	}
	for _, c := range list {
		if c.Supported {
			t.Errorf("%q appears in Unsupported() but is marked supported", c.Label)
		}
		if c.Reason == "" {
			t.Errorf("%q documents no reason", c.Label)
		}
	}
	// Ordered most-valuable-first, so the biggest gaps are read first.
	for i := 1; i < len(list); i++ {
		if list[i-1].Priority.Rank() > list[i].Priority.Rank() {
			t.Errorf("unsupported list is not in priority order at %d: %q(%s) before %q(%s)",
				i, list[i-1].Label, list[i-1].Priority, list[i].Label, list[i].Priority)
		}
	}
}

func TestPriorityRank_OrdersCorrectly(t *testing.T) {
	order := []artifacts.Priority{
		artifacts.PriorityCritical, artifacts.PriorityHigh,
		artifacts.PriorityMedium, artifacts.PriorityLow, artifacts.PriorityUnknown,
	}
	for i := 1; i < len(order); i++ {
		if order[i-1].Rank() >= order[i].Rank() {
			t.Errorf("%q does not rank above %q", order[i-1], order[i])
		}
	}
}

// Classification must not depend on anything but its inputs.
func TestClassify_IsDeterministic(t *testing.T) {
	r := registry()
	for i := 0; i < 20; i++ {
		a := r.Classify("Windows/Prefetch/X.pf", "")
		b := r.Classify("Windows/Prefetch/X.pf", "")
		if a != b {
			t.Fatalf("classification differed between calls: %+v vs %+v", a, b)
		}
	}
}
