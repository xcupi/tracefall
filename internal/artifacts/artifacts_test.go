package artifacts_test

import (
	"reflect"
	"strings"
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
		{"C/$MFT", "NTFS $MFT", artifacts.PriorityHigh, artifacts.FamilyFileSystem},
		{"Windows/appcompat/Programs/Amcache.hve", "Amcache hive", artifacts.PriorityHigh, artifacts.FamilyExecution},
		{"Windows/System32/sru/SRUDB.dat", "SRUM database", artifacts.PriorityHigh, artifacts.FamilyExecution},
		{"Users/j/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat", "IE / Edge Legacy web cache (WebCacheV01.dat)", artifacts.PriorityMedium, artifacts.FamilyBrowser},
		{"Users/j/AppData/Roaming/Mozilla/Firefox/Profiles/x/cookies.sqlite", "Browser cookie store", artifacts.PriorityMedium, artifacts.FamilyBrowser},
		{"Users/j/AppData/Local/Google/Chrome/User Data/Default/Cache/data_1", "Browser cache", artifacts.PriorityMedium, artifacts.FamilyBrowser},
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

// Phase 10A made raw Prefetch, PowerShell console history and the two
// browser history schemas genuinely supported. The registry must now say
// so -- support is derived from the parser registry, so this proves the
// parsers really are wired in rather than the table being edited.
func TestClassify_Phase10AArtifactsAreNowSupported(t *testing.T) {
	r := registry()

	cases := []struct {
		name         string
		artifactType string
		wantFamily   artifacts.Family
		wantPriority artifacts.Priority
	}{
		{"raw Prefetch", model.ArtifactPrefetch, artifacts.FamilyPrefetch, artifacts.PriorityHigh},
		{"PowerShell console history", model.ArtifactPowerShellHistory, artifacts.FamilyPowerShell, artifacts.PriorityHigh},
		{"browser history", model.ArtifactBrowserHistory, artifacts.FamilyBrowser, artifacts.PriorityMedium},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := r.Classify("whatever/path", tc.artifactType)
			if !c.Supported {
				t.Error("classified as unsupported despite a registered parser")
			}
			if c.Parser == "" {
				t.Error("supported but names no parser")
			}
			if c.Family != tc.wantFamily {
				t.Errorf("family = %q, want %q", c.Family, tc.wantFamily)
			}
			if c.Priority != tc.wantPriority {
				t.Errorf("priority = %q, want %q", c.Priority, tc.wantPriority)
			}
			if c.Reason != "" {
				t.Errorf("a supported artifact carries an unsupported reason: %q", c.Reason)
			}
		})
	}
}

// The registry must no longer claim these are unparsed -- a stale
// "Tracefall has no X parser" reason would actively mislead.
func TestUnsupported_NoLongerClaimsTheNewParsersAreMissing(t *testing.T) {
	for _, c := range registry().Unsupported() {
		lower := strings.ToLower(c.Label + " " + c.Reason)
		for _, gone := range []string{"no raw prefetch", "no consolehost_history parser", "has no browser history parser"} {
			if strings.Contains(lower, gone) {
				t.Errorf("unsupported entry %q still claims a parser is missing that now exists: %q", c.Label, c.Reason)
			}
		}
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
	r := registry()
	back := r.Classify(`Windows\Logs\CBS\CBS.log`, "")
	fwd := r.Classify("Windows/Logs/CBS/CBS.log", "")
	if back.Label != fwd.Label {
		t.Errorf("label = %q; a backslash path must classify the same as a forward-slash one (%q)", back.Label, fwd.Label)
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
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("classification differed between calls: %+v vs %+v", a, b)
		}
	}
}

// Browser support is PARTIAL. An unsupported browser artifact must never
// read as "Tracefall does not parse browser history" -- it does parse
// Chromium History and Firefox places.sqlite, and every unsupported
// browser classification has to say so on its own row.
func TestClassify_UnsupportedBrowserArtifactNamesWhatIsParsed(t *testing.T) {
	r := registry()

	unsupported := []struct {
		path      string
		wantLabel string
	}{
		{"Users/j/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat", "IE / Edge Legacy web cache (WebCacheV01.dat)"},
		{"Users/j/AppData/Roaming/Mozilla/Firefox/Profiles/x/cookies.sqlite", "Browser cookie store"},
		{"Users/j/AppData/Local/Google/Chrome/User Data/Default/Cache/data_1", "Browser cache"},
	}
	for _, tc := range unsupported {
		t.Run(tc.wantLabel, func(t *testing.T) {
			c := r.Classify(tc.path, "")
			if c.Supported {
				t.Fatal("classified as supported; no browser cache/cookie/ESE parser exists")
			}
			if !c.Recognized {
				t.Error("a known-but-unparsed browser artifact must stay recognized")
			}
			if c.Label != tc.wantLabel {
				t.Errorf("label = %q, want %q", c.Label, tc.wantLabel)
			}
			// The label must be specific: the old catch-all told the
			// analyst nothing about WHICH browser artifact this was.
			if strings.Contains(c.Label, "unsupported format") {
				t.Errorf("label %q is the old vague catch-all", c.Label)
			}
			if len(c.ParsedInstead) == 0 {
				t.Fatal("no ParsedInstead list: the row implies all browser data is unsupported")
			}
			joined := strings.Join(c.ParsedInstead, " | ")
			if !strings.Contains(joined, "Chromium History") {
				t.Errorf("ParsedInstead does not mention Chromium History: %q", joined)
			}
			if !strings.Contains(joined, "places.sqlite") {
				t.Errorf("ParsedInstead does not mention Firefox places.sqlite: %q", joined)
			}
			if len(c.NotParsed) == 0 {
				t.Error("NotParsed does not enumerate what this classification covers")
			}
		})
	}
}

// The browser artifacts Tracefall DOES parse must still classify as
// supported -- the split above must not have widened the unsupported
// rules over them.
func TestClassify_SupportedBrowserHistoryStaysSupported(t *testing.T) {
	r := registry()
	for _, at := range []string{"browser_history"} {
		c := r.Classify("Users/j/AppData/Local/Google/Chrome/User Data/Default/History", at)
		if !c.Supported {
			t.Errorf("artifact type %q classified unsupported; the browser parser still exists", at)
		}
		if !c.Recognized {
			t.Errorf("artifact type %q classified unrecognized", at)
		}
	}
	// And a bare Chromium History path with no artifact type must not be
	// swallowed by the cache rule (it lives under .../Default/, not
	// .../Default/Cache/).
	c := r.Classify("Users/j/AppData/Local/Google/Chrome/User Data/Default/History", "")
	if c.Label == "Browser cache" {
		t.Error("Chromium History was misclassified as browser cache")
	}
}

// "Known artifact, parser unavailable" and "genuinely unidentified" are
// different answers and must stay distinguishable.
func TestClassify_RecognizedButUnsupportedIsNotUnrecognized(t *testing.T) {
	r := registry()

	mft := r.Classify("C/$MFT", "")
	if mft.Supported {
		t.Fatal("$MFT reported as supported; Tracefall has no NTFS parser")
	}
	if !mft.Recognized {
		t.Error("$MFT must be RECOGNIZED-but-unsupported, not unknown")
	}
	if mft.Label != "NTFS $MFT" {
		t.Errorf("label = %q, want %q", mft.Label, "NTFS $MFT")
	}
	if !strings.Contains(mft.Reason, "no NTFS filesystem parser") ||
		!strings.Contains(mft.Reason, "File-system timeline analysis is not available") {
		t.Errorf("the $MFT explanation changed: %q", mft.Reason)
	}
	if mft.Priority != artifacts.PriorityHigh {
		t.Errorf("$MFT priority = %q, want high", mft.Priority)
	}

	unknown := r.Classify("Windows/System32/some-random-thing.dll", "")
	if unknown.Recognized {
		t.Error("an unidentified file must not be marked recognized")
	}
	if unknown.Label != "Unrecognized" {
		t.Errorf("unknown label = %q, want %q", unknown.Label, "Unrecognized")
	}
	if unknown.Priority != artifacts.PriorityUnknown {
		t.Errorf("unknown priority = %q, want unknown", unknown.Priority)
	}
}

// Nothing here may claim a parser that does not exist.
func TestRegistry_NoFabricatedSupport(t *testing.T) {
	r := registry()
	for _, c := range r.Unsupported() {
		if c.Supported {
			t.Errorf("%q listed as unsupported but marked supported", c.Label)
		}
		if c.Parser != "" {
			t.Errorf("%q names a parser %q while being unsupported", c.Label, c.Parser)
		}
	}
	for _, c := range r.Supported() {
		if !c.Supported || c.Parser == "" {
			t.Errorf("%q is listed as supported but names no parser", c.Label)
		}
	}
}
