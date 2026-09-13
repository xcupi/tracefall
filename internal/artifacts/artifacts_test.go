package artifacts_test

import (
	"reflect"
	"strings"
	"testing"

	"tracefall/internal/artifacts"
	"tracefall/internal/ingest"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

func registry() *artifacts.Registry { return artifacts.NewRegistry(ingest.Registry()) }

// The registry must describe THIS build. Deriving support from the live
// parser registry is what stops the capability list drifting away from
// what the code can actually parse -- so the test asserts the relationship,
// not a hardcoded list that would need editing alongside every new parser.
func TestRegistry_SupportedMatchesTheParserRegistry(t *testing.T) {
	r := registry()

	// Both kinds of artifact type a parser can produce: the type of the
	// FILE it claims, and (Phase 15) the types its EVENTS carry, for a
	// container like a registry hive that holds several distinct
	// artifacts. Gathering both keeps the invariant intact -- support is
	// still derived from the live registry, never hardcoded.
	parserTypes := map[string]bool{}
	for _, p := range ingest.Registry() {
		parserTypes[p.ArtifactType()] = true
		if src, ok := p.(parsers.EventArtifactTypeSource); ok {
			for _, at := range src.EventArtifactTypes() {
				parserTypes[at] = true
			}
		}
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
		// $MFT, $UsnJrnl and $LogFile are all parsed now; $Secure is the
		// NTFS metafile still without a reader.
		{"C/$Secure", "NTFS volume metadata (other metafiles)", artifacts.PriorityMedium, artifacts.FamilyFileSystem},
		// Amcache.hve is deliberately ABSENT as of Phase 16: it is now
		// parsed (the hive parser extracts its inventory trees), so it
		// belongs with the supported artifacts. Asserting it here would
		// claim Tracefall cannot read something it can.
		{"Windows/System32/sru/SRUDB.dat", "SRUM database", artifacts.PriorityHigh, artifacts.FamilyExecution},
		{"Users/j/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat", "IE / Edge Legacy web cache (WebCacheV01.dat)", artifacts.PriorityMedium, artifacts.FamilyBrowser},
		{"Users/j/AppData/Roaming/Mozilla/Firefox/Profiles/x/cookies.sqlite", "Browser cookie store", artifacts.PriorityMedium, artifacts.FamilyBrowser},
		// Classified from the path alone, with no bytes to read: an
		// unidentified file in a cache directory. LOW deliberately --
		// see recognizedTypeInfo. When discovery HAS read the bytes this
		// same file is recognized as blockfile rankings instead; that
		// path is covered in browsercache_classification_test.go.
		{"Users/j/AppData/Local/Google/Chrome/User Data/Default/Cache/data_0", "Browser cache unknown", artifacts.PriorityLow, artifacts.FamilyBrowser},
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
		{"Users/j/AppData/Local/Google/Chrome/User Data/Default/Cache/data_0", "Browser cache unknown"},
		{"Users/j/AppData/Local/Google/Chrome/User Data/Default/Cache/f_0000a5", "Browser cache auxiliary file"},
		{"Users/j/AppData/Local/Google/Chrome/User Data/Default/Cache/journal", "Browser cache journal/state"},
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
			// The label must be specific: the old catch-alls told the
			// analyst nothing about WHICH browser artifact this was.
			for _, vague := range []string{
				"Browser data (unsupported format)",
				"unrecognized format or container file",
			} {
				if strings.Contains(c.Label, vague) {
					t.Errorf("label %q is an old vague catch-all", c.Label)
				}
			}
			// And short enough to read in a table cell.
			if len(c.Reason) > 200 {
				t.Errorf("reason is %d chars; the Notes column needs one line, not a paragraph: %q",
					len(c.Reason), c.Reason)
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

	// $Secure is the recognized-but-unsupported case now: $MFT,
	// $UsnJrnl and $LogFile are all parsed. This test's subject is the
	// distinction between the two kinds of "no", and the security
	// descriptor store is what still sits on the unsupported side.
	logfile := r.Classify("C/$Secure", "")
	if logfile.Supported {
		t.Fatal("$Secure reported as supported; Tracefall has no security-descriptor parser")
	}
	if !logfile.Recognized {
		t.Error("$Secure must be RECOGNIZED-but-unsupported, not unknown")
	}
	if !strings.Contains(logfile.Reason, "$Secure") {
		t.Errorf("the explanation does not name the artifact: %q", logfile.Reason)
	}
	if logfile.Priority != artifacts.PriorityMedium {
		t.Errorf("$Secure priority = %q, want medium", logfile.Priority)
	}
	// It must say what IS parsed, so "no NTFS support" is not implied.
	if len(logfile.ParsedInstead) == 0 {
		t.Error("the NTFS gap does not name the $MFT support that does exist")
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

// The NTFS $MFT is a SUPPORTED artifact now: a parser exists, so the
// capability registry must report it as parseable rather than as a gap.
func TestClassify_MFTIsSupported(t *testing.T) {
	r := registry()

	c := r.Classify("C/$MFT", "ntfs_mft")
	if !c.Supported {
		t.Fatal("$MFT is not reported as supported despite a parser existing")
	}
	if !c.Recognized {
		t.Error("$MFT is not recognized")
	}
	if c.Label != "NTFS $MFT" {
		t.Errorf("label = %q, want %q", c.Label, "NTFS $MFT")
	}
	if c.Family != artifacts.FamilyFileSystem {
		t.Errorf("family = %q, want filesystem", c.Family)
	}
	if c.Priority != artifacts.PriorityHigh {
		t.Errorf("priority = %q, want high", c.Priority)
	}
	if c.Parser == "" {
		t.Error("a supported artifact names no parser")
	}
	// High-value AND parseable, so it is worth recommending.
	if !c.Recommended() {
		t.Error("$MFT should be recommended: it is high priority and parseable")
	}
	// The old "no NTFS parser" wording must be gone.
	if strings.Contains(c.Reason, "no NTFS filesystem parser") {
		t.Errorf("the supported $MFT still carries the unsupported explanation: %q", c.Reason)
	}

	// The registry must list it among supported capabilities.
	var listed bool
	for _, s := range r.Supported() {
		if s.ArtifactType == "ntfs_mft" {
			listed = true
		}
	}
	if !listed {
		t.Error("$MFT is absent from the supported capability list")
	}
	// And must NOT still appear as an unsupported class.
	for _, u := range r.Unsupported() {
		if u.Label == "NTFS $MFT" {
			t.Error("$MFT is still listed as an unsupported artifact class")
		}
	}
}
