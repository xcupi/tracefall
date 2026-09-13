package artifacts_test

import (
	"strings"
	"testing"

	"tracefall/internal/artifacts"
	"tracefall/internal/ingest"
	"tracefall/internal/model"
)

// Priority is a judgement about the ARTIFACT, not about Tracefall.
//
// The failure mode these tests exist to prevent is subtle and was
// already present once: an artifact quietly given a low priority
// because no parser reads it. That inverts the registry's purpose --
// the whole reason to show an unsupported artifact at all is to tell an
// investigator what is being missed, and an unsupported CRITICAL row is
// the most valuable thing the screen can say.

func reg() *artifacts.Registry { return artifacts.NewRegistry(ingest.Registry()) }

// Every classification carries a priority. There is no path through the
// registry that produces a blank one.
func TestPriority_EveryClassificationHasOne(t *testing.T) {
	r := reg()
	for _, c := range append(r.Supported(), r.Unsupported()...) {
		if c.Priority == "" {
			t.Errorf("%q has no priority", c.Label)
		}
	}
	// Including files that match nothing at all.
	for _, p := range []string{
		"Users/j/Desktop/holiday.jpg", "Windows/Fonts/arial.ttf",
		"opaque-name-with-no-extension", "", "a/b/c/d/e",
	} {
		if c := r.Classify(p, ""); c.Priority == "" {
			t.Errorf("%q classified with no priority at all", p)
		}
	}
}

// An unsupported artifact keeps the priority its forensic value earns.
// These are the classes whose priority most obviously must not track
// parser availability.
func TestPriority_IsIndependentOfSupport(t *testing.T) {
	r := reg()
	cases := []struct {
		path string
		want artifacts.Priority
	}{
		// CRITICAL, and none of them parseable.
		{"Windows/System32/config/lsass.dmp", artifacts.PriorityCritical},
		{"Windows/System32/wbem/Repository/OBJECTS.DATA", artifacts.PriorityCritical},
		{"C/hiberfil.sys", artifacts.PriorityCritical},
		{"Windows/System32/winevt/Logs/AppEvent.evt", artifacts.PriorityCritical},
		// HIGH, and none of them parseable.
		// Amcache.hve: see artifacts_test.go -- parsed as of Phase 16.
		{"Windows/System32/sru/SRUDB.dat", artifacts.PriorityHigh},
		// UsrClass.dat is deliberately ABSENT from this list as of Phase
		// 15: ShellBags are now extracted from it, so it is a supported
		// artifact and belongs in the supported-priority tests instead.
		// Leaving it here would assert that Tracefall cannot read
		// something it can.
		// ActivitiesCache.db is deliberately ABSENT as of Phase 16: it is
		// now parsed by internal/parsers/activitiescache, so it belongs
		// with the supported artifacts.
		{"Windows/inf/setupapi.dev.log", artifacts.PriorityHigh},
		{"C/pagefile.sys", artifacts.PriorityHigh},
	}
	for _, tc := range cases {
		c := r.Classify(tc.path, "")
		if c.Supported {
			t.Fatalf("%s is supported; this test is about UNSUPPORTED artifacts", tc.path)
		}
		if c.Priority != tc.want {
			t.Errorf("%s: priority = %q, want %q (label %q)", tc.path, c.Priority, tc.want, c.Label)
		}
	}
}

// No unsupported artifact may be LOW unless its rationale argues from
// forensic value. This is the specific regression being guarded: LOW
// assigned as a synonym for "we cannot read it".
func TestPriority_LowIsNeverAProxyForUnsupported(t *testing.T) {
	r := reg()
	banned := []string{
		"no parser", "not parsed", "unsupported", "cannot read",
		"tracefall does not", "not implemented", "not decoded",
	}
	for _, c := range r.Unsupported() {
		if c.PriorityReason == "" {
			t.Errorf("%q has no priority rationale; an unexplained priority cannot be checked", c.Label)
			continue
		}
		lower := strings.ToLower(c.PriorityReason)
		for _, b := range banned {
			if strings.Contains(lower, b) {
				t.Errorf("%q justifies its priority by parser availability (%q): %s", c.Label, b, c.PriorityReason)
			}
		}
	}
}

// Shortcuts and $I records became SUPPORTED without their priority
// moving: parser availability and forensic value are separate axes, and
// gaining a parser must not change what an artifact is worth.
func TestPriority_NewlySupportedArtifactsKeepTheirPriority(t *testing.T) {
	r := reg()
	for artifactType, want := range map[string]artifacts.Priority{
		model.ArtifactLNK:        artifacts.PriorityHigh,
		model.ArtifactRecycleBin: artifacts.PriorityHigh,
		// $R gained a parser in phase 19 and kept the MEDIUM it had when
		// it was unsupported. That is the rule this test exists for:
		// support and forensic value are separate axes.
		model.ArtifactRecycleBinContent: artifacts.PriorityMedium,
		// Jump Lists gained a parser in phase 21 and kept the HIGH they
		// had while unsupported.
		model.ArtifactJumpListAutomatic: artifacts.PriorityHigh,
		model.ArtifactJumpListCustom:    artifacts.PriorityHigh,
	} {
		c := r.Classify("", artifactType)
		if !c.Supported {
			t.Errorf("%s is not supported", artifactType)
		}
		if c.Priority != want {
			t.Errorf("%s: priority = %q, want %q", artifactType, c.Priority, want)
		}
		if c.PriorityReason == "" {
			t.Errorf("%s has no priority rationale", artifactType)
		}
		if c.Note == "" {
			t.Errorf("%s has no forensic note explaining what the parser provides", artifactType)
		}
	}
}

// Supported artifacts state their rationale too, on the same terms.
func TestPriority_SupportedArtifactsExplainTheirPriority(t *testing.T) {
	for _, c := range reg().Supported() {
		if c.PriorityReason == "" {
			t.Errorf("%q has no priority rationale", c.Label)
		}
		if strings.Contains(strings.ToLower(c.PriorityReason), "parser") {
			t.Errorf("%q justifies its priority by the parser: %s", c.Label, c.PriorityReason)
		}
	}
}

// An unrecognized file gets UNKNOWN -- deterministically, and never LOW.
//
// The distinction is the point: "of limited forensic value" is a claim
// about a file whose class was established. Nothing was established
// here, so nothing is claimed.
func TestPriority_UnrecognizedIsUnknownNotLow(t *testing.T) {
	r := reg()
	for _, p := range []string{
		"Users/j/Desktop/holiday.jpg",
		"Windows/Fonts/arial.ttf",
		"Program Files/App/app.exe",
		"random.bin",
	} {
		c := r.Classify(p, "")
		if c.Priority == artifacts.PriorityLow {
			t.Errorf("%s: an unrecognized file was called LOW; LOW is a claim about value, not about ignorance", p)
		}
		if c.Priority != artifacts.PriorityUnknown {
			t.Errorf("%s: priority = %q, want unknown", p, c.Priority)
		}
		if c.Recognized {
			t.Errorf("%s: reported as recognized", p)
		}
		if c.PriorityReason == "" {
			t.Errorf("%s: unknown priority carries no explanation", p)
		}
	}
}

// Classification is deterministic: the same path always classifies the
// same way, and rule order never depends on map iteration.
func TestPriority_ClassificationIsDeterministic(t *testing.T) {
	r := reg()
	paths := []string{
		"Windows/inf/setupapi.dev.log",
		"Windows/System32/LogFiles/W3SVC1/u_ex260901.log",
		"ProgramData/Microsoft/Windows Defender/Support/MPLog-20260901.log",
		"Windows/Logs/CBS/CBS.log",
		"Users/j/Desktop/unknown.dat",
		"C/hiberfil.sys",
	}
	first := map[string]artifacts.Capability{}
	for _, p := range paths {
		first[p] = r.Classify(p, "")
	}
	for i := 0; i < 50; i++ {
		for _, p := range paths {
			got := r.Classify(p, "")
			if got.Priority != first[p].Priority || got.Label != first[p].Label {
				t.Fatalf("run %d: %s classified as %q/%q, first as %q/%q",
					i, p, got.Label, got.Priority, first[p].Label, first[p].Priority)
			}
		}
	}
}

// A more specific artifact must not be swallowed by a generic extension
// rule. SetupAPI, Defender and IIS logs are all ".log"; a crash dump and
// an LSASS dump are both ".dmp".
func TestPriority_SpecificRulesBeatGenericExtensions(t *testing.T) {
	r := reg()
	cases := []struct {
		path      string
		wantLabel string
		wantPrio  artifacts.Priority
	}{
		{"Windows/inf/setupapi.dev.log", "USB / device install log (SetupAPI)", artifacts.PriorityHigh},
		{"ProgramData/Microsoft/Windows Defender/Support/MPLog-20260901.log", "Antimalware detection log", artifacts.PriorityHigh},
		{"inetpub/logs/LogFiles/W3SVC1/u_ex260901.log", "Web server log (IIS / W3C)", artifacts.PriorityHigh},
		{"Windows/System32/LogFiles/Firewall/pfirewall.log", "Host firewall log", artifacts.PriorityMedium},
		{"Windows/Logs/CBS/CBS.log", "Log file", artifacts.PriorityLow},
		{"Windows/System32/config/lsass.dmp", "Process memory dump (LSASS or similar)", artifacts.PriorityCritical},
		{"Users/j/AppData/Local/CrashDumps/notepad.exe.4242.dmp", "Process memory dump (LSASS or similar)", artifacts.PriorityCritical},
		{"Windows/Minidump/260901-1234-01.dmp", "Crash dump", artifacts.PriorityMedium},
	}
	for _, tc := range cases {
		c := r.Classify(tc.path, "")
		if c.Label != tc.wantLabel {
			t.Errorf("%s: label = %q, want %q", tc.path, c.Label, tc.wantLabel)
		}
		if c.Priority != tc.wantPrio {
			t.Errorf("%s: priority = %q, want %q", tc.path, c.Priority, tc.wantPrio)
		}
	}
}

// The new matchers must not claim files that merely resemble their
// targets. A narrow rule that over-matches is worse than no rule.
func TestPriority_NewRulesDoNotOverMatch(t *testing.T) {
	r := reg()
	// The labels added by this change. A near-miss file may still be
	// claimed by a pre-existing rule -- a .txt in Documents is
	// "Documentation / notes", correctly -- so what is asserted is that
	// none of the NEW rules claimed it.
	added := map[string]bool{
		"Recycle Bin metadata ($I)":              true,
		"PowerShell transcript":                  true,
		"Hosts / network configuration file":     true,
		"Thumbnail cache":                        true,
		"RDP bitmap cache":                       true,
		"USB / device install log (SetupAPI)":    true,
		"Antimalware detection log":              true,
		"Web server log (IIS / W3C)":             true,
		"Process memory dump (LSASS or similar)": true,
		"WMI repository":                         true,
		"Shortcut file (LNK)":                    true,
		"Jump List":                              true,
	}
	for _, p := range []string{
		// $I outside a Recycle Bin is an ordinary file.
		"Users/j/Documents/$Invoice.txt",
		// A .txt that is not a transcript.
		"Users/j/Documents/powershell_notes.txt",
		// hosts outside an etc directory.
		"Users/j/Documents/hosts",
		// A .db that is not a thumbnail cache.
		"Users/j/AppData/Local/app/storage.db",
		// A .bin that is not an RDP cache.
		"Users/j/Downloads/firmware.bin",
		// A .dmp outside any dump-collection directory.
		"Users/j/Downloads/notes.dmp",
	} {
		if c := r.Classify(p, ""); added[c.Label] {
			t.Errorf("%s was claimed as %q; the rule over-matches", p, c.Label)
		}
	}
}

// Priority and support are orthogonal: the registry must contain
// unsupported artifacts at every level above LOW, or the independence is
// theoretical rather than real.
func TestPriority_UnsupportedSpansTheWholeScale(t *testing.T) {
	counts := map[artifacts.Priority]int{}
	for _, c := range reg().Unsupported() {
		counts[c.Priority]++
	}
	for _, level := range []artifacts.Priority{
		artifacts.PriorityCritical, artifacts.PriorityHigh,
		artifacts.PriorityMedium, artifacts.PriorityLow,
	} {
		if counts[level] == 0 {
			t.Errorf("no unsupported artifact class at %s; priority is tracking support", level)
		}
	}
	if len(artifacts.Levels()) != 4 {
		t.Errorf("Levels() returned %d levels, want 4", len(artifacts.Levels()))
	}
	for _, l := range artifacts.Levels() {
		if l == artifacts.PriorityUnknown {
			t.Error("UNKNOWN is not a level in the scale and must not be listed as one")
		}
	}
}

// Rank ordering stays strict, with UNKNOWN last.
func TestPriority_RankOrdersTheScale(t *testing.T) {
	order := []artifacts.Priority{
		artifacts.PriorityCritical, artifacts.PriorityHigh,
		artifacts.PriorityMedium, artifacts.PriorityLow, artifacts.PriorityUnknown,
	}
	for i := 1; i < len(order); i++ {
		if order[i-1].Rank() >= order[i].Rank() {
			t.Errorf("%s does not rank above %s", order[i-1], order[i])
		}
	}
}
