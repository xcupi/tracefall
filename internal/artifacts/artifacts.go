// Package artifacts is the single authoritative answer to two questions
// an investigator asks about every file in an evidence collection:
//
//	What kind of artifact is this?
//	How much should I care about it?
//
// It exists because those questions were previously answerable only for
// files a parser happened to recognize. Everything else was cataloged
// with an empty artifact type and no other information -- so a KAPE
// collection or AD1 image containing seven thousand files presented as
// "8 supported, 7,065 unsupported" with no way to tell a Prefetch file
// from a font, and no way to find the six registry hives buried in it.
//
// Two things are deliberately kept separate here:
//
//   - SUPPORT is a fact about Tracefall: does a parser exist? It is
//     derived at runtime from internal/ingest's parser registry, never
//     restated by hand, so it cannot drift from what the code can
//     actually parse.
//   - PRIORITY is a fact about forensics: how much investigative value
//     does this artifact class usually carry? It is a fixed table, and
//     it is INDEPENDENT of support. Raw Prefetch is HIGH priority and
//     unsupported, and saying so is more useful than hiding it --
//     it tells an investigator what Tracefall is not looking at.
//
// The frontend renders this registry; it does not reimplement it. That
// is the point of the package existing rather than a table in app.js.
package artifacts

import (
	"path"
	"sort"
	"strings"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

// Priority is an artifact class's forensic triage value. It describes
// the ARTIFACT, not any finding derived from it, and not whether
// Tracefall can parse it.
type Priority string

const (
	PriorityCritical Priority = "critical"
	PriorityHigh     Priority = "high"
	PriorityMedium   Priority = "medium"
	PriorityLow      Priority = "low"
	// PriorityUnknown is used for a file no rule recognizes at all. It
	// sorts last and is never "recommended".
	PriorityUnknown Priority = "unknown"
)

// Rank orders priorities most-important-first, for deterministic sorting.
func (p Priority) Rank() int {
	switch p {
	case PriorityCritical:
		return 0
	case PriorityHigh:
		return 1
	case PriorityMedium:
		return 2
	case PriorityLow:
		return 3
	default:
		return 4
	}
}

// Family groups artifacts the way an investigator thinks about them,
// which is coarser than artifact type: an EvtxECmd CSV and a raw .evtx
// are different artifact types but the same family, and an investigator
// filtering for "Event Log" wants both.
type Family string

const (
	FamilyEventLog      Family = "event_log"
	FamilyRegistry      Family = "registry"
	FamilyPrefetch      Family = "prefetch"
	FamilyScheduledTask Family = "scheduled_task"
	FamilyPowerShell    Family = "powershell"
	FamilyExecution     Family = "execution"
	FamilyFileSystem    Family = "filesystem"
	FamilyBrowser       Family = "browser"
	FamilyMemory        Family = "memory"
	FamilyLog           Family = "log"
	FamilyOther         Family = "other"
)

// FamilyLabels renders a family for display. One place, so the UI never
// invents its own wording.
var FamilyLabels = map[Family]string{
	FamilyEventLog:      "Event Log",
	FamilyRegistry:      "Registry",
	FamilyPrefetch:      "Prefetch",
	FamilyScheduledTask: "Scheduled Task",
	FamilyPowerShell:    "PowerShell",
	FamilyExecution:     "Execution Artifact",
	FamilyFileSystem:    "File System",
	FamilyBrowser:       "Browser",
	FamilyMemory:        "Memory",
	FamilyLog:           "Application Log",
	FamilyOther:         "Other",
}

// Capability describes one artifact class Tracefall knows about --
// whether or not it can parse it.
type Capability struct {
	// ArtifactType is the model.Artifact* constant a parser produces, or
	// "" for a class Tracefall recognizes but does not parse.
	ArtifactType string   `json:"artifact_type,omitempty"`
	Label        string   `json:"label"`
	Family       Family   `json:"family"`
	FamilyLabel  string   `json:"family_label"`
	Priority     Priority `json:"priority"`
	// Supported means a parser exists and this file can become evidence.
	Supported bool `json:"supported"`
	// Parser is the parser name@version, when one exists.
	Parser string `json:"parser,omitempty"`
	// Reason explains an unsupported classification in plain language --
	// what Tracefall cannot do, and what it CAN read instead where an
	// alternative exists. Empty for supported artifacts.
	Reason string `json:"reason,omitempty"`

	// Recognized separates two states that are both "not supported" but
	// mean completely different things to an investigator:
	//
	//	Recognized && !Supported -- Tracefall KNOWS what this artifact is
	//	                            and has no parser for it. NTFS $MFT is
	//	                            the canonical example: identifying it
	//	                            as $MFT and saying the parser does not
	//	                            exist is far more useful than calling
	//	                            it an unknown file.
	//	!Recognized              -- genuinely unidentified. Tracefall has
	//	                            no idea what it is.
	//
	// Collapsing these would tell an analyst that a $MFT and a random
	// .dll are the same kind of gap. They are not.
	Recognized bool `json:"recognized"`

	// ParsedInstead names the artifacts in the SAME family that Tracefall
	// does parse. It exists so an unsupported classification cannot be
	// read as "this whole family is unsupported": a WebCacheV01.dat that
	// Tracefall cannot read says nothing about Chromium History, which it
	// reads fine.
	ParsedInstead []string `json:"parsed_instead,omitempty"`

	// NotParsed enumerates, specifically, what this classification covers
	// -- the counterpart to ParsedInstead. Prose in Reason explains why;
	// these two lists let the UI show the boundary as a boundary rather
	// than asking the analyst to parse a sentence.
	NotParsed []string `json:"not_parsed,omitempty"`
}

// Recommended reports whether this artifact class is worth an
// investigator's attention first: high-value AND actually parseable.
// An unsupported artifact is never recommended -- selecting it would do
// nothing -- but it is still shown, with its real priority.
func (c Capability) Recommended() bool {
	return c.Supported && (c.Priority == PriorityCritical || c.Priority == PriorityHigh)
}

// ---------- supported artifact metadata ----------
//
// Keyed by model.Artifact* constant. Support itself is NOT recorded
// here: it comes from the parser registry. This table only supplies the
// label, family and priority for an artifact type a parser produces, so
// adding a parser for a new artifact type means adding one entry here
// and nothing else. An artifact type with no entry still works -- it
// falls back to a derived label, FamilyOther and PriorityMedium -- so a
// forgotten entry degrades the display rather than breaking discovery.

type typeInfo struct {
	label    string
	family   Family
	priority Priority
}

var supportedTypeInfo = map[string]typeInfo{
	model.ArtifactWindowsEventLog: {
		label: "Windows Event Log (EVTX)", family: FamilyEventLog, priority: PriorityCritical,
	},
	model.ArtifactRegistryHive: {
		label: "Windows Registry Hive", family: FamilyRegistry, priority: PriorityCritical,
	},
	model.ArtifactRegistryRunKey: {
		label: "Registry (RECmd export)", family: FamilyRegistry, priority: PriorityHigh,
	},
	model.ArtifactScheduledTask: {
		label: "Scheduled Task XML", family: FamilyScheduledTask, priority: PriorityHigh,
	},
	model.ArtifactPrefetch: {
		label: "Prefetch", family: FamilyPrefetch, priority: PriorityHigh,
	},
	model.ArtifactPowerShellHistory: {
		label: "PowerShell console history", family: FamilyPowerShell, priority: PriorityHigh,
	},
	model.ArtifactBrowserHistory: {
		label: "Browser history (Chromium / Firefox)", family: FamilyBrowser, priority: PriorityMedium,
	},
}

// ---------- recognized-but-unparsed artifact classes ----------
//
// These are the artifacts a DFIR analyst expects to find in a triage
// collection and would want to know about even though Tracefall has no
// parser for them. Each carries an honest reason.
//
// Matching is by path/filename only: these files are never opened during
// discovery, because discovery walks every file in a collection and must
// stay cheap. Content sniffing is reserved for the parsers that actually
// claim a file (see parsers.ContentDetector).

// browserParsedInstead is the browser evidence Tracefall DOES parse,
// attached to every unsupported browser classification so the gap is
// never mistaken for the whole family. Kept as one variable because
// these three rules must never drift apart from each other.
//
// This list describes internal/parsers/browserhistory and is not a
// promise of future support; nothing here adds a parser.
var browserParsedInstead = []string{
	"Chromium History (Chrome, Edge, Brave, Opera, Vivaldi)",
	"Firefox History (places.sqlite)",
}

type unsupportedRule struct {
	label    string
	family   Family
	priority Priority
	reason   string
	// parsedInstead / notParsed populate the Capability fields of the
	// same name. See Capability for why the boundary is expressed as two
	// lists and not only as prose.
	parsedInstead []string
	notParsed     []string
	// match reports whether a lower-cased forward-slash relative path is
	// this artifact class.
	match func(lowerPath, lowerBase string) bool
}

func hasExt(ext string) func(string, string) bool {
	return func(_, base string) bool { return strings.HasSuffix(base, ext) }
}

func baseIs(names ...string) func(string, string) bool {
	set := map[string]bool{}
	for _, n := range names {
		set[strings.ToLower(n)] = true
	}
	return func(_, base string) bool { return set[base] }
}

func pathContains(fragments ...string) func(string, string) bool {
	return func(p, _ string) bool {
		for _, f := range fragments {
			if strings.Contains(p, f) {
				return true
			}
		}
		return false
	}
}

// unsupportedRules is ordered: the first match wins, so specific rules
// precede general ones.
var unsupportedRules = []unsupportedRule{
	{
		label: "Amcache hive", family: FamilyExecution, priority: PriorityHigh,
		reason: "Amcache records program execution and installation. Tracefall reads the hive format but has no Amcache-specific extraction yet, so no events are produced from it.",
		match:  baseIs("amcache.hve"),
	},
	{
		label: "SRUM database", family: FamilyExecution, priority: PriorityHigh,
		reason: "The System Resource Usage Monitor database records per-application network and resource usage. Tracefall has no ESE database parser.",
		match:  baseIs("srudb.dat"),
	},
	{
		label: "ShellBags / UsrClass", family: FamilyRegistry, priority: PriorityMedium,
		reason: "Tracefall reads this hive, but has no ShellBags-specific extraction, so only persistence locations produce events.",
		match:  baseIs("usrclass.dat"),
	},
	{
		// Deliberately RECOGNIZED-but-unsupported, not "Unrecognized":
		// telling an investigator "this is the $MFT and Tracefall cannot
		// parse it" is actionable (they can carve it with another tool);
		// calling it an unknown file is not.
		label: "NTFS $MFT", family: FamilyFileSystem, priority: PriorityHigh,
		reason: "Tracefall has no NTFS filesystem parser. File-system timeline analysis is not available.",
		notParsed: []string{
			"NTFS $MFT (master file table)",
			"NTFS $LogFile",
			"NTFS $UsnJrnl change journal",
		},
		match: baseIs("$mft", "$logfile", "$usnjrnl", "$j"),
	},
	// ---- browser artifacts ----
	//
	// Browser support is PARTIAL, and the old single rule ("Browser data
	// (unsupported format)") described the gap so vaguely that a file
	// landing in it read as "Tracefall does not do browsers". It does:
	// Chromium History and Firefox places.sqlite are parsed (see
	// internal/parsers/browserhistory).
	//
	// Split into one rule per artifact so each unsupported browser file
	// is named for what it actually is, and each carries the list of
	// browser artifacts that ARE parsed. An analyst looking at a
	// WebCacheV01.dat row can then see, on that row, that their Chrome
	// history is still covered.
	{
		label: "IE / Edge Legacy web cache (WebCacheV01.dat)", family: FamilyBrowser, priority: PriorityMedium,
		reason:        "WebCacheV01.dat is an ESE (Extensible Storage Engine) database. Tracefall has no ESE parser, so Internet Explorer and Edge Legacy browsing history is not extracted.",
		parsedInstead: browserParsedInstead,
		notParsed:     []string{"Internet Explorer / Edge Legacy WebCacheV01.dat (ESE database)"},
		match:         baseIs("webcachev01.dat", "index.dat"),
	},
	{
		label: "Browser cookie store", family: FamilyBrowser, priority: PriorityMedium,
		reason:        "Tracefall has no cookie-store parser. Cookies are not extracted from any browser.",
		parsedInstead: browserParsedInstead,
		notParsed:     []string{"Browser cookie stores"},
		match:         baseIs("cookies.sqlite", "cookies"),
	},
	{
		label: "Browser cache", family: FamilyBrowser, priority: PriorityMedium,
		reason:        "Tracefall has no browser-cache parser. Cached responses and their metadata are not extracted from any browser.",
		parsedInstead: browserParsedInstead,
		notParsed:     []string{"Browser cache stores"},
		match:         pathContains("/cache/", "/code cache/"),
	},
	{
		label: "Memory image", family: FamilyMemory, priority: PriorityHigh,
		reason: "Tracefall performs no memory analysis.",
		match:  baseIs("pagefile.sys", "hiberfil.sys", "memory.dmp", "swapfile.sys"),
	},
	{
		label: "Windows Error Report", family: FamilyLog, priority: PriorityLow,
		reason: "Crash telemetry. Tracefall has no WER parser.",
		match:  hasExt(".wer"),
	},
	{
		label: "Event Log (legacy .evt)", family: FamilyEventLog, priority: PriorityMedium,
		reason: "Tracefall parses the modern EVTX format only, not the pre-Vista .evt format.",
		match:  hasExt(".evt"),
	},
	{
		label: "Log file", family: FamilyLog, priority: PriorityLow,
		reason: "Plain-text logs are not parsed; their format is application-specific.",
		match:  hasExt(".log"),
	},
	{
		label: "CSV (unrecognized tool output)", family: FamilyOther, priority: PriorityMedium,
		reason: "This CSV does not match the naming convention of any EZ Tools output Tracefall parses (EvtxECmd, PECmd, RECmd).",
		match:  hasExt(".csv"),
	},
	{
		label: "XML (not a Scheduled Task)", family: FamilyOther, priority: PriorityLow,
		reason: "Only Task Scheduler XML collected under a Tasks directory is parsed.",
		match:  hasExt(".xml"),
	},
	{
		label: "Documentation / notes", family: FamilyOther, priority: PriorityLow,
		reason: "Not forensic evidence.",
		match: func(_, base string) bool {
			return hasExt(".md")("", base) || hasExt(".txt")("", base) || hasExt(".rtf")("", base)
		},
	},
}

// unknownCapability is what a file matching no rule gets: honest about
// being unrecognized rather than guessing.
var unknownCapability = Capability{
	Label:       "Unrecognized",
	Family:      FamilyOther,
	FamilyLabel: FamilyLabels[FamilyOther],
	Priority:    PriorityUnknown,
	Supported:   false,
	Recognized:  false,
	Reason:      "Tracefall does not recognize this file as a known forensic artifact.",
}

// Registry answers capability questions for one build of Tracefall.
type Registry struct {
	// byType maps an artifact type produced by a real parser to its
	// capability. Built from the parser registry, so it is exactly the
	// set of things this binary can parse.
	byType map[string]Capability
	all    []Capability
}

// NewRegistry derives the capability registry from the live parser
// registry. Pass ingest.Registry().
func NewRegistry(registered []parsers.ArtifactParser) *Registry {
	r := &Registry{byType: map[string]Capability{}}

	for _, p := range registered {
		at := p.ArtifactType()
		if _, seen := r.byType[at]; seen {
			// Two parsers producing the same artifact type (e.g. the
			// EvtxECmd CSV parser and the native .evtx parser both
			// produce windows_event_log) is normal and intended -- the
			// capability describes the TYPE, so the first registration
			// wins and the type is listed once.
			continue
		}
		info, ok := supportedTypeInfo[at]
		if !ok {
			// A parser whose artifact type has no metadata entry still
			// works; it just displays generically. Better than omitting
			// a supported artifact from the registry entirely.
			info = typeInfo{label: humanize(at), family: FamilyOther, priority: PriorityMedium}
		}
		r.byType[at] = Capability{
			ArtifactType: at,
			Label:        info.label,
			Family:       info.family,
			FamilyLabel:  FamilyLabels[info.family],
			Priority:     info.priority,
			Supported:    true,
			Recognized:   true,
			Parser:       p.Name(),
		}
	}

	for _, c := range r.byType {
		r.all = append(r.all, c)
	}
	// Deterministic order: priority first, then label.
	sort.Slice(r.all, func(i, j int) bool {
		if a, b := r.all[i].Priority.Rank(), r.all[j].Priority.Rank(); a != b {
			return a < b
		}
		return r.all[i].Label < r.all[j].Label
	})
	return r
}

// Supported returns every artifact class this build can actually parse.
func (r *Registry) Supported() []Capability {
	out := make([]Capability, len(r.all))
	copy(out, r.all)
	return out
}

// Unsupported returns the recognized-but-unparsed artifact classes, in
// priority order. Useful on its own as documentation of the gaps.
func (r *Registry) Unsupported() []Capability {
	out := make([]Capability, 0, len(unsupportedRules))
	for _, rule := range unsupportedRules {
		out = append(out, Capability{
			Label:         rule.label,
			Family:        rule.family,
			FamilyLabel:   FamilyLabels[rule.family],
			Priority:      rule.priority,
			Supported:     false,
			Recognized:    true,
			Reason:        rule.reason,
			ParsedInstead: rule.parsedInstead,
			NotParsed:     rule.notParsed,
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority.Rank() < out[j].Priority.Rank() })
	return out
}

// Classify answers "what is this file, and how much should I care?" for
// one discovered file.
//
// artifactType is what discovery already determined (non-empty exactly
// when a parser claimed the file). When it is set, the answer comes from
// the parser registry -- the authoritative source. When it is empty, the
// path is matched against the recognized-but-unparsed rules so the file
// still gets a type, a priority and a reason instead of being an
// anonymous row in a list of seven thousand.
func (r *Registry) Classify(relPath, artifactType string) Capability {
	if artifactType != "" {
		if c, ok := r.byType[artifactType]; ok {
			return c
		}
		// An artifact type from an older collection whose parser no
		// longer exists in this build. Report it honestly rather than
		// claiming support that is gone.
		return Capability{
			ArtifactType: artifactType,
			Label:        humanize(artifactType),
			Family:       FamilyOther,
			FamilyLabel:  FamilyLabels[FamilyOther],
			Priority:     PriorityMedium,
			Supported:    false,
			Recognized:   true,
			Reason:       "This evidence was cataloged by a version of Tracefall that had a parser for it; this build does not.",
		}
	}

	lower := strings.ToLower(strings.ReplaceAll(relPath, `\`, "/"))
	base := path.Base(lower)
	for _, rule := range unsupportedRules {
		if rule.match(lower, base) {
			return Capability{
				Label:         rule.label,
				Family:        rule.family,
				FamilyLabel:   FamilyLabels[rule.family],
				Priority:      rule.priority,
				Supported:     false,
				Recognized:    true,
				Reason:        rule.reason,
				ParsedInstead: rule.parsedInstead,
				NotParsed:     rule.notParsed,
			}
		}
	}
	return unknownCapability
}

// humanize turns an artifact type constant into a readable label as a
// last resort ("windows_event_log" -> "Windows Event Log").
func humanize(s string) string {
	if s == "" {
		return "Unrecognized"
	}
	parts := strings.Split(s, "_")
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, " ")
}
