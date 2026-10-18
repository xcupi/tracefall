package api

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

// UI regression tests for this pass. These read app.js and assert the
// behaviour that is only expressible in the frontend -- the same
// approach the existing lifecycle_ui_test.go takes, and the reason
// functionBody exists.

func appJS(t *testing.T) []byte {
	t.Helper()
	src, err := os.ReadFile("../web/static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	return src
}

// Issue 1: browser coverage must be shown as a boundary, and must never
// imply the whole family is unsupported.
func TestUI_BrowserCoverageShowsBothSides(t *testing.T) {
	src := appJS(t)
	body := functionBody(t, src, "function renderCapabilityBoundary(")

	for _, want := range []string{"Not currently supported", "Supported in this family"} {
		if !strings.Contains(body, want) {
			t.Errorf("capability boundary does not render %q", want)
		}
	}
	if !strings.Contains(body, "not_parsed") || !strings.Contains(body, "parsed_instead") {
		t.Error("the boundary does not read the server's parsed_instead / not_parsed lists")
	}
	// The detail panel must call it.
	details := functionBody(t, src, "function evidenceDetails(")
	if !strings.Contains(details, "renderCapabilityBoundary(") {
		t.Error("evidence details no longer renders the capability boundary")
	}
}

// Issue 5: the UI must distinguish known-but-unparsed from unrecognized.
func TestUI_DistinguishesKnownUnsupportedFromUnrecognized(t *testing.T) {
	src := appJS(t)
	body := functionBody(t, src, "function capabilityClassification(")

	if !strings.Contains(body, "Known artifact, parser unavailable") {
		t.Error("no wording for a recognized-but-unsupported artifact")
	}
	if !strings.Contains(body, "Unrecognized") {
		t.Error("no wording for a genuinely unidentified artifact")
	}
	if !strings.Contains(body, "f.recognized") {
		t.Error("the classification does not consult the server's recognized flag")
	}
	// It must be surfaced in the detail grid.
	details := functionBody(t, src, "function evidenceDetails(")
	if !strings.Contains(details, "capabilityClassification(") {
		t.Error("evidence details does not show the classification")
	}
}

// Issue 2: the import UI must offer cancellation and treat a cancelled
// import as a normal outcome rather than a failure.
func TestUI_ImportOffersCancellation(t *testing.T) {
	src := appJS(t)
	text := string(src)

	runner := functionBody(t, src, "async function runImportWithProgress(")
	if !strings.Contains(runner, "/cancel") {
		t.Error("the import runner never calls the cancel endpoint")
	}
	if !strings.Contains(runner, "cancelled") {
		t.Error("the import runner does not handle the cancelled terminal state")
	}

	progress := functionBody(t, src, "function renderImportProgress(")
	if !strings.Contains(progress, "import-cancel-btn") {
		t.Error("no Cancel import button in the progress panel")
	}
	if !strings.Contains(progress, "Cancel import") {
		t.Error("the cancel control is not labelled 'Cancel import'")
	}
	if !strings.Contains(progress, "Cancelling...") {
		t.Error("no in-flight state; a clicked Cancel button would look inert")
	}
	if !strings.Contains(progress, "p.done") {
		t.Error("the Cancel button is not hidden once the import is done")
	}

	results := functionBody(t, src, "function renderImportResults(")
	if !strings.Contains(results, "Import cancelled") {
		t.Error("a cancelled import is not labelled as cancelled")
	}
	if !strings.Contains(results, "not a parse failure") {
		t.Error("unprocessed files are not distinguished from parse failures in the summary")
	}
	// The summary must not claim files were "never processed": some of
	// them were parsed and then discarded unwritten, which is a
	// different thing and the analyst can tell.
	if strings.Contains(results, "never processed") {
		t.Error("the cancelled summary claims files were never processed; some were parsed but not written")
	}
	if !strings.Contains(results, "unprocessed") {
		t.Error("the cancelled summary does not report unprocessed files")
	}
	// The phase label table must know the state.
	if !strings.Contains(text, `cancelled: "Cancelled"`) {
		t.Error("the phase label table has no entry for cancelled")
	}
}

// Issue 3: correlations and activity chains must expose their events.
func TestUI_CorrelationEventsAreInspectable(t *testing.T) {
	src := appJS(t)

	card := functionBody(t, src, "function renderCorrelationCard(")
	if !strings.Contains(card, "mountCorrelationEventDetail(") {
		t.Error("a correlation card offers no way to inspect its events")
	}
	if !strings.Contains(card, "underlying event") {
		t.Error("the event count does not say the events are the correlation's underlying events")
	}

	chain := functionBody(t, src, "function renderActivityChain(")
	if !strings.Contains(chain, "mountCorrelationEventDetail(") {
		t.Error("an activity chain offers no event drill-down")
	}
	if !strings.Contains(chain, "CHAIN_INLINE_STEPS") {
		t.Error("a long chain still renders every step inline")
	}

	detail := functionBody(t, src, "function mountCorrelationEventDetail(")
	if !strings.Contains(detail, "paginate(") || !strings.Contains(detail, "wirePager(") {
		t.Error("the drill-down does not paginate; a 60-event chain would render as one wall")
	}
	if !strings.Contains(detail, "rowForEvent(") {
		t.Error("the drill-down does not reuse the existing event row renderer")
	}
	if !strings.Contains(detail, "hidden") {
		t.Error("the drill-down is not collapsed by default")
	}
}

// Ordering must be deterministic, and an activity chain's recorded
// narrative order must never be re-sorted.
func TestUI_CorrelationEventOrderingIsDeterministic(t *testing.T) {
	src := appJS(t)
	body := functionBody(t, src, "function correlationEventsFor(")

	if !strings.Contains(body, "isChainCorrelationType(") {
		t.Error("chain ordering is not distinguished from other correlations")
	}
	if !strings.Contains(body, "return { events: resolved, missing, ordering: \"narrative\" }") {
		t.Error("an activity chain's recorded event order is not preserved verbatim")
	}
	// Non-chain correlations sort chronologically with a stable tiebreak.
	if !strings.Contains(body, "localeCompare") {
		t.Error("no stable tiebreak: events sharing a timestamp could order differently between renders")
	}
	if !strings.Contains(body, "new Date(a.timestamp)") {
		t.Error("non-chain correlations are not ordered by event timestamp")
	}
	// Unresolvable events must be reported, never silently dropped.
	if !strings.Contains(body, "missing") {
		t.Error("unresolved events are not counted")
	}
	detail := functionBody(t, src, "function mountCorrelationEventDetail(")
	if !strings.Contains(detail, "could not be resolved") {
		t.Error("unresolved events are not surfaced to the analyst")
	}
}

// Issue 4: case state must be visible at a glance in the header.
func TestUI_CaseHeaderShowsStatePriorityAndFreshness(t *testing.T) {
	src := appJS(t)

	header := functionBody(t, src, "function renderCaseHeader(")
	if !strings.Contains(header, "renderCaseStateBadges(") {
		t.Error("the case header does not render the state badges")
	}

	badges := functionBody(t, src, "function renderCaseStateBadges(")
	for _, fn := range []string{"caseWorkflowBadge(", "casePriorityBadge(", "analysisStateBadge("} {
		if !strings.Contains(badges, fn) {
			t.Errorf("state badges do not include %s", fn)
		}
	}

	// The workflow badge must show the ANALYST status, never the engine
	// status -- conflating the two is a standing hazard in this codebase.
	wf := functionBody(t, src, "function caseWorkflowBadge(")
	if strings.Contains(wf, "c.status") {
		t.Error("the workflow badge reads the engine status instead of case_status")
	}

	// Analysis freshness must have three distinct states.
	an := functionBody(t, src, "function analysisStateBadge(")
	for _, want := range []string{"ANALYSIS STALE", "ANALYZED", "NEVER ANALYZED"} {
		if !strings.Contains(an, want) {
			t.Errorf("analysis badge is missing the %q state", want)
		}
	}

	// Editing must still exist, in exactly one place.
	if !strings.Contains(header, "case-status-select") || !strings.Contains(header, "case-priority-select") {
		t.Error("the editable selects were removed from the header")
	}
	if strings.Count(header, `id="case-status-select"`) != 1 {
		t.Error("more than one control edits case status")
	}
	if strings.Count(header, `id="case-priority-select"`) != 1 {
		t.Error("more than one control edits priority")
	}
}

// Issue 6: timestamp conversion must be centralized and DST-correct.
func TestUI_TimezoneConversionIsCentralizedAndDSTCorrect(t *testing.T) {
	src := appJS(t)
	text := string(src)

	fmtTime := functionBody(t, src, "function fmtTime(")
	fmtDate := functionBody(t, src, "function fmtDate(")

	for name, body := range map[string]string{"fmtTime": fmtTime, "fmtDate": fmtDate} {
		if !strings.Contains(body, "tzParts(") {
			t.Errorf("%s does not convert through the shared timezone formatter", name)
		}
		if !strings.Contains(body, "tzLabel()") {
			t.Errorf("%s does not label which zone it rendered in", name)
		}
		if strings.Contains(body, "toISOString") {
			t.Errorf("%s still formats via toISOString, which is always UTC", name)
		}
	}

	// Conversion must go through the IANA database, never offset maths.
	if !strings.Contains(text, "Intl.DateTimeFormat") {
		t.Error("no Intl.DateTimeFormat: conversion is not using the timezone database")
	}
	if !strings.Contains(functionBody(t, src, "function tzFormatter("), "timeZone: zone") {
		t.Error("the formatter does not pass an IANA timeZone")
	}
	// Hand-rolled offset arithmetic is exactly what the requirement
	// forbids: it cannot express DST.
	for _, bad := range []string{"3600 * 7", "* 7 * 60", "setHours(d.getHours() + "} {
		if strings.Contains(text, bad) {
			t.Errorf("hand-rolled offset arithmetic found: %q", bad)
		}
	}

	// Settings must load before the first render.
	if !strings.Contains(text, "await loadDisplaySettings()") {
		t.Error("display settings are not awaited before the first route render")
	}
	// Hardcoded UTC column headers would now be wrong.
	if strings.Contains(text, "Time (UTC)") {
		t.Error("a column header still hardcodes UTC instead of naming the display zone")
	}
}

// Issue 7: the setting must be reachable and persist the IANA id.
func TestUI_TimezoneControlPersistsIANAIdentifier(t *testing.T) {
	src := appJS(t)
	body := functionBody(t, src, "function renderTimezoneControl(")

	if !strings.Contains(body, `api("/settings"`) {
		t.Error("the control does not persist through the settings endpoint")
	}
	if !strings.Contains(body, `method: "PUT"`) {
		t.Error("the control does not PUT its change")
	}
	if !strings.Contains(body, "timezone: chosen") {
		t.Error("the control does not send the canonical identifier")
	}
	if !strings.Contains(body, "applyDisplaySettings(") {
		t.Error("the control does not apply the server's confirmed setting")
	}
	if !strings.Contains(body, "route()") {
		t.Error("changing the zone does not re-render the current view")
	}
	// It must NOT trigger re-analysis or a data refetch.
	for _, bad := range []string{"/analyze", "location.reload"} {
		if strings.Contains(body, bad) {
			t.Errorf("changing the display timezone triggers %q", bad)
		}
	}
	// The control must live in the persistent chrome, not one page.
	html, err := os.ReadFile("../web/static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(html), `id="timezone-control"`) {
		t.Error("no timezone control host in the app shell")
	}
}

// Changing the timezone must re-render the CASE HEADER too.
//
// route() has a fast path that swaps only the tab body when the same
// case is already on screen. Taking it after a timezone change left the
// header's Created / Last analyzed timestamps in the previous zone while
// every other timestamp on the page had converted -- two zones on one
// screen, unlabelled as such. Proven by browser verification before this
// guard existed.
func TestUI_TimezoneChangeRebuildsTheCaseHeader(t *testing.T) {
	src := appJS(t)
	body := functionBody(t, src, "function renderTimezoneControl(")

	if !strings.Contains(body, "renderedCaseId = null") {
		t.Error("the timezone handler does not reset renderedCaseId, so route() will take the " +
			"switchTab fast path and leave the case header in the previous zone")
	}
	if !strings.Contains(body, "renderedTab = null") {
		t.Error("the timezone handler does not reset renderedTab")
	}
	// The reset must come before the route() CALL, or it does nothing.
	// Anchored on "route();" -- the word "route()" also appears in the
	// comment explaining why the reset is there, and matching that
	// instead would compare against the wrong position.
	reset := strings.Index(body, "renderedCaseId = null")
	call := strings.Index(body, "route();")
	if reset < 0 || call < 0 {
		t.Fatalf("could not locate the reset (%d) or the route() call (%d)", reset, call)
	}
	if reset > call {
		t.Error("renderedCaseId is reset after route(), which is too late to matter")
	}
	// And the header must actually format through the shared formatter.
	header := functionBody(t, src, "function renderCaseHeader(")
	if !strings.Contains(header, "fmtTime(c.created_at)") {
		t.Error("the case header does not format Created through the shared formatter")
	}
	if !strings.Contains(header, "fmtTime(c.analyzed_at)") {
		t.Error("the case header does not format Last analyzed through the shared formatter")
	}
}

// The case header's right-hand controls must be ONE coherent row.
//
// Regression: .case-state-badges was a COLUMN flex nested inside the row
// that holds Export and Delete Case. The three badges stacked vertically
// into a single tall flex item, and the two buttons centred against the
// full height of that stack -- so the status badges and the action
// buttons appeared to sit on different rows, and the badges overlapped
// the header's intended structure.
//
// A geometric check in a real browser is what actually proves the fix
// (all five controls share one centre line at desktop width); this
// guards the CSS declarations that make it true, because the failure
// mode is a single property flipping back.
func TestUI_CaseHeaderActionsAreOneRow(t *testing.T) {
	css, err := os.ReadFile("../web/static/style.css")
	if err != nil {
		t.Fatal(err)
	}
	text := string(css)

	rule := func(selector string) string {
		i := strings.Index(text, "\n"+selector+" {")
		if i < 0 {
			t.Fatalf("no %s rule", selector)
		}
		end := strings.Index(text[i:], "}")
		if end < 0 {
			t.Fatalf("unterminated %s rule", selector)
		}
		return text[i : i+end]
	}

	badges := rule(".case-state-badges")
	if strings.Contains(badges, "flex-direction: column") {
		t.Error("the state badges are a column again: they will stack vertically and the " +
			"action buttons will centre against the whole stack")
	}
	if !strings.Contains(badges, "flex-direction: row") {
		t.Error("the state badges do not declare a row direction")
	}
	if !strings.Contains(badges, "align-items: center") {
		t.Error("the state badges are not vertically centred")
	}

	actions := rule(".case-header-actions")
	for _, want := range []string{"display: flex", "align-items: center", "flex-wrap: wrap"} {
		if !strings.Contains(actions, want) {
			t.Errorf("the action group is missing %q", want)
		}
	}
	// Wrapping must keep the group together on the right, not scatter it.
	if !strings.Contains(actions, "justify-content: flex-end") {
		t.Error("the action group does not stay right-aligned when it wraps")
	}

	// Absolute positioning is explicitly ruled out for these elements.
	for _, sel := range []string{".case-header-actions", ".case-state-badges"} {
		if strings.Contains(rule(sel), "position: absolute") {
			t.Errorf("%s uses absolute positioning", sel)
		}
	}

	// Analysis state must be visually distinct from status/priority and
	// must not dominate: outlined rather than filled.
	i := strings.Index(text, "\n.badge.analysis-state {")
	if i < 0 {
		t.Fatal("no .badge.analysis-state rule")
	}
	analysis := text[i : i+strings.Index(text[i:], "}")]
	if !strings.Contains(analysis, "background: transparent") {
		t.Error("the analysis badge is filled, so it competes with the status and priority badges")
	}
	if !strings.Contains(analysis, "border") {
		t.Error("the analysis badge has no outline to distinguish it")
	}
}

// The top bar must not force a horizontal scrollbar on a narrow
// viewport. Adding the timezone control widened its right-hand group
// past a phone width, which put a horizontal scrollbar on every screen
// in the app.
func TestUI_TopBarWrapsInsteadOfOverflowing(t *testing.T) {
	css, err := os.ReadFile("../web/static/style.css")
	if err != nil {
		t.Fatal(err)
	}
	text := string(css)
	for _, sel := range []string{".topbar", ".topbar-right"} {
		i := strings.Index(text, "\n"+sel+" {")
		if i < 0 {
			t.Fatalf("no %s rule", sel)
		}
		rule := text[i : i+strings.Index(text[i:], "}")]
		if !strings.Contains(rule, "flex-wrap: wrap") {
			t.Errorf("%s does not wrap; its contents will push the page wider than the viewport", sel)
		}
	}
}

// Case-status badges must use the palette, and OPEN must look active.
//
// Regression: OPEN was styled `background: var(--bg-muted, #e8eaed)`.
// --bg-muted is not defined in this theme, so the fallback applied and
// an ACTIVE case rendered as a near-white chip on a dark panel -- it
// read as disabled. The other three statuses were Material light-theme
// hexes that belong to no palette here.
//
// This pins the fix at its cause: status colours come from the theme
// tokens, and every var() used must actually be defined.
func TestUI_CaseStatusBadgesUseThePalette(t *testing.T) {
	css, err := os.ReadFile("../web/static/style.css")
	if err != nil {
		t.Fatal(err)
	}
	text := string(css)

	rule := func(selector string) string {
		i := strings.Index(text, "\n"+selector+" {")
		if i < 0 {
			t.Fatalf("no %s rule", selector)
		}
		return text[i : i+strings.Index(text[i:], "}")]
	}

	// Every var() referenced by the status badges must be a real token.
	defined := map[string]bool{}
	for _, tok := range []string{"--accent", "--ok", "--high", "--medium", "--low", "--critical", "--text", "--text-dim", "--border"} {
		if strings.Contains(text, tok+":") {
			defined[tok] = true
		}
	}
	if defined["--bg-muted"] {
		t.Error("--bg-muted is defined now; this test's premise needs revisiting")
	}

	statuses := map[string]string{
		".badge.case-state-open":          "--accent", // blue: an active state
		".badge.case-state-investigating": "--high",   // amber/orange
		".badge.case-state-contained":     "--ok",     // green
	}
	for sel, wantToken := range statuses {
		r := rule(sel)
		if !strings.Contains(r, "var("+wantToken+")") {
			t.Errorf("%s does not take its colour from var(%s): %s", sel, wantToken, r)
		}
		if strings.Contains(r, "var(--bg-muted") {
			t.Errorf("%s still references the undefined --bg-muted token", sel)
		}
		// A tinted fill is what separates a status badge from the
		// outline-only priority badges beside it.
		if !strings.Contains(r, "background: rgba(") {
			t.Errorf("%s has no tinted background, so it will not read as a state", sel)
		}
	}

	// CLOSED is the deliberate exception: neutral grey, and the one
	// status allowed to recede.
	closed := rule(".badge.case-state-closed")
	if !strings.Contains(closed, "rgba(136, 146, 171") {
		t.Errorf("CLOSED is not a neutral grey: %s", closed)
	}
	for _, hot := range []string{"var(--ok)", "var(--accent)", "var(--critical)", "var(--high)"} {
		if strings.Contains(closed, hot) {
			t.Errorf("CLOSED uses an active colour %s", hot)
		}
	}

	// Analysis state stays separate from case status, and stale is a
	// warning rather than a critical.
	stale := rule(".badge.analysis-stale")
	if !strings.Contains(stale, "var(--high)") {
		t.Errorf("stale analysis is not the warning colour: %s", stale)
	}
	if strings.Contains(stale, "var(--critical)") {
		t.Error("stale analysis uses the critical colour, which is reserved for priority and severity")
	}
	if !strings.Contains(rule(".badge.analysis-current"), "var(--ok)") {
		t.Error("ANALYZED is not green")
	}

	// Priority colours must be untouched by all of this.
	for sel, want := range map[string]string{
		".badge.prio-critical": "var(--critical)",
		".badge.prio-high":     "var(--high)",
		".badge.prio-medium":   "var(--medium)",
		".badge.prio-low":      "var(--low)",
	} {
		i := strings.Index(text, "\n"+sel+" ")
		if i < 0 {
			t.Fatalf("no %s rule", sel)
		}
		line := text[i : i+strings.Index(text[i:], "\n}")+1]
		if !strings.Contains(line, want) {
			t.Errorf("%s no longer uses %s", sel, want)
		}
	}
	// Priority stays outline-only, so it can never be confused with a
	// status badge.
	if !strings.Contains(rule(".badge.prio"), "background: transparent") {
		t.Error("priority badges gained a fill; they would then look like status badges")
	}
}

// The application shell must use the viewport rather than sitting in a
// narrow centred column.
//
// The layout was capped at 1100px, which left roughly 410px empty on
// each side of a 1920 display and — worse — made the 14-column timeline
// scroll inside its own box while most of the screen sat unused. These
// pin the token values the whole layout derives from, since a single
// number here silently governs every page.
func TestUI_ApplicationShellIsWide(t *testing.T) {
	css, err := os.ReadFile("../web/static/style.css")
	if err != nil {
		t.Fatal(err)
	}
	text := string(css)

	tokenValue := func(name string) string {
		i := strings.Index(text, name+":")
		if i < 0 {
			t.Fatalf("no %s token", name)
		}
		rest := text[i+len(name)+1:]
		return strings.TrimSpace(rest[:strings.Index(rest, ";")])
	}

	// Content cap: wide enough to be worth the screen, still bounded.
	max := tokenValue("--content-max")
	if !strings.HasSuffix(max, "px") {
		t.Fatalf("--content-max is not a pixel value: %q", max)
	}
	px, err := strconv.Atoi(strings.TrimSuffix(max, "px"))
	if err != nil {
		t.Fatal(err)
	}
	if px < 1600 {
		t.Errorf("--content-max is %dpx; anything under 1600 recreates the wasted side margins", px)
	}
	if px > 2000 {
		t.Errorf("--content-max is %dpx; an unbounded line length is unreadable", px)
	}

	// Sidebar: stable, and not consuming content width.
	side := tokenValue("--sidebar-w")
	sidePx, err := strconv.Atoi(strings.TrimSuffix(side, "px"))
	if err != nil {
		t.Fatalf("--sidebar-w is not a pixel value: %q", side)
	}
	if sidePx < 240 || sidePx > 260 {
		t.Errorf("--sidebar-w is %dpx, outside the 240-260 band", sidePx)
	}

	// The shell must still guard against a wide table stretching the
	// grid track and pushing the PAGE into horizontal scroll.
	if !strings.Contains(text, "grid-template-columns: var(--sidebar-w) minmax(0, 1fr)") {
		t.Error("the shell no longer uses minmax(0, 1fr); a wide table would overflow the page")
	}
	if !strings.Contains(text, ".app-main { min-width: 0; }") {
		t.Error(".app-main lost min-width:0")
	}

	// The top bar's content must align with the shell rather than
	// sitting flush left while the sidebar starts further in.
	if !strings.Contains(text, "calc((100% - var(--content-max)) / 2 + var(--page-pad))") {
		t.Error("the top bar does not inset its content to the shell column")
	}
	// 100vw would include the scrollbar and cause horizontal overflow.
	i := strings.Index(text, ".topbar,")
	if i >= 0 && strings.Contains(text[i:i+400], "100vw") {
		t.Error("the top bar inset uses 100vw, which includes the scrollbar and overflows the page")
	}

	// A very wide tier must exist so an ultrawide is not left with the
	// same gutters this change removed.
	if !strings.Contains(text, "@media (min-width: 2000px)") {
		t.Error("no very-wide tier: a 2560 display keeps ~420px gutters and the timeline still scrolls internally")
	}
}

// The case LIST must speak the same vocabulary as the case detail page.
//
// It previously rendered statusBadge(c.status) -- the raw ENGINE status
// -- so a case that had simply never been analysed showed a badge
// reading "created", sitting where the analysis state belongs. That is
// not a value in either published vocabulary (open/investigating/
// contained/closed for the case, analyzed/never analyzed/stale for the
// analysis) and reads as a status the product does not have.
func TestUI_CaseListUsesTheSameBadgeVocabularyAsTheDetailPage(t *testing.T) {
	src := appJS(t)
	text := string(src)
	body := functionBody(t, src, "async function renderCaseList(")

	for _, fn := range []string{"caseWorkflowBadge(", "casePriorityBadge(", "analysisStateBadge("} {
		if !strings.Contains(body, fn) {
			t.Errorf("the case list does not use %s -- the shared badge helper the detail page uses", fn)
		}
	}
	if strings.Contains(body, "statusBadge(") {
		t.Error("the case list still renders the raw engine status as a badge")
	}
	if strings.Contains(body, "lifecycleBadge(") {
		t.Error("the case list still uses its own lifecycle badge instead of the shared one")
	}

	// EXACTLY ONE definition of each shared helper. Two definitions of
	// casePriorityBadge existed at once: function declarations hoist, so
	// the later silently won and the list rendered with the header's
	// classes while its own CSS went unused.
	for _, fn := range []string{
		"function casePriorityBadge(",
		"function caseWorkflowBadge(",
		"function analysisStateBadge(",
	} {
		if n := strings.Count(text, fn); n != 1 {
			t.Errorf("%s is defined %d times; duplicate declarations silently shadow each other", fn, n)
		}
	}

	// The list has no summary to compute staleness from, so the shared
	// helper must derive it rather than mislabel a stale case.
	analysis := functionBody(t, src, "function analysisStateBadge(")
	if !strings.Contains(analysis, "staleAnalysis === undefined") {
		t.Error("analysisStateBadge does not handle being called without a stale flag, " +
			"so the case list would report a stale case as analyzed")
	}
	if !strings.Contains(analysis, "c.analyzed_at") {
		t.Error("the derived staleness does not consult analyzed_at")
	}
}

// The Cases page must not open with a band of empty space.
func TestUI_CasesListStartsBelowItsToolbar(t *testing.T) {
	css, err := os.ReadFile("../web/static/style.css")
	if err != nil {
		t.Fatal(err)
	}
	text := string(css)

	// Anchored on the RULE BODY, not the selector: the same selector also
	// appears in the sibling "+ .case-list" spacing rule, so a plain
	// substring check would still pass with the height collapse removed.
	i := strings.Index(text, "\n#case-bulk-bar:empty {")
	if i < 0 {
		t.Fatal("the cases bulk bar still reserves its full height when empty, " +
			"pushing the first card ~64px below the toolbar")
	}
	collapse := text[i : i+strings.Index(text[i:], "}")]
	// Newline-anchored: "min-height: 0" also contains "height: 0", so an
	// unanchored check passes even when the height itself is restored.
	if !strings.Contains(collapse, "\n  height: 0;") {
		t.Errorf("the empty cases bulk bar does not collapse its height: %s", collapse)
	}
	// And the list still needs deliberate breathing room beneath the
	// toolbar once the bar is collapsed.
	if !strings.Contains(text, "#case-bulk-bar:empty + .case-list") {
		t.Error("no spacing rule for the list once the bulk bar collapses; " +
			"the first card would sit flush against the toolbar")
	}
	// The reservation must SURVIVE on the evidence list, where it exists
	// to stop the row under the cursor jumping when a box is ticked.
	if strings.Contains(text, "#evidence-bulk-bar:empty") {
		t.Error("the evidence bulk bar's height reservation was removed; ticking a " +
			"checkbox there will shove the row under the cursor")
	}
	if !strings.Contains(text, ".bulk-bar-host") {
		t.Error(".bulk-bar-host was removed entirely")
	}
}

// The New case form is compact on desktop and stacks when narrow.
func TestUI_NewCaseFormIsCompactOnDesktop(t *testing.T) {
	css, err := os.ReadFile("../web/static/style.css")
	if err != nil {
		t.Fatal(err)
	}
	text := string(css)
	i := strings.Index(text, "\n.new-case-form {")
	if i < 0 {
		t.Fatal("no .new-case-form rule")
	}
	rule := text[i : i+strings.Index(text[i:], "}")]
	if !strings.Contains(rule, "grid-template-columns") {
		t.Error("the new-case form is not laid out in columns")
	}
	if !strings.Contains(text, ".new-case-form { grid-template-columns: minmax(0, 1fr); }") {
		t.Error("no narrow-viewport fallback to a stacked form")
	}

	// Behaviour must be untouched: same ids, same error element.
	src := appJS(t)
	body := functionBody(t, src, "async function renderCaseList(")
	for _, id := range []string{"new-case-name", "new-case-desc", "create-case-btn", "new-case-error", "new-case-name-icon"} {
		if !strings.Contains(body, id) {
			t.Errorf("the compact form dropped %q", id)
		}
	}
	// The uniqueness note must still be present. It moved from the
	// bordered .field-info-box to plain .field-info-note text so it stops
	// reading as a third input; the message itself is unchanged.
	if !strings.Contains(body, "field-info-note") {
		t.Error("the uniqueness note was dropped from the form")
	}
	if !strings.Contains(body, "Case names must be unique") {
		t.Error("the uniqueness wording was dropped")
	}
}

// Case cards must form COLUMNS, not a per-row flex arrangement.
//
// The badges were previously flex siblings of the case name, so where
// each one landed depended on how long that particular name was and no
// two rows lined up. A list is scanned vertically -- down the status
// column -- so the columns have to be deterministic.
func TestUI_CaseCardsUseAlignedGridColumns(t *testing.T) {
	src := appJS(t)
	body := functionBody(t, src, "async function renderCaseList(")

	// Badges are their own grid cells, not siblings of the name.
	if strings.Contains(body, "case-card-head") {
		t.Error("the card still uses the flex head that mixed the name and badges in one row")
	}
	for _, hook := range []string{"case-card-info", "case-card-col"} {
		if !strings.Contains(body, hook) {
			t.Errorf("the card markup has no %s element", hook)
		}
	}
	if n := strings.Count(body, `<div class="case-card-col">`); n != 3 {
		t.Errorf("found %d badge columns, want 3 (status, priority, analysis)", n)
	}

	css, err := os.ReadFile("../web/static/style.css")
	if err != nil {
		t.Fatal(err)
	}
	text := string(css)
	i := strings.Index(text, "\n.case-card {")
	if i < 0 {
		t.Fatal("no .case-card rule")
	}
	rule := text[i : i+strings.Index(text[i:], "}")]
	if !strings.Contains(rule, "display: grid") {
		t.Error(".case-card is not a grid, so its columns cannot align across rows")
	}
	if !strings.Contains(rule, "grid-template-columns") {
		t.Error(".case-card declares no column tracks")
	}
	// The name column must absorb the slack so a long name cannot shift
	// the badge columns.
	if !strings.Contains(rule, "minmax(") {
		t.Error("the case-information column is not minmax(); a long name would move the badges")
	}

	// Badges align to the START of their column. Centring reintroduces
	// the raggedness the grid removes, because a centred badge shifts
	// with its own text length.
	j := strings.Index(text, "\n.case-card-col {")
	if j < 0 {
		t.Fatal("no .case-card-col rule")
	}
	col := text[j : j+strings.Index(text[j:], "}")]
	if !strings.Contains(col, "justify-content: flex-start") {
		t.Errorf("badges are not start-aligned within their column: %s", col)
	}
	if strings.Contains(col, "justify-content: center") {
		t.Error("badges are centred in their column, which un-aligns them across rows")
	}

	// A narrow fallback must exist; fixed badge columns would leave the
	// name a sliver on a phone.
	if !strings.Contains(text, ".case-card {\n    grid-template-columns: minmax(0, 1fr);") {
		t.Error("no narrow-viewport fallback for the card grid")
	}
}

// New case: fields, then the helper note, then the primary action.
func TestUI_NewCaseFormHierarchy(t *testing.T) {
	src := appJS(t)
	body := functionBody(t, src, "async function renderCaseList(")

	iFields := strings.Index(body, `class="new-case-form"`)
	iNote := strings.Index(body, `class="field-info-note"`)
	iAction := strings.Index(body, `class="new-case-actions"`)
	if iFields < 0 || iNote < 0 || iAction < 0 {
		t.Fatalf("missing form landmarks: fields=%d note=%d action=%d", iFields, iNote, iAction)
	}
	if !(iFields < iNote && iNote < iAction) {
		t.Error("the form order is not fields -> helper note -> primary action")
	}
	// The button must no longer sit on the field row.
	if strings.Contains(body, "new-case-submit") {
		t.Error("the Create case button is still a column of the field row")
	}

	css, err := os.ReadFile("../web/static/style.css")
	if err != nil {
		t.Fatal(err)
	}
	text := string(css)

	// Two fields side by side on desktop, stacked when narrow.
	i := strings.Index(text, "\n.new-case-form {")
	rule := text[i : i+strings.Index(text[i:], "}")]
	if strings.Count(rule, "minmax(") != 2 {
		t.Errorf("the field row is not two columns: %s", rule)
	}
	if !strings.Contains(text, ".new-case-form { grid-template-columns: minmax(0, 1fr); }") {
		t.Error("no stacked fallback for the field row")
	}

	// The action is left-aligned and sized to its content.
	j := strings.Index(text, "\n.new-case-actions {")
	if j < 0 {
		t.Fatal("no .new-case-actions rule")
	}
	act := text[j : j+strings.Index(text[j:], "}")]
	if !strings.Contains(act, "justify-content: flex-start") {
		t.Error("the primary action is not left-aligned with the form content")
	}
	if !strings.Contains(text, ".new-case-actions button { flex: 0 0 auto; }") {
		t.Error("the Create case button is allowed to stretch to full width")
	}
}

// The uniqueness note is INFORMATION, not a third input -- but a real
// error must keep a distinct, visible treatment.
func TestUI_HelperNoteIsNotStyledAsAnInput(t *testing.T) {
	css, err := os.ReadFile("../web/static/style.css")
	if err != nil {
		t.Fatal(err)
	}
	text := string(css)

	i := strings.Index(text, "\n.field-info-note {")
	if i < 0 {
		t.Fatal("no .field-info-note rule; the helper text is still the bordered box")
	}
	note := text[i : i+strings.Index(text[i:], "}")]
	if strings.Contains(note, "border:") && !strings.Contains(note, "border: none") {
		t.Errorf("the helper note still draws a border, so it reads as an input: %s", note)
	}
	if !strings.Contains(note, "color: var(--text-dim)") {
		t.Error("the helper note is not subdued")
	}

	// The error treatment must survive, distinctly.
	if !strings.Contains(text, ".field-error-box") {
		t.Error(".field-error-box was removed; validation errors would lose their treatment")
	}
	src := appJS(t)
	if !strings.Contains(string(src), "field-error-box") {
		t.Error("nameFieldError no longer renders the distinct error box")
	}
	// And the informational box remains available for genuine warnings.
	if !strings.Contains(text, ".field-info-box {") {
		t.Error(".field-info-box was deleted rather than left for warning use")
	}
}

// ---------------- Phase 14: browser cache in the dashboard ----------------

// Browser cache and browser history are SEPARATE timeline categories.
// Collapsing them into one -- or leaving either in "other" -- would put
// a cached subresource in the same bucket as a recorded navigation.
func TestUI_BrowserCacheAndHistoryAreDistinctCategories(t *testing.T) {
	src := string(appJS(t))

	for _, want := range []string{
		`browser_visit: "browser_history"`,
		`browser_cache_entry: "browser_cache"`,
		`browser_history: "Browser History"`,
		`browser_cache: "Browser Cache"`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("app.js is missing %s", want)
		}
	}
	// Neither may be mapped into an existing category: "network" would
	// merge them with DNS/connection events, and each other.
	for _, wrong := range []string{
		`browser_cache_entry: "network"`, `browser_visit: "network"`,
		`browser_cache_entry: "browser_history"`, `browser_visit: "browser_cache"`,
	} {
		if strings.Contains(src, wrong) {
			t.Errorf("app.js maps a browser event to the wrong category: %s", wrong)
		}
	}
	if !strings.Contains(src, `browser_cache: "Browser cache entry"`) {
		t.Error("the browser_cache artifact type has no label")
	}
}

// A URL-bearing event must be searchable BY URL and must show the URL
// as its detail. Matching only network_dest would limit the analyst to
// bare hostnames, and a cache row's file_path is the hashed cache file,
// which names nothing an investigator recognizes.
func TestUI_WebEvidenceIsSearchableAndReadableByURL(t *testing.T) {
	src := appJS(t)

	hay := functionBody(t, src, "function eventSearchHaystack(")
	if !strings.Contains(hay, "e.extra.url") {
		t.Error("the timeline search haystack does not include the event's URL")
	}

	detail := functionBody(t, src, "function eventDetailValue(")
	if !strings.Contains(detail, "e.extra.url") {
		t.Error("the timeline detail cell does not prefer the URL for web evidence")
	}
	// The URL must outrank file_path: a cache entry's file_path is the
	// hashed on-disk name.
	urlAt := strings.Index(detail, "url")
	pathAt := strings.Index(detail, "e.file_path")
	if urlAt < 0 || pathAt < 0 || urlAt > pathAt {
		t.Errorf("the URL does not take precedence over file_path in the detail cell: %s", detail)
	}
}

// An imported file that produced no timeline events must say why, so a
// legitimate "0 event(s)" is never read as a silent parse failure.
func TestUI_ZeroEventImportIsExplained(t *testing.T) {
	src := appJS(t)
	body := functionBody(t, src, "function noEventNote(")

	if !strings.Contains(body, "Parsed successfully") {
		t.Error("the note does not distinguish a successful parse from a failure")
	}
	// It must apply ONLY to files that actually imported: a parse
	// failure has its own status and must not be described as parsed.
	if !strings.Contains(body, `sf.import_status !== "imported"`) {
		t.Error("the note is not restricted to successfully imported files")
	}
	if !strings.Contains(body, "eventCount !== 0") {
		t.Error("the note is not restricted to files that produced no events")
	}
	// And the provenance panel must actually call it.
	prov := functionBody(t, src, "function renderSourceFileProvenance(")
	if !strings.Contains(prov, "noEventNote(") {
		t.Error("the source-file provenance panel does not render the note")
	}
}

// ---------------- Priority is shown for every artifact ----------------

// The priority badge must render on every row, including unsupported
// and unrecognized ones. A blank cell reads as "no opinion", which is
// indistinguishable from "nobody looked".
func TestUI_PriorityBadgeRendersForEveryArtifact(t *testing.T) {
	src := appJS(t)
	body := functionBody(t, src, "function priorityBadge(")

	if strings.Contains(body, `if (!p) return "";`) {
		t.Error("priorityBadge still returns nothing for a row without a priority")
	}
	if !strings.Contains(body, `p || "unknown"`) {
		t.Error("priorityBadge does not fall back to an explicit unknown level")
	}
	// Every call site passes the rationale, so the reasoning is
	// reachable wherever the badge appears. Counting substrings would be
	// brittle -- "priority_reason" appears in other renderers too -- so
	// the single-argument call form is what is banned.
	for _, single := range []string{
		"priorityBadge(f.priority)", "priorityBadge(b.priority)",
		"priorityBadge(sf.priority)",
	} {
		if strings.Contains(string(src), single) {
			t.Errorf("%s drops the rationale; every call site must pass it", single)
		}
	}

	// The unknown level needs a style of its own, or it renders as an
	// unstyled badge that looks like a defect.
	css, err := os.ReadFile("../web/static/style.css")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(css), ".badge.prio-unknown") {
		t.Error("the unknown priority badge has no style rule")
	}
}

// The Notes column carries the priority rationale, and the file detail
// panel shows it as its own row.
func TestUI_PriorityRationaleIsVisible(t *testing.T) {
	src := string(appJS(t))

	if !strings.Contains(src, "ev-note-why") {
		t.Error("the coverage Notes column does not render the priority rationale")
	}
	if !strings.Contains(src, `row("Why this priority", f.priority_reason)`) {
		t.Error("the evidence detail panel does not show why the priority was assigned")
	}
	// The rationale is rendered beside the level it explains, so the
	// note reads "High: <reason>" rather than a bare sentence.
	if !strings.Contains(src, `PRIORITY_LABELS[b.priority] || b.priority || "Unknown"`) {
		t.Error("the rationale is not labelled with the priority level it explains")
	}
}

// ---------------- Evidence deletion confirmation ----------------

// Deleting evidence must be confirmed through a modal whose buttons say
// what they do. window.confirm cannot express that -- its buttons are
// OK/Cancel -- so a destructive action would be confirmed by a button
// that does not name the action.
func TestUI_EvidenceDeletionUsesANamedConfirmationModal(t *testing.T) {
	src := string(appJS(t))

	if !strings.Contains(src, "function confirmDestructive(") {
		t.Fatal("there is no confirmation modal")
	}
	body := functionBody(t, appJS(t), "function confirmDestructive(")
	for _, want := range []string{`createElement("dialog")`, "showModal()", `data-choice="confirm"`, `data-choice="cancel"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the modal is missing %q", want)
		}
	}
	// Escape and the backdrop must cancel, and focus must start on
	// Cancel so Enter never confirms a deletion the user has not read.
	if !strings.Contains(body, `finish(false)`) {
		t.Error("the modal has no cancelling path")
	}
	if !strings.Contains(body, `'[data-choice="cancel"]'`) {
		t.Error("focus does not start on the cancelling button")
	}

	// The required wording, verbatim.
	if !strings.Contains(src, `title: "Delete Evidence?"`) {
		t.Error(`the modal title is not "Delete Evidence?"`)
	}
	if !strings.Contains(src, `confirmLabel: "Delete Evidence"`) {
		t.Error(`the confirming button is not labelled "Delete Evidence"`)
	}
	if !strings.Contains(src, `cancelLabel = "Cancel"`) {
		t.Error(`the cancelling button is not labelled "Cancel"`)
	}
	warning := functionBody(t, appJS(t), "const EVIDENCE_DELETION_WARNING =")
	for _, want := range []string{
		"invalidate the current analysis results",
		"findings, investigations, correlations, activity chains, and ATT&CK mappings",
		"cannot be undone",
	} {
		if !strings.Contains(warning, want) {
			t.Errorf("the warning does not say %q: %s", want, warning)
		}
	}

	// Both evidence-deletion paths use it, and neither still uses the
	// unlabelled browser prompt.
	if strings.Count(src, `confirmLabel: "Delete Evidence"`) < 2 {
		t.Error("not every evidence-deletion path uses the modal")
	}
	for _, fn := range []string{"async function confirmAndDeleteEvidence(", "function wireDeleteCollection("} {
		if strings.Contains(functionBody(t, appJS(t), fn), "window.confirm(") {
			t.Errorf("%s still confirms with window.confirm", fn)
		}
	}
}

// A case whose analysis was invalidated reports NOT ANALYZED -- neither
// "stale" (which means results still describe evidence that exists) nor
// "never analyzed" (which would deny that analysis ever ran).
func TestUI_InvalidatedAnalysisReportsNotAnalyzed(t *testing.T) {
	src := appJS(t)
	badge := functionBody(t, src, "function analysisStateBadge(")

	if !strings.Contains(badge, "NOT ANALYZED") {
		t.Error("there is no NOT ANALYZED state")
	}
	// Invalidated must be checked BEFORE stale, or an invalidated case
	// falls through to the stale branch.
	invalidatedAt := strings.Index(badge, "if (invalidated)")
	staleAt := strings.Index(badge, "if (stale)")
	if invalidatedAt < 0 || staleAt < 0 || invalidatedAt > staleAt {
		t.Error("the invalidated state is not checked before the stale state")
	}
	if !strings.Contains(string(src), "summary.analysis_invalidated") {
		t.Error("the UI does not read the backend's invalidation flag")
	}
	// Stale must be suppressed when invalidated, so the two can never
	// both be claimed.
	if !strings.Contains(string(src), "!invalidated && c.status !== \"analyzed\"") {
		t.Error("stale is not suppressed for an invalidated case")
	}
}

// ---------------- Recycle Bin $R: recovered content ----------------

// The two halves of a Recycle Bin pair must be distinguishable at a
// glance. Sharing a label would make a pair look like two copies of one
// thing.
func TestUI_RecycleBinHalvesAreLabelledDistinctly(t *testing.T) {
	src := string(appJS(t))
	// The $I half is named "Recycle Bin" as of the UI-exposure pass: it
	// is what an analyst looks for in the Artifact filter, and the $I
	// detail lives on the event rather than in the filter option. The $R
	// half keeps its own name -- the two must never read as one artifact.
	for _, want := range []string{
		`recycle_bin_metadata: "Recycle Bin"`,
		`recycle_bin_content: "Recycle Bin content ($R)"`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("app.js is missing %s", want)
		}
	}
	if strings.Contains(src, `recycle_bin_content: "Recycle Bin"`) {
		t.Error("the $R half is labelled identically to the $I record")
	}
}

// A file that produced records but no events must still be able to show
// them. Recovered content is exactly that case: its record IS the
// deliverable, and before this it had no route out of the database.
func TestUI_RecordsAreShownForFilesWithNoEvents(t *testing.T) {
	src := appJS(t)
	body := functionBody(t, src, "function renderSourceFileRecords(")

	if !strings.Contains(body, "p.raw_evidence") {
		t.Error("the panel does not read the provenance view's raw records")
	}
	// Only for files with no events -- a file with events already shows
	// its records through them.
	if !strings.Contains(body, "p.event_count > 0") {
		t.Error("records are rendered even for files whose events already show them")
	}
	if !strings.Contains(body, "raw_evidence_truncated") {
		t.Error("a truncated record list is not disclosed, so an empty tail reads as completeness")
	}
	prov := functionBody(t, src, "function renderSourceFileProvenance(")
	if !strings.Contains(prov, "renderSourceFileRecords(") {
		t.Error("the source-file provenance panel does not render the records")
	}
}

func TestUI_AutomaticUploadUsesTheResumableServerPipeline(t *testing.T) {
	src := appJS(t)
	if !strings.Contains(string(src), `id="upload-auto-analyze" checked`) {
		t.Error("automatic import and analysis must be enabled by default for uploads")
	}
	header := functionBody(t, src, "function wireEvidenceHeader(")
	for _, want := range []string{"uploadResumable(", "runServerPipeline(", "resumePipelineIfActive(", "apiUpload("} {
		if !strings.Contains(header, want) {
			t.Errorf("the upload flow does not use %s", want)
		}
	}
	if !strings.Contains(header, "upload-auto-analyze") {
		t.Error("the upload flow ignores the automatic-analysis checkbox: the manual selection flow must stay available")
	}
}

func TestUI_ResumableUploadSendsOffsetsInChunksAndSurvivesAFailure(t *testing.T) {
	src := appJS(t)
	up := functionBody(t, src, "async function uploadResumable(")
	for _, want := range []string{
		"/uploads", "Upload-Offset", ".slice(", "/complete", "received", "409",
		"localStorage", "retry", "X-Tracefall-CSRF", "onProgress",
	} {
		if !strings.Contains(up, want) {
			t.Errorf("resumable upload is missing %q", want)
		}
	}
	for _, banned := range []string{".arrayBuffer()", "FileReader", "readAsArrayBuffer"} {
		if strings.Contains(up, banned) {
			t.Errorf("resumable upload reads the whole file into memory with %s; an image is tens of GB", banned)
		}
	}
	if !strings.Contains(up, "UPLOAD_CHUNK_BYTES") {
		t.Error("chunk size is not a named constant")
	}
}

func TestUI_ServerPipelinePanelPollsCancelsAndReportsEveryOutcome(t *testing.T) {
	src := appJS(t)
	// The panel is the polling loop plus the two renderers it calls.
	run := functionBody(t, src, "async function runServerPipeline(") +
		functionBody(t, src, "function renderPipelinePanel(") +
		functionBody(t, src, "function renderPipelineOutcome(")
	for _, want := range []string{
		"/pipeline/jobs", "/cancel", "succeeded", "failed", "cancelled",
		"files_imported", "findings", "correlations", "localStorage", "import-continue-btn",
	} {
		if !strings.Contains(run, want) {
			t.Errorf("pipeline panel does not handle %q", want)
		}
	}
	if strings.Contains(run, ".innerHTML = job.error") || strings.Contains(run, "${job.error}") {
		t.Error("a server error string is inserted into HTML unescaped")
	}
	if !strings.Contains(run, "esc(") {
		t.Error("pipeline panel never escapes server text")
	}
	resume := functionBody(t, src, "async function resumePipelineIfActive(")
	for _, want := range []string{"/pipeline/jobs", "queued", "running", "runServerPipeline("} {
		if !strings.Contains(resume, want) {
			t.Errorf("resume-on-load does not handle %q", want)
		}
	}
}
