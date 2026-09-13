package api

import (
	"strings"
	"testing"
)

// The delete confirmation and the in-flight state.
//
// A deletion warning that overstates or understates what it destroys is
// worse than no warning: an analyst decides on the basis of it. These
// assert that it names what actually goes and what actually stays, and
// that the UI does not report completion before the server has finished.

func TestDeleteCaseUI_WarningNamesWhatIsActuallyDeleted(t *testing.T) {
	body := functionBody(t, appJS(t), "async function confirmAndDeleteCases(")
	if body == "" {
		t.Fatal("the delete confirmation is gone")
	}
	low := strings.ToLower(body)

	// Everything store.DeleteCase and Service.DeleteCase remove.
	for _, want := range []string{
		"evidence collection", "files on disk", "uploaded archive",
		"source file", "event", "finding", "correlation", "investigation", "att&ck",
		"notes", "analysis run", "audit",
	} {
		if !strings.Contains(low, want) {
			t.Errorf("the warning does not mention %q, which case deletion removes", want)
		}
	}
	// The two things that are deliberately NOT deleted must be named, or
	// the warning overstates.
	if !strings.Contains(low, "local folder") {
		t.Error("the warning does not say that evidence ingested from a local folder is kept")
	}
	if !strings.Contains(low, "security log") {
		t.Error("the warning does not say the system security log is kept")
	}
	if !strings.Contains(low, "cannot be undone") {
		t.Error("the warning does not say the action is irreversible")
	}
	// It must be an explicit confirmation, not a passive notice.
	if !strings.Contains(body, "window.confirm(") {
		t.Error("deletion does not require an explicit confirmation")
	}
}

// Deletion is synchronous. The UI must hold an in-flight state until the
// server responds, and must not fake progress it cannot know.
func TestDeleteCaseUI_InFlightStateIsIndeterminateAndBlocksDoubleSubmit(t *testing.T) {
	src := string(appJS(t))
	body := functionBody(t, appJS(t), "async function confirmAndDeleteCases(")
	begin := functionBody(t, appJS(t), "function beginDeleting(")

	if begin == "" {
		t.Fatal("there is no in-flight state for deletion")
	}
	if !strings.Contains(body, "beginDeleting(") {
		t.Error("the delete flow does not enter an in-flight state")
	}
	// Success navigates only AFTER the await, so completion is never
	// claimed early.
	awaitIdx := strings.Index(body, "await api(")
	successIdx := strings.Index(body, "onSuccess ||")
	if awaitIdx < 0 || successIdx < 0 || successIdx < awaitIdx {
		t.Error("the UI signals success before the server's response is awaited")
	}
	// Double submit is blocked.
	if !strings.Contains(begin, "deleteInFlight") {
		t.Error("a second delete can be started while one is running")
	}
	if !strings.Contains(begin, "disabled = true") {
		t.Error("the delete control is not disabled while a deletion runs")
	}
	// The deleted case must not linger in the frontend's cached state.
	for _, cleared := range []string{"overviewData = null", "renderedCaseId = null", "currentCollections = []"} {
		if !strings.Contains(body, cleared) {
			t.Errorf("the delete flow does not clear %q; the deleted case stays in memory", cleared)
		}
	}

	// A failure restores the control rather than leaving it stuck.
	if !strings.Contains(body, "restore()") {
		t.Error("a failed deletion leaves the control disabled")
	}

	// INDETERMINATE, not a fabricated percentage. The server does not
	// report deletion progress, so any number here would be invented.
	if strings.Contains(begin, "%") && !strings.Contains(begin, "100%") {
		t.Errorf("the in-flight state appears to show a percentage: %s", begin)
	}
	for _, banned := range []string{"progress =", "percent", "Math.round((", "toFixed(0) + \"%\""} {
		if strings.Contains(begin, banned) {
			t.Errorf("the in-flight state computes a progress value (%q); the backend reports none", banned)
		}
	}
	// The trigger must NOT become a second status indicator: the modal
	// is the single authoritative one. It is disabled and keeps its own
	// label.
	if strings.Contains(begin, "Deleting case") {
		t.Error("the Delete button is relabelled during deletion, duplicating the modal's status")
	}
	if strings.Contains(begin, "is-deleting") {
		t.Error("the Delete button is given an animated in-flight style, duplicating the modal's status")
	}
	if strings.Contains(styleCSS(t), "deleting-sweep") {
		t.Error("the button's sweep animation is still defined; it was a duplicate status indicator")
	}
	// "Deleting case..." must still exist -- in the modal.
	if !strings.Contains(src, `"Deleting case\u2026"`) {
		t.Error("nothing says what is happening")
	}
}

// The deletion progress state: what it must show, and what it must never
// claim.
func TestDeleteCaseUI_ProgressPanelShowsWorkWithoutClaimingPosition(t *testing.T) {
	src := string(appJS(t))
	css := styleCSS(t)
	open := functionBody(t, appJS(t), "  open(title, detail) {")

	if open == "" {
		t.Fatal("there is no deletion progress panel")
	}

	// A heading, a visible spinner, an indeterminate activity indicator,
	// and the summary of what is going.
	for _, want := range []string{"deletion-spinner", "deletion-activity", "deletion-summary"} {
		if !strings.Contains(open, want) {
			t.Errorf("the deletion panel does not render %q", want)
		}
	}
	// The old partially-filled track must not come back: a fill has an
	// edge, and an edge reads as a position.
	if strings.Contains(open, "progress-track") || strings.Contains(open, "progress-fill") {
		t.Error("the panel uses the filled progress track again; its edge reads as a percentage")
	}
	// The source escapes the ellipsis, so match it as written.
	if !strings.Contains(src, `"Deleting case\u2026"`) {
		t.Error("the panel does not say \"Deleting case...\"")
	}
	for _, want := range []string{".deletion-spinner", ".deletion-overlay", ".deletion-panel"} {
		if !strings.Contains(css, want) {
			t.Errorf("%s has no styling", want)
		}
	}
	// The spinner must actually spin, and the activity indicator must
	// actually animate.
	if !strings.Contains(css, "deletion-spin") {
		t.Error("the spinner has no animation")
	}
	if !strings.Contains(css, "deletion-activity-scroll") {
		t.Error("the activity indicator has no animation")
	}
	// Motion is not the only channel: a reduced-motion reader still gets
	// the bar and the text.
	if !strings.Contains(css, "prefers-reduced-motion") {
		t.Error("the deletion state does not respect reduced motion")
	}

	// It is a dialog, and it is modal -- requirement 10.
	for _, want := range []string{`role", "alertdialog"`, `aria-modal", "true"`} {
		if !strings.Contains(open, want) {
			t.Errorf("the deletion panel is not announced as a modal dialog (%s)", want)
		}
	}
	if !strings.Contains(css, "body.deletion-open") {
		t.Error("the page is still scrollable/interactive behind the deletion panel")
	}
}

// Requirements 4 and 5: no percentage, because the backend reports none.
func TestDeleteCaseUI_DeletionPanelShowsNoFabricatedProgress(t *testing.T) {
	src := string(appJS(t))
	start := strings.Index(src, "const deletionProgress = {")
	end := strings.Index(src, "// confirmAndDeleteCases requires explicit confirmation")
	if start < 0 || end < 0 || end < start {
		t.Fatal("could not isolate the deletion progress section")
	}
	section := src[start:end]

	for _, banned := range []string{
		"aria-valuenow", "percent", "Math.round(", "toFixed(", "width:${", "progress-fill\" style=",
	} {
		if strings.Contains(section, banned) {
			t.Errorf("the deletion panel computes or renders a position (%q); the backend reports none", banned)
		}
	}
	// The bar must declare itself positionless to assistive technology.
	if !strings.Contains(section, `aria-valuetext="in progress"`) {
		t.Error("the progress bar does not declare itself indeterminate")
	}

	// Requirement 8: no stage may be announced as done. These are the
	// stage names the requirement offers -- none of them can be claimed,
	// because the database deletions are one transaction that can roll
	// back.
	for _, stage := range []string{
		"Removing events", "Removing analysis data", "Removing evidence...",
		"Preparing deletion", "Finalizing",
	} {
		if strings.Contains(section, stage) {
			t.Errorf("the panel announces the stage %q, which the backend does not confirm", stage)
		}
	}
	// Elapsed time is allowed: it is measured, not estimated.
	if !strings.Contains(section, "Elapsed ") {
		t.Error("the panel shows no elapsed time, which is the one real number available")
	}
}

// Requirement 3: the status message must describe what is being removed,
// from counts the case already holds -- never invented ones.
func TestDeleteCaseUI_StatusMessageDescribesRealCounts(t *testing.T) {
	// Bounded explicitly: functionBody runs to the next top-level
	// "function", and this one is followed by a const, so it would sweep
	// up the whole delete flow and assert against the wrong code.
	fn := sectionBetween(t, string(appJS(t)),
		"function deletionSummaryHTML(ids, evidence) {", "\n// deletionNavGuard")
	if fn == "" {
		t.Fatal("there is no status message for deletion")
	}
	// Every count the case summary carries, each on its own labelled row
	// rather than run together in a sentence.
	for _, field := range []string{
		"collections", "source_files", "events", "findings", "correlations",
		"technique_count", "investigations",
	} {
		if !strings.Contains(fn, field) {
			t.Errorf("the summary does not include %s", field)
		}
	}
	if !strings.Contains(fn, "deletion-row-label") || !strings.Contains(fn, "deletion-row-value") {
		t.Error("the summary is not laid out as labelled rows")
	}
	// Counts are used ONLY when they belong to the case being deleted.
	if !strings.Contains(fn, "overviewData.c.id === ids[0]") {
		t.Error("the status message could show another case's counts")
	}
	// With no counts loaded it must not invent any.
	if !strings.Contains(fn, "Removing this case's evidence, events and analysis") {
		t.Error("there is no count-free fallback message")
	}
	// The on-disk size, when the server measured it -- and never turned
	// into a position.
	if !strings.Contains(fn, "evidence.measured") {
		t.Error("the summary shows a size without checking that it was measured")
	}
	if strings.Contains(fn, "%") || strings.Contains(fn, "Math.") {
		t.Error("the summary derives a proportion from the size")
	}
	if strings.Contains(fn, "await ") || strings.Contains(fn, "api(") {
		t.Error("the status message fetches counts of its own; it must use what is already loaded")
	}
}

// Requirement 11: a failure stops the loading state, shows the error, and
// never says "Deleted".
func TestDeleteCaseUI_FailureIsShownAndNeverReportsDeleted(t *testing.T) {
	src := string(appJS(t))
	fail := functionBody(t, appJS(t), "  fail(message, onClose) {")
	body := functionBody(t, appJS(t), "async function confirmAndDeleteCases(")

	if fail == "" {
		t.Fatal("the deletion panel has no failure state")
	}
	if !strings.Contains(fail, "clearInterval") {
		t.Error("a failed deletion leaves the running state ticking")
	}
	if !strings.Contains(fail, "Deletion failed") {
		t.Error("the failure state does not say deletion failed")
	}
	if strings.Contains(fail, ">Deleted<") || strings.Contains(fail, "\"Deleted\"") {
		t.Error("the failure state claims the case was deleted")
	}
	// It must say what is and is not known about the partial state,
	// rather than asserting nothing was removed.
	if !strings.Contains(fail, "may already have been removed") {
		t.Error("the failure state overstates what survived")
	}
	// The catch path must route into it.
	if !strings.Contains(body, "deletionProgress.fail(") {
		t.Error("a failed request does not show the failure state")
	}
	// And the guard must be released, or the button stays dead.
	if !strings.Contains(body, "stop();") {
		t.Error("a failed deletion does not release the in-flight guard")
	}
	_ = src
}

// Requirement 9: a second click must not start a second deletion, and
// must not open a second panel over the first.
func TestDeleteCaseUI_DuplicateRequestIsRefusedBeforeAnyPanelOpens(t *testing.T) {
	begin := functionBody(t, appJS(t), "function beginDeleting(")
	body := functionBody(t, appJS(t), "async function confirmAndDeleteCases(")

	if !strings.Contains(begin, "noop.started = false") {
		t.Error("beginDeleting does not report a refused duplicate to its caller")
	}
	if !strings.Contains(begin, "restore.started = true") {
		t.Error("beginDeleting does not report a real start")
	}
	if !strings.Contains(body, "if (!restore.started) return;") {
		t.Error("the delete flow proceeds even when the in-flight guard refused it")
	}
	// The guard check must come BEFORE the panel is opened.
	guardIdx := strings.Index(body, "if (!restore.started) return;")
	panelIdx := strings.Index(body, "deletionProgress.open(")
	if guardIdx < 0 || panelIdx < 0 || guardIdx > panelIdx {
		t.Error("a refused duplicate can still open a progress panel")
	}
}

// Requirement 10: leaving the page mid-deletion must warn, and the guard
// must be released on every exit path.
func TestDeleteCaseUI_NavigationIsGuardedWhileDeleting(t *testing.T) {
	src := string(appJS(t))
	body := functionBody(t, appJS(t), "async function confirmAndDeleteCases(")

	if !strings.Contains(src, "const deletionNavGuard = {") {
		t.Fatal("there is no navigation guard for a running deletion")
	}
	if !strings.Contains(src, `addEventListener("beforeunload"`) {
		t.Error("a reload or tab close during deletion is not warned about")
	}
	if !strings.Contains(body, "deletionNavGuard.arm()") {
		t.Error("the navigation guard is never armed")
	}
	if !strings.Contains(body, "deletionNavGuard.disarm()") {
		t.Error("the navigation guard is never released")
	}
	// Released through the single stop() helper, so no exit path can
	// forget it.
	if !strings.Contains(body, "const stop = () => {") {
		t.Error("guard release is not funnelled through one helper")
	}
}

// Requirement 14, and the bug this pass fixes: a bulk delete answers 200
// even when individual cases failed, so the 200 alone is not success.
func TestDeleteCaseUI_BulkPartialFailureIsNotReportedAsSuccess(t *testing.T) {
	body := functionBody(t, appJS(t), "async function confirmAndDeleteCases(")

	if !strings.Contains(body, "res.failed") {
		t.Fatal("the bulk delete ignores the server's failed map and reports success regardless")
	}
	if !strings.Contains(body, "deleted_case_ids") {
		t.Error("the bulk result's deleted list is not read")
	}
	// A partial failure must take the failure path, not the success one.
	failIdx := strings.Index(body, "failedIDs.length > 0")
	successIdx := strings.Index(body, "onSuccess ||")
	if failIdx < 0 || successIdx < 0 || failIdx > successIdx {
		t.Error("a partial bulk failure is not checked before success is declared")
	}
	if !strings.Contains(body, "of ${ids.length} cases were deleted") {
		t.Error("a partial failure does not say how many were actually deleted")
	}
}

// The whole point, asserted structurally: nothing declares completion
// before the request has resolved.
func TestDeleteCaseUI_CompletionFollowsTheServerResponse(t *testing.T) {
	body := functionBody(t, appJS(t), "async function confirmAndDeleteCases(")

	// Anchored on the DELETE specifically. The flow also awaits the
	// evidence-size measurement earlier, and matching the first "await
	// api(" would have measured that request instead of this one.
	awaitIdx := strings.Index(body, `method: "DELETE"`)
	closeIdx := strings.Index(body, "deletionProgress.close()")
	successIdx := strings.Index(body, "onSuccess ||")
	if awaitIdx < 0 {
		t.Fatal("the delete flow does not issue a DELETE")
	}
	if closeIdx < awaitIdx {
		t.Error("the progress panel is torn down before the server responded")
	}
	if successIdx < awaitIdx {
		t.Error("success is signalled before the server responded")
	}
	// And the panel must be opened before the request, or there is no
	// loading state at all for a slow deletion.
	openIdx := strings.Index(body, "deletionProgress.open(")
	if openIdx < 0 || openIdx > awaitIdx {
		t.Error("the progress panel is not shown while the request is in flight")
	}
}

// sectionBetween returns the source between two markers, for the cases
// where functionBody's "to the next top-level function" rule overshoots.
func sectionBetween(t *testing.T, src, from, to string) string {
	t.Helper()
	i := strings.Index(src, from)
	if i < 0 {
		t.Fatalf("%q not found in app.js; update this test", from)
	}
	rest := src[i:]
	j := strings.Index(rest, to)
	if j < 0 {
		t.Fatalf("%q not found after %q; update this test", to, from)
	}
	return rest[:j]
}

// The modal must be the ONLY deletion status on screen, and everything
// underneath must be inert.
func TestDeleteCaseUI_ModalIsTheSingleStatusIndicator(t *testing.T) {
	src := string(appJS(t))
	css := styleCSS(t)
	begin := functionBody(t, appJS(t), "function beginDeleting(")

	// Nothing underneath may relabel or animate.
	for _, banned := range []string{"btn.textContent =", "classList.add(\"is-deleting\")"} {
		if strings.Contains(begin, banned) {
			t.Errorf("the control underneath the modal still does %q", banned)
		}
	}
	// Every delete control is disabled, including the collection one.
	for _, want := range []string{"#delete-case-btn", "#case-delete-selected-btn", ".delete-collection-btn"} {
		if !strings.Contains(begin, want) {
			t.Errorf("%s is not disabled during a deletion", want)
		}
	}
	// The page behind is made inert rather than left operable.
	if !strings.Contains(begin, "deletion-inert") {
		t.Error("the page behind the modal is not made inert")
	}
	if !strings.Contains(css, ".deletion-inert") {
		t.Error(".deletion-inert has no styling")
	}
	if !strings.Contains(css, "pointer-events: none") {
		t.Error("the inert state does not actually block interaction")
	}
	// And it must be restored, or the case stays unusable after a failure.
	if !strings.Contains(begin, `classList.remove("deletion-inert")`) {
		t.Error("the inert state is never lifted")
	}
	_ = src
}

// The bar must say what it represents, which was the reported ambiguity.
func TestDeleteCaseUI_ProgressBarExplainsItself(t *testing.T) {
	open := functionBody(t, appJS(t), "  open(title, detail) {")

	// Concise and user-facing. The long technical explanation of why
	// there is no partial count belonged in the source, not on screen.
	if !strings.Contains(open, "Deletion is in progress. Please keep this tab open until it finishes.") {
		t.Error("the modal does not carry the concise progress wording")
	}
	for _, gone := range []string{"It is not a position", "one transaction", "deletion-bar-note"} {
		if strings.Contains(open, gone) {
			t.Errorf("the long technical explanation is still on screen (%q)", gone)
		}
	}
	// Indeterminate, and it must not declare a position to assistive
	// technology either.
	if !strings.Contains(open, `aria-valuetext="in progress"`) {
		t.Error("the activity indicator does not declare itself indeterminate")
	}
	if strings.Contains(open, "aria-valuenow") {
		t.Error("the indicator declares a position")
	}
}

// Stages come from the server and are only ticked once confirmed.
func TestDeleteCaseUI_StagesAreServerConfirmedOnly(t *testing.T) {
	src := string(appJS(t))
	render := functionBody(t, appJS(t), "  renderStages(p) {")

	if render == "" {
		t.Fatal("there is no stage rendering")
	}
	// Ticks are driven by server fields, never by elapsed time.
	for _, field := range []string{"p.records_confirmed", "p.evidence_files_removed", "p.done", "p.stage"} {
		if !strings.Contains(render, field) {
			t.Errorf("stage rendering does not read %s", field)
		}
	}
	for _, banned := range []string{"Date.now()", "elapsed", "setTimeout"} {
		if strings.Contains(render, banned) {
			t.Errorf("stage rendering uses %q; stages must come from the server, not from time passing", banned)
		}
	}
	// Row counts are shown only alongside a confirmed commit.
	if !strings.Contains(render, "p.records_confirmed && p.records_removed") {
		t.Error("row counts can be rendered without the commit being confirmed")
	}
	// Polling exists and is stopped on both exits.
	if !strings.Contains(src, "deletion-progress") {
		t.Error("the modal never asks the server for progress")
	}
	for _, fn := range []string{"  close() {", "  fail(message, onClose) {"} {
		body := functionBody(t, appJS(t), fn)
		if !strings.Contains(body, "stopTracking()") {
			t.Errorf("%s does not stop the progress polling", strings.TrimSpace(fn))
		}
	}
}

// Counts rendered in the modal must be the server's confirmed ones.
func TestDeleteCaseUI_CountsShownAreTheConfirmedOnes(t *testing.T) {
	// Bounded explicitly: functionBody runs to the next top-level
	// "function", and this one is followed by a const.
	fn := sectionBetween(t, string(appJS(t)),
		"function deletionCountsNote(c) {", "\nconst deletionProgress = {")
	if fn == "" {
		t.Fatal("there is no confirmed-counts renderer")
	}
	for _, field := range []string{"c.collections", "c.source_files", "c.events", "c.findings", "c.correlations"} {
		if !strings.Contains(fn, field) {
			t.Errorf("the confirmed counts do not include %s", field)
		}
	}
	// It must not compute a ratio out of them -- there is no numerator.
	// Comments are stripped first: "// " contains "/ ", which made an
	// earlier version of this check fire on prose.
	code := stripJSLineComments(fn)
	for _, banned := range []string{"Math.", " / ", "* 100", "%"} {
		if strings.Contains(code, banned) {
			t.Errorf("the counts renderer computes %q; there is no partial count to derive", banned)
		}
	}
}

// Bulk deletion has no combined progress, so it must not be given a
// stage list it cannot substantiate.
func TestDeleteCaseUI_BulkDeletionDoesNotClaimStages(t *testing.T) {
	body := functionBody(t, appJS(t), "async function confirmAndDeleteCases(")
	if !strings.Contains(body, "if (ids.length === 1) deletionProgress.track(") {
		t.Error("progress tracking is not restricted to single-case deletion")
	}
}

// stripJSLineComments removes // comments so a prose check cannot fire
// on comment syntax or on wording inside a comment.
func stripJSLineComments(src string) string {
	var b strings.Builder
	for _, line := range strings.Split(src, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// The regression this pass exists to prevent: an activity indicator that
// LOOKS like a percentage.
//
// The previous one was a 35%-wide fill sliding inside a track. Nothing
// about it claimed a position, but its geometry implied one -- a filled
// portion with an edge is read as an amount, and no caption undoes that.
// The replacement has no fill and no edge.
func TestDeleteCaseUI_ActivityIndicatorCannotReadAsAPercentage(t *testing.T) {
	css := styleCSS(t)
	block := sectionBetween(t, css, ".deletion-activity {", "\n.deletion-lede")

	// A width-driven child is exactly what makes a bar look determinate.
	for _, banned := range []string{"width:", "transform: translateX"} {
		if strings.Contains(block, banned) {
			t.Errorf("the activity indicator is sized or slid by %q, which reads as a position", banned)
		}
	}
	// It must cover its whole track, so there is no edge to interpret.
	if !strings.Contains(block, "repeating-linear-gradient") {
		t.Error("the indicator is not a full-width pattern; a partial fill implies an amount")
	}
	if !strings.Contains(block, "animation:") {
		t.Error("the indicator does not animate, so it does not show activity at all")
	}
	// Motion must not be the only channel.
	if !strings.Contains(css, "prefers-reduced-motion") {
		t.Error("the deletion UI does not respect reduced motion")
	}

	// And nothing anywhere in the deletion UI may render a percentage.
	//
	// The check is on what reaches the SCREEN, not on arithmetic:
	// Math.floor is used to turn elapsed milliseconds into whole seconds
	// for "Elapsed 40s", which is a measured duration and not a position.
	// An earlier version of this test banned it outright and fired on
	// exactly that.
	src := string(appJS(t))
	panel := stripJSLineComments(
		sectionBetween(t, src, "const deletionProgress = {", "\n// deletionNavGuard"))
	for _, banned := range []string{`%`, "toFixed(", "aria-valuenow"} {
		if strings.Contains(panel, banned) {
			t.Errorf("the deletion panel renders %q, which implies a completion percentage", banned)
		}
	}
}

// The summary must be a table of labelled figures, not a sentence.
func TestDeleteCaseUI_SummaryIsStructuredNotProse(t *testing.T) {
	css := styleCSS(t)
	fn := sectionBetween(t, string(appJS(t)),
		"function deletionSummaryHTML(ids, evidence) {", "\n// deletionNavGuard")

	for _, want := range []string{".deletion-table", ".deletion-row-label", ".deletion-row-value"} {
		if !strings.Contains(css, want) {
			t.Errorf("%s has no styling", want)
		}
	}
	// Figures line up and are comparable.
	if !strings.Contains(css, "tabular-nums") {
		t.Error("the figures are not tabular, so they do not line up")
	}
	if !strings.Contains(css, "text-align: right") {
		t.Error("the figures are not right-aligned")
	}
	// The old run-on sentence must be gone.
	for _, gone := range []string{"together with the case's notes", "Removing ${list}"} {
		if strings.Contains(fn, gone) {
			t.Errorf("the prose summary is still being built (%q)", gone)
		}
	}
	// A zero count is omitted rather than shown as a row of noise.
	if !strings.Contains(fn, "Number(n) > 0") {
		t.Error("zero counts are not filtered out of the summary")
	}
}

// The size is measured before the confirmation, so the walk never runs
// during the deletion and cannot race the removal it would measure.
func TestDeleteCaseUI_EvidenceSizeIsMeasuredBeforeTheDeletion(t *testing.T) {
	body := functionBody(t, appJS(t), "async function confirmAndDeleteCases(")

	sizeIdx := strings.Index(body, "/evidence-size")
	confirmIdx := strings.Index(body, "window.confirm(")
	deleteIdx := strings.Index(body, `method: "DELETE"`)
	if sizeIdx < 0 {
		t.Fatal("the evidence size is never measured")
	}
	if sizeIdx > confirmIdx {
		t.Error("the size is measured after the confirmation rather than before it")
	}
	if sizeIdx > deleteIdx {
		t.Error("the size walk runs during the deletion it would be measuring")
	}
	// A failed measurement must not block the deletion.
	if !strings.Contains(body, "evidence = null;") {
		t.Error("a failed size measurement is not tolerated")
	}
}
