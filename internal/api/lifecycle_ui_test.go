package api

import (
	"bytes"
	"net/http"
	"os"
	"strings"
	"testing"

	"tracefall/internal/model"
)

// The regression these cover: saving a status change updated the case
// header but left the Evidence Collections panel rendering the OLD lock
// banner. A case saved from Contained to Investigating showed
// "Investigating" at the top and "This case is contained" below it.
//
// The defect was client-side, so it splits into two testable halves:
//
//   1. The API contract the client refreshes from -- every status change
//      must immediately yield correct evidence_mutable / priority_editable
//      on the very next read. Tested here over HTTP.
//   2. The client actually applying that answer to BOTH places the lock
//      is rendered. There is no JS test harness, so that is pinned by a
//      narrow source guard below and by browser verification.

// After each save, the next read must report lock state matching the new
// status -- this is exactly what refreshLifecycleLocks() fetches.
func TestLifecycleUI_LockStateIsCorrectImmediatelyAfterEachSave(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Lock state after save")

	// The reported sequence, plus both directions out of every locked state.
	steps := []struct {
		to           string
		wantMutable  bool
		wantPriority bool
	}{
		{model.CaseWorkflowContained, false, true},
		{model.CaseWorkflowInvestigating, true, true}, // the reported bug
		{model.CaseWorkflowContained, false, true},
		{model.CaseWorkflowClosed, false, false},
		{model.CaseWorkflowInvestigating, true, true}, // reopen from closed
		{model.CaseWorkflowOpen, true, true},
		{model.CaseWorkflowClosed, false, false},
		{model.CaseWorkflowOpen, true, true},
	}
	for _, step := range steps {
		t.Run(step.to, func(t *testing.T) {
			if rec := setStatus(t, mux, c.ID, step.to); rec.Code != http.StatusOK {
				t.Fatalf("saving %q: status %d, body %s", step.to, rec.Code, rec.Body.String())
			}
			var out struct {
				Case             model.Case `json:"case"`
				EvidenceMutable  bool       `json:"evidence_mutable"`
				PriorityEditable bool       `json:"priority_editable"`
			}
			doJSON(t, mux, "GET", "/api/cases/"+c.ID, nil, &out)

			if out.Case.CaseStatus != step.to {
				t.Errorf("case_status = %q, want %q", out.Case.CaseStatus, step.to)
			}
			if out.EvidenceMutable != step.wantMutable {
				t.Errorf("evidence_mutable = %v, want %v -- the client refreshes the lock UI from this",
					out.EvidenceMutable, step.wantMutable)
			}
			if out.PriorityEditable != step.wantPriority {
				t.Errorf("priority_editable = %v, want %v", out.PriorityEditable, step.wantPriority)
			}
		})
	}
}

// The lock is genuinely lifted, not merely reported as lifted: an
// evidence mutation that was refused while Contained must succeed
// immediately after saving Investigating, with no other action between.
func TestLifecycleUI_UnlockTakesEffectImmediatelyForRealMutations(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Unlock takes effect")
	rec := discoverPath(t, mux, c.ID, "../../testdata/synthetic_case")
	if rec.Code != http.StatusOK {
		t.Fatalf("seeding evidence: %d", rec.Code)
	}
	var disc DiscoverResult
	mustDecode(t, rec, &disc)
	sfID, collID := disc.SourceFiles[0].ID, disc.Collection.ID

	importOnce := func() int {
		return doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/evidence/"+collID+"/import",
			map[string][]string{"source_file_ids": {sfID}}, nil).Code
	}

	setStatus(t, mux, c.ID, model.CaseWorkflowContained)
	if got := importOnce(); got != http.StatusConflict {
		t.Fatalf("import while contained: status %d, want 409", got)
	}
	// The exact save from the report.
	setStatus(t, mux, c.ID, model.CaseWorkflowInvestigating)
	if got := importOnce(); got != http.StatusOK {
		t.Errorf("import immediately after saving Investigating: status %d, want 200 -- "+
			"Investigating must allow evidence mutation", got)
	}
	// And it re-locks on the way back.
	setStatus(t, mux, c.ID, model.CaseWorkflowContained)
	if got := importOnce(); got != http.StatusConflict {
		t.Errorf("import after re-containing: status %d, want 409", got)
	}
	setStatus(t, mux, c.ID, model.CaseWorkflowClosed)
	if got := importOnce(); got != http.StatusConflict {
		t.Errorf("import while closed: status %d, want 409", got)
	}
	setStatus(t, mux, c.ID, model.CaseWorkflowOpen)
	if got := importOnce(); got != http.StatusOK {
		t.Errorf("import after reopening: status %d, want 200", got)
	}
}

// The fix must not have weakened the server: enforcement is independent
// of anything the client renders.
func TestLifecycleUI_ServerEnforcementIsIndependentOfTheClient(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Server authority")
	rec := discoverPath(t, mux, c.ID, "../../testdata/synthetic_case")
	var disc DiscoverResult
	mustDecode(t, rec, &disc)
	sfID, collID := disc.SourceFiles[0].ID, disc.Collection.ID

	for _, status := range []string{model.CaseWorkflowContained, model.CaseWorkflowClosed} {
		setStatus(t, mux, c.ID, status)
		before := sourcesSnapshot(t, mux, c.ID)
		for _, attempt := range evidenceMutationAttempts(mux, c.ID, sfID, collID) {
			if got := attempt.Do(t).Code; got != http.StatusConflict {
				t.Errorf("%s while %s: status %d, want 409", attempt.Name, status, got)
			}
		}
		if after := sourcesSnapshot(t, mux, c.ID); after != before {
			t.Errorf("a refused mutation changed the evidence set while %s", status)
		}
	}
}

// ---------------- client-side guard ----------------

// The lock is rendered in TWO places: the case header
// (#case-lock-banner) and the evidence panel inside the tab body
// (#tab-lock-banner). Saving refreshes the first via
// applyLifecycleLocks; the second was refreshed only when a tab was
// re-rendered, which a save deliberately does not do -- so the panel
// kept the stale banner.
//
// This asserts the one property whose absence caused it: that
// applyLifecycleLocks drives the tab-level update too, rather than each
// caller being expected to remember both.
func TestLifecycleUI_DashboardRefreshesBothLockSurfaces(t *testing.T) {
	src, err := os.ReadFile("../web/static/app.js")
	if err != nil {
		t.Fatalf("reading the dashboard source: %v", err)
	}
	body := functionBody(t, src, "function applyLifecycleLocks(")

	if !strings.Contains(body, "applyTabLifecycleLocks()") {
		t.Error("applyLifecycleLocks does not refresh the tab-level lock UI; " +
			"a saved status change will leave #tab-lock-banner showing the previous status")
	}
	if !strings.Contains(body, "case-lock-banner") {
		t.Error("applyLifecycleLocks no longer refreshes the case header banner")
	}
}

// Hiding a control on lock must be matched by restoring it on unlock,
// or reopening a case leaves it permanently stripped.
func TestLifecycleUI_TabLockControlsAreRestoredOnUnlock(t *testing.T) {
	src, err := os.ReadFile("../web/static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	body := functionBody(t, src, "function applyTabLifecycleLocks(")

	// The delete controls must be driven by the lock state in both
	// directions, not hidden one-way.
	if strings.Contains(body, "(b) => (b.hidden = true)") {
		t.Error("evidence delete buttons are hidden one-way; they will stay hidden after the case is reopened")
	}
	if !strings.Contains(body, "b.hidden = locked") {
		t.Error("evidence delete buttons are not driven symmetrically by the lock state")
	}
}

// functionBody returns the source of one top-level function, so a guard
// asserts on the function it means rather than the whole file.
func functionBody(t *testing.T, src []byte, decl string) string {
	t.Helper()
	start := bytes.Index(src, []byte(decl))
	if start < 0 {
		t.Fatalf("%q not found in app.js; update this test", decl)
	}
	rest := src[start+len(decl):]
	end := bytes.Index(rest, []byte("\nfunction "))
	if end < 0 {
		end = len(rest)
	}
	return string(rest[:end])
}

// A pager prefix may embed a collection UUID, and wirePager stores its
// "already wired" marker on element.dataset. A dataset property name
// containing "-" followed by a lowercase letter is rejected by
// DOMStringMap with a SyntaxError -- so a pager scoped by UUID threw for
// some collection ids and not others, purely by whether a hyphen in the
// id happened to precede a letter. That made the failure look
// intermittent and took out the whole integrity panel when it hit.
//
// The key is sanitized at the single place it is built.
func TestPagination_WirePagerKeyIsSafeForUUIDPrefixes(t *testing.T) {
	src, err := os.ReadFile("../web/static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	body := functionBody(t, src, "function wirePager(")

	if strings.Contains(body, "dataset[`pagerWired${prefix}`]") {
		t.Error("wirePager keys its dataset marker on the raw prefix; a prefix containing a UUID " +
			"will throw a SyntaxError for some ids")
	}
	if !strings.Contains(body, `replace(/[^A-Za-z0-9]/g, "")`) {
		t.Error("wirePager does not sanitize the dataset key")
	}
}

// The per-file integrity table lists every file in a collection, so it
// must be paged rather than rendered whole: 1,240 files measured as
// 1,240 rows and ~10,000 DOM nodes before this was added.
func TestPagination_IntegrityTableIsPaged(t *testing.T) {
	src, err := os.ReadFile("../web/static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	body := functionBody(t, src, "function mountIntegrityTable(")

	for _, want := range []string{"pagerFor(", "paginate(", "renderPager(", "wirePager("} {
		if !strings.Contains(body, want) {
			t.Errorf("mountIntegrityTable does not use %s; the table would render every file", want)
		}
	}
	if !strings.Contains(body, "defaultSize: 10") {
		t.Error("the integrity table does not default to 10 rows per page")
	}
	// It must page, not truncate: every file stays reachable.
	if strings.Contains(body, ".slice(0, 100)") || strings.Contains(body, "MAX_") {
		t.Error("the integrity table appears to truncate rather than paginate")
	}
}

// The import result must keep four different outcomes distinguishable:
// imported, skipped (never eligible), parse failure (eligible but
// broken), and duplicate events. Collapsing any pair of them
// misrepresents what Tracefall did with the evidence.
func TestImportResult_SkipsAreBrokenDownByReason(t *testing.T) {
	src, err := os.ReadFile("../web/static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	results := functionBody(t, src, "function renderImportResults(")
	body := functionBody(t, src, "function renderImportSkips(")
	if !strings.Contains(body, "s.reason") {
		t.Error("skipped files are not grouped by their per-file reason")
	}
	if !strings.Contains(body, "not a parse failure") {
		t.Error("the skipped breakdown does not distinguish itself from parse failures")
	}

	// The old lumped wording must be gone from what is RENDERED. It
	// still appears in renderImportSkips's doc comment, quoting the
	// wording it replaced, so the whole file is the wrong thing to
	// search.
	if strings.Contains(results, "already imported/unsupported/duplicate") {
		t.Error("the import result still lumps three distinct skip reasons into one parenthetical")
	}

	// And the parse-failure line must still say what it is not.
	if !strings.Contains(results, "not the same as unsupported evidence") {
		t.Error("the parse-failure line no longer distinguishes itself from unsupported evidence")
	}
	if !strings.Contains(results, "renderImportSkips(") {
		t.Error("renderImportResults no longer calls the per-reason skip breakdown")
	}
}

// The reasons the server emits must stay distinct from one another --
// the UI breakdown is only meaningful if the server does not itself
// collapse them.
func TestImportResult_ServerEmitsDistinctSkipReasons(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Skip reasons")

	hive := persistenceHive()
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		"Users/a/NTUSER.DAT": hive,
		"Users/b/NTUSER.DAT": hive, // duplicate content
		"notes.txt":          []byte("unsupported"),
	})
	coll := disc.Collection.ID

	// Every DISCOVERED file, not just the selectable ones. The ids
	// endpoint returns only what is selectable, which deliberately
	// excludes unsupported and duplicate files -- so asking it would
	// never exercise the skip reasons this test exists to check.
	var listing EvidenceFilePage
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/evidence/"+coll+"/files?page=1&page_size=250", nil, &listing)
	var ids []string
	for _, f := range listing.Items {
		ids = append(ids, f.ID)
	}
	if len(ids) < 3 {
		t.Fatalf("expected 3 discovered files, got %d", len(ids))
	}

	var first ImportResult
	doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/evidence/"+coll+"/import",
		map[string][]string{"source_file_ids": ids}, &first)

	// The first import already yields distinct reasons: the unsupported
	// file has no parser, the second copy of the hive is duplicate
	// content. Re-importing then adds "already imported" on top.
	var second ImportResult
	doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/evidence/"+coll+"/import",
		map[string][]string{"source_file_ids": ids}, &second)

	if len(first.Skipped) == 0 {
		t.Fatal("importing unsupported and duplicate files skipped nothing")
	}
	if len(second.Skipped) == 0 {
		t.Fatal("re-importing an already-imported set skipped nothing")
	}
	reasons := map[string]int{}
	for _, s := range first.Skipped {
		if strings.TrimSpace(s.Reason) == "" {
			t.Errorf("skip for %s carries no reason", s.SourceFileID)
		}
		reasons[s.Reason]++
	}
	for _, s := range second.Skipped {
		if strings.TrimSpace(s.Reason) == "" {
			t.Errorf("skip for %s carries no reason", s.SourceFileID)
		}
		reasons[s.Reason]++
	}
	if len(reasons) < 2 {
		t.Errorf("expected distinguishable skip reasons, got only %v", reasons)
	}
	// A skip must never be reported as a parse failure.
	if len(second.ParseFailures) != 0 {
		t.Errorf("skipped files were reported as parse failures: %+v", second.ParseFailures)
	}
	// Specifically: "no parser available" must never be conflated with a
	// parse failure, and duplicate content must be named as such.
	var sawNoParser, sawDuplicate bool
	for r := range reasons {
		if strings.Contains(r, "no parser") {
			sawNoParser = true
		}
		if strings.Contains(r, "duplicate") {
			sawDuplicate = true
		}
	}
	if !sawNoParser {
		t.Errorf("unsupported file was not skipped with a capability reason: %v", reasons)
	}
	if !sawDuplicate {
		t.Errorf("duplicate content was not skipped with a duplicate reason: %v", reasons)
	}
}

// The `hidden` attribute must actually hide.
//
// Found by browser verification, not by reading code: the stylesheet's
// `button, .btn { display: inline-flex }` is more specific than the user
// agent's `[hidden] { display: none }`, so every control the lifecycle
// code hid with `el.hidden = true` -- Add Evidence and the rest of the
// evidence-mutation set on a contained or closed case -- carried the
// attribute while still rendering at full size. The server refused those
// actions regardless, so nothing unsafe was reachable, but the UI showed
// the opposite of the lock it was reporting.
//
// Every earlier assertion of this behaviour tested `el.hidden`, which
// was true the whole time. Only a computed-geometry check in a real
// browser caught it, so this test guards the CSS rule that fixes it.
func TestUI_HiddenAttributeIsNotOverriddenByDisplayRules(t *testing.T) {
	css, err := os.ReadFile("../web/static/style.css")
	if err != nil {
		t.Fatal(err)
	}
	text := string(css)

	// Anchored at a line start: the same selector appears inside the
	// rule's own explanatory comment, and matching that would measure
	// the comment's position rather than the rule's.
	idx := strings.Index(text, "\n[hidden] {")
	if idx < 0 {
		t.Fatal("no global [hidden] rule: controls hidden by the lifecycle code will still render, " +
			"because `button, .btn { display: inline-flex }` outranks the user agent's [hidden] rule")
	}
	// It must be forceful enough to beat the component rules.
	end := idx + 120
	if end > len(text) {
		end = len(text)
	}
	rule := text[idx:end]
	if !strings.Contains(rule, "display: none !important") {
		t.Errorf("the [hidden] rule does not force display:none; a later display rule will override it:\n%s", rule)
	}
	// And it must come BEFORE the button rule it exists to outrank, so
	// the ordering intent stays visible to the next reader.
	btnIdx := strings.Index(text, "\nbutton, .btn {")
	if btnIdx >= 0 && idx > btnIdx {
		t.Error("the [hidden] rule is declared after `button, .btn`; it relies on !important alone")
	}
}
