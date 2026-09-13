package api

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// UI regression tests for the Timeline Detail "Copy" action.
//
// Two things were wrong. Copy was offered ONLY on values long enough to
// be truncated, so an analyst could not copy a short browser URL or a
// deleted file's original path at all. And the copy itself went
// straight to navigator.clipboard.writeText, which is unavailable
// (Chrome) or rejects (Firefox) on a page served over plain HTTP from a
// LAN address -- the way Tracefall is normally reached -- so the button
// that did exist reported "Copy failed".
//
// These read app.js and assert the behaviour, the same approach
// ui_phase14_test.go and ui_daterange_test.go take.

// Requirement 1 and 2: every non-empty Detail value gets a Copy button,
// and a short value does NOT get a reveal toggle, because there is
// nothing hidden to reveal.
func TestUICopy_EveryDetailValueGetsACopyButton(t *testing.T) {
	src := appJS(t)
	body := functionBody(t, src, "function detailCell(")

	// The button must be rendered once, OUTSIDE any length branch. The
	// old code returned a bare <span> for short values and never
	// reached the button at all.
	if n := strings.Count(body, "detail-copy-btn"); n != 1 {
		t.Fatalf("detailCell renders %d copy buttons, want exactly 1 shared by both the short and long paths", n)
	}
	// The only early returns allowed are for an empty value. The old
	// code returned a bare <span class="detail-cell"> for anything at
	// or under the truncation length, which is why short values had no
	// Copy button.
	for _, ret := range regexp.MustCompile(`(?m)^\s*(if \(.*\) )?return .*$`).FindAllString(body, -1) {
		if strings.Contains(ret, "detail-cell") && !strings.Contains(ret, "detail-copy-btn") {
			t.Errorf("detailCell has a return path that renders a detail cell with no Copy button: %s", strings.TrimSpace(ret))
		}
	}
	// The toggle, by contrast, IS conditional on length.
	if !strings.Contains(body, "const toggle = long") {
		t.Error("detailCell does not make the reveal toggle conditional on the value being truncated")
	}
	if !strings.Contains(body, "detail-toggle-btn") {
		t.Error("detailCell no longer renders a reveal toggle for long values")
	}
}

// Requirement 3 and 5: Copy carries the COMPLETE value. The truncated
// form is only ever what is displayed.
func TestUICopy_ButtonCarriesTheCompleteValueNotTheTruncatedOne(t *testing.T) {
	src := appJS(t)
	body := functionBody(t, src, "function detailCell(")

	if !strings.Contains(body, `data-copy="${esc(str)}"`) {
		t.Error("the Copy button does not carry the complete value in data-copy")
	}
	// The truncation must be applied to the DISPLAY only. If the value
	// handed to data-copy were sliced, Copy would produce a value that
	// is not the one on the event.
	copyAttr := regexp.MustCompile(`data-copy="\$\{([^}]*)\}"`).FindStringSubmatch(body)
	if copyAttr == nil {
		t.Fatal("could not find the data-copy expression")
	}
	if strings.Contains(copyAttr[1], "slice") || strings.Contains(copyAttr[1], "short") {
		t.Errorf("data-copy is built from a truncated value: %s", copyAttr[1])
	}
	// A separate truncated value must exist for DISPLAY. The truncation
	// length is configurable (a credential hash is shown shorter than a
	// timeline cell), so the assertion is on the separation, not on the
	// constant.
	if !strings.Contains(body, "const short = str.slice(0,") {
		t.Error("detailCell no longer derives a separate truncated display value")
	}
	if !strings.Contains(body, "DETAIL_TRUNCATE_AT") {
		t.Error("detailCell no longer has a default truncation length")
	}
}

// Requirement 5 again, on the read side: the handler must take the
// value from the attribute, never from the rendered cell text, which
// may be the truncated form ending in an ellipsis.
func TestUICopy_HandlerReadsTheAttributeNotTheDOMText(t *testing.T) {
	src := appJS(t)
	body := functionBody(t, src, "function wireDetailCells(")

	if !strings.Contains(body, "copyText(btn.dataset.copy)") {
		t.Error("the copy handler does not copy btn.dataset.copy")
	}
	for _, banned := range []string{"textContent)", "innerText", "parentElement.textContent"} {
		// The toggle legitimately writes textContent; only the copy
		// handler is under test, so look at the copy branch alone.
		copyBranch := body[strings.Index(body, "detail-copy-btn"):]
		if strings.Contains(copyBranch, banned) {
			t.Errorf("the copy handler reads %s; the displayed text may be truncated", banned)
		}
	}
}

// Requirement 9: the toggle and Copy are independent. Expanding or
// collapsing must not change what a copy produces.
func TestUICopy_ToggleAndCopyAreIndependent(t *testing.T) {
	src := appJS(t)
	body := functionBody(t, src, "function wireDetailCells(")

	toggle := body[:strings.Index(body, "detail-copy-btn")]
	if strings.Contains(toggle, "dataset.copy") {
		t.Error("the reveal toggle writes to data-copy; Show full must only affect display")
	}
	copyBranch := body[strings.Index(body, "detail-copy-btn"):]
	if strings.Contains(copyBranch, "dataset.full") || strings.Contains(copyBranch, "classList") {
		t.Error("the copy handler inspects the expanded/collapsed state; Copy must not depend on it")
	}
}

// Requirement 4: the clipboard implementation. navigator.clipboard
// first, then a temporary textarea + execCommand, then cleanup.
func TestUICopy_ClipboardFallsBackToExecCommand(t *testing.T) {
	src := appJS(t)
	body := functionBody(t, src, "async function copyText(")
	fallback := functionBody(t, src, "function copyTextFallback(")

	if !strings.Contains(body, "navigator.clipboard.writeText(value)") {
		t.Error("copyText does not try navigator.clipboard.writeText first")
	}
	if !strings.Contains(body, "catch") {
		t.Error("copyText does not catch a rejected clipboard promise")
	}
	if !strings.Contains(body, "copyTextFallback(value)") {
		t.Error("copyText does not fall back when the clipboard API is unavailable or rejects")
	}
	// The API must be GUARDED, not just tried: on plain HTTP
	// navigator.clipboard is undefined in Chrome, and reading
	// .writeText off it would throw rather than fall back.
	if !strings.Contains(body, "navigator.clipboard &&") {
		t.Error("copyText does not check that navigator.clipboard exists before using it")
	}
	if !strings.Contains(body, "window.isSecureContext") {
		t.Error("copyText does not check for a secure context; on plain HTTP it must not spend the " +
			"click's user activation on a promise that will reject")
	}

	// The fallback itself.
	if !strings.Contains(fallback, `createElement("textarea")`) {
		t.Error("the fallback does not create a textarea")
	}
	if !strings.Contains(fallback, `document.execCommand("copy")`) {
		t.Error("the fallback does not use document.execCommand")
	}
	if !strings.Contains(fallback, "ta.select()") {
		t.Error("the fallback does not select the textarea contents")
	}
	if !strings.Contains(fallback, "ta.remove()") {
		t.Error("the fallback does not remove the temporary textarea")
	}
	// Cleanup must happen even when execCommand throws.
	if !strings.Contains(fallback, "finally") {
		t.Error("the temporary textarea is not removed in a finally block; a throw would leak it into the DOM")
	}
	if !strings.Contains(fallback, "ta.value = value") {
		t.Error("the fallback does not put the full value in the textarea")
	}
}

// Requirement 7 and 8: report the outcome truthfully. A failed copy
// must never read "Copied" -- an analyst who believes it will paste
// whatever was on the clipboard before into a report.
func TestUICopy_SuccessAndFailureStatesAreDistinct(t *testing.T) {
	src := appJS(t)
	body := functionBody(t, src, "function flashCopyState(")

	if !strings.Contains(body, `ok ? "Copied" : "Copy failed"`) {
		t.Error("flashCopyState does not drive the label from the actual outcome")
	}
	if !strings.Contains(body, "copy-failed") || !strings.Contains(body, "copy-ok") {
		t.Error("flashCopyState does not distinguish success and failure styling")
	}
	// The label must come BACK.
	if !strings.Contains(body, "setTimeout") || !strings.Contains(body, "dataset.copyLabel") {
		t.Error("flashCopyState does not restore the button's normal label")
	}

	// copyText must be able to return false at all -- a helper that
	// always resolves true would make the failure state unreachable.
	ct := functionBody(t, src, "async function copyText(")
	if !strings.Contains(ct, "return false") {
		t.Error("copyText never reports failure")
	}
}

// Several Copy buttons appear on one page (one per timeline row). Their
// state must not be shared, or copying one row would reset the label of
// another mid-flash.
func TestUICopy_ButtonStateIsPerButton(t *testing.T) {
	src := appJS(t)
	body := functionBody(t, src, "function flashCopyState(")

	// Everything the flash remembers must live on the button.
	for _, want := range []string{"btn.dataset.copyTimer", "btn.dataset.copyLabel", "btn.textContent", "btn.classList"} {
		if !strings.Contains(body, want) {
			t.Errorf("flashCopyState does not keep %s on the button itself", want)
		}
	}
	// A second click while a state is showing must not capture
	// "Copied" as the label to restore.
	if !strings.Contains(body, "clearTimeout") {
		t.Error("flashCopyState does not cancel a pending restore; a rapid second click would strand the outcome label")
	}
	if !strings.Contains(body, "else btn.dataset.copyLabel = btn.textContent") {
		t.Error("flashCopyState re-captures the label on every click; a second click would remember \"Copied\" as the normal label")
	}
}

// One clipboard implementation, not two. The evidence-integrity hash
// had its own working fallback while the Detail column had none; that
// divergence is what let the Detail button ship broken.
func TestUICopy_ThereIsOneClipboardImplementation(t *testing.T) {
	src := string(appJS(t))

	// Only copyText may call the async API.
	for _, m := range regexp.MustCompile(`(?m)^.*navigator\.clipboard\.writeText.*$`).FindAllString(src, -1) {
		if strings.Contains(m, "window.isSecureContext") {
			continue // the availability guard inside copyText
		}
		if !strings.Contains(m, "navigator.clipboard.writeText(value)") {
			t.Errorf("a clipboard write bypasses copyText: %s", strings.TrimSpace(m))
		}
	}
	if n := strings.Count(src, `document.execCommand("copy")`); n != 1 {
		t.Errorf("found %d execCommand copy fallbacks, want exactly 1 (in copyTextFallback)", n)
	}
	hash := functionBody(t, []byte(src), "function wireIntegrityHash(")
	if !strings.Contains(hash, "copyText(btn.dataset.hash)") {
		t.Error("the integrity-hash Copy does not go through the shared copyText helper")
	}
	if strings.Contains(hash, `"Copied"`) && strings.Contains(hash, "ok ?") {
		// Correct: driven by the outcome.
	} else {
		t.Error("the integrity-hash Copy does not drive its label from the actual outcome")
	}
}

// The Copy affordance must be reachable for every kind of Detail value
// the Timeline shows -- a URL, a path, a registry value, a command
// line, a Recycle Bin original path. They all come from one function,
// so one Copy button covers all of them; this pins that they are not
// special-cased into separate render paths.
func TestUICopy_AllDetailValuesFlowThroughDetailCell(t *testing.T) {
	src := string(appJS(t))

	// Every Detail column cell is rendered by detailCell(eventDetailValue(...)).
	cells := regexp.MustCompile(`class="mono small detail-td">\$\{([a-zA-Z]+)\(`).FindAllStringSubmatch(src, -1)
	if len(cells) == 0 {
		t.Fatal("no Detail column cells found; update this test")
	}
	for _, c := range cells {
		if c[1] != "detailCell" {
			t.Errorf("a Detail cell is rendered by %s, bypassing detailCell and its Copy button", c[1])
		}
	}

	// And eventDetailValue is the single field chooser, covering URLs,
	// paths, registry values and command lines alike.
	body := functionBody(t, []byte(src), "function eventDetailValue(")
	for _, field := range []string{"command_line", "registry_path", "url", "target_path", "file_path"} {
		if !strings.Contains(body, field) {
			t.Errorf("eventDetailValue no longer considers %s; those events would have nothing to copy", field)
		}
	}
}

// The styling requirement: the failure state must be visible, and must
// not reuse the success colour.
func TestUICopy_FailureStateIsStyled(t *testing.T) {
	css := styleCSS(t)

	if !strings.Contains(css, ".copy-failed") {
		t.Error("style.css has no .copy-failed rule; the failure state would be indistinguishable from the normal button")
	}
	if !strings.Contains(css, ".detail-cell-inline") {
		t.Error("style.css has no layout rule for a short detail cell with a Copy button")
	}
	// The failure state must not be painted with the success colour.
	failRule := css[strings.Index(css, ".copy-failed"):]
	failRule = failRule[:strings.Index(failRule, "}")]
	if strings.Contains(failRule, "var(--ok)") {
		t.Error(".copy-failed uses the success colour")
	}
}

// styleCSS reads the stylesheet the same way appJS reads the script.
func styleCSS(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../web/static/style.css")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
