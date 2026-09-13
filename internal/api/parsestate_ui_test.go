package api

import (
	"strings"
	"testing"
)

// The import UI must separate the states a file can end in. Reporting
// "unsupported artifact", "unsupported compression", "misclassified",
// "corrupt", "empty" and "limit reached" identically told an analyst
// nothing about which they were looking at -- and three of those mean
// the evidence is FINE.
func TestParseStateUI_EveryCategoryIsNamedAndExplained(t *testing.T) {
	src := string(appJS(t))
	labels := functionBodyOrConst(t, src, "const PARSE_CATEGORY_LABELS")
	notes := functionBodyOrConst(t, src, "const PARSE_CATEGORY_NOTE")

	for _, c := range []string{
		ParseFailureUnsupported,
		ParseFailureUnsupportedCompression,
		ParseFailureMisclassified,
		ParseFailureCorrupt,
		ParseFailureEmpty,
		ParseFailureLimit,
		ParseFailureUnreadable,
		ParseFailureInternal,
	} {
		if !strings.Contains(labels, c+":") {
			t.Errorf("the UI has no label for parse state %q; it would render the raw constant", c)
		}
		if !strings.Contains(notes, c+":") {
			t.Errorf("the UI does not explain what parse state %q means for the evidence", c)
		}
	}

	// The states that mean the evidence is intact must say so.
	for _, c := range []string{ParseFailureUnsupported, ParseFailureMisclassified, ParseFailureEmpty} {
		idx := strings.Index(notes, c+":")
		line := notes[idx:]
		if end := strings.Index(line, "\n"); end > 0 {
			line = line[:end]
		}
		low := strings.ToLower(line)
		if !strings.Contains(low, "intact") && !strings.Contains(low, "nothing is wrong") &&
			!strings.Contains(low, "no content") {
			t.Errorf("%q does not tell the analyst the evidence itself is fine: %s", c, strings.TrimSpace(line))
		}
	}

	// And the one that means it is NOT fine must not.
	corrupt := notes[strings.Index(notes, ParseFailureCorrupt+":"):]
	if end := strings.Index(corrupt, "\n"); end > 0 {
		corrupt = corrupt[:end]
	}
	if !strings.Contains(strings.ToLower(corrupt), "damaged") {
		t.Errorf("the corrupt state does not say the evidence is damaged: %s", strings.TrimSpace(corrupt))
	}
}

// The state must be visible in both places failures are shown.
func TestParseStateUI_StateIsRenderedInTheTableAndTheSummary(t *testing.T) {
	src := string(appJS(t))

	row := functionBody(t, appJS(t), "function parseFailureRow(")
	if !strings.Contains(row, "parseCategoryLabel(f.category)") {
		t.Error("the per-file row does not show the parse state")
	}
	groups := functionBody(t, appJS(t), "function renderParseFailureGroups(")
	if !strings.Contains(groups, "parseCategoryLabel(g.category)") {
		t.Error("the grouped summary does not show the parse state")
	}
	if !strings.Contains(groups, "PARSE_CATEGORY_NOTE[g.category]") {
		t.Error("the grouped summary does not explain what the state means")
	}
	// The table header must have a column for it, or the cell lands
	// under the wrong heading.
	if !strings.Contains(src, "<th>State</th>") {
		t.Error("the parse-error table has no State column")
	}
	if !strings.Contains(styleCSS(t), ".parse-category") {
		t.Error("the parse state has no styling")
	}
}

// functionBodyOrConst returns the source of a top-level const block,
// which functionBody cannot reach because it looks for "\nfunction ".
func functionBodyOrConst(t *testing.T, src, decl string) string {
	t.Helper()
	start := strings.Index(src, decl)
	if start < 0 {
		t.Fatalf("%q not found in app.js", decl)
	}
	rest := src[start:]
	end := strings.Index(rest, "\n};")
	if end < 0 {
		t.Fatalf("%q is not a closed const block", decl)
	}
	return rest[:end]
}
