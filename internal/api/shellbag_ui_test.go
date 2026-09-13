package api

import (
	"strings"
	"testing"
)

// The ShellBags Detail column and hierarchy panel.

// The Detail column must show the reconstructed PATH -- the folder's
// place in the tree -- not the registry key, which is nearly identical
// on every row.
func TestShellBagUI_DetailShowsTheReconstructedPath(t *testing.T) {
	body := functionBody(t, appJS(t), "function eventDetailValue(")
	if !strings.Contains(body, "extra.reconstructed_path") {
		t.Error("the Detail column does not show the reconstructed ShellBags path")
	}
}

// The hierarchy has to be inspectable, and a level that could not be
// decoded must be VISIBLE as a gap rather than removed.
func TestShellBagUI_HierarchyPanelShowsEveryLevel(t *testing.T) {
	panel := functionBody(t, appJS(t), "function shellBagPanel(")
	if panel == "" {
		t.Fatal("there is no ShellBags hierarchy panel")
	}
	if !strings.Contains(panel, `ev.event_type !== "shellbag_navigation"`) {
		t.Error("the panel is not gated on the ShellBags event type")
	}
	// It renders the chain level by level.
	if !strings.Contains(panel, "sb-chain") || !strings.Contains(panel, "sb-level") {
		t.Error("the panel does not render the chain level by level")
	}
	// An undecoded level is marked, not hidden.
	if !strings.Contains(panel, "(undecoded)") || !strings.Contains(panel, "sb-undecoded") {
		t.Error("an undecoded level is not distinguished in the chain")
	}
	if !strings.Contains(panel, "not decoded") {
		t.Error("an undecoded level does not say so in words")
	}
	// The relationship metadata an analyst needs.
	for _, field := range []string{
		"parent_name", "parent_path", "shellbag_node", "parent_registry_key",
		"shell_item_kind", "registry_last_write", "shell_item_name_source",
	} {
		if !strings.Contains(panel, field) {
			t.Errorf("the panel does not show %s", field)
		}
	}
	// An incomplete path must state its limitation.
	if !strings.Contains(panel, "path_limitation") || !strings.Contains(panel, "path_complete") {
		t.Error("the panel does not report whether the path is complete")
	}
	// The forensic meaning must travel with it.
	if !strings.Contains(panel, "evidence_meaning") || !strings.Contains(panel, "timestamp_meaning") {
		t.Error("the panel drops the ShellBags evidence and timestamp meaning")
	}
	// And it must be wired into the detail view.
	loader := functionBody(t, appJS(t), "async function loadProvenanceInto(")
	if !strings.Contains(loader, "shellBagPanel(") {
		t.Error("the hierarchy panel is not rendered in the event detail view")
	}
	if !strings.Contains(styleCSS(t), ".sb-chain") {
		t.Error("the hierarchy panel has no styling")
	}
}
