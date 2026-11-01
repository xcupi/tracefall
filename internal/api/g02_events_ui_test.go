package api

import (
	"strings"
	"testing"
)

// Every event type added by the G02 EVTX coverage work needs a category in the
// timeline UI, or it falls into an unlabeled bucket. None is "execution": a
// trigger, an ignored launch, an exit record or a pipeline error does not show
// that a program ran, and configuration records are not process activity.
func TestUI_G02EventTypeCategories(t *testing.T) {
	src := string(appJS(t))
	for typ, cat := range map[string]string{
		"antimalware_configuration_change": "other",
		"antimalware_history_deleted":      "other",
		"wmi_activity":                     "other",
		"scheduled_task_launch":            "other",
		"smb_security_event":               "authentication",
		"token_right_adjusted":             "other",
		"process_exit":                     "other",
		"powershell_pipeline_error":        "other",
	} {
		if !strings.Contains(src, "  "+typ+`: "`+cat+`"`) {
			t.Errorf("%s lacks the %q category in app.js", typ, cat)
		}
	}
}
