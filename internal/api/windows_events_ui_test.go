package api

import (
	"strings"
	"testing"
)

func TestUI_WindowsAuditEventCategories(t *testing.T) {
	for _, typ := range []string{"event_log_cleared", "audit_policy_change"} {
		if !strings.Contains(string(appJS(t)), typ+`: "other"`) {
			t.Errorf("%s lacks category", typ)
		}
	}
}

func TestUI_WindowsTaskEventCategory(t *testing.T) {
	if !strings.Contains(string(appJS(t)), `scheduled_task_change: "persistence"`) {
		t.Error("task change lacks persistence category")
	}
}

func TestUI_WindowsRemoteEventCategories(t *testing.T) {
	src := string(appJS(t))
	for _, typ := range []string{"remote_authentication", "session_change"} {
		if !strings.Contains(src, typ+`: "authentication"`) {
			t.Errorf("%s lacks authentication category", typ)
		}
	}
}

func TestUI_WindowsTaskExecutionAndPowerShellEngineCategories(t *testing.T) {
	src := string(appJS(t))
	for typ, cat := range map[string]string{"scheduled_task_run": "execution", "powershell_engine_lifecycle": "other"} {
		if !strings.Contains(src, typ+`: "`+cat+`"`) {
			t.Errorf("%s lacks %s category", typ, cat)
		}
	}
}
