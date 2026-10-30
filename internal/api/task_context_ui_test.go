package api

import (
	"strings"
	"testing"
	"tracefall/internal/model"
)

func TestUI_TaskContextsAreNeutralCards(t *testing.T) {
	src := string(appJS(t))
	for typ, label := range map[string]string{model.CorrelationTaskInstanceContext: "Task instance context", model.CorrelationTaskProcessContext: "Task process context"} {
		if !strings.Contains(src, typ+`: "`+label+`"`) {
			t.Errorf("missing context label %s", typ)
		}
	}
	start := strings.Index(src, "function isChainCorrelationType(")
	end := strings.Index(src[start:], "\n}") + start
	if start < 0 || end < start {
		t.Fatal("chain classifier absent")
	}
	if strings.Contains(src[start:end], "task_instance_context") || strings.Contains(src[start:end], "task_process_context") {
		t.Fatal("context promoted to causal flow")
	}
	if !strings.Contains(src, "Recorded observation window:") {
		t.Fatal("context lacks noncausal time label")
	}
}
