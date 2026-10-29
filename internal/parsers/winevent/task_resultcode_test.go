package winevent_test

import (
	"fmt"
	"testing"

	"tracefall/internal/model"
	"tracefall/internal/parsers/winevent"
)

// Input is the shared contract, including already-decoded CSV adapter values.
// Export formatting is not an original XML/BinXML fidelity guarantee.
func TestTaskCompletionResultCodeLiteralPresence(t *testing.T) {
	for _, id := range []int{201, 202} {
		for _, code := range []string{"", "-", " ", "\t\r\n", "\u00a0\u2003\t0\r\n\u202f", "0", "00", "0x00000000", "2147942401", "0xZZ", "not-a-number"} {
			t.Run(fmt.Sprintf("%d/%q", id, code), func(t *testing.T) {
				e := model.Event{}
				if !winevent.Normalize(&e, winevent.Input{Channel: taskChannel, Provider: taskProvider, EventID: id, Data: map[string]string{"ResultCode": code, "TaskName": " task "}}) {
					t.Fatal("record not mapped")
				}
				if got, present := e.Extra["result_code"]; !present || got != code {
					t.Fatalf("literal ResultCode = %q (%t), want %q", got, present, code)
				}
				action, outcome := "task_action_completed", "observed"
				if id == 202 {
					action, outcome = "task_action_failed", "failure"
				}
				if e.Extra["action"] != action || e.Extra["outcome"] != outcome || e.EventType != model.EventScheduledTaskRun {
					t.Fatal("ResultCode must not infer program success/failure or change record semantics")
				}
				if e.User != "" || e.PID != 0 || e.ProcessName != "" || e.CommandLine != "" || e.Extra["process_id"] != "" {
					t.Fatal("completion/failure must not invent actor or payload execution")
				}
				if id == 201 && e.Extra["task_name"] != "task" {
					t.Fatal("unrelated trimming changed")
				}
			})
		}
		for _, data := range []map[string]string{nil, {}, {"TaskName": "task"}} {
			e := model.Event{}
			if !winevent.Normalize(&e, winevent.Input{Channel: taskChannel, Provider: taskProvider, EventID: id, Data: data}) {
				t.Fatal("missing code record not mapped")
			}
			if _, present := e.Extra["result_code"]; present {
				t.Fatal("absent ResultCode invented")
			}
			outcome := "observed"
			if id == 202 {
				outcome = "failure"
			}
			if e.Extra["outcome"] != outcome {
				t.Fatal("absent code inferred outcome")
			}
		}
	}
}

func TestTaskCompletionResultCodeAdapterSemanticParity(t *testing.T) {
	for _, code := range []string{"0", "0000", "2147942401", "0xZZ"} {
		assertServerMapping(t, winevent.Input{Channel: taskChannel, Provider: taskProvider, EventID: 201, Data: map[string]string{"ResultCode": code}}, model.EventScheduledTaskRun, "", "", map[string]string{"action": "task_action_completed", "outcome": "observed", "result_code": code})
	}
	// No export token is supplied: both adapters must leave the code absent.
	assertServerMapping(t, winevent.Input{Channel: taskChannel, Provider: taskProvider, EventID: 201}, model.EventScheduledTaskRun, "", "", map[string]string{"action": "task_action_completed", "outcome": "observed"})
}
