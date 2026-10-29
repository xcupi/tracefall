package evtx_test

import (
	"encoding/json"
	"testing"
	"time"

	"tracefall/internal/evtx/evtxgen"
	"tracefall/internal/model"
	parser "tracefall/internal/parsers/evtx"
	"tracefall/internal/parsers/winevent"
)

// These fixtures are native BinXML string substitutions, not XML sidecars.
func TestNativeResultCodeLiteral(t *testing.T) {
	const provider = "Microsoft-Windows-TaskScheduler"
	const channel = provider + "/Operational"
	ts := time.Date(2026, 1, 15, 9, 0, 0, 123456700, time.UTC)
	values := []string{"", "0", " 0x00000000 ", "\u00a0\u2003\t0\r\n\u202f", "\t\r\n", "-", "not-a-number", "00", "0xZZ", "0<&\"'"}
	for _, id := range []int{201, 202} {
		for _, value := range values {
			data := map[string]string{"ResultCode": value, "TaskName": " \ttask\r\n ", "EnginePID": "00900"}
			result, err := parser.New().Parse(writeLog(t, []evtxgen.Event{{RecordID: 9, EventID: id, Provider: provider, Channel: channel, Computer: "host01", Timestamp: ts, Data: data}}))
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Events) != 1 || len(result.Raw) != 1 || result.Coverage.RecordsRead != 1 || result.Coverage.Mapped != 1 || result.Coverage.Unmapped != 0 {
				t.Fatalf("coverage changed: %+v", result.Coverage)
			}
			var raw struct {
				Data map[string]string `json:"event_data"`
			}
			if err := json.Unmarshal([]byte(result.Raw[0].Raw), &raw); err != nil {
				t.Fatal(err)
			}
			if got, ok := raw.Data["ResultCode"]; !ok || got != value {
				t.Fatalf("native %d raw ResultCode = %q (%t), want %q", id, got, ok, value)
			}
			if raw.Data["TaskName"] != "task" {
				t.Fatal("unrelated field trimming changed")
			}
			e := result.Events[0]
			if !e.Timestamp.Equal(ts) || e.Timestamp.Nanosecond() != 123456700 || e.SourceReference != "record:9" || e.Extra["event_provider"] != provider || e.Extra["event_channel"] != channel || e.Host != "HOST01" || e.Extra["evtx_computer"] != "host01" {
				t.Fatal("record identity, provider/channel case or time changed")
			}
			// Adapter must feed the same literal to the shared mapper.
			want := model.Event{Extra: map[string]string{}}
			if !winevent.Normalize(&want, winevent.Input{EventID: id, Channel: channel, Provider: provider, Data: raw.Data}) {
				t.Fatal("shared mapping rejected record")
			}
			got, gotOK := e.Extra["result_code"]
			wantValue, wantOK := want.Extra["result_code"]
			if got != wantValue || gotOK != wantOK {
				t.Fatal("adapter/shared literal input parity lost")
			}
			if got != value || !gotOK {
				t.Fatalf("native %d normalized literal = %q (%t), want %q", id, got, gotOK, value)
			}
			action, outcome := "task_action_completed", "observed"
			if id == 202 {
				action, outcome = "task_action_failed", "failure"
			}
			if e.Extra["action"] != action || e.Extra["outcome"] != outcome || e.EventType != model.EventScheduledTaskRun {
				t.Fatal("literal code changed recorded action/outcome")
			}
		}
	}
	for _, id := range []int{201, 202} {
		result, err := parser.New().Parse(writeLog(t, []evtxgen.Event{{RecordID: 10, EventID: id, Provider: provider, Channel: channel, Timestamp: ts}}))
		if err != nil || len(result.Events) != 1 {
			t.Fatalf("missing-field parse: %v", err)
		}
		if _, ok := result.Events[0].Extra["result_code"]; ok {
			t.Fatal("missing result code fabricated")
		}
	}
}

func TestNativeSecurityResultCodeDoesNotChangeSemantics(t *testing.T) {
	for _, id := range []int{4624, 4625} {
		parse := func(code string) model.Event {
			r, err := parser.New().Parse(writeLog(t, []evtxgen.Event{{RecordID: 1, EventID: id, Provider: "Microsoft-Windows-Security-Auditing", Channel: "Security", Data: map[string]string{"TargetUserName": "alice", "ResultCode": code}}}))
			if err != nil || len(r.Events) != 1 {
				t.Fatalf("security parse: %v", err)
			}
			return r.Events[0]
		}
		a, b := parse("0"), parse("\u2003\t0\r\n")
		x, _ := json.Marshal(a)
		y, _ := json.Marshal(b)
		if string(x) != string(y) || a.ComputeDedupHash() != b.ComputeDedupHash() {
			t.Fatal("unrelated Security mapping changed")
		}
	}
}
