package evtx_test

import (
	"testing"
	"time"

	"tracefall/internal/evtx/evtxgen"
	"tracefall/internal/model"
	parser "tracefall/internal/parsers/evtx"
)

func TestTaskActionFailureLiteralTimeIdentityCoverage(t *testing.T) {
	const provider = "Microsoft-Windows-TaskScheduler"
	const channel = provider + "/Operational"
	ts := time.Date(2026, 1, 15, 9, 0, 0, 123456700, time.UTC)
	data := map[string]string{"TaskName": "task", "TaskInstanceId": "{aAbB}", "InstanceId": "not-the-recorded-instance", "ActionName": "tool.exe", "EnginePID": "00900", "ResultCode": "0x00000000"}
	records := []evtxgen.Event{
		{RecordID: 1, Timestamp: ts, Computer: "host01", Channel: channel, Provider: provider, EventID: 202, Data: data},
		{RecordID: 2, Timestamp: ts, Computer: "host01", Channel: channel, Provider: provider, EventID: 202, Data: data},
		{RecordID: 1, Timestamp: ts, Computer: "host01", Channel: channel, Provider: provider, EventID: 202, Data: data},
		{RecordID: 3, Computer: "host01", Channel: channel, Provider: provider, EventID: 202},
		{RecordID: 4, Timestamp: ts, Channel: channel, Provider: "Other", EventID: 202, Data: data},
		{RecordID: 5, Timestamp: ts, Channel: "Application", Provider: provider, EventID: 202, Data: data},
		{RecordID: 6, Timestamp: ts, Channel: channel, Provider: provider, EventID: 9999},
	}
	r, err := parser.New().Parse(writeLog(t, records))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Events) != 4 || len(r.Raw) != 4 || r.Coverage.RecordsRead != 7 || r.Coverage.Mapped != 4 || r.Coverage.Unmapped != 3 || r.Coverage.Undated != 1 {
		t.Fatalf("incorrect coverage: %+v", r.Coverage)
	}
	for i, e := range r.Events {
		if e.EventType != model.EventScheduledTaskRun || e.Extra["action"] != "task_action_failed" || e.Extra["outcome"] != "failure" || e.User != "" || e.ProcessName != "" || e.CommandLine != "" {
			t.Fatal("failure reinterpreted")
		}
		if e.SourceReference != r.Raw[i].SourceReference || e.Extra["event_provider"] != provider || e.Extra["event_channel"] != channel || e.Extra["evtx_channel"] != channel {
			t.Fatal("provenance lost")
		}
		if i < 3 {
			if !e.Timestamp.Equal(ts) || e.Timestamp.Nanosecond() != 123456700 {
				t.Fatal("100 ns timestamp precision lost")
			}
			for src, dst := range map[string]string{"TaskName": "task_name", "TaskInstanceId": "task_instance_id", "EnginePID": "engine_pid", "ResultCode": "result_code"} {
				if e.Extra[dst] != data[src] {
					t.Errorf("literal %s lost", src)
				}
			}
		} else if !e.Timestamp.IsZero() || e.Extra["timestamp_basis"] != "not_recorded" {
			t.Fatal("invented missing time")
		}
	}
	if r.Events[0].ComputeDedupHash() == r.Events[1].ComputeDedupHash() || r.Events[0].ComputeDedupHash() != r.Events[2].ComputeDedupHash() {
		t.Fatal("record identity changed")
	}
}
