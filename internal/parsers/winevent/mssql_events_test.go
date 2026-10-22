package winevent_test

import (
	"testing"
	"tracefall/internal/evtx/evtxgen"
	"tracefall/internal/model"
	native "tracefall/internal/parsers/evtx"
	"tracefall/internal/parsers/evtxcsv"
	"tracefall/internal/parsers/winevent"
)

func TestMSSQLExplicitMessageOutcome(t *testing.T) {
	var e model.Event
	winevent.Normalize(&e, winevent.Input{Channel: "Application", Provider: "MSSQL$LAB", EventID: 17055, Data: map[string]string{"Message": "Login succeeded for user 'alice'. [CLIENT: 203.0.113.5]"}})
	if e.EventType != model.EventSQLLoginSuccess || e.User != "alice" || e.NetworkSource != "203.0.113.5" {
		t.Fatal("explicit message not normalized", e)
	}
}

func TestMSSQLDescriptionsRedactedNotRawData(t *testing.T) {
	var e model.Event
	text := "net user alice synthetic-only"
	winevent.Normalize(&e, winevent.Input{Channel: "Application", Provider: "MSSQLSERVER", EventID: 17055, Description: text, Data: map[string]string{"Message": text}})
	if e.Extra["rendered_description"] == text {
		t.Fatal("description secret not redacted")
	}
	if e.Extra["sql_data.Message"] != text {
		t.Fatal("raw data mutated")
	}
}

func TestMSSQLAvailableDescriptionPreserved(t *testing.T) {
	var e model.Event
	winevent.Normalize(&e, winevent.Input{Channel: "Application", Provider: "MSSQLSERVER", EventID: 17055, Description: "SQL Server informational message"})
	if e.Extra["rendered_description"] != "SQL Server informational message" {
		t.Fatal("available description lost", e)
	}
	if e.Extra["outcome"] != "" || e.EventType != model.EventSQLMessage {
		t.Fatal("invented outcome", e)
	}
}

func TestMSSQLProviderChannelGateAndParity(t *testing.T) {
	for _, provider := range []string{"MSSQLSERVER", "MSSQL$LAB", "SQLSERVERAGENT", "SQLAgent$LAB"} {
		var e model.Event
		if !winevent.Normalize(&e, winevent.Input{Channel: "Application", Provider: provider, EventID: 18456, Data: map[string]string{"param1": "alice", "param2": "Reason: login rejected", "param3": "[CLIENT: 203.0.113.5]"}}) {
			t.Fatalf("provider %s unmapped", provider)
		}
		if e.Extra["sql_data.param1"] != "alice" || e.Extra["sql_data.param3"] != "[CLIENT: 203.0.113.5]" {
			t.Fatal(e)
		}
		if provider == "MSSQL$LAB" && e.Extra["instance"] != "LAB" {
			t.Fatal(e)
		}
	}
	for _, in := range []winevent.Input{{Channel: "Application", Provider: "Other", EventID: 18456}, {Channel: "Security", Provider: "MSSQLSERVER", EventID: 18456}} {
		var e model.Event
		if winevent.Normalize(&e, in) {
			t.Fatal("claimed unrelated provider/channel", in)
		}
	}
	// Native and CSV share recorded named fields; no rendered-message requirement.
	n, err := native.New().Parse(writeBytes(t, "Application.evtx", evtxgen.Build([]evtxgen.Event{{RecordID: 1, Timestamp: crossTime, Provider: "MSSQL$LAB", Channel: "Application", Computer: "host01", EventID: 18456, Data: map[string]string{"param1": "alice"}}})))
	if err != nil {
		t.Fatal(err)
	}
	c, err := evtxcsv.New().Parse(writeFile(t, "test_EvtxECmd_Output.csv", csvHeader+"2026-01-15T09:15:30Z,18456,MSSQL$LAB,Application,host01,,,,param1: alice,,,,,,1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(n.Events) != 1 || len(c.Events) != 1 {
		t.Fatalf("native=%d CSV=%d", len(n.Events), len(c.Events))
	}
	if n.Events[0].ComputeDedupHash() != c.Events[0].ComputeDedupHash() {
		t.Fatalf("parity failure\n%+v\n%+v", n.Events[0], c.Events[0])
	}
}
