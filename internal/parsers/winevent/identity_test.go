package winevent_test

import (
	"fmt"
	"testing"

	"tracefall/internal/evtx/evtxgen"
	nativeevtx "tracefall/internal/parsers/evtx"
	"tracefall/internal/parsers/evtxcsv"
)

func TestCrossSource_RecordIdentityNotSourceInstance(t *testing.T) {
	for _, tc := range []struct {
		name, channel, provider string
		id                      int
		data                    map[string]string
		payload                 string
	}{
		{"session", "Security", "Microsoft-Windows-Security-Auditing", 4624, map[string]string{"TargetUserName": "alice", "TargetDomainName": "DOMAIN01", "TargetLogonId": "0x123"}, "TargetUserName: alice; TargetDomainName: DOMAIN01; TargetLogonId: 0x123"},
		{"group", "Security", "Microsoft-Windows-Security-Auditing", 4732, map[string]string{"SubjectUserName": "alice", "TargetUserName": "Users", "MemberSid": "S-1-5-21-1001"}, "SubjectUserName: alice; TargetUserName: Users; MemberSid: S-1-5-21-1001"},
		{"script", "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell", 4104, map[string]string{"ScriptBlockText": "Get-Process", "ScriptBlockId": "block01", "MessageNumber": "2"}, "ScriptBlockText: Get-Process; ScriptBlockId: block01; MessageNumber: 2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var records []evtxgen.Event
			for _, id := range []uint64{1, 2, 1} {
				records = append(records, evtxgen.Event{RecordID: id, Timestamp: crossTime, Computer: "host01", Channel: tc.channel, Provider: tc.provider, EventID: tc.id, Data: tc.data})
			}
			n, err := nativeevtx.New().Parse(writeBytes(t, "Log.evtx", evtxgen.Build(records)))
			if err != nil {
				t.Fatal(err)
			}
			// The CSV row order differs from native order; padded record IDs are
			// still the original Windows record numbers, not new source instances.
			csv := csvHeader
			for _, id := range []string{"0002", "0001", "0001"} {
				csv += fmt.Sprintf("%s,%d,%s,%s,host01,,-,Desc,%s,,,,,,%s\n", crossTime.Format("2006-01-02T15:04:05.0000000Z"), tc.id, tc.provider, tc.channel, csvField(tc.payload), id)
			}
			c, err := evtxcsv.New().Parse(writeFile(t, "EvtxECmd_Output.csv", csv))
			if err != nil {
				t.Fatal(err)
			}
			if len(n.Events) != 3 || len(c.Events) != 3 {
				t.Fatalf("unexpected parse counts: native=%d csv=%d", len(n.Events), len(c.Events))
			}
			if n.Events[0].ComputeDedupHash() == n.Events[1].ComputeDedupHash() {
				t.Fatal("distinct Windows record IDs collapsed despite identical semantic content/time")
			}
			if n.Events[0].ComputeDedupHash() != n.Events[2].ComputeDedupHash() {
				t.Fatal("true duplicate native record inflated timeline")
			}
			for i, j := range []int{1, 0, 2} {
				if n.Events[i].ComputeDedupHash() != c.Events[j].ComputeDedupHash() {
					t.Errorf("record identity differs across reordered exports: native %d csv %d", i, j)
				}
			}
		})
	}
}
