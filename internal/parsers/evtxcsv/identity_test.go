package evtxcsv

import (
	"fmt"
	"testing"
)

func TestRecordIdentity_MissingDoesNotInventRowIdentity(t *testing.T) {
	for _, recordNumber := range []string{"", "not-recorded"} {
		t.Run(recordNumber, func(t *testing.T) {
			text := "TimeCreated,EventId,Channel,ComputerName,PayloadData1,RecordNumber\n"
			row := fmt.Sprintf("2026-01-15T09:00:00Z,4625,Security,host01,TargetUserName: alice; IpAddress: 203.0.113.1,%s\n", recordNumber)
			r, err := New().Parse(writeTemp(t, "EvtxECmd_Output.csv", text+row+row))
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Events) != 2 {
				t.Fatalf("got %d events", len(r.Events))
			}
			if r.Events[0].Extra["evtx_record_id"] != "" {
				t.Fatal("invented Windows record number")
			}
			if r.Events[0].ComputeDedupHash() != r.Events[1].ComputeDedupHash() {
				t.Fatal("row position became record identity")
			}
		})
	}
}
