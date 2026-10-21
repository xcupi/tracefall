package evtxcsv

import (
	"os"
	"path/filepath"
	"testing"
)

// The raw EVTX parser keeps a record whose timestamp is unusable, undated.
// The CSV path must do the same: dropping the row would lose evidence only
// when the log arrives as an export.
func TestParse_RowWithoutUsableTimeIsKeptUndated(t *testing.T) {
	csv := "TimeCreated,EventId,Provider,Channel,ComputerName,UserName,RemoteHost,MapDescription,PayloadData1,PayloadData2,PayloadData3,PayloadData4,PayloadData5,PayloadData6,RecordNumber\n" +
		",4624,Microsoft-Windows-Security-Auditing,Security,host01,alice,,Successful logon,TargetUserName: alice; LogonType: 2,,,,,,7\n"
	f := filepath.Join(t.TempDir(), "export_EvtxECmd_Output.csv")
	if err := os.WriteFile(f, []byte(csv), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := New().Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want the undated row kept", len(res.Events))
	}
	e := res.Events[0]
	if !e.Timestamp.IsZero() || e.Extra["timestamp_basis"] != "not_recorded" {
		t.Fatalf("timestamp=%v basis=%q, want zero time and basis not_recorded", e.Timestamp, e.Extra["timestamp_basis"])
	}
}
