package srum

import (
	"strings"
	"testing"

	"tracefall/internal/ese/esegen"
)

// The wording is part of the contract (added after independent review): each
// phrase below was deleted or altered by a mutation that survived.
func TestNetworkWordingContract(t *testing.T) {
	for _, c := range []struct{ name, text, want string }{
		{"limits: left the host", limitsNet, "does not show that data left the host"},
		{"limits: network evidence", limitsNet, "must come from network evidence, never from SRUM"},
		{"limits: not a flow", limitsNet, "Not a flow"},
		{"limits: in/out not verified", limitsNet, "not verified"},
		{"net use: unit", meaningNetUse, "Bytes"},
		{"net use: not a flow", meaningNetUse, "not a flow"},
		{"sdp: not a flow", meaningSDPNet, "not a flow"},
		{"sdp: unit unverified", meaningSDPNet, "NOT been verified"},
		{"sdp: adapter is hedged", meaningSDPNet, "for example, a network adapter"},
		{"sdp: public tools say so", meaningSDPNet, "public tools call them"},
		{"time basis: uncalibrated", timeBasis, "has not been calibrated"},
	} {
		if !strings.Contains(c.text, c.want) {
			t.Errorf("%s: %q missing from %q", c.name, c.want, c.text)
		}
	}
	if strings.Contains(strings.ToLower(meaningSDPNet), "packet") {
		t.Error("SDP wording must not name a packet unit")
	}
}

// A deleted record in a table Tracefall does not interpret is still counted in
// the census (it showed a mutant that dropped the count).
func TestCensusCountsDeletedRecordsOfUninterpretedTables(t *testing.T) {
	gone := esegen.Record{Defunct: true, Fixed: map[uint32][]byte{1: i32(2), 2: ole(t0), 3: i32(1), 4: i32(5)}}
	other := esegen.Table{Name: guidTimeln, Columns: common(), Records: []esegen.Record{
		{Fixed: map[uint32][]byte{1: i32(1), 2: ole(t0), 3: i32(1), 4: i32(5)}}, gone}}
	_, _, cov := parse(t, write(t, []esegen.Table{standardIDs(), other}, esegen.Options{}))
	if r := tableRow(t, cov, guidTimeln); r.Rows != 1 || r.Deleted != 1 || r.Interpreted {
		t.Errorf("census row = %+v, want 1 live row, 1 deleted, not interpreted", r)
	}
}
