package detect

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
)

func privEvent(id, host, user string, at time.Time, logon string) model.Event {
	return model.Event{ID: id, CaseID: "c1", EventType: model.EventPrivilegedLogon, Host: host, User: user, Timestamp: at,
		Extra: map[string]string{"logon_id": logon, "privilege_list": "SeTcbPrivilege\r\n\t\tSeDebugPrivilege"}}
}

func TestPrivilegedLogon_AggregatesPerHostAndAccount(t *testing.T) {
	base := mustTime("2026-01-15T09:00:00Z")
	var events []model.Event
	for i := 0; i < 100; i++ {
		events = append(events, privEvent(fmt.Sprintf("a%03d", i), "host01", "alice", base.Add(time.Duration(i)*time.Minute), fmt.Sprintf("0x%x", 100+i)))
	}
	events = append(events, privEvent("b1", "host01", "bob", base, "0x1"), privEvent("c1", "host02", "alice", base, "0x2"))

	got := privilegedLogonObserved{}.Evaluate(events)
	if len(got) != 3 {
		t.Fatalf("got %d findings, want 3 (host01/alice, host01/bob, host02/alice)", len(got))
	}
	var alice *model.Finding
	for i := range got {
		if strings.Contains(got[i].Title, "alice") && strings.Contains(got[i].Title, "host01") {
			alice = &got[i]
		}
		if got[i].Severity != model.SeverityLow {
			t.Errorf("%s severity %s, want low", got[i].Title, got[i].Severity)
		}
	}
	if alice == nil {
		t.Fatal("no finding for host01/alice")
	}
	if !strings.Contains(alice.Description, "100 privileged logon") {
		t.Errorf("description must state the true count: %s", alice.Description)
	}
	if n := len(alice.SupportingEvents); n > supportingCap {
		t.Errorf("supporting list %d exceeds cap %d", n, supportingCap)
	}
	if !alice.FirstSeen.Equal(base) || !alice.LastSeen.Equal(base.Add(99*time.Minute)) {
		t.Errorf("window %s..%s must span the whole run", alice.FirstSeen, alice.LastSeen)
	}
	if !containsID(alice.SupportingEvents, "a000") || !containsID(alice.SupportingEvents, "a099") {
		t.Errorf("first and last events must stay cited: %v", alice.SupportingEvents)
	}
	if !strings.Contains(alice.Description, "SeDebugPrivilege") {
		t.Errorf("distinct privileges missing: %s", alice.Description)
	}
}

func TestPrivilegedLogon_AggregationIsOrderIndependent(t *testing.T) {
	base := mustTime("2026-01-15T09:00:00Z")
	var fwd, rev []model.Event
	for i := 0; i < 60; i++ {
		fwd = append(fwd, privEvent(fmt.Sprintf("e%02d", i), "host01", "alice", base.Add(time.Duration(i)*time.Second), "0x1"))
	}
	for i := len(fwd) - 1; i >= 0; i-- {
		rev = append(rev, fwd[i])
	}
	a, b := privilegedLogonObserved{}.Evaluate(fwd), privilegedLogonObserved{}.Evaluate(rev)
	if len(a) != 1 || len(b) != 1 || strings.Join(a[0].SupportingEvents, ",") != strings.Join(b[0].SupportingEvents, ",") || a[0].Description != b[0].Description {
		t.Fatal("aggregation depends on input order")
	}
}

func containsID(ids []string, id string) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}
