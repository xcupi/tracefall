package winevent

import (
	"testing"

	"tracefall/internal/model"
)

func norm(t *testing.T, id int, data map[string]string) model.Event {
	t.Helper()
	ev := model.Event{Extra: map[string]string{}}
	if !Normalize(&ev, Input{Channel: "Security", EventID: id, Data: data}) {
		t.Fatalf("event %d not normalized", id)
	}
	return ev
}

func TestNormalize_AccountAndGroupChanges(t *testing.T) {
	cases := []struct {
		id                  int
		action, object      string
		data                map[string]string
		wantName, wantActor string
	}{
		{4720, "user_created", "user", map[string]string{"TargetUserName": "alice", "TargetDomainName": "HOST01", "TargetSid": "S-1-5-21-1-2-3-1001", "SubjectUserName": "carol", "SubjectLogonId": "0x3e7"}, "alice", "carol"},
		{4722, "user_enabled", "user", map[string]string{"TargetUserName": "alice", "SubjectUserName": "carol"}, "alice", "carol"},
		{4725, "user_disabled", "user", map[string]string{"TargetUserName": "alice", "SubjectUserName": "carol"}, "alice", "carol"},
		{4726, "user_deleted", "user", map[string]string{"TargetUserName": "alice", "SubjectUserName": "carol"}, "alice", "carol"},
		{4724, "password_reset", "user", map[string]string{"TargetUserName": "alice", "SubjectUserName": "carol"}, "alice", "carol"},
		{4738, "user_modified", "user", map[string]string{"TargetUserName": "alice", "SubjectUserName": "carol"}, "alice", "carol"},
		{4731, "group_created", "group", map[string]string{"TargetUserName": "ops", "SubjectUserName": "carol"}, "ops", "carol"},
		{4734, "group_deleted", "group", map[string]string{"TargetUserName": "ops", "SubjectUserName": "carol"}, "ops", "carol"},
		{4732, "group_member_added", "group", map[string]string{"TargetUserName": "Administrators", "MemberSid": "S-1-5-21-1-2-3-1001", "MemberName": "-", "SubjectUserName": "carol"}, "Administrators", "carol"},
		{4728, "group_member_added", "group", map[string]string{"TargetUserName": "Domain Admins", "MemberName": "CN=alice,CN=Users,DC=corp,DC=example", "SubjectUserName": "carol"}, "Domain Admins", "carol"},
		{4756, "group_member_added", "group", map[string]string{"TargetUserName": "Enterprise Admins", "MemberSid": "S-1-5-21-9", "SubjectUserName": "carol"}, "Enterprise Admins", "carol"},
		{4733, "group_member_removed", "group", map[string]string{"TargetUserName": "Administrators", "MemberSid": "S-1-5-21-9", "SubjectUserName": "carol"}, "Administrators", "carol"},
	}
	for _, c := range cases {
		ev := norm(t, c.id, c.data)
		if ev.EventType != model.EventAccountChange || ev.Extra["action"] != c.action || ev.Extra["object_type"] != c.object ||
			ev.Extra["object_name"] != c.wantName || ev.User != c.wantActor {
			t.Errorf("%d: got type=%s extra=%v user=%s", c.id, ev.EventType, ev.Extra, ev.User)
		}
	}
	ev := norm(t, 4732, map[string]string{"TargetUserName": "Administrators", "MemberSid": "S-1-5-21-1-2-3-1001", "MemberName": "-", "SubjectUserName": "carol"})
	if ev.Extra["member"] != "S-1-5-21-1-2-3-1001" {
		t.Errorf("a '-' member name must fall back to the SID, got %q", ev.Extra["member"])
	}
	ev = norm(t, 4720, map[string]string{"TargetUserName": "alice", "TargetDomainName": "HOST01", "TargetSid": "S-1-5-21-1-2-3-1001", "SubjectUserName": "carol", "SubjectDomainName": "HOST01", "SubjectLogonId": "0x3e7"})
	if ev.Extra["object_domain"] != "HOST01" || ev.Extra["object_sid"] != "S-1-5-21-1-2-3-1001" || ev.Extra["logon_id"] != "0x3e7" {
		t.Errorf("identifiers lost: %v", ev.Extra)
	}
}

func TestNormalize_OneLogonIdTiesLogonProcessAndLogoff(t *testing.T) {
	const id = "0x1a2b3c"
	logon := norm(t, 4624, map[string]string{
		"TargetUserName": "alice", "TargetDomainName": "CORP", "TargetLogonId": id, "SubjectLogonId": "0x3e7",
		"LogonType": "10", "IpAddress": "203.0.113.9", "IpPort": "51000", "LogonProcessName": "User32",
		"AuthenticationPackageName": "Negotiate",
	})
	priv := norm(t, 4672, map[string]string{"SubjectUserName": "alice", "SubjectLogonId": id, "SubjectDomainName": "CORP"})
	proc := norm(t, 4688, map[string]string{"SubjectUserName": "alice", "SubjectLogonId": id, "NewProcessName": `C:\Windows\System32\cmd.exe`})
	off := norm(t, 4634, map[string]string{"TargetUserName": "alice", "TargetLogonId": id})
	for name, e := range map[string]model.Event{"4624": logon, "4672": priv, "4688": proc, "4634": off} {
		if e.Extra["logon_id"] != id {
			t.Errorf("%s: logon_id = %q, want %q", name, e.Extra["logon_id"], id)
		}
	}
	if logon.Extra["target_domain"] != "CORP" || logon.Extra["source_port"] != "51000" || logon.Extra["auth_package"] != "Negotiate" {
		t.Errorf("4624 detail: %v", logon.Extra)
	}
	if _, has := logon.Extra["linked_logon_id"]; has {
		t.Error("a field the record did not carry must not be set")
	}
}

func TestNormalize_DashIsNotAValue(t *testing.T) {
	logon := norm(t, 4624, map[string]string{"TargetUserName": "alice", "TargetLogonId": "0x1", "TargetDomainName": "-", "LinkedLogonId": "-"})
	if _, has := logon.Extra["target_domain"]; has {
		t.Error("'-' is Windows' way of writing 'not applicable'")
	}
}
