package winevent_test

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"tracefall/internal/evtx/evtxgen"
	"tracefall/internal/model"
	native "tracefall/internal/parsers/evtx"
	"tracefall/internal/parsers/evtxcsv"
	"tracefall/internal/parsers/winevent"
)

const securityProvider = "Microsoft-Windows-Security-Auditing"

// Both real parser entry points consume synthetic bytes, not reconstructed Events.
func assertServerMapping(t *testing.T, in winevent.Input, typ, user, src string, extra map[string]string) {
	t.Helper()
	ts := time.Date(2026, 1, 15, 9, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	bin := filepath.Join(dir, "events.evtx")
	if err := os.WriteFile(bin, evtxgen.Build([]evtxgen.Event{{RecordID: 1, Timestamp: ts, Computer: "HOST01", Channel: in.Channel, Provider: in.Provider, EventID: in.EventID, Data: in.Data}}), 0600); err != nil {
		t.Fatal(err)
	}
	cp := filepath.Join(dir, "EvtxECmd.csv")
	f, err := os.Create(cp)
	if err != nil {
		t.Fatal(err)
	}
	w := csv.NewWriter(f)
	keys := make([]string, 0, len(in.Data))
	for k := range in.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := []string{}
	for _, k := range keys {
		parts = append(parts, k+": "+in.Data[k])
	}
	_ = w.Write([]string{"TimeCreated", "EventId", "Provider", "Channel", "ComputerName", "PayloadData1"})
	_ = w.Write([]string{ts.Format(time.RFC3339), fmt.Sprint(in.EventID), in.Provider, in.Channel, "HOST01", strings.Join(parts, "; ")})
	w.Flush()
	if err := w.Error(); err != nil {
		t.Fatal(err)
	}
	f.Close()
	a, err := native.New().Parse(bin)
	if err != nil {
		t.Fatal(err)
	}
	b, err := evtxcsv.New().Parse(cp)
	if err != nil {
		t.Fatal(err)
	}
	for label, res := range map[string][]model.Event{"native": a.Events, "csv": b.Events} {
		if len(res) != 1 {
			t.Errorf("%s mapped %d records, want 1", label, len(res))
			continue
		}
		e := res[0]
		if e.EventType != typ || e.User != user || e.NetworkSource != src {
			t.Errorf("%s type/user/source = %q/%q/%q, want %q/%q/%q", label, e.EventType, e.User, e.NetworkSource, typ, user, src)
		}
		for k, v := range extra {
			if e.Extra[k] != v {
				t.Errorf("%s extra[%s]=%q want %q", label, k, e.Extra[k], v)
			}
		}
		if e.Extra["event_provider"] != in.Provider || e.Extra["event_channel"] != in.Channel {
			t.Errorf("%s lost provider/channel: %v", label, e.Extra)
		}
		if e.Extra["evidence_meaning"] == "" || e.Extra["limitations"] == "" {
			t.Errorf("%s lacks meaning/limitations", label)
		}
	}
	if len(a.Events) == 1 && len(b.Events) == 1 {
		ae, be := a.Events[0], b.Events[0]
		for k := range ae.Extra {
			if strings.HasPrefix(k, "evtx_") {
				delete(ae.Extra, k)
			}
		}
		ae.Parser = ""
		be.Parser = ""
		ae.SourceReference = ""
		be.SourceReference = ""
		if !reflect.DeepEqual(ae, be) {
			t.Errorf("native/CSV normalized events differ:\n%+v\n%+v", ae, be)
		}
	}
	// These IDs belong only to the exact provider AND channel.
	for _, bad := range []winevent.Input{{Channel: in.Channel, Provider: "Unrelated-Provider", EventID: in.EventID, Data: in.Data}, {Channel: "Application", Provider: in.Provider, EventID: in.EventID, Data: in.Data}, {Channel: in.Channel, EventID: in.EventID, Data: in.Data}} {
		e := model.Event{Extra: map[string]string{}}
		if winevent.Normalize(&e, bad) {
			t.Errorf("accepted wrong provider/channel: %+v", bad)
		}
	}
}

func TestServerKerberosPreauthFailure(t *testing.T) {
	assertServerMapping(t, winevent.Input{Channel: "Security", Provider: securityProvider, EventID: 4771, Data: map[string]string{"TargetUserName": "alice", "TargetSid": "S-1-5-21-1001", "TargetDomainName": "LAB", "ServiceName": "krbtgt/LAB", "IpAddress": "203.0.113.10", "IpPort": "53012", "Status": "0x18", "PreAuthType": "2", "TicketOptions": "0x40810010"}}, "logon_failure", "alice", "203.0.113.10", map[string]string{"target_user_sid": "S-1-5-21-1001", "target_domain": "LAB", "service_name": "krbtgt/LAB", "source_port": "53012", "failure_reason": "0x18", "pre_auth_type": "2", "ticket_options": "0x40810010", "auth_package": "Kerberos", "auth_stage": "preauthentication", "action": "kerberos_preauthentication_failed", "outcome": "failure"})
}

func TestServerComputerAccountChanges(t *testing.T) {
	for _, tc := range []struct {
		id     int
		action string
	}{{4741, "computer_created"}, {4742, "computer_modified"}, {4743, "computer_deleted"}} {
		t.Run(fmt.Sprint(tc.id), func(t *testing.T) {
			assertServerMapping(t, winevent.Input{Channel: "Security", Provider: securityProvider, EventID: tc.id, Data: map[string]string{"SubjectUserName": "alice", "SubjectDomainName": "LAB", "SubjectUserSid": "S-1-5-21-1001", "SubjectLogonId": "0x42", "TargetUserName": "HOST02$", "TargetDomainName": "LAB", "TargetSid": "S-1-5-21-1002"}}, "account_change", "alice", "", map[string]string{"action": tc.action, "object_type": "computer", "object_name": "HOST02$", "object_domain": "LAB", "object_sid": "S-1-5-21-1002", "actor_domain": "LAB", "actor_sid": "S-1-5-21-1001", "logon_id": "0x42", "outcome": "success"})
		})
	}
}

func TestServerLogClearingAndAuditChanges(t *testing.T) {
	for _, tc := range []struct {
		id                             int
		channel, provider, typ, action string
		data, want                     map[string]string
	}{
		{1102, "Security", "Microsoft-Windows-Eventlog", "event_log_cleared", "log_cleared", map[string]string{"SubjectUserName": "alice", "SubjectDomainName": "LAB", "SubjectUserSid": "S-1-5-21-1001", "SubjectLogonId": "0x42"}, map[string]string{"cleared_channel": "Security", "actor_domain": "LAB", "actor_sid": "S-1-5-21-1001", "logon_id": "0x42"}},
		{104, "System", "Microsoft-Windows-Eventlog", "event_log_cleared", "log_cleared", map[string]string{"SubjectUserName": "alice", "SubjectDomainName": "LAB", "Channel": "Application", "BackupPath": `C:\Logs\backup.evtx`}, map[string]string{"cleared_channel": "Application", "backup_path": `C:\Logs\backup.evtx`, "actor_domain": "LAB"}},
		{4719, "Security", securityProvider, "audit_policy_change", "audit_policy_changed", map[string]string{"SubjectUserName": "alice", "SubjectDomainName": "LAB", "SubjectUserSid": "S-1-5-21-1001", "SubjectLogonId": "0x42", "CategoryId": "%%8273", "SubcategoryId": "%%12807", "SubcategoryGuid": "{0CCE9215-69AE-11D9-BED3-505054503030}", "AuditPolicyChanges": "%%8448, %%8450"}, map[string]string{"actor_domain": "LAB", "actor_sid": "S-1-5-21-1001", "logon_id": "0x42", "audit_category_id": "%%8273", "audit_subcategory_id": "%%12807", "audit_subcategory_guid": "{0CCE9215-69AE-11D9-BED3-505054503030}", "audit_policy_changes": "%%8448, %%8450"}},
	} {
		t.Run(fmt.Sprint(tc.id), func(t *testing.T) {
			tc.want["action"] = tc.action
			tc.want["outcome"] = "success"
			assertServerMapping(t, winevent.Input{Channel: tc.channel, Provider: tc.provider, EventID: tc.id, Data: tc.data}, tc.typ, "alice", "", tc.want)
		})
	}
}

func TestServerServiceChanges(t *testing.T) {
	t.Run("install audit", func(t *testing.T) {
		assertServerMapping(t, winevent.Input{Channel: "Security", Provider: securityProvider, EventID: 4697, Data: map[string]string{"SubjectUserName": "alice", "SubjectDomainName": "LAB", "SubjectUserSid": "S-1-5-21-1001", "SubjectLogonId": "0x42", "ServiceName": "Maintenance", "ServiceFileName": `C:\Windows\System32\hostsvc.exe`, "ServiceType": "0x10", "ServiceStartType": "2", "ServiceAccount": "LocalSystem"}}, "service_install", "alice", "", map[string]string{"service_name": "Maintenance", "service_account": "LocalSystem", "actor_domain": "LAB", "actor_sid": "S-1-5-21-1001", "logon_id": "0x42", "start_type": "2", "service_type": "0x10", "action": "service_installed", "outcome": "success"})
	})
	t.Run("state is not execution", func(t *testing.T) {
		assertServerMapping(t, winevent.Input{Channel: "System", Provider: "Service Control Manager", EventID: 7036, Data: map[string]string{"param1": "Maintenance", "param2": "stopped"}}, "service_message", "", "", map[string]string{"service_name": "Maintenance", "service_state": "stopped", "action": "service_state_changed", "outcome": "observed"})
	})
	t.Run("start type is not execution", func(t *testing.T) {
		assertServerMapping(t, winevent.Input{Channel: "System", Provider: "Service Control Manager", EventID: 7040, Data: map[string]string{"param1": "Maintenance", "param2": "auto start", "param3": "demand start", "param4": "MaintenanceSvc"}}, "service_message", "", "", map[string]string{"service_name": "MaintenanceSvc", "service_display_name": "Maintenance", "old_start_type": "auto start", "start_type": "demand start", "action": "service_start_type_changed", "outcome": "success"})
	})
}

func TestServerTaskChanges(t *testing.T) {
	for _, tc := range []struct {
		id          int
		typ, action string
	}{{4698, "scheduled_task_created", "task_created"}, {4699, "scheduled_task_change", "task_deleted"}, {4700, "scheduled_task_change", "task_enabled"}, {4701, "scheduled_task_change", "task_disabled"}, {4702, "scheduled_task_change", "task_updated"}} {
		t.Run(fmt.Sprint(tc.id), func(t *testing.T) {
			in := winevent.Input{Channel: "Security", Provider: securityProvider, EventID: tc.id, Data: map[string]string{"SubjectUserName": "alice", "SubjectDomainName": "LAB", "SubjectUserSid": "S-1-5-21-1001", "SubjectLogonId": "0x42", "TaskName": `\Maintenance`, "TaskContent": `<Task><Actions><Exec><Command>net</Command><Arguments>user alice FakeSecret123!</Arguments></Exec></Actions></Task>`}}
			assertServerMapping(t, in, tc.typ, "alice", "", map[string]string{"action": tc.action, "task_name": `\Maintenance`, "actor_domain": "LAB", "actor_sid": "S-1-5-21-1001", "logon_id": "0x42", "outcome": "success"})
			e := model.Event{Extra: map[string]string{}}
			winevent.Normalize(&e, in)
			if strings.Contains(fmt.Sprint(e), "FakeSecret123!") {
				t.Error("task credential copied out of raw payload")
			}
			if e.ProcessName != "" || e.CommandLine != "" {
				t.Error("task configuration mislabeled as execution")
			}
		})
	}
}

func TestServerRemoteSessions(t *testing.T) {
	rcm := "Microsoft-Windows-TerminalServices-RemoteConnectionManager"
	lsm := "Microsoft-Windows-TerminalServices-LocalSessionManager"
	t.Run("authentication is not desktop", func(t *testing.T) {
		assertServerMapping(t, winevent.Input{Channel: rcm + "/Operational", Provider: rcm, EventID: 1149, Data: map[string]string{"Param1": "alice", "Param2": "LAB", "Param3": "203.0.113.10"}}, "remote_authentication", "alice", "203.0.113.10", map[string]string{"target_domain": "LAB", "action": "authentication_succeeded", "outcome": "success"})
	})
	for _, tc := range []struct {
		id          int
		typ, action string
	}{{21, "session_start", "session_logon"}, {24, "session_change", "session_disconnected"}, {25, "session_change", "session_reconnected"}} {
		t.Run(fmt.Sprint(tc.id), func(t *testing.T) {
			assertServerMapping(t, winevent.Input{Channel: lsm + "/Operational", Provider: lsm, EventID: tc.id, Data: map[string]string{"User": `LAB\alice`, "SessionID": "3", "Address": "203.0.113.10"}}, tc.typ, `LAB\alice`, "203.0.113.10", map[string]string{"session_id": "3", "action": tc.action})
		})
	}
	for _, tc := range []struct {
		id     int
		action string
	}{{4778, "session_reconnected"}, {4779, "session_disconnected"}} {
		t.Run(fmt.Sprint(tc.id), func(t *testing.T) {
			assertServerMapping(t, winevent.Input{Channel: "Security", Provider: securityProvider, EventID: tc.id, Data: map[string]string{"AccountName": "alice", "AccountDomain": "LAB", "LogonID": "0x42", "SessionName": "RDP-Tcp#2", "ClientName": "HOST02", "ClientAddress": "203.0.113.10"}}, "session_change", "alice", "203.0.113.10", map[string]string{"target_domain": "LAB", "logon_id": "0x42", "session_name": "RDP-Tcp#2", "client_name": "HOST02", "action": tc.action})
		})
	}
}
