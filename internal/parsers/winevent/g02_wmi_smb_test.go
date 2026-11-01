package winevent_test

import (
	"strings"
	"testing"

	"tracefall/internal/parsers/winevent"
)

const (
	wmiChannel  = "Microsoft-Windows-WMI-Activity/Operational"
	wmiProvider = "Microsoft-Windows-WMI-Activity"
)

func wmiIn(id int, data map[string]string) winevent.Input {
	return winevent.Input{Channel: wmiChannel, Provider: wmiProvider, EventID: id, Data: data}
}

func ess5860() map[string]string {
	return map[string]string{
		"NamespaceName": `ROOT\CIMV2`, "Query": "SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'tool.exe'",
		"User": `LAB\alice`, "Processid": "4242", "ClientMachine": "HOST01", "PossibleCause": "Temporary",
	}
}

func TestWMI5860_TemporaryEventConsumer(t *testing.T) {
	in := wmiIn(5860, ess5860())
	e, ok := g02Direct(in)
	if !ok {
		t.Fatal("5860 not mapped")
	}
	g02Expect(t, e, "wmi_activity", `LAB\alice`, "", map[string]string{
		"action": "temporary_event_consumer_started", "namespace": `ROOT\CIMV2`, "query": ess5860()["Query"],
		"client_process_id": "4242", "client_machine": "HOST01", "possible_cause": "Temporary",
	}, "result_code", "operation")
	if e.PID != 4242 {
		t.Errorf("PID = %d, want the client process id 4242", e.PID)
	}
	lim := e.Extra["limitations"]
	for _, c := range []string{"does not establish", "execution", "intent"} {
		if !strings.Contains(lim, c) {
			t.Errorf("limitations lacks %q: %q", c, lim)
		}
	}
	g02Parity(t, in)
	g02Gate(t, in)
	// Under-specified: neither a query nor a namespace.
	for _, d := range []map[string]string{{}, {"User": `LAB\alice`, "Processid": "1"}, {"Query": " ", "NamespaceName": ""}} {
		if _, ok := g02Direct(wmiIn(5860, d)); ok {
			t.Errorf("under-specified 5860 mapped: %v", d)
		}
	}
}

func TestWMI5860_QueryIsBoundedAndRedacted(t *testing.T) {
	d := ess5860()
	d["Query"] = "SELECT * FROM X WHERE Note = 'a' -- " + strings.Repeat("Z", 5000)
	e, _ := g02Direct(wmiIn(5860, d))
	if n := len(e.Extra["query"]); n == 0 || n > 1100 || e.Extra["query_truncated"] != "true" {
		t.Errorf("query len %d truncated=%q", n, e.Extra["query_truncated"])
	}
	d["Query"] = "SELECT * FROM X WHERE A = '1' /* --password=hunter2 */"
	e, _ = g02Direct(wmiIn(5860, d))
	if strings.Contains(e.Extra["query"], "hunter2") {
		t.Errorf("secret kept: %q", e.Extra["query"])
	}
}

func fail5858() map[string]string {
	return map[string]string{
		"Id": "{AAAAAAAA-0000-4000-8000-000000000001}", "ClientMachine": "HOST01", "User": `LAB\alice`, "ClientProcessId": "4242",
		"Component": "Provider", "Operation": `Start IWbemServices::ExecQuery - ROOT\CIMV2 : SELECT * FROM Win32_Missing`,
		"ResultCode": "0x80041008", "PossibleCause": "Unknown",
	}
}

func TestWMI5858_ClientFailure(t *testing.T) {
	in := wmiIn(5858, fail5858())
	e, ok := g02Direct(in)
	if !ok {
		t.Fatal("5858 not mapped")
	}
	g02Expect(t, e, "wmi_activity", `LAB\alice`, "", map[string]string{
		"action": "client_operation_failed", "outcome": "failure", "operation_id": "{AAAAAAAA-0000-4000-8000-000000000001}",
		"client_machine": "HOST01", "client_process_id": "4242", "component": "Provider",
		"operation": fail5858()["Operation"], "result_code": "0x80041008", "possible_cause": "Unknown",
	}, "namespace", "query")
	if e.PID != 4242 {
		t.Errorf("PID = %d", e.PID)
	}
	for _, c := range []string{"does not establish", "intent"} {
		if !strings.Contains(e.Extra["limitations"], c) {
			t.Errorf("limitations lacks %q", c)
		}
	}
	g02Parity(t, in)
	g02Gate(t, in)
	// A zero result code is a recorded value; absence is not zero.
	d := fail5858()
	d["ResultCode"] = "0x00000000"
	if e, _ := g02Direct(wmiIn(5858, d)); e.Extra["result_code"] != "0x00000000" {
		t.Error("zero result code not preserved")
	}
	delete(d, "ResultCode")
	if e, _ := g02Direct(wmiIn(5858, d)); func() bool { _, r := e.Extra["result_code"]; return r }() {
		t.Error("absent ResultCode invented")
	}
	// Neither operation nor result: nothing to report.
	if _, ok := g02Direct(wmiIn(5858, map[string]string{"Id": "{x}", "User": "u"})); ok {
		t.Error("under-specified 5858 mapped")
	}
	// Distinct operations at the same instant stay distinct; a recollection collapses.
	other := fail5858()
	other["Operation"] = `Start IWbemServices::ExecQuery - ROOT\CIMV2 : SELECT * FROM Win32_Other`
	g02Distinct(t, in, wmiIn(5858, other))
	g02Distinct(t, wmiIn(5860, ess5860()), wmiIn(5860, func() map[string]string { d := ess5860(); d["Query"] = "SELECT * FROM Win32_Other"; return d }()))
}

// 5857 (provider loaded) is routine and stays unmapped; it is not claimed as another ID.
func TestWMI5857StaysUnmapped(t *testing.T) {
	d := map[string]string{"ProviderName": "CIMWin32", "Code": "0x0", "HostProcess": "wmiprvse.exe", "ProcessID": "100", "ProviderPath": `%systemroot%\system32\wbem\wmipcima.dll`}
	if e, ok := g02Direct(wmiIn(5857, d)); ok || e.EventType != "" {
		t.Errorf("5857 mapped: %+v", e)
	}
}

// ---- SMB server 551 / 1009; client 31010 / 31002 ----

const (
	smbChannel  = "Microsoft-Windows-SMBServer/Security"
	smbProvider = "Microsoft-Windows-SMBServer"
	// A SOCKADDR_IN for 203.0.113.7:50123 as a 16-byte binary, hex-rendered.
	smbAddr4 = "0200C3CBCB00710700000000" + "00000000"
	// A SOCKADDR_IN6 for [2001:db8::1]:445.
	smbAddr6 = "1700" + "01BD" + "00000000" + "20010DB8000000000000000000000001" + "00000000"
)

func smb551() map[string]string {
	return map[string]string{
		"SessionGUID": "{AAAAAAAA-0000-4000-8000-000000000011}", "ConnectionGUID": "{AAAAAAAA-0000-4000-8000-000000000022}",
		"Status": "0xc000006d", "TranslatedStatus": "0xc000006d", "ClientAddressLength": "16", "ClientAddress": smbAddr4,
		"SessionId": "0x1000000000001", "UserNameLength": "5", "UserName": "alice", "ClientNameLength": "13", "ClientName": `\\203.0.113.7`,
		"SPN": "session setup failed before the SPN could be queried", "SPNValidationPolicy": "0", "ReasonCode": "11",
	}
}

func smbIn(id int, d map[string]string) winevent.Input {
	return winevent.Input{Channel: smbChannel, Provider: smbProvider, EventID: id, Data: d}
}

func TestSMB551_SessionAuthenticationFailure(t *testing.T) {
	in := smbIn(551, smb551())
	e, ok := g02Direct(in)
	if !ok {
		t.Fatal("551 not mapped")
	}
	g02Expect(t, e, "smb_security_event", "alice", "203.0.113.7", map[string]string{
		"action": "smb_session_authentication_failed", "outcome": "failure", "source_port": "50123",
		"client_address_recorded": smbAddr4, "client_name": `\\203.0.113.7`, "status": "0xc000006d", "translated_status": "0xc000006d",
		"session_id": "0x1000000000001", "session_guid": "{AAAAAAAA-0000-4000-8000-000000000011}", "connection_guid": "{AAAAAAAA-0000-4000-8000-000000000022}",
		"spn": "session setup failed before the SPN could be queried", "spn_validation_policy": "0", "reason_code": "11",
	})
	for _, c := range []string{"does not establish", "not a logon"} {
		if !strings.Contains(e.Extra["limitations"], c) {
			t.Errorf("limitations lacks %q: %q", c, e.Extra["limitations"])
		}
	}
	g02Parity(t, in)
	g02Gate(t, in)
}

func TestSMB_ClientAddressDecoding(t *testing.T) {
	for _, tc := range []struct{ raw, ip, port string }{
		{smbAddr4, "203.0.113.7", "50123"},
		{strings.ToLower(smbAddr4), "203.0.113.7", "50123"},
		{smbAddr6, "2001:db8::1", "445"},
		{"203.0.113.7:50123", "203.0.113.7", "50123"},
		{"[2001:db8::1]:445", "2001:db8::1", "445"},
		{"203.0.113.7", "203.0.113.7", ""},
	} {
		d := smb551()
		d["ClientAddress"] = tc.raw
		e, _ := g02Direct(smbIn(551, d))
		if e.NetworkSource != tc.ip || e.Extra["source_port"] != tc.port {
			t.Errorf("%q decoded to %q/%q, want %q/%q", tc.raw, e.NetworkSource, e.Extra["source_port"], tc.ip, tc.port)
		}
		if e.Extra["client_address_recorded"] != tc.raw {
			t.Errorf("raw value not retained: %q", e.Extra["client_address_recorded"])
		}
	}
	// Anything not a recognizable address is kept as recorded and is NOT a source.
	for _, raw := range []string{"garbage", "0200C3CB", "FFFF" + smbAddr4[4:], "0200C3CBCB007107ZZZZZZZZZZZZZZZZ", "999.1.1.1:1", ""} {
		d := smb551()
		d["ClientAddress"] = raw
		e, ok := g02Direct(smbIn(551, d))
		if !ok {
			t.Fatalf("%q: record dropped", raw)
		}
		if e.NetworkSource != "" {
			t.Errorf("%q invented source %q", raw, e.NetworkSource)
		}
		if got, rec := e.Extra["client_address_recorded"]; !rec || got != raw {
			t.Errorf("%q not retained literally (%q, %v)", raw, got, rec)
		}
	}
	d := smb551()
	delete(d, "ClientAddress")
	e, _ := g02Direct(smbIn(551, d))
	if _, rec := e.Extra["client_address_recorded"]; rec || e.NetworkSource != "" {
		t.Error("absent ClientAddress was invented")
	}
}

func smb1009() map[string]string {
	return map[string]string{
		"ClientAddressLength": "16", "ClientAddress": smbAddr4, "ClientNameLength": "13", "ClientName": `\\203.0.113.7`,
		"SessionID": "0x1000000000001", "SessionGUID": "{AAAAAAAA-0000-4000-8000-000000000011}", "ConnectionGUID": "{AAAAAAAA-0000-4000-8000-000000000022}",
	}
}

func TestSMB1009_AnonymousAccessDenied(t *testing.T) {
	in := smbIn(1009, smb1009())
	e, ok := g02Direct(in)
	if !ok {
		t.Fatal("1009 not mapped")
	}
	g02Expect(t, e, "smb_security_event", "", "203.0.113.7", map[string]string{
		"action": "smb_anonymous_access_denied", "outcome": "failure", "source_port": "50123", "client_name": `\\203.0.113.7`,
		"session_id": "0x1000000000001", "session_guid": "{AAAAAAAA-0000-4000-8000-000000000011}", "connection_guid": "{AAAAAAAA-0000-4000-8000-000000000022}",
	}, "status", "translated_status", "spn", "reason_code")
	g02Parity(t, in)
	g02Gate(t, in)
	// The two events spell the session id differently (SessionId / SessionID); each reads only its own.
	d := smb1009()
	delete(d, "SessionID")
	d["SessionId"] = "0x9"
	if e, _ := g02Direct(smbIn(1009, d)); func() bool { _, r := e.Extra["session_id"]; return r }() {
		t.Error("1009 read the 551 spelling")
	}
	d = smb551()
	delete(d, "SessionId")
	d["SessionID"] = "0x9"
	if e, _ := g02Direct(smbIn(551, d)); func() bool { _, r := e.Extra["session_id"]; return r }() {
		t.Error("551 read the 1009 spelling")
	}
	// Neither address nor name nor session: under-specified.
	if _, ok := g02Direct(smbIn(1009, map[string]string{"ConnectionGUID": "{x}"})); ok {
		t.Error("under-specified 1009 mapped")
	}
	if _, ok := g02Direct(smbIn(551, map[string]string{"Status": "0xc000006d"})); ok {
		t.Error("551 with neither client nor user mapped")
	}
}

func TestSMBIdentity(t *testing.T) {
	a := smb551()
	b := smb551()
	b["SessionId"] = "0x1000000000002"
	g02Distinct(t, smbIn(551, a), smbIn(551, b))
	c := smb551()
	c["Status"] = "0xc0000022"
	g02Distinct(t, smbIn(551, a), smbIn(551, c))
	g02Distinct(t, smbIn(551, a), smbIn(1009, smb1009()))
}

// The SMB client IDs (31010 connect failure, 31002 outbound authentication
// failure) have no real record layout available, so they stay unmapped rather
// than guessed. Claiming the ID under the right provider must not map it.
func TestSMBClient31010And31002AreDeferred(t *testing.T) {
	for _, id := range []int{31010, 31002} {
		in := winevent.Input{Channel: "Microsoft-Windows-SmbClient/Security", Provider: "Microsoft-Windows-SMBClient", EventID: id,
			Data: map[string]string{"Reason": "12", "Status": "3221225506", "ShareNameLength": "10", "ShareName": `\\host01\share`}}
		if e, ok := g02Direct(in); ok || e.EventType != "" {
			t.Errorf("%d mapped without a verified layout: %+v", id, e)
		}
	}
}
