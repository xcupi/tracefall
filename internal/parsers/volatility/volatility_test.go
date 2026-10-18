package volatility

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tracefall/internal/memory"
	"tracefall/internal/model"
)

// The rows below follow the column definitions of Volatility 3 2.28.2's
// plugins (read from its source: windows.pslist/psscan/cmdline/netscan/
// svcscan/malware.malfind/info), rendered the way its JSON renderer does:
// datetimes as ISO 8601 with an offset, absent values as null, hex
// columns as integers. They are CONSTRUCTED to that schema, not captured
// from a real image; see docs/memory-analysis.md.

type row = map[string]any

func ok(logical, plugin string, rows ...row) memory.PluginResult {
	rs := make([]map[string]any, len(rows))
	for i, r := range rows {
		rs[i] = r
	}
	return memory.PluginResult{Logical: logical, Plugin: plugin, Status: memory.StatusOK, Rows: rs}
}

func baseAnalysis() memory.Analysis {
	return memory.Analysis{
		Schema: memory.AnalysisSchema, Volatility: "2.28.2", Isolation: "bubblewrap", ImageName: "mem.raw", ImageSize: 1 << 30,
		CollectedAt: time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC),
		Info: map[string]string{
			"SystemTime": "2026-02-01 09:30:00+00:00", "NTBuildLab": "19041.1.amd64fre.vb_release.191206-1406",
			"Major/Minor": "15.19041", "Is64Bit": "True", "Kernel Base": "0xf80000000000",
		},
		Plugins: []memory.PluginResult{
			ok("pslist", "windows.pslist.PsList",
				row{"PID": 4.0, "PPID": 0.0, "ImageFileName": "System", "Threads": 120.0, "Handles": nil, "SessionId": nil, "Wow64": false, "CreateTime": "2026-02-01T08:00:00+00:00", "ExitTime": nil, "File output": "Disabled"},
				row{"PID": 600.0, "PPID": 4.0, "ImageFileName": "svchost.exe", "Threads": 9.0, "Handles": 300.0, "SessionId": 0.0, "Wow64": false, "CreateTime": "2026-02-01T08:01:00+00:00", "ExitTime": nil},
				row{"PID": 4242.0, "PPID": 600.0, "ImageFileName": "powershell.exe", "Threads": 5.0, "Handles": 200.0, "SessionId": 1.0, "Wow64": false, "CreateTime": "2026-02-01T09:10:00.123456+00:00", "ExitTime": nil},
				row{"PID": 700.0, "PPID": 4.0, "ImageFileName": "paged.exe", "Threads": 1.0, "Handles": 10.0, "SessionId": 1.0, "Wow64": false, "CreateTime": "2026-02-01T09:00:00+00:00", "ExitTime": nil},
			),
			ok("psscan", "windows.psscan.PsScan",
				row{"PID": 4.0, "PPID": 0.0, "ImageFileName": "System", "CreateTime": "2026-02-01T08:00:00+00:00", "ExitTime": nil},
				row{"PID": 600.0, "PPID": 4.0, "ImageFileName": "svchost.exe", "CreateTime": "2026-02-01T08:01:00+00:00", "ExitTime": nil},
				row{"PID": 4242.0, "PPID": 600.0, "ImageFileName": "powershell.exe", "CreateTime": "2026-02-01T09:10:00.123456+00:00", "ExitTime": nil},
				row{"PID": 700.0, "PPID": 4.0, "ImageFileName": "paged.exe", "CreateTime": "2026-02-01T09:00:00+00:00", "ExitTime": nil},
				// present only in the pool scan, never exited: unlinked from the process list
				row{"PID": 1337.0, "PPID": 600.0, "ImageFileName": "evil.exe", "CreateTime": "2026-02-01T09:20:00+00:00", "ExitTime": nil},
				// present only in the pool scan, but exited: an ordinary dead process
				row{"PID": 999.0, "PPID": 600.0, "ImageFileName": "done.exe", "CreateTime": "2026-02-01T08:30:00+00:00", "ExitTime": "2026-02-01T08:31:00+00:00"},
				// the same PID reused later by another process
				row{"PID": 4242.0, "PPID": 600.0, "ImageFileName": "old4242.exe", "CreateTime": "2026-02-01T07:00:00+00:00", "ExitTime": "2026-02-01T07:05:00+00:00"},
			),
			ok("cmdline", "windows.cmdline.CmdLine",
				row{"PID": 4.0, "Process": "System", "Args": "Required memory at 0x20 is inaccessible (addr 0x20)"},
				row{"PID": 600.0, "Process": "svchost.exe", "Args": `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`},
				row{"PID": 4242.0, "Process": "powershell.exe", "Args": `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -nop -w hidden -enc SQBFAFgA`},
				row{"PID": 700.0, "Process": "paged.exe", "Args": "Required memory at 0x7ffe1000 is not valid (process exited?)"},
			),
			ok("netscan", "windows.netscan.NetScan",
				row{"Offset": 1.0e9, "Proto": "TCPv4", "LocalAddr": "10.0.0.5", "LocalPort": 49812.0, "ForeignAddr": "203.0.113.77", "ForeignPort": 443.0, "State": "ESTABLISHED", "PID": 4242.0, "Owner": "powershell.exe", "Created": "2026-02-01T09:11:00+00:00"},
				row{"Offset": 2.0e9, "Proto": "TCPv4", "LocalAddr": "0.0.0.0", "LocalPort": 135.0, "ForeignAddr": "0.0.0.0", "ForeignPort": 0.0, "State": "LISTENING", "PID": 600.0, "Owner": "svchost.exe", "Created": nil},
				row{"Offset": 3.0e9, "Proto": "UDPv4", "LocalAddr": "10.0.0.5", "LocalPort": 5353.0, "ForeignAddr": "*", "ForeignPort": 0.0, "State": "", "PID": 600.0, "Owner": "svchost.exe", "Created": "2026-02-01T08:05:00+00:00"},
				row{"Offset": 4.0e9, "Proto": "TCPv4", "LocalAddr": "10.0.0.5", "LocalPort": 50000.0, "ForeignAddr": "198.51.100.9", "ForeignPort": 80.0, "State": "CLOSED", "PID": 4242.0, "Owner": "powershell.exe", "Created": nil},
			),
			ok("malfind", "windows.malware.malfind.Malfind",
				row{"PID": 4242.0, "Process": "powershell.exe", "Start VPN": 2.0e12, "End VPN": 2.0e12 + 4095, "Tag": "VadS", "Protection": "PAGE_EXECUTE_READWRITE", "CommitCharge": 1.0, "PrivateMemory": 1.0, "File output": "Disabled", "Notes": "MZ header", "Hexdump": "4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00", "Disasm": "0x0: dec ebp\n0x1: pop edx"},
				row{"PID": 4242.0, "Process": "powershell.exe", "Start VPN": 2.0e12, "End VPN": 2.0e12 + 4095, "Tag": "VadS", "Protection": "PAGE_EXECUTE_READWRITE", "CommitCharge": 1.0, "PrivateMemory": 1.0, "Hexdump": "4d 5a", "Disasm": ""},
				row{"PID": 600.0, "Process": "svchost.exe", "Start VPN": 3.0e12, "End VPN": 3.0e12 + 8191, "Tag": "VadS", "Protection": "PAGE_EXECUTE_READWRITE", "CommitCharge": 2.0, "PrivateMemory": 1.0, "Hexdump": "fc 48 83 e4 f0 e8 c0 00", "Disasm": "0x0: cld"},
			),
			ok("svcscan", "windows.svcscan.SvcScan",
				row{"Offset": 5.0e9, "Order": 1.0, "PID": 600.0, "Start": "SERVICE_AUTO_START", "State": "SERVICE_RUNNING", "Type": "SERVICE_WIN32_SHARE_PROCESS", "Name": "Schedule", "Display": "Task Scheduler", "Binary": `C:\Windows\System32\svchost.exe -k netsvcs -p`, "Binary (Registry)": `%SystemRoot%\System32\svchost.exe -k netsvcs -p`, "Dll": `C:\Windows\System32\schedsvc.dll`},
				row{"Offset": 6.0e9, "Order": 2.0, "PID": nil, "Start": "SERVICE_DEMAND_START", "State": "SERVICE_STOPPED", "Type": "SERVICE_WIN32_OWN_PROCESS", "Name": "EvilSvc", "Display": "Updater", "Binary": `C:\Users\Public\evil.exe`, "Binary (Registry)": `C:\Users\Public\evil.exe`, "Dll": nil},
			),
		},
	}
}

func writeAnalysis(t *testing.T, a memory.Analysis) string {
	t.Helper()
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "memory", "volatility-analysis.json")
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func parseAll(t *testing.T, a memory.Analysis) []model.Event {
	t.Helper()
	res, err := New().Parse(writeAnalysis(t, a))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Raw) < len(res.Events) {
		t.Errorf("%d events but %d raw records: every event must carry its source row", len(res.Events), len(res.Raw))
	}
	return res.Events
}

func byType(evs []model.Event, typ string) []model.Event {
	var out []model.Event
	for _, e := range evs {
		if e.EventType == typ {
			out = append(out, e)
		}
	}
	return out
}

func procByPID(t *testing.T, evs []model.Event, pid int64, name string) model.Event {
	t.Helper()
	for _, e := range byType(evs, model.EventProcessCreate) {
		if e.PID == pid && (name == "" || strings.EqualFold(e.Extra["image_file_name"], name)) {
			return e
		}
	}
	t.Fatalf("no process event for pid %d %q", pid, name)
	return model.Event{}
}

func TestProcesses_BecomeProcessCreateEventsAtTheirCreateTimeWithCommandLines(t *testing.T) {
	evs := parseAll(t, baseAnalysis())
	ps := procByPID(t, evs, 4242, "powershell.exe")
	if !ps.Timestamp.Equal(time.Date(2026, 2, 1, 9, 10, 0, 123456000, time.UTC)) {
		t.Errorf("timestamp = %v", ps.Timestamp)
	}
	if ps.Timestamp.Location() != time.UTC {
		t.Error("timestamps must be UTC")
	}
	if !strings.Contains(ps.CommandLine, "-enc SQBFAFgA") || ps.ProcessPath != `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` {
		t.Errorf("command=%q path=%q", ps.CommandLine, ps.ProcessPath)
	}
	if ps.ProcessName != "powershell.exe" || ps.PPID != 600 || ps.ParentProcessName != "svchost.exe" {
		t.Errorf("name=%q ppid=%d parent=%q", ps.ProcessName, ps.PPID, ps.ParentProcessName)
	}
	if ps.ArtifactType != model.ArtifactMemoryAnalysis || ps.Parser != parserName || ps.Confidence < 0.8 {
		t.Errorf("provenance: %q %q %v", ps.ArtifactType, ps.Parser, ps.Confidence)
	}
	if ps.Extra["memory_source"] != "pslist+psscan" || ps.Extra["evidence_kind"] != "memory" {
		t.Errorf("extra = %v", ps.Extra)
	}
}

func TestProcesses_AnUnlinkedProcessIsFlaggedHiddenAndADeadOneIsNot(t *testing.T) {
	evs := parseAll(t, baseAnalysis())
	hidden := procByPID(t, evs, 1337, "")
	if hidden.Extra["hidden_process"] != "true" || hidden.Extra["memory_source"] != "psscan" {
		t.Errorf("a process in the pool scan but not the process list must be flagged: %v", hidden.Extra)
	}
	if hidden.Confidence >= 0.9 {
		t.Errorf("a pool-scan-only process is weaker evidence than a listed one: confidence %v", hidden.Confidence)
	}
	dead := procByPID(t, evs, 999, "")
	if dead.Extra["hidden_process"] == "true" || dead.Extra["exit_time"] == "" {
		t.Errorf("a process that exited is not hidden: %v", dead.Extra)
	}
	listed := procByPID(t, evs, 600, "")
	if listed.Extra["hidden_process"] == "true" {
		t.Error("a listed process was flagged hidden")
	}
}

func TestProcesses_ReusedPIDsStayDistinctAndCommandLinesGoToTheLiveOne(t *testing.T) {
	evs := parseAll(t, baseAnalysis())
	var with4242 []model.Event
	for _, e := range byType(evs, model.EventProcessCreate) {
		if e.PID == 4242 {
			with4242 = append(with4242, e)
		}
	}
	if len(with4242) != 2 {
		t.Fatalf("%d events for pid 4242, want the live process and the older one", len(with4242))
	}
	for _, e := range with4242 {
		if e.Extra["image_file_name"] == "old4242.exe" && e.CommandLine != "" {
			t.Errorf("the command line of the LIVE process was attached to an older process that reused the PID: %q", e.CommandLine)
		}
	}
	// And the older one must not be assigned the live one's parent as a fact it cannot support.
	for _, e := range with4242 {
		if e.Extra["image_file_name"] == "old4242.exe" && e.Extra["exit_time"] == "" {
			t.Error("exit time lost")
		}
	}
}

func TestProcesses_ACommandLineVolatilityCouldNotReadIsNotPresentedAsOne(t *testing.T) {
	evs := parseAll(t, baseAnalysis())
	for _, pid := range []int64{4, 700} {
		e := procByPID(t, evs, pid, "")
		if e.CommandLine != "" || e.Extra["cmdline_unavailable"] == "" {
			t.Errorf("pid %d: command line %q extra %v: an error string must not become a command line", pid, e.CommandLine, e.Extra)
		}
	}
}

func TestNetwork_ConnectionsListenersAndTheTimeBasis(t *testing.T) {
	evs := parseAll(t, baseAnalysis())
	conns := byType(evs, model.EventNetworkConnection)
	if len(conns) != 2 {
		t.Fatalf("%d connections, want 2 (the established one and the closed one)", len(conns))
	}
	var est, closed model.Event
	for _, c := range conns {
		if c.NetworkDest == "203.0.113.77" {
			est = c
		} else {
			closed = c
		}
	}
	if est.NetworkDestPort != 443 || est.NetworkSource != "10.0.0.5" || est.PID != 4242 || est.ProcessName != "powershell.exe" ||
		!est.Timestamp.Equal(time.Date(2026, 2, 1, 9, 11, 0, 0, time.UTC)) || est.Extra["timestamp_basis"] != "socket_created" {
		t.Errorf("established = %+v", est)
	}
	if !closed.Timestamp.Equal(time.Date(2026, 2, 1, 9, 30, 0, 0, time.UTC)) || closed.Extra["timestamp_basis"] != "memory_snapshot" {
		t.Errorf("a socket with no creation time is dated to the snapshot and says so: %v %v", closed.Timestamp, closed.Extra)
	}
	ls := byType(evs, model.EventNetworkListener)
	if len(ls) != 2 {
		t.Fatalf("%d listeners, want 2 (TCP 135 and UDP 5353)", len(ls))
	}
	for _, l := range ls {
		if l.NetworkDest != "" || l.Extra["local_port"] == "" {
			t.Errorf("a listener has no destination: %+v", l)
		}
	}
}

func TestMalfind_HitsAreIndicatorsDatedToTheSnapshotAndDeduplicated(t *testing.T) {
	evs := parseAll(t, baseAnalysis())
	hits := byType(evs, model.EventMemoryInjection)
	if len(hits) != 2 {
		t.Fatalf("%d malfind events, want 2 (the duplicate region collapses)", len(hits))
	}
	var pe, shell model.Event
	for _, h := range hits {
		if h.PID == 4242 {
			pe = h
		} else {
			shell = h
		}
	}
	if !pe.Timestamp.Equal(time.Date(2026, 2, 1, 9, 30, 0, 0, time.UTC)) || pe.Extra["timestamp_basis"] != "memory_snapshot" {
		t.Errorf("a malfind hit has no event time of its own; it is dated to the snapshot and must say so: %v %v", pe.Timestamp, pe.Extra)
	}
	if pe.Extra["pe_header"] != "true" || shell.Extra["pe_header"] == "true" {
		t.Errorf("pe_header flags wrong: %v / %v", pe.Extra, shell.Extra)
	}
	if pe.Extra["protection"] != "PAGE_EXECUTE_READWRITE" || pe.Extra["start_vpn"] == "" || pe.Confidence > 0.6 {
		t.Errorf("malfind = %+v: it is a heuristic and its confidence must say so", pe)
	}
}

func TestServices_AreMemoryObservationsNotInstallEvents(t *testing.T) {
	evs := parseAll(t, baseAnalysis())
	if len(byType(evs, model.EventServiceInstall)) != 0 {
		t.Error("a service seen in memory was reported as an installation event")
	}
	svcs := byType(evs, model.EventMemoryService)
	if len(svcs) != 2 {
		t.Fatalf("%d services", len(svcs))
	}
	for _, s := range svcs {
		if s.Extra["service_name"] == "EvilSvc" && (s.FilePath != `C:\Users\Public\evil.exe` || s.Extra["state"] != "SERVICE_STOPPED") {
			t.Errorf("service = %+v", s)
		}
	}
}

func TestSnapshotEvent_RecordsTheAcquisitionTimeAndWhatCouldNotBeRun(t *testing.T) {
	a := baseAnalysis()
	a.Plugins[3] = memory.PluginResult{Logical: "netscan", Plugin: "windows.netscan.NetScan", Status: memory.StatusFailed, Error: "a structure is missing", Rows: []map[string]any{}}
	evs := parseAll(t, a)
	snap := byType(evs, model.EventMemorySnapshot)
	if len(snap) != 1 {
		t.Fatalf("%d snapshot events", len(snap))
	}
	s := snap[0]
	if !s.Timestamp.Equal(time.Date(2026, 2, 1, 9, 30, 0, 0, time.UTC)) {
		t.Errorf("timestamp = %v", s.Timestamp)
	}
	if !strings.Contains(s.Extra["plugins_failed"], "netscan") || s.Extra["volatility_version"] != "2.28.2" || s.Extra["isolation"] != "bubblewrap" {
		t.Errorf("extra = %v: a plugin that failed must be visible, not silently absent", s.Extra)
	}
	if len(byType(evs, model.EventNetworkConnection)) != 0 {
		t.Error("events were produced from a plugin that failed")
	}
}

func TestMissingSystemTimeStillYieldsProcessesButNoSnapshotDatedEvents(t *testing.T) {
	a := baseAnalysis()
	delete(a.Info, "SystemTime")
	evs := parseAll(t, a)
	if len(byType(evs, model.EventProcessCreate)) == 0 {
		t.Error("process events depend only on their own create times")
	}
	for _, typ := range []string{model.EventMemoryInjection, model.EventMemoryService, model.EventMemorySnapshot} {
		if n := len(byType(evs, typ)); n != 0 {
			t.Errorf("%d %s events were dated without a snapshot time", n, typ)
		}
	}
}

func TestDetectAndConfirm(t *testing.T) {
	p := New()
	if !p.Detect("memory/volatility-analysis.json") || !p.Detect("vol1/x/Volatility-Analysis.JSON") {
		t.Error("the analysis file is not detected by name")
	}
	if p.Detect("memory/other.json") || p.Detect("volatility-analysis.json.bak") {
		t.Error("an unrelated file was detected")
	}
	b, _ := json.Marshal(baseAnalysis())
	if !p.ConfirmContent(b[:512]) || !p.DetectContent(b[:512]) {
		t.Error("content is not recognised")
	}
	if p.ConfirmContent([]byte(`{"schema":"something-else"}`)) || p.DetectContent([]byte("MZ\x90\x00")) {
		t.Error("foreign content was accepted")
	}
}

func TestParse_RejectsWhatIsNotAnAnalysis(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{"notjson": "hello", "wrong": `{"schema":"other/1"}`, "empty": ""} {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(body), 0o644)
		if _, err := New().Parse(p); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestParse_HostileRowsNeverPanicAndAreBounded(t *testing.T) {
	a := baseAnalysis()
	huge := strings.Repeat("A", 1<<20)
	a.Plugins = []memory.PluginResult{
		ok("pslist", "windows.pslist.PsList",
			row{"PID": "not a number", "PPID": -5.0, "ImageFileName": huge, "CreateTime": 12345.0},
			row{"PID": 1e30, "ImageFileName": nil, "CreateTime": "garbage"},
			row{"PID": 5.0, "PPID": 5.0, "ImageFileName": "self.exe", "CreateTime": "2026-02-01T08:00:00+00:00"}, // its own parent
		),
		ok("cmdline", "windows.cmdline.CmdLine", row{"PID": 5.0, "Args": huge}),
		ok("netscan", "windows.netscan.NetScan", row{"ForeignAddr": huge, "ForeignPort": "x", "PID": []any{1}}),
		ok("malfind", "windows.malware.malfind.Malfind", row{"PID": 5.0, "Hexdump": huge, "Start VPN": "bad"}),
		{Logical: "svcscan", Plugin: "x", Status: memory.StatusOK, Rows: nil},
		{Logical: "unknown-plugin", Plugin: "y", Status: memory.StatusOK, Rows: []map[string]any{{"a": "b"}}},
	}
	evs := parseAll(t, a)
	for _, e := range evs {
		for _, v := range []string{e.ProcessName, e.CommandLine, e.NetworkDest, e.ProcessPath} {
			if len(v) > 20000 {
				t.Fatalf("an unbounded string reached an event field: %d bytes", len(v))
			}
		}
		for k, v := range e.Extra {
			if len(v) > 5000 {
				t.Fatalf("extra[%s] is %d bytes", k, len(v))
			}
		}
	}
	self := procByPID(t, evs, 5, "")
	if self.ParentProcessName != "" {
		t.Errorf("a process was named as its own parent: %q", self.ParentProcessName)
	}
}

func TestParse_ManyRowsAreCapped(t *testing.T) {
	a := baseAnalysis()
	var rs []row
	for i := 0; i < maxEvents+500; i++ {
		rs = append(rs, row{"PID": float64(10000 + i), "PPID": 4.0, "ImageFileName": "p.exe", "CreateTime": "2026-02-01T08:00:00+00:00"})
	}
	a.Plugins = []memory.PluginResult{ok("pslist", "windows.pslist.PsList", rs...)}
	evs := parseAll(t, a)
	if len(evs) > maxEvents+1 {
		t.Errorf("%d events: the cap does not hold", len(evs))
	}
}
