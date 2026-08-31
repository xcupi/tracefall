package nativegen

// This package exists only to generate testdata/native_samples. It is a
// test rather than a command so it cannot end up in the shipped binary,
// and so `go vet ./...` keeps checking it.
//
// Regenerate with:
//
//	go test ./internal/nativegen -run TestGenerateSamples -write-samples

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tracefall/internal/evtx/evtxgen"
	"tracefall/internal/regf/regfgen"
)

var write = flag.Bool("write-samples", false, "write the sample artifacts into testdata/native_samples")

var base = time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)

func TestGenerateSamples(t *testing.T) {
	if !*write {
		t.Skip("pass -write-samples to regenerate testdata/native_samples")
	}
	dir := filepath.Join("..", "..", "testdata", "native_samples")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	samples := map[string][]byte{
		"Security.evtx": securityLog(),
		"Sysmon.evtx":   sysmonLog(),
		"SYSTEM":        systemHive(),
		"SOFTWARE":      softwareHive(),
		"NTUSER.DAT":    ntuserHive(),
		"Broken.evtx":   evtxgen.CorruptChunkCRC(securityLog(), 0),
		"Truncated.dat": regfgen.Truncate(systemHive(), 2500),
	}
	for name, data := range samples {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s (%d bytes)", p, len(data))
	}
}

func ev(offset time.Duration, id uint64, channel, provider string, eventID int, data map[string]string) evtxgen.Event {
	return evtxgen.Event{
		RecordID: id, Timestamp: base.Add(offset),
		Provider: provider, Channel: channel, Computer: "WKSTN-042",
		EventID: eventID, ProcessID: 668, ThreadID: 1024, UserID: "S-1-5-18",
		Data: data,
	}
}

// securityLog tells one coherent, entirely fictional story: a password
// spray that eventually succeeds, then privileged access.
func securityLog() []byte {
	const ch, pr = "Security", "Microsoft-Windows-Security-Auditing"
	var out []evtxgen.Event
	var id uint64
	for i := 0; i < 4; i++ {
		id++
		out = append(out, ev(time.Duration(i)*time.Minute, id, ch, pr, 4625, map[string]string{
			"TargetUserName": "jdoe", "LogonType": "3", "IpAddress": "198.51.100.23",
		}))
	}
	id++
	out = append(out, ev(5*time.Minute, id, ch, pr, 4624, map[string]string{
		"TargetUserName": "jdoe", "LogonType": "3", "IpAddress": "198.51.100.23",
	}))
	id++
	out = append(out, ev(6*time.Minute, id, ch, pr, 4672, map[string]string{
		"SubjectUserName": "jdoe", "PrivilegeList": "SeDebugPrivilege, SeBackupPrivilege",
	}))
	id++
	out = append(out, ev(7*time.Minute, id, ch, pr, 4648, map[string]string{
		"SubjectUserName": "jdoe", "TargetUserName": "svc-backup", "TargetServerName": "SRV-FS01",
	}))
	id++
	out = append(out, ev(20*time.Minute, id, "System", "Service Control Manager", 7045, map[string]string{
		"ServiceName": "AcmeUpdateSvc", "ImagePath": `C:\Users\jdoe\AppData\Local\Temp\update.exe`,
		"StartType": "auto start", "AccountName": "LocalSystem",
	}))
	return evtxgen.Build(out)
}

// sysmonLog covers the Sysmon event IDs Tracefall normalizes.
func sysmonLog() []byte {
	const ch, pr = "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon"
	payload := `C:\Users\jdoe\AppData\Local\Temp\update.exe`
	return evtxgen.Build([]evtxgen.Event{
		ev(10*time.Minute, 1, ch, pr, 11, map[string]string{
			"Image": `C:\Windows\System32\cmd.exe`, "TargetFilename": payload,
		}),
		ev(11*time.Minute, 2, ch, pr, 1, map[string]string{
			"Image": payload, "CommandLine": `update.exe -silent`,
			"ParentImage": `C:\Windows\System32\cmd.exe`,
			"ProcessId":   "8260", "ParentProcessId": "1000", "User": "jdoe",
		}),
		ev(12*time.Minute, 3, ch, pr, 22, map[string]string{
			"Image": payload, "QueryName": "updates.example.test", "ProcessId": "8260",
		}),
		ev(13*time.Minute, 4, ch, pr, 3, map[string]string{
			"Image": payload, "SourceIp": "10.0.0.5",
			"DestinationIp": "203.0.113.77", "DestinationPort": "443", "ProcessId": "8260",
		}),
		ev(14*time.Minute, 5, ch, pr, 13, map[string]string{
			"TargetObject": `HKU\S-1-5-21-1111-2222-3333-1001\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdateHelper`,
			"Details":      payload,
			"Image":        payload, "ProcessId": "8260",
		}),
	})
}

func systemHive() []byte {
	cn := regfgen.NewKey("ComputerName").WithLastWrite(base).WithValues(
		regfgen.StringValue("ComputerName", "WKSTN-042"),
	)
	control := regfgen.NewKey("Control", regfgen.NewKey("ComputerName", cn))
	svc := regfgen.NewKey("AcmeUpdateSvc").WithLastWrite(base.Add(20*time.Minute)).WithValues(
		regfgen.ExpandStringValue("ImagePath", `C:\Users\jdoe\AppData\Local\Temp\update.exe`),
		regfgen.DWordValue("Start", 2),
	)
	services := regfgen.NewKey("Services", svc)
	cs := regfgen.NewKey("ControlSet001", control, services)
	root := regfgen.NewKey("CMI-CreateHive{SYSTEM}", cs).WithLastWrite(base)
	return regfgen.Build(`\??\C:\Windows\System32\config\SYSTEM`, root)
}

func softwareHive() []byte {
	run := regfgen.NewKey("Run").WithLastWrite(base.Add(21 * time.Minute)).WithValues(
		regfgen.StringValue("AcmeTray", `C:\Program Files\Acme\tray.exe`),
	)
	cvWin := regfgen.NewKey("CurrentVersion", run)
	win := regfgen.NewKey("Windows", cvWin)

	winlogon := regfgen.NewKey("Winlogon").WithLastWrite(base.Add(22 * time.Minute)).WithValues(
		regfgen.StringValue("Userinit", `C:\Windows\system32\userinit.exe,C:\Users\jdoe\AppData\Local\Temp\update.exe`),
	)
	ifeoTarget := regfgen.NewKey("sethc.exe").WithLastWrite(base.Add(23 * time.Minute)).WithValues(
		regfgen.StringValue("Debugger", `C:\Windows\System32\cmd.exe`),
	)
	ifeo := regfgen.NewKey("Image File Execution Options", ifeoTarget)
	ntWin := regfgen.NewKey("Windows").WithLastWrite(base.Add(24 * time.Minute)).WithValues(
		regfgen.StringValue("AppInit_DLLs", `C:\Users\jdoe\AppData\Local\Temp\inject.dll`),
	)
	cvNT := regfgen.NewKey("CurrentVersion", winlogon, ifeo, ntWin)
	winNT := regfgen.NewKey("Windows NT", cvNT)

	ms := regfgen.NewKey("Microsoft", win, winNT)
	root := regfgen.NewKey("CMI-CreateHive{SOFTWARE}", ms).WithLastWrite(base)
	return regfgen.Build(`\??\C:\Windows\System32\config\SOFTWARE`, root)
}

func ntuserHive() []byte {
	run := regfgen.NewKey("Run").WithLastWrite(base.Add(14 * time.Minute)).WithValues(
		regfgen.StringValue("WindowsUpdateHelper", `C:\Users\jdoe\AppData\Local\Temp\update.exe`),
	)
	runOnce := regfgen.NewKey("RunOnce").WithLastWrite(base.Add(15 * time.Minute)).WithValues(
		regfgen.StringValue("Cleanup", `C:\Users\jdoe\AppData\Local\Temp\cleanup.cmd`),
	)
	cv := regfgen.NewKey("CurrentVersion", run, runOnce)
	win := regfgen.NewKey("Windows", cv)
	ms := regfgen.NewKey("Microsoft", win)
	sw := regfgen.NewKey("Software", ms)
	root := regfgen.NewKey("CMI-CreateHive{NTUSER}", sw).WithLastWrite(base)
	return regfgen.Build(`\??\C:\Users\jdoe\NTUSER.DAT`, root)
}
