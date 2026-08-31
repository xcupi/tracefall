package nativegen

// Generates a multi-host, multi-user, multi-technique evidence directory
// for Phase 9B browser verification of Timeline/Findings/Investigations
// filtering. Entirely synthetic.
//
//	RICH_OUT=/path go test ./internal/nativegen -run TestGenerateRichCase -write-samples

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tracefall/internal/evtx/evtxgen"
	"tracefall/internal/regf/regfgen"
)

func TestGenerateRichCase(t *testing.T) {
	if !*write {
		t.Skip("pass -write-samples to regenerate")
	}
	root := os.Getenv("RICH_OUT")
	if root == "" {
		root = filepath.Join(os.TempDir(), "tracefall-rich")
	}
	mk := func(rel string, data []byte) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	hosts := []string{"WKSTN-042", "WKSTN-108", "SRV-DC01"}
	users := []string{"jdoe", "asmith", "CORP\\svc-backup"}

	for hi, host := range hosts {
		var evs []evtxgen.Event
		var id uint64
		add := func(off time.Duration, ch, pr string, eid int, data map[string]string) {
			id++
			evs = append(evs, evtxgen.Event{
				RecordID: id, Timestamp: base.Add(off),
				Provider: pr, Channel: ch, Computer: host,
				EventID: eid, ProcessID: 668, ThreadID: 1024, UserID: "S-1-5-18",
				Data: data,
			})
		}
		const sec, secP = "Security", "Microsoft-Windows-Security-Auditing"
		const sys, sysP = "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon"
		u := users[hi%len(users)]

		// Authentication: failures into a success, then privileges.
		for i := 0; i < 4; i++ {
			add(time.Duration(hi*60+i)*time.Minute, sec, secP, 4625,
				map[string]string{"TargetUserName": u, "LogonType": "3", "IpAddress": "198.51.100.23"})
		}
		add(time.Duration(hi*60+5)*time.Minute, sec, secP, 4624,
			map[string]string{"TargetUserName": u, "LogonType": "3", "IpAddress": "198.51.100.23"})
		add(time.Duration(hi*60+6)*time.Minute, sec, secP, 4672,
			map[string]string{"SubjectUserName": u, "PrivilegeList": "SeDebugPrivilege"})
		add(time.Duration(hi*60+7)*time.Minute, sec, secP, 4648,
			map[string]string{"SubjectUserName": u, "TargetUserName": "CORP\\svc-backup", "TargetServerName": "SRV-FS01"})

		// Execution: Office -> PowerShell, encoded command, LOLBin, network, DNS.
		payload := fmt.Sprintf(`C:\Users\%s\AppData\Local\Temp\stage%d.exe`, "jdoe", hi)
		add(time.Duration(hi*60+10)*time.Minute, sys, sysP, 1, map[string]string{
			"Image":       `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			"CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgA",
			"ParentImage": `C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE`,
			"ProcessId":   "4242", "ParentProcessId": "1000", "User": u,
		})
		add(time.Duration(hi*60+11)*time.Minute, sys, sysP, 11, map[string]string{
			"Image": `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "TargetFilename": payload,
		})
		add(time.Duration(hi*60+12)*time.Minute, sys, sysP, 1, map[string]string{
			"Image": payload, "CommandLine": "stage.exe -q",
			"ParentImage": `C:\Windows\System32\cmd.exe`,
			"ProcessId":   "8260", "ParentProcessId": "4242", "User": u,
		})
		add(time.Duration(hi*60+13)*time.Minute, sys, sysP, 22, map[string]string{
			"Image": payload, "QueryName": fmt.Sprintf("c2-%d.example.test", hi), "ProcessId": "8260",
		})
		add(time.Duration(hi*60+14)*time.Minute, sys, sysP, 3, map[string]string{
			"Image": payload, "SourceIp": "10.0.0.5",
			"DestinationIp": fmt.Sprintf("203.0.113.%d", 10+hi), "DestinationPort": "443", "ProcessId": "8260",
		})
		// Persistence: service install + registry.
		add(time.Duration(hi*60+20)*time.Minute, "System", "Service Control Manager", 7045, map[string]string{
			"ServiceName": fmt.Sprintf("AcmeSvc%d", hi), "ImagePath": payload,
			"StartType": "auto start", "AccountName": "LocalSystem",
		})
		add(time.Duration(hi*60+21)*time.Minute, sys, sysP, 13, map[string]string{
			"TargetObject": `HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run\Updater`,
			"Details":      payload, "Image": payload, "ProcessId": "8260",
		})
		mk(fmt.Sprintf("%s/Security.evtx", host), evtxgen.Build(evs))

		// A hive per host: Run key + Winlogon, so registry findings exist too.
		run := regfgen.NewKey("Run").WithLastWrite(base.Add(time.Duration(hi*60+22) * time.Minute)).WithValues(
			regfgen.StringValue(fmt.Sprintf("Helper%d", hi), payload),
		)
		cv := regfgen.NewKey("CurrentVersion", run)
		win := regfgen.NewKey("Windows", cv)
		winlogon := regfgen.NewKey("Winlogon").WithLastWrite(base.Add(time.Duration(hi*60+23) * time.Minute)).WithValues(
			regfgen.StringValue("Userinit", `C:\Windows\system32\userinit.exe,`+payload),
		)
		cvNT := regfgen.NewKey("CurrentVersion", winlogon)
		winNT := regfgen.NewKey("Windows NT", cvNT)
		ms := regfgen.NewKey("Microsoft", win, winNT)
		sw := regfgen.NewKey("Software", ms)
		cn := regfgen.NewKey("ComputerName").WithLastWrite(base).WithValues(regfgen.StringValue("ComputerName", host))
		ctrl := regfgen.NewKey("Control", regfgen.NewKey("ComputerName", cn))
		cs := regfgen.NewKey("ControlSet001", ctrl)
		root2 := regfgen.NewKey("CMI-CreateHive{H}", sw, cs).WithLastWrite(base)
		mk(fmt.Sprintf("%s/SYSTEM", host), regfgen.Build(fmt.Sprintf(`\??\C:\%s\SYSTEM`, host), root2))
	}
	t.Logf("wrote %s: %d hosts", root, len(hosts))
}
