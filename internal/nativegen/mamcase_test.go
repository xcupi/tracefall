package nativegen

// Generates an evidence directory pairing Windows 10/11 MAM-compressed
// Prefetch with event logs describing the SAME executables on the SAME
// hosts in the SAME window, so correlation and investigation can be seen
// consuming events that came out of a compressed container.
//
//	MAM_OUT=/path go test ./internal/nativegen -run TestGenerateMAMCase -write-samples

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tracefall/internal/evtx/evtxgen"
	"tracefall/internal/prefetch/prefetchgen"
)

func TestGenerateMAMCase(t *testing.T) {
	if !*write {
		t.Skip("pass -write-samples to regenerate")
	}
	root := os.Getenv("MAM_OUT")
	if root == "" {
		root = filepath.Join(os.TempDir(), "tracefall-mam")
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

	base := time.Date(2026, 3, 14, 9, 0, 0, 0, time.UTC)
	const host = "WKSTN-042"

	// Sysmon process-creation events for three executables.
	var evs []evtxgen.Event
	var id uint64
	exes := []string{"STAGE0.EXE", "POWERSHELL.EXE", "RUNDLL32.EXE"}
	for i, exe := range exes {
		id++
		evs = append(evs, evtxgen.Event{
			RecordID: id, Timestamp: base.Add(time.Duration(i*2) * time.Minute),
			Provider: "Microsoft-Windows-Sysmon", Channel: "Microsoft-Windows-Sysmon/Operational",
			Computer: host, EventID: 1, ProcessID: 4242, ThreadID: 1024, UserID: "S-1-5-18",
			Data: map[string]string{
				"Image":       `C:\Windows\System32\` + exe,
				"CommandLine": exe + " -run",
				"ParentImage": `C:\Windows\explorer.exe`,
				"ProcessId":   fmt.Sprint(4000 + i), "ParentProcessId": "1000", "User": "jdoe",
			},
		})
	}
	mk("Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx",
		evtxgen.Build(evs))

	// The SAME executions, as MAM-compressed Prefetch -- the container
	// Windows 10/11 actually writes.
	for i, exe := range exes {
		plain := prefetchgen.Build(prefetchgen.File{
			Version:        30,
			ExecutableName: exe,
			PrefetchHash:   uint32(0x0A0B0C00 + i),
			RunCount:       uint32(3 + i),
			LastRunTimes: []time.Time{
				base.Add(time.Duration(i*2) * time.Minute),
				base.Add(time.Duration(i*2)*time.Minute - 26*time.Hour),
			},
			Filenames: []string{
				`\VOLUME{01d7}\WINDOWS\SYSTEM32\` + exe,
				`\VOLUME{01d7}\WINDOWS\SYSTEM32\NTDLL.DLL`,
			},
			VolumeDevicePath: `\DEVICE\HARDDISKVOLUME2`,
			VolumeSerial:     0xA1B2C3D4,
			VolumeCreated:    base.Add(-800 * time.Hour),
		})
		mk(fmt.Sprintf("Windows/Prefetch/%s-%08X.pf", exe, 0x0A0B0C00+i),
			prefetchgen.CompressMAM(plain))
	}
	t.Logf("wrote MAM-paired evidence to %s", root)
}
