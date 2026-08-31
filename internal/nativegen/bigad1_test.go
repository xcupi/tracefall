package nativegen

// Generates a large synthetic AD1 for Phase 9A browser verification:
// enough files that the coverage summary, search/filter toolbar and
// import progress are all exercised at realistic scale.
//
//	go test ./internal/nativegen -run TestGenerateBigAD1 -write-samples

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"tracefall/internal/ad1/ad1gen"
	"tracefall/internal/evtx/evtxgen"
	"tracefall/internal/regf/regfgen"
)

func TestGenerateBigAD1(t *testing.T) {
	if !*write {
		t.Skip("pass -write-samples to regenerate")
	}
	out := os.Getenv("BIGAD1_OUT")
	if out == "" {
		out = filepath.Join(os.TempDir(), "TriageDemo.ad1")
	}
	var files []ad1gen.File

	// Supported, high-value evidence -- the needles.
	files = append(files,
		ad1gen.File{Path: "C/Windows/System32/winevt/Logs/Security.evtx", Data: securityLog()},
		ad1gen.File{Path: "C/Windows/System32/winevt/Logs/Sysmon.evtx", Data: sysmonLog()},
		ad1gen.File{Path: "C/Windows/System32/config/SYSTEM", Data: systemHive()},
		ad1gen.File{Path: "C/Windows/System32/config/SOFTWARE", Data: softwareHive()},
		ad1gen.File{Path: "C/Users/jdoe/NTUSER.DAT", Data: ntuserHive()},
	)
	files = append(files, ad1gen.File{
		Path: "C/Windows/Tasks/AcmeUpdate.xml",
		Data: []byte(`<?xml version="1.0" encoding="UTF-16"?>
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Date>2026-03-01T09:20:00</Date><Author>CORP\jdoe</Author></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Actions><Exec><Command>C:\Users\jdoe\AppData\Local\Temp\update.exe</Command></Exec></Actions>
</Task>`),
	})

	// A deliberately damaged supported file, so the parse-error path is
	// exercised rather than only described.
	files = append(files, ad1gen.File{
		Path: "C/Windows/System32/winevt/Logs/Application.evtx",
		Data: evtxgen.CorruptChunkSignature(securityLog(), 0),
	})
	files = append(files, ad1gen.File{
		Path: "C/Windows/System32/config/COMPONENTS",
		Data: regfgen.Truncate(systemHive(), 2200),
	})

	// The haystack: thousands of recognizable-but-unsupported artifacts
	// plus ordinary noise, mirroring a real logical acquisition.
	for i := 0; i < 900; i++ {
		files = append(files, ad1gen.File{
			Path: fmt.Sprintf("C/Windows/Prefetch/APP%04d.EXE-A1B2C3D4.pf", i),
			Data: []byte(fmt.Sprintf("MAM\x04synthetic prefetch %d", i)),
		})
	}
	for i := 0; i < 600; i++ {
		files = append(files, ad1gen.File{
			Path: fmt.Sprintf("C/Windows/Logs/CBS/CBS%04d.log", i),
			Data: []byte(fmt.Sprintf("synthetic log line %d\n", i)),
		})
	}
	for i := 0; i < 400; i++ {
		files = append(files, ad1gen.File{
			Path: fmt.Sprintf("C/Users/jdoe/AppData/Local/Microsoft/Edge/User Data/Default/Cache/data_%04d", i),
			Data: []byte("synthetic browser cache"),
		})
	}
	for i := 0; i < 800; i++ {
		files = append(files, ad1gen.File{
			Path: fmt.Sprintf("C/Windows/WinSxS/synthetic/file_%05d.dll", i),
			Data: []byte("synthetic binary content"),
		})
	}
	for i := 0; i < 300; i++ {
		files = append(files, ad1gen.File{
			Path: fmt.Sprintf("C/ProgramData/Acme/reports/report_%04d.xml", i),
			Data: []byte("<report>synthetic</report>"),
		})
	}
	files = append(files, ad1gen.File{Path: "C/$MFT", Data: []byte("FILE0synthetic mft")})
	files = append(files, ad1gen.File{Path: "C/Windows/appcompat/Programs/Amcache.hve", Data: systemHive()})
	files = append(files, ad1gen.File{Path: "C/Windows/System32/sru/SRUDB.dat", Data: []byte("synthetic ESE")})
	files = append(files, ad1gen.File{
		Path: "C/Users/jdoe/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadline/ConsoleHost_history.txt",
		Data: []byte("Get-Process\nwhoami\n"),
	})

	img, err := ad1gen.Build(`E:\TriageDemo`, files, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, img, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s: %d files, %d bytes", out, len(files), len(img))
}
