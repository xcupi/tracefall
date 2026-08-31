package nativegen

// Generates a large LOCAL-PATH evidence directory for Phase 9A
// performance and progress verification: many genuinely supported files,
// so an import takes long enough for progress to be observable, plus a
// realistic mass of unsupported noise around them.
//
//	BULK_OUT=/path go test ./internal/nativegen -run TestGenerateBulkDir -write-samples

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tracefall/internal/evtx/evtxgen"
	"tracefall/internal/regf/regfgen"
)

func TestGenerateBulkDir(t *testing.T) {
	if !*write {
		t.Skip("pass -write-samples to regenerate")
	}
	root := os.Getenv("BULK_OUT")
	if root == "" {
		root = filepath.Join(os.TempDir(), "tracefall-bulk")
	}
	supported := envInt("BULK_SUPPORTED", 300)
	noise := envInt("BULK_NOISE", 7000)

	mk := func(rel string, data []byte) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	for i := 0; i < supported; i++ {
		// Alternate the two native formats so both parsers are exercised.
		// Each file gets DISTINCT content: identical bytes would be
		// correctly flagged as within-collection duplicates and become
		// unselectable, which is right but defeats a bulk-import test.
		if i%2 == 0 {
			mk(fmt.Sprintf("Windows/System32/winevt/Logs/Archive-Security-%04d.evtx", i), uniqueSecurityLog(i))
		} else {
			mk(fmt.Sprintf("Users/user%04d/NTUSER.DAT", i), uniqueNTUser(i))
		}
	}
	for i := 0; i < noise; i++ {
		switch i % 5 {
		case 0:
			mk(fmt.Sprintf("Windows/Prefetch/APP%05d.EXE-A1B2C3D4.pf", i), []byte("MAM\x04noise"))
		case 1:
			mk(fmt.Sprintf("Windows/Logs/CBS/CBS%05d.log", i), []byte("noise"))
		case 2:
			mk(fmt.Sprintf("Users/u/AppData/Local/Microsoft/Edge/User Data/Default/Cache/d_%05d", i), []byte("noise"))
		case 3:
			mk(fmt.Sprintf("Windows/WinSxS/x/file_%05d.dll", i), []byte("noise"))
		default:
			mk(fmt.Sprintf("ProgramData/Acme/reports/r_%05d.xml", i), []byte("<r/>"))
		}
	}
	t.Logf("wrote %s: %d supported + %d unsupported", root, supported, noise)
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n := 0
	for _, c := range v {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
	}
	if n == 0 {
		return def
	}
	return n
}

// uniqueSecurityLog varies the account name per file so no two fixtures
// are byte-identical.
func uniqueSecurityLog(i int) []byte {
	const ch, pr = "Security", "Microsoft-Windows-Security-Auditing"
	var out []evtxgen.Event
	for j := 0; j < 6; j++ {
		out = append(out, ev(time.Duration(j)*time.Minute, uint64(j+1), ch, pr, 4624, map[string]string{
			"TargetUserName": fmt.Sprintf("user%04d-%d", i, j),
			"LogonType":      "3",
			"IpAddress":      "198.51.100.23",
		}))
	}
	return evtxgen.Build(out)
}

func uniqueNTUser(i int) []byte {
	run := regfgen.NewKey("Run").WithLastWrite(base).WithValues(
		regfgen.StringValue(fmt.Sprintf("Helper%04d", i), fmt.Sprintf(`C:\Users\user%04d\AppData\Local\Temp\update.exe`, i)),
	)
	cv := regfgen.NewKey("CurrentVersion", run)
	win := regfgen.NewKey("Windows", cv)
	ms := regfgen.NewKey("Microsoft", win)
	sw := regfgen.NewKey("Software", ms)
	root := regfgen.NewKey("CMI-CreateHive{NTUSER}", sw).WithLastWrite(base)
	return regfgen.Build(fmt.Sprintf(`\??\C:\Users\user%04d\NTUSER.DAT`, i), root)
}
