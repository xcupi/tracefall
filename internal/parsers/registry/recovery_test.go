package registry_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
	parser "tracefall/internal/parsers/registry"
	"tracefall/internal/regf/regfgen"
)

// systemHiveWith is a SYSTEM hive; with the backdoor service it is the state the
// transaction log leads to.
func systemHiveWith(backdoor bool) []byte {
	svcs := []*regfgen.Key{regfgen.NewKey("AcmeUpdater").WithLastWrite(lastWrite).WithValues(
		regfgen.ExpandStringValue("ImagePath", `C:\Windows\System32\acme.exe`), regfgen.DWordValue("Start", 2))}
	if backdoor {
		for _, n := range []string{"Svc1", "Svc2", "Svc3", "Svc4", "Svc5", "Svc6"} {
			pad := make([]byte, 3000)
			svcs = append(svcs, regfgen.NewKey(n).WithLastWrite(lastWrite).WithValues(regfgen.BinaryValue("blob", pad)))
		}
		svcs = append(svcs, regfgen.NewKey("Updater2").WithLastWrite(lastWrite).WithValues(
			regfgen.ExpandStringValue("ImagePath", `C:\Users\Public\u2.exe`), regfgen.DWordValue("Start", 2)))
	}
	cn := regfgen.NewKey("ComputerName", regfgen.NewKey("ComputerName").WithLastWrite(lastWrite).WithValues(regfgen.StringValue("ComputerName", "WKSTN-042")))
	cs1 := regfgen.NewKey("ControlSet001", regfgen.NewKey("Control", cn), regfgen.NewKey("Services", svcs...))
	root := regfgen.NewKey("CMI-CreateHive{SYSTEM}", cs1, regfgen.NewKey("Select").WithValues(regfgen.DWordValue("Current", 1))).WithLastWrite(lastWrite)
	return regfgen.Build(`\??\C:\Windows\System32\config\SYSTEM`, root)
}

func parseWithRes(t *testing.T, path string) parsers.ParseResult {
	t.Helper()
	res, err := parser.New().ParseWithContext(path, parsers.ParseContext{EvidencePath: filepath.Base(path)})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func hasService(events []model.Event, image string) bool {
	for _, e := range events {
		if strings.Contains(e.Extra["registry_value_data"], image) {
			return true
		}
	}
	return false
}

func dirtyDir(t *testing.T, logName string, logSeq uint32) string {
	t.Helper()
	old, truth := systemHiveWith(false), systemHiveWith(true)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SYSTEM"), regfgen.WithSequences(old, 3, 2), 0o600); err != nil {
		t.Fatal(err)
	}
	if logName != "" {
		if err := os.WriteFile(filepath.Join(dir, logName), regfgen.NewFormatLog(old, truth, logSeq), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "SYSTEM")
}

func TestParse_DirtyHiveIsReadInTheStateItsTransactionLogDescribes(t *testing.T) {
	res := parseWithRes(t, dirtyDir(t, "SYSTEM.LOG1", 3))
	if !hasService(res.Events, `C:\Users\Public\u2.exe`) {
		t.Fatal("a service that exists only in the transaction log was not seen")
	}
	for _, e := range res.Events {
		if e.Extra["hive_state"] != "replayed" || !strings.Contains(e.Extra["hive_recovery"], "SYSTEM.LOG1") {
			t.Fatalf("event %s does not say it comes from a replayed hive: %v", e.EventType, e.Extra)
		}
	}
}

func TestParse_LogsAreFoundWhateverTheirCase(t *testing.T) {
	// Collections copied from Windows keep the case the file system gave them,
	// and a Linux file system distinguishes it.
	res := parseWithRes(t, dirtyDir(t, "system.log1", 3))
	if !hasService(res.Events, `C:\Users\Public\u2.exe`) {
		t.Fatal("system.log1 beside SYSTEM was not used")
	}
}

func TestParse_DirtyHiveWithoutALogSaysItIsNotComplete(t *testing.T) {
	res := parseWithRes(t, dirtyDir(t, "", 0))
	if hasService(res.Events, `C:\Users\Public\u2.exe`) {
		t.Fatal("without a log the later state must not appear")
	}
	if res.Coverage == nil || !res.Coverage.Incomplete() || len(res.Coverage.Notes) == 0 || !strings.Contains(res.Coverage.Notes[0], "not cleanly written") {
		t.Fatalf("coverage = %+v", res.Coverage)
	}
	for _, e := range res.Events {
		if e.Extra["hive_state"] != "no_logs" {
			t.Fatalf("event not marked: %v", e.Extra)
		}
	}
}

func TestParse_LogThatDoesNotConnectIsNotAppliedAndIsExplained(t *testing.T) {
	res := parseWithRes(t, dirtyDir(t, "SYSTEM.LOG1", 40)) // primary finished 2, began 3
	if hasService(res.Events, `C:\Users\Public\u2.exe`) {
		t.Fatal("a log with a gap was applied")
	}
	if res.Coverage == nil || len(res.Coverage.Notes) == 0 || !strings.Contains(res.Coverage.Notes[0], "40") {
		t.Fatalf("the note should name where the log starts: %+v", res.Coverage)
	}
	for _, e := range res.Events {
		if e.Extra["hive_state"] != "not_recoverable" {
			t.Fatalf("event not marked: %v", e.Extra)
		}
	}
}

func TestParse_CleanHiveCarriesNoRecoveryNoise(t *testing.T) {
	res := parseWithRes(t, writeHive(t, "SYSTEM", systemHive()))
	if len(res.Events) == 0 {
		t.Fatal("no events")
	}
	for _, e := range res.Events {
		if _, ok := e.Extra["hive_state"]; ok {
			t.Fatalf("a clean hive's event carries hive_state: %v", e.Extra)
		}
	}
	if res.Coverage != nil && len(res.Coverage.Notes) > 0 {
		t.Fatalf("notes on a clean hive: %v", res.Coverage.Notes)
	}
}
