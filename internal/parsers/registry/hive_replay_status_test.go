package registry_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The replay status of a hive is recorded on its parse coverage in every state,
// including clean, so "no entry" never has to be read as "clean".

func TestHiveReplay_StatusIsRecordedForEveryState(t *testing.T) {
	cases := []struct {
		name      string
		logName   string
		logSeq    uint32
		wantState string
		wantLog   string
	}{
		{"replayed", "SYSTEM.LOG1", 3, "replayed", "SYSTEM.LOG1"},
		{"no logs", "", 0, "no_logs", ""},
		{"gap", "SYSTEM.LOG1", 9, "not_recoverable", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := parseWithRes(t, dirtyDir(t, tc.logName, tc.logSeq))
			if res.Coverage == nil || res.Coverage.HiveReplay == nil {
				t.Fatalf("no hive replay status recorded: %+v", res.Coverage)
			}
			hr := res.Coverage.HiveReplay
			if hr.State != tc.wantState {
				t.Fatalf("state = %q, want %q (%+v)", hr.State, tc.wantState, hr)
			}
			if tc.wantLog != "" && (len(hr.LogsApplied) != 1 || hr.LogsApplied[0] != tc.wantLog) {
				t.Errorf("logs applied = %v, want [%s]", hr.LogsApplied, tc.wantLog)
			}
			if tc.wantState != "replayed" && strings.TrimSpace(hr.Reason) == "" {
				t.Errorf("state %s has no reason", hr.State)
			}
		})
	}
}

func TestHiveReplay_CleanHiveSaysCleanAndIsNotMarkedIncomplete(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "SYSTEM")
	if err := os.WriteFile(p, systemHiveWith(true), 0o600); err != nil {
		t.Fatal(err)
	}
	res := parseWithRes(t, p)
	if res.Coverage == nil || res.Coverage.HiveReplay == nil || res.Coverage.HiveReplay.State != "clean" {
		t.Fatalf("clean hive status = %+v", res.Coverage)
	}
	if res.Coverage.Incomplete() {
		t.Errorf("a clean hive must not be reported as incomplete: %+v", res.Coverage)
	}
	for _, e := range res.Events {
		if _, ok := e.Extra["hive_state"]; ok {
			t.Errorf("a clean hive's events must stay unannotated (contract): %v", e.Extra)
		}
	}
}
