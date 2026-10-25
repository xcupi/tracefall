package winevent_test

import (
	"os"
	"strconv"
	"strings"
	"testing"

	"tracefall/internal/model"
	native "tracefall/internal/parsers/evtx"
)

// expectCounts reads "key=n,key=n" from an environment variable. The expected
// numbers come from an independent decode of the same file (a separate EVTX
// reader), supplied by whoever runs the test; they are not part of this code.
func expectCounts(t *testing.T, env string) map[string]int {
	t.Helper()
	out := map[string]int{}
	raw := os.Getenv(env)
	if raw == "" {
		t.Fatalf("%s must list the independent counts, e.g. 1116=N,1117=M", env)
	}
	for _, kv := range strings.Split(raw, ",") {
		k, v, ok := strings.Cut(kv, "=")
		n, err := strconv.Atoi(v)
		if !ok || err != nil {
			t.Fatalf("bad %s entry %q", env, kv)
		}
		out[strings.TrimSpace(k)] = n
	}
	return out
}

// TRACEFALL_REAL_DEFENDER_EVTX is the path of a real Defender Operational log;
// TRACEFALL_REAL_DEFENDER_EVTX_EXPECT lists the per-EventID record counts from
// an independent reader.
func TestRealDefenderOperationalLog(t *testing.T) {
	path := os.Getenv("TRACEFALL_REAL_DEFENDER_EVTX")
	if path == "" {
		t.Skip("TRACEFALL_REAL_DEFENDER_EVTX not set")
	}
	want := expectCounts(t, "TRACEFALL_REAL_DEFENDER_EVTX_EXPECT")
	res, err := native.New().Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, e := range res.Events {
		if e.Extra["evtx_provider"] != "Microsoft-Windows-Windows Defender" {
			continue
		}
		switch e.EventType {
		case model.EventAntimalwareDetection, model.EventAntimalwareAction:
			got[strconv.Itoa(parseID(t, e.Extra["evtx_event_id"]))]++
			if e.Extra["threat_name"] == "" || e.Extra["detection_id"] == "" || e.Extra["resource"] == "" || e.Extra["action_name"] == "" {
				t.Errorf("record %s lacks recorded fields: %v", e.SourceReference, e.Extra)
			}
			if e.CommandLine != "" || e.FilePath != "" {
				t.Errorf("resource leaked into command/file fields")
			}
		}
	}
	for id, n := range want {
		if got[id] != n {
			t.Errorf("EventID %s: mapped %d, independent count %d", id, got[id], n)
		}
	}
	for id := range got {
		if _, ok := want[id]; !ok {
			t.Errorf("EventID %s mapped %d with no independent count supplied", id, got[id])
		}
	}
}

func parseID(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatalf("event id %q", s)
	}
	return n
}
