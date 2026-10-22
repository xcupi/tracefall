package defendercmd

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
)

// TRACEFALL_REAL_MPCMDRUN is the path of a real MpCmdRun.log (Windows 10). The
// expected figures come from a separate pass over the raw bytes, not from this
// parser.
func TestRealMpCmdRunLog(t *testing.T) {
	path := os.Getenv("TRACEFALL_REAL_MPCMDRUN")
	if path == "" {
		t.Skip("TRACEFALL_REAL_MPCMDRUN not set")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != "36e1e7c40fe7e29bceccb976f13dce8ed8ecbf661d935e0f60afea14ceda0084" {
		t.Fatal("this is not the pinned MpCmdRun.log")
	}
	res, err := New().Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 16 {
		t.Fatalf("%d runs, want 16", len(res.Events))
	}
	verbs, withErr, withEnd := map[string]int{}, 0, 0
	for _, e := range res.Events {
		verbs[e.Extra["verb"]]++
		if e.Extra["error_lines"] != "" {
			withErr++
		}
		if e.Extra["end_local"] != "" {
			withEnd++
		}
		if e.Extra["timestamp_local"] == "" || !e.Timestamp.IsZero() {
			t.Errorf("every run has a local start and no instant: %v", e.Extra)
		}
	}
	for v, n := range map[string]int{"-EnableService": 1, "-RestartService": 2, "SignatureUpdate": 7, "SignaturesUpdateService": 6} {
		if verbs[v] != n {
			t.Errorf("verb %s: %d, want %d", v, verbs[v], n)
		}
	}
	if withErr != 5 || withEnd != 16 {
		t.Errorf("runs with errors %d (want 5), with an end %d (want 16)", withErr, withEnd)
	}
	if res.Events[0].Extra["timestamp_local"] != "2023-07-12T09:04:37" || res.Events[len(res.Events)-1].Extra["timestamp_local"] != "2023-07-12T20:07:48" {
		t.Errorf("first %s last %s", res.Events[0].Extra["timestamp_local"], res.Events[len(res.Events)-1].Extra["timestamp_local"])
	}
}
