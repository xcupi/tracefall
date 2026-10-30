package ingest

import (
	"os"
	"testing"
)

func TestDefenderHistoryRegistryPublic(t *testing.T) {
	p := os.Getenv("TRACEFALL_REAL_DEFENDER_HISTORY")
	if p == "" {
		t.Skip("public native fixture not configured")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"DetectionHistory/random", `root\DetectionHistory\folder\neutral.bin`} {
		got := MatchParser(name, b[:512], Registry())
		if got == nil || got.ArtifactType() != "defender_detection_history" {
			t.Fatal("generic history discovery missing")
		}
	}
	if got := MatchParser("DetectionHistory/random", []byte("not history"), Registry()); got != nil && got.ArtifactType() == "defender_detection_history" {
		t.Fatal("path alone claimed")
	}
	if got := MatchParser("other/random", b[:512], Registry()); got != nil && got.ArtifactType() == "defender_detection_history" {
		t.Fatal("path-scoped detection escaped")
	}
}
