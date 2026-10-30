package defenderhistory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParserDiscoveryPrivacyAndAtomicFailure(t *testing.T) {
	p := New()
	b := fixture()
	if p.Detect("DetectionHistory/random") || !p.DetectPath(`neutral\DetectionHistory\any\arbitrary-name`) || p.DetectPath("Other/arbitrary-name") || !p.DetectContent(b[:512]) || !p.ConfirmContent(b[:512]) || p.ConfirmContent([]byte("unrelated")) {
		t.Fatal("path hint/content confirmation contract missing")
	}
	f := filepath.Join(t.TempDir(), "not-a-guid")
	if err := os.WriteFile(f, b, 0600); err != nil {
		t.Fatal(err)
	}
	out, err := p.Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Events) != 1 || len(out.Raw) != 1 || out.Coverage == nil || out.Coverage.RecordsRead != 1 || out.Coverage.Mapped != 1 || out.Coverage.Undated != 1 {
		t.Fatalf("observation coverage: %+v", out.Coverage)
	}
	e := out.Events[0]
	if e.EventType != "antimalware_history_observation" || !e.Timestamp.IsZero() || e.Host != "" || e.ProcessName != "" || e.SourceReference != out.Raw[0].SourceReference {
		t.Fatal("fabricated outcome/time/attribution")
	}
	projected, _ := json.Marshal(e)
	for _, canary := range []string{"private canary", "neutral-secret-canary", "RepeatedUnknown", "Neutral.Test"} {
		if strings.Contains(string(projected), canary) {
			t.Fatal("private raw values leaked to event")
		}
	}
	var raw struct {
		SourceBytes []byte
		Record      *Record
	}
	if err := json.Unmarshal([]byte(out.Raw[0].Raw), &raw); err != nil {
		t.Fatal(err)
	}
	if string(raw.SourceBytes) != string(b) || raw.Record.EOF != len(b) {
		t.Fatal("raw source/typed projection not lossless")
	}
	if err := os.WriteFile(f, b[:len(b)-1], 0600); err != nil {
		t.Fatal(err)
	}
	bad, err := p.Parse(f)
	if err == nil || len(bad.Events) != 0 || bad.Coverage != nil {
		t.Fatal("partial/false-zero success on truncation")
	}
}
