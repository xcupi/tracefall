package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"tracefall/internal/evtx/evtxgen"
)

func TestParseCoverage_ZeroMappedImportPersistsAndWarnsInReport(t *testing.T) {
	svc := newTestService(t)
	c := mustCreateCase(t, routerFor(svc), "Unmapped source")
	dir := t.TempDir()
	f := filepath.Join(dir, "Application.evtx")
	if err := os.WriteFile(f, evtxgen.Build([]evtxgen.Event{{RecordID: 1, Timestamp: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), Provider: "OtherApplication", Channel: "Application", Computer: "SERVER01", EventID: 18456}}), 0600); err != nil {
		t.Fatal(err)
	}
	d, err := svc.DiscoverEvidenceFromPath(c.ID, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.SourceFiles) != 1 {
		t.Fatal(d)
	}
	r, err := svc.ImportEvidence(c.ID, d.Collection.ID, []string{d.SourceFiles[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	if r.EventCount != 0 || len(r.Errors) > 0 {
		t.Fatalf("%+v", r)
	}
	sf, err := svc.store.GetSourceFile(d.SourceFiles[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if sf.ParseCoverage == nil || sf.ParseCoverage.Unmapped != 1 {
		t.Error("coverage diagnostic disappeared before persistent source detail")
	}
	b, err := svc.buildReport(c.ID, time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	defer b.release()
	if !strings.Contains(string(b.HTML), "unmapped=1") || !strings.Contains(string(b.HTML), "18456") {
		t.Error("report hides valid-but-unmapped evidence")
	}
}
