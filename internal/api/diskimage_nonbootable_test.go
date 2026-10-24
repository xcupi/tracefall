package api

import (
	"os"
	"strings"
	"testing"
)

func TestDiskImage_NonbootableCaptureCatalogAndWarning(t *testing.T) {
	svc, c := newImageCase(t)
	raw := rawFixture(t, "gpt")
	baseline, err := svc.DiscoverEvidenceFromPath(c.ID, raw)
	if err != nil {
		t.Fatal(err)
	}
	want := catalogPaths(t, svc, baseline.Collection.ID)
	baseReport, ok := svc.loadDiskImageReport(c.ID, baseline.Collection.ID)
	if !ok || strings.Contains(strings.Join(baseReport.Notes, " "), "DOS boot jump") {
		t.Fatal("ordinary fixture warning behavior changed")
	}
	// Mutate a separate temporary copy, never a discovered evidence source.
	raw = rawFixture(t, "gpt")
	f, err := os.OpenFile(raw, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.WriteAt([]byte{0, 0, 0}, 2048*512); err != nil {
		t.Fatal(err)
	}
	if _, err = f.WriteAt([]byte{0, 0}, 2048*512+510); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	res, err := svc.DiscoverEvidenceFromPath(c.ID, raw)
	if err != nil {
		t.Fatalf("capture discovery: %v", err)
	}
	got := catalogPaths(t, svc, res.Collection.ID)
	if len(got) != len(want) {
		t.Fatalf("catalog files=%d want %d", len(got), len(want))
	}
	for p, w := range want {
		g, ok := got[p]
		if !ok || g.Supported != w.Supported {
			t.Errorf("catalog selection changed for %s", p)
		}
	}
	for _, p := range wantImageArtifacts {
		if _, ok := got[p]; !ok {
			t.Errorf("missing native artifact %s", p)
		}
	}
	rep, ok := svc.loadDiskImageReport(c.ID, res.Collection.ID)
	if !ok {
		t.Fatal("missing persisted image report")
	}
	notes := strings.Join(rep.Notes, " ")
	if !strings.Contains(notes, "DOS boot jump and 0x55AA signature are absent") {
		t.Fatalf("missing persisted capture warning: %s", notes)
	}
	html, _, err := svc.ReportHTML(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(html), "DOS boot jump and 0x55AA signature are absent") {
		t.Fatal("warning absent from report")
	}
}
