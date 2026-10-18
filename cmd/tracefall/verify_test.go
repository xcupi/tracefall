package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tracefall/internal/report"
)

func writeBundle(t *testing.T, tamper bool) string {
	t.Helper()
	html := []byte("<html>report</html>")
	att := []report.File{{Name: "timeline.csv", Data: []byte("a,b\n")}}
	d := report.Data{Meta: report.Meta{CaseID: "c1", CaseName: "n", GeneratedAt: "2026-10-02T10:00:00Z"}}
	mj, err := report.NewManifest(d, "report.html", html, att).JSON()
	if err != nil {
		t.Fatal(err)
	}
	if tamper {
		html = []byte("<html>REPORT</html>")
	}
	z, err := report.Bundle(time.Now(), []report.File{
		{Name: "report.html", Data: html}, {Name: report.ManifestName, Data: mj}, att[0],
	})
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "bundle.zip")
	if err := os.WriteFile(p, z, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestVerifyReport_AcceptsAnUntouchedBundle(t *testing.T) {
	var out bytes.Buffer
	if code := verifyReportCmd([]string{writeBundle(t, false)}, &out); code != 0 {
		t.Fatalf("exit %d, output: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "OK") {
		t.Errorf("output does not say OK: %s", out.String())
	}
}

func TestVerifyReport_RejectsATamperedBundleAndNamesTheFile(t *testing.T) {
	var out bytes.Buffer
	if code := verifyReportCmd([]string{writeBundle(t, true)}, &out); code != 1 {
		t.Fatalf("exit %d, want 1; output: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "report.html") || !strings.Contains(out.String(), "MISMATCH") {
		t.Errorf("the altered file is not named: %s", out.String())
	}
}

func TestVerifyReport_UsageAndUnreadableInputAreErrorsNotPasses(t *testing.T) {
	var out bytes.Buffer
	if code := verifyReportCmd(nil, &out); code != 2 {
		t.Errorf("no argument: exit %d, want 2", code)
	}
	if code := verifyReportCmd([]string{filepath.Join(t.TempDir(), "missing.zip")}, &out); code != 2 {
		t.Errorf("missing file: exit %d, want 2", code)
	}
	bad := filepath.Join(t.TempDir(), "x.zip")
	_ = os.WriteFile(bad, []byte("not a zip"), 0o600)
	if code := verifyReportCmd([]string{bad}, &out); code != 2 {
		t.Errorf("corrupt zip: exit %d, want 2", code)
	}
}
