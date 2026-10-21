package api

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tracefall/internal/model"
	"tracefall/internal/regf/regfgen"
)

// negBias is UTC+7 in the registry's signed convention (UTC = local + bias).
var negBias int32 = -420

// tzSystemHive builds a SYSTEM hive whose TimeZoneInformation names UTC+7.
func tzSystemHive(t *testing.T, path string) {
	t.Helper()
	tzi := regfgen.NewKey("TimeZoneInformation").WithValues(
		regfgen.StringValue("TimeZoneKeyName", "SE Asia Standard Time"),
		regfgen.DWordValue("ActiveTimeBias", uint32(negBias)),
	)
	ctl := regfgen.NewKey("Control", tzi)
	cs := regfgen.NewKey("ControlSet001", ctl)
	sel := regfgen.NewKey("Select").WithValues(regfgen.DWordValue("Current", 1))
	root := regfgen.NewKey("CMI-CreateHive{SYSTEM}", sel, cs)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, regfgen.Build(`\??\C:\Windows\System32\config\SYSTEM`, root), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestResolveCollectionTimeZone_RecordsTheZoneOfTheCollectionsOwnSystemHive(t *testing.T) {
	svc := newTestService(t)
	c, err := svc.CreateCase("tz", "")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	tzSystemHive(t, filepath.Join(dir, "Windows", "System32", "config", "SYSTEM"))
	if _, err := svc.DiscoverEvidenceFromPath(c.ID, dir); err != nil {
		t.Fatalf("discover: %v", err)
	}
	cols, _ := svc.ListCollections(c.ID)
	if len(cols) != 1 {
		t.Fatalf("collections = %d", len(cols))
	}
	tz, err := svc.resolveCollectionTimeZone(c.ID, cols[0].ID, cols[0])
	if err != nil {
		t.Fatal(err)
	}
	if !tz.Recorded || tz.ActiveBiasMinutes != -420 || tz.KeyName != "SE Asia Standard Time" {
		t.Fatalf("tz = %+v; want UTC+7 from this collection's SYSTEM hive", tz)
	}
	if !strings.Contains(tz.Source, "Windows/System32/config/SYSTEM") && !strings.Contains(tz.Source, `Windows\System32\config\SYSTEM`) {
		t.Errorf("source %q does not name the hive it came from", tz.Source)
	}
	// Persisted, so the next import reads the record rather than the hive.
	stored, err := svc.store.GetCollection(cols[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.TimeZone.Recorded || stored.TimeZone.ActiveBiasMinutes != -420 {
		t.Errorf("stored time zone = %+v; it must survive the round trip", stored.TimeZone)
	}
}

func TestResolveCollectionTimeZone_ExplainsWhyThereIsNoZone(t *testing.T) {
	svc := newTestService(t)
	c, _ := svc.CreateCase("no tz", "")
	dir := evidenceFolder(t, t.TempDir()) // no SYSTEM hive
	if _, err := svc.DiscoverEvidenceFromPath(c.ID, dir); err != nil {
		t.Fatal(err)
	}
	cols, _ := svc.ListCollections(c.ID)
	tz, _ := svc.resolveCollectionTimeZone(c.ID, cols[0].ID, cols[0])
	if tz.Recorded {
		t.Fatalf("tz = %+v; a collection with no SYSTEM hive must not get a zone", tz)
	}
	if !strings.Contains(tz.Reason, "no SYSTEM hive") {
		t.Errorf("reason = %q; it must say why there is no zone", tz.Reason)
	}
}

func TestGenerateCaseReport_StoresTheBundleAndAuditsIt(t *testing.T) {
	svc := newTestService(t)
	c, _ := svc.CreateCase("auto report", "")

	st, err := svc.GenerateCaseReport(c.ID, "job-test")
	if err != nil {
		t.Fatalf("GenerateCaseReport: %v", err)
	}
	if !strings.HasPrefix(st.File, "report-") || !strings.HasSuffix(st.File, ".zip") {
		t.Errorf("file name %q", st.File)
	}
	name, lf, linfo, err := svc.OpenLatestStoredReport(c.ID)
	if err != nil {
		t.Fatalf("OpenLatestStoredReport: %v", err)
	}
	body, err := io.ReadAll(lf)
	lf.Close()
	if err != nil || int64(len(body)) != linfo.Size() {
		t.Fatalf("reading the stored report: %v (%d bytes, file says %d)", err, len(body), linfo.Size())
	}
	if name != st.File {
		t.Errorf("latest = %q, generated = %q", name, st.File)
	}
	if int64(len(body)) != st.Bytes {
		t.Errorf("stored %d bytes, reported %d", len(body), st.Bytes)
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("not a zip: %v", err)
	}
	have := map[string]bool{}
	for _, f := range zr.File {
		have[f.Name] = true
	}
	for _, want := range []string{"report.html", "manifest.json"} {
		if !have[want] {
			t.Errorf("bundle lacks %s; has %v", want, have)
		}
	}

	audit, _ := svc.AuditLog(c.ID)
	var issued bool
	for _, e := range audit {
		if e.Action == model.AuditExport && strings.Contains(e.Summary, "generated automatically") &&
			strings.Contains(e.Summary, st.File) && strings.Contains(e.Summary, st.SHA256) {
			issued = true
		}
	}
	if !issued {
		t.Error("the generated report must be recorded in the audit log with its file name and SHA-256")
	}
}

func TestReportLatest_ServesTheStoredBundleAnd404WhenNone(t *testing.T) {
	svc := newTestService(t)
	c, _ := svc.CreateCase("serve", "")
	h := routerFor(svc)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/cases/"+c.ID+"/report/latest", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("before any report: status %d, want 404", rec.Code)
	}

	st, err := svc.GenerateCaseReport(c.ID, "job-serve")
	if err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/cases/"+c.ID+"/report/latest", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("after generation: status %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Content-Disposition"), st.File) {
		t.Errorf("disposition %q does not name %s", rec.Header().Get("Content-Disposition"), st.File)
	}
	if rec.Body.Len() == 0 {
		t.Error("empty body")
	}
}
