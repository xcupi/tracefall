package api

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/report"
	"tracefall/internal/version"
)

func rawGet(t *testing.T, mux http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	return rec
}

// reportCase builds an analyzed case from the bundled synthetic dataset
// and returns its service so tests can reach below the HTTP surface.
func reportCase(t *testing.T) (*Service, http.Handler, model.Case) {
	t.Helper()
	svc := newTestService(t)
	mux := routerFor(svc)
	c := mustCreateCase(t, mux, "Report case")
	discoverPathAndImportAll(t, mux, c.ID, filepath.Join("..", "..", "testdata", "synthetic_case"))
	if rec := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/analyze", nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("analyze: %d %s", rec.Code, rec.Body.String())
	}
	return svc, mux, c
}

func unzip(t *testing.T, b []byte) map[string][]byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("not a zip: %v", err)
	}
	out := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(rc)
		rc.Close()
		out[f.Name] = data
	}
	return out
}

func TestReport_BundleVerifiesAndCarriesTheCaseEvidence(t *testing.T) {
	svc, mux, c := reportCase(t)

	rec := rawGet(t, mux, "/api/cases/"+c.ID+"/report.zip")
	if rec.Code != http.StatusOK {
		t.Fatalf("report.zip: %d %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/zip" {
		t.Errorf("Content-Type = %q", ct)
	}
	files := unzip(t, rec.Body.Bytes())
	for _, name := range []string{"report.html", "manifest.json", "timeline.csv", "findings.csv"} {
		if len(files[name]) == 0 {
			t.Errorf("bundle is missing %s", name)
		}
	}

	var list []report.File
	for n, d := range files {
		list = append(list, report.File{Name: n, Data: d})
	}
	if mm, err := report.Verify(files["manifest.json"], list); err != nil || len(mm) != 0 {
		t.Fatalf("a freshly produced bundle must verify: %v %+v", err, mm)
	}

	html := string(files["report.html"])
	if strings.Contains(html, "Tracefall Tracefall") {
		t.Error("the tool name is printed twice")
	}
	if !strings.Contains(html, "Tracefall "+version.Version) {
		t.Errorf("the report does not name the tool version %q", version.Version)
	}
	cols, _ := svc.store.ListCollections(c.ID)
	if len(cols) != 1 {
		t.Fatalf("collections = %d", len(cols))
	}
	for _, want := range []string{"Report case", cols[0].ArchiveHash, cols[0].IntegritySHA512, "Executive summary", "Findings"} {
		if !strings.Contains(html, want) {
			t.Errorf("report does not contain %q", want)
		}
	}
	if cols[0].EvidenceDirectory != "" && strings.Contains(html, cols[0].EvidenceDirectory) {
		t.Error("the report leaks a server filesystem path")
	}
	findings, _ := svc.store.ListFindings(c.ID)
	if len(findings) == 0 {
		t.Fatal("fixture produced no findings; the test would prove nothing")
	}
	if !strings.Contains(html, findings[0].Title) {
		t.Errorf("finding %q is not in the report", findings[0].Title)
	}
}

func TestReport_AttachmentsAreByteIdenticalToTheExportEndpoints(t *testing.T) {
	_, mux, c := reportCase(t)
	files := unzip(t, rawGet(t, mux, "/api/cases/"+c.ID+"/report.zip").Body.Bytes())

	for name, path := range map[string]string{
		"timeline.csv": "/api/cases/" + c.ID + "/export/timeline.csv",
		"findings.csv": "/api/cases/" + c.ID + "/export/findings.csv",
	} {
		if got := rawGet(t, mux, path).Body.Bytes(); !bytes.Equal(got, files[name]) {
			t.Errorf("%s differs from %s: the hash in the manifest would not match the export an examiner downloads", name, path)
		}
	}
}

func TestReport_SameInstantRendersIdentically(t *testing.T) {
	svc, _, c := reportCase(t)
	when := time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)

	a, err := svc.buildReport(c.ID, when)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := svc.buildReport(c.ID, when)
	if !bytes.Equal(a.HTML, b.HTML) || !bytes.Equal(a.ManifestJSON, b.ManifestJSON) {
		t.Fatal("the same case at the same instant produced different bytes")
	}
	late, _ := svc.buildReport(c.ID, when.Add(time.Hour))
	if bytes.Equal(a.HTML, late.HTML) {
		t.Error("the generation time must appear in the report")
	}
}

func TestReport_FlagsAnalysisThatDoesNotDescribeTheEvidence(t *testing.T) {
	svc := newTestService(t)
	mux := routerFor(svc)
	c := mustCreateCase(t, mux, "Never analyzed")
	discoverPathAndImportAll(t, mux, c.ID, filepath.Join("..", "..", "testdata", "synthetic_case"))

	html := rawGet(t, mux, "/api/cases/"+c.ID+"/report.html").Body.String()
	if !strings.Contains(html, "may not reflect") {
		t.Error("a case that was never analyzed must carry the warning")
	}
	if rec := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/analyze", nil, nil); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	html = rawGet(t, mux, "/api/cases/"+c.ID+"/report.html").Body.String()
	if strings.Contains(html, "may not reflect") {
		t.Error("a freshly analyzed case must not carry the warning")
	}
}

func TestReport_HTMLEndpointHeadersAndHash(t *testing.T) {
	_, mux, c := reportCase(t)
	rec := rawGet(t, mux, "/api/cases/"+c.ID+"/report.html")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q", ct)
	}
	sum := sha256.Sum256(rec.Body.Bytes())
	if got := rec.Header().Get("X-Tracefall-Report-SHA256"); got != hex.EncodeToString(sum[:]) {
		t.Errorf("X-Tracefall-Report-SHA256 = %q, want the hash of the body", got)
	}
	if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "default-src 'none'") {
		t.Error("the HTML report must be served under a restrictive CSP")
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing nosniff")
	}
}

func TestReport_GenerationIsAuditedWithItsHash(t *testing.T) {
	svc, mux, c := reportCase(t)
	rec := rawGet(t, mux, "/api/cases/"+c.ID+"/report.html")
	want := rec.Header().Get("X-Tracefall-Report-SHA256")

	log, err := svc.store.ListAuditLog(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range log {
		if e.Action == model.AuditExport && strings.Contains(e.Summary, want) {
			return
		}
	}
	t.Errorf("no audit entry records that a report with hash %s was issued", want)
}

func TestReport_UnknownCaseIsNotFound(t *testing.T) {
	mux := newTestRouter(t)
	for _, p := range []string{"report.html", "report.zip", "report.pdf"} {
		if rec := rawGet(t, mux, "/api/cases/nope/"+p); rec.Code != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", p, rec.Code)
		}
	}
}

func TestReport_CaseWithNoEvidenceStillProducesAnHonestReport(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Empty")
	rec := rawGet(t, mux, "/api/cases/"+c.ID+"/report.html")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	html := rec.Body.String()
	if !strings.Contains(html, "No evidence has been added") || !strings.Contains(html, "may not reflect") {
		t.Error("an empty case must say so rather than imply a clean result")
	}
}

func TestReport_PDFIsUnavailableNotFakedWhenNoRendererExists(t *testing.T) {
	t.Setenv("TRACEFALL_CHROME", "/nonexistent/chrome")
	t.Setenv("PATH", t.TempDir())
	_, mux, c := reportCase(t)
	rec := rawGet(t, mux, "/api/cases/"+c.ID+"/report.pdf")
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status %d, want 501", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "report.html") {
		t.Error("the error should point to the HTML report as the alternative")
	}
}

func TestReport_PDFIsRealWhenARendererExists(t *testing.T) {
	found := ""
	for _, n := range []string{"chromium", "chromium-browser", "google-chrome", "google-chrome-stable"} {
		if p, err := exec.LookPath(n); err == nil {
			found = p
			break
		}
	}
	if found == "" {
		t.Skip("no Chrome/Chromium on this machine")
	}
	_, mux, c := reportCase(t)
	rec := rawGet(t, mux, "/api/cases/"+c.ID+"/report.pdf")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if !bytes.HasPrefix(rec.Body.Bytes(), []byte("%PDF-")) || rec.Body.Len() < 2000 {
		t.Errorf("not a plausible PDF (%d bytes)", rec.Body.Len())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/pdf" {
		t.Errorf("Content-Type = %q", ct)
	}
}

// The report is only useful if an examiner can reach it. The dashboard's
// export menu is where the other deliverables already live.
func TestUI_ExportMenuOffersTheForensicReport(t *testing.T) {
	src := string(appJS(t))
	for _, want := range []string{"/report.html", "/report.pdf", "/report.zip"} {
		if !strings.Contains(src, "/api/cases/${caseId}"+want) {
			t.Errorf("the export menu has no link to %s", want)
		}
	}
}
