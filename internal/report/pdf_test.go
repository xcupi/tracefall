package report

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// These tests drive the production RenderPDF (headless Chrome, with the
// browser's own sandbox left on) against a neutral synthetic report. They
// skip when the browser or Poppler is missing; they never substitute
// another renderer. Set TRACEFALL_PDF_PROOF_DIR to keep the PDF and its
// extracted text for visual review.

const (
	pdfLongPath = `C:\Users\synthetic.user\AppData\Local\Temp\` +
		`aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\` +
		`bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\END-OF-PATH.dat`
	pdfLongCmd  = `powershell.exe -NoProfile -Command "Write-Output ` + `x1x2x3x4x5x6x7x8x9x0` + `y1y2y3y4y5y6y7y8y9y0z1z2z3z4z5z6z7z8z9z0w1w2w3w4w5w6w7w8w9w0 END-OF-COMMAND"`
	pdfIndoText = "Pengguna “contoh” — café, naïve, 日本語, Ünïcode… ½ ≥ 5 — akhir-teks"
	pdfEvtHash  = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func needPDFTools(t *testing.T) {
	t.Helper()
	if _, err := FindChrome(); err != nil {
		t.Skip("no Chrome/Chromium on this machine")
	}
	for _, n := range []string{"pdftotext", "pdfinfo"} {
		if _, err := exec.LookPath(n); err != nil {
			t.Skip(n + " (Poppler) not installed")
		}
	}
}

func pdfEvents(prefix string, n int) []EventRef {
	out := make([]EventRef, 0, n)
	for i := 0; i < n; i++ {
		e := EventRef{
			ID:       fmt.Sprintf("%s-%03d", prefix, i),
			Time:     fmt.Sprintf("2026-10-01T07:%02d:00Z", i%60),
			Type:     "process_creation",
			Artifact: "Windows Event Log",
			Summary:  pdfLongCmd,
			Source:   "Windows/System32/winevt/Logs/" + pdfLongPath,
			Ref:      fmt.Sprintf("record %d", i),
			Details: []KV{
				{"File SHA-256", pdfEvtHash},
				{"Image path", pdfLongPath},
			},
		}
		if i%10 == 3 { // an observation that records no time at all
			e.Time = ""
		}
		out = append(out, e)
	}
	return out
}

// pdfFixture is a neutral, synthetic report of at most 100 events that is
// long enough to cross many pages.
func pdfFixture() Data {
	d := sampleData()
	d.Meta.CaseName = "Synthetic neutral case — " + pdfIndoText
	d.Summary.Events = 100
	d.Timeline.Total = 100
	d.Timeline.Dated = 90
	d.Timeline.Undated = 10
	d.Timeline.Key = pdfEvents("key", 40)
	d.Findings = nil
	for i := 0; i < 3; i++ {
		f := sampleData().Findings[0]
		f.Number = fmt.Sprintf("F-%03d", i+1)
		f.ID = fmt.Sprintf("find-%d", i)
		f.Description = pdfIndoText
		f.Events = pdfEvents(fmt.Sprintf("f%d", i), 20)
		f.EventCount = len(f.Events)
		d.Findings = append(d.Findings, f)
	}
	d.Summary.Findings = len(d.Findings)
	d.Correlations = []Correlation{{
		Number: "C-001", ID: "corr-1", Type: "execution_chain", Title: "Synthetic chain",
		Description: "neutral", FirstSeen: "2026-10-01T07:00:00Z", LastSeen: "2026-10-01T07:59:00Z",
		Events: pdfEvents("c0", 10), EventCount: 10,
	}}
	d.Coverage.Duplicates = 0
	d.Coverage.ParseFailed = 0
	return d
}

type pdfResult struct {
	pdf  []byte
	text string // pdftotext -layout output
	flat string // text with all whitespace removed, for wrapped long strings
	path string
}

func renderFixturePDF(t *testing.T, d Data) pdfResult {
	t.Helper()
	html, err := Render(d)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pdf, err := RenderPDF(ctx, html)
	if err != nil {
		t.Fatalf("RenderPDF: %v", err)
	}
	dir := os.Getenv("TRACEFALL_PDF_PROOF_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	p := filepath.Join(dir, t.Name()+".pdf")
	if err := os.WriteFile(p, pdf, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("pdftotext", "-layout", p, "-").Output()
	if err != nil {
		t.Fatalf("pdftotext: %v", err)
	}
	if os.Getenv("TRACEFALL_PDF_PROOF_DIR") != "" {
		_ = os.WriteFile(filepath.Join(dir, t.Name()+".txt"), out, 0o600)
	}
	// Layout mode interleaves the wrapped lines of neighbouring table
	// cells, so wrapped strings are checked in raw (content-stream order) extraction.
	raw, err := exec.Command("pdftotext", "-raw", p, "-").Output()
	if err != nil {
		t.Fatalf("pdftotext: %v", err)
	}
	flat := strings.Join(strings.Fields(string(raw)), "")
	return pdfResult{pdf: pdf, text: string(out), flat: flat, path: p}
}

func pdfPages(t *testing.T, path string) int {
	t.Helper()
	out, err := exec.Command("pdfinfo", path).Output()
	if err != nil {
		t.Fatalf("pdfinfo: %v", err)
	}
	m := regexp.MustCompile(`Pages:\s+(\d+)`).FindSubmatch(out)
	if m == nil {
		t.Fatalf("no page count in pdfinfo output: %s", out)
	}
	n, _ := strconv.Atoi(string(m[1]))
	return n
}

func TestPDF_SyntheticReportKeepsEvidenceThroughChrome(t *testing.T) {
	needPDFTools(t)
	d := pdfFixture()
	r := renderFixturePDF(t, d)

	if !bytes.HasPrefix(r.pdf, []byte("%PDF-")) || len(r.pdf) < 20000 {
		t.Fatalf("not a plausible PDF (%d bytes)", len(r.pdf))
	}
	if n := pdfPages(t, r.path); n < 8 {
		t.Errorf("fixture is meant to span many pages; got %d", n)
	}

	for name, want := range map[string]string{
		"SHA-256 of evidence":    d.Evidence[0].SHA256,
		"SHA-512 of evidence":    d.Evidence[0].SHA512,
		"event hash":             pdfEvtHash,
		"attachment hash":        d.Attachments[0].SHA256,
		"path tail":              "END-OF-PATH.dat",
		"command tail":           "END-OF-COMMAND",
		"Indonesian/non-Latin":   strings.Join(strings.Fields(pdfIndoText), ""),
		"finding number":         "F-003",
		"correlation":            "C-001",
		"footer":                 "Case" + d.Meta.CaseID,
		"last key timeline item": "key-039",
	} {
		if !strings.Contains(r.flat, strings.Join(strings.Fields(want), "")) {
			t.Errorf("PDF text lost %s (%q)", name, want)
		}
	}

	// Unknown must stay distinct from measured zero.
	if !strings.Contains(r.text, "10 record none") && !strings.Contains(r.flat, "10recordnone") {
		t.Error("the undated count (10) is not stated")
	}
	if !strings.Contains(r.flat, "0failedtoparse") || !strings.Contains(r.flat, "0duplicate") {
		t.Error("measured zero (0 failed to parse / 0 duplicates) is not rendered")
	}
	if !strings.Contains(r.flat, "notrecorded") {
		t.Error("an unrecorded time zone / period must read 'not recorded'")
	}
}

func TestPDF_UnknownCoverageIsNotRenderedAsZero(t *testing.T) {
	needPDFTools(t)
	d := pdfFixture()
	d.Coverage = Coverage{Discovered: 5, Supported: 4, Unsupported: 1, Imported: 4, ParseFailed: 2,
		Failed: []string{"Windows/bad.evtx"}}
	d.TimeZones = []TimeZoneRow{{Label: "Collection 1", Recorded: false, Reason: "SYSTEM hive was not collected"}}
	r := renderFixturePDF(t, d)
	if !strings.Contains(r.flat, "2failedtoparse") || !strings.Contains(r.flat, "bad.evtx") {
		t.Error("a measured non-zero parse failure must be rendered")
	}
	if strings.Contains(r.flat, "0failedtoparse") && !strings.Contains(r.flat, "10failedtoparse") && !strings.Contains(r.flat, "20failedtoparse") {
		t.Error("a measured 2 must not read as 0")
	}
	if !strings.Contains(r.flat, "SYSTEMhivewasnotcollected") {
		t.Error("the reason a time zone is unknown must be rendered")
	}
}

func TestPDF_PagesStayInsideTheA4Box(t *testing.T) {
	needPDFTools(t)
	r := renderFixturePDF(t, pdfFixture())
	out, err := exec.Command("pdftotext", "-bbox", r.path, "-").Output()
	if err != nil {
		t.Fatal(err)
	}
	pageW, pageH := 595.0, 842.0 // A4 in points
	re := regexp.MustCompile(`xMin="([\d.]+)" yMin="([\d.]+)" xMax="([\d.]+)" yMax="([\d.]+)"`)
	for _, m := range re.FindAllSubmatch(out, -1) {
		x1, _ := strconv.ParseFloat(string(m[1]), 64)
		x2, _ := strconv.ParseFloat(string(m[3]), 64)
		y2, _ := strconv.ParseFloat(string(m[4]), 64)
		if x1 < 0 || x2 > pageW+1 || y2 > pageH+1 {
			t.Fatalf("word outside the page box: %s", m[0])
		}
	}
}

func TestPDF_CancelledRenderLeavesNoBrowserOrTempFiles(t *testing.T) {
	needPDFTools(t)
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	html, err := Render(pdfFixture())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(150 * time.Millisecond); cancel() }()
	if pdf, err := RenderPDF(ctx, html); err == nil {
		t.Skipf("render finished before cancel (%d bytes); nothing to clean up", len(pdf))
	} else if pdf != nil {
		t.Error("a cancelled render must return no PDF")
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Errorf("temp dir not cleaned: %v", left)
	}
	time.Sleep(500 * time.Millisecond)
	// Any survivor would carry our throwaway profile path on its command line.
	if out, _ := exec.Command("pgrep", "-f", tmp).Output(); len(bytes.TrimSpace(out)) != 0 {
		t.Errorf("browser processes survived cancellation: %s", out)
	}
}

func TestPDF_MissingRendererIsAnHonestErrorNotAFallback(t *testing.T) {
	t.Setenv(EnvChrome, "/nonexistent/chrome")
	pdf, err := RenderPDF(context.Background(), []byte("<html></html>"))
	if !errors.Is(err, ErrNoRenderer) || pdf != nil {
		t.Fatalf("got (%d bytes, %v), want ErrNoRenderer and no output", len(pdf), err)
	}
}

// Attachment file names are short, tool-chosen identifiers. Splitting one
// across lines ("timeline.c" / "sv") makes the inventory harder to match
// against the bundle and manifest.
func TestPDF_AttachmentNamesAreNotBrokenMidWord(t *testing.T) {
	needPDFTools(t)
	d := pdfFixture()
	d.Attachments = []Attachment{
		{Name: "timeline.csv", Description: "Full timeline", SHA256: strings.Repeat("ef", 32), Bytes: 1000, Rows: 120},
		{Name: "cited-events.json", Description: "Cited events", SHA256: strings.Repeat("12", 32), Bytes: 2000, Rows: 7},
	}
	r := renderFixturePDF(t, d)
	for _, a := range d.Attachments {
		if !strings.Contains(r.text, a.Name) {
			t.Errorf("attachment name %q is split across lines in the PDF", a.Name)
		}
	}
}

// Chrome binds a unix socket under TMPDIR, and sun_path holds ~107 bytes.
// With a deep TMPDIR the browser aborts. That must surface as an
// actionable error naming the cause, not just "signal: aborted"; the
// shallow-TMPDIR control proves the renderer itself is fine.
func TestPDF_DeepTMPDIRFailureNamesItsCause(t *testing.T) {
	needPDFTools(t)
	html := []byte("<html><body><p>neutral</p></body></html>")

	// Positive control: the ambient TMPDIR (already used by the tests above).
	if pdf, err := RenderPDF(context.Background(), html); err != nil || !bytes.HasPrefix(pdf, []byte("%PDF-")) {
		t.Fatalf("control render failed: %v", err)
	}

	deep := filepath.Join(t.TempDir(), strings.Repeat("d", 60), strings.Repeat("e", 60))
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", deep)
	pdf, err := RenderPDF(context.Background(), html)
	if err == nil {
		t.Skip("this Chrome tolerates a deep TMPDIR")
	}
	if pdf != nil {
		t.Error("a failed render must return no PDF")
	}
	for _, want := range []string{"Socket path too long", "TMPDIR"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
	if left, _ := os.ReadDir(deep); len(left) != 0 {
		t.Errorf("staging dir left behind: %v", left)
	}
}
