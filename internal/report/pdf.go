package report

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// ErrNoRenderer means no headless Chrome or Chromium could be found. It
// is a normal, reportable condition and not a failure of the report: the
// HTML report is complete and prints to PDF from any browser.
var ErrNoRenderer = errors.New("report: no headless Chrome or Chromium is available to render a PDF")

// EnvChrome names the environment variable that pins the browser
// binary. When it is set, only that path is tried: silently falling back
// to a different browser than the one an operator chose would make the
// output depend on what happens to be installed.
const EnvChrome = "TRACEFALL_CHROME"

var chromeCandidates = []string{"chromium", "chromium-browser", "google-chrome", "google-chrome-stable"}

// FindChrome locates a browser able to print HTML to PDF.
func FindChrome() (string, error) {
	if p := os.Getenv(EnvChrome); p != "" {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
		return "", ErrNoRenderer
	}
	for _, n := range chromeCandidates {
		if p, err := exec.LookPath(n); err == nil {
			return p, nil
		}
	}
	return "", ErrNoRenderer
}

// pdfTimeout bounds one rendering. A browser that hangs must not hold a
// request open indefinitely.
const pdfTimeout = 90 * time.Second

// RenderPDF prints a rendered report to PDF with a headless browser.
//
// The input is the report's own HTML, which carries a CSP forbidding
// script and any network load, so the browser is given nothing it can
// act on beyond laying out text. It runs with an empty throwaway
// profile, a minimal environment, and a deadline.
//
// The PDF is derived from the HTML and is NOT byte-reproducible: the
// browser embeds its own creation time. The HTML is the canonical
// artifact and the one the manifest hashes.
func RenderPDF(ctx context.Context, html []byte) ([]byte, error) {
	chrome, err := FindChrome()
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "tracefall-pdf-*")
	if err != nil {
		return nil, fmt.Errorf("report: temp dir: %w", err)
	}
	defer os.RemoveAll(dir)

	in := filepath.Join(dir, "report.html")
	out := filepath.Join(dir, "report.pdf")
	if err := os.WriteFile(in, html, 0o600); err != nil {
		return nil, fmt.Errorf("report: staging html: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, pdfTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, chrome,
		"--headless=new", "--disable-gpu", "--disable-dev-shm-usage",
		"--no-first-run", "--disable-extensions", "--disable-sync",
		"--disable-background-networking", "--no-pdf-header-footer",
		"--user-data-dir="+filepath.Join(dir, "profile"),
		"--print-to-pdf="+out,
		"file://"+in,
	)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "TMPDIR=" + dir}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("report: PDF rendering timed out: %w", ctx.Err())
		}
		return nil, fmt.Errorf("report: PDF rendering failed: %w", err)
	}

	pdf, err := os.ReadFile(out)
	if err != nil {
		return nil, fmt.Errorf("report: the browser produced no PDF: %w", err)
	}
	if !bytes.HasPrefix(pdf, []byte("%PDF-")) {
		return nil, errors.New("report: the browser output is not a PDF")
	}
	return pdf, nil
}
