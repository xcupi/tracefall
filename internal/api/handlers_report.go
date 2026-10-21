package api

import (
	"errors"
	"io"
	"net/http"
	"strconv"

	"tracefall/internal/report"
)

// reportHeaders applies the headers every report download carries. The
// CSP is also inside the HTML itself; sending it as a header as well
// covers a browser that renders the file inline from this origin, where
// the application's own policy would otherwise apply.
func reportHeaders(w http.ResponseWriter, contentType, filename string, inline bool) {
	h := w.Header()
	h.Set("Content-Type", contentType)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	disp := "attachment"
	if inline {
		disp = "inline"
	}
	h.Set("Content-Disposition", disp+`; filename="`+filename+`"`)
}

// reportHTML serves the report as one self-contained HTML document.
// ?download=1 forces a download rather than showing it in the browser.
func (h *handlers) reportHTML(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	html, sum, err := h.as(r).ReportHTML(id)
	if h.fail(w, err) {
		return
	}
	reportHeaders(w, "text/html; charset=utf-8", "tracefall-report-"+id+".html", r.URL.Query().Get("download") != "1")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.Header().Set("X-Tracefall-Report-SHA256", sum)
	_, _ = w.Write(html)
}

// reportBundle serves the report with its manifest and CSV attachments.
func (h *handlers) reportBundle(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	d, err := h.as(r).ReportBundleFile(id)
	if isCancelled(err) {
		return // the client left while queued; nobody is listening
	}
	if h.fail(w, err) {
		return
	}
	defer d.Close()
	reportHeaders(w, "application/zip", "tracefall-report-"+id+".zip", false)
	w.Header().Set("X-Tracefall-Report-SHA256", d.ReportSHA256)
	w.Header().Set("X-Tracefall-Bundle-SHA256", d.BundleSHA256)
	w.Header().Set("Content-Length", strconv.FormatInt(d.Size, 10))
	_, _ = io.Copy(w, d.File)
}

// reportPDF serves the report printed to PDF. Where the server has no
// browser to print with it says so (501) and points at the HTML report;
// it never substitutes something else for a PDF.
func (h *handlers) reportPDF(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	pdf, err := h.as(r).ReportPDF(r.Context(), id)
	switch {
	case errors.Is(err, report.ErrNoRenderer):
		writeError(w, http.StatusNotImplemented,
			"PDF output needs headless Chrome or Chromium on the server (install it, or set "+report.EnvChrome+
				" to its path). The HTML report (report.html) is complete and prints to PDF from any browser.")
		return
	case err != nil && !errors.Is(err, ErrCaseNotFound):
		h.log.Error("PDF report failed", "case", id, "error", err)
		writeError(w, http.StatusInternalServerError, "the PDF could not be rendered; the HTML report (report.html) is unaffected")
		return
	}
	if h.fail(w, err) {
		return
	}
	reportHeaders(w, "application/pdf", "tracefall-report-"+id+".pdf", false)
	_, _ = w.Write(pdf)
}
