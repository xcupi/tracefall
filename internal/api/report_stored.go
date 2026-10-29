package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/report"
)

// ErrNoStoredReport means the case has no report bundle written by the
// pipeline yet.
var ErrNoStoredReport = errors.New("no report has been generated for this case")

// StoredReport describes a report bundle the pipeline wrote for a case.
type StoredReport struct {
	File string `json:"file"`
	// SHA256 is the hash of the whole ZIP, the file an examiner keeps.
	SHA256 string `json:"sha256"`
	// ReportHTMLSHA256 is the hash of report.html inside it, as the manifest
	// and the audit entry record it.
	ReportHTMLSHA256 string    `json:"report_html_sha256"`
	Bytes            int64     `json:"bytes"`
	GeneratedAt      time.Time `json:"generated_at"`
}

func (s *Service) reportsDir(caseID string) string {
	return filepath.Join(s.files.CaseDir(caseID), "reports")
}

// GenerateCaseReport builds the case's report bundle, writes it into the case
// directory and records the issuance in the audit log. The pipeline calls it
// after analysis, so every analysed case ends with a report on disk.
//
// The bundle is built before the audit entry is written, so the report never
// lists its own issuance (the same rule as the on-demand endpoints).
func (s *Service) GenerateCaseReport(caseID, jobID string) (StoredReport, error) {
	releaseGate, err := s.heavyOp()
	if err != nil {
		return StoredReport{}, err
	}
	defer releaseGate()
	now := time.Now().UTC()
	b, err := s.buildReport(caseID, now)
	if err != nil {
		return StoredReport{}, fmt.Errorf("building the report: %w", err)
	}
	defer b.release()

	dir := s.reportsDir(caseID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return StoredReport{}, fmt.Errorf("creating the report directory: %w", err)
	}
	name := "report-" + now.Format("20060102T150405.000000000Z") + ".zip"
	final := filepath.Join(dir, name)
	// Write beside the final name and rename, so a reader never sees a
	// half-written bundle and a crash leaves no file under the real name. The
	// bundle is streamed to that file, so it is never held in memory.
	tmp := final + ".partial"
	sum, size, err := writeBundleFile(tmp, now, b)
	if err != nil {
		os.Remove(tmp)
		return StoredReport{}, fmt.Errorf("writing the report: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		os.Remove(tmp)
		return StoredReport{}, fmt.Errorf("saving the report: %w", err)
	}
	manifest := b.Manifest
	st := StoredReport{
		File:             name,
		SHA256:           sum,
		ReportHTMLSHA256: manifest.Report.SHA256,
		Bytes:            size,
		GeneratedAt:      now,
	}
	s.audit(caseID, model.AuditExport, model.TargetCase, caseID,
		fmt.Sprintf("Forensic report generated automatically by pipeline job %s: %s (bundle SHA-256 %s; report.html SHA-256 %s)",
			jobID, name, st.SHA256, st.ReportHTMLSHA256))
	return st, nil
}

// writeBundleFile writes the report bundle to path and returns its SHA-256
// and size. The bundle is streamed: the spooled timeline is copied from its
// own file, never loaded whole.
func writeBundleFile(path string, generated time.Time, b reportBuild) (string, int64, error) {
	return writeBundleFileCtx(context.Background(), path, generated, b)
}

// writeBundleFileCtx is writeBundleFile that stops mid-stream once ctx is done.
// The caller removes the partial file on error.
func writeBundleFileCtx(ctx context.Context, path string, generated time.Time, b reportBuild) (string, int64, error) {
	if err := ctx.Err(); err != nil {
		return "", 0, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return "", 0, err
	}
	h := sha256.New()
	cw := &countWriter{w: io.MultiWriter(f, h)}
	if err := writeBundleTo(ctx, cw, generated, b); err != nil {
		f.Close()
		return "", 0, err
	}
	if err := f.Close(); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), cw.n, nil
}

// writeBundleTo streams the bundle ZIP to w, stopping once ctx is done.
func writeBundleTo(ctx context.Context, w io.Writer, generated time.Time, b reportBuild) error {
	all := append([]report.File{
		{Name: "report.html", Data: b.HTML},
		{Name: report.ManifestName, Data: b.ManifestJSON},
	}, b.Files...)
	return report.BundleTo(ctxWriter{ctx: ctx, w: w}, generated, all)
}
