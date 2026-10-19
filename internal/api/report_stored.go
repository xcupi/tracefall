package api

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
	now := time.Now().UTC()
	zipBytes, manifest, err := s.reportBundleBytes(caseID, now)
	if err != nil {
		return StoredReport{}, fmt.Errorf("building the report: %w", err)
	}

	dir := s.reportsDir(caseID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return StoredReport{}, fmt.Errorf("creating the report directory: %w", err)
	}
	name := "report-" + now.Format("20060102T150405.000000000Z") + ".zip"
	final := filepath.Join(dir, name)
	// Write beside the final name and rename, so a reader never sees a
	// half-written bundle and a crash leaves no file under the real name.
	tmp := final + ".partial"
	if err := os.WriteFile(tmp, zipBytes, 0o644); err != nil {
		return StoredReport{}, fmt.Errorf("writing the report: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		os.Remove(tmp)
		return StoredReport{}, fmt.Errorf("saving the report: %w", err)
	}

	sum := sha256.Sum256(zipBytes)
	st := StoredReport{
		File:             name,
		SHA256:           hex.EncodeToString(sum[:]),
		ReportHTMLSHA256: manifest.Report.SHA256,
		Bytes:            int64(len(zipBytes)),
		GeneratedAt:      now,
	}
	s.audit(caseID, model.AuditExport, model.TargetCase, caseID,
		fmt.Sprintf("Forensic report generated automatically by pipeline job %s: %s (bundle SHA-256 %s; report.html SHA-256 %s)",
			jobID, name, st.SHA256, st.ReportHTMLSHA256))
	return st, nil
}

// LatestStoredReport returns the newest report bundle the pipeline wrote for
// the case, with its file name.
func (s *Service) LatestStoredReport(caseID string) (string, []byte, error) {
	entries, err := os.ReadDir(s.reportsDir(caseID))
	if err != nil {
		return "", nil, ErrNoStoredReport
	}
	var names []string
	for _, e := range entries {
		n := e.Name()
		if !e.IsDir() && strings.HasPrefix(n, "report-") && strings.HasSuffix(n, ".zip") {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return "", nil, ErrNoStoredReport
	}
	// The names carry a UTC timestamp of fixed width, so lexical order is
	// generation order.
	sort.Strings(names)
	latest := names[len(names)-1]
	b, err := os.ReadFile(filepath.Join(s.reportsDir(caseID), latest))
	if err != nil {
		return "", nil, fmt.Errorf("reading the stored report: %w", err)
	}
	return latest, b, nil
}

// reportBundleBytes builds the ZIP and its manifest. It writes nothing and
// records nothing: issuance is the caller's job.
func (s *Service) reportBundleBytes(caseID string, now time.Time) ([]byte, report.Manifest, error) {
	b, err := s.buildReport(caseID, now)
	if err != nil {
		return nil, report.Manifest{}, err
	}
	all := append([]report.File{
		{Name: "report.html", Data: b.HTML},
		{Name: report.ManifestName, Data: b.ManifestJSON},
	}, b.Files...)
	z, err := report.Bundle(now, all)
	if err != nil {
		return nil, report.Manifest{}, err
	}
	return z, b.Manifest, nil
}
