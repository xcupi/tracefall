package api

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"tracefall/internal/model"
)

// BundleDownload is a report bundle that has been written to disk and is ready
// to be sent. The server never holds the bundle in memory: building it needs a
// few hundred MB however large the case, and sending it needs none, so the
// memory a download costs does not grow with the case or with how many people
// download at once.
type BundleDownload struct {
	File *os.File
	// Size is the bundle's length in bytes.
	Size int64
	// BundleSHA256 is the hash of the ZIP, the file an examiner keeps.
	BundleSHA256 string
	// ReportSHA256 is the hash of report.html inside it, as the manifest and
	// the audit entry record it.
	ReportSHA256 string

	path string // set only if the file could not be unlinked while open
}

// Close releases the file. Nothing is left on disk.
func (d *BundleDownload) Close() error {
	err := d.File.Close()
	if d.path != "" {
		os.Remove(d.path)
	}
	return err
}

// ReportBundleFile builds the report bundle (report.html, manifest.json and the
// CSV attachments, from one consistent read so the manifest matches the files
// by construction), writes it to a file in the case folder, and returns it open.
//
// The file is unlinked as soon as it is open, so a crash cannot leave a copy of
// a case's report behind. The slot that bounds concurrent builds is held only
// while the bundle is built, not while a slow client reads it.
func (s *Service) ReportBundleFile(caseID string) (*BundleDownload, error) {
	release, err := s.heavyOp()
	if err != nil {
		return nil, err
	}
	defer release()

	now := time.Now().UTC()
	b, err := s.buildReport(caseID, now)
	if err != nil {
		return nil, err
	}
	defer b.release()
	if err := s.checkpoint("bundle-write"); err != nil {
		return nil, err
	}

	dir := s.reportsDir(caseID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("creating the report directory: %w", err)
	}
	path := filepath.Join(dir, ".download-"+uuid.NewString()+".tmp")
	sum, size, err := writeBundleFileCtx(s.opCtx(), path, now, b)
	if err != nil {
		os.Remove(path)
		return nil, fmt.Errorf("writing the report bundle: %w", err)
	}
	f, err := os.Open(path)
	if err != nil {
		os.Remove(path)
		return nil, fmt.Errorf("opening the report bundle: %w", err)
	}
	// Issuance commits at the audit entry below. Until then an abandoned
	// request leaves no file and no history entry.
	if err := s.checkpoint("pre-issue"); err != nil {
		f.Close()
		os.Remove(path)
		return nil, err
	}
	d := &BundleDownload{File: f, Size: size, BundleSHA256: sum, ReportSHA256: b.Manifest.Report.SHA256, path: path}
	if os.Remove(path) == nil {
		d.path = ""
	}
	s.audit(caseID, model.AuditExport, model.TargetCase, caseID,
		fmt.Sprintf("Forensic report bundle issued (report.html SHA-256 %s)", d.ReportSHA256))
	_ = s.checkpoint("issued")
	return d, nil
}

// OpenLatestStoredReport opens the newest report bundle the pipeline wrote for
// the case. It is opened, not read: the caller streams it.
func (s *Service) OpenLatestStoredReport(caseID string) (name string, f *os.File, info os.FileInfo, err error) {
	entries, err := os.ReadDir(s.reportsDir(caseID))
	if err != nil {
		return "", nil, nil, ErrNoStoredReport
	}
	var names []string
	for _, e := range entries {
		n := e.Name()
		if !e.IsDir() && strings.HasPrefix(n, "report-") && strings.HasSuffix(n, ".zip") {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return "", nil, nil, ErrNoStoredReport
	}
	// The names carry a UTC timestamp of fixed width, so lexical order is
	// generation order.
	sort.Strings(names)
	latest := names[len(names)-1]
	f, err = os.Open(filepath.Join(s.reportsDir(caseID), latest))
	if err != nil {
		return "", nil, nil, fmt.Errorf("opening the stored report: %w", err)
	}
	info, err = f.Stat()
	if err != nil {
		f.Close()
		return "", nil, nil, fmt.Errorf("reading the stored report: %w", err)
	}
	return latest, f, info, nil
}

// ErrRequestCancelled is returned when the client went away while its request
// was queued for a slot.
var ErrRequestCancelled = errors.New("request cancelled while waiting")

// isCancelled reports whether err is a request that ended while queued.
func isCancelled(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
