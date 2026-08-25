// Package archive safely extracts untrusted ZIP archives to a
// destination directory. It has no knowledge of Tracefall's domain
// (cases, KAPE, evidence) -- it is a generic, defense-in-depth "extract
// an untrusted zip" primitive, kept separate so it can be reasoned about
// and tested in complete isolation from the ingestion pipeline.
//
// Every entry is validated before anything is written to disk:
//
//   - path traversal ("../", Zip Slip) and absolute paths (both
//     Unix-style "/..." and Windows-style "C:\...") are rejected
//   - symlink entries are rejected outright, never followed or recreated
//   - the resolved destination path is additionally verified to remain
//     inside destDir after joining, as a second, independent check
//     beyond the string-level validation above
//   - a corrupt/non-zip input, too many entries, a single entry too
//     large, the total extracted size too large, or an entry whose
//     compression ratio is implausible (a classic zip-bomb signature)
//     all abort the whole extraction
//
// Any rejection aborts the entire extraction (fail closed) rather than
// silently skipping the offending entry -- a crafted archive is treated
// as malicious as a whole, not partially trusted. Extracted files are
// always written with fixed, non-executable permissions, ignoring
// whatever mode bits the archive itself declared, and nothing extracted
// is ever executed by Tracefall.
package archive

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// Sentinel error categories. Wrap these with fmt.Errorf's %w so callers
// can classify a failure (e.g. to choose an HTTP status) with errors.Is
// while still getting a specific, descriptive message.
var (
	// ErrUnsafeEntry means the archive contains an entry that would
	// escape the destination directory, use an absolute path, or is a
	// symlink.
	ErrUnsafeEntry = errors.New("archive contains an unsafe entry")
	// ErrLimitExceeded means the archive (or one of its entries) exceeds
	// a configured extraction limit -- a zip-bomb/DoS defense.
	ErrLimitExceeded = errors.New("archive exceeds extraction limits")
	// ErrInvalidArchive means the input isn't a well-formed zip file at
	// all (wrong format, truncated, corrupt central directory, ...).
	ErrInvalidArchive = errors.New("not a valid zip archive")
)

// Limits bounds resource usage during extraction. All fields are
// required to be positive; use DefaultLimits for sane production values,
// or construct a small Limits in tests to exercise rejection paths
// cheaply without generating multi-gigabyte fixtures.
type Limits struct {
	MaxFiles      int     // maximum number of entries (files + directories)
	MaxFileBytes  int64   // maximum uncompressed size of any single file
	MaxTotalBytes int64   // maximum total uncompressed size across all files
	MaxRatio      float64 // maximum uncompressed:compressed ratio for files over RatioMinBytes
	RatioMinBytes int64   // only enforce MaxRatio for files at least this large (avoids false positives on tiny well-compressed files)
}

// DefaultLimits are conservative but generous enough for a real KAPE
// collection (which can contain hundreds of thousands of small
// artifact files plus some large raw ones).
var DefaultLimits = Limits{
	MaxFiles:      200_000,
	MaxFileBytes:  1 << 30, // 1 GiB
	MaxTotalBytes: 8 << 30, // 8 GiB
	MaxRatio:      300,
	RatioMinBytes: 10 << 20, // 10 MiB
}

// Result summarizes a successful extraction.
type Result struct {
	FilesExtracted int   // regular files written (directories not counted)
	TotalBytes     int64 // total uncompressed bytes written
}

// ExtractFile opens zipPath (a file already on local disk -- the zip
// format requires random access to read the central directory at the
// end of the file, so a pure streaming io.Reader isn't sufficient) and
// extracts it into destDir. This is the entry point most callers want;
// Extract is exposed separately for tests that build an in-memory
// *zip.Reader without touching disk.
func ExtractFile(zipPath, destDir string, limits Limits) (Result, error) {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrInvalidArchive, err)
	}
	defer r.Close()
	return Extract(&r.Reader, destDir, limits)
}

// Extract validates and extracts every entry in zr into destDir, which
// must already exist. On any error, partially extracted files may exist
// under destDir -- callers that need a clean slate on failure (as
// internal/casefiles does) are responsible for removing destDir
// themselves; this package does not delete anything, so it stays
// side-effect-predictable and easy to test.
func Extract(zr *zip.Reader, destDir string, limits Limits) (Result, error) {
	if len(zr.File) > limits.MaxFiles {
		return Result{}, fmt.Errorf("%w: archive contains %d entries, limit is %d", ErrLimitExceeded, len(zr.File), limits.MaxFiles)
	}

	destAbs, err := filepath.Abs(destDir)
	if err != nil {
		return Result{}, fmt.Errorf("resolving destination directory: %w", err)
	}

	var res Result
	for _, f := range zr.File {
		target, err := safeJoin(destAbs, f.Name)
		if err != nil {
			return Result{}, fmt.Errorf("%w: %s: %v", ErrUnsafeEntry, f.Name, err)
		}

		if isSymlink(f) {
			return Result{}, fmt.Errorf("%w: %s: symlink entries are not permitted", ErrUnsafeEntry, f.Name)
		}

		if strings.HasSuffix(f.Name, "/") || f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return Result{}, fmt.Errorf("creating directory %s: %w", f.Name, err)
			}
			continue
		}

		if f.UncompressedSize64 > uint64(limits.MaxFileBytes) {
			return Result{}, fmt.Errorf("%w: %s: declared uncompressed size %d exceeds per-file limit %d",
				ErrLimitExceeded, f.Name, f.UncompressedSize64, limits.MaxFileBytes)
		}
		if ratioSuspicious(f, limits) {
			return Result{}, fmt.Errorf("%w: %s: compression ratio too high (possible zip bomb)", ErrLimitExceeded, f.Name)
		}

		n, err := extractFile(f, target, limits.MaxFileBytes)
		if err != nil {
			return Result{}, err
		}

		res.TotalBytes += n
		if res.TotalBytes > limits.MaxTotalBytes {
			return Result{}, fmt.Errorf("%w: total extracted size exceeds limit %d bytes", ErrLimitExceeded, limits.MaxTotalBytes)
		}
		res.FilesExtracted++
	}

	return res, nil
}

// driveLetterRe matches a Windows-style absolute path prefix, e.g. "C:\"
// or "c:/" -- these can appear in archives built from a Windows KAPE
// collection folder.
var driveLetterRe = regexp.MustCompile(`^[A-Za-z]:[\\/]`)

// safeJoin validates a zip entry's name and returns its extraction path
// under destAbs, or an error if the name is absolute, attempts path
// traversal, or (as a second, independent check after string validation)
// would resolve outside destAbs.
func safeJoin(destAbs, name string) (string, error) {
	if name == "" {
		return "", errors.New("empty entry name")
	}
	norm := strings.ReplaceAll(name, `\`, "/")
	if strings.HasPrefix(norm, "/") {
		return "", errors.New("absolute path")
	}
	if driveLetterRe.MatchString(norm) {
		return "", errors.New("absolute path")
	}

	cleaned := path.Clean(norm)
	if cleaned == "." {
		return "", errors.New("invalid entry name")
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", errors.New("path traversal (..)")
	}

	target := filepath.Join(destAbs, filepath.FromSlash(cleaned))

	// Belt-and-suspenders: independently verify the resolved path is
	// still inside destAbs, in case any of the string-level checks above
	// missed an edge case (e.g. platform-specific path semantics).
	rel, err := filepath.Rel(destAbs, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("resolved outside destination directory")
	}

	return target, nil
}

// isSymlink reports whether a zip entry's stored Unix mode bits mark it
// as a symbolic link. Archives built on Windows never set this bit, so
// this only matters for archives built on Unix-like systems -- but since
// Tracefall runs on operator machines of unknown OS, it's checked
// unconditionally.
func isSymlink(f *zip.File) bool {
	return f.Mode()&os.ModeSymlink != 0
}

// ratioSuspicious flags a file whose declared compression ratio is
// implausibly high for its size -- one signature of a zip bomb (a small
// compressed input that decompresses to an enormous output). Small files
// are exempt: many legitimately compress well (e.g. a mostly-whitespace
// XML file), and the absolute size is already bounded by MaxFileBytes.
func ratioSuspicious(f *zip.File, limits Limits) bool {
	if f.UncompressedSize64 < uint64(limits.RatioMinBytes) {
		return false
	}
	compressed := f.CompressedSize64
	if compressed == 0 {
		compressed = 1
	}
	ratio := float64(f.UncompressedSize64) / float64(compressed)
	return ratio > limits.MaxRatio
}

// extractFile writes one zip entry to target, capping the bytes actually
// read from the decompressor at maxBytes+1 -- this defends against a
// zip entry whose header lies about its own uncompressed size, which a
// check against f.UncompressedSize64 alone would not catch.
func extractFile(f *zip.File, target string, maxBytes int64) (int64, error) {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return 0, fmt.Errorf("creating parent directory for %s: %w", f.Name, err)
	}

	rc, err := f.Open()
	if err != nil {
		return 0, fmt.Errorf("opening archive entry %s: %w", f.Name, err)
	}
	defer rc.Close()

	// 0o644: never carry over the archive's own mode bits (which could
	// mark a file executable); extracted evidence is never executable.
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, fmt.Errorf("creating %s: %w", f.Name, err)
	}
	defer out.Close()

	n, err := io.Copy(out, io.LimitReader(rc, maxBytes+1))
	if err != nil {
		return n, fmt.Errorf("extracting %s: %w", f.Name, err)
	}
	if n > maxBytes {
		return n, fmt.Errorf("%w: %s: actual decompressed size exceeds per-file limit %d (declared size was inaccurate)",
			ErrLimitExceeded, f.Name, maxBytes)
	}
	return n, nil
}
