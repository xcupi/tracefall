package main

import (
	"archive/zip"
	"fmt"
	"io"

	"tracefall/internal/report"
)

// maxVerifyFileBytes bounds one file read from a bundle being verified,
// so a hostile archive cannot exhaust memory. A real report bundle is
// megabytes; the cap is generous and only protects the verifier.
const maxVerifyFileBytes = 1 << 30

// verifyReportCmd implements `tracefall verify-report <bundle.zip>`.
//
// It needs no database and no server: whoever receives a report bundle
// can check it against its own manifest. Exit codes distinguish the three
// outcomes an examiner must never confuse:
//
//	0  every file matches the manifest
//	1  at least one file does not match, is missing, or is not listed
//	2  the check could not be performed (bad arguments, unreadable or
//	   corrupt input) -- explicitly NOT a pass
func verifyReportCmd(args []string, out io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(out, "usage: tracefall verify-report <report-bundle.zip>")
		return 2
	}
	files, err := readBundle(args[0])
	if err != nil {
		fmt.Fprintln(out, "cannot verify:", err)
		return 2
	}
	var manifest []byte
	for _, f := range files {
		if f.Name == report.ManifestName {
			manifest = f.Data
		}
	}
	if manifest == nil {
		fmt.Fprintf(out, "cannot verify: the bundle has no %s\n", report.ManifestName)
		return 2
	}
	mismatches, err := report.Verify(manifest, files)
	if err != nil {
		fmt.Fprintln(out, "cannot verify:", err)
		return 2
	}
	if len(mismatches) > 0 {
		for _, m := range mismatches {
			fmt.Fprintf(out, "MISMATCH  %s: %s\n", m.Name, m.Reason)
		}
		fmt.Fprintln(out, "The bundle does NOT match its manifest.")
		return 1
	}
	fmt.Fprintf(out, "OK  %d file(s) match %s (SHA-256).\n", len(files)-1, report.ManifestName)
	fmt.Fprintln(out, "Note: a manifest shows the files are unchanged since it was made; it is not a signature.")
	return 0
}

func readBundle(path string) ([]report.File, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	var files []report.File
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", f.Name, err)
		}
		data, err := io.ReadAll(io.LimitReader(rc, maxVerifyFileBytes+1))
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", f.Name, err)
		}
		if len(data) > maxVerifyFileBytes {
			return nil, fmt.Errorf("%s is larger than the verifier will read", f.Name)
		}
		files = append(files, report.File{Name: f.Name, Data: data})
	}
	return files, nil
}
