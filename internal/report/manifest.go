package report

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// ManifestSchema identifies the manifest format so a future reader can
// tell which rules to apply.
const ManifestSchema = "tracefall.report-manifest/1"

// ManifestName is the file name the manifest is delivered under.
const ManifestName = "manifest.json"

// Artifact is one hashed file.
type Artifact struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// EvidenceHash records the digests of one evidence collection.
type EvidenceHash struct {
	Label    string `json:"label"`
	Source   string `json:"source"`
	SHA256   string `json:"sha256"`
	SHA512   string `json:"sha512"`
	HashKind string `json:"hash_kind"`
}

// Manifest lists the report and every attachment with its SHA-256.
type Manifest struct {
	Schema        string         `json:"schema"`
	HashAlgorithm string         `json:"hash_algorithm"`
	CaseID        string         `json:"case_id"`
	CaseName      string         `json:"case_name"`
	ToolName      string         `json:"tool_name"`
	ToolVersion   string         `json:"tool_version"`
	GeneratedAt   string         `json:"generated_at"`
	Report        Artifact       `json:"report"`
	Attachments   []Artifact     `json:"attachments"`
	Evidence      []EvidenceHash `json:"evidence"`
	Notes         []string       `json:"notes"`
}

// File is one named file in a bundle. Its content is either in Data, or, for a
// large file already written to disk, in the file at Path. A spooled file
// carries its own digest and size (see SpooledFile), so the manifest does not
// read it twice.
type File struct {
	Name string
	Data []byte

	Path   string
	SHA256 string
	Size   int64
}

// NewFile holds a file's content in memory.
func NewFile(name string, data []byte) File {
	return File{Name: name, Data: data}
}

// SpooledFile names a file that is already on disk at path, with the digest
// and size its writer computed while writing it.
func SpooledFile(name, path, sha256hex string, size int64) File {
	return File{Name: name, Path: path, SHA256: sha256hex, Size: size}
}

// open returns the file's content. The caller closes it.
func (f File) open() (io.ReadCloser, error) {
	if f.Path == "" {
		return io.NopCloser(bytes.NewReader(f.Data)), nil
	}
	return os.Open(f.Path)
}

// contentDigest is the SHA-256 of a file's content, reading a spooled file
// from disk when it has no in-memory content.
func contentDigest(f File) (string, error) {
	if f.Path == "" {
		return sha256Hex(f.Data), nil
	}
	r, err := f.open()
	if err != nil {
		return "", err
	}
	defer r.Close()
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// SHA256Hex is the lowercase hex SHA-256 of b, the digest used throughout
// the manifest.
func SHA256Hex(b []byte) string { return sha256Hex(b) }

func artifactOf(f File) Artifact {
	if f.Path != "" {
		return Artifact{Name: f.Name, SHA256: f.SHA256, Bytes: f.Size}
	}
	return Artifact{Name: f.Name, SHA256: sha256Hex(f.Data), Bytes: int64(len(f.Data))}
}

// NewManifest builds the manifest for a rendered report and its
// attachments. Attachments are sorted by name so the manifest does not
// depend on the order the caller happened to build them in.
func NewManifest(d Data, reportName string, html []byte, attachments []File) Manifest {
	arts := make([]Artifact, 0, len(attachments))
	for _, a := range attachments {
		arts = append(arts, artifactOf(a))
	}
	sort.Slice(arts, func(i, j int) bool { return arts[i].Name < arts[j].Name })

	ev := make([]EvidenceHash, 0, len(d.Evidence))
	for _, e := range d.Evidence {
		ev = append(ev, EvidenceHash{
			Label: e.Label, Source: e.OriginalName, SHA256: e.SHA256, SHA512: e.SHA512, HashKind: e.HashKind,
		})
	}
	return Manifest{
		Schema:        ManifestSchema,
		HashAlgorithm: "SHA-256",
		CaseID:        d.Meta.CaseID,
		CaseName:      d.Meta.CaseName,
		ToolName:      d.Meta.ToolName,
		ToolVersion:   d.Meta.ToolVersion,
		GeneratedAt:   d.Meta.GeneratedAt,
		Report:        artifactOf(File{Name: reportName, Data: html}),
		Attachments:   arts,
		Evidence:      ev,
		Notes: []string{
			"SHA-256 digests of the files delivered in this bundle. The evidence digests are those recorded at ingestion.",
			"A manifest shows that files match this list. It is not a digital signature and does not identify who produced it.",
		},
	}
}

// JSON serializes the manifest in a fixed, indented form.
func (m Manifest) JSON() ([]byte, error) {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Mismatch is one file that does not match the manifest.
type Mismatch struct {
	Name   string
	Reason string
}

// Verify checks delivered files against a manifest's JSON. It returns
// every discrepancy: a file whose digest differs, a listed file that is
// absent, and a delivered file the manifest does not list. A manifest
// that cannot be read is an error, never a pass.
func Verify(manifestJSON []byte, files []File) ([]Mismatch, error) {
	var m Manifest
	if err := json.Unmarshal(manifestJSON, &m); err != nil {
		return nil, fmt.Errorf("report: manifest is not valid JSON: %w", err)
	}
	if m.Schema != ManifestSchema {
		return nil, fmt.Errorf("report: unsupported manifest schema %q", m.Schema)
	}
	if m.Report.Name == "" || m.Report.SHA256 == "" {
		return nil, errors.New("report: manifest does not describe a report")
	}

	want := map[string]string{m.Report.Name: m.Report.SHA256}
	for _, a := range m.Attachments {
		want[a.Name] = a.SHA256
	}
	have := map[string]string{}
	for _, f := range files {
		if f.Name == ManifestName {
			continue
		}
		sum, err := contentDigest(f)
		if err != nil {
			return nil, fmt.Errorf("report: reading %s: %w", f.Name, err)
		}
		have[f.Name] = sum
	}

	var out []Mismatch
	for name, sum := range want {
		got, ok := have[name]
		switch {
		case !ok:
			out = append(out, Mismatch{name, "listed in the manifest but not present"})
		case got != sum:
			out = append(out, Mismatch{name, "SHA-256 differs from the manifest"})
		}
	}
	for name := range have {
		if _, ok := want[name]; !ok {
			out = append(out, Mismatch{name, "present but not listed in the manifest"})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Bundle packs files into a ZIP in memory. See BundleTo.
func Bundle(generated time.Time, files []File) ([]byte, error) {
	var buf bytes.Buffer
	if err := BundleTo(&buf, generated, files); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// BundleTo writes a ZIP whose bytes depend only on its inputs: entries are
// ordered by name, every entry carries the report's generation time instead of
// the wall clock, and names are flat. Each file is copied from its content or
// from its spool file, so the bundle is not held in memory.
func BundleTo(w io.Writer, generated time.Time, files []File) error {
	sorted := append([]File(nil), files...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	zw := zip.NewWriter(w)
	for _, f := range sorted {
		if f.Name == "" || strings.ContainsAny(f.Name, `/\`) || strings.Contains(f.Name, "..") {
			return fmt.Errorf("report: unsafe bundle file name %q", f.Name)
		}
		entry, err := zw.CreateHeader(&zip.FileHeader{Name: f.Name, Method: zip.Deflate, Modified: generated.UTC()})
		if err != nil {
			return err
		}
		r, err := f.open()
		if err != nil {
			return err
		}
		_, err = io.Copy(entry, r)
		r.Close()
		if err != nil {
			return err
		}
	}
	return zw.Close()
}
