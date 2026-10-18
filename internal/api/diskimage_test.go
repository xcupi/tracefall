package api

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
)

// These tests run the whole disk-image path against images written by
// independent tools (ewfacquire, sgdisk, mkntfs + ntfs-3g); see
// testdata/images/gen.py. The artifact files inside are the synthetic
// samples from testdata/native_samples.

const imageFixtures = "../../testdata/images"

type imageManifest struct {
	Images map[string]struct {
		MD5    string `json:"md5"`
		SHA1   string `json:"sha1"`
		SHA256 string `json:"sha256"`
	} `json:"images"`
	Volume struct {
		Files map[string]struct {
			SHA256 string `json:"sha256"`
		} `json:"files"`
	} `json:"volume"`
}

func loadImageManifest(t *testing.T) imageManifest {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(imageFixtures, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m imageManifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// rawFixture writes a gunzipped raw disk fixture to a temp file.
func rawFixture(t *testing.T, name string) string {
	t.Helper()
	f, err := os.Open(filepath.Join(imageFixtures, name+".dd.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), name+".dd")
	out, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	if _, err := io.Copy(out, z); err != nil {
		t.Fatal(err)
	}
	return p
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func newImageCase(t *testing.T) (*Service, model.Case) {
	t.Helper()
	svc := newTestService(t)
	c, err := svc.CreateCase("Disk image "+t.Name(), "")
	if err != nil {
		t.Fatal(err)
	}
	return svc, c
}

func catalogPaths(t *testing.T, svc *Service, collectionID string) map[string]model.SourceFile {
	t.Helper()
	files, err := svc.store.ListSourceFilesByCollection(collectionID)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]model.SourceFile{}
	for _, f := range files {
		out[f.Path] = f
	}
	return out
}

var wantImageArtifacts = []string{
	"vol1/Windows/System32/winevt/Logs/Security.evtx",
	"vol1/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx",
	"vol1/Windows/System32/config/SYSTEM",
	"vol1/Windows/System32/config/SOFTWARE",
	"vol1/Users/alice/NTUSER.DAT",
	"vol1/Windows/Prefetch/EDGE.EXE-11111111.pf",
	"vol1/Windows/Prefetch/UPDATE.EXE-0BADF00D.pf",
	"vol1/$MFT",
}

func TestDiskImage_E01CatalogsTheArtifactsInsideItsFileSystem(t *testing.T) {
	svc, c := newImageCase(t)
	m := loadImageManifest(t)
	e01 := filepath.Join(imageFixtures, "gpt.E01")
	res, err := svc.DiscoverEvidenceFromPath(c.ID, e01)
	if err != nil {
		t.Fatal(err)
	}
	col := res.Collection
	if col.SourceType != model.SourceTypeDiskImage || col.IngestionStatus != model.CollectionStatusPending {
		t.Fatalf("collection = %+v", col)
	}
	if col.ArchiveHash != fileSHA256(t, e01) {
		t.Errorf("the collection hash must be the SHA-256 of the container bytes as received")
	}
	files := catalogPaths(t, svc, col.ID)
	for _, p := range wantImageArtifacts {
		sf, ok := files[p]
		if !ok {
			t.Errorf("not cataloged: %s", p)
			continue
		}
		if !sf.Supported || sf.ImportStatus != model.SourceFileDiscovered || sf.Parser == "" {
			t.Errorf("%s: supported=%v status=%s parser=%q", p, sf.Supported, sf.ImportStatus, sf.Parser)
		}
	}
	if sf := files["vol1/Windows/System32/winevt/Logs/Security.evtx"]; sf.SizeBytes != 69632 {
		t.Errorf("evtx size = %d, want 69632", sf.SizeBytes)
	}
	for p := range files {
		if strings.HasPrefix(p, "vol2/") {
			t.Errorf("a file from the unformatted partition appeared: %s", p)
		}
	}
	// A plain data file is listed, so the analyst can see it, but it must
	// never be invented as evidence: it stays unsupported.
	sf, ok := files["vol1/big.bin"]
	if !ok {
		t.Error("a plain data file was dropped instead of listed as unsupported")
	} else if sf.Supported || sf.ImportStatus != model.SourceFileUnsupported {
		t.Errorf("a plain data file was catalogued as an artifact: supported=%v status=%s", sf.Supported, sf.ImportStatus)
	}
	_ = m
}

func TestDiskImage_RawAndE01ListTheSameEvidence(t *testing.T) {
	svc, c := newImageCase(t)
	a, err := svc.DiscoverEvidenceFromPath(c.ID, filepath.Join(imageFixtures, "gpt.E01"))
	if err != nil {
		t.Fatal(err)
	}
	svc2, c2 := newImageCase(t)
	b, err := svc2.DiscoverEvidenceFromPath(c2.ID, rawFixture(t, "gpt"))
	if err != nil {
		t.Fatal(err)
	}
	list := func(s *Service, id string) []string {
		var out []string
		for p, sf := range catalogPaths(t, s, id) {
			out = append(out, p+"|"+sf.Parser)
		}
		sort.Strings(out)
		return out
	}
	la, lb := list(svc, a.Collection.ID), list(svc2, b.Collection.ID)
	if strings.Join(la, "\n") != strings.Join(lb, "\n") || len(la) < len(wantImageArtifacts) {
		t.Errorf("E01 and raw disagree:\nE01: %v\nraw: %v", la, lb)
	}
}

func TestDiskImage_RecordsAcquisitionVerificationAndLayout(t *testing.T) {
	svc, c := newImageCase(t)
	m := loadImageManifest(t)
	res, err := svc.DiscoverEvidenceFromPath(c.ID, filepath.Join(imageFixtures, "gpt.E01"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(svc.files.DiskImageReportPath(c.ID, res.Collection.ID))
	if err != nil {
		t.Fatalf("no image report was written: %v", err)
	}
	var rep diskImageReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatal(err)
	}
	g := m.Images["gpt"]
	if rep.Format != "ewf" || rep.StoredMD5 != g.MD5 || rep.StoredSHA1 != g.SHA1 || rep.ComputedMD5 != g.MD5 || rep.ComputedSHA256 != g.SHA256 {
		t.Errorf("hashes = %+v", rep)
	}
	if rep.MD5Match == nil || !*rep.MD5Match || rep.SHA1Match == nil || !*rep.SHA1Match {
		t.Errorf("an intact image must verify against its stored hashes: %+v", rep)
	}
	if rep.Acquisition["examiner"] != "Fixture Examiner" || rep.Partitioning != "gpt" {
		t.Errorf("acquisition/partitioning = %+v / %s", rep.Acquisition, rep.Partitioning)
	}
	if len(rep.Partitions) != 2 || rep.Partitions[0].FS != "ntfs" || rep.Partitions[1].FS != "unknown" {
		t.Fatalf("partitions = %+v", rep.Partitions)
	}
	if len(rep.Volumes) != 1 || rep.Volumes[0].Prefix != "vol1" || rep.Volumes[0].Label != "TFIMG" || rep.Volumes[0].FilesInUse < 1200 || rep.Volumes[0].Deleted < 1 {
		t.Errorf("volumes = %+v", rep.Volumes)
	}
	joined := strings.Join(rep.Notes, " ")
	if !strings.Contains(joined, "partition 2") {
		t.Errorf("an unreadable partition must be reported, not skipped silently: notes = %v", rep.Notes)
	}
	var audited bool
	log, _ := svc.store.ListAuditLog(c.ID)
	for _, e := range log {
		if e.Action == model.AuditEvidenceDiscovered && strings.Contains(e.Summary, "disk image") && strings.Contains(e.Summary, "verified") {
			audited = true
		}
	}
	if !audited {
		t.Error("the discovery audit entry does not record the image verification result")
	}
}

func TestDiskImage_ImportExtractsParsesAndAnalyzesRealArtifacts(t *testing.T) {
	svc, c := newImageCase(t)
	res, err := svc.DiscoverEvidenceFromPath(c.ID, filepath.Join(imageFixtures, "gpt.E01"))
	if err != nil {
		t.Fatal(err)
	}
	col := res.Collection
	ids, err := svc.EvidenceFileIDs(c.ID, col.ID, EvidenceFilter{})
	if err != nil || len(ids) < len(wantImageArtifacts) {
		t.Fatalf("selectable ids = %d, err %v", len(ids), err)
	}
	imp, err := svc.ImportEvidence(c.ID, col.ID, ids)
	if err != nil {
		t.Fatal(err)
	}
	if len(imp.Imported) == 0 || imp.EventCount == 0 {
		t.Fatalf("import = imported %d events %d skipped %+v failures %+v", len(imp.Imported), imp.EventCount, imp.Skipped, imp.ParseFailures)
	}
	files := catalogPaths(t, svc, col.ID)
	sec := files["vol1/Windows/System32/winevt/Logs/Security.evtx"]
	if sec.ImportStatus != model.SourceFileImported || sec.EventCount == 0 {
		t.Errorf("Security.evtx = %+v", sec)
	}
	// The extracted copy must be byte-identical to what is inside the
	// NTFS volume, and Tracefall must have recorded its own hash.
	want := loadImageManifest(t).Volume.Files["/Windows/System32/winevt/Logs/Security.evtx"].SHA256
	if sec.SHA256 != want {
		t.Errorf("recorded sha256 %s, want %s (the file's hash inside the image)", sec.SHA256, want)
	}
	if got := fileSHA256(t, filepath.Join(col.EvidenceDirectory, filepath.FromSlash(sec.Path))); got != want {
		t.Errorf("extracted bytes hash %s, want %s", got, want)
	}
	sum, err := svc.AnalyzeCase(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Findings == nil {
		t.Error("analysis returned no findings list")
	}
	events, _ := svc.store.CountEvents(c.ID)
	if events == 0 {
		t.Error("no events after import")
	}
}

func TestDiskImage_UploadedRawImageIsRecognisedByContent(t *testing.T) {
	svc, c := newImageCase(t)
	raw, err := os.ReadFile(rawFixture(t, "mbr"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := svc.DiscoverEvidenceFromUpload(c.ID, bytes.NewReader(raw), "whatever.bin")
	if err != nil {
		t.Fatal(err)
	}
	if res.Collection.SourceType != model.SourceTypeDiskImage {
		t.Fatalf("source type = %s", res.Collection.SourceType)
	}
	h := sha256.Sum256(raw)
	if res.Collection.ArchiveHash != hex.EncodeToString(h[:]) {
		t.Error("the hash of an uploaded image must be of the uploaded bytes")
	}
	if _, ok := catalogPaths(t, svc, res.Collection.ID)["vol1/Windows/System32/winevt/Logs/Security.evtx"]; !ok {
		t.Error("an uploaded MBR image was not cataloged")
	}
	if _, err := os.Stat(svc.files.DiskImagePath(c.ID, res.Collection.ID)); err != nil {
		t.Errorf("the uploaded image is not stored: %v", err)
	}
	// Import works from the stored copy.
	ids, _ := svc.EvidenceFileIDs(c.ID, res.Collection.ID, EvidenceFilter{})
	imp, err := svc.ImportEvidence(c.ID, res.Collection.ID, ids)
	if err != nil || len(imp.Imported) == 0 {
		t.Errorf("import from an uploaded image: %v %+v", err, imp)
	}
}

func TestDiskImage_FirstSegmentAloneIsRefusedWithAnExplanation(t *testing.T) {
	svc, c := newImageCase(t)
	first, err := os.ReadFile(filepath.Join(imageFixtures, "gpt-store.E01"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.DiscoverEvidenceFromUpload(c.ID, bytes.NewReader(first), "gpt-store.E01")
	if !errors.Is(err, ErrInvalidDiskImage) {
		t.Fatalf("err = %v, want ErrInvalidDiskImage", err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "segment") {
		t.Errorf("the error does not say a segment is missing: %v", err)
	}
	if cols, _ := svc.store.ListCollections(c.ID); len(cols) != 0 {
		t.Error("a failed image upload left a collection behind")
	}
}

func TestDiskImage_ADamagedImageIsRefusedNotPartlyIngested(t *testing.T) {
	svc, c := newImageCase(t)
	b, _ := os.ReadFile(filepath.Join(imageFixtures, "gpt.E01"))
	b[len(b)/2] ^= 0x55
	p := filepath.Join(t.TempDir(), "damaged.E01")
	os.WriteFile(p, b, 0o644)
	_, err := svc.DiscoverEvidenceFromPath(c.ID, p)
	if !errors.Is(err, ErrInvalidDiskImage) {
		t.Fatalf("err = %v, want ErrInvalidDiskImage", err)
	}
	if cols, _ := svc.store.ListCollections(c.ID); len(cols) != 0 {
		t.Error("a damaged image left a collection behind")
	}
}

func TestDiskImage_DuplicateImageIsRefused(t *testing.T) {
	svc, c := newImageCase(t)
	e01 := filepath.Join(imageFixtures, "gpt.E01")
	if _, err := svc.DiscoverEvidenceFromPath(c.ID, e01); err != nil {
		t.Fatal(err)
	}
	var dup *DuplicateEvidenceError
	if _, err := svc.DiscoverEvidenceFromPath(c.ID, e01); !errors.As(err, &dup) {
		t.Errorf("second add of the same image: %v", err)
	}
}

func TestDiskImage_IntegrityCanBeReverifiedLater(t *testing.T) {
	svc, c := newImageCase(t)
	res, err := svc.DiscoverEvidenceFromPath(c.ID, filepath.Join(imageFixtures, "gpt.E01"))
	if err != nil {
		t.Fatal(err)
	}
	ir, err := svc.VerifyCollectionIntegrity(c.ID, res.Collection.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ir.Status != IntegrityVerified {
		t.Errorf("a freshly ingested image must re-verify: %+v", ir)
	}
}

func TestDiskImage_PipelineIngestsAnImageEndToEnd(t *testing.T) {
	svc, c := newImageCase(t)
	svc.pipe.poll = 10 * time.Millisecond
	startWorker(t, svc)
	mux := routerFor(svc)
	_, job := enqueue(t, mux, c.ID, map[string]any{"local_path": filepath.Join(imageFixtures, "gpt.E01")})
	done := waitPipelineJob(t, mux, c.ID, job.ID)
	if done.Status != model.JobSucceeded {
		t.Fatalf("job = %+v", done)
	}
	if num(done.Result, "files_imported") < len(wantImageArtifacts) || num(done.Result, "events") == 0 || done.Result["analyzed"] != true {
		t.Errorf("result = %+v", done.Result)
	}
}

func TestDiskImage_TheReportDescribesTheImage(t *testing.T) {
	svc, c := newImageCase(t)
	res, err := svc.DiscoverEvidenceFromPath(c.ID, filepath.Join(imageFixtures, "gpt.E01"))
	if err != nil {
		t.Fatal(err)
	}
	ids, _ := svc.EvidenceFileIDs(c.ID, res.Collection.ID, EvidenceFilter{})
	if _, err := svc.ImportEvidence(c.ID, res.Collection.ID, ids); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AnalyzeCase(c.ID); err != nil {
		t.Fatal(err)
	}
	html, _, err := svc.ReportHTML(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	s := string(html)
	for _, want := range []string{"Disk image", "CASE-0001", "Fixture Examiner", "TFIMG", "GPT"} {
		if !strings.Contains(s, want) {
			t.Errorf("the report does not mention %q", want)
		}
	}
}

func TestDiskImage_HTTPUploadOfAnIncompleteImageIs400WithTheReason(t *testing.T) {
	svc := newTestService(t)
	mux := routerFor(svc)
	c := mustCreateCase(t, mux, "http image")
	first, _ := os.ReadFile(filepath.Join(imageFixtures, "gpt-store.E01"))
	rec := uploadAD1(t, mux, c.ID, first, "gpt-store.E01") // generic multipart upload helper
	if rec.Code != 400 || !strings.Contains(strings.ToLower(rec.Body.String()), "segment") {
		t.Errorf("status %d body %s, want 400 naming the missing segment", rec.Code, rec.Body.String())
	}
}

func TestDiskImage_HTTPUploadOfAWholeImageIsCataloged(t *testing.T) {
	svc := newTestService(t)
	mux := routerFor(svc)
	c := mustCreateCase(t, mux, "http image ok")
	raw, _ := os.ReadFile(rawFixture(t, "gpt"))
	rec := uploadAD1(t, mux, c.ID, raw, "disk.dd")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"source_type":"disk_image"`) {
		t.Errorf("status %d body %.300s", rec.Code, rec.Body.String())
	}
}
