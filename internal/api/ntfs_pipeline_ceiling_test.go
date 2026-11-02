package api

import (
	"archive/zip"
	"bytes"
	"os"
	"testing"
	"time"

	"tracefall/internal/ingest"
	"tracefall/internal/model"
	"tracefall/internal/ntfs/mftgen"
	"tracefall/internal/parsers/mft"
	"tracefall/internal/parsers/usnjrnl"
)

// A KAPE-style ZIP holding $MFT and $Extend/$J goes through the real pipeline
// (upload, discovery, isolated worker, bounded stream, staging, persistence).
// Neither source stops at the legacy Parse event ceiling: the MFT emits more
// than mft.DefaultMaxEvents and the journal more than usnjrnl.DefaultMaxEvents,
// and the stored coverage says nothing was capped. Neutral, generated data.
func TestNTFSTriageUploadIsNotCappedAtTheLegacyCeilings(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a ~70 MB fixture")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ingest.SetParserRunner(ingest.Subprocess{Exe: exe, Sandbox: ingest.FindSandbox()})
	defer ingest.SetParserRunner(nil)

	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	times := mftgen.Times{Created: at, Modified: at.Add(time.Second), Changed: at.Add(2 * time.Second), Accessed: at.Add(3 * time.Second)}
	const mftRecords = mft.DefaultMaxEvents/4 + 1 // > 200,000 events
	files := make([]mftgen.File, 0, mftRecords)
	for i := 0; i < mftRecords; i++ {
		files = append(files, mftgen.File{RecordNumber: uint64(i), SequenceNumber: 1, InUse: i%7 != 0, SI: times, Names: []mftgen.Name{{Name: "f.txt", Namespace: 1, ParentRef: 5, ParentSeq: 1}}})
	}
	const usnRecords = usnjrnl.DefaultMaxEvents + 100 // > 300,000 events
	var journal []byte
	for i := 0; i < usnRecords; i++ {
		journal = append(journal, mftgen.BuildUsnRecord(mftgen.UsnEntry{FileRecord: 64, FileSequence: 1, ParentRecord: 5, ParentSeq: 1, Usn: uint64(i + 1), Timestamp: at, Reason: mftgen.ReasonFileCreate, FileName: "same.txt"})...)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range map[string][]byte{"C/$MFT": mftgen.Build(files), "C/$Extend/$J": journal} {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	svc := newTestService(t)
	c, err := svc.CreateCase("ntfs ceilings", "")
	if err != nil {
		t.Fatal(err)
	}
	d, err := svc.DiscoverEvidenceFromUpload(c.ID, bytes.NewReader(buf.Bytes()), "triage.zip")
	if err != nil {
		t.Fatal(err)
	}
	list, err := svc.store.ListSourceFilesByCollection(d.Collection.ID)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, sf := range list {
		if sf.Supported {
			ids = append(ids, sf.ID)
		}
	}
	if len(ids) != 2 {
		t.Fatalf("both NTFS sources must be discovered in the KAPE layout, got %d", len(ids))
	}
	result, err := svc.ImportEvidence(c.ID, d.Collection.ID, ids)
	if err != nil {
		t.Fatal(err)
	}
	wantMFT, wantUSN := mftRecords*4, usnRecords
	if len(result.ParseFailures) != 0 || result.EventCount != wantMFT+wantUSN {
		t.Fatalf("events=%d want %d failures=%+v", result.EventCount, wantMFT+wantUSN, result.ParseFailures)
	}
	seen := map[string]bool{}
	for _, id := range ids {
		sf, err := svc.store.GetSourceFile(id)
		if err != nil {
			t.Fatal(err)
		}
		cov := sf.ParseCoverage
		want := wantUSN
		if sf.ArtifactType == model.ArtifactMFT {
			want = wantMFT
			if cov == nil || cov.Ntfs == nil || cov.Ntfs.FreeMapped == 0 {
				t.Fatalf("free records must be counted: %+v", cov)
			}
		}
		if sf.EventCount != want || cov == nil || cov.LimitReached || cov.Ntfs == nil || cov.Ntfs.Failed {
			t.Fatalf("%s: events=%d want %d cov=%+v", sf.ArtifactType, sf.EventCount, want, cov)
		}
		seen[sf.ArtifactType] = true
	}
	if !seen[model.ArtifactMFT] || !seen[model.ArtifactUsnJournal] {
		t.Fatalf("both sources must be imported: %v", seen)
	}
}
