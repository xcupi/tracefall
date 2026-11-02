package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tracefall/internal/ingest"
	"tracefall/internal/model"
	"tracefall/internal/ntfs/mftgen"
	"tracefall/internal/report"
)

// mftShapedJournal is the layout of the diagnosed real failure built from
// neutral data: 1 KiB FILE records at a 2-byte shift where a journal should be.
func mftShapedJournal() []byte {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	table := mftgen.Build([]mftgen.File{
		{RecordNumber: 0, SequenceNumber: 1, InUse: true, SI: mftgen.Times{Created: at}, Names: []mftgen.Name{{Name: "a.txt", Namespace: 1, ParentRef: 5, ParentSeq: 1}}},
		{RecordNumber: 1, SequenceNumber: 1, InUse: true, SI: mftgen.Times{Created: at}, Names: []mftgen.Name{{Name: "b.txt", Namespace: 1, ParentRef: 5, ParentSeq: 1}}},
	})
	return append([]byte{2, 0}, table...)
}

func importOne(t *testing.T, name string, data []byte) (*Service, model.SourceFile, ImportResult) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ingest.SetParserRunner(ingest.Subprocess{Exe: exe, Sandbox: ingest.FindSandbox()})
	t.Cleanup(func() { ingest.SetParserRunner(nil) })
	svc := newTestService(t)
	c, err := svc.CreateCase("ntfs coverage", "")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, name), data, 0600); err != nil {
		t.Fatal(err)
	}
	d, err := svc.DiscoverEvidenceFromPath(c.ID, root)
	if err != nil {
		t.Fatal(err)
	}
	files, err := svc.store.ListSourceFilesByCollection(d.Collection.ID)
	if err != nil || len(files) == 0 {
		t.Fatalf("discovery: %v %d", err, len(files))
	}
	var sf model.SourceFile
	for _, f := range files {
		if f.Supported {
			sf = f
		}
	}
	if sf.ID == "" {
		t.Fatal("source not supported by discovery")
	}
	result, err := svc.ImportEvidence(c.ID, d.Collection.ID, []string{sf.ID})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := svc.store.GetSourceFile(sf.ID)
	if err != nil {
		t.Fatal(err)
	}
	return svc, stored, result
}

func TestNTFSFailedSourcePersistsItsCoverage(t *testing.T) {
	_, stored, result := importOne(t, "$J", mftShapedJournal())
	if len(result.ParseFailures) != 1 || stored.ImportStatus != model.SourceFileFailed || stored.EventCount != 0 {
		t.Fatalf("status=%s events=%d failures=%d", stored.ImportStatus, stored.EventCount, len(result.ParseFailures))
	}
	c := stored.ParseCoverage
	if c == nil || c.Ntfs == nil || !c.Ntfs.Failed || c.Ntfs.FailureClass != model.NtfsFailureNotAJournal || c.Ntfs.NonRecordBytes <= 0 {
		t.Fatalf("a failed NTFS source must keep its coverage: %+v", c)
	}
	if c.EmittedEvents == nil || *c.EmittedEvents != 0 {
		t.Fatalf("nothing was imported from a failed source: %+v", c.EmittedEvents)
	}
}

func TestNTFSFailedSourceIsInTheReportCoverageSection(t *testing.T) {
	_, stored, _ := importOne(t, "$J", mftShapedJournal())
	stored.Path = "vol/$Extend/$J"
	got := reportCoverage([]model.SourceFile{stored})
	if len(got.ParserDiagnostics) != 1 {
		t.Fatalf("failed source omitted from diagnostics: %+v", got.ParserDiagnostics)
	}
	text := got.ParserDiagnostics[0].Value
	for _, want := range []string{"FAILED", "this source produced no events", "not evidence of no activity", "not a USN change journal"} {
		if !strings.Contains(text, want) {
			t.Errorf("diagnostic lacks %q: %s", want, text)
		}
	}
	lim := strings.Join(reportLimitations(report.Data{}, reportInputs{sourceFiles: []model.SourceFile{stored}}), "\n")
	if !strings.Contains(lim, "this source produced no events") {
		t.Errorf("limitations omit the failed source: %s", lim)
	}
}

func TestReport_NTFSSourceWithoutRecordedDetailReadsNotRecorded(t *testing.T) {
	old := model.SourceFile{Path: "vol/$MFT", ArtifactType: model.ArtifactMFT, ImportStatus: model.SourceFileImported,
		ParseCoverage: &model.ParseCoverage{RecordsRead: 10, Mapped: 10}}
	got := reportCoverage([]model.SourceFile{old})
	if len(got.ParserDiagnostics) != 1 || !strings.Contains(got.ParserDiagnostics[0].Value, "NTFS coverage detail: not recorded") {
		t.Fatalf("old NTFS import must not read as complete: %+v", got.ParserDiagnostics)
	}
}

func TestReport_NTFSSourceShowsEveryReasonClass(t *testing.T) {
	ev := 40
	off := int64(1000)
	c := &model.ParseCoverage{EmittedEvents: &ev, RecordsRead: 12, Mapped: 8, Unmapped: 4, Ntfs: &model.NtfsCoverage{Source: model.NtfsSourceMFT, ZeroSlots: 3, FreeMapped: 2, UnmappedNonBase: 1, UnmappedNoName: 2, UnmappedNoTime: 1, NonRecordBytes: 9, FirstNonRecordOffset: &off}}
	got := reportCoverage([]model.SourceFile{{Path: "vol/$MFT", ArtifactType: model.ArtifactMFT, ImportStatus: model.SourceFileImported, ParseCoverage: c}})
	text := got.ParserDiagnostics[0].Value
	for _, want := range []string{"12 records read", "1 extension (non-base)", "2 without a file name", "3 empty slots", "2 mapped records are marked free", "first at offset 1000"} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q: %s", want, text)
		}
	}
}
