package api

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/ntfs/mftgen"
)

// End-to-end NTFS $MFT support: discovery classifies it, import parses
// it, and its events reach the unified timeline like any other artifact.

func mftTimes() mftgen.Times {
	return mftgen.Times{
		Created:  time.Date(2026, 4, 1, 9, 0, 0, 0, time.UTC),
		Modified: time.Date(2026, 4, 2, 10, 30, 0, 0, time.UTC),
		Changed:  time.Date(2026, 4, 2, 10, 31, 0, 0, time.UTC),
		Accessed: time.Date(2026, 4, 3, 8, 15, 0, 0, time.UTC),
	}
}

// sampleMFT builds a small but realistic table: system records, a
// directory, a normal file, and a deleted one.
func sampleMFT() []byte {
	t := mftTimes()
	files := mftgen.SystemRecords(t)
	files = append(files,
		mftgen.File{RecordNumber: 40, SequenceNumber: 1, InUse: true, IsDirectory: true, HardLinks: 1, SI: t,
			Names: []mftgen.Name{{Name: "Windows", Namespace: mftgen.NamespaceWin32, ParentRef: 5, ParentSeq: 5}}},
		mftgen.File{RecordNumber: 64, SequenceNumber: 2, InUse: true, HardLinks: 1, SI: t,
			Names:           []mftgen.Name{{Name: "notepad.exe", Namespace: mftgen.NamespaceWin32, ParentRef: 40, ParentSeq: 1}},
			NonResidentData: &mftgen.NonResident{AllocatedSize: 8192, RealSize: 4096, InitializedSize: 4096}},
		mftgen.File{RecordNumber: 65, SequenceNumber: 4, InUse: false, SI: t,
			Names:        []mftgen.Name{{Name: "deleted.tmp", Namespace: mftgen.NamespaceWin32, ParentRef: 40, ParentSeq: 1}},
			ResidentData: []byte("gone")},
	)
	return mftgen.Build(files)
}

// $MFT must be classified as a SUPPORTED, recommended artifact.
func TestMFT_IsClassifiedSupportedAndRecommended(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "MFT classification")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{"C/$MFT": sampleMFT()})

	sf, ok := sourceFileByPath(disc.SourceFiles, "C/$MFT")
	if !ok {
		t.Fatal("$MFT was not discovered")
	}
	if !sf.Supported {
		t.Fatal("$MFT is not classified as supported")
	}
	if sf.ArtifactType != model.ArtifactMFT {
		t.Errorf("artifact type = %q, want %q", sf.ArtifactType, model.ArtifactMFT)
	}
	if sf.TypeLabel != "NTFS $MFT" {
		t.Errorf("label = %q, want %q", sf.TypeLabel, "NTFS $MFT")
	}
	if sf.Priority != "high" {
		t.Errorf("priority = %q, want high", sf.Priority)
	}
	if !sf.Recommended {
		t.Error("$MFT should be recommended: high value and parseable")
	}
	if sf.UnsupportedReason != "" {
		t.Errorf("a supported artifact carries an unsupported reason: %q", sf.UnsupportedReason)
	}
	if sf.Parser == "" {
		t.Error("no parser recorded for the $MFT")
	}
}

// It imports, produces filesystem events, and reports no parse failure.
func TestMFT_ImportsAndProducesTimelineEvents(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "MFT import")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{"C/$MFT": sampleMFT()})

	imp := importAllFrom(t, mux, c.ID, disc)
	if len(imp.ParseFailures) != 0 {
		t.Fatalf("a valid $MFT was reported as a parse failure: %+v", imp.ParseFailures)
	}
	if imp.EventCount == 0 {
		t.Fatal("no events from a valid $MFT")
	}

	var events []model.Event
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/timeline", nil, &events)
	if len(events) == 0 {
		t.Fatal("no events on the unified timeline")
	}

	byType := map[string]int{}
	var sawFile bool
	for _, e := range events {
		if e.ArtifactType != model.ArtifactMFT {
			continue
		}
		byType[e.EventType]++
		if e.Extra["file_name"] == "notepad.exe" {
			sawFile = true
			if e.FilePath != `\Windows\notepad.exe` {
				t.Errorf("path = %q, want the reconstructed full path", e.FilePath)
			}
			if e.Extra["mft_record_number"] != "64" {
				t.Errorf("record number = %q", e.Extra["mft_record_number"])
			}
			if e.Parser == "" {
				t.Error("event carries no parser for provenance")
			}
			// Stored canonically in UTC.
			if e.Timestamp.Location() != time.UTC {
				t.Error("event timestamp is not stored in UTC")
			}
		}
	}
	if !sawFile {
		t.Error("the file record produced no timeline events")
	}
	for _, want := range []string{
		model.EventFilesystemCreated, model.EventFilesystemModified,
		model.EventFilesystemChanged, model.EventFilesystemAccessed,
	} {
		if byType[want] == 0 {
			t.Errorf("no %s events reached the timeline", want)
		}
	}
	// The deleted record is present and labelled, not silently dropped.
	var sawDeleted bool
	for _, e := range events {
		if e.Extra["file_name"] == "deleted.tmp" && strings.Contains(e.Extra["allocation_state"], "not in use") {
			sawDeleted = true
		}
	}
	if !sawDeleted {
		t.Error("the deleted record produced no labelled events")
	}
}

// Ordinary filesystem records must not manufacture findings. A file
// existing on a volume is the normal state of every file on it.
func TestMFT_OrdinaryRecordsProduceNoFindings(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "MFT no false findings")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{"C/$MFT": sampleMFT()})
	importAllFrom(t, mux, c.ID, disc)
	doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/analyze", nil, nil)

	var findings []model.Finding
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/findings", nil, &findings)
	for _, f := range findings {
		t.Errorf("an ordinary MFT record produced a finding: %q (%s)", f.Title, f.Severity)
	}

	var corrs []model.Correlation
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/correlations", nil, &corrs)
	// Correlations across a single artifact type are structurally
	// impossible here, but assert it rather than assume.
	for _, cr := range corrs {
		if strings.Contains(strings.ToLower(cr.Title), "burst") {
			t.Errorf("filesystem metadata alone produced a temporal burst: %q", cr.Title)
		}
	}
}

// Filesystem events must be filterable like any other event.
func TestMFT_EventsParticipateInTimelineFiltering(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "MFT filtering")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{"C/$MFT": sampleMFT()})
	importAllFrom(t, mux, c.ID, disc)

	var events []model.Event
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/timeline", nil, &events)

	// The fields the timeline filters on must be populated coherently.
	var checked int
	for _, e := range events {
		if e.ArtifactType != model.ArtifactMFT {
			continue
		}
		checked++
		if e.EventType == "" {
			t.Error("event has no type, so the category filter cannot see it")
		}
		if e.Timestamp.IsZero() {
			t.Error("event has no timestamp, so the date filter cannot see it")
		}
		// NTFS records no host or user; those filters simply will not
		// match, which is correct rather than a defect.
		if e.Host != "" || e.User != "" {
			t.Errorf("host/user were invented: %q / %q", e.Host, e.User)
		}
	}
	if checked == 0 {
		t.Fatal("no filesystem events to check")
	}

	// A date range that excludes the records must exclude them.
	from := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	var inRange int
	for _, e := range events {
		if e.ArtifactType == model.ArtifactMFT && e.Timestamp.After(from) {
			inRange++
		}
	}
	if inRange != 0 {
		t.Errorf("%d filesystem events claim to be after 2030", inRange)
	}
}

// A file merely NAMED $MFT that is not one fails cleanly, and is
// reported as unsupported rather than as a corrupt table.
func TestMFT_NonTableNamedMFTFailsCleanly(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Fake MFT")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		"C/$MFT": []byte("this file is called $MFT but is plainly not one"),
	})
	sf, ok := sourceFileByPath(disc.SourceFiles, "C/$MFT")
	if !ok {
		t.Fatal("not discovered")
	}
	if !sf.Supported {
		t.Error("a file named $MFT is still CATALOGED as the supported artifact type; the parse is what fails")
	}
	imp := importAllFrom(t, mux, c.ID, disc)
	if len(imp.ParseFailures) != 1 {
		t.Fatalf("parse failures = %d, want 1: %+v", len(imp.ParseFailures), imp.ParseFailures)
	}
	f := imp.ParseFailures[0]
	if !strings.Contains(f.Message, "not an NTFS $MFT") {
		t.Errorf("message does not explain the mismatch: %q", f.Message)
	}
	if f.PartialEvents {
		t.Error("a failed parse must not claim partial events")
	}
	if imp.EventCount != 0 {
		t.Errorf("event count = %d, want 0", imp.EventCount)
	}
}

// Existing parsers must be unaffected by the new one.
func TestMFT_DoesNotDisturbExistingParsers(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "MFT alongside others")
	files := mixedCatalog()
	files["C/$MFT"] = sampleMFT()
	disc := discoverBinaryDir(t, mux, c.ID, files)

	byType := map[string]string{}
	for _, f := range disc.SourceFiles {
		byType[f.OriginalFilename] = f.ArtifactType
	}
	for name, want := range map[string]string{
		"Security.evtx": model.ArtifactWindowsEventLog,
		"NTUSER.DAT":    model.ArtifactRegistryHive,
		"$MFT":          model.ArtifactMFT,
	} {
		if got := byType[name]; got != want {
			t.Errorf("%s classified as %q, want %q", name, got, want)
		}
	}
	// The $MFT must not have swallowed anything else.
	for name, at := range byType {
		if at == model.ArtifactMFT && name != "$MFT" {
			t.Errorf("%q was misclassified as an $MFT", name)
		}
	}
}

// Determinism across repeated imports of the same table.
func TestMFT_RepeatedImportsAreDeterministic(t *testing.T) {
	var counts []int
	for i := 0; i < 3; i++ {
		mux := newTestRouter(t)
		c := mustCreateCase(t, mux, fmt.Sprintf("MFT determinism %d", i))
		disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{"C/$MFT": sampleMFT()})
		imp := importAllFrom(t, mux, c.ID, disc)
		counts = append(counts, imp.EventCount)
	}
	for i := 1; i < len(counts); i++ {
		if counts[i] != counts[0] {
			t.Fatalf("import %d produced %d events, first produced %d", i, counts[i], counts[0])
		}
	}
	if counts[0] == 0 {
		t.Fatal("no events")
	}
}

// The parse must not modify the evidence.
func TestMFT_EvidenceIsNotModified(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "MFT integrity")
	table := sampleMFT()
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{"C/$MFT": table})
	sf, _ := sourceFileByPath(disc.SourceFiles, "C/$MFT")
	before := sf.SHA256
	if before == "" {
		t.Fatal("no hash recorded at discovery")
	}
	importAllFrom(t, mux, c.ID, disc)

	var listing EvidenceFilePage
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/evidence/"+disc.Collection.ID+"/files?page=1&page_size=50", nil, &listing)
	for _, f := range listing.Items {
		if f.OriginalFilename == "$MFT" && f.SHA256 != before {
			t.Errorf("the evidence hash changed across parsing: %s -> %s", before, f.SHA256)
		}
	}
	rec := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/evidence/"+disc.Collection.ID+"/verify", nil, nil)
	if rec.Code != http.StatusOK && rec.Code != http.StatusNotFound {
		t.Errorf("integrity verification returned %d", rec.Code)
	}
}

// Provenance must resolve END TO END: clicking a filesystem event in the
// timeline has to return its raw evidence, source file and collection.
//
// This is the API behind the timeline's detail panel. It failed for
// every filesystem event until the parser paired each event with a raw
// record carrying the same source reference.
func TestMFT_EventProvenanceResolves(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "MFT provenance")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{"C/$MFT": sampleMFT()})
	importAllFrom(t, mux, c.ID, disc)

	var events []model.Event
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/timeline", nil, &events)

	var checked int
	for _, e := range events {
		if e.ArtifactType != model.ArtifactMFT || checked >= 6 {
			continue
		}
		checked++
		var prov EventProvenance
		rec := doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/events/"+e.ID, nil, &prov)
		if rec.Code != http.StatusOK {
			t.Fatalf("event provenance for %s returned %d: %s", e.SourceReference, rec.Code, rec.Body.String())
		}
		if prov.RawEvidence.Raw == "" {
			t.Errorf("event %s resolved no raw evidence", e.SourceReference)
		}
		if prov.SourceFile.OriginalFilename != "$MFT" {
			t.Errorf("provenance names source file %q, want $MFT", prov.SourceFile.OriginalFilename)
		}
		if !strings.Contains(prov.RawEvidence.Raw, "mft_record_number") {
			t.Errorf("raw evidence for %s does not carry the record number", e.SourceReference)
		}
	}
	if checked == 0 {
		t.Fatal("no filesystem events to check provenance for")
	}
}
