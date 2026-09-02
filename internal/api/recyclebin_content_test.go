package api

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/recyclebin/rbgen"
)

// End-to-end Recycle Bin $R (recovered content) ingestion.
//
// The pair is two files answering two questions. The $I says WHAT was
// deleted and WHEN; the $R holds WHAT IT WAS. They must reach an analyst
// as two distinct artifacts whose facts are attributed to the file each
// came from -- never merged, and never with the $R's own filename
// standing in for the deleted file's name.

var rbContentDeleted = time.Date(2026, 5, 21, 14, 32, 8, 0, time.UTC)

const rbDir = `C/$Recycle.Bin/S-1-5-21-1004336348-1177238915-682003330-1001/`

func iRecord(path string, size uint64, at time.Time) []byte {
	return rbgen.Build(rbgen.Record{Version: 2, Size: size, Deleted: at, Path: path})
}

// rbPairCatalog holds every pairing outcome at once.
func rbPairCatalog() (map[string][]byte, []byte) {
	body := []byte("the contents of a deliberately deleted document")
	return map[string][]byte{
		// A complete, consistent pair.
		rbDir + "$IA1B2C3.docx": iRecord(`C:\Users\jdoe\Documents\confidential-plan.docx`, uint64(len(body)), rbContentDeleted),
		rbDir + "$RA1B2C3.docx": body,
		// $I with no $R: metadata only.
		rbDir + "$IB2C3D4.xlsx": iRecord(`C:\Users\jdoe\Desktop\salaries.xlsx`, 65536, rbContentDeleted.Add(time.Minute)),
		// $R with no $I: an orphan.
		rbDir + "$RC3D4E5.exe": []byte("orphaned deleted content"),
		// A pair whose sizes disagree.
		rbDir + "$ID4E5F6.bin": iRecord(`C:\Windows\Temp\payload.bin`, 999999, rbContentDeleted.Add(2*time.Minute)),
		rbDir + "$RD4E5F6.bin": []byte("much smaller than the record claims"),
		// A $R whose $I is present but is not a record.
		rbDir + "$IE5F6A7.txt": []byte("this file is not a metadata record at all"),
		rbDir + "$RE5F6A7.txt": []byte("content whose identity cannot be recovered"),
	}, body
}

// 1. Both halves are supported, and each is its own artifact type.
func TestRBContent_BothHalvesAreDistinctSupportedArtifacts(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Recycle Bin pair classification")
	files, _ := rbPairCatalog()
	disc := discoverBinaryDir(t, mux, c.ID, files)

	want := map[string]struct{ artifact, label string }{
		rbDir + "$IA1B2C3.docx": {model.ArtifactRecycleBin, "Windows Recycle Bin $I metadata"},
		rbDir + "$RA1B2C3.docx": {model.ArtifactRecycleBinContent, "Recycle Bin recovered content ($R)"},
		rbDir + "$RC3D4E5.exe":  {model.ArtifactRecycleBinContent, "Recycle Bin recovered content ($R)"},
		rbDir + "$RE5F6A7.txt":  {model.ArtifactRecycleBinContent, "Recycle Bin recovered content ($R)"},
	}
	for path, w := range want {
		sf, ok := sourceFileByPath(disc.SourceFiles, path)
		if !ok {
			t.Errorf("%s was not discovered", path)
			continue
		}
		if !sf.Supported {
			t.Errorf("%s is not supported: %s", path, sf.UnsupportedReason)
			continue
		}
		if sf.ArtifactType != w.artifact {
			t.Errorf("%s artifact type = %q, want %q", path, sf.ArtifactType, w.artifact)
		}
		if sf.TypeLabel != w.label {
			t.Errorf("%s label = %q, want %q", path, sf.TypeLabel, w.label)
		}
	}
	// The two halves must never share a label -- that is the whole point
	// of separating them.
	iFile, _ := sourceFileByPath(disc.SourceFiles, rbDir+"$IA1B2C3.docx")
	rFile, _ := sourceFileByPath(disc.SourceFiles, rbDir+"$RA1B2C3.docx")
	if iFile.TypeLabel == rFile.TypeLabel {
		t.Errorf("both halves of the pair are labelled %q", iFile.TypeLabel)
	}
	if rFile.Priority != "medium" {
		t.Errorf("$R priority = %q, want medium", rFile.Priority)
	}
	if !strings.Contains(rFile.Note, "paired $I record") {
		t.Errorf("the $R row does not say where its metadata comes from: %q", rFile.Note)
	}
}

//  2. A valid pair imports: the $I contributes the deletion event, the
//     $R contributes recovered content and no event.
func TestRBContent_ValidPairImportsAsMetadataPlusContent(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Valid pair import")
	body := []byte("recoverable bytes")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		rbDir + "$IA1B2C3.docx": iRecord(`C:\Users\jdoe\Documents\plan.docx`, uint64(len(body)), rbContentDeleted),
		rbDir + "$RA1B2C3.docx": body,
	})
	imp := importAllFrom(t, mux, c.ID, disc)
	if len(imp.ParseFailures) != 0 {
		t.Fatalf("parse failures: %+v", imp.ParseFailures)
	}
	if len(imp.Imported) != 2 {
		t.Fatalf("imported %d files, want both halves", len(imp.Imported))
	}

	// Exactly one timeline event: the deletion, from the $I record. The
	// $R must not put a second row at the same moment.
	events := typedTimeline(t, mux, c.ID)
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1 -- the deletion is timestamped once, by the $I record", len(events))
	}
	if events[0].EventType != model.EventRecycleBinDeletion {
		t.Errorf("event type = %q", events[0].EventType)
	}
	if events[0].ArtifactType != model.ArtifactRecycleBin {
		t.Errorf("the deletion event came from %q, not the $I record", events[0].ArtifactType)
	}

	// And the $R produced a record with the measured content.
	var contentRaw string
	for _, sf := range imp.Imported {
		if sf.ArtifactType != model.ArtifactRecycleBinContent {
			continue
		}
		if sf.EventCount != 0 {
			t.Errorf("the $R file produced %d events", sf.EventCount)
		}
		var prov SourceFileProvenance
		doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/sources/"+sf.ID+"/provenance", nil, &prov)
		if prov.SourceFile.Parser != "recyclebincontent@1" {
			t.Errorf("parser = %q", prov.SourceFile.Parser)
		}
		// The evidence model's own hash of the collected file.
		if prov.SourceFile.SHA256 == "" {
			t.Error("the recovered content carries no evidence hash")
		}
		want := sha256.Sum256(body)
		if prov.SourceFile.SHA256 != hex.EncodeToString(want[:]) {
			t.Errorf("the collected file's hash does not match its content: %s", prov.SourceFile.SHA256)
		}
		contentRaw = sf.ID
	}
	if contentRaw == "" {
		t.Fatal("no recovered-content file was imported")
	}
}

//  3. The recovered record carries the original path, deletion time and
//     size from the $I -- each attributed to it -- plus its own hash.
func TestRBContent_MetadataIsPropagatedAndAttributed(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Metadata propagation")
	body := []byte("the contents of a deliberately deleted document")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		rbDir + "$IA1B2C3.docx": iRecord(`C:\Users\jdoe\Documents\confidential-plan.docx`, uint64(len(body)), rbContentDeleted),
		rbDir + "$RA1B2C3.docx": body,
	})
	importAllFrom(t, mux, c.ID, disc)

	raw := contentRecordFor(t, mux, c.ID, "$RA1B2C3.docx")
	digest := sha256.Sum256(body)
	for _, want := range []string{
		`"pairing_status":"resolved"`,
		`"paired_i_file":"$IA1B2C3.docx"`,
		`"original_path":"C:\\Users\\jdoe\\Documents\\confidential-plan.docx"`,
		`"original_name":"confidential-plan.docx"`,
		`"deletion_time":"2026-05-21T14:32:08Z"`,
		`"source":"$IA1B2C3.docx"`,
		`"measured_from":"$RA1B2C3.docx"`,
		`"sha256":"` + hex.EncodeToString(digest[:]) + `"`,
		`"size_matches_record":true`,
		`"recycle_bin_sid":"S-1-5-21-1004336348-1177238915-682003330-1001"`,
	} {
		if !strings.Contains(raw, want) {
			t.Errorf("the recovered-content record omits %s:\n%s", want, raw)
		}
	}
	// The $R filename must never be presented as the original name.
	if strings.Contains(raw, `"original_name":"$RA1B2C3.docx"`) {
		t.Error("the $R filename was reported as the deleted file's name")
	}
}

// 4. Every pairing outcome survives a real import, distinctly.
func TestRBContent_AllPairingOutcomesImportCleanly(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "All pairing outcomes")
	files, _ := rbPairCatalog()
	disc := discoverBinaryDir(t, mux, c.ID, files)
	imp := importAllFrom(t, mux, c.ID, disc)

	// A pairing problem is a finding about the evidence, never a parse
	// failure: every one of these files is genuinely what it claims.
	for _, f := range imp.ParseFailures {
		if strings.HasPrefix(f.Filename, "$R") {
			t.Errorf("a $R file was reported as a parse failure: %s (%s)", f.Filename, f.Message)
		}
	}

	cases := map[string]struct {
		status      string
		mustContain []string
	}{
		"$RA1B2C3.docx": {"resolved", []string{`"original_name":"confidential-plan.docx"`}},
		"$RC3D4E5.exe": {"orphan", []string{
			`"original_path":null`, `"deletion_time":null`, "no paired $I record was collected"}},
		"$RD4E5F6.bin": {"resolved", []string{
			`"original_size":999999`, "both values are preserved", `"size_matches_record":false`}},
		"$RE5F6A7.txt": {"invalid", []string{
			`"resolved":false`, "could not be read as a metadata record"}},
	}
	for name, want := range cases {
		raw := contentRecordFor(t, mux, c.ID, name)
		if !strings.Contains(raw, `"pairing_status":"`+want.status+`"`) {
			t.Errorf("%s: pairing status is not %q:\n%s", name, want.status, raw)
		}
		for _, frag := range want.mustContain {
			if !strings.Contains(raw, frag) {
				t.Errorf("%s: record omits %s", name, frag)
			}
		}
		// Whatever the pairing, the content itself was measured.
		if !strings.Contains(raw, `"status":"recovered"`) {
			t.Errorf("%s: content was not recovered despite the file being readable", name)
		}
	}

	// The $I with no $R keeps reporting its side of the pairing.
	iRaw := eventRecordFor(t, mux, c.ID, `C:\Users\jdoe\Desktop\salaries.xlsx`)
	if !strings.Contains(iRaw, `"present_in_collection":false`) {
		t.Errorf("the unpaired $I does not report its missing content:\n%s", iRaw)
	}
}

// 5. The existing $I parser is unchanged by any of this.
func TestRBContent_IParserIsUnchanged(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "I parser unchanged")
	body := []byte("content")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		rbDir + "$IA1B2C3.docx": iRecord(`C:\Users\jdoe\Documents\plan.docx`, uint64(len(body)), rbContentDeleted),
		rbDir + "$RA1B2C3.docx": body,
	})
	importAllFrom(t, mux, c.ID, disc)

	events := typedTimeline(t, mux, c.ID)
	if len(events) != 1 {
		t.Fatalf("got %d events", len(events))
	}
	e := events[0]
	for field, want := range map[string]string{
		"original_path":     `C:\Users\jdoe\Documents\plan.docx`,
		"original_name":     "plan.docx",
		"original_size":     "7",
		"record_version":    "2",
		"recycle_bin_sid":   "S-1-5-21-1004336348-1177238915-682003330-1001",
		"paired_r_file":     "$RA1B2C3.docx",
		"timestamp_meaning": "Recycle Bin deletion time",
	} {
		if e.Extra[field] != want {
			t.Errorf("the $I parser's %q changed: got %q, want %q", field, e.Extra[field], want)
		}
	}
	if !e.Timestamp.Equal(rbContentDeleted) {
		t.Errorf("deletion time = %s", e.Timestamp)
	}
	if e.Confidence != 1.0 {
		t.Errorf("confidence = %v", e.Confidence)
	}
	if !strings.Contains(e.Extra["paired_r_file_status"], "present") {
		t.Errorf("the $I no longer resolves its pair: %q", e.Extra["paired_r_file_status"])
	}
}

// 6. Recovered content raises no findings on its own.
func TestRBContent_RaisesNoFindings(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "No findings from content")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		rbDir + "$IA1B2C3.exe": iRecord(`C:\Windows\Temp\mimikatz.exe`, 9, rbContentDeleted),
		rbDir + "$RA1B2C3.exe": []byte("MZ payload"),
	})
	importAllFrom(t, mux, c.ID, disc)
	doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/analyze", nil, nil)

	var findings []model.Finding
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/findings", nil, &findings)
	for _, f := range findings {
		t.Errorf("recovered content alone produced a finding: %q (%s)", f.Title, f.Severity)
	}
}

// contentRecordFor returns the raw record a named $R file produced.
func contentRecordFor(t *testing.T, mux http.Handler, caseID, name string) string {
	t.Helper()
	var page struct {
		Items []TriagedSourceFile `json:"items"`
	}
	var colls []model.Collection
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/evidence", nil, &colls)
	for _, coll := range colls {
		doJSON(t, mux, "GET",
			"/api/cases/"+caseID+"/evidence/"+coll.ID+"/files?page=1&page_size=250", nil, &page)
		for _, f := range page.Items {
			if f.OriginalFilename != name {
				continue
			}
			var prov SourceFileProvenance
			doJSON(t, mux, "GET", "/api/cases/"+caseID+"/sources/"+f.ID+"/provenance", nil, &prov)
			if len(prov.RawEvidence) == 0 {
				t.Fatalf("%s produced no raw record", name)
			}
			return prov.RawEvidence[0].Raw
		}
	}
	t.Fatalf("%s was not found in the catalog", name)
	return ""
}

// eventRecordFor returns the raw record behind the deletion event for a
// given original path.
func eventRecordFor(t *testing.T, mux http.Handler, caseID, originalPath string) string {
	t.Helper()
	for _, e := range typedTimeline(t, mux, caseID) {
		if e.Extra["original_path"] != originalPath {
			continue
		}
		var prov EventProvenance
		doJSON(t, mux, "GET", "/api/cases/"+caseID+"/events/"+e.ID, nil, &prov)
		return prov.RawEvidence.Raw
	}
	t.Fatalf("no deletion event for %s", originalPath)
	return ""
}
