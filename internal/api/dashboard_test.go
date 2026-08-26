package api

import (
	"net/http"
	"testing"
)

// TestCaseSummary_ImportedSourceFilesDiffersFromDiscovered covers the one
// backend addition this phase needed: Summary.ImportedSourceFiles must
// count only files that were actually selected and imported, distinct
// from Summary.SourceFiles (every active cataloged file, imported or
// not) -- the case overview dashboard shows both numbers separately.
func TestCaseSummary_ImportedSourceFilesDiffersFromDiscovered(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "Summary counts case")

	files := map[string]string{}
	for _, name := range []string{"a", "b", "c"} {
		files["EvtxECmd/"+name+"_EvtxECmd_Output.csv"] = evtxHeader + evtxRow(
			"2026-01-15T09:00:00.0000000Z", "4624", "Security", "WKSTN-042", name, "TargetUserName: "+name+"; LogonType: 2", "1")
	}
	files["readme.txt"] = "not evidence"
	zipData := buildZipBytes(t, files)

	discRec := uploadZip(t, mux, c.ID, zipData)
	if discRec.Code != http.StatusOK {
		t.Fatalf("discover: status %d, body %s", discRec.Code, discRec.Body.String())
	}
	var disc DiscoverResult
	mustDecode(t, discRec, &disc)
	if disc.SupportedCount != 3 {
		t.Fatalf("got %d supported files, want 3", disc.SupportedCount)
	}

	// Import only 2 of the 3 supported files -- the third stays merely
	// "discovered", and the unsupported readme.txt stays "unsupported".
	var toImport []string
	for _, sf := range disc.SourceFiles {
		if sf.ImportStatus == "discovered" && len(toImport) < 2 {
			toImport = append(toImport, sf.ID)
		}
	}
	if len(toImport) != 2 {
		t.Fatalf("expected to find 2 importable files, got %d", len(toImport))
	}
	importRec := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/evidence/"+disc.Collection.ID+"/import",
		map[string][]string{"source_file_ids": toImport}, nil)
	if importRec.Code != http.StatusOK {
		t.Fatalf("import: status %d, body %s", importRec.Code, importRec.Body.String())
	}

	var caseDetail struct {
		Summary Summary `json:"summary"`
	}
	rec := doJSON(t, mux, "GET", "/api/cases/"+c.ID, nil, &caseDetail)
	if rec.Code != http.StatusOK {
		t.Fatalf("get case: status %d", rec.Code)
	}
	if caseDetail.Summary.SourceFiles != 4 {
		t.Errorf("SourceFiles = %d, want 4 (3 supported + 1 unsupported, all cataloged)", caseDetail.Summary.SourceFiles)
	}
	if caseDetail.Summary.ImportedSourceFiles != 2 {
		t.Errorf("ImportedSourceFiles = %d, want 2 (only the files actually selected and imported)", caseDetail.Summary.ImportedSourceFiles)
	}
	if caseDetail.Summary.Events != 2 {
		t.Errorf("Events = %d, want 2 (one logon per imported file)", caseDetail.Summary.Events)
	}
}
