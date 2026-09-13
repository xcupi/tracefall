package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tracefall/internal/casefiles"
	"tracefall/internal/model"
	"tracefall/internal/store"
)

// Whole-case deletion at the SERVICE level: the database, the evidence
// on disk, the audit record, and what happens when the two halves
// disagree.
//
// internal/store/deletion_audit_test.go proves the database side against
// the live schema. These cover what only this layer can: files, ordering,
// recovery from a partial failure, and authorization.

// serviceWithPaths builds a service and hands back the paths it uses, so
// a test can look at the disk directly rather than trusting the API.
func serviceWithPaths(t *testing.T) (*Service, *store.Store, *casefiles.Store, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	root := t.TempDir()
	files := casefiles.NewStore(root)
	return NewService(db, files), db, files, dbPath
}

// seedUploadedCase creates a case whose evidence arrived as an upload,
// so its bytes are storage TRACEFALL OWNS and must be deleted with it.
func seedUploadedCase(t *testing.T, svc *Service, files *casefiles.Store, name string) (model.Case, string) {
	t.Helper()
	c, err := svc.CreateCase(name, "d")
	if err != nil {
		t.Fatal(err)
	}
	res, err := svc.DiscoverEvidenceFromPath(c.ID, "../../testdata/synthetic_case")
	if err != nil {
		t.Fatal(err)
	}
	collID := res.Collection.ID
	var ids []string
	for _, sf := range res.SourceFiles {
		if sf.Supported {
			ids = append(ids, sf.ID)
		}
	}
	if _, err := svc.ImportEvidence(c.ID, collID, ids); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AnalyzeCase(c.ID); err != nil {
		t.Fatal(err)
	}
	// Write an "uploaded archive" and an extracted tree into the case's
	// own storage, which is what a real upload leaves behind.
	dir := files.CollectionDir(c.ID, collID)
	if err := os.MkdirAll(filepath.Join(dir, "evidence", "Logs"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{
		files.UploadPath(c.ID, collID),
		files.MetadataPath(c.ID, collID),
		filepath.Join(dir, "evidence", "Logs", "extracted.evtx"),
	} {
		if err := os.WriteFile(f, []byte("evidence bytes"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return c, collID
}

// The evidence Tracefall stores must actually leave the disk.
func TestDeleteCase_EvidenceOnDiskIsRemoved(t *testing.T) {
	svc, _, files, _ := serviceWithPaths(t)
	c, collID := seedUploadedCase(t, svc, files, "Disk deletion")

	caseDir := files.CaseDir(c.ID)
	upload := files.UploadPath(c.ID, collID)
	extracted := filepath.Join(files.EvidenceDir(c.ID, collID), "Logs", "extracted.evtx")
	for _, p := range []string{caseDir, upload, extracted} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("fixture is wrong, %s does not exist: %v", p, err)
		}
	}

	if err := svc.DeleteCase(c.ID); err != nil {
		t.Fatalf("DeleteCase: %v", err)
	}

	for _, p := range []string{upload, extracted, caseDir} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s still exists after the case was deleted (err=%v)", p, err)
		}
	}
}

// Evidence ingested from a LOCAL FOLDER is the investigator's own data,
// not storage Tracefall owns. Deleting a case must never reach outside
// its own directory to destroy it.
func TestDeleteCase_LocalPathEvidenceIsNotDestroyed(t *testing.T) {
	svc, _, files, _ := serviceWithPaths(t)

	// A local evidence folder the investigator owns.
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "20260115_090000_EvtxECmd_Output.csv"),
		[]byte(bruteForceCSV), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := svc.CreateCase("Local path", "")
	if err != nil {
		t.Fatal(err)
	}
	res, err := svc.DiscoverEvidenceFromPath(c.ID, src)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, sf := range res.SourceFiles {
		if sf.Supported {
			ids = append(ids, sf.ID)
		}
	}
	if _, err := svc.ImportEvidence(c.ID, res.Collection.ID, ids); err != nil {
		t.Fatal(err)
	}

	if err := svc.DeleteCase(c.ID); err != nil {
		t.Fatal(err)
	}

	// The investigator's own folder and its contents are untouched.
	if _, err := os.Stat(src); err != nil {
		t.Fatalf("the source folder was destroyed: %v", err)
	}
	entries, err := os.ReadDir(src)
	if err != nil || len(entries) != 1 {
		t.Errorf("the source folder holds %d files, want 1 (err=%v)", len(entries), err)
	}
	// And Tracefall's own directory for the case is gone.
	if _, err := os.Stat(files.CaseDir(c.ID)); !os.IsNotExist(err) {
		t.Errorf("the case directory survived: %v", err)
	}
}

// A filesystem failure after the database commit must be REPORTED and
// must be RECOVERABLE. Before this, the rows were gone, the files
// remained, the error named neither, and every retry stopped at "case
// not found" -- so the evidence could never be cleaned up through the
// application at all.
func TestDeleteCase_FilesystemFailureIsReportedAndRecoverable(t *testing.T) {
	svc, _, files, _ := serviceWithPaths(t)
	c, collID := seedUploadedCase(t, svc, files, "Partial failure")
	caseDir := files.CaseDir(c.ID)

	// Make the case directory undeletable by removing write permission
	// from its parent.
	parent := filepath.Dir(caseDir)
	info, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o555); err != nil {
		t.Fatal(err)
	}
	restored := false
	defer func() {
		if !restored {
			os.Chmod(parent, info.Mode())
		}
	}()

	err = svc.DeleteCase(c.ID)
	if err == nil {
		if os.Geteuid() == 0 {
			t.Skip("running as root; permissions cannot be used to force a filesystem failure")
		}
		t.Fatal("DeleteCase reported success although the evidence directory could not be removed")
	}
	// The error has to say what actually happened: rows gone, files not.
	msg := err.Error()
	for _, want := range []string{"database records were deleted", "may remain on disk", caseDir} {
		if !strings.Contains(msg, want) {
			t.Errorf("the error does not mention %q: %s", want, msg)
		}
	}
	// The message must not OVERSTATE either. Removal is depth-first, so
	// a partial failure leaves an unknown mixture; the wording says
	// "may remain", and what is definitely true is that the directory
	// itself is still there.
	if strings.Contains(msg, "are still on disk") {
		t.Error("the error claims all files remain; removal is depth-first and that cannot be known")
	}
	if _, statErr := os.Stat(caseDir); statErr != nil {
		t.Errorf("the error reported a failed removal, but the directory is gone: %v", statErr)
	}
	_ = collID

	// Now the operator fixes the permission and retries. The retry must
	// finish the job rather than refusing because the case row is gone.
	os.Chmod(parent, info.Mode())
	restored = true
	if err := svc.DeleteCase(c.ID); err != nil {
		t.Fatalf("the retry did not complete the cleanup: %v", err)
	}
	if _, err := os.Stat(caseDir); !os.IsNotExist(err) {
		t.Errorf("the evidence directory survived the retry: %v", err)
	}
}

// A genuinely unknown case must still be refused -- the recovery path
// above must not turn every bad id into a success.
func TestDeleteCase_UnknownCaseIsStillRefused(t *testing.T) {
	svc, _, _, _ := serviceWithPaths(t)
	if err := svc.DeleteCase("no-such-case"); err == nil {
		t.Fatal("deleting a case that never existed reported success")
	}
}

// The deletion must leave a record, and it has to be somewhere that
// survives the deletion. The case's own audit_log does not: those rows
// are part of the case and go with it.
func TestDeleteCase_IsRecordedInTheSecurityLog(t *testing.T) {
	svc, db, files, _ := serviceWithPaths(t)
	c, _ := seedUploadedCase(t, svc, files, "Audited deletion")

	if err := svc.WithActor(Principal{Username: "admin-user", Role: "admin"}).DeleteCase(c.ID); err != nil {
		t.Fatal(err)
	}

	entries, err := db.ListSecurityLog(200)
	if err != nil {
		t.Fatal(err)
	}
	var found *model.AuditEvent
	for i := range entries {
		if entries[i].Action == model.AuditCaseDeleted {
			found = &entries[i]
		}
	}
	if found == nil {
		t.Fatal("the deletion left no record anywhere that outlives the case")
	}
	if found.CaseID != c.ID {
		t.Errorf("the record does not name the case: %q", found.CaseID)
	}
	if found.Actor != "admin-user" {
		t.Errorf("the record does not name who did it: %q", found.Actor)
	}
	if !strings.Contains(found.Summary, "Audited deletion") {
		t.Errorf("the record does not name the case that was deleted: %q", found.Summary)
	}
	// And the case's own audit log went with the case.
	if audit, err := db.ListAuditLog(c.ID); err != nil || len(audit) != 0 {
		t.Errorf("the deleted case still has %d audit rows (err=%v)", len(audit), err)
	}
}

// Cross-case safety through the real HTTP API, end to end.
func TestDeleteCase_APICrossCaseSafety(t *testing.T) {
	mux := newTestRouter(t)
	a := createTestCase(t, mux, "Case A")
	b := createTestCase(t, mux, "Case B")

	for _, c := range []model.Case{a, b} {
		discoverPathAndImportAll(t, mux, c.ID, "../../testdata/synthetic_case")
		if rec := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/analyze", nil, nil); rec.Code != http.StatusOK {
			t.Fatalf("analyzing %s: %d", c.Name, rec.Code)
		}
	}

	beforeB := caseSnapshot(t, mux, b.ID)
	if beforeB.Events == 0 || beforeB.Findings == 0 {
		t.Fatalf("case B has nothing to protect: %+v", beforeB)
	}

	if rec := doJSON(t, mux, "DELETE", "/api/cases/"+a.ID, nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}

	if rec := doJSON(t, mux, "GET", "/api/cases/"+a.ID, nil, nil); rec.Code != http.StatusNotFound {
		t.Errorf("the deleted case returns %d, want 404", rec.Code)
	}
	afterB := caseSnapshot(t, mux, b.ID)
	if afterB != beforeB {
		t.Errorf("deleting case A changed case B:\n before %+v\n after  %+v", beforeB, afterB)
	}
	// Every case-scoped collection endpoint must also be empty for A.
	for _, path := range []string{"/evidence", "/findings", "/correlations", "/investigations", "/attack", "/audit"} {
		rec := doJSON(t, mux, "GET", "/api/cases/"+a.ID+path, nil, nil)
		if rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), a.ID) {
			t.Errorf("%s still returns data for the deleted case: %s", path, rec.Body.String())
		}
	}
}

// caseSummary is the comparable rollup used to prove an untouched case.
type caseSummary struct {
	Events, Findings, Correlations, Collections, Investigations int
}

func caseSnapshot(t *testing.T, mux http.Handler, caseID string) caseSummary {
	t.Helper()
	var out caseSummary
	var detail struct {
		Summary struct {
			Events       int `json:"events"`
			Findings     int `json:"findings"`
			Correlations int `json:"correlations"`
		} `json:"summary"`
	}
	if rec := doJSON(t, mux, "GET", "/api/cases/"+caseID, nil, &detail); rec.Code != http.StatusOK {
		t.Fatalf("case %s: %d", caseID, rec.Code)
	}
	out.Events = detail.Summary.Events
	out.Findings = detail.Summary.Findings
	out.Correlations = detail.Summary.Correlations

	var cols []model.Collection
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/evidence", nil, &cols)
	out.Collections = len(cols)
	var inv []model.Investigation
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/investigations", nil, &inv)
	out.Investigations = len(inv)
	return out
}

// Only an admin may delete a case, and being refused must change
// nothing.
func TestDeleteCase_AdminOnly(t *testing.T) {
	f := newAuthFixture(t, time.Hour)
	f.mustCreateUser(t, "boss", "admin-password-here", model.RoleAdmin)
	f.mustCreateUser(t, "annie", "analyst-password-12", model.RoleAnalyst)
	admin, _ := f.login(t, "boss", "admin-password-here")

	created := admin.do("POST", "/api/cases", map[string]string{"name": "Admin-only case deletion"})
	var c model.Case
	if err := json.Unmarshal(created.Body.Bytes(), &c); err != nil {
		t.Fatal(err)
	}

	analyst, _ := f.login(t, "annie", "analyst-password-12")
	if got := analyst.do("DELETE", "/api/cases/"+c.ID, nil); got.Code != http.StatusForbidden {
		t.Errorf("analyst deleting a case: status %d, want 403", got.Code)
	}
	if got := admin.do("GET", "/api/cases/"+c.ID, nil); got.Code != http.StatusOK {
		t.Error("the case an analyst was refused permission to delete is gone")
	}
	if got := admin.do("DELETE", "/api/cases/"+c.ID, nil); got.Code != http.StatusOK {
		t.Errorf("admin deleting a case: status %d, want 200", got.Code)
	}
}
