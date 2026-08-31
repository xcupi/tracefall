package api

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tracefall/internal/model"
)

func verifyIntegrity(t *testing.T, mux http.Handler, caseID, collectionID string) IntegrityResult {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("POST",
		"/api/cases/"+caseID+"/evidence/"+collectionID+"/verify-integrity", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("verify: status %d, body %s", rec.Code, rec.Body.String())
	}
	var res IntegrityResult
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("decoding result: %v", err)
	}
	return res
}

// dirEvidenceCase discovers a directory of evidence and returns the case
// and collection plus the directory itself, so a test can modify the
// evidence and re-verify.
func dirEvidenceCase(t *testing.T, mux http.Handler, name string) (caseID, collectionID, dir string) {
	t.Helper()
	c := mustCreateCase(t, mux, name)
	dir = t.TempDir()
	for path, content := range map[string][]byte{
		"Windows/System32/winevt/Logs/Security.evtx": attackEvtx(),
		"Users/jdoe/NTUSER.DAT":                      persistenceHive(),
	} {
		p := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rec := discoverPath(t, mux, c.ID, dir)
	if rec.Code != http.StatusOK {
		t.Fatalf("discover: %d %s", rec.Code, rec.Body.String())
	}
	var disc DiscoverResult
	mustDecode(t, rec, &disc)
	return c.ID, disc.Collection.ID, dir
}

// ---------------- directory evidence ----------------

func TestVerify_UnchangedDirectoryEvidencePasses(t *testing.T) {
	mux := newTestRouter(t)
	caseID, collID, _ := dirEvidenceCase(t, mux, "Verify unchanged")

	res := verifyIntegrity(t, mux, caseID, collID)
	if res.Status != IntegrityVerified {
		t.Errorf("status = %q, want %q (reason: %s)", res.Status, IntegrityVerified, res.Reason)
	}
	if res.RecordedSHA512 == "" || len(res.RecordedSHA512) != 128 {
		t.Errorf("recorded digest is not a full SHA-512: %q", res.RecordedSHA512)
	}
	if res.ComputedSHA512 != res.RecordedSHA512 {
		t.Errorf("computed %q != recorded %q", res.ComputedSHA512, res.RecordedSHA512)
	}
	if res.EvidenceKind != EvidenceKindDirectory {
		t.Errorf("evidence_kind = %q, want %q", res.EvidenceKind, EvidenceKindDirectory)
	}
	if res.ToolVersion == "" {
		t.Error("no tool version recorded on the verification result")
	}
}

// The point of the whole feature: changed evidence must be detected.
func TestVerify_ModifiedContentIsDetected(t *testing.T) {
	mux := newTestRouter(t)
	caseID, collID, dir := dirEvidenceCase(t, mux, "Verify modified")

	before := verifyIntegrity(t, mux, caseID, collID)
	if before.Status != IntegrityVerified {
		t.Fatalf("baseline verification did not pass: %+v", before)
	}

	// Change one byte of one file.
	target := filepath.Join(dir, "Users", "jdoe", "NTUSER.DAT")
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	content[len(content)-1] ^= 0xFF
	if err := os.WriteFile(target, content, 0o644); err != nil {
		t.Fatal(err)
	}

	after := verifyIntegrity(t, mux, caseID, collID)
	if after.Status != IntegrityMismatch {
		t.Fatalf("status = %q, want %q -- a modified byte must be detected", after.Status, IntegrityMismatch)
	}
	if after.ComputedSHA512 == after.RecordedSHA512 {
		t.Error("computed digest equals the recorded one despite modified content")
	}
	// THE critical property: verification must not rewrite history.
	if after.RecordedSHA512 != before.RecordedSHA512 {
		t.Errorf("the RECORDED digest changed across verification: %q -> %q; it is a historical fact and must be immutable",
			before.RecordedSHA512, after.RecordedSHA512)
	}
	if len(after.ComputedSHA512) != 128 {
		t.Errorf("computed digest is not a full SHA-512: %q", after.ComputedSHA512)
	}
}

// Renaming a file changes the digest, because the relative path is part
// of the hashed stream (Phase 10A semantics).
func TestVerify_RenameIsDetected(t *testing.T) {
	mux := newTestRouter(t)
	caseID, collID, dir := dirEvidenceCase(t, mux, "Verify rename")

	from := filepath.Join(dir, "Users", "jdoe", "NTUSER.DAT")
	to := filepath.Join(dir, "Users", "jdoe", "NTUSER.RENAMED")
	if err := os.Rename(from, to); err != nil {
		t.Fatal(err)
	}
	if res := verifyIntegrity(t, mux, caseID, collID); res.Status != IntegrityMismatch {
		t.Errorf("status = %q, want %q -- a rename changes the path-sensitive digest", res.Status, IntegrityMismatch)
	}
}

// A metadata-only change must NOT alter the digest: Phase 10A hashes
// path and content, never mtime or permissions.
func TestVerify_MetadataOnlyChangeDoesNotAlterTheDigest(t *testing.T) {
	mux := newTestRouter(t)
	caseID, collID, dir := dirEvidenceCase(t, mux, "Verify metadata")

	target := filepath.Join(dir, "Users", "jdoe", "NTUSER.DAT")
	if err := os.Chmod(target, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(target, testFixedTime(), testFixedTime()); err != nil {
		t.Fatal(err)
	}

	if res := verifyIntegrity(t, mux, caseID, collID); res.Status != IntegrityVerified {
		t.Errorf("status = %q, want %q -- permissions and mtime are not part of the digest",
			res.Status, IntegrityVerified)
	}
}

// ---------------- uploaded evidence ----------------

func TestVerify_UploadedArchiveHashesTheReceivedBytes(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Verify upload")
	zipData := buildZipBytes(t, map[string]string{
		"Windows/System32/winevt/Logs/Security.evtx": "not really an evtx",
		"notes.txt": "hello",
	})
	rec := uploadZip(t, mux, c.ID, zipData)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", rec.Code, rec.Body.String())
	}
	var disc DiscoverResult
	mustDecode(t, rec, &disc)

	res := verifyIntegrity(t, mux, c.ID, disc.Collection.ID)
	if res.Status != IntegrityVerified {
		t.Fatalf("status = %q, want verified (reason: %s)", res.Status, res.Reason)
	}
	if res.EvidenceKind != EvidenceKindUpload {
		t.Errorf("evidence_kind = %q, want %q", res.EvidenceKind, EvidenceKindUpload)
	}
	// The digest must cover the RECEIVED bytes, not the extraction
	// directory. Hashing the uploaded bytes independently must agree.
	independent := sha512OfBytes(zipData)
	if res.ComputedSHA512 != independent {
		t.Errorf("computed digest does not match an independent hash of the uploaded bytes;\n got  %s\n want %s",
			res.ComputedSHA512, independent)
	}
	if res.RecordedSHA512 != independent {
		t.Errorf("recorded digest is not the digest of the received bytes")
	}
}

// ---------------- read-only guarantee ----------------

// Verification must change nothing except the audit trail.
func TestVerify_IsReadOnly(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Verify read-only")
	disc, _ := discoverPathAndImportAll(t, mux, c.ID, "../../testdata/synthetic_case")
	doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/analyze", nil, &AnalyzeResultSummary{})

	before := captureCaseState(t, mux, c.ID)
	for i := 0; i < 3; i++ {
		verifyIntegrity(t, mux, c.ID, disc.Collection.ID)
	}
	after := captureCaseState(t, mux, c.ID)

	if before.collectionsJSON != after.collectionsJSON {
		t.Error("verification changed the collections (hashes or counters must be untouched)")
	}
	if before.sourceFilesJSON != after.sourceFilesJSON {
		t.Error("verification changed the source files")
	}
	if before.timelineJSON != after.timelineJSON {
		t.Error("verification changed the events")
	}
	if before.findingsJSON != after.findingsJSON {
		t.Error("verification changed the findings")
	}
	if before.caseStatus != after.caseStatus {
		t.Errorf("verification changed the case status: %q -> %q", before.caseStatus, after.caseStatus)
	}
}

// Verification appends exactly one audit entry per run, recording the
// outcome -- and never edits an earlier one.
func TestVerify_AppendsAuditEntryPerRun(t *testing.T) {
	mux := newTestRouter(t)
	caseID, collID, dir := dirEvidenceCase(t, mux, "Verify audit")

	before := auditEntries(t, mux, caseID)
	verifyIntegrity(t, mux, caseID, collID)
	afterFirst := auditEntries(t, mux, caseID)

	if len(afterFirst) != len(before)+1 {
		t.Fatalf("audit grew by %d entries, want exactly 1", len(afterFirst)-len(before))
	}
	entry := afterFirst[len(afterFirst)-1]
	if entry.Action != model.AuditIntegrityVerified {
		t.Errorf("action = %q, want %q", entry.Action, model.AuditIntegrityVerified)
	}
	if entry.TargetID != collID {
		t.Errorf("target_id = %q, want the collection id", entry.TargetID)
	}
	if entry.Actor != model.ActorLocalUser {
		t.Errorf("actor = %q; the audit model's only honest value is %q", entry.Actor, model.ActorLocalUser)
	}

	// A failing verification must be recorded too, and must say so.
	if err := os.WriteFile(filepath.Join(dir, "Users", "jdoe", "NTUSER.DAT"), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	verifyIntegrity(t, mux, caseID, collID)
	afterSecond := auditEntries(t, mux, caseID)
	if len(afterSecond) != len(afterFirst)+1 {
		t.Fatalf("second verification did not append an audit entry")
	}
	// The earlier entry must be untouched.
	if afterSecond[len(afterFirst)-1] != afterFirst[len(afterFirst)-1] {
		t.Error("an existing audit entry was modified by a later verification")
	}
	if last := afterSecond[len(afterSecond)-1]; !containsAny(last.Summary, "MISMATCH") {
		t.Errorf("mismatch was not recorded in the audit summary: %q", last.Summary)
	}
}

// ---------------- legacy / unavailable ----------------

// A collection with no recorded digest is "unavailable", never
// "verified" and never "mismatch". Not knowing is not the same as
// knowing it changed.
func TestVerify_NoRecordedDigestIsUnavailableNotFailure(t *testing.T) {
	svc := newTestService(t)
	mux := routerFor(svc)
	caseID, collID, _ := dirEvidenceCase(t, mux, "Verify legacy")

	// Simulate a pre-Phase-10A row by clearing the recorded digest.
	if err := svc.store.ClearIntegrityForTest(collID); err != nil {
		t.Fatal(err)
	}

	res := verifyIntegrity(t, mux, caseID, collID)
	if res.Status != IntegrityUnavailable {
		t.Errorf("status = %q, want %q", res.Status, IntegrityUnavailable)
	}
	if res.Reason == "" {
		t.Error("an unavailable result must explain why")
	}
	if res.ComputedSHA512 != "" {
		t.Error("a digest was computed for a collection with nothing to compare against; that attests to nothing")
	}
}

// Evidence that has gone missing is "unavailable", and the reason must
// not leak the server path that could not be read.
func TestVerify_MissingEvidenceIsUnavailableAndLeaksNoPath(t *testing.T) {
	mux := newTestRouter(t)
	caseID, collID, dir := dirEvidenceCase(t, mux, "Verify missing")
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}

	res := verifyIntegrity(t, mux, caseID, collID)
	if res.Status != IntegrityUnavailable {
		t.Errorf("status = %q, want %q", res.Status, IntegrityUnavailable)
	}
	if containsAny(res.Reason, dir, "/tmp/", "TempDir", ".go:", "goroutine") {
		t.Errorf("the reason leaks a server path or internals: %q", res.Reason)
	}
	// The recorded digest survives evidence going missing.
	if len(res.RecordedSHA512) != 128 {
		t.Errorf("recorded digest lost when evidence went missing: %q", res.RecordedSHA512)
	}
}

func TestVerify_RejectsCollectionFromAnotherCase(t *testing.T) {
	mux := newTestRouter(t)
	caseA, collA, _ := dirEvidenceCase(t, mux, "Verify case A")
	_ = caseA
	b := mustCreateCase(t, mux, "Verify case B")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("POST",
		"/api/cases/"+b.ID+"/evidence/"+collA+"/verify-integrity", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status %d, want 404 -- case B must not verify case A's evidence", rec.Code)
	}
}

// ---------------- helpers ----------------

func sha512OfBytes(b []byte) string {
	sum := sha512.Sum512(b)
	return hex.EncodeToString(sum[:])
}

func testFixedTime() time.Time {
	return time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
}

// caseState is a snapshot of everything verification must leave alone,
// captured as JSON so any difference at all is caught rather than only
// the fields a test thought to compare.
type caseState struct {
	collectionsJSON string
	sourceFilesJSON string
	timelineJSON    string
	findingsJSON    string
	caseStatus      string
}

func captureCaseState(t *testing.T, mux http.Handler, caseID string) caseState {
	t.Helper()
	get := func(path string) string {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", "/api/cases/"+caseID+path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: status %d", path, rec.Code)
		}
		return rec.Body.String()
	}
	var summary struct {
		Case model.Case `json:"case"`
	}
	if err := json.Unmarshal([]byte(get("")), &summary); err != nil {
		t.Fatal(err)
	}
	return caseState{
		collectionsJSON: get("/evidence"),
		sourceFilesJSON: get("/sources"),
		timelineJSON:    get("/timeline"),
		findingsJSON:    get("/findings"),
		caseStatus:      summary.Case.Status,
	}
}

func auditEntries(t *testing.T, mux http.Handler, caseID string) []model.AuditEvent {
	t.Helper()
	var out []model.AuditEvent
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/audit", nil, &out)
	return out
}
