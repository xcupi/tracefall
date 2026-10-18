package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"tracefall/internal/casefiles"
	"tracefall/internal/model"
	"tracefall/internal/store"
)

const synthPath = "../../testdata/synthetic_case"

type jobView struct {
	ID              string         `json:"job_id"`
	CaseID          string         `json:"case_id"`
	Status          string         `json:"status"`
	Stage           string         `json:"stage"`
	CollectionID    string         `json:"collection_id"`
	Error           string         `json:"error"`
	Attempts        int            `json:"attempts"`
	CancelRequested bool           `json:"cancel_requested"`
	Progress        map[string]any `json:"progress"`
	Result          map[string]any `json:"result"`
}

// serviceAt opens a service over an explicit database and data
// directory, and returns a function that closes it -- so a test can
// "restart" the server over the same files.
func serviceAt(t *testing.T, dbPath, dataDir string) (*Service, func()) {
	t.Helper()
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(db, casefiles.NewStore(dataDir))
	svc.pipe.poll = 10 * time.Millisecond
	return svc, func() { db.Close() }
}

func startWorker(t *testing.T, svc *Service) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	stop := svc.StartPipeline(ctx)
	t.Cleanup(func() { cancel(); stop() })
}

func do(t *testing.T, mux http.Handler, method, path string, body []byte, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func sha(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func initUpload(t *testing.T, mux http.Handler, caseID, name string, data []byte, declareHash bool) model.UploadSession {
	t.Helper()
	req := map[string]any{"filename": name, "size": len(data)}
	if declareHash {
		req["sha256"] = sha(data)
	}
	b, _ := json.Marshal(req)
	rec := do(t, mux, "POST", "/api/cases/"+caseID+"/uploads", b, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("init upload: %d %s", rec.Code, rec.Body.String())
	}
	var u model.UploadSession
	mustDecode(t, rec, &u)
	return u
}

func putChunk(t *testing.T, mux http.Handler, caseID, id string, off int64, chunk []byte) *httptest.ResponseRecorder {
	t.Helper()
	return do(t, mux, "PUT", "/api/cases/"+caseID+"/uploads/"+id, chunk,
		map[string]string{"Upload-Offset": strconv.FormatInt(off, 10), "Content-Type": "application/octet-stream"})
}

func sendInChunks(t *testing.T, mux http.Handler, caseID, id string, data []byte, n int) {
	t.Helper()
	step := (len(data) + n - 1) / n
	for off := 0; off < len(data); off += step {
		end := off + step
		if end > len(data) {
			end = len(data)
		}
		if rec := putChunk(t, mux, caseID, id, int64(off), data[off:end]); rec.Code != http.StatusOK {
			t.Fatalf("chunk at %d: %d %s", off, rec.Code, rec.Body.String())
		}
	}
}

func completeUpload(t *testing.T, mux http.Handler, caseID, id string) *httptest.ResponseRecorder {
	t.Helper()
	return do(t, mux, "POST", "/api/cases/"+caseID+"/uploads/"+id+"/complete", nil, nil)
}

func enqueue(t *testing.T, mux http.Handler, caseID string, body map[string]any) (*httptest.ResponseRecorder, jobView) {
	t.Helper()
	b, _ := json.Marshal(body)
	rec := do(t, mux, "POST", "/api/cases/"+caseID+"/pipeline/jobs", b, nil)
	var j jobView
	if rec.Code < 300 {
		mustDecode(t, rec, &j)
	}
	return rec, j
}

func getJob(t *testing.T, mux http.Handler, caseID, id string) jobView {
	t.Helper()
	rec := do(t, mux, "GET", "/api/cases/"+caseID+"/pipeline/jobs/"+id, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get job: %d %s", rec.Code, rec.Body.String())
	}
	var j jobView
	mustDecode(t, rec, &j)
	return j
}

func waitPipelineJob(t *testing.T, mux http.Handler, caseID, id string) jobView {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		j := getJob(t, mux, caseID, id)
		if j.Status == model.JobSucceeded || j.Status == model.JobFailed || j.Status == model.JobCancelled {
			return j
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("job %s did not finish", id)
	return jobView{}
}

func num(m map[string]any, k string) int {
	f, _ := m[k].(float64)
	return int(f)
}

// ---------------------------------------------------------------- uploads

func TestUpload_ChunkedUploadFeedsThePipelineEndToEnd(t *testing.T) {
	svc := newTestService(t)
	svc.pipe.poll = 10 * time.Millisecond
	mux := routerFor(svc)
	startWorker(t, svc)
	c := mustCreateCase(t, mux, "Chunked")
	zip := buildKAPEZip(t)

	u := initUpload(t, mux, c.ID, "kape.zip", zip, true)
	if u.Received != 0 || u.Status != model.UploadOpen {
		t.Fatalf("new session = %+v", u)
	}
	sendInChunks(t, mux, c.ID, u.ID, zip, 3)
	rec := completeUpload(t, mux, c.ID, u.ID)
	if rec.Code != http.StatusOK {
		t.Fatalf("complete: %d %s", rec.Code, rec.Body.String())
	}

	rec, job := enqueue(t, mux, c.ID, map[string]any{"upload_id": u.ID})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("enqueue: %d %s", rec.Code, rec.Body.String())
	}
	done := waitPipelineJob(t, mux, c.ID, job.ID)
	if done.Status != model.JobSucceeded || done.Stage != model.StageComplete {
		t.Fatalf("job = %+v", done)
	}
	if num(done.Result, "findings") == 0 || num(done.Result, "events") == 0 || done.Result["collection_id"] == "" {
		t.Errorf("result does not describe the work: %+v", done.Result)
	}

	cols, _ := svc.store.ListCollections(c.ID)
	if len(cols) != 1 || cols[0].ArchiveHash != sha(zip) {
		t.Fatalf("the stored evidence hash must be the hash of the bytes the client sent: %+v", cols)
	}
	got, _ := svc.store.GetCase(c.ID)
	if got.Status != model.CaseStatusAnalyzed {
		t.Errorf("case status = %q, want analyzed", got.Status)
	}
	sess, _ := svc.store.GetUploadSession(u.ID)
	if sess.Status != model.UploadConsumed {
		t.Errorf("session status = %q, want consumed", sess.Status)
	}
	if _, err := os.Stat(svc.files.UploadSessionPath(c.ID, u.ID)); !os.IsNotExist(err) {
		t.Error("the staging file was not cleaned up after the job finished")
	}
}

func TestUpload_ResumesAfterAServerRestart(t *testing.T) {
	dir := t.TempDir()
	dbPath, data := filepath.Join(dir, "t.db"), filepath.Join(dir, "data")
	zip := buildKAPEZip(t)

	svc1, closeFirst := serviceAt(t, dbPath, data)
	mux1 := routerFor(svc1)
	c := mustCreateCase(t, mux1, "Resume")
	u := initUpload(t, mux1, c.ID, "kape.zip", zip, true)
	half := len(zip) / 2
	if rec := putChunk(t, mux1, c.ID, u.ID, 0, zip[:half]); rec.Code != http.StatusOK {
		t.Fatalf("first chunk: %d %s", rec.Code, rec.Body.String())
	}
	closeFirst() // the server goes away mid-upload

	svc2, closeSecond := serviceAt(t, dbPath, data)
	defer closeSecond()
	mux2 := routerFor(svc2)
	rec := do(t, mux2, "GET", "/api/cases/"+c.ID+"/uploads/"+u.ID, nil, nil)
	var st model.UploadSession
	mustDecode(t, rec, &st)
	if rec.Code != http.StatusOK || st.Received != int64(half) {
		t.Fatalf("after restart the server must report the bytes it kept: %d received=%d want %d", rec.Code, st.Received, half)
	}
	if rec := putChunk(t, mux2, c.ID, u.ID, int64(half), zip[half:]); rec.Code != http.StatusOK {
		t.Fatalf("resumed chunk: %d %s", rec.Code, rec.Body.String())
	}
	if rec := completeUpload(t, mux2, c.ID, u.ID); rec.Code != http.StatusOK {
		t.Fatalf("complete: %d %s", rec.Code, rec.Body.String())
	}
}

func TestUpload_WrongOffsetIs409AndNamesTheTrueOffset(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Offsets")
	data := bytes.Repeat([]byte("x"), 100)
	u := initUpload(t, mux, c.ID, "a.zip", data, false)
	putChunk(t, mux, c.ID, u.ID, 0, data[:40])

	for _, off := range []int64{0, 10, 41, 90} {
		rec := putChunk(t, mux, c.ID, u.ID, off, data[40:60])
		if rec.Code != http.StatusConflict {
			t.Errorf("offset %d: status %d, want 409", off, rec.Code)
			continue
		}
		var body struct {
			Received int64 `json:"received"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if body.Received != 40 {
			t.Errorf("offset %d: server said received=%d, want 40 so the client can resume", off, body.Received)
		}
	}
	if rec := do(t, mux, "PUT", "/api/cases/"+c.ID+"/uploads/"+u.ID, data[40:], nil); rec.Code != http.StatusBadRequest {
		t.Errorf("a chunk with no Upload-Offset header: %d, want 400", rec.Code)
	}
}

func TestUpload_NeverAcceptsMoreThanWasDeclared(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Overrun")
	u := initUpload(t, mux, c.ID, "a.zip", bytes.Repeat([]byte("x"), 10), false)
	if rec := putChunk(t, mux, c.ID, u.ID, 0, bytes.Repeat([]byte("x"), 20)); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status %d, want 413", rec.Code)
	}
	st := do(t, mux, "GET", "/api/cases/"+c.ID+"/uploads/"+u.ID, nil, nil)
	var s model.UploadSession
	mustDecode(t, st, &s)
	if s.Received != 0 {
		t.Errorf("a rejected chunk still advanced the offset to %d", s.Received)
	}
}

func TestUpload_SizeOverTheServerLimitIsRefusedUpFront(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Too big")
	b, _ := json.Marshal(map[string]any{"filename": "huge.zip", "size": testMaxUploadBytes + 1})
	if rec := do(t, mux, "POST", "/api/cases/"+c.ID+"/uploads", b, nil); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status %d, want 413 before a single byte is sent", rec.Code)
	}
	for _, bad := range []string{`{"filename":"a","size":0}`, `{"filename":"","size":5}`, `{"filename":"a","size":-1}`, `{"filename":"a","size":5,"sha256":"xyz"}`} {
		if rec := do(t, mux, "POST", "/api/cases/"+c.ID+"/uploads", []byte(bad), nil); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", bad, rec.Code)
		}
	}
}

func TestUpload_CompletionChecksSizeAndTheCorruptFileFailsTheJob(t *testing.T) {
	svc := newTestService(t)
	svc.pipe.poll = 10 * time.Millisecond
	mux := routerFor(svc)
	startWorker(t, svc)
	c := mustCreateCase(t, mux, "Verify")
	data := buildKAPEZip(t)

	short := initUpload(t, mux, c.ID, "a.zip", data, false)
	putChunk(t, mux, c.ID, short.ID, 0, data[:len(data)/2])
	if rec := completeUpload(t, mux, c.ID, short.ID); rec.Code != http.StatusConflict {
		t.Errorf("incomplete upload: status %d, want 409", rec.Code)
	}
	if rec, _ := enqueue(t, mux, c.ID, map[string]any{"upload_id": short.ID}); rec.Code != http.StatusConflict {
		t.Errorf("enqueue of an incomplete upload: %d, want 409", rec.Code)
	}

	// The declared hash is of different bytes than were sent. Completion
	// only confirms the byte count: hashing a very large file inside one
	// HTTP request would outlast any timeout. The pipeline verifies the
	// digest, and a mismatch fails the job before any evidence exists.
	b, _ := json.Marshal(map[string]any{"filename": "b.zip", "size": len(data), "sha256": sha([]byte("something else"))})
	var bad model.UploadSession
	mustDecode(t, do(t, mux, "POST", "/api/cases/"+c.ID+"/uploads", b, nil), &bad)
	sendInChunks(t, mux, c.ID, bad.ID, data, 2)
	if rec := completeUpload(t, mux, c.ID, bad.ID); rec.Code != http.StatusOK {
		t.Fatalf("complete: %d %s", rec.Code, rec.Body.String())
	}
	_, job := enqueue(t, mux, c.ID, map[string]any{"upload_id": bad.ID})
	done := waitPipelineJob(t, mux, c.ID, job.ID)
	if done.Status != model.JobFailed || !strings.Contains(done.Error, "SHA-256") {
		t.Fatalf("job = %+v, want failed with a hash mismatch", done)
	}
	if cols, _ := svc.store.ListCollections(c.ID); len(cols) != 0 {
		t.Error("corrupt evidence was recorded in the case")
	}
}

func TestUpload_BelongsToItsCase(t *testing.T) {
	mux := newTestRouter(t)
	a := mustCreateCase(t, mux, "Case A")
	b := mustCreateCase(t, mux, "Case B")
	data := []byte("0123456789")
	u := initUpload(t, mux, a.ID, "a.zip", data, false)

	if rec := do(t, mux, "GET", "/api/cases/"+b.ID+"/uploads/"+u.ID, nil, nil); rec.Code != http.StatusNotFound {
		t.Errorf("status via another case: %d, want 404", rec.Code)
	}
	if rec := putChunk(t, mux, b.ID, u.ID, 0, data); rec.Code != http.StatusNotFound {
		t.Errorf("writing via another case: %d, want 404", rec.Code)
	}
	sendInChunks(t, mux, a.ID, u.ID, data, 1)
	completeUpload(t, mux, a.ID, u.ID)
	if rec, _ := enqueue(t, mux, b.ID, map[string]any{"upload_id": u.ID}); rec.Code != http.StatusNotFound {
		t.Errorf("enqueue with another case's upload: %d, want 404", rec.Code)
	}
}

func TestUpload_AbortRemovesTheBytesAndRefusesMore(t *testing.T) {
	svc := newTestService(t)
	mux := routerFor(svc)
	c := mustCreateCase(t, mux, "Abort")
	data := bytes.Repeat([]byte("x"), 100)
	u := initUpload(t, mux, c.ID, "a.zip", data, false)
	putChunk(t, mux, c.ID, u.ID, 0, data[:50])

	if rec := do(t, mux, "POST", "/api/cases/"+c.ID+"/uploads/"+u.ID+"/abort", nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("abort: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(svc.files.UploadSessionPath(c.ID, u.ID)); !os.IsNotExist(err) {
		t.Error("the partial file survived an abort")
	}
	if rec := putChunk(t, mux, c.ID, u.ID, 50, data[50:]); rec.Code != http.StatusConflict {
		t.Errorf("bytes after abort: %d, want 409", rec.Code)
	}
}

func TestUpload_StaleOpenSessionsArePurged(t *testing.T) {
	svc := newTestService(t)
	mux := routerFor(svc)
	c := mustCreateCase(t, mux, "Stale")
	u := initUpload(t, mux, c.ID, "a.zip", []byte("0123456789"), false)
	putChunk(t, mux, c.ID, u.ID, 0, []byte("01234"))

	if n, err := svc.PurgeStaleUploads(time.Hour); err != nil || n != 0 {
		t.Fatalf("a fresh session must survive: n=%d err=%v", n, err)
	}
	time.Sleep(20 * time.Millisecond)
	if n, err := svc.PurgeStaleUploads(time.Millisecond); err != nil || n != 1 {
		t.Fatalf("purged %d (err %v), want 1", n, err)
	}
	if _, err := os.Stat(svc.files.UploadSessionPath(c.ID, u.ID)); !os.IsNotExist(err) {
		t.Error("the stale file was left on disk")
	}
	s, _ := svc.store.GetUploadSession(u.ID)
	if s.Status != model.UploadAborted {
		t.Errorf("status = %q", s.Status)
	}
}

func TestUpload_ChunkRoutesNeedOnlyAnalystRole(t *testing.T) {
	for _, tc := range []struct{ m, p string }{
		{"POST", "/api/cases/x/uploads"}, {"PUT", "/api/cases/x/uploads/y"},
		{"POST", "/api/cases/x/uploads/y/complete"}, {"POST", "/api/cases/x/uploads/y/abort"},
		{"POST", "/api/cases/x/pipeline/jobs"}, {"POST", "/api/cases/x/pipeline/jobs/j/cancel"},
	} {
		if role, ok := requiredRole(tc.m, tc.p); !ok || role != "analyst" {
			t.Errorf("%s %s requires %q (ok=%v), want analyst: an analyst must be able to upload their own evidence", tc.m, tc.p, role, ok)
		}
	}
}

// ---------------------------------------------------------------- pipeline

func TestPipeline_LocalPathRunsDiscoverImportAnalyze(t *testing.T) {
	svc := newTestService(t)
	svc.pipe.poll = 10 * time.Millisecond
	mux := routerFor(svc)
	startWorker(t, svc)
	c := mustCreateCase(t, mux, "Local")

	rec, job := enqueue(t, mux, c.ID, map[string]any{"local_path": synthPath})
	if rec.Code != http.StatusAccepted || job.Status != model.JobQueued {
		t.Fatalf("enqueue: %d %+v", rec.Code, job)
	}
	done := waitPipelineJob(t, mux, c.ID, job.ID)
	if done.Status != model.JobSucceeded {
		t.Fatalf("job = %+v", done)
	}
	if num(done.Result, "files_imported") != 5 || num(done.Result, "findings") == 0 {
		t.Errorf("result = %+v", done.Result)
	}
	var found bool
	log, _ := svc.store.ListAuditLog(c.ID)
	for _, e := range log {
		if e.Action == model.AuditAnalysisCompleted {
			found = true
		}
	}
	if !found {
		t.Error("the pipeline's analysis is not in the audit trail")
	}
}

func TestPipeline_AnalysisCanBeSkipped(t *testing.T) {
	svc := newTestService(t)
	svc.pipe.poll = 10 * time.Millisecond
	mux := routerFor(svc)
	startWorker(t, svc)
	c := mustCreateCase(t, mux, "No analysis")
	_, job := enqueue(t, mux, c.ID, map[string]any{"local_path": synthPath, "analyze": false})
	done := waitPipelineJob(t, mux, c.ID, job.ID)
	if done.Status != model.JobSucceeded {
		t.Fatalf("job = %+v", done)
	}
	if got, _ := svc.store.GetCase(c.ID); got.Status == model.CaseStatusAnalyzed {
		t.Error("analysis ran although it was declined")
	}
}

func TestPipeline_ResumesAnInterruptedJobWithoutDiscoveringAgain(t *testing.T) {
	dir := t.TempDir()
	dbPath, data := filepath.Join(dir, "t.db"), filepath.Join(dir, "data")

	svc1, closeFirst := serviceAt(t, dbPath, data)
	mux1 := routerFor(svc1)
	c := mustCreateCase(t, mux1, "Crash")
	disc, err := svc1.DiscoverEvidenceFromPath(c.ID, synthPath) // the server died right after this
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	_ = svc1.store.CreatePipelineJob(model.PipelineJob{
		ID: "job-crash", CaseID: c.ID, Kind: model.JobKindIngest, Status: model.JobQueued, Stage: model.StageQueued,
		Params: `{"local_path":"` + synthPath + `"}`, CreatedBy: "local-user", CreatedAt: now, UpdatedAt: now,
	})
	_, _, _ = svc1.store.ClaimNextPipelineJob(now) // running, attempts=1
	stage, coll := model.StageImport, disc.Collection.ID
	_ = svc1.store.UpdatePipelineJob("job-crash", store.JobUpdate{Stage: &stage, CollectionID: &coll}, now)
	closeFirst()

	svc2, closeSecond := serviceAt(t, dbPath, data)
	defer closeSecond()
	mux2 := routerFor(svc2)
	if req, fail, err := svc2.RecoverPipeline(); err != nil || req != 1 || fail != 0 {
		t.Fatalf("recover = %d/%d err=%v, want 1/0", req, fail, err)
	}
	startWorker(t, svc2)

	done := waitPipelineJob(t, mux2, c.ID, "job-crash")
	if done.Status != model.JobSucceeded || done.Attempts != 2 {
		t.Fatalf("job = %+v, want succeeded on its second attempt", done)
	}
	if cols, _ := svc2.store.ListCollections(c.ID); len(cols) != 1 {
		t.Errorf("%d collections: the resumed job discovered the evidence a second time", len(cols))
	}
	if num(done.Result, "findings") == 0 {
		t.Errorf("result = %+v", done.Result)
	}
}

func TestPipeline_ResumeAdoptsEvidenceItAlreadyDiscoveredButNeverRecorded(t *testing.T) {
	dir := t.TempDir()
	dbPath, data := filepath.Join(dir, "t.db"), filepath.Join(dir, "data")
	svc1, closeFirst := serviceAt(t, dbPath, data)
	mux1 := routerFor(svc1)
	c := mustCreateCase(t, mux1, "Adopt")
	if _, err := svc1.DiscoverEvidenceFromPath(c.ID, synthPath); err != nil { // committed, but the job never saved its checkpoint
		t.Fatal(err)
	}
	now := time.Now().UTC()
	_ = svc1.store.CreatePipelineJob(model.PipelineJob{
		ID: "job-adopt", CaseID: c.ID, Kind: model.JobKindIngest, Status: model.JobQueued, Stage: model.StageQueued,
		Params: `{"local_path":"` + synthPath + `"}`, CreatedBy: "local-user", CreatedAt: now, UpdatedAt: now,
	})
	_, _, _ = svc1.store.ClaimNextPipelineJob(now)
	closeFirst()

	svc2, closeSecond := serviceAt(t, dbPath, data)
	defer closeSecond()
	_, _, _ = svc2.RecoverPipeline()
	startWorker(t, svc2)
	done := waitPipelineJob(t, routerFor(svc2), c.ID, "job-adopt")
	if done.Status != model.JobSucceeded {
		t.Fatalf("job = %+v", done)
	}
	if cols, _ := svc2.store.ListCollections(c.ID); len(cols) != 1 {
		t.Errorf("%d collections", len(cols))
	}
}

func TestPipeline_AFreshJobForEvidenceAlreadyInTheCaseFailsInsteadOfAdopting(t *testing.T) {
	svc := newTestService(t)
	svc.pipe.poll = 10 * time.Millisecond
	mux := routerFor(svc)
	startWorker(t, svc)
	c := mustCreateCase(t, mux, "Dup")
	if _, err := svc.DiscoverEvidenceFromPath(c.ID, synthPath); err != nil {
		t.Fatal(err)
	}
	_, job := enqueue(t, mux, c.ID, map[string]any{"local_path": synthPath})
	done := waitPipelineJob(t, mux, c.ID, job.ID)
	if done.Status != model.JobFailed || !strings.Contains(done.Error, "already been added") {
		t.Errorf("a user submitting the same evidence twice must be told so: %+v", done)
	}
}

func TestPipeline_FailureIsReportedAndLeavesTheCaseAlone(t *testing.T) {
	svc := newTestService(t)
	svc.pipe.poll = 10 * time.Millisecond
	mux := routerFor(svc)
	startWorker(t, svc)
	c := mustCreateCase(t, mux, "Bad path")
	_, job := enqueue(t, mux, c.ID, map[string]any{"local_path": "/definitely/not/here"})
	done := waitPipelineJob(t, mux, c.ID, job.ID)
	if done.Status != model.JobFailed || done.Stage != model.StageFailed || done.Error == "" {
		t.Fatalf("job = %+v", done)
	}
	if strings.Contains(done.Error, "goroutine") || strings.Contains(done.Error, ".go:") {
		t.Errorf("internals leaked into a client-visible error: %q", done.Error)
	}
	if cols, _ := svc.store.ListCollections(c.ID); len(cols) != 0 {
		t.Error("a failed discovery left a collection behind")
	}
}

func TestPipeline_ALockedCaseRefusesJobsUpFront(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Locked")
	b, _ := json.Marshal(map[string]string{"case_status": "closed"})
	if rec := do(t, mux, "PATCH", "/api/cases/"+c.ID, b, nil); rec.Code != http.StatusOK {
		t.Fatalf("closing the case: %d %s", rec.Code, rec.Body.String())
	}
	if rec, _ := enqueue(t, mux, c.ID, map[string]any{"local_path": synthPath}); rec.Code != http.StatusConflict {
		t.Errorf("status %d, want 409: a closed case must not accept evidence, and the analyst should hear it now, not from a failed job later", rec.Code)
	}
}

func TestPipeline_RequestsMustNameExactlyOneSource(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Sources")
	for name, body := range map[string]map[string]any{
		"none": {}, "both": {"upload_id": "u", "local_path": "/x"},
	} {
		if rec, _ := enqueue(t, mux, c.ID, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, rec.Code)
		}
	}
	if rec, _ := enqueue(t, mux, c.ID, map[string]any{"upload_id": "does-not-exist"}); rec.Code != http.StatusNotFound {
		t.Errorf("unknown upload: status %d, want 404", rec.Code)
	}
}

func TestPipeline_QueuedJobCanBeCancelledAndIsNeverRun(t *testing.T) {
	svc := newTestService(t)
	svc.pipe.poll = 10 * time.Millisecond
	mux := routerFor(svc)
	c := mustCreateCase(t, mux, "Cancel")
	_, job := enqueue(t, mux, c.ID, map[string]any{"local_path": synthPath})

	if rec := do(t, mux, "POST", "/api/cases/"+c.ID+"/pipeline/jobs/"+job.ID+"/cancel", nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("cancel: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(t, mux, "POST", "/api/cases/"+c.ID+"/pipeline/jobs/"+job.ID+"/cancel", nil, nil); rec.Code != http.StatusOK {
		t.Errorf("a second cancel must be harmless, got %d", rec.Code)
	}
	if got := getJob(t, mux, c.ID, job.ID); got.Status != model.JobCancelled {
		t.Fatalf("status = %q, want cancelled", got.Status)
	}
	startWorker(t, svc)
	time.Sleep(150 * time.Millisecond)
	if cols, _ := svc.store.ListCollections(c.ID); len(cols) != 0 {
		t.Error("a cancelled job ran anyway")
	}
}

func TestPipeline_JobsAreScopedToTheirCase(t *testing.T) {
	mux := newTestRouter(t)
	a := mustCreateCase(t, mux, "Scope A")
	b := mustCreateCase(t, mux, "Scope B")
	_, job := enqueue(t, mux, a.ID, map[string]any{"local_path": synthPath})
	if rec := do(t, mux, "GET", "/api/cases/"+b.ID+"/pipeline/jobs/"+job.ID, nil, nil); rec.Code != http.StatusNotFound {
		t.Errorf("read via another case: %d, want 404", rec.Code)
	}
	if rec := do(t, mux, "POST", "/api/cases/"+b.ID+"/pipeline/jobs/"+job.ID+"/cancel", nil, nil); rec.Code != http.StatusNotFound {
		t.Errorf("cancel via another case: %d, want 404", rec.Code)
	}
	var list []jobView
	mustDecode(t, do(t, mux, "GET", "/api/cases/"+b.ID+"/pipeline/jobs", nil, nil), &list)
	if len(list) != 0 {
		t.Errorf("case B lists %d of case A's jobs", len(list))
	}
}

func TestPipeline_JobsRunOneAtATimeOldestFirst(t *testing.T) {
	svc := newTestService(t)
	svc.pipe.poll = 10 * time.Millisecond
	mux := routerFor(svc)
	a := mustCreateCase(t, mux, "Order A")
	b := mustCreateCase(t, mux, "Order B")
	_, ja := enqueue(t, mux, a.ID, map[string]any{"local_path": synthPath})
	time.Sleep(5 * time.Millisecond)
	_, jb := enqueue(t, mux, b.ID, map[string]any{"local_path": synthPath})
	startWorker(t, svc)

	da, db := waitPipelineJob(t, mux, a.ID, ja.ID), waitPipelineJob(t, mux, b.ID, jb.ID)
	if da.Status != model.JobSucceeded || db.Status != model.JobSucceeded {
		t.Fatalf("a=%+v b=%+v", da, db)
	}
	x, _ := svc.store.GetPipelineJob(ja.ID)
	y, _ := svc.store.GetPipelineJob(jb.ID)
	if y.StartedAt.Before(*x.FinishedAt) {
		t.Errorf("job B started at %v before job A finished at %v: two heavy jobs overlapped", y.StartedAt, x.FinishedAt)
	}
}
