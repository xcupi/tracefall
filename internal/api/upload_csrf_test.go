package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
)

// Evidence upload is a multipart POST, and Phase 12 made every
// state-changing request carry a CSRF token. The dashboard's uploader
// predates authentication and used XMLHttpRequest directly rather than
// the fetch wrapper that attaches the token, so uploads were rejected
// before the handler ran.
//
// The failure was hard to recognise: the middleware rejects WITHOUT
// reading the request body, and Go's server will not drain more than
// maxPostHandlerReadBytes (256 KB) of an unread body -- it closes the
// connection instead. A browser part-way through uploading a real
// evidence image therefore reported net::ERR_CONNECTION_RESET rather
// than the 403 that actually happened, which is why the terminal showed
// no error at all.
//
// These tests exercise the real HTTP multipart path, not the service
// layer, because that is where the defect lived.

// multipartUpload builds a genuine multipart/form-data request with a
// "file" part, exactly as a browser's FormData does.
func multipartUpload(t *testing.T, url, filename string, content []byte) *http.Request {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", url, &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

func realAD1(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("../../testdata/ad1_samples/DiskDrigger.ad1")
	if err != nil {
		t.Skipf("AD1 sample not available: %v", err)
	}
	return data
}

// uploadFixture returns an authenticated deployment plus a case to
// upload into, with the bootstrap gate already cleared.
func uploadFixture(t *testing.T) (*authFixture, *client, string) {
	t.Helper()
	f := newAuthFixture(t, time.Hour)
	f.mustCreateUser(t, "uploader", "uploader-password-12", model.RoleAnalyst)
	c, rec := f.login(t, "uploader", "uploader-password-12")
	if rec.Code != http.StatusOK {
		t.Fatalf("login: %d", rec.Code)
	}
	created := c.do("POST", "/api/cases", map[string]string{"name": "Upload CSRF case"})
	if created.Code != http.StatusCreated {
		t.Fatalf("create case: status %d, body %s", created.Code, created.Body.String())
	}
	var caseObj model.Case
	json.Unmarshal(created.Body.Bytes(), &caseObj)
	return f, c, caseObj.ID
}

// THE REGRESSION: an authenticated multipart upload that carries the
// CSRF token must succeed and discover the AD1.
func TestUpload_AD1MultipartSucceedsWithCSRFToken(t *testing.T) {
	f, c, caseID := uploadFixture(t)

	req := multipartUpload(t, "/api/cases/"+caseID+"/evidence", "DiskDrigger.ad1", realAD1(t))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: c.session})
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: c.csrf})
	req.Header.Set(csrfHeaderName, c.csrf)

	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("AD1 upload: status %d, body %s", rec.Code, rec.Body.String())
	}
	var disc DiscoverResult
	if err := json.Unmarshal(rec.Body.Bytes(), &disc); err != nil {
		t.Fatalf("decoding discovery result: %v", err)
	}
	if disc.Collection.SourceType != model.SourceTypeAD1 {
		t.Errorf("source_type = %q, want %q -- the upload was not recognized as an AD1 image",
			disc.Collection.SourceType, model.SourceTypeAD1)
	}
	if disc.Collection.OriginalFilename != "DiskDrigger.ad1" {
		t.Errorf("original_filename = %q", disc.Collection.OriginalFilename)
	}
	if disc.DiscoveredCount == 0 {
		t.Error("the AD1 upload discovered no files")
	}
	// Integrity metadata is recorded over the received bytes, unchanged.
	if len(disc.Collection.ArchiveHash) != 64 {
		t.Errorf("archive_hash is not a full SHA-256: %q", disc.Collection.ArchiveHash)
	}
	if len(disc.Collection.IntegritySHA512) != 128 {
		t.Errorf("integrity_sha512 is not a full SHA-512: %q", disc.Collection.IntegritySHA512)
	}
}

// The other half of the contract: CSRF is still ENFORCED on uploads.
// The fix must not have been to exempt the upload route.
func TestUpload_MultipartWithoutCSRFTokenIsStillRejected(t *testing.T) {
	f, c, caseID := uploadFixture(t)

	req := multipartUpload(t, "/api/cases/"+caseID+"/evidence", "DiskDrigger.ad1", realAD1(t))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: c.session})
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: c.csrf})
	// No X-Tracefall-CSRF header -- a cross-site form post.

	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("upload without a CSRF token: status %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "CSRF") {
		t.Errorf("rejection does not mention CSRF: %s", rec.Body.String())
	}
	// And nothing was ingested.
	list := c.do("GET", "/api/cases/"+caseID+"/evidence", nil)
	var collections []model.Collection
	json.Unmarshal(list.Body.Bytes(), &collections)
	if len(collections) != 0 {
		t.Errorf("a CSRF-less upload created %d collection(s)", len(collections))
	}
}

// A mismatched token is rejected too, not merely a missing one.
func TestUpload_MultipartWithMismatchedCSRFTokenIsRejected(t *testing.T) {
	f, c, caseID := uploadFixture(t)

	req := multipartUpload(t, "/api/cases/"+caseID+"/evidence", "DiskDrigger.ad1", realAD1(t))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: c.session})
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: c.csrf})
	req.Header.Set(csrfHeaderName, "a-different-token-entirely")

	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("mismatched CSRF token: status %d, want 403", rec.Code)
	}
}

// An unauthenticated upload is refused before CSRF is even considered.
func TestUpload_MultipartUnauthenticatedIsRejected(t *testing.T) {
	f, _, caseID := uploadFixture(t)

	req := multipartUpload(t, "/api/cases/"+caseID+"/evidence", "DiskDrigger.ad1", realAD1(t))
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated upload: status %d, want 401", rec.Code)
	}
}

// A body larger than Go's 256 KB undrained-body threshold is the size at
// which a rejected upload stopped being a readable 403 and became a
// connection reset in the browser. A correctly-tokened upload of that
// size must go through, so the fix is exercised at the size that
// actually failed.
func TestUpload_LargeMultipartBodySucceedsWithCSRFToken(t *testing.T) {
	f, c, caseID := uploadFixture(t)

	// Real AD1 header bytes followed by padding: large enough to exceed
	// maxPostHandlerReadBytes several times over.
	large := append(append([]byte{}, realAD1(t)...), bytes.Repeat([]byte{0}, 2<<20)...)

	req := multipartUpload(t, "/api/cases/"+caseID+"/evidence", "BigDrigger.ad1", large)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: c.session})
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: c.csrf})
	req.Header.Set(csrfHeaderName, c.csrf)

	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("large AD1 upload: status %d, body %s", rec.Code, truncate(rec.Body.String(), 300))
	}
	var disc DiscoverResult
	json.Unmarshal(rec.Body.Bytes(), &disc)
	if disc.UploadSizeBytes < int64(len(large)) {
		t.Errorf("upload_size_bytes = %d, want at least %d", disc.UploadSizeBytes, len(large))
	}
}

// The dashboard's uploader must attach the CSRF token. There is no
// JavaScript test harness in this project, and the defect was in the
// browser code rather than the server, so this asserts the one property
// whose absence caused it -- deliberately narrow, and paired with the
// HTTP tests above that pin the server contract.
func TestUpload_DashboardUploaderAttachesCSRFToken(t *testing.T) {
	src, err := os.ReadFile("../web/static/app.js")
	if err != nil {
		t.Fatalf("reading the dashboard source: %v", err)
	}
	start := bytes.Index(src, []byte("function apiUpload("))
	if start < 0 {
		t.Fatal("apiUpload is no longer present in app.js; update this test")
	}
	end := bytes.Index(src[start:], []byte("\nfunction "))
	if end < 0 {
		end = len(src) - start
	}
	body := string(src[start : start+end])

	if !strings.Contains(body, csrfHeaderName) {
		t.Errorf("apiUpload does not set the %s header; uploads will be rejected with 403, "+
			"and a large upload will surface as a connection reset", csrfHeaderName)
	}
	if !strings.Contains(body, "csrfToken()") {
		t.Error("apiUpload does not read the CSRF cookie via csrfToken()")
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

var _ = fmt.Sprintf
