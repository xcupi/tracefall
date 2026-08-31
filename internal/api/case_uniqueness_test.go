package api

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"tracefall/internal/model"
)

// createCase POSTs a case and returns the response recorder, without the
// createTestCase helper's baked-in assumption that creation succeeds --
// duplicate-name tests need to inspect a rejected response.
func createCase(t *testing.T, mux http.Handler, name string) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, mux, "POST", "/api/cases", map[string]string{"name": name}, nil)
}

// TestCaseNameUniqueness_ExactDuplicate covers items 1-3: first creation
// succeeds, the exact same name again is rejected with 409 identifying
// the existing case, and no second case is created.
func TestCaseNameUniqueness_ExactDuplicate(t *testing.T) {
	mux := newTestRouter(t)

	rec := createCase(t, mux, "WKSTN-042 Phishing Triage")
	if rec.Code != http.StatusCreated {
		t.Fatalf("first case: status %d, body %s", rec.Code, rec.Body.String())
	}
	var first model.Case
	mustDecode(t, rec, &first)

	rec = createCase(t, mux, "WKSTN-042 Phishing Triage")
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate case: status %d, want %d, body %s", rec.Code, http.StatusConflict, rec.Body.String())
	}
	var dupBody struct {
		Error             string `json:"error"`
		DuplicateCaseID   string `json:"duplicate_case_id"`
		DuplicateCaseName string `json:"duplicate_case_name"`
	}
	mustDecode(t, rec, &dupBody)
	if dupBody.DuplicateCaseID != first.ID {
		t.Errorf("duplicate_case_id = %q, want %q", dupBody.DuplicateCaseID, first.ID)
	}
	if dupBody.DuplicateCaseName != "WKSTN-042 Phishing Triage" {
		t.Errorf("duplicate_case_name = %q, want %q", dupBody.DuplicateCaseName, "WKSTN-042 Phishing Triage")
	}

	var cases []model.Case
	rec = doJSON(t, mux, "GET", "/api/cases", nil, &cases)
	if rec.Code != http.StatusOK {
		t.Fatalf("list cases: status %d", rec.Code)
	}
	if len(cases) != 1 {
		t.Fatalf("case count after duplicate = %d, want 1 (no second case created)", len(cases))
	}
	if cases[0].ID != first.ID || cases[0].Name != first.Name || !cases[0].CreatedAt.Equal(first.CreatedAt) {
		t.Errorf("existing case changed after rejected duplicate: got %+v, want unchanged from %+v", cases[0], first)
	}
}

// TestCaseNameUniqueness_WhitespaceDuplicate covers item 4 and the
// trimming half of the normalization requirement: leading/trailing
// whitespace must not be enough to bypass uniqueness.
func TestCaseNameUniqueness_WhitespaceDuplicate(t *testing.T) {
	mux := newTestRouter(t)

	rec := createCase(t, mux, "WKSTN-042 Phishing Triage")
	if rec.Code != http.StatusCreated {
		t.Fatalf("first case: status %d, body %s", rec.Code, rec.Body.String())
	}
	var first model.Case
	mustDecode(t, rec, &first)
	if first.Name != "WKSTN-042 Phishing Triage" {
		t.Errorf("stored name = %q, want unchanged (no leading/trailing whitespace to trim)", first.Name)
	}

	rec = createCase(t, mux, "  WKSTN-042 Phishing Triage  ")
	if rec.Code != http.StatusConflict {
		t.Fatalf("whitespace-padded duplicate: status %d, want %d, body %s", rec.Code, http.StatusConflict, rec.Body.String())
	}

	var cases []model.Case
	doJSON(t, mux, "GET", "/api/cases", nil, &cases)
	if len(cases) != 1 {
		t.Fatalf("case count after whitespace duplicate = %d, want 1", len(cases))
	}
}

// TestCaseNameUniqueness_CaseInsensitiveDuplicate covers item 5: per
// docs/data-model.md's "Case name uniqueness" section, uniqueness is
// case-insensitive for human-facing case names.
func TestCaseNameUniqueness_CaseInsensitiveDuplicate(t *testing.T) {
	mux := newTestRouter(t)

	rec := createCase(t, mux, "WKSTN-042 Phishing Triage")
	if rec.Code != http.StatusCreated {
		t.Fatalf("first case: status %d, body %s", rec.Code, rec.Body.String())
	}

	rec = createCase(t, mux, "wkstn-042 phishing triage")
	if rec.Code != http.StatusConflict {
		t.Fatalf("case-insensitive duplicate: status %d, want %d, body %s", rec.Code, http.StatusConflict, rec.Body.String())
	}

	var cases []model.Case
	doJSON(t, mux, "GET", "/api/cases", nil, &cases)
	if len(cases) != 1 {
		t.Fatalf("case count after case-insensitive duplicate = %d, want 1", len(cases))
	}
}

// TestCaseNameUniqueness_DifferentNameSucceeds covers item 6: uniqueness
// must not be so aggressive that it rejects genuinely different names.
func TestCaseNameUniqueness_DifferentNameSucceeds(t *testing.T) {
	mux := newTestRouter(t)

	rec := createCase(t, mux, "WKSTN-042 Phishing Triage")
	if rec.Code != http.StatusCreated {
		t.Fatalf("first case: status %d, body %s", rec.Code, rec.Body.String())
	}
	rec = createCase(t, mux, "WKSTN-043 Ransomware Triage")
	if rec.Code != http.StatusCreated {
		t.Fatalf("second (different-named) case: status %d, body %s", rec.Code, rec.Body.String())
	}

	var cases []model.Case
	doJSON(t, mux, "GET", "/api/cases", nil, &cases)
	if len(cases) != 2 {
		t.Fatalf("case count = %d, want 2", len(cases))
	}
}

// TestCaseNameUniqueness_ConcurrentCreation covers item 7 (race safety):
// many concurrent requests creating a case with the same name must
// result in exactly one case, not one-per-request. The SELECT-based
// pre-check alone (Service.checkDuplicateCase) can't guarantee this --
// see idx_cases_name_unique in internal/store/schema.go/migrate.go,
// enforced via Service.CreateCase's store.ErrDuplicateCase handling --
// so this fires requests in parallel to exercise that race window
// directly. Run with -race to also catch Go-level data races.
func TestCaseNameUniqueness_ConcurrentCreation(t *testing.T) {
	mux := newTestRouter(t)

	const attempts = 8
	var wg sync.WaitGroup
	codes := make([]int, attempts)
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := createCase(t, mux, "Concurrent Case Name")
			codes[i] = rec.Code
		}(i)
	}
	wg.Wait()

	var succeeded, conflicted int
	for _, code := range codes {
		switch code {
		case http.StatusCreated:
			succeeded++
		case http.StatusConflict:
			conflicted++
		default:
			t.Errorf("unexpected status %d among concurrent case creations", code)
		}
	}
	if succeeded != 1 {
		t.Errorf("got %d successful concurrent case creations, want exactly 1", succeeded)
	}
	if conflicted != attempts-1 {
		t.Errorf("got %d conflicted concurrent case creations, want %d", conflicted, attempts-1)
	}

	var cases []model.Case
	doJSON(t, mux, "GET", "/api/cases", nil, &cases)
	if len(cases) != 1 {
		t.Fatalf("case count after concurrent duplicate creation = %d, want 1", len(cases))
	}
}
