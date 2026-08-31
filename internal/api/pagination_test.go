package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

// paginate is the primitive every paginated endpoint is built on, so its
// boundaries are worth pinning down directly rather than only through
// the endpoints that use it.
func TestPaginate_Boundaries(t *testing.T) {
	all := make([]int, 0, 250)
	for i := 0; i < 250; i++ {
		all = append(all, i)
	}

	cases := []struct {
		name       string
		page, size int
		wantLen    int
		wantFirst  int
		wantPages  int
	}{
		{"first page", 1, 100, 100, 0, 3},
		{"middle page", 2, 100, 100, 100, 3},
		{"partial last page", 3, 100, 50, 200, 3},
		{"exact division", 1, 50, 50, 0, 5},
		{"past the end", 9, 100, 0, 0, 3},
		{"far past the end", 10000, 25, 0, 0, 10},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := paginate(all, PageRequest{Page: tc.page, PageSize: tc.size})
			if len(p.Items) != tc.wantLen {
				t.Errorf("len(items) = %d, want %d", len(p.Items), tc.wantLen)
			}
			if tc.wantLen > 0 && p.Items[0] != tc.wantFirst {
				t.Errorf("items[0] = %d, want %d", p.Items[0], tc.wantFirst)
			}
			if p.TotalPages != tc.wantPages {
				t.Errorf("total_pages = %d, want %d", p.TotalPages, tc.wantPages)
			}
			if p.Total != 250 {
				t.Errorf("total = %d, want 250 -- the true total must survive every page", p.Total)
			}
		})
	}
}

// An out-of-range page must report EMPTY, not clamp to the last page.
// Clamping answers a different question than the one asked, and a caller
// that believed it was reading page 90 would be reading page 3.
func TestPaginate_PastEndDoesNotClampToLastPage(t *testing.T) {
	all := []string{"a", "b", "c"}
	p := paginate(all, PageRequest{Page: 5, PageSize: 2})
	if len(p.Items) != 0 {
		t.Errorf("page 5 of 2 returned %v; want an empty page, not the last one", p.Items)
	}
	if p.Number != 5 {
		t.Errorf("page = %d, want the requested 5 so the caller can see it overshot", p.Number)
	}
	if p.TotalPages != 2 {
		t.Errorf("total_pages = %d, want 2", p.TotalPages)
	}
}

// An empty page must serialize as [] -- a null would crash the dashboard
// the moment it mapped over it, the same bug class fixed in Phase 8.
func TestPaginate_EmptyPageSerializesAsArray(t *testing.T) {
	p := paginate([]string{}, PageRequest{Page: 1, PageSize: 25})
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["items"] == nil {
		t.Errorf("items serialized as null: %s", b)
	}
}

// Every record appears exactly once across the pages, and none is
// skipped. For evidence selection this is a correctness property, not a
// cosmetic one.
func TestPaginate_CoversEveryRecordExactlyOnce(t *testing.T) {
	for _, size := range []int{25, 50, 100, 250} {
		all := make([]int, 0, 617)
		for i := 0; i < 617; i++ {
			all = append(all, i)
		}
		seen := map[int]int{}
		pages := paginate(all, PageRequest{Page: 1, PageSize: size}).TotalPages
		for p := 1; p <= pages; p++ {
			for _, v := range paginate(all, PageRequest{Page: p, PageSize: size}).Items {
				seen[v]++
			}
		}
		if len(seen) != 617 {
			t.Errorf("page_size=%d: saw %d of 617 records", size, len(seen))
		}
		for v, n := range seen {
			if n != 1 {
				t.Errorf("page_size=%d: record %d appeared %d times", size, v, n)
			}
		}
	}
}

func TestParsePageRequest_ClampsAndEnforcesTheAllowList(t *testing.T) {
	req := func(query string) PageRequest {
		r := httptest.NewRequest("GET", "/x?"+query, nil)
		return parsePageRequest(r, evidencePageSizes, defaultEvidencePageSize)
	}

	if got := req(""); got.Page != 1 || got.PageSize != defaultEvidencePageSize {
		t.Errorf("no params: %+v, want page 1 at the default size", got)
	}
	if got := req("page=0"); got.Page != 1 {
		t.Errorf("page=0 -> %d, want 1", got.Page)
	}
	if got := req("page=-5"); got.Page != 1 {
		t.Errorf("page=-5 -> %d, want 1", got.Page)
	}
	if got := req("page=abc"); got.Page != 1 {
		t.Errorf("page=abc -> %d, want 1", got.Page)
	}
	for _, size := range evidencePageSizes {
		if got := req("page_size=" + itoa(size)); got.PageSize != size {
			t.Errorf("page_size=%d was not honored (got %d)", size, got.PageSize)
		}
	}
	// The allow-list is the whole point: an arbitrary size is how a
	// caller asks the server to materialize an unbounded response.
	for _, bad := range []string{"0", "-1", "7", "999999", "abc", "1e6"} {
		if got := req("page_size=" + bad); got.PageSize != defaultEvidencePageSize {
			t.Errorf("page_size=%s produced %d; it must fall back to the default", bad, got.PageSize)
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
