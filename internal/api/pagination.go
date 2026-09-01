package api

import (
	"net/http"
	"strconv"
)

// Pagination for large evidence sets (Phase 10B).
//
// One envelope and one request parser serve every paginated endpoint, so
// the four screens that need pagination share a single definition of
// what a page is rather than four subtly different ones.
//
// The forensic constraint that shapes this file: a page is a VIEW, never
// a filter on what exists. Every paginated response carries the true
// total of matching records, so an investigator is never left believing
// a page boundary is the end of the evidence.

// Page is the envelope every paginated endpoint returns.
//
// Items is always a non-nil slice: an empty page serializes as [], not
// null, so the dashboard never has to defend against a null it would
// then try to map over.
type Page[T any] struct {
	Items []T `json:"items"`
	// Number is the 1-based page index. It is not called "Page" because
	// this struct is embedded (see EvidenceFilePage), and a field with
	// the same name as its own type shadows the embedded struct at every
	// use site. The JSON name is unaffected.
	Number     int `json:"page"`
	PageSize   int `json:"page_size"`
	Total      int `json:"total"`
	TotalPages int `json:"total_pages"`
}

// PageRequest is a validated page/page_size pair.
type PageRequest struct {
	Page     int
	PageSize int
}

// Page sizes are a fixed allow-list rather than any integer the caller
// sends. An arbitrary page_size is a trivial way to ask the server to
// materialize an unbounded response, which is exactly what pagination
// exists to prevent.
var (
	// 10 is the smallest offered size (Phase 13). A dense evidence or
	// error row carries a filename, a path, a type, a status and a
	// reason; ten of those is about what fits on screen without
	// scrolling, and scanning them is the actual task. The larger sizes
	// remain for anyone who would rather scroll than page.
	evidencePageSizes = []int{10, 25, 50, 100, 250}
	recordPageSizes   = []int{10, 25, 50, 100}
	timelinePageSizes = []int{10, 25, 50, 100, 250}
)

const (
	// Defaults are 10 (Phase 13, down from 100/50). The previous
	// defaults were chosen to reduce paging; in practice they produced a
	// wall of rows that had to be scrolled past before the pager was even
	// visible.
	defaultEvidencePageSize = 10
	defaultRecordPageSize   = 10
)

// parsePageRequest reads page/page_size from the query string.
//
// Invalid input is CLAMPED rather than rejected: a bad page number is a
// navigation mistake, not a forensic one, and returning page 1 is more
// useful than a 400. An out-of-range page_size falls back to the
// default rather than being honored, so the allow-list cannot be
// bypassed by sending page_size=1000000.
func parsePageRequest(r *http.Request, allowed []int, defaultSize int) PageRequest {
	page, err := strconv.Atoi(r.URL.Query().Get("page"))
	if err != nil || page < 1 {
		page = 1
	}
	size := defaultSize
	if raw := r.URL.Query().Get("page_size"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			for _, ok := range allowed {
				if n == ok {
					size = n
					break
				}
			}
		}
	}
	return PageRequest{Page: page, PageSize: size}
}

// paginate slices one page out of an already-filtered, already-ordered
// set.
//
// Ordering is the caller's responsibility and must be deterministic:
// paging through a non-deterministic order would show the same record
// twice and skip another, which for evidence selection is a correctness
// bug, not a cosmetic one.
//
// A page number past the end returns an EMPTY page rather than clamping
// to the last page. Clamping would silently answer a different question
// than the one asked -- the caller asked for page 90 of 71 and gets told
// there is nothing there, with Total and TotalPages available to correct
// itself.
func paginate[T any](all []T, req PageRequest) Page[T] {
	total := len(all)
	totalPages := 0
	if req.PageSize > 0 {
		totalPages = (total + req.PageSize - 1) / req.PageSize
	}

	start := (req.Page - 1) * req.PageSize
	if start > total {
		start = total
	}
	end := start + req.PageSize
	if end > total {
		end = total
	}

	items := make([]T, 0, end-start)
	items = append(items, all[start:end]...)

	return Page[T]{
		Items:      items,
		Number:     req.Page,
		PageSize:   req.PageSize,
		Total:      total,
		TotalPages: totalPages,
	}
}
