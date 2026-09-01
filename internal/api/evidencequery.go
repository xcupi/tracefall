package api

import (
	"net/http"
	"sort"
	"strings"

	"tracefall/internal/model"
)

// Server-side evidence filtering and pagination (Phase 10B).
//
// A logical image can catalog tens of thousands of files. Sending all of
// them to the browser so it can render 100 rows wastes the response, the
// parse, and the DOM -- so the filtering that decides WHICH files matter
// happens here, and the browser receives one page.
//
// # Why this filters in Go rather than in SQL
//
// The fields an investigator filters on -- artifact family, forensic
// priority, supported/unsupported -- are NOT stored columns. They are
// derived at read time from the capability registry (see triage.go),
// which is what guarantees the triage view can never drift from what the
// running binary can actually parse. Pushing them into SQL would mean
// persisting a classification, and a persisted classification goes stale
// the moment a parser is added.
//
// So the collection's rows are loaded, classified, filtered and paged
// here. The database read is local and bounded by one collection; what
// crosses the network is one page. That trade -- a local full scan to
// keep classification live -- is deliberate, and is the reason the
// Phase 9A invariant survives Phase 10B.

// EvidenceFilter is the server-side equivalent of the triage toolbar.
//
// Semantics are exactly Phase 9A's, unchanged: values WITHIN one
// multi-select are OR'd, and the separate filters are AND'd together.
// An empty selection means "no constraint", not "match nothing".
type EvidenceFilter struct {
	// Q is a free-text term matched case-insensitively against filename,
	// path, artifact labels and parser.
	Q string
	// Families, Priorities and Statuses are OR-sets.
	Families   []string
	Priorities []string
	Statuses   []string
	// RecommendedOnly restricts to importable high-value evidence.
	RecommendedOnly bool
}

// IsEmpty reports whether the filter constrains nothing.
func (f EvidenceFilter) IsEmpty() bool {
	return f.Q == "" && len(f.Families) == 0 && len(f.Priorities) == 0 &&
		len(f.Statuses) == 0 && !f.RecommendedOnly
}

// parseEvidenceFilter reads a filter from the query string. Repeated
// parameters form the OR-set (?priority=high&priority=critical), which
// is the conventional encoding and keeps each value individually
// escaped rather than relying on a delimiter that could appear in a
// value.
func parseEvidenceFilter(r *http.Request) EvidenceFilter {
	q := r.URL.Query()
	return EvidenceFilter{
		Q:               strings.TrimSpace(q.Get("q")),
		Families:        nonEmpty(q["family"]),
		Priorities:      nonEmpty(q["priority"]),
		Statuses:        nonEmpty(q["status"]),
		RecommendedOnly: q.Get("recommended") == "true",
	}
}

func nonEmpty(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// evidenceStatusValue collapses a file's capability and import state
// into the single status the filter offers. It mirrors the dashboard's
// function of the same name; both must agree, or a filter would mean one
// thing in the dropdown and another on the server.
func evidenceStatusValue(f TriagedSourceFile) string {
	switch f.ImportStatus {
	case model.SourceFileImported:
		return "imported"
	case model.SourceFileDuplicate:
		return "duplicate"
	case model.SourceFileFailed:
		return "failed"
	}
	if f.Supported {
		return "supported"
	}
	return "unsupported"
}

// matchesAny implements the OR within one multi-select. An empty set
// constrains nothing.
func matchesAny(set []string, value string) bool {
	if len(set) == 0 {
		return true
	}
	for _, v := range set {
		if strings.EqualFold(v, value) {
			return true
		}
	}
	return false
}

// Matches reports whether one file satisfies the whole filter.
func (f EvidenceFilter) Matches(sf TriagedSourceFile) bool {
	if f.Q != "" {
		haystack := strings.ToLower(strings.Join([]string{
			sf.OriginalFilename, sf.Path, sf.TypeLabel, sf.FamilyLabel, sf.ArtifactType, sf.Parser,
		}, " "))
		if !strings.Contains(haystack, strings.ToLower(f.Q)) {
			return false
		}
	}
	if !matchesAny(f.Families, sf.FamilyLabel) {
		return false
	}
	if !matchesAny(f.Priorities, sf.Priority) {
		return false
	}
	if !matchesAny(f.Statuses, evidenceStatusValue(sf)) {
		return false
	}
	if f.RecommendedOnly && !sf.Recommended {
		return false
	}
	return true
}

// EvidenceFilePage is one page of a collection's catalog, plus the facts
// the toolbar needs to describe the WHOLE catalog rather than the page.
type EvidenceFilePage struct {
	Page[TriagedSourceFile]
	// CollectionTotal is how many files the collection holds in total,
	// regardless of the filter -- so the UI can say "120 of 7,074"
	// rather than only knowing the filtered number.
	CollectionTotal int `json:"collection_total"`
	// SelectableTotal is how many of the MATCHING files could actually be
	// imported (supported and still discovered). This is what "select all
	// matching" will really select, and stating it separately stops
	// "7,074 matching" being mistaken for "7,074 importable".
	SelectableTotal int `json:"selectable_total"`
	// RecommendedTotal is how many of the MATCHING files are recommended
	// AND importable -- exactly what "Select recommended" will select.
	//
	// Scoped to the filter, not the whole catalog: the button's number
	// and the set it selects have to be the same thing, or the count on
	// screen describes an action other than the one the button performs.
	RecommendedTotal int `json:"recommended_total"`
	// Vocabularies are derived from the whole collection, never from the
	// current page -- a dropdown that only offered the current page's
	// values would shrink as you paged, which would be unusable.
	Families   []LabeledValue `json:"families"`
	Priorities []LabeledValue `json:"priorities"`
	Statuses   []LabeledValue `json:"statuses"`
}

// evidenceStatusLabels mirrors the dashboard's label map so the
// vocabulary is defined once, on the server, and the UI renders what it
// is given.
var evidenceStatusLabels = map[string]string{
	"supported":   "Supported (not imported)",
	"unsupported": "Unsupported",
	"imported":    "Imported",
	"duplicate":   "Duplicate",
	"failed":      "Parse error",
}

var priorityLabels = map[string]string{
	"critical": "Critical", "high": "High", "medium": "Medium",
	"low": "Low", "unknown": "Unknown",
}

// selectable reports whether a file can actually be imported. This is
// the single definition used by both "select all matching" and the
// import validation, so the count shown and the set acted on can never
// disagree.
func selectable(sf TriagedSourceFile) bool {
	return sf.Supported && sf.ImportStatus == model.SourceFileDiscovered
}

// catalogFor loads and classifies a collection's whole catalog in the
// collection's stored order.
//
// Order matters more than it looks: pagination over a non-deterministic
// order would show one file twice and skip another, which for evidence
// selection is a correctness bug. ListSourceFilesByCollection orders by
// path, and that order is preserved through classification.
func (s *Service) catalogFor(caseID, collectionID string) ([]TriagedSourceFile, error) {
	// The collection must belong to THIS case. Without this check a
	// collection ID from another case would page that case's evidence
	// through this case's URL.
	c, err := s.store.GetCollection(collectionID)
	if err != nil || c.CaseID != caseID {
		return nil, ErrCollectionNotFound
	}
	files, err := s.store.ListSourceFilesByCollection(collectionID)
	if err != nil {
		return nil, err
	}
	return triageAll(files), nil
}

// EvidenceFiles returns one filtered, ordered page of a collection.
func (s *Service) EvidenceFiles(caseID, collectionID string, filter EvidenceFilter, req PageRequest) (EvidenceFilePage, error) {
	catalog, err := s.catalogFor(caseID, collectionID)
	if err != nil {
		return EvidenceFilePage{}, err
	}

	matching := make([]TriagedSourceFile, 0, len(catalog))
	selectableCount, recommendedCount := 0, 0
	for _, sf := range catalog {
		if !filter.Matches(sf) {
			continue
		}
		matching = append(matching, sf)
		if selectable(sf) {
			selectableCount++
			if sf.Recommended {
				recommendedCount++
			}
		}
	}

	return EvidenceFilePage{
		Page:             paginate(matching, req),
		CollectionTotal:  len(catalog),
		SelectableTotal:  selectableCount,
		RecommendedTotal: recommendedCount,
		Families:         vocabulary(catalog, func(sf TriagedSourceFile) string { return sf.FamilyLabel }, nil),
		Priorities:       vocabulary(catalog, func(sf TriagedSourceFile) string { return sf.Priority }, priorityLabels),
		Statuses:         vocabulary(catalog, evidenceStatusValue, evidenceStatusLabels),
	}, nil
}

// EvidenceFileIDs resolves a filter to the stable IDs of every matching
// file that can actually be imported.
//
// This is what backs "select all matching". It returns IDs rather than
// records because the client needs identity, not content -- and because
// materializing the selection as an explicit set of STABLE IDs, at the
// moment the investigator asked for it, is what makes the selection
// auditable. The alternative (storing the filter and re-evaluating it at
// import time) would let the imported set differ from the set the
// investigator was looking at when they chose it.
//
// Only selectable files are returned: "select all matching" that
// included already-imported or unsupported files would produce a
// selection count that the import could never honor.
func (s *Service) EvidenceFileIDs(caseID, collectionID string, filter EvidenceFilter) ([]string, error) {
	catalog, err := s.catalogFor(caseID, collectionID)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(catalog))
	for _, sf := range catalog {
		if filter.Matches(sf) && selectable(sf) {
			ids = append(ids, sf.ID)
		}
	}
	return ids, nil
}

// vocabulary derives a filter dropdown's options from the whole catalog,
// sorted for a stable UI. Only values actually present are offered, so a
// dropdown never suggests a filter that would return nothing.
func vocabulary(catalog []TriagedSourceFile, value func(TriagedSourceFile) string, labels map[string]string) []LabeledValue {
	counts := map[string]int{}
	for _, sf := range catalog {
		if v := value(sf); v != "" {
			counts[v]++
		}
	}
	out := make([]LabeledValue, 0, len(counts))
	for v, n := range counts {
		label := v
		if labels != nil {
			if l, ok := labels[v]; ok {
				label = l
			}
		}
		out = append(out, LabeledValue{Value: v, Label: label, Count: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out
}
