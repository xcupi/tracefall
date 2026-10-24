package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"tracefall/internal/model"
	"tracefall/internal/narrative"
)

// Both routes are scoped by the stored review/run and case. There is deliberately
// no current-row fallback: UpsertEnrichment preserves IDs while replacing data.
func (h *handlers) getReviewVT(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.PathValue("reference"), "/")
	if len(parts) != 2 || parts[0] != "virustotal" || parts[1] == "" {
		h.reviewFail(w, sql.ErrNoRows)
		return
	}
	s := h.as(r)
	caseID := r.PathValue("id")
	id := parts[1]
	if _, err := s.GetCase(caseID); h.reviewFail(w, err) {
		return
	}
	dto, err := s.store.CaseReviewVT(caseID, r.PathValue("review"), id)
	if h.reviewFail(w, err) {
		return
	}
	writeJSON(w, 200, dto)
}
func (h *handlers) getBatchReviewVT(w http.ResponseWriter, r *http.Request) {
	s := h.as(r)
	caseID := r.PathValue("id")
	run := r.PathValue("run")
	id := r.PathValue("enrichment")
	if _, err := s.GetCase(caseID); h.reviewFail(w, err) {
		return
	}
	if _, _, err := s.store.BatchRun(caseID, run); h.reviewFail(w, err) {
		return
	}
	raw, err := s.store.BatchMemberJSON(caseID, run, "enrichment", id)
	if h.reviewFail(w, err) {
		return
	}
	var e model.Enrichment
	if err = json.Unmarshal(raw, &e); h.reviewFail(w, err) {
		return
	}
	if e.CaseID != caseID || e.Provider != "virustotal" || !narrative.ValidReviewVTIndicator(e) {
		h.reviewFail(w, sql.ErrNoRows)
		return
	}
	var links []string
	for _, eventID := range e.SourceEventIDs {
		ev, ok, err := s.store.BatchEvent(caseID, run, eventID)
		if h.reviewFail(w, err) {
			return
		}
		if ok && len(narrative.ReviewVTLinks(e, []model.Event{ev})) > 0 {
			links = append(links, eventID)
		}
	}
	writeJSON(w, 200, narrative.FreezeReviewVT(e, links, "batch_run_snapshot"))
}
