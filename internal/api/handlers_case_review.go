package api

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"tracefall/internal/narrative"
	"tracefall/internal/store"
)

func (h *handlers) reviewFail(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, sql.ErrNoRows):
		writeError(w, 404, "batch plan not found in this case")
	case errors.Is(err, context.DeadlineExceeded):
		writeError(w, 408, "bounded local preparation deadline exceeded; no requests sent")
	case errors.Is(err, store.ErrReviewSnapshotLimit), errors.Is(err, narrative.ErrLeak):
		writeError(w, 422, err.Error())
	case errors.Is(err, ErrNarrativeEgress), errors.Is(err, ErrNarrativeNeedsAck):
		writeError(w, http.StatusForbidden, err.Error())
	case errors.Is(err, ErrNarrativeNotConfigured):
		writeError(w, http.StatusNotImplemented, err.Error())
	case errors.Is(err, errReviewRunning), errors.Is(err, errReviewPreviewChanged), errors.Is(err, errLLMConfigurationBusy):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, errReviewEmpty), errors.Is(err, ErrNarrativeRefused), errors.Is(err, narrative.ErrReviewTooLarge), errors.Is(err, errReviewBudgetEmpty):
		writeError(w, http.StatusUnprocessableEntity, err.Error())
	default:
		return h.fail(w, err)
	}
	return true
}
func (h *handlers) getCaseReview(w http.ResponseWriter, r *http.Request) {
	v, err := h.as(r).CaseReviewStatus(r.PathValue("id"))
	if !h.reviewFail(w, err) {
		writeJSON(w, 200, v)
	}
}
func (h *handlers) previewCaseReview(w http.ResponseWriter, r *http.Request) {
	v, err := h.as(r).PreviewCaseReview(r.PathValue("id"))
	if !h.reviewFail(w, err) {
		writeJSON(w, 200, v)
	}
}
func (h *handlers) getCaseReviewPayload(w http.ResponseWriter, r *http.Request) {
	v, ok, err := h.as(r).LatestCaseReviewPayload(r.PathValue("id"))
	if h.reviewFail(w, err) {
		return
	}
	if !ok {
		writeError(w, 404, "no bounded case review has been requested")
		return
	}
	writeJSON(w, 200, v)
}
func (h *handlers) startCaseReview(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Acknowledge bool   `json:"acknowledge"`
		PreviewKey  string `json:"preview_key"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	v, err := h.as(r).StartCaseReview(r.PathValue("id"), body.Acknowledge, body.PreviewKey)
	if !h.reviewFail(w, err) {
		writeJSON(w, http.StatusAccepted, v)
	}
}
func (h *handlers) cancelCaseReview(w http.ResponseWriter, r *http.Request) {
	if !h.reviewFail(w, h.as(r).CancelCaseReview(r.PathValue("id"))) {
		w.WriteHeader(http.StatusNoContent)
	}
}
