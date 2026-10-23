package api

import (
	"errors"
	"net/http"

	"tracefall/internal/egress"
)

// egressInfo is what GET /egress reports.
func egressInfo(level egress.Level) map[string]any {
	type opt struct {
		Level       string `json:"level"`
		Description string `json:"description"`
		Selectable  bool   `json:"selectable"`
	}
	var opts []opt
	for _, l := range []egress.Level{egress.None, egress.Hashes, egress.Pseudonymized, egress.Full} {
		opts = append(opts, opt{string(l), l.Describe(), l.Selectable()})
	}
	return map[string]any{"level": string(level), "description": level.Describe(), "options": opts}
}

// getEgress reports how much of the case may leave the server.
func (h *handlers) getEgress(w http.ResponseWriter, r *http.Request) {
	l, err := h.as(r).EgressLevel(r.PathValue("id"))
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, egressInfo(l))
}

// putEgress changes it. The change is recorded in the audit trail.
func (h *handlers) putEgress(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Level string `json:"level"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if _, perr := egress.Parse(body.Level); perr != nil {
		writeError(w, http.StatusBadRequest, perr.Error())
		return
	}
	l, err := h.as(r).SetEgressLevel(r.PathValue("id"), body.Level)
	if errors.Is(err, ErrEgressUnavailable) {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, egressInfo(l))
}

// getVirusTotal reports the case's VirusTotal state and stored answers. It
// sends nothing.
func (h *handlers) getVirusTotal(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	st, err := h.as(r).VirusTotalStatus(id)
	if h.fail(w, err) {
		return
	}
	res, err := h.as(r).VirusTotalResults(id)
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": st, "results": res})
}

// startVirusTotal begins the lookups in the background (202). It is refused
// unless the case's egress level allows file hashes to leave.
func (h *handlers) startVirusTotal(w http.ResponseWriter, r *http.Request) {
	st, err := h.as(r).StartVirusTotal(r.PathValue("id"))
	switch {
	case errors.Is(err, ErrEgressDenied):
		writeError(w, http.StatusForbidden, err.Error())
		return
	case errors.Is(err, ErrEnrichNotConfigured):
		writeError(w, http.StatusNotImplemented, err.Error())
		return
	case errors.Is(err, ErrEnrichRunning), errors.Is(err, ErrEnrichDailyLimit), errors.Is(err, ErrEnrichMonthlyLimit):
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusAccepted, st)
}

// cancelVirusTotal stops a running lookup.
func (h *handlers) cancelVirusTotal(w http.ResponseWriter, r *http.Request) {
	if h.fail(w, h.as(r).CancelVirusTotal(r.PathValue("id"))) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// getNarrative reports the case's summary state and the latest draft. It
// sends nothing.
func (h *handlers) getNarrative(w http.ResponseWriter, r *http.Request) {
	st, err := h.as(r).NarrativeStatus(r.PathValue("id"))
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// getNarrativePayload returns exactly what the latest request sent.
func (h *handlers) getNarrativePayload(w http.ResponseWriter, r *http.Request) {
	p, ok, err := h.as(r).LatestNarrativePayload(r.PathValue("id"))
	if h.fail(w, err) {
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "no summary has been requested for this case")
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// startNarrative begins drafting in the background (202).
func (h *handlers) startNarrative(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Acknowledge bool `json:"acknowledge"`
	}
	if r.ContentLength != 0 && !decodeJSON(w, r, &body) {
		return
	}
	st, err := h.as(r).StartNarrative(r.PathValue("id"), body.Acknowledge)
	switch {
	case errors.Is(err, ErrNarrativeEgress), errors.Is(err, ErrNarrativeNeedsAck):
		writeError(w, http.StatusForbidden, err.Error())
		return
	case errors.Is(err, ErrNarrativeNotConfigured):
		writeError(w, http.StatusNotImplemented, err.Error())
		return
	case errors.Is(err, ErrNarrativeRunning), errors.Is(err, errLLMConfigurationBusy):
		writeError(w, http.StatusConflict, err.Error())
		return
	case errors.Is(err, ErrNarrativeNoFindings), errors.Is(err, ErrNarrativeRefused):
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusAccepted, st)
}

// cancelNarrative stops a request in progress.
func (h *handlers) cancelNarrative(w http.ResponseWriter, r *http.Request) {
	if h.fail(w, h.as(r).CancelNarrative(r.PathValue("id"))) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
