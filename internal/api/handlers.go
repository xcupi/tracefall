package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"tracefall/internal/archive"
	"tracefall/internal/model"
)

// NewRouter builds Tracefall's HTTP API mux. It registers only the JSON
// API under /api/ -- static file/dashboard serving is wired separately in
// cmd/tracefall so internal/api stays UI-agnostic. maxUploadBytes bounds
// the size of a POST /cases/{id}/evidence request body (see addEvidenceUpload).
//
// A case can hold more than one evidence collection (see
// internal/model.Collection), which reused two of Phase 1.5's paths for
// a different purpose:
//
//   - GET  /cases/{id}/evidence               now lists collections (was: source files -- moved to /sources)
//   - GET  /cases/{id}/evidence/{collectionId} now shows one collection (was: one event's provenance -- moved to /events/{eventID})
//   - POST /cases/{id}/evidence                replaces the old POST .../upload
//
// This is a deliberate, documented rename (see docs/data-model.md), not
// an oversight -- "evidence" now primarily means "evidence collections"
// from the UI and API's perspective, matching how investigators think
// about a case built from more than one KAPE triage.
func NewRouter(svc *Service, logger *slog.Logger, maxUploadBytes int64) *http.ServeMux {
	h := &handlers{svc: svc, log: logger, maxUploadBytes: maxUploadBytes}
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/cases", h.createCase)
	mux.HandleFunc("GET /api/cases", h.listCases)
	mux.HandleFunc("GET /api/cases/{id}", h.getCase)
	mux.HandleFunc("POST /api/cases/{id}/ingest", h.ingestCase)
	mux.HandleFunc("POST /api/cases/{id}/evidence", h.addEvidenceUpload)
	mux.HandleFunc("GET /api/cases/{id}/evidence", h.listCollections)
	mux.HandleFunc("GET /api/cases/{id}/evidence/{collectionID}", h.collectionDetail)
	mux.HandleFunc("GET /api/cases/{id}/sources", h.sources)
	mux.HandleFunc("GET /api/cases/{id}/events/{eventID}", h.eventProvenance)
	mux.HandleFunc("POST /api/cases/{id}/analyze", h.analyzeCase)
	mux.HandleFunc("GET /api/cases/{id}/timeline", h.timeline)
	mux.HandleFunc("GET /api/cases/{id}/findings", h.findings)
	mux.HandleFunc("GET /api/cases/{id}/findings/{findingID}", h.findingDetail)
	mux.HandleFunc("GET /api/cases/{id}/attack", h.attack)
	mux.HandleFunc("GET /api/cases/{id}/correlations", h.correlations)
	mux.HandleFunc("GET /api/healthz", h.healthz)

	return mux
}

type handlers struct {
	svc            *Service
	log            *slog.Logger
	maxUploadBytes int64
}

func (h *handlers) healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *handlers) createCase(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	c, err := h.svc.CreateCase(req.Name, req.Description)
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusCreated, c)
}

func (h *handlers) listCases(w http.ResponseWriter, r *http.Request) {
	cases, err := h.svc.ListCases()
	if h.fail(w, err) {
		return
	}
	if cases == nil {
		cases = []model.Case{}
	}
	writeJSON(w, http.StatusOK, cases)
}

func (h *handlers) getCase(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c, err := h.svc.GetCase(id)
	if h.fail(w, err) {
		return
	}
	summary, err := h.svc.CaseSummary(id)
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Case    any `json:"case"`
		Summary any `json:"summary"`
	}{c, summary})
}

// ingestCase adds a new evidence collection to a case from a local
// filesystem directory. Unlike Phase 1.5, this can be called more than
// once per case -- each call adds another collection.
func (h *handlers) ingestCase(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Path string `json:"path"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Path == "" {
		writeError(w, http.StatusBadRequest, "path is required (a local filesystem directory containing the evidence package)")
		return
	}
	res, err := h.svc.AddEvidenceFromPath(id, req.Path)
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// addEvidenceUpload accepts a browser-uploaded KAPE package as multipart
// form-data (field name "file") and adds it to a case as a new evidence
// collection via Service.AddEvidenceFromUpload. Can be called more than
// once per case. The request body is capped at h.maxUploadBytes before
// anything else happens, so an oversized upload is rejected before it's
// buffered or written to disk.
func (h *handlers) addEvidenceUpload(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	// A small amount of slack over the configured limit accounts for
	// multipart boundary/header overhead, so a file whose *content* is
	// exactly at the limit isn't spuriously rejected.
	r.Body = http.MaxBytesReader(w, r.Body, h.maxUploadBytes+1<<20)

	// Parts up to 32MB are kept in memory; anything larger is spilled by
	// mime/multipart to a temp file automatically, so this doesn't load
	// an entire large KAPE package into RAM.
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			h.fail(w, fmt.Errorf("%w (limit is %d MB)", ErrUploadTooLarge, h.maxUploadBytes/(1<<20)))
			return
		}
		writeError(w, http.StatusBadRequest, "invalid multipart upload: "+err.Error())
		return
	}
	defer r.MultipartForm.RemoveAll()

	file, _, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, `missing uploaded file (expected multipart form field "file")`)
		return
	}
	defer file.Close()

	res, err := h.svc.AddEvidenceFromUpload(id, file)
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (h *handlers) listCollections(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	collections, err := h.svc.ListCollections(id)
	if h.fail(w, err) {
		return
	}
	if collections == nil {
		collections = []model.Collection{}
	}
	writeJSON(w, http.StatusOK, collections)
}

func (h *handlers) collectionDetail(w http.ResponseWriter, r *http.Request) {
	id, collectionID := r.PathValue("id"), r.PathValue("collectionID")
	detail, err := h.svc.CollectionDetail(id, collectionID)
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

func (h *handlers) analyzeCase(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	res, err := h.svc.AnalyzeCase(id)
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// timeline returns the case's unified timeline across every collection,
// or just one collection's events if ?collection=<id> is given.
func (h *handlers) timeline(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	collectionID := r.URL.Query().Get("collection")
	events, err := h.svc.Timeline(id, collectionID)
	if h.fail(w, err) {
		return
	}
	if events == nil {
		events = []model.Event{}
	}
	writeJSON(w, http.StatusOK, events)
}

func (h *handlers) findings(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	findings, err := h.svc.Findings(id)
	if h.fail(w, err) {
		return
	}
	if findings == nil {
		findings = []model.Finding{}
	}
	writeJSON(w, http.StatusOK, findings)
}

func (h *handlers) findingDetail(w http.ResponseWriter, r *http.Request) {
	id, findingID := r.PathValue("id"), r.PathValue("findingID")
	fd, err := h.svc.Finding(id, findingID)
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, fd)
}

func (h *handlers) attack(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	techniques, err := h.svc.AttackSummary(id)
	if h.fail(w, err) {
		return
	}
	if techniques == nil {
		techniques = []AttackTechnique{}
	}
	writeJSON(w, http.StatusOK, techniques)
}

func (h *handlers) sources(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sources, err := h.svc.Sources(id)
	if h.fail(w, err) {
		return
	}
	if sources == nil {
		sources = []model.SourceFile{}
	}
	writeJSON(w, http.StatusOK, sources)
}

func (h *handlers) eventProvenance(w http.ResponseWriter, r *http.Request) {
	id, eventID := r.PathValue("id"), r.PathValue("eventID")
	prov, err := h.svc.EventProvenance(id, eventID)
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, prov)
}

func (h *handlers) correlations(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	corr, err := h.svc.Correlations(id)
	if h.fail(w, err) {
		return
	}
	if corr == nil {
		corr = []model.Correlation{}
	}
	writeJSON(w, http.StatusOK, corr)
}

// ---------- helpers ----------

// fail writes an appropriate error response for err (if non-nil) and
// reports whether it did so, so handlers can `if h.fail(w, err) { return }`.
func (h *handlers) fail(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	var dupErr *DuplicateEvidenceError
	switch {
	case errors.Is(err, ErrCaseNotFound), errors.Is(err, ErrCollectionNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.As(err, &dupErr):
		// Structured, not just a message, so the dashboard can show
		// "Evidence already exists ... as Collection #1" without having
		// to parse it back out of a sentence -- see internal/web/static/app.js.
		writeJSON(w, http.StatusConflict, map[string]string{
			"error":                      dupErr.Error(),
			"duplicate_collection_id":    dupErr.CollectionID,
			"duplicate_collection_label": dupErr.CollectionLabel,
		})
	case errors.Is(err, ErrNotIngested):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, ErrUploadTooLarge), errors.Is(err, archive.ErrLimitExceeded):
		writeError(w, http.StatusRequestEntityTooLarge, err.Error())
	case errors.Is(err, archive.ErrInvalidArchive), errors.Is(err, archive.ErrUnsafeEntry):
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		h.log.Error("request failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
	}
	return true
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Body == nil {
		writeError(w, http.StatusBadRequest, "request body is required")
		return false
	}
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
