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
//   - GET  /cases/{id}/evidence               lists collections (was: source files -- moved to /sources)
//   - GET  /cases/{id}/evidence/{collectionId} shows one collection, including files merely
//     discovered as well as imported (was: one event's provenance -- moved to /events/{eventID})
//
// Adding evidence is discover-then-import, not one step (see
// docs/data-model.md's "Evidence selection workflow" section):
//
//   - POST   /cases/{id}/evidence                            discover: upload a ZIP, catalog every file inside it
//   - POST   /cases/{id}/ingest                               discover: catalog every file under a local path
//   - POST   /cases/{id}/evidence/{collectionId}/import       import: parse exactly the selected file IDs
//   - DELETE /cases/{id}/evidence/{sourceFileId}              delete one evidence file
//   - DELETE /cases/{id}/evidence                              bulk-delete evidence files (body: source_file_ids)
//   - DELETE /cases/{id}                                       delete a case and everything in it
//   - DELETE /cases                                            bulk-delete cases (body: case_ids)
//
// This is a deliberate, documented rename/extension (see
// docs/data-model.md), not an oversight -- "evidence" primarily means
// "evidence collections and the files inside them" from the UI and API's
// perspective, matching how investigators think about a case built from
// more than one KAPE triage, each contributing more than one artifact.
// lanExposed tells healthz whether the server is bound to a non-loopback
// host (see cmd/tracefall/main.go's cfg.IsLoopbackHost()) -- surfaced to
// the dashboard so an analyst actually looking at the web UI sees the
// "no authentication, don't expose this beyond a trusted LAN" warning
// too, not just whoever reads the process's startup log.
func NewRouter(svc *Service, logger *slog.Logger, maxUploadBytes int64, lanExposed bool) *http.ServeMux {
	h := &handlers{svc: svc, log: logger, maxUploadBytes: maxUploadBytes, lanExposed: lanExposed}
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/cases", h.createCase)
	mux.HandleFunc("GET /api/cases", h.listCases)
	mux.HandleFunc("DELETE /api/cases", h.deleteCases)
	mux.HandleFunc("GET /api/cases/{id}", h.getCase)
	mux.HandleFunc("PATCH /api/cases/{id}", h.updateCaseMetadata)
	mux.HandleFunc("DELETE /api/cases/{id}", h.deleteCase)
	mux.HandleFunc("POST /api/cases/{id}/ingest", h.discoverEvidencePath)
	mux.HandleFunc("POST /api/cases/{id}/evidence", h.discoverEvidenceUpload)
	mux.HandleFunc("GET /api/cases/{id}/evidence", h.listCollections)
	mux.HandleFunc("DELETE /api/cases/{id}/evidence", h.deleteSourceFiles)
	mux.HandleFunc("POST /api/cases/{id}/evidence/{collectionID}/import", h.importEvidence)
	mux.HandleFunc("GET /api/cases/{id}/evidence/{collectionID}", h.collectionDetail)
	mux.HandleFunc("DELETE /api/cases/{id}/evidence/{sourceFileID}", h.deleteSourceFile)
	mux.HandleFunc("GET /api/cases/{id}/sources", h.sources)
	mux.HandleFunc("GET /api/cases/{id}/events/{eventID}", h.eventProvenance)
	mux.HandleFunc("POST /api/cases/{id}/analyze", h.analyzeCase)
	mux.HandleFunc("GET /api/cases/{id}/timeline", h.timeline)
	mux.HandleFunc("GET /api/cases/{id}/findings", h.findings)
	mux.HandleFunc("GET /api/cases/{id}/findings/{findingID}", h.findingDetail)
	mux.HandleFunc("GET /api/cases/{id}/attack", h.attack)
	mux.HandleFunc("GET /api/cases/{id}/correlations", h.correlations)
	mux.HandleFunc("GET /api/cases/{id}/investigations", h.investigations)
	mux.HandleFunc("GET /api/cases/{id}/investigations/{investigationID}", h.investigationDetail)
	mux.HandleFunc("PATCH /api/cases/{id}/investigations/{investigationID}/status", h.setInvestigationStatus)
	mux.HandleFunc("GET /api/cases/{id}/investigations/{investigationID}/export", h.exportInvestigation)
	mux.HandleFunc("PATCH /api/cases/{id}/findings/{findingID}/status", h.setFindingStatus)

	// Phase 6: analyst workflow (notes, tags, audit log, export).
	mux.HandleFunc("GET /api/cases/{id}/notes", h.listNotes)
	mux.HandleFunc("POST /api/cases/{id}/notes", h.createNote)
	mux.HandleFunc("PATCH /api/notes/{noteID}", h.updateNote)
	mux.HandleFunc("DELETE /api/notes/{noteID}", h.deleteNote)
	mux.HandleFunc("GET /api/cases/{id}/tags", h.listTags)
	mux.HandleFunc("POST /api/cases/{id}/tags", h.addTag)
	mux.HandleFunc("DELETE /api/cases/{id}/tags", h.removeTag)
	mux.HandleFunc("GET /api/cases/{id}/audit", h.auditLog)
	mux.HandleFunc("GET /api/cases/{id}/analyst-status", h.listAnalystStatus)
	mux.HandleFunc("GET /api/cases/{id}/export", h.exportCase)
	mux.HandleFunc("GET /api/cases/{id}/export/timeline.csv", h.exportTimelineCSV)
	mux.HandleFunc("GET /api/cases/{id}/export/findings.csv", h.exportFindingsCSV)

	mux.HandleFunc("GET /api/healthz", h.healthz)

	return mux
}

type handlers struct {
	svc            *Service
	log            *slog.Logger
	maxUploadBytes int64
	lanExposed     bool
}

func (h *handlers) healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "lan_exposed": h.lanExposed})
}

func (h *handlers) createCase(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if !decodeJSON(w, r, &req) {
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

// deleteCase permanently deletes a case and everything associated with
// it (see Service.DeleteCase). Confirmation is a UI responsibility --
// internal/web always asks before calling this, since it's irreversible.
func (h *handlers) deleteCase(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.svc.DeleteCase(id); h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted_case_id": id})
}

// deleteCases bulk-deletes cases (see Service.DeleteCases), reporting
// exactly which succeeded and which failed rather than treating the
// batch as all-or-nothing.
func (h *handlers) deleteCases(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CaseIDs []string `json:"case_ids"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if len(req.CaseIDs) == 0 {
		writeError(w, http.StatusBadRequest, "case_ids is required")
		return
	}
	res := h.svc.DeleteCases(req.CaseIDs)
	writeJSON(w, http.StatusOK, res)
}

// discoverEvidencePath catalogs a new evidence collection from a local
// filesystem directory -- every file under it, classified but not yet
// parsed (see Service.DiscoverEvidenceFromPath). Can be called more than
// once per case -- each call adds another collection. Nothing becomes
// evidence until POST .../evidence/{collectionId}/import selects specific
// files from the returned catalog.
func (h *handlers) discoverEvidencePath(w http.ResponseWriter, r *http.Request) {
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
	res, err := h.svc.DiscoverEvidenceFromPath(id, req.Path)
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// discoverEvidenceUpload accepts a browser-uploaded KAPE package as
// multipart form-data (field name "file"), safely extracts it, and
// catalogs every file inside as a new evidence collection -- see
// Service.DiscoverEvidenceFromUpload. Can be called more than once per
// case. The request body is capped at h.maxUploadBytes before anything
// else happens, so an oversized upload is rejected before it's buffered
// or written to disk. Nothing becomes evidence until POST
// .../evidence/{collectionId}/import selects specific files from the
// returned catalog.
func (h *handlers) discoverEvidenceUpload(w http.ResponseWriter, r *http.Request) {
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

	res, err := h.svc.DiscoverEvidenceFromUpload(id, file)
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// importEvidence parses exactly the selected source files from a
// collection's discovery catalog -- see Service.ImportEvidence.
func (h *handlers) importEvidence(w http.ResponseWriter, r *http.Request) {
	id, collectionID := r.PathValue("id"), r.PathValue("collectionID")
	var req struct {
		SourceFileIDs []string `json:"source_file_ids"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if len(req.SourceFileIDs) == 0 {
		writeError(w, http.StatusBadRequest, "source_file_ids is required (the discovered files to import)")
		return
	}
	res, err := h.svc.ImportEvidence(id, collectionID, req.SourceFileIDs)
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// deleteSourceFile removes exactly one evidence file (see
// Service.DeleteSourceFile). Confirmation is a UI responsibility --
// internal/web always asks before calling this.
func (h *handlers) deleteSourceFile(w http.ResponseWriter, r *http.Request) {
	id, sourceFileID := r.PathValue("id"), r.PathValue("sourceFileID")
	res, err := h.svc.DeleteSourceFile(id, sourceFileID)
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// deleteSourceFiles bulk-deletes evidence files (see
// Service.DeleteSourceFiles).
func (h *handlers) deleteSourceFiles(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		SourceFileIDs []string `json:"source_file_ids"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if len(req.SourceFileIDs) == 0 {
		writeError(w, http.StatusBadRequest, "source_file_ids is required")
		return
	}
	res, err := h.svc.DeleteSourceFiles(id, req.SourceFileIDs)
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

func (h *handlers) investigations(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	invs, err := h.svc.Investigations(id)
	if h.fail(w, err) {
		return
	}
	if invs == nil {
		invs = []model.Investigation{}
	}
	writeJSON(w, http.StatusOK, invs)
}

func (h *handlers) investigationDetail(w http.ResponseWriter, r *http.Request) {
	id, investigationID := r.PathValue("id"), r.PathValue("investigationID")
	detail, err := h.svc.Investigation(id, investigationID)
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

// ---------- helpers ----------

// fail writes an appropriate error response for err (if non-nil) and
// reports whether it did so, so handlers can `if h.fail(w, err) { return }`.
func (h *handlers) fail(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	var dupErr *DuplicateEvidenceError
	var dupCaseErr *DuplicateCaseError
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
	case errors.As(err, &dupCaseErr):
		// Same pattern as dupErr above: structured so the dashboard can
		// show "Case already exists" without parsing a sentence.
		writeJSON(w, http.StatusConflict, map[string]string{
			"error":               dupCaseErr.Error(),
			"duplicate_case_id":   dupCaseErr.CaseID,
			"duplicate_case_name": dupCaseErr.CaseName,
		})
	case errors.Is(err, ErrCaseNameRequired):
		writeError(w, http.StatusBadRequest, err.Error())
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
