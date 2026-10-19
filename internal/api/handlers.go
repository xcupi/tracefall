package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"tracefall/internal/ad1"
	"tracefall/internal/archive"
	"tracefall/internal/memory"
	"tracefall/internal/model"
	"tracefall/internal/store"
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
// NewRouter builds the API router with authentication DISABLED -- the
// single-operator localhost mode Tracefall shipped with before Phase 12.
//
// Kept as-is so existing callers and the whole pre-Phase-12 test suite
// continue to describe the behaviour they were written for. A LAN
// deployment must use NewRouterWithAuth; cmd/tracefall refuses to start
// otherwise (see cmd/tracefall/main.go).
func NewRouter(svc *Service, logger *slog.Logger, maxUploadBytes int64, lanExposed bool) http.Handler {
	return NewRouterWithAuth(svc, logger, maxUploadBytes, lanExposed, AuthConfig{})
}

// NewRouterWithAuth builds the API router with an explicit auth config.
func NewRouterWithAuth(svc *Service, logger *slog.Logger, maxUploadBytes int64, lanExposed bool, authCfg AuthConfig) http.Handler {
	h := &handlers{svc: svc, log: logger, maxUploadBytes: maxUploadBytes, lanExposed: lanExposed, auth: authCfg}
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/cases", h.createCase)
	mux.HandleFunc("GET /api/cases", h.listCases)
	mux.HandleFunc("DELETE /api/cases", h.deleteCases)
	mux.HandleFunc("GET /api/cases/{id}", h.getCase)
	mux.HandleFunc("PATCH /api/cases/{id}", h.updateCaseMetadata)
	mux.HandleFunc("DELETE /api/cases/{id}", h.deleteCase)
	// Progress for a deletion that is CURRENTLY RUNNING. Reads an
	// in-memory record and never touches the database -- the store holds
	// a single connection, so a poll that queried would queue behind the
	// deletion it is reporting on (see deleteprogress.go).
	mux.HandleFunc("GET /api/cases/{id}/deletion-progress", h.deletionProgress)
	// How much evidence this case stores on disk. Measured on demand
	// (while a deletion confirmation is being prepared), never as part of
	// the case payload every page view loads.
	mux.HandleFunc("GET /api/cases/{id}/evidence-size", h.evidenceSize)
	mux.HandleFunc("POST /api/cases/{id}/ingest", h.discoverEvidencePath)
	mux.HandleFunc("POST /api/cases/{id}/evidence", h.discoverEvidenceUpload)
	mux.HandleFunc("GET /api/cases/{id}/evidence", h.listCollections)
	// What this build can and cannot parse. Case-independent, so the
	// dashboard fetches it once and renders the registry rather than
	// keeping its own copy of what is supported.
	mux.HandleFunc("GET /api/capabilities", h.capabilities)
	// The finding-severity model, published read-only for inspection.
	mux.HandleFunc("GET /api/severity-model", h.severityModel)
	mux.HandleFunc("DELETE /api/cases/{id}/evidence", h.deleteSourceFiles)
	mux.HandleFunc("POST /api/cases/{id}/evidence/{collectionID}/import", h.importEvidence)
	// Background import + polling. The synchronous route above is kept
	// unchanged (scripted use, and every existing test), so this adds
	// progress reporting without altering what already worked.
	mux.HandleFunc("POST /api/cases/{id}/evidence/{collectionID}/import/start", h.startImport)
	mux.HandleFunc("GET /api/settings", h.getSettings)
	mux.HandleFunc("PUT /api/settings", h.updateSettings)
	mux.HandleFunc("GET /api/cases/{id}/import-jobs/{jobID}", h.importJobStatus)
	mux.HandleFunc("POST /api/cases/{id}/import-jobs/{jobID}/cancel", h.cancelImportJob)
	mux.HandleFunc("GET /api/cases/{id}/evidence/{collectionID}", h.collectionDetail)
	// Phase 10B: one page of a collection's catalog, filtered on the
	// server. The dashboard renders exactly what this returns, so a
	// 7,000-file image costs one page of rows rather than all of them.
	mux.HandleFunc("GET /api/cases/{id}/evidence/{collectionID}/files", h.evidenceFiles)
	// The stable IDs of every importable file matching a filter -- what
	// "select all matching" materializes its selection from.
	mux.HandleFunc("GET /api/cases/{id}/evidence/{collectionID}/files/ids", h.evidenceFileIDs)

	// Roadmap item 2: resumable uploads and the server-side pipeline.
	mux.HandleFunc("POST /api/cases/{id}/uploads", h.createUpload)
	mux.HandleFunc("GET /api/cases/{id}/uploads/{uploadID}", h.uploadStatus)
	mux.HandleFunc("PUT /api/cases/{id}/uploads/{uploadID}", h.uploadChunk)
	mux.HandleFunc("POST /api/cases/{id}/uploads/{uploadID}/complete", h.completeUpload)
	mux.HandleFunc("POST /api/cases/{id}/uploads/{uploadID}/abort", h.abortUpload)
	mux.HandleFunc("POST /api/cases/{id}/pipeline/jobs", h.enqueuePipelineJob)
	mux.HandleFunc("GET /api/cases/{id}/pipeline/jobs", h.listPipelineJobs)
	mux.HandleFunc("GET /api/cases/{id}/pipeline/jobs/{jobID}", h.getPipelineJob)
	mux.HandleFunc("POST /api/cases/{id}/pipeline/jobs/{jobID}/cancel", h.cancelPipelineJob)
	mux.HandleFunc("DELETE /api/cases/{id}/evidence/{sourceFileID}", h.deleteSourceFile)
	// Collection-level deletion. Registered on a more specific pattern
	// than the source-file route above so Go's ServeMux routes them
	// unambiguously rather than by declaration order.
	mux.HandleFunc("DELETE /api/cases/{id}/collections/{collectionID}", h.deleteCollection)
	mux.HandleFunc("GET /api/cases/{id}/sources", h.sources)
	// The forensic timeline (Phase 14). Registered on the SAME mux as
	// every other route, so withSecurity's authentication, CSRF and role
	// checks apply to it automatically -- a new route is protected by
	// default rather than by remembering to protect it.
	//
	// "facets" is a literal segment and therefore matches ahead of the
	// {eventID} wildcard below it; event ids are UUIDs, so the two can
	// never collide.
	mux.HandleFunc("GET /api/cases/{id}/events", h.eventSearch)
	mux.HandleFunc("GET /api/cases/{id}/events/facets", h.eventFacets)
	mux.HandleFunc("GET /api/cases/{id}/events/{eventID}", h.eventProvenance)
	// Phase 21: the Photo Map. geo/photos is a second VIEW of the
	// image_gps events the EXIF parser already produced -- it creates no
	// event and parses no image. The two image routes are the only place
	// a browser's input reaches evidence bytes; both take an opaque
	// source file ID, never a path, and both are authorized against the
	// case in the URL (see Service.imagePath).
	mux.HandleFunc("GET /api/cases/{id}/geo/photos", h.geoPhotos)
	mux.HandleFunc("GET /api/cases/{id}/images/{sourceFileID}/content", h.imageContent)
	mux.HandleFunc("GET /api/cases/{id}/images/{sourceFileID}/thumbnail", h.imageThumbnail)
	// World geography, not evidence, so it is not case-scoped -- but it
	// sits behind the same authentication as everything else under /api.
	mux.HandleFunc("GET /api/geo/basemap", h.basemap)
	// Phase 11: provenance and integrity. Read-only except
	// verify-integrity, which writes only an audit entry recording that
	// the check ran. Scoped under the existing /api/cases/{id}/... shape
	// rather than a new top-level namespace, so case ownership is checked
	// the same way every other route already checks it.
	mux.HandleFunc("GET /api/cases/{id}/provenance", h.caseProvenance)
	mux.HandleFunc("GET /api/cases/{id}/findings/{findingID}/provenance", h.findingProvenance)
	mux.HandleFunc("GET /api/cases/{id}/sources/{sourceFileID}/provenance", h.sourceFileProvenance)
	mux.HandleFunc("POST /api/cases/{id}/evidence/{collectionID}/verify-integrity", h.verifyIntegrity)
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
	// Case-scoped (Phase 12). These were previously /api/notes/{noteID}
	// with no case in the path and no ownership check in the store, so a
	// note id alone was enough to edit or delete a note in ANY case. The
	// case is now part of both the route and the SQL predicate.
	mux.HandleFunc("PATCH /api/cases/{id}/notes/{noteID}", h.updateNote)
	mux.HandleFunc("DELETE /api/cases/{id}/notes/{noteID}", h.deleteNote)
	mux.HandleFunc("GET /api/cases/{id}/tags", h.listTags)
	mux.HandleFunc("POST /api/cases/{id}/tags", h.addTag)
	mux.HandleFunc("DELETE /api/cases/{id}/tags", h.removeTag)
	mux.HandleFunc("GET /api/cases/{id}/audit", h.auditLog)
	mux.HandleFunc("GET /api/cases/{id}/audit/verify", h.verifyAudit)
	mux.HandleFunc("GET /api/cases/{id}/analyst-status", h.listAnalystStatus)
	mux.HandleFunc("GET /api/cases/{id}/export", h.exportCase)
	mux.HandleFunc("GET /api/cases/{id}/export/timeline.csv", h.exportTimelineCSV)
	mux.HandleFunc("GET /api/cases/{id}/export/findings.csv", h.exportFindingsCSV)
	// The forensic report: a self-contained HTML document, a hashed
	// bundle (report + manifest + CSV attachments), and an optional PDF.
	mux.HandleFunc("GET /api/cases/{id}/report.html", h.reportHTML)
	mux.HandleFunc("GET /api/cases/{id}/report.zip", h.reportBundle)
	mux.HandleFunc("GET /api/cases/{id}/report.pdf", h.reportPDF)

	mux.HandleFunc("GET /api/healthz", h.healthz)

	// Authentication and account administration (Phase 12).
	// login/session are public; everything under /api/admin/ is
	// admin-only by the requiredRole rule in middleware.go.
	mux.HandleFunc("POST /api/auth/login", h.login)
	mux.HandleFunc("POST /api/auth/logout", h.logout)
	mux.HandleFunc("GET /api/auth/session", h.currentSession)
	mux.HandleFunc("POST /api/auth/change-password", h.changeOwnPassword)
	mux.HandleFunc("GET /api/admin/users", h.listUsers)
	mux.HandleFunc("POST /api/admin/users", h.createUser)
	mux.HandleFunc("DELETE /api/admin/users/{userID}", h.deleteUser)
	mux.HandleFunc("PATCH /api/admin/users/{userID}", h.updateUser)
	mux.HandleFunc("GET /api/admin/security-log", h.securityLog)

	// Every API request passes through withSecurity, so authorization is
	// enforced in one place rather than per handler. A route added later
	// is protected by default; a forgotten check denies rather than opens.
	return h.withSecurity(mux)
}

// as returns the Service bound to this request's authenticated identity,
// so anything it audits is attributed to the user who actually asked.
//
// Handlers call h.as(r) rather than h.svc for exactly this reason; the
// shared h.svc carries no identity and would record every action as the
// generic local operator.
func (h *handlers) as(r *http.Request) *Service {
	return h.svc.WithActor(principalFrom(r))
}

type handlers struct {
	svc            *Service
	log            *slog.Logger
	maxUploadBytes int64
	// auth controls whether requests must carry a valid session. See
	// AuthConfig; the zero value is authentication disabled.
	auth       AuthConfig
	lanExposed bool
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
	c, err := h.as(r).CreateCase(req.Name, req.Description)
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusCreated, c)
}

func (h *handlers) listCases(w http.ResponseWriter, r *http.Request) {
	cases, err := h.as(r).ListCases()
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
	c, err := h.as(r).GetCase(id)
	if h.fail(w, err) {
		return
	}
	summary, err := h.as(r).CaseSummary(id)
	if h.fail(w, err) {
		return
	}
	// Phase 13: the lifecycle locks are DERIVED from case_status and sent
	// alongside it, so the dashboard renders one authoritative answer
	// instead of each view re-deriving the rule and risking drift. They
	// are a convenience for rendering only -- the server re-checks both
	// on every mutating request (see internal/api/lifecycle.go).
	writeJSON(w, http.StatusOK, struct {
		Case             any  `json:"case"`
		Summary          any  `json:"summary"`
		EvidenceMutable  bool `json:"evidence_mutable"`
		PriorityEditable bool `json:"priority_editable"`
	}{c, summary, model.EvidenceMutable(c.CaseStatus), model.PriorityEditable(c.CaseStatus)})
}

// deleteCase permanently deletes a case and everything associated with
// it (see Service.DeleteCase). Confirmation is a UI responsibility --
// internal/web always asks before calling this, since it's irreversible.
func (h *handlers) deleteCase(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.as(r).DeleteCase(id); h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted_case_id": id})
}

// deleteCases bulk-deletes cases (see Service.DeleteCases), reporting
// exactly which succeeded and which failed rather than treating the
// batch as all-or-nothing.
// deletionProgress answers how far a running case deletion has got.
//
// 404 means nothing is being tracked for this case, which is the normal
// answer whenever a deletion is not in flight. It is deliberately NOT an
// error state for the caller: a poll that arrives before the deletion
// registers, or long after it finished, gets the same honest "no
// deletion in progress".
//
// Deliberately NOT behind the case-exists check the other case routes
// use: by the time a deletion reaches its final stage the case is gone,
// and a progress endpoint that started 404ing at exactly the moment the
// answer became interesting would be useless.
func (h *handlers) deletionProgress(w http.ResponseWriter, r *http.Request) {
	prog, ok := h.as(r).DeletionProgressFor(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "no deletion is in progress for this case")
		return
	}
	writeJSON(w, http.StatusOK, prog)
}

// evidenceSize reports the on-disk size of a case's stored evidence.
func (h *handlers) evidenceSize(w http.ResponseWriter, r *http.Request) {
	size, err := h.as(r).EvidenceSizeFor(r.PathValue("id"))
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, size)
}

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
	res := h.as(r).DeleteCases(req.CaseIDs)
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
	res, err := h.as(r).DiscoverEvidenceFromPath(id, req.Path)
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

	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, `missing uploaded file (expected multipart form field "file")`)
		return
	}
	defer file.Close()

	res, err := h.as(r).DiscoverEvidenceFromUpload(id, file, header.Filename)
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// deleteCollection permanently removes an entire evidence collection.
//
// Admin-only and lifecycle-guarded through the same paths as every other
// evidence mutation -- the router makes every DELETE admin-only, and the
// service refuses a contained or closed case -- so this handler adds no
// authorization logic of its own that could drift from them.
func (h *handlers) deleteCollection(w http.ResponseWriter, r *http.Request) {
	res, err := h.as(r).DeleteCollection(r.PathValue("id"), r.PathValue("collectionID"))
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
	res, err := h.as(r).ImportEvidence(id, collectionID, req.SourceFileIDs)
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
	res, err := h.as(r).DeleteSourceFile(id, sourceFileID)
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
	res, err := h.as(r).DeleteSourceFiles(id, req.SourceFileIDs)
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (h *handlers) listCollections(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	collections, err := h.as(r).ListCollections(id)
	if h.fail(w, err) {
		return
	}
	if collections == nil {
		collections = []model.Collection{}
	}
	writeJSON(w, http.StatusOK, collections)
}

func (h *handlers) severityModel(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.as(r).SeverityModelReport())
}

func (h *handlers) capabilities(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.as(r).Capabilities())
}

// startImport begins an import in the background and returns its job ID
// for polling. Returns 409 if this collection already has one running --
// the server-side half of the "don't submit the same selection twice"
// guarantee.
// evidenceFiles serves one filtered page of a collection's catalog.
func (h *handlers) evidenceFiles(w http.ResponseWriter, r *http.Request) {
	page, err := h.as(r).EvidenceFiles(
		r.PathValue("id"), r.PathValue("collectionID"),
		parseEvidenceFilter(r),
		parsePageRequest(r, evidencePageSizes, defaultEvidencePageSize),
	)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

// evidenceFileIDs resolves the current filter to the stable IDs of every
// importable file matching it.
//
// It returns IDs only. The client needs identity to build a selection,
// not content, and a list of IDs is roughly a fiftieth the size of the
// records -- which is what makes "select all matching" affordable on a
// catalog the browser is deliberately never sent in full.
func (h *handlers) evidenceFileIDs(w http.ResponseWriter, r *http.Request) {
	ids, err := h.as(r).EvidenceFileIDs(
		r.PathValue("id"), r.PathValue("collectionID"), parseEvidenceFilter(r))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ids": ids, "total": len(ids)})
}

func (h *handlers) startImport(w http.ResponseWriter, r *http.Request) {
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
	jobID, err := h.as(r).StartImport(id, collectionID, req.SourceFileIDs)
	if err != nil {
		if errors.Is(err, ErrImportInProgress) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"job_id": jobID})
}

// importJobStatus reports a running or finished import's progress. It
// reads in-memory job state only and never touches the database, so it
// stays responsive while the import holds the single write connection.
func (h *handlers) importJobStatus(w http.ResponseWriter, r *http.Request) {
	id, jobID := r.PathValue("id"), r.PathValue("jobID")
	progress, err := h.as(r).ImportJob(id, jobID)
	if err != nil {
		if errors.Is(err, ErrJobNotFound) {
			writeError(w, http.StatusNotFound, "import job not found")
			return
		}
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, progress)
}

// getSettings returns the application-wide display preferences plus the
// shortlist of timezones the UI offers.
//
// Unauthenticated-readable like the rest of the read API: it exposes no
// evidence and no account information, only how timestamps are rendered.
func (h *handlers) getSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := h.as(r).DisplaySettings()
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"display":          settings,
		"common_timezones": CommonTimezones,
		"default_timezone": DefaultDisplayTimezone,
	})
}

// updateSettings changes the display timezone.
//
// An invalid identifier is a 400 with the reason, never a silent
// fallback to UTC: an analyst who mistypes a zone must find out
// immediately, not discover later that every timestamp they read was in
// a different zone from the one they thought they had chosen.
func (h *handlers) updateSettings(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Timezone string `json:"timezone"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	settings, err := h.as(r).SetDisplayTimezone(body.Timezone)
	if err != nil {
		if errors.Is(err, ErrInvalidTimezone) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"display": settings})
}

// cancelImportJob asks a running import to stop.
//
// POST, not DELETE: this does not delete the job, and every DELETE in
// Tracefall is admin-only (see withSecurity). Cancelling an import you
// started is ordinary analyst work, so it must not require admin -- it
// is already guarded by the same case scoping as reading the job.
//
// Returns the progress snapshot rather than 204, so a client that
// cancels never has to guess: it gets back whether the import had
// already finished, and the counts as they stand.
func (h *handlers) cancelImportJob(w http.ResponseWriter, r *http.Request) {
	id, jobID := r.PathValue("id"), r.PathValue("jobID")
	progress, err := h.as(r).CancelImport(id, jobID)
	if err != nil {
		if errors.Is(err, ErrJobNotFound) {
			writeError(w, http.StatusNotFound, "import job not found")
			return
		}
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, progress)
}

func (h *handlers) collectionDetail(w http.ResponseWriter, r *http.Request) {
	id, collectionID := r.PathValue("id"), r.PathValue("collectionID")
	detail, err := h.as(r).CollectionDetail(id, collectionID)
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

func (h *handlers) analyzeCase(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	res, err := h.as(r).AnalyzeCase(id)
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
	events, err := h.as(r).Timeline(id, collectionID)
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
	findings, err := h.as(r).Findings(id)
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
	fd, err := h.as(r).Finding(id, findingID)
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, fd)
}

func (h *handlers) attack(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	techniques, err := h.as(r).AttackSummary(id)
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
	sources, err := h.as(r).Sources(id)
	if h.fail(w, err) {
		return
	}
	if sources == nil {
		sources = []TriagedSourceFile{}
	}
	writeJSON(w, http.StatusOK, sources)
}

// eventSearch answers one forensic timeline query: filters in, one page
// of normalized events out, with the true total.
//
// A bad date is a 400 with the reason, never a silently-dropped filter
// -- showing the whole case to an analyst who believes they are looking
// at one day is the failure this refuses to produce.
func (h *handlers) eventSearch(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	loc, err := h.as(r).displayLocation()
	if h.fail(w, err) {
		return
	}
	req, err := parseEventSearch(r, id, loc)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := h.as(r).SearchEvents(req)
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// eventFacets returns the filter vocabulary this case's events support.
func (h *handlers) eventFacets(w http.ResponseWriter, r *http.Request) {
	facets, err := h.as(r).EventFacets(r.PathValue("id"))
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, facets)
}

func (h *handlers) eventProvenance(w http.ResponseWriter, r *http.Request) {
	id, eventID := r.PathValue("id"), r.PathValue("eventID")
	prov, err := h.as(r).EventProvenance(id, eventID)
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, prov)
}

// caseProvenance returns the case-level chain-of-custody summary.
func (h *handlers) caseProvenance(w http.ResponseWriter, r *http.Request) {
	prov, err := h.as(r).CaseProvenanceFor(r.PathValue("id"))
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, prov)
}

// findingProvenance answers "what evidence is this finding standing on?".
func (h *handlers) findingProvenance(w http.ResponseWriter, r *http.Request) {
	prov, err := h.as(r).FindingProvenanceFor(r.PathValue("id"), r.PathValue("findingID"))
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, prov)
}

// sourceFileProvenance reports one source file and what it produced.
func (h *handlers) sourceFileProvenance(w http.ResponseWriter, r *http.Request) {
	prov, err := h.as(r).SourceFileProvenanceFor(r.PathValue("id"), r.PathValue("sourceFileID"))
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, prov)
}

// verifyIntegrity recomputes a collection's SHA-512 and compares it with
// the digest recorded at ingestion.
//
// POST because it is an ACTION an analyst takes and it appends to the
// audit trail -- not because it changes any evidence, which it never
// does. A mismatch is a 200 carrying a mismatch result, not an HTTP
// error: the request succeeded, and what it found is the answer.
func (h *handlers) verifyIntegrity(w http.ResponseWriter, r *http.Request) {
	res, err := h.as(r).VerifyCollectionIntegrity(r.PathValue("id"), r.PathValue("collectionID"))
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (h *handlers) correlations(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	corr, err := h.as(r).Correlations(id)
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
	invs, err := h.as(r).Investigations(id)
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
	detail, err := h.as(r).Investigation(id, investigationID)
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
	var offErr *UploadOffsetError
	var dupCaseErr *DuplicateCaseError
	switch {
	case errors.Is(err, ErrEvidenceLocked), errors.Is(err, ErrPriorityLocked):
		// 409 Conflict, not 403: the caller is permitted to act on this
		// case, but the case's own STATE forbids this change. A 403 would
		// suggest a permissions problem and send an analyst looking at
		// their role instead of the case's status.
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, ErrServerPathRefused):
		// 403: the request is well formed; the server's own policy refuses it.
		writeError(w, http.StatusForbidden, err.Error())
	case errors.Is(err, ErrEvidenceTreeEscapes):
		writeError(w, http.StatusUnprocessableEntity, err.Error())
	case errors.Is(err, ErrCaseNotFound), errors.Is(err, ErrCollectionNotFound),
		errors.Is(err, ErrFindingNotFound), errors.Is(err, ErrSourceFileNotFound),
		errors.Is(err, store.ErrNoteNotFound):
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
	case errors.Is(err, ErrUnsupportedEvidence), errors.Is(err, ErrInvalidAD1), errors.Is(err, ErrInvalidDiskImage), errors.Is(err, ad1.ErrLimitExceeded):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, ErrMemoryNotConfigured):
		writeError(w, http.StatusNotImplemented, err.Error())
	case errors.Is(err, memory.ErrSymbols), errors.Is(err, memory.ErrUnrecognised), errors.Is(err, memory.ErrTimeout):
		writeError(w, http.StatusUnprocessableEntity, err.Error())
	case errors.Is(err, store.ErrJobNotFound), errors.Is(err, store.ErrUploadNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, ErrUploadInvalid):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, ErrUploadIncomplete), errors.Is(err, ErrUploadNotReady), errors.Is(err, store.ErrUploadClosed):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, ErrUploadHashMismatch):
		writeError(w, http.StatusUnprocessableEntity, err.Error())
	case errors.As(err, &offErr):
		writeJSON(w, http.StatusConflict, map[string]any{"error": offErr.Error(), "received": offErr.Received})
	case errors.Is(err, ErrEvidencePathNotFound), errors.Is(err, ErrNoEvidenceFound):
		// Investigator-actionable: the path is wrong, or the source is
		// empty. Both used to fall through to the default branch below
		// and surface as an opaque 500 "internal error", which told an
		// investigator nothing about what to fix.
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		// Genuinely unexpected. The detail goes to the server log, where
		// it can name paths, SQL and internals freely; the client gets a
		// deliberately generic message so none of that leaks.
		h.log.Error("request failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
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
