// Phase 6 HTTP handlers: case metadata, notes, tags, finding/
// investigation review status, audit log, and exports. See
// internal/api/workflow.go and export.go for the underlying Service
// methods; these handlers only decode requests and encode responses,
// consistent with the rest of this package's "dumb JSON boundary" style.
package api

import (
	"net/http"

	"tracefall/internal/model"
)

func (h *handlers) updateCaseMetadata(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req CaseMetadataUpdate
	if !decodeJSON(w, r, &req) {
		return
	}
	c, err := h.svc.UpdateCaseMetadata(id, req)
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (h *handlers) listNotes(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	targetType := r.URL.Query().Get("target_type")
	targetID := r.URL.Query().Get("target_id")
	notes, err := h.svc.ListNotes(id, targetType, targetID)
	if h.fail(w, err) {
		return
	}
	if notes == nil {
		notes = []model.Note{}
	}
	writeJSON(w, http.StatusOK, notes)
}

func (h *handlers) createNote(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		TargetType string `json:"target_type"`
		TargetID   string `json:"target_id"`
		Note       string `json:"note"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	n, err := h.svc.CreateNote(id, req.TargetType, req.TargetID, req.Note)
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusCreated, n)
}

func (h *handlers) updateNote(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("noteID")
	var req struct {
		Note string `json:"note"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if _, err := h.svc.UpdateNote(id, req.Note); h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (h *handlers) deleteNote(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("noteID")
	if err := h.svc.DeleteNote(id); h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (h *handlers) listTags(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	targetType := r.URL.Query().Get("target_type")
	targetID := r.URL.Query().Get("target_id")
	tags, err := h.svc.ListTags(id, targetType, targetID)
	if h.fail(w, err) {
		return
	}
	if tags == nil {
		tags = []model.Tag{}
	}
	writeJSON(w, http.StatusOK, tags)
}

func (h *handlers) addTag(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		TargetType string `json:"target_type"`
		TargetID   string `json:"target_id"`
		Tag        string `json:"tag"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	t, err := h.svc.AddTag(id, req.TargetType, req.TargetID, req.Tag)
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusCreated, t)
}

func (h *handlers) removeTag(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		TargetType string `json:"target_type"`
		TargetID   string `json:"target_id"`
		Tag        string `json:"tag"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := h.svc.RemoveTag(id, req.TargetType, req.TargetID, req.Tag); h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}

func (h *handlers) setFindingStatus(w http.ResponseWriter, r *http.Request) {
	id, findingID := r.PathValue("id"), r.PathValue("findingID")
	var req struct {
		Status string `json:"status"`
		Note   string `json:"note"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	a, err := h.svc.SetFindingStatus(id, findingID, req.Status, req.Note)
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (h *handlers) setInvestigationStatus(w http.ResponseWriter, r *http.Request) {
	id, investigationID := r.PathValue("id"), r.PathValue("investigationID")
	var req struct {
		Status string `json:"status"`
		Note   string `json:"note"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	a, err := h.svc.SetInvestigationStatus(id, investigationID, req.Status, req.Note)
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (h *handlers) listAnalystStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	statuses, err := h.svc.ListAnalystStatus(id)
	if h.fail(w, err) {
		return
	}
	if statuses == nil {
		statuses = []model.AnalystStatus{}
	}
	writeJSON(w, http.StatusOK, statuses)
}

func (h *handlers) auditLog(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	events, err := h.svc.AuditLog(id)
	if h.fail(w, err) {
		return
	}
	if events == nil {
		events = []model.AuditEvent{}
	}
	writeJSON(w, http.StatusOK, events)
}

func (h *handlers) exportCase(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	export, err := h.svc.ExportCase(id)
	if h.fail(w, err) {
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="case-`+id+`.json"`)
	writeJSON(w, http.StatusOK, export)
}

func (h *handlers) exportInvestigation(w http.ResponseWriter, r *http.Request) {
	id, investigationID := r.PathValue("id"), r.PathValue("investigationID")
	export, err := h.svc.ExportInvestigation(id, investigationID)
	if h.fail(w, err) {
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="investigation-`+investigationID+`.json"`)
	writeJSON(w, http.StatusOK, export)
}

func (h *handlers) exportTimelineCSV(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", `attachment; filename="timeline-`+id+`.csv"`)
	if err := h.svc.ExportTimelineCSV(id, w); err != nil {
		h.log.Error("timeline CSV export failed", "case", id, "error", err)
	}
}

func (h *handlers) exportFindingsCSV(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", `attachment; filename="findings-`+id+`.csv"`)
	if err := h.svc.ExportFindingsCSV(id, w); err != nil {
		h.log.Error("findings CSV export failed", "case", id, "error", err)
	}
}
