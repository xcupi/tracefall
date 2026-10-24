package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"tracefall/internal/narrative"
	"tracefall/internal/store"
)

func (h *handlers) getReviewBatchHistory(w http.ResponseWriter, r *http.Request) {
	s := h.as(r)
	id := r.PathValue("id")
	if _, err := s.GetCase(id); h.fail(w, err) {
		return
	}
	offset, limit := 0, 20
	var err error
	if v := r.URL.Query().Get("offset"); v != "" {
		offset, err = strconv.Atoi(v)
		if err != nil {
			writeError(w, 400, "invalid history offset")
			return
		}
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		limit, err = strconv.Atoi(v)
		if err != nil {
			writeError(w, 400, "invalid history limit")
			return
		}
	}
	if offset < 0 || limit < 1 || limit > 100 {
		writeError(w, 400, "offset must be >=0; limit 1..100")
		return
	}
	plans, total, err := s.store.BatchHistory(id, offset, limit)
	if h.fail(w, err) {
		return
	}
	for i, raw := range plans {
		var p ReviewBatchPlan
		if err = json.Unmarshal(raw, &p); h.fail(w, err) {
			return
		}
		p.Progress, err = s.store.BatchProgress(id, p.ID)
		if h.fail(w, err) {
			return
		}
		plans[i], err = json.Marshal(p)
		if h.fail(w, err) {
			return
		}
	}
	writeJSON(w, 200, map[string]any{"plans": plans, "total": total, "offset": offset, "limit": limit, "has_more": offset+len(plans) < total})
}
func (h *handlers) getReviewBatchPayload(w http.ResponseWriter, r *http.Request) {
	s := h.as(r)
	caseID, runID := r.PathValue("id"), r.PathValue("run")
	if _, err := s.GetCase(caseID); h.fail(w, err) {
		return
	}
	if _, err := s.readBatchPlan(caseID, runID); err != nil {
		writeError(w, 404, "batch plan not found in this case")
		return
	}
	seq, err := strconv.Atoi(r.PathValue("seq"))
	if err != nil || seq < 0 {
		writeError(w, 400, "invalid packet sequence")
		return
	}
	rows, err := s.store.BatchPackets(caseID, runID, seq-1, 1)
	if h.fail(w, err) {
		return
	}
	var packet ReviewBatchPacket
	if len(rows) != 1 {
		writeError(w, 404, "packet not found")
		return
	}
	if err = json.Unmarshal(rows[0], &packet); h.fail(w, err) {
		return
	}
	if packet.Seq != seq || packet.Payload.SHA256 == "" {
		writeError(w, 404, "no prepared payload for this packet")
		return
	}
	writeJSON(w, 200, struct {
		Payload   NarrativePayload        `json:"payload"`
		Privacy   narrative.ReviewPrivacy `json:"privacy"`
		Attempted bool                    `json:"attempted"`
		State     string                  `json:"state"`
	}{packet.Payload, packet.Privacy, packet.AttemptedAt != "", packet.State})
}
func (h *handlers) getReviewBatchManifest(w http.ResponseWriter, r *http.Request) {
	s := h.as(r)
	caseID, runID := r.PathValue("id"), r.PathValue("run")
	if _, err := s.GetCase(caseID); h.fail(w, err) {
		return
	}
	p, err := s.readBatchPlan(caseID, runID)
	if err != nil {
		writeError(w, 404, "batch plan not found in this case")
		return
	}
	kind := r.URL.Query().Get("kind")
	total := 0
	switch kind {
	case "event":
		total = p.Snapshot.Events
	case "finding":
		total = p.Snapshot.Findings
	case "correlation":
		total = p.Snapshot.Correlations
	case "source":
		total = p.Snapshot.Sources
	default:
		writeError(w, 400, "kind must be event, finding, correlation or source")
		return
	}
	offset, limit := 0, store.BatchPageSize
	if v := r.URL.Query().Get("offset"); v != "" {
		offset, err = strconv.Atoi(v)
		if err != nil {
			writeError(w, 400, "invalid manifest offset")
			return
		}
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		limit, err = strconv.Atoi(v)
		if err != nil {
			writeError(w, 400, "invalid manifest limit")
			return
		}
	}
	if offset < 0 || limit < 1 || limit > store.BatchPageSize {
		writeError(w, 400, "offset must be >=0; limit 1..60")
		return
	}
	rows, err := s.store.BatchMembers(caseID, runID, kind, offset, limit)
	if h.fail(w, err) {
		return
	}
	members := []map[string]any{}
	for _, row := range rows {
		seq := -1
		switch kind {
		case "event":
			seq = row.Ordinal / store.BatchPageSize
		case "finding":
			seq = batchCount(p.Snapshot.Events, store.BatchPageSize) + row.Ordinal/20
		case "correlation":
			seq = batchCount(p.Snapshot.Events, store.BatchPageSize) + batchCount(p.Snapshot.Findings, 20) + row.Ordinal/20
		}
		members = append(members, map[string]any{"kind": kind, "member_id": row.ID, "ordinal": row.Ordinal, "primary_packet_seq": seq})
	}
	writeJSON(w, 200, map[string]any{"members": members, "total": total, "offset": offset, "limit": limit, "has_more": offset+len(rows) < total})
}
