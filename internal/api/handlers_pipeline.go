package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"tracefall/internal/model"
)

// HTTP surface for resumable uploads and the server-side pipeline
// (roadmap item 2). Protocol, in one paragraph: POST /uploads declares a
// file name and size and returns a session; PUT /uploads/{id} with an
// Upload-Offset header appends a chunk (409 with the true "received" count
// if the offset is wrong, which is also how a client discovers where to
// resume); GET /uploads/{id} reports "received" without sending anything;
// POST .../complete confirms every byte arrived; POST /pipeline/jobs then
// starts discover -> import -> analyze on the server.

// jobResponse is the wire form of a pipeline job. Progress and Result are
// stored as JSON text and returned as JSON objects.
type jobResponse struct {
	ID              string          `json:"job_id"`
	CaseID          string          `json:"case_id"`
	Kind            string          `json:"kind"`
	Status          string          `json:"status"`
	Stage           string          `json:"stage"`
	CollectionID    string          `json:"collection_id,omitempty"`
	Progress        json.RawMessage `json:"progress,omitempty"`
	Result          json.RawMessage `json:"result,omitempty"`
	Error           string          `json:"error,omitempty"`
	Attempts        int             `json:"attempts"`
	CancelRequested bool            `json:"cancel_requested"`
	CreatedBy       string          `json:"created_by"`
	CreatedAt       time.Time       `json:"created_at"`
	StartedAt       *time.Time      `json:"started_at,omitempty"`
	FinishedAt      *time.Time      `json:"finished_at,omitempty"`
}

func toJobResponse(j model.PipelineJob) jobResponse {
	r := jobResponse{
		ID: j.ID, CaseID: j.CaseID, Kind: j.Kind, Status: j.Status, Stage: j.Stage, CollectionID: j.CollectionID,
		Error: j.Error, Attempts: j.Attempts, CancelRequested: j.CancelRequested, CreatedBy: j.CreatedBy,
		CreatedAt: j.CreatedAt, StartedAt: j.StartedAt, FinishedAt: j.FinishedAt,
	}
	if json.Valid([]byte(j.Progress)) {
		r.Progress = json.RawMessage(j.Progress)
	}
	if json.Valid([]byte(j.Result)) {
		r.Result = json.RawMessage(j.Result)
	}
	return r
}

func (h *handlers) createUpload(w http.ResponseWriter, r *http.Request) {
	var in UploadInit
	if !decodeJSON(w, r, &in) {
		return
	}
	u, err := h.as(r).CreateUpload(r.PathValue("id"), in, h.maxUploadBytes)
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusCreated, u)
}

func (h *handlers) uploadStatus(w http.ResponseWriter, r *http.Request) {
	u, err := h.as(r).UploadStatus(r.PathValue("id"), r.PathValue("uploadID"))
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (h *handlers) uploadChunk(w http.ResponseWriter, r *http.Request) {
	offset, err := strconv.ParseInt(r.Header.Get("Upload-Offset"), 10, 64)
	if err != nil || offset < 0 {
		writeError(w, http.StatusBadRequest, "Upload-Offset header is required: the byte offset this chunk starts at")
		return
	}
	// A chunk is bounded by its own cap, independent of the whole-file
	// limit, so no single request can hold a connection indefinitely.
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadChunkBytes+1)
	u, err := h.as(r).AppendUploadChunk(r.PathValue("id"), r.PathValue("uploadID"), offset, r.Body)
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (h *handlers) completeUpload(w http.ResponseWriter, r *http.Request) {
	u, err := h.as(r).CompleteUpload(r.PathValue("id"), r.PathValue("uploadID"))
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (h *handlers) abortUpload(w http.ResponseWriter, r *http.Request) {
	if h.fail(w, h.as(r).AbortUpload(r.PathValue("id"), r.PathValue("uploadID"))) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": model.UploadAborted})
}

func (h *handlers) enqueuePipelineJob(w http.ResponseWriter, r *http.Request) {
	var p IngestJobParams
	if !decodeJSON(w, r, &p) {
		return
	}
	j, err := h.as(r).EnqueueIngest(r.PathValue("id"), p)
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusAccepted, toJobResponse(j))
}

func (h *handlers) listPipelineJobs(w http.ResponseWriter, r *http.Request) {
	jobs, err := h.as(r).ListPipelineJobs(r.PathValue("id"))
	if h.fail(w, err) {
		return
	}
	out := make([]jobResponse, 0, len(jobs))
	for _, j := range jobs {
		out = append(out, toJobResponse(j))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handlers) getPipelineJob(w http.ResponseWriter, r *http.Request) {
	j, err := h.as(r).GetPipelineJob(r.PathValue("id"), r.PathValue("jobID"))
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, toJobResponse(j))
}

func (h *handlers) cancelPipelineJob(w http.ResponseWriter, r *http.Request) {
	svc := h.as(r)
	if h.fail(w, svc.CancelPipelineJob(r.PathValue("id"), r.PathValue("jobID"))) {
		return
	}
	j, err := svc.GetPipelineJob(r.PathValue("id"), r.PathValue("jobID"))
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, toJobResponse(j))
}
