package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/google/uuid"
	"tracefall/internal/model"
	"tracefall/internal/narrative"
	"tracefall/internal/store"
)

var errReviewBudgetEmpty = errors.New("approved budget enables no initial packets; increase the explicit request/input allowance or disable synthesis")

// BatchBudget is an admitted local ceiling, not a provider compute/charge cap.
type BatchBudget struct {
	Requests          int  `json:"requests"`
	InputBytes        int  `json:"input_bytes"`
	OutputBytes       int  `json:"output_bytes"`
	PerRequestSeconds int  `json:"per_request_seconds"`
	OverallSeconds    int  `json:"overall_seconds"`
	Concurrency       int  `json:"concurrency"`
	Retries           int  `json:"retries"`
	Synthesis         bool `json:"synthesis"`
}

func defaultBatchBudget() BatchBudget {
	return BatchBudget{Requests: 8, InputBytes: 1280000, OutputBytes: 131072, PerRequestSeconds: 120, OverallSeconds: 900, Concurrency: 1, Retries: 0, Synthesis: true}
}
func (b BatchBudget) validate() error {
	if b.Requests < 1 || b.Requests > 8 || b.InputBytes < 4096 || b.InputBytes > 1280000 || b.OutputBytes < 1024 || b.OutputBytes > 131072 || b.PerRequestSeconds < 1 || b.PerRequestSeconds > 120 || b.OverallSeconds < 1 || b.OverallSeconds > 900 || b.Concurrency != 1 || b.Retries != 0 {
		return errors.New("invalid batch budget: requests 1..8, input_bytes 4096..1280000, output_bytes 1024..131072, per_request_seconds 1..120, overall_seconds 1..900, concurrency 1, retries 0")
	}
	return nil
}

type ReviewBatchPlan struct {
	Acknowledged              bool                 `json:"acknowledged"`
	RequestedBy               string               `json:"requested_by,omitempty"`
	StartedAt                 string               `json:"started_at,omitempty"`
	FinishedAt                string               `json:"finished_at,omitempty"`
	InputIncomplete           bool                 `json:"input_incomplete"`
	ProviderBinding           string               `json:"provider_binding"`
	ID                        string               `json:"id"`
	CaseID                    string               `json:"case_id"`
	State                     string               `json:"state"`
	Reason                    string               `json:"reason"`
	CreatedAt                 string               `json:"created_at"`
	PlanKey                   string               `json:"plan_key"`
	SourceFingerprint         string               `json:"source_fingerprint"`
	PrivacyContract           string               `json:"privacy_contract"`
	Destination               string               `json:"destination"`
	Model                     string               `json:"model"`
	Local                     bool                 `json:"local"`
	EgressLevel               string               `json:"egress_level"`
	Budget                    BatchBudget          `json:"budget"`
	EligibleEvents            int                  `json:"eligible_events"`
	PlannedEvents             int                  `json:"planned_events"`
	TotalBatches              int                  `json:"total_batches"`
	EnabledBatches            int                  `json:"enabled_batches"`
	InitialInputBytes         int                  `json:"initial_input_bytes"`
	FindingsIncluded          int                  `json:"findings_included"`
	FindingsOmitted           int                  `json:"findings_omitted"`
	CorrelationsIncluded      int                  `json:"correlations_included"`
	CorrelationsOmitted       int                  `json:"correlations_omitted"`
	Snapshot                  store.ReviewSnapshot `json:"snapshot"`
	Scope                     string               `json:"scope"`
	Progress                  store.BatchProgress  `json:"progress"`
	SynthesisState            string               `json:"synthesis_state"`
	SynthesisOmittedSentences int                  `json:"synthesis_omitted_sentences"`
	UnsynthesizedBatches      int                  `json:"unsynthesized_batches"`
}
type ReviewBatchPacket struct {
	OmittedSourceBatches []int                    `json:"omitted_source_batches,omitempty"`
	OutputBytesRetained  int                      `json:"output_bytes_retained"`
	Seq                  int                      `json:"seq"`
	Kind                 string                   `json:"kind"`
	Offset               int                      `json:"offset"`
	State                string                   `json:"state"`
	Namespace            string                   `json:"namespace"`
	PrimaryEvents        int                      `json:"primary_events"`
	EventIDs             []string                 `json:"event_ids"`
	FindingIDs           []string                 `json:"finding_ids"`
	CorrelationIDs       []string                 `json:"correlation_ids"`
	Payload              NarrativePayload         `json:"payload"`
	Privacy              narrative.ReviewPrivacy  `json:"privacy"`
	Coverage             narrative.ReviewCoverage `json:"coverage"`
	AttemptedAt          string                   `json:"attempted_at,omitempty"`
	RawAnswer            string                   `json:"raw_answer,omitempty"`
	Sentences            []narrative.Sentence     `json:"sentences,omitempty"`
	Rejected             int                      `json:"rejected"`
	Reasons              map[string]int           `json:"reasons,omitempty"`
	ActualModel          string                   `json:"actual_model,omitempty"`
	PromptTokens         int                      `json:"prompt_tokens,omitempty"`
	CompletionTokens     int                      `json:"completion_tokens,omitempty"`
	Error                string                   `json:"error,omitempty"`
}

func batchCount(n, size int) int { return (n + size - 1) / size }

func (s *Service) PlanReviewBatches(caseID string, budget BatchBudget) (plan ReviewBatchPlan, err error) {
	if _, err = s.GetCase(caseID); err != nil {
		return plan, err
	}
	if err = budget.validate(); err != nil {
		return plan, err
	}
	ctx := s.reqCtx
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	release, err := s.heavy.Acquire(ctx)
	if err != nil {
		return plan, err
	}
	defer release()
	id := uuid.NewString()
	snap, err := s.store.FreezeReviewSnapshot(ctx, caseID, id)
	if err != nil {
		return plan, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = s.store.DeleteBatchPlan(caseID, id)
		}
	}()
	if snap.Events+snap.Findings+snap.Correlations == 0 {
		return plan, errReviewEmpty
	}
	lvl, err := s.EgressLevel(caseID)
	if err != nil {
		return plan, err
	}
	providerBinding := s.llm.batchBinding()
	c := s.llm.snapshot()
	host, local := c.Destination()
	plan = ReviewBatchPlan{ProviderBinding: providerBinding, ID: id, CaseID: caseID, State: "planned", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), SourceFingerprint: snap.Fingerprint, PrivacyContract: narrative.ReviewPrivacyContract, Destination: host, Model: c.ModelName(), Local: local, EgressLevel: string(lvl), Budget: budget, EligibleEvents: snap.Events, Snapshot: snap, Scope: "bounded_batched_parsed_snapshot"}
	available := budget.Requests
	if budget.Synthesis {
		available--
	}
	seq := 0
	binding := ""
	for _, group := range []struct {
		kind    string
		n, size int
	}{{"event", snap.Events, store.BatchPageSize}, {"finding", snap.Findings, 20}, {"correlation", snap.Correlations, 20}} {
		for offset := 0; offset < group.n; offset += group.size {
			if err := ctx.Err(); err != nil {
				return plan, err
			}
			packet := ReviewBatchPacket{Seq: seq, Kind: group.kind, Offset: offset, State: "unreviewed", Namespace: fmt.Sprintf("packet_%d", seq)}
			plan.TotalBatches++
			seq++
			if plan.EnabledBatches < available {
				in, e := s.batchInput(caseID, id, group.kind, offset, group.size, snap.Names)
				if e != nil {
					return plan, e
				}
				pr, e := narrative.PrepareReview(in)
				if e != nil {
					return plan, e
				}
				// Per-packet aliases are explicitly scoped; synthesis must restore locally
				// and re-prepare, never concatenate incompatible USER_1/E1 dictionaries.
				narrative.AddBatchCatalog(pr, snap.Coverage, snap.SourceParseGaps)
				pr.System += "\nAll aliases and pseudonyms in this request are scoped only to " + packet.Namespace + ". Equal-looking aliases in another packet MUST NOT be treated as equal identities."
				if err := narrative.CheckReviewBatchSize(pr); err != nil {
					return plan, err
				}
				size := len(pr.System) + len(pr.User)
				reserve := 0
				if budget.Synthesis {
					reserve = narrative.ReviewMaxBytes
				}
				if plan.InitialInputBytes+size+reserve <= budget.InputBytes {
					packet.State = "ready"
					packet.Payload = NarrativePayload{System: pr.System, User: pr.User, SHA256: payloadHash(pr.System, pr.User), Destination: host, Model: c.ModelName()}
					packet.Privacy = pr.Privacy
					packet.Privacy.PayloadBytes = size
					packet.Coverage = pr.Coverage
					if cv := pr.Coverage; cv.EventsOmitted > 0 || cv.FindingsOmitted > 0 || cv.CorrelationsOmitted > 0 || cv.CommandLinesOmitted > 0 || cv.MissingSupportingRefs > 0 || cv.SupportingRefsOmitted > 0 {
						plan.InputIncomplete = true
					}
					packet.EventIDs = pr.EventIDs
					packet.FindingIDs = pr.FindingIDs
					for _, cc := range in.Correlations {
						packet.CorrelationIDs = append(packet.CorrelationIDs, cc.ID)
					}
					if group.kind == "event" {
						packet.PrimaryEvents = len(in.Events)
						plan.PlannedEvents += len(in.Events)
					}
					plan.FindingsIncluded += pr.Coverage.FindingsIncluded
					plan.CorrelationsIncluded += pr.Coverage.CorrelationsIncluded
					plan.EnabledBatches++
					plan.InitialInputBytes += size
					binding += packet.Payload.SHA256 + "\x00"
				} else {
					available = plan.EnabledBatches
				}
			}
			if err = s.store.SaveBatchPacket(caseID, id, packet.Seq, packet.State, packet); err != nil {
				return plan, err
			}
		}
	}
	plan.Progress, err = s.store.BatchProgress(caseID, id)
	if err != nil {
		return plan, err
	}
	plan.FindingsOmitted = snap.Findings - plan.FindingsIncluded
	plan.CorrelationsOmitted = snap.Correlations - plan.CorrelationsIncluded
	b, _ := json.Marshal(budget)
	plan.PlanKey = payloadHash(binding+snap.Fingerprint+plan.ProviderBinding, fmt.Sprintf("%T\x00%s\x00%s\x00%t\x00%s\x00%s\x00%s", c, host, c.ModelName(), local, lvl, narrative.ReviewPrivacyContract, b))
	if s.llm.batchBinding() != providerBinding {
		return plan, errReviewPreviewChanged
	}
	if err = s.store.SaveBatchRun(caseID, id, "planned", plan); err != nil {
		return plan, err
	}
	keep = true
	return plan, nil
}
func (s *Service) batchInput(caseID, runID, kind string, offset, size int, names narrative.Names) (narrative.ReviewInput, error) {
	in := narrative.ReviewInput{CaseID: caseID, Names: names, KnownOmittedEvents: map[string]bool{}}
	records, err := s.store.BatchMembers(caseID, runID, kind, offset, size)
	if err != nil {
		return in, err
	}
	refs := map[string]bool{}
	for _, r := range records {
		switch kind {
		case "event":
			var e model.Event
			err = json.Unmarshal([]byte(r.JSON), &e)
			in.Events = append(in.Events, e)
		case "finding":
			var f model.Finding
			err = json.Unmarshal([]byte(r.JSON), &f)
			in.Findings = append(in.Findings, f)
			for _, id := range f.SupportingEvents {
				refs[id] = true
			}
		case "correlation":
			var c model.Correlation
			err = json.Unmarshal([]byte(r.JSON), &c)
			in.Correlations = append(in.Correlations, c)
			for _, id := range c.EventIDs {
				refs[id] = true
			}
		}
		if err != nil {
			return in, err
		}
	}
	// Bound context explicitly; PrepareReview counts unresolved/omitted claim refs.
	ids := make([]string, 0, len(refs))
	for id := range refs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if len(refs) > 10000 {
			return in, fmt.Errorf("%w: claim context exceeds 10000 references", store.ErrReviewSnapshotLimit)
		}
		if len(in.Events) >= store.BatchPageSize {
			exists, err := s.store.BatchMemberExists(caseID, runID, "event", id)
			if err != nil {
				return in, err
			}
			if exists {
				in.KnownOmittedEvents[id] = true
			}
			continue
		}
		e, ok, err := s.store.BatchEvent(caseID, runID, id)
		if err != nil {
			return in, err
		}
		if ok {
			in.Events = append(in.Events, e)
		}
	}
	sources, err := s.store.BatchMembers(caseID, runID, "source", 0, store.BatchPageSize)
	if err != nil {
		return in, err
	}
	for _, r := range sources {
		var sf model.SourceFile
		if err := json.Unmarshal([]byte(r.JSON), &sf); err != nil {
			return in, err
		}
		in.Sources = append(in.Sources, sf)
	}
	return in, nil
}

func (h *handlers) planReviewBatches(w http.ResponseWriter, r *http.Request) {
	body := struct {
		Budget *BatchBudget `json:"budget"`
	}{}
	if !decodeJSON(w, r, &body) {
		return
	}
	budget := defaultBatchBudget()
	if body.Budget != nil {
		budget = *body.Budget
	}
	if err := budget.validate(); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	plan, err := h.as(r).PlanReviewBatches(r.PathValue("id"), budget)
	if h.reviewFail(w, err) {
		return
	}
	writeJSON(w, http.StatusCreated, plan)
}
func (h *handlers) getReviewBatches(w http.ResponseWriter, r *http.Request) {
	s := h.as(r)
	id := r.PathValue("id")
	if _, err := s.GetCase(id); h.fail(w, err) {
		return
	}
	raw, state, err := s.store.BatchRun(id, r.PathValue("run"))
	if errors.Is(err, sql.ErrNoRows) {
		if r.PathValue("run") != "" {
			writeError(w, 404, "batch plan not found in this case")
			return
		}
		writeJSON(w, 200, map[string]any{"latest": nil, "defaults": defaultBatchBudget()})
		return
	}
	if h.fail(w, err) {
		return
	}
	var p ReviewBatchPlan
	if err = json.Unmarshal(raw, &p); h.fail(w, err) {
		return
	}
	p.State = state
	p.Progress, err = s.store.BatchProgress(id, p.ID)
	if h.fail(w, err) {
		return
	}
	writeJSON(w, 200, p)
}
func parsePage(r *http.Request) (int, int, error) {
	after, limit := -1, 20
	var err error
	if v := r.URL.Query().Get("after"); v != "" {
		after, err = strconv.Atoi(v)
		if err != nil {
			return 0, 0, err
		}
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		limit, err = strconv.Atoi(v)
	}
	if after < -1 || limit < 1 || limit > 100 {
		return 0, 0, errors.New("after must be >= -1; limit 1..100")
	}
	return after, limit, err
}
func (h *handlers) getReviewBatchPackets(w http.ResponseWriter, r *http.Request) {
	s := h.as(r)
	id := r.PathValue("id")
	if _, err := s.GetCase(id); h.fail(w, err) {
		return
	}
	after, limit, err := parsePage(r)
	if err != nil {
		writeError(w, 400, "after must be >= -1; limit 1..100")
		return
	}
	if _, err := s.readBatchPlan(id, r.PathValue("run")); err != nil {
		writeError(w, 404, "batch plan not found in this case")
		return
	}
	rows, err := s.store.BatchPackets(id, r.PathValue("run"), after, limit)
	if h.fail(w, err) {
		return
	}
	writeJSON(w, 200, map[string]any{"packets": rows, "after": after, "limit": limit})
}
