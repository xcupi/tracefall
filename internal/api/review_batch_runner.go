package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
	"unicode/utf8"

	"tracefall/internal/enrich/llm"
	"tracefall/internal/model"
	"tracefall/internal/narrative"
)

type batchManager struct {
	mu            sync.Mutex
	runs          map[string]*batchActive
	policyBlocked map[string]int
}
type batchActive struct {
	id       string
	external bool
	cancel   context.CancelFunc
}

func newBatchManager() *batchManager {
	return &batchManager{runs: map[string]*batchActive{}, policyBlocked: map[string]int{}}
}

func (s *Service) readBatchPlan(caseID, runID string) (ReviewBatchPlan, error) {
	raw, state, err := s.store.BatchRun(caseID, runID)
	var p ReviewBatchPlan
	if err == nil {
		err = json.Unmarshal(raw, &p)
		p.State = state
	}
	return p, err
}
func (s *Service) StartReviewBatches(caseID, runID, key string, ack bool) (ReviewBatchPlan, error) {
	if _, err := s.GetCase(caseID); err != nil {
		return ReviewBatchPlan{}, err
	}
	p, err := s.readBatchPlan(caseID, runID)
	if err != nil {
		return p, err
	}
	if p.State != "planned" || key == "" || key != p.PlanKey {
		return p, errReviewPreviewChanged
	}
	c, release, err := s.llm.acquire()
	if err != nil {
		return p, err
	}
	handed := false
	defer func() {
		if !handed {
			release()
		}
	}()
	// Full snapshot validation is streamed outside every run-map/policy lock.
	ctx := s.reqCtx
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, stop := context.WithTimeout(ctx, 60*time.Second)
	defer stop()
	snap, err := s.store.FreezeReviewSnapshot(ctx, caseID, "")
	if err != nil {
		return p, err
	}
	host, local := c.Destination()
	lvl, err := s.EgressLevel(caseID)
	if err != nil {
		return p, err
	}
	configured, allowed, _ := narrativeAllowed(c, lvl)
	if !configured {
		return p, ErrNarrativeNotConfigured
	}
	if !allowed {
		return p, ErrNarrativeEgress
	}
	if !local && !ack {
		return p, ErrNarrativeNeedsAck
	}
	if p.ProviderBinding != s.llm.batchBinding() || p.SourceFingerprint != snap.Fingerprint || p.Destination != host || p.Local != local || p.Model != c.ModelName() || p.EgressLevel != string(lvl) || p.PrivacyContract != narrative.ReviewPrivacyContract {
		return p, errReviewPreviewChanged
	}
	if p.EnabledBatches == 0 {
		return p, errReviewBudgetEmpty
	}
	// Reconstruct validators from frozen records and require byte-identical output
	// before registering any provider work. At most eight bounded preparations.
	p.Snapshot.Names = snap.Names
	packets, prepared, err := s.prepareBatchValidators(p, snap.Names)
	if err != nil {
		return p, err
	}
	s.batches.mu.Lock()
	defer s.batches.mu.Unlock()
	if !p.Local && s.batches.policyBlocked[caseID] > 0 {
		return p, ErrNarrativeEgress
	}
	if s.batches.runs[caseID] != nil {
		return p, errReviewRunning
	}
	// Policy could change during preparation. Admission and revocation share this
	// short lock, never a network or snapshot-building lock.
	lvl, err = s.EgressLevel(caseID)
	if err != nil {
		return p, err
	}
	_, allowed, _ = narrativeAllowed(c, lvl)
	if !allowed || string(lvl) != p.EgressLevel {
		return p, ErrNarrativeEgress
	}
	p.State = "running"
	p.Acknowledged = !local && ack
	p.RequestedBy = s.auditActor()
	p.StartedAt = time.Now().UTC().Format(time.RFC3339Nano)
	ok, err := s.store.UpdateBatchRun(caseID, runID, "planned", "running", p)
	if err != nil {
		return p, err
	}
	if !ok {
		return p, errReviewPreviewChanged
	}
	runCtx, cancel := context.WithTimeout(context.Background(), time.Duration(p.Budget.OverallSeconds)*time.Second)
	s.batches.runs[caseID] = &batchActive{id: runID, external: !local, cancel: cancel}
	s.audit(caseID, "case_review_batches_started", model.TargetCase, caseID, fmt.Sprintf("Approved parsed-snapshot batch plan %s; %d/%d initial packets enabled, %d request ceiling, no automatic retries. External acknowledgement=%t. Exact initial payloads frozen; optional commentary is not evidence.", runID, p.EnabledBatches, p.TotalBatches, p.Budget.Requests, !local && ack))
	handed = true
	go func() {
		defer release()
		defer cancel()
		defer func() { s.batches.mu.Lock(); delete(s.batches.runs, caseID); s.batches.mu.Unlock() }()
		s.runReviewBatches(runCtx, p, packets, prepared, c)
	}()
	return p, nil
}
func (s *Service) prepareBatchValidators(p ReviewBatchPlan, names narrative.Names) ([]ReviewBatchPacket, []*narrative.ReviewPrepared, error) {
	// Read budget-enabled packets directly, not a metadata page that may hold
	// only unreviewed packets. Reserve a full synthesis input packet up front.
	raws, err := s.store.BatchPackets(p.CaseID, p.ID, -1, 8, true)
	if err != nil {
		return nil, nil, err
	}
	var packets []ReviewBatchPacket
	var validators []*narrative.ReviewPrepared
	for _, raw := range raws {
		var packet ReviewBatchPacket
		if err = json.Unmarshal(raw, &packet); err != nil {
			return nil, nil, err
		}
		if packet.State != "ready" {
			continue
		}
		size := 60
		if packet.Kind != "event" {
			size = 20
		}
		in, err := s.batchInput(p.CaseID, p.ID, packet.Kind, packet.Offset, size, names)
		if err != nil {
			return nil, nil, err
		}
		pr, err := narrative.PrepareReview(in)
		if err != nil {
			return nil, nil, err
		}
		narrative.AddBatchCatalog(pr, p.Snapshot.Coverage, p.Snapshot.SourceParseGaps)
		pr.System += "\nAll aliases and pseudonyms in this request are scoped only to " + packet.Namespace + ". Equal-looking aliases in another packet MUST NOT be treated as equal identities."
		if payloadHash(pr.System, pr.User) != packet.Payload.SHA256 || pr.System != packet.Payload.System || pr.User != packet.Payload.User {
			return nil, nil, errReviewPreviewChanged
		}
		packets = append(packets, packet)
		validators = append(validators, pr)
	}
	return packets, validators, nil
}
func (s *Service) runReviewBatches(ctx context.Context, p ReviewBatchPlan, packets []ReviewBatchPacket, validators []*narrative.ReviewPrepared, c llm.Chatter) {
	requests, input, output := 0, 0, 0
	state, reason := "succeeded", "all enabled bounded requests validated; this does not establish semantic accuracy or raw-image completeness"
	synthAttempted := false
	for i := 0; ; i++ {
		if i == len(packets) {
			if !p.Budget.Synthesis || synthAttempted || ctx.Err() != nil {
				break
			}
			synthAttempted = true
			packet, validator, omitted, err := s.prepareBatchSynthesis(p, packets)
			p.SynthesisOmittedSentences = omitted
			if err != nil {
				p.SynthesisState = "omitted"
				state, reason = "partial", "synthesis preparation unavailable or privacy refused; initial results retained"
				break
			}
			p.SynthesisState = "ready"
			if reviewCoverageIncomplete(packet.Coverage) {
				p.InputIncomplete = true
			}
			if err = s.store.SaveBatchPacket(p.CaseID, p.ID, packet.Seq, "ready", packet); err != nil {
				state, reason = "failed", "could not persist dynamic synthesis packet"
				break
			}
			packets = append(packets, packet)
			validators = append(validators, validator)
		}
		packet := &packets[i]
		if reviewCoverageIncomplete(packet.Coverage) {
			p.InputIncomplete = true
		}
		if ctx.Err() != nil {
			state, reason = "cancelled", "cancelled"
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				state, reason = "partial", "overall time budget exhausted"
			}
			break
		}
		bytes := len(packet.Payload.System) + len(packet.Payload.User)
		if requests >= p.Budget.Requests || input+bytes > p.Budget.InputBytes || output >= p.Budget.OutputBytes {
			state, reason = "partial", "approved local budget exhausted"
			break
		}
		s.batches.mu.Lock()
		lvl, policyErr := s.EgressLevel(p.CaseID)
		_, allowed, _ := narrativeAllowed(c, lvl)
		if !p.Local && s.batches.policyBlocked[p.CaseID] > 0 {
			allowed = false
		}
		if policyErr != nil || !allowed || ctx.Err() != nil {
			s.batches.mu.Unlock()
			state, reason = "cancelled", "cancelled or current policy refused dispatch"
			break
		}
		packet.State = "sending"
		packet.AttemptedAt = time.Now().UTC().Format(time.RFC3339Nano)
		packet.Payload.SentAt = packet.AttemptedAt
		// The attempted exact text/digest is durable BEFORE entering Chatter.
		ok, err := s.store.UpdateBatchPacket(p.CaseID, p.ID, packet.Seq, "ready", "sending", packet)
		s.batches.mu.Unlock()
		if err != nil || !ok {
			state, reason = "failed", "could not persist attempted request or run no longer active"
			break
		}
		requests++
		input += bytes
		reqCtx, stop := context.WithTimeout(ctx, time.Duration(p.Budget.PerRequestSeconds)*time.Second)
		result, chatErr := c.Chat(reqCtx, []llm.Message{{Role: "system", Content: packet.Payload.System}, {Role: "user", Content: packet.Payload.User}})
		requestErr := reqCtx.Err()
		stop()
		packet.RawAnswer = result.Content
		packet.ActualModel = result.Model
		packet.PromptTokens = result.PromptTokens
		packet.CompletionTokens = result.CompletionTokens
		packet.State = "failed"
		remaining := p.Budget.OutputBytes - output
		switch {
		case len(result.Content) > remaining:
			// Local admission/storage limit, not a promise about provider computation.
			packet.RawAnswer = result.Content[:remaining]
			for i := 0; i < len(packet.RawAnswer); {
				_, size := utf8.DecodeRuneInString(packet.RawAnswer[i:])
				if size == 1 && packet.RawAnswer[i] >= utf8.RuneSelf {
					packet.RawAnswer = packet.RawAnswer[:i]
					break
				}
				i += size
			}
			output += len(packet.RawAnswer)
			packet.Error = "local response/output byte ceiling exceeded; raw answer truncated locally"
		case ctx.Err() != nil:
			output += len(result.Content)
			packet.State = "cancelled"
			packet.Error = "cancelled; delivery may have occurred"
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				packet.State = "failed"
				packet.Error = "overall time budget exhausted; delivery may have occurred"
			}
		case requestErr != nil || chatErr != nil:
			output += len(result.Content)
			packet.Error = "bounded provider request failed or timed out; no automatic retry"
		default:
			output += len(result.Content)
			draft, err := validators[i].Validate(result.Content)
			packet.Rejected = draft.Rejected
			packet.Reasons = draft.Reasons
			if err != nil {
				packet.Error = "no commentary sentence passed validation"
			} else {
				validatedBytes, _ := json.Marshal(draft.Sentences)
				if output+len(validatedBytes) > p.Budget.OutputBytes {
					packet.Error = "local validated-output byte ceiling exceeded; commentary not retained"
				} else {
					packet.Sentences = draft.Sentences
					packet.State = "succeeded"
					output += len(validatedBytes)
				}
			}
		}
		packet.OutputBytesRetained = len(packet.RawAnswer)
		if len(packet.Sentences) > 0 {
			b, _ := json.Marshal(packet.Sentences)
			packet.OutputBytesRetained += len(b)
		}
		ok, err = s.persistBatchOutcome(ctx, p, packet)
		if err != nil || !ok {
			state, reason = "failed", "outcome persistence refused; attempted request remains recorded"
			break
		}
		if packet.State != "succeeded" {
			state, reason = "partial", "a bounded request failed or was cancelled; subsequent packets not sent"
			if errors.Is(ctx.Err(), context.Canceled) {
				state = "cancelled"
			}
			break
		}
	}
	if state == "succeeded" && (p.InputIncomplete || p.EnabledBatches < p.TotalBatches || p.FindingsOmitted > 0 || p.CorrelationsOmitted > 0 || p.Snapshot.Coverage.SourcesFailed > 0 || p.Snapshot.Coverage.SourcesUnsupported > 0 || p.Snapshot.Coverage.SourcesNotImported > 0 || p.Snapshot.Coverage.ParseCoverageNotRecorded > 0 || p.Snapshot.SourceParseGaps > 0) {
		state, reason = "partial", "budget/claim/privacy omissions or source parse gaps; not whole-case review"
	}
	if p.Budget.Synthesis {
		p.SynthesisState = "omitted"
		p.UnsynthesizedBatches = 0
		for _, packet := range packets {
			if packet.Kind == "synthesis" {
				p.SynthesisState = packet.State
				if packet.State == "succeeded" {
					p.UnsynthesizedBatches = len(packet.OmittedSourceBatches)
				}
			}
		}
		if p.SynthesisState != "succeeded" {
			for _, packet := range packets {
				if packet.Kind != "synthesis" && packet.State == "succeeded" {
					p.UnsynthesizedBatches++
				}
			}
		}
		if state != "cancelled" && (p.SynthesisState != "succeeded" || p.SynthesisOmittedSentences > 0) {
			state, reason = "partial", "synthesis omitted/failed or commentary items dropped; initial results retained"
		}
	} else {
		p.SynthesisState = "disabled"
	}
	// Final admission shares revocation/cancel ordering too. Deadline exhaustion
	// takes precedence over a generic synthesis omission or successful loop exit.
	s.batches.mu.Lock()
	if err := ctx.Err(); err != nil {
		state, reason = "cancelled", "cancelled; already delivered bytes cannot be recalled"
		if errors.Is(err, context.DeadlineExceeded) {
			state, reason = "partial", "overall time budget exhausted"
		}
	}
	pendingState := "unreviewed"
	if state == "cancelled" {
		pendingState = "cancelled"
	}
	_ = s.store.ClosePendingBatchPackets(p.CaseID, p.ID, pendingState)
	p.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	p.Progress, _ = s.store.BatchProgress(p.CaseID, p.ID)
	p.State, p.Reason = state, reason
	_, _ = s.store.UpdateBatchRun(p.CaseID, p.ID, "running", state, p)
	s.batches.mu.Unlock()
	s.audit(p.CaseID, "case_review_batches_finished", model.TargetCase, p.CaseID, fmt.Sprintf("Parsed-snapshot batch run %s; %d request(s), %d admitted input bytes, %d retained response bytes. No automatic retry or resume; validated commentary is not evidence.", state, requests, input, output))
}

// persistBatchOutcome retains a late raw response without reviving a durable
// cancellation. An interrupted/deleted run still cannot be updated.
func (s *Service) persistBatchOutcome(ctx context.Context, p ReviewBatchPlan, packet *ReviewBatchPacket) (bool, error) {
	// Explicit cancellation and policy revocation use the same admission lock.
	// Observe cancellation and commit its outcome in one critical section; never
	// hold this mutex during Chat or validation.
	s.batches.mu.Lock()
	defer s.batches.mu.Unlock()
	cancelOutcome := func() {
		packet.State = "cancelled"
		packet.Sentences = nil
		packet.Error = "cancelled after provider outcome; delivery may have occurred"
		packet.OutputBytesRetained = len(packet.RawAnswer)
	}
	if err := ctx.Err(); err != nil {
		cancelOutcome()
		if errors.Is(err, context.DeadlineExceeded) {
			packet.State = "failed"
			packet.Error = "overall time budget exhausted after provider outcome; delivery may have occurred"
		}
	}
	return s.store.UpdateBatchPacket(p.CaseID, p.ID, packet.Seq, "sending", packet.State, packet)
}

func (h *handlers) startReviewBatches(w http.ResponseWriter, r *http.Request) {
	var body struct {
		PlanKey     string `json:"plan_key"`
		Acknowledge bool   `json:"acknowledge"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	p, err := h.as(r).StartReviewBatches(r.PathValue("id"), r.PathValue("run"), body.PlanKey, body.Acknowledge)
	if h.reviewFail(w, err) {
		return
	}
	writeJSON(w, 202, p)
}
func (s *Service) CancelReviewBatches(caseID, runID string) error {
	if _, err := s.GetCase(caseID); err != nil {
		return err
	}
	s.batches.mu.Lock()
	defer s.batches.mu.Unlock()
	if run := s.batches.runs[caseID]; run != nil && run.id == runID {
		run.cancel()
	}
	p, err := s.readBatchPlan(caseID, runID)
	if err != nil {
		return err
	}
	if p.State == "running" || p.State == "planned" {
		old := p.State
		p.State = "cancelled"
		p.Reason = "explicit cancellation; already delivered bytes cannot be recalled"
		_, err = s.store.UpdateBatchRun(caseID, runID, old, "cancelled", p)
	}
	if err == nil {
		err = s.store.ClosePendingBatchPackets(caseID, runID, "cancelled")
	}
	return err
}
func (h *handlers) cancelReviewBatches(w http.ResponseWriter, r *http.Request) {
	if h.fail(w, h.as(r).CancelReviewBatches(r.PathValue("id"), r.PathValue("run"))) {
		return
	}
	w.WriteHeader(204)
}
