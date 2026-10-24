package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"tracefall/internal/egress"
	"tracefall/internal/enrich/llm"
	"tracefall/internal/model"
	"tracefall/internal/narrative"
	"tracefall/internal/store"
)

var errReviewPreviewChanged = errors.New("case review preview is missing or changed: inspect the current preview before starting")
var errReviewEmpty = errors.New("there are no parsed events, findings or correlations to review")
var errReviewRunning = errors.New("a bounded case review is already running")

type CaseReviewView struct {
	Privacy *narrative.ReviewPrivacy `json:"privacy,omitempty"`
	NarrativeView
	Coverage          narrative.ReviewCoverage `json:"coverage"`
	SourceFingerprint string                   `json:"source_fingerprint"`
}
type CaseReviewStatus struct {
	PrivacyContract      string          `json:"privacy_contract"`
	SourceFingerprint    string          `json:"source_fingerprint"`
	Configured           bool            `json:"configured"`
	Allowed              bool            `json:"allowed"`
	Local                bool            `json:"local"`
	Destination          string          `json:"destination"`
	Model                string          `json:"model"`
	Notice               string          `json:"notice"`
	EgressLevel          string          `json:"egress_level"`
	NeedsAcknowledgement bool            `json:"needs_acknowledgement"`
	Scope                string          `json:"scope"`
	Events               int             `json:"events"`
	Run                  *NarrativeRun   `json:"run,omitempty"`
	Latest               *CaseReviewView `json:"latest,omitempty"`
}
type CaseReviewPreview struct {
	EgressLevel string                  `json:"egress_level"`
	Local       bool                    `json:"local"`
	Privacy     narrative.ReviewPrivacy `json:"privacy"`
	PreviewKey  string                  `json:"preview_key"`
	NarrativePayload
	Coverage          narrative.ReviewCoverage `json:"coverage"`
	SourceFingerprint string                   `json:"source_fingerprint"`
}

func (s *Service) reviewPreparationContext() (context.Context, context.CancelFunc) {
	ctx := s.reqCtx
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(ctx, 60*time.Second)
}

func (s *Service) reviewInput(caseID string) (narrative.ReviewInput, error) {
	ctx, cancel := s.reviewPreparationContext()
	defer cancel()
	if err := ctx.Err(); err != nil {
		return narrative.ReviewInput{}, err
	}
	in := narrative.ReviewInput{CaseID: caseID}
	if _, err := s.GetCase(caseID); err != nil {
		return in, err
	}
	var err error
	if in.Events, err = s.store.ListEvents(caseID); err != nil {
		return in, err
	}
	if in.Findings, err = s.store.ListFindings(caseID); err != nil {
		return in, err
	}
	if in.Correlations, err = s.store.ListCorrelations(caseID); err != nil {
		return in, err
	}
	if in.Sources, err = s.store.ListSourceFiles(caseID); err != nil {
		return in, err
	}
	pr, e := narrative.PrepareReview(in)
	if e != nil {
		return in, e
	}
	selected := map[string]bool{}
	for _, id := range pr.EventIDs {
		selected[id] = true
	}
	var events []model.Event
	for _, ev := range in.Events {
		if selected[ev.ID] {
			events = append(events, ev)
		}
	}
	vt, cv, e := s.store.ReviewVTContext(ctx, caseID, "", events)
	if e != nil {
		return in, e
	}
	in.Enrichments = vt
	in.VTCatalog = &cv
	return in, nil
}
func (s *Service) prepareCaseReview(caseID string) (*narrative.ReviewPrepared, error) {
	ctx, cancel := s.reviewPreparationContext()
	defer cancel()
	before, _, err := s.store.LegacyReviewFingerprint(ctx, caseID)
	if err != nil {
		return nil, err
	}
	in, err := s.reviewInput(caseID)
	if err != nil {
		if errors.Is(err, narrative.ErrNothingToSay) {
			return nil, errReviewEmpty
		}
		if errors.Is(err, narrative.ErrLeak) {
			s.audit(caseID, "case_review_refused", model.TargetCase, caseID, "Bounded case review refused by the pseudonymization leak gate. Nothing was sent.")
			return nil, ErrNarrativeRefused
		}
		return nil, err
	}
	names, err := s.store.CaseNames(caseID)
	if err != nil {
		return nil, err
	}
	in.Names = narrative.Names{Hosts: names.Hosts, Users: names.Users, Domains: names.Domains}
	pr, err := narrative.PrepareReview(in)
	if errors.Is(err, narrative.ErrNothingToSay) {
		return nil, errReviewEmpty
	}
	if errors.Is(err, narrative.ErrLeak) {
		s.audit(caseID, "case_review_refused", model.TargetCase, caseID, "Bounded case review refused by the pseudonymization leak gate. Nothing was sent.")
		return nil, ErrNarrativeRefused
	}
	if err == nil {
		pr.Fingerprint, _, err = s.store.LegacyReviewFingerprint(ctx, caseID)
		if err == nil && pr.Fingerprint != before {
			return nil, errReviewPreviewChanged
		}
	}
	return pr, err
}

// reviewPreviewKey binds consent to the exact selected source snapshot and provider,
// separate from the independently inspectable hash of the system/user payload.
func reviewPreviewKey(pr *narrative.ReviewPrepared, c llm.Chatter, lvl egress.Level) string {
	host, local := c.Destination()
	return payloadHash(payloadHash(pr.System, pr.User)+"\x00"+pr.Fingerprint, fmt.Sprintf("%T\x00%s\x00%s\x00%t\x00%s\x00%s", c, host, c.ModelName(), local, lvl, pr.Privacy.Contract))
}

// PreviewCaseReview is local-only and never calls Chat or acquires credentials.
func (s *Service) PreviewCaseReview(caseID string) (CaseReviewPreview, error) {
	pr, err := s.prepareCaseReview(caseID)
	if err != nil {
		return CaseReviewPreview{}, err
	}
	c := s.llm.snapshot()
	host, local := c.Destination()
	lvl, err := s.EgressLevel(caseID)
	if err != nil {
		return CaseReviewPreview{}, err
	}
	return CaseReviewPreview{EgressLevel: string(lvl), Local: local, Privacy: pr.Privacy, NarrativePayload: NarrativePayload{System: pr.System, User: pr.User, SHA256: payloadHash(pr.System, pr.User), Destination: host, Model: c.ModelName()}, Coverage: pr.Coverage, SourceFingerprint: pr.Fingerprint, PreviewKey: reviewPreviewKey(pr, c, lvl)}, nil
}
func (s *Service) CaseReviewStatus(caseID string) (CaseReviewStatus, error) {
	if _, err := s.GetCase(caseID); err != nil {
		return CaseReviewStatus{}, err
	}
	ctx := s.reqCtx
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	fingerprint, eventCount, err := s.store.LegacyReviewFingerprint(ctx, caseID)
	if err != nil {
		return CaseReviewStatus{}, err
	}
	lvl, err := s.EgressLevel(caseID)
	if err != nil {
		return CaseReviewStatus{}, err
	}
	c := s.llm.snapshot()
	configured, allowed, local := narrativeAllowed(c, lvl)
	host, _ := c.Destination()
	st := CaseReviewStatus{PrivacyContract: narrative.ReviewPrivacyContract, Configured: configured, Allowed: allowed, Local: local, Destination: host, Model: c.ModelName(), Notice: c.Notice(), EgressLevel: string(lvl), NeedsAcknowledgement: configured && !local, Scope: "bounded_partial_parsed_case", Events: eventCount}
	st.SourceFingerprint = fingerprint
	// Read the durable outcome and terminal run state from one admission view;
	// otherwise a poll can combine the initial error row with a finished run.
	s.review.mu.Lock()
	defer s.review.mu.Unlock()
	r, ok, err := s.store.LatestCaseReview(caseID)
	if err != nil {
		return st, err
	}
	if ok {
		n := r.Narrative
		v := CaseReviewView{Privacy: r.Privacy, NarrativeView: NarrativeView{ID: n.ID, CreatedAt: n.CreatedAt.UTC().Format(time.RFC3339), Status: n.Status, Error: n.Error, Destination: n.Destination, Local: n.Local, Model: n.Model, Rejected: n.Rejected, PayloadSHA256: n.PayloadSHA256, PromptTokens: n.PromptTokens, CompletionTokens: n.CompletionTokens, FindingsCovered: len(n.FindingIDs), Stale: r.Fingerprint != st.SourceFingerprint}, Coverage: r.Coverage, SourceFingerprint: r.Fingerprint}
		_ = json.Unmarshal([]byte(n.SentencesJSON), &v.Sentences)
		_ = json.Unmarshal([]byte(n.ReasonsJSON), &v.Reasons)
		st.Latest = &v
	}
	run := s.review.runs[caseID]
	if run != nil {
		rs := run.snapshot()
		st.Run = &rs
	}
	return st, nil
}
func (s *Service) LatestCaseReviewPayload(caseID string) (NarrativePayload, bool, error) {
	if _, err := s.GetCase(caseID); err != nil {
		return NarrativePayload{}, false, err
	}
	r, ok, err := s.store.LatestCaseReview(caseID)
	if err != nil || !ok {
		return NarrativePayload{}, false, err
	}
	n := r.Narrative
	return NarrativePayload{System: n.PayloadSystem, User: n.PayloadUser, SHA256: n.PayloadSHA256, Destination: n.Destination, Model: n.Model, SentAt: n.CreatedAt.UTC().Format(time.RFC3339)}, true, nil
}

// StartCaseReview pins the existing hardened provider. The persisted request is
// written before Chat; interrupted runs remain explicit errors, never resumed.
func (s *Service) StartCaseReview(caseID string, ack bool, previewKey string) (CaseReviewStatus, error) {
	c, release, err := s.llm.acquire()
	if err != nil {
		return CaseReviewStatus{}, err
	}
	handedOff := false
	defer func() {
		if !handedOff {
			release()
		}
	}()
	s.review.mu.Lock()
	defer s.review.mu.Unlock()
	lvl, err := s.EgressLevel(caseID)
	if err != nil {
		return CaseReviewStatus{}, err
	}
	configured, allowed, local := narrativeAllowed(c, lvl)
	if !configured {
		return CaseReviewStatus{}, ErrNarrativeNotConfigured
	}
	if !allowed {
		return CaseReviewStatus{}, ErrNarrativeEgress
	}
	if !local && !ack {
		return CaseReviewStatus{}, ErrNarrativeNeedsAck
	}
	if r := s.review.runs[caseID]; r != nil && r.snapshot().State == "running" {
		return CaseReviewStatus{}, errReviewRunning
	}
	pr, err := s.prepareCaseReview(caseID)
	if err != nil {
		return CaseReviewStatus{}, err
	}
	sum := payloadHash(pr.System, pr.User)
	if previewKey == "" || previewKey != reviewPreviewKey(pr, c, lvl) {
		return CaseReviewStatus{}, errReviewPreviewChanged
	}
	host, _ := c.Destination()
	now := time.Now().UTC()
	row := store.CaseReview{FrozenVT: pr.FrozenVT, Privacy: &pr.Privacy, Narrative: model.Narrative{ID: uuid.NewString(), CaseID: caseID, CreatedAt: now, Destination: host, Local: local, Model: c.ModelName(), PayloadSystem: pr.System, PayloadUser: pr.User, PayloadSHA256: sum, FindingIDs: pr.FindingIDs, RequestedBy: s.auditActor(), SentencesJSON: "[]", Status: model.NarrativeError, Error: "request not completed (running or interrupted); no automatic resume"}, Coverage: pr.Coverage, Fingerprint: pr.Fingerprint}
	if err := s.store.SaveCaseReview(row); err != nil {
		return CaseReviewStatus{}, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	run := &narrativeRun{cancel: cancel, externalReview: !local, st: NarrativeRun{State: "running", StartedAt: now.Format(time.RFC3339)}}
	s.review.runs[caseID] = run
	s.audit(caseID, "case_review_requested", model.TargetCase, caseID, fmt.Sprintf("Prepared an attempt for one bounded partial parsed-case review to %s, model %s, egress %s, external acknowledgement=%t: %d/%d events, %d findings, %d correlations. Payload SHA-256 %s. Optional commentary, not findings/evidence; no raw-image or exhaustive review.", host, c.ModelName(), lvl, !local && ack, pr.Coverage.EventsIncluded, pr.Coverage.EventsTotal, pr.Coverage.FindingsIncluded, pr.Coverage.CorrelationsIncluded, sum))
	handedOff = true
	go func() { defer release(); s.runCaseReview(ctx, caseID, pr, row, run, c) }()
	// Do not call status here while holding the run-map lock.
	rs := run.snapshot()
	return CaseReviewStatus{Configured: configured, Allowed: allowed, Local: local, Destination: host, Model: c.ModelName(), Scope: "bounded_partial_parsed_case", Run: &rs}, nil
}
func (s *Service) CancelCaseReview(caseID string) error {
	if _, err := s.GetCase(caseID); err != nil {
		return err
	}
	s.review.mu.Lock()
	defer s.review.mu.Unlock()
	r := s.review.runs[caseID]
	if r != nil {
		r.cancel()
	}
	return nil
}
func (s *Service) runCaseReview(ctx context.Context, caseID string, pr *narrative.ReviewPrepared, row store.CaseReview, run *narrativeRun, c llm.Chatter) {
	defer run.cancel()
	state, reason := "finished", ""
	n := &row.Narrative
	// Admission and privacy preparation are not a lasting egress grant. Check
	// again at dispatch; policy changes cancel the same transport context,
	// including any retry. Already-delivered bytes cannot be recalled.
	s.review.mu.Lock()
	var res llm.Result
	err := ctx.Err()
	if err == nil {
		lvl, policyErr := s.EgressLevel(caseID)
		_, allowed, _ := narrativeAllowed(c, lvl)
		if policyErr != nil || !allowed {
			err = errors.New("case review refused before dispatch: current case policy does not permit this request; nothing sent")
		}
	}
	s.review.mu.Unlock()
	if err == nil {
		res, err = c.Chat(ctx, []llm.Message{{Role: "system", Content: pr.System}, {Role: "user", Content: pr.User}})
	}
	n.RawAnswer, n.PromptTokens, n.CompletionTokens = res.Content, res.PromptTokens, res.CompletionTokens
	if res.Model != "" {
		n.Model = res.Model
	}
	switch {
	case errors.Is(err, context.Canceled):
		state, reason = "cancelled", "cancelled"
	case err != nil:
		state, reason = "failed", safeEnrichError(err)
	default:
		d, verr := pr.Validate(res.Content)
		n.Rejected = d.Rejected
		b, _ := json.Marshal(d.Reasons)
		n.ReasonsJSON = string(b)
		if verr != nil {
			state, reason = "failed", "no commentary sentence passed validation"
		} else {
			b, _ = json.Marshal(d.Sentences)
			n.SentencesJSON = string(b)
			n.Status = model.NarrativeOK
			n.Error = ""
		}
	}
	s.admitCaseReviewOutcome(ctx, caseID, row, run, state, reason)
}

func (s *Service) admitCaseReviewOutcome(ctx context.Context, caseID string, row store.CaseReview, run *narrativeRun, state, reason string) {
	n := &row.Narrative
	// Validation and provider work stay outside admission. The final context
	// observation, durable outcome and published run state are one ordered
	// boundary with explicit cancellation, policy revocation and deletion.
	s.review.mu.Lock()
	defer s.review.mu.Unlock()
	if ctx.Err() != nil {
		state, reason = "cancelled", "cancelled"
		n.SentencesJSON = "[]"
	}
	if state != "finished" {
		n.Status, n.Error = model.NarrativeError, reason
	}
	// Deletion won admission and removed the attempt; do not recreate it or
	// replace cancellation with a misleading storage-failure outcome.
	if _, err := s.GetCase(caseID); errors.Is(err, ErrCaseNotFound) {
		run.mu.Lock()
		run.st.State, run.st.Reason, run.st.FinishedAt = "cancelled", "case deleted", time.Now().UTC().Format(time.RFC3339)
		run.mu.Unlock()
		return
	}
	if err := s.store.SaveCaseReview(row); err != nil {
		state, reason = "failed", "could not store the review outcome; initial payload remains recorded"
	}
	s.audit(caseID, "case_review_finished", model.TargetCase, caseID, fmt.Sprintf("Bounded case review %s; %d line(s) rejected. Validation checks references, entities and numbers, not semantic truth.", state, n.Rejected))
	run.mu.Lock()
	run.st.State, run.st.Reason, run.st.FinishedAt = state, reason, time.Now().UTC().Format(time.RFC3339)
	run.mu.Unlock()
}
