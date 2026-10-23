package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"tracefall/internal/egress"
	"tracefall/internal/enrich/llm"
	"tracefall/internal/model"
	"tracefall/internal/narrative"
	"tracefall/internal/store"
)

// A language model drafts a short summary of a case's findings.
//
// Nothing here is needed for analysis and nothing here is evidence. A model on
// another machine is reached only if the case's egress level is
// "pseudonymized", the analyst acknowledges the provider's terms for that
// request, and the text to be sent has passed the leak check in
// internal/narrative. The exact text sent is stored with the draft, and every
// request, refusal and outcome is written to the case's audit trail.

var (
	// ErrNarrativeNotConfigured: no model is configured.
	ErrNarrativeNotConfigured = errors.New("no language model is configured: open Settings → Integrations to authorize ChatGPT and select a provider, or configure TRACEFALL_LLM_API_KEY and TRACEFALL_LLM_MODEL")
	// ErrNarrativeEgress: the case's egress level does not allow this.
	ErrNarrativeEgress = errors.New("the case's egress level does not allow sending this to another machine; raise it to \"pseudonymized\" first")
	// ErrNarrativeNeedsAck: a request to another machine needs the analyst's acknowledgement.
	ErrNarrativeNeedsAck = errors.New("this request goes to another machine: acknowledge that you have checked the provider's terms for the data it will receive")
	// ErrNarrativeRunning: a request for this case is already in progress.
	ErrNarrativeRunning = errors.New("a summary for this case is already being drafted")
	// ErrNarrativeNoFindings: there is nothing to summarise.
	ErrNarrativeNoFindings = errors.New("the case has no findings to summarise: run the analysis first")
	// ErrNarrativeRefused: the text still held identifying values, so nothing was sent.
	ErrNarrativeRefused = errors.New("the text to send still held identifying values after pseudonymization; nothing was sent")
)

// SetLLM configures the language model. Call it before the service handles
// requests. A nil or key-less client leaves drafting unavailable.
func (s *Service) SetLLM(c llm.Chatter) {
	if c == nil {
		c = llm.None{}
	}
	s.llm.mu.Lock()
	s.llm.api = c
	s.llm.mu.Unlock()
}

// NarrativeRun is the state of a request.
type NarrativeRun struct {
	State      string `json:"state"` // running, finished, failed, cancelled
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

type narrativeRun struct {
	mu     sync.Mutex
	st     NarrativeRun
	cancel context.CancelFunc
}

func (r *narrativeRun) snapshot() NarrativeRun { r.mu.Lock(); defer r.mu.Unlock(); return r.st }

type narrativeManager struct {
	mu   sync.Mutex
	runs map[string]*narrativeRun
}

func newNarrativeManager() *narrativeManager {
	return &narrativeManager{runs: map[string]*narrativeRun{}}
}

// NarrativeView is a stored draft as the API shows it.
type NarrativeView struct {
	ID               string               `json:"id"`
	CreatedAt        string               `json:"created_at"`
	Status           string               `json:"status"`
	Error            string               `json:"error,omitempty"`
	Destination      string               `json:"destination"`
	Local            bool                 `json:"local"`
	Model            string               `json:"model"`
	Sentences        []narrative.Sentence `json:"sentences"`
	Rejected         int                  `json:"rejected"`
	Reasons          map[string]int       `json:"reasons,omitempty"`
	PayloadSHA256    string               `json:"payload_sha256"`
	PromptTokens     int                  `json:"prompt_tokens"`
	CompletionTokens int                  `json:"completion_tokens"`
	FindingsCovered  int                  `json:"findings_covered"`
	// Stale is true when the case's findings are no longer the ones this draft covered.
	Stale bool `json:"stale"`
}

// NarrativeStatus is where a case stands. It sends nothing.
type NarrativeStatus struct {
	Configured  bool   `json:"configured"`
	Destination string `json:"destination,omitempty"`
	Local       bool   `json:"local"`
	Model       string `json:"model,omitempty"`
	// Notice is what the provider route says about how it treats what it
	// receives, to be read before acknowledging a request.
	Notice      string `json:"notice,omitempty"`
	EgressLevel string `json:"egress_level"`
	// Allowed: the egress level lets this request go where it goes.
	Allowed bool `json:"allowed"`
	// NeedsAcknowledgement: the request goes to another machine.
	NeedsAcknowledgement bool           `json:"needs_acknowledgement"`
	Findings             int            `json:"findings"`
	Run                  *NarrativeRun  `json:"run,omitempty"`
	Latest               *NarrativeView `json:"latest,omitempty"`
}

func narrativeAllowed(client llm.Chatter, lvl egress.Level) (configured, allowed, local bool) {
	if !client.Configured() {
		return false, false, false
	}
	_, local = client.Destination()
	// a model on this machine is not an outside service: nothing leaves
	return true, local || lvl.AtLeast(egress.Pseudonymized), local
}

func viewOf(n model.Narrative, current []model.Finding) NarrativeView {
	v := NarrativeView{ID: n.ID, CreatedAt: n.CreatedAt.UTC().Format(time.RFC3339), Status: n.Status, Error: n.Error,
		Destination: n.Destination, Local: n.Local, Model: n.Model, Rejected: n.Rejected, PayloadSHA256: n.PayloadSHA256,
		PromptTokens: n.PromptTokens, CompletionTokens: n.CompletionTokens, FindingsCovered: len(n.FindingIDs)}
	_ = json.Unmarshal([]byte(n.SentencesJSON), &v.Sentences)
	if n.ReasonsJSON != "" {
		_ = json.Unmarshal([]byte(n.ReasonsJSON), &v.Reasons)
	}
	now := narrative.Select(current, narrative.DefaultLimits)
	ids := make([]string, len(now))
	for i, f := range now {
		ids[i] = f.ID
	}
	sort.Strings(ids)
	was := append([]string(nil), n.FindingIDs...)
	sort.Strings(was)
	v.Stale = len(ids) != len(was)
	if !v.Stale {
		for i := range ids {
			if ids[i] != was[i] {
				v.Stale = true
			}
		}
	}
	return v
}

// NarrativeStatus describes the case's state. It sends nothing.
func (s *Service) NarrativeStatus(caseID string) (NarrativeStatus, error) {
	client := s.llm.snapshot()
	lvl, err := s.EgressLevel(caseID)
	if err != nil {
		return NarrativeStatus{}, err
	}
	findings, err := s.store.ListFindings(caseID)
	if err != nil {
		return NarrativeStatus{}, err
	}
	configured, allowed, local := narrativeAllowed(client, lvl)
	st := NarrativeStatus{Configured: configured, EgressLevel: string(lvl), Allowed: allowed, Local: local, Findings: len(findings), NeedsAcknowledgement: configured && !local}
	if configured {
		st.Destination, _ = client.Destination()
		st.Model = client.ModelName()
		st.Notice = client.Notice()
	}
	if n, ok, err := s.store.LatestNarrative(caseID); err != nil {
		return NarrativeStatus{}, err
	} else if ok {
		v := viewOf(n, findings)
		st.Latest = &v
	}
	s.narr.mu.Lock()
	run := s.narr.runs[caseID]
	s.narr.mu.Unlock()
	if run != nil {
		rs := run.snapshot()
		st.Run = &rs
	}
	return st, nil
}

// NarrativePayload is exactly what was sent for the latest draft.
type NarrativePayload struct {
	System      string `json:"system"`
	User        string `json:"user"`
	SHA256      string `json:"sha256"`
	Destination string `json:"destination"`
	Model       string `json:"model"`
	SentAt      string `json:"sent_at"`
}

// LatestNarrativePayload returns what the latest request sent.
func (s *Service) LatestNarrativePayload(caseID string) (NarrativePayload, bool, error) {
	if _, err := s.GetCase(caseID); err != nil {
		return NarrativePayload{}, false, err
	}
	n, ok, err := s.store.LatestNarrative(caseID)
	if err != nil || !ok {
		return NarrativePayload{}, false, err
	}
	return NarrativePayload{System: n.PayloadSystem, User: n.PayloadUser, SHA256: n.PayloadSHA256, Destination: n.Destination, Model: n.Model, SentAt: n.CreatedAt.UTC().Format(time.RFC3339)}, true, nil
}

func payloadHash(system, user string) string {
	h := sha256.Sum256([]byte(system + "\x00" + user))
	return hex.EncodeToString(h[:])
}

// StartNarrative prepares the request, records it, and sends it in the
// background. Everything that can refuse does so before anything leaves.
func (s *Service) StartNarrative(caseID string, acknowledge bool) (NarrativeStatus, error) {
	client, release, leaseErr := s.llm.acquire()
	if leaseErr != nil {
		return NarrativeStatus{}, leaseErr
	}
	handedOff := false
	defer func() {
		if !handedOff {
			release()
		}
	}()
	lvl, err := s.EgressLevel(caseID)
	if err != nil {
		return NarrativeStatus{}, err
	}
	configured, allowed, local := narrativeAllowed(client, lvl)
	if !configured {
		return NarrativeStatus{}, ErrNarrativeNotConfigured
	}
	if !allowed {
		return NarrativeStatus{}, ErrNarrativeEgress
	}
	if !local && !acknowledge {
		return NarrativeStatus{}, ErrNarrativeNeedsAck
	}

	s.narr.mu.Lock()
	if r := s.narr.runs[caseID]; r != nil && r.snapshot().State == "running" {
		s.narr.mu.Unlock()
		return NarrativeStatus{}, ErrNarrativeRunning
	}
	s.narr.mu.Unlock()

	findings, err := s.store.ListFindings(caseID)
	if err != nil {
		return NarrativeStatus{}, err
	}
	if len(findings) == 0 {
		return NarrativeStatus{}, ErrNarrativeNoFindings
	}
	sel := narrative.Select(findings, narrative.DefaultLimits)
	var ids []string
	for _, f := range sel {
		ids = append(ids, f.SupportingEvents...)
	}
	evs, err := s.store.EventsByIDs(ids)
	if err != nil {
		return NarrativeStatus{}, fmt.Errorf("loading cited events: %w", err)
	}
	byID := make(map[string]model.Event, len(evs))
	for _, e := range evs {
		if e.CaseID == caseID {
			byID[e.ID] = e
		}
	}
	names, err := s.store.CaseNames(caseID)
	if err != nil {
		if errors.Is(err, store.ErrTooManyNames) {
			s.audit(caseID, model.AuditNarrativeRefused, model.TargetCase, caseID, "Summary request stopped before sending: the case has more distinct names than the pseudonymizer can hold. Nothing was sent.")
		}
		return NarrativeStatus{}, err
	}
	pr, err := narrative.Prepare(narrative.Input{Findings: findings, Events: byID, Names: narrative.Names{Hosts: names.Hosts, Users: names.Users, Domains: names.Domains}})
	if err != nil {
		if errors.Is(err, narrative.ErrLeak) {
			// the message names kinds of text, never values
			s.audit(caseID, model.AuditNarrativeRefused, model.TargetCase, caseID, "Summary request stopped before sending: "+err.Error()+".")
			return NarrativeStatus{}, ErrNarrativeRefused
		}
		return NarrativeStatus{}, err
	}

	host, _ := client.Destination()
	sum := payloadHash(pr.System, pr.User)
	where := "to " + host
	if local {
		where = "to a model on this machine (" + host + ")"
	}
	s.audit(caseID, model.AuditNarrativeRequested, model.TargetCase, caseID, fmt.Sprintf(
		"Sending pseudonymized facts %s, model %s, at egress level %s: %d finding(s), %d event(s), %d characters. Names, addresses, identifiers and hashes are replaced by tokens and secrets are removed. SHA-256 of exactly what was sent: %s.%s",
		where, client.ModelName(), lvl, len(pr.FindingIDs), len(pr.EventIDs), len(pr.System)+len(pr.User), sum,
		map[bool]string{true: " The analyst acknowledged the provider's terms for this request.", false: ""}[!local]))

	ctx, cancel := context.WithCancel(context.Background())
	run := &narrativeRun{cancel: cancel, st: NarrativeRun{State: "running", StartedAt: time.Now().UTC().Format(time.RFC3339)}}
	s.narr.mu.Lock()
	if r := s.narr.runs[caseID]; r != nil && r.snapshot().State == "running" {
		s.narr.mu.Unlock()
		cancel()
		return NarrativeStatus{}, ErrNarrativeRunning
	}
	s.narr.runs[caseID] = run
	s.narr.mu.Unlock()
	handedOff = true
	go func() { defer release(); s.runNarrative(ctx, caseID, pr, run, host, local, sum, client) }()
	return s.NarrativeStatus(caseID)
}

// CancelNarrative stops a request in progress.
func (s *Service) CancelNarrative(caseID string) error {
	if _, err := s.GetCase(caseID); err != nil {
		return err
	}
	s.narr.mu.Lock()
	run := s.narr.runs[caseID]
	s.narr.mu.Unlock()
	if run != nil {
		run.cancel()
	}
	return nil
}

func (s *Service) runNarrative(ctx context.Context, caseID string, pr *narrative.Prepared, run *narrativeRun, host string, local bool, sum string, client llm.Chatter) {
	n := model.Narrative{ID: uuid.NewString(), CaseID: caseID, CreatedAt: time.Now().UTC(), Destination: host, Local: local, Model: client.ModelName(),
		PayloadSystem: pr.System, PayloadUser: pr.User, PayloadSHA256: sum, FindingIDs: pr.FindingIDs, RequestedBy: s.auditActor(), SentencesJSON: "[]"}
	finish := func(state, reason string) {
		if state != "finished" {
			n.Status, n.Error = model.NarrativeError, reason
		}
		if serr := s.store.SaveNarrative(n); serr != nil && state == "finished" {
			state, reason = "failed", "could not store the draft"
		}
		run.mu.Lock()
		run.st.State, run.st.FinishedAt, run.st.Reason = state, time.Now().UTC().Format(time.RFC3339), reason
		run.mu.Unlock()
		run.cancel()
		s.audit(caseID, model.AuditNarrativeFinished, model.TargetCase, caseID, fmt.Sprintf(
			"Summary request %s: %d sentence(s) kept, %d dropped by validation.%s%s",
			state, len(sentencesOf(n)), n.Rejected,
			map[bool]string{true: fmt.Sprintf(" %d prompt and %d completion tokens.", n.PromptTokens, n.CompletionTokens), false: ""}[n.PromptTokens > 0 || n.CompletionTokens > 0],
			map[bool]string{true: " " + reason + ".", false: ""}[reason != ""]))
	}

	msgs := []llm.Message{{Role: "system", Content: pr.System}, {Role: "user", Content: pr.User}}
	res, err := client.Chat(ctx, msgs)
	var rl *llm.RateLimitError
	if errors.As(err, &rl) {
		select {
		case <-ctx.Done():
			finish("cancelled", "cancelled")
			return
		case <-time.After(rl.RetryAfter):
		}
		res, err = client.Chat(ctx, msgs)
	}
	switch {
	case errors.Is(err, context.Canceled):
		finish("cancelled", "cancelled")
		return
	case err != nil:
		finish("failed", safeEnrichError(err))
		return
	}
	if ctx.Err() != nil {
		finish("cancelled", "cancelled")
		return
	}
	n.RawAnswer, n.PromptTokens, n.CompletionTokens = res.Content, res.PromptTokens, res.CompletionTokens
	if res.Model != "" {
		// the model that answered, when the provider says (a default is not known until then)
		n.Model = res.Model
	}
	draft, verr := pr.Validate(res.Content)
	n.Rejected = draft.Rejected
	if len(draft.Reasons) > 0 {
		b, _ := json.Marshal(draft.Reasons)
		n.ReasonsJSON = string(b)
	}
	if verr != nil {
		finish("failed", "the model's answer had no sentence that passed validation")
		return
	}
	b, _ := json.Marshal(draft.Sentences)
	n.SentencesJSON = string(b)
	n.Status = model.NarrativeOK
	finish("finished", "")
}

func sentencesOf(n model.Narrative) []narrative.Sentence {
	var out []narrative.Sentence
	_ = json.Unmarshal([]byte(n.SentencesJSON), &out)
	return out
}
