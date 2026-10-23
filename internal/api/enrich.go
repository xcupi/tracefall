package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"tracefall/internal/egress"
	"tracefall/internal/enrich/virustotal"
	"tracefall/internal/model"
)

// Outside enrichment.
//
// Nothing here is needed for analysis. A case's egress level (internal/egress)
// says how much of it may leave the server; it starts at "none", an analyst
// raises it, and every change and every transmission is recorded in the case's
// audit trail. VirusTotal needs level "hashes": it is sent file hashes and
// nothing else, and its answers are stored as enrichments, apart from events
// and findings, which they never alter.

var (
	// ErrEgressDenied: the case's egress level does not allow this.
	ErrEgressDenied = errors.New("the case's egress level does not allow sending this outside; raise it to \"hashes\" first")
	// ErrEgressUnavailable: the level exists but no feature uses it yet.
	ErrEgressUnavailable = errors.New("that egress level is reserved: no feature uses it in this version")
	// ErrEnrichNotConfigured: no VirusTotal API key.
	ErrEnrichNotConfigured = errors.New("VirusTotal is not configured: set TRACEFALL_VT_API_KEY")
	// ErrEnrichRunning: a lookup run for this case is already in progress.
	ErrEnrichRunning = errors.New("a VirusTotal lookup for this case is already running")
	// ErrEnrichDailyLimit: the day's request allowance is used up.
	ErrEnrichDailyLimit = errors.New("the VirusTotal daily request allowance is used up")
)

const (
	// vtDailyLimit is the free API's allowance per day.
	vtDailyLimit = 500
	// vtRetryCap bounds how long a rate-limit answer is waited out.
	vtRetryCap = 2 * time.Minute
	// vtMaxEventRefs bounds the events remembered for one hash.
	vtMaxEventRefs = 50
	// vtMaxConsecutiveErrors stops a run that keeps failing.
	vtMaxConsecutiveErrors = 5
)

// hashFieldKeys are the event fields that hold the hash of a file that was in
// the evidence. The list is exact and fixed. Fields that merely contain "hash"
// or "sha" (an NTLM hash, the hash of a SQL record, of a boot key's source
// file) are not file hashes and are never read.
var hashFieldKeys = []string{"content_sha256", "response_sha256", "sha256", "sha1", "md5"}

// SetVirusTotal configures VirusTotal lookups. Call it before the service
// handles requests. A nil or key-less client leaves lookups unavailable.
func (s *Service) SetVirusTotal(c *virustotal.Client) { s.vt = c }

// ---------- egress level ----------

func egressKey(caseID string) string { return "egress:" + caseID }

// EgressLevel is how much of the case may leave the server. A stored value
// that is not a known level means none: the failure is always toward keeping
// the data in.
func (s *Service) EgressLevel(caseID string) (egress.Level, error) {
	if _, err := s.GetCase(caseID); err != nil {
		return egress.None, err
	}
	v, ok, err := s.store.GetSetting(egressKey(caseID))
	if err != nil {
		return egress.None, err
	}
	if !ok {
		return egress.None, nil
	}
	l, err := egress.Parse(v)
	if err != nil {
		return egress.None, nil
	}
	return l, nil
}

// SetEgressLevel changes it and records the change.
func (s *Service) SetEgressLevel(caseID, level string) (egress.Level, error) {
	l, err := egress.Parse(level)
	if err != nil {
		return egress.None, err
	}
	if !l.Selectable() {
		return egress.None, ErrEgressUnavailable
	}
	old, err := s.EgressLevel(caseID)
	if err != nil {
		return egress.None, err
	}
	if old == l {
		return l, nil
	}
	if err := s.store.SetSetting(egressKey(caseID), string(l)); err != nil {
		return egress.None, err
	}
	s.audit(caseID, model.AuditEgressChanged, model.TargetCase, caseID, fmt.Sprintf("Egress level changed from %s to %s. %s", old, l, l.Describe()))
	return l, nil
}

// ---------- candidates ----------

// VTCandidate is a file hash found in a case's evidence.
type VTCandidate struct {
	Hash     string   `json:"hash"`
	Type     string   `json:"type"`
	EventIDs []string `json:"event_ids"`
}

// the hashes of empty content: looking them up says nothing about the case.
var trivialHashes = map[string]bool{
	"d41d8cd98f00b204e9800998ecf8427e":                                 true,
	"da39a3ee5e6b4b0d3255bfef95601890afd80709":                         true,
	"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": true,
}

func trivialHash(h string) bool {
	return trivialHashes[h] || strings.Trim(h, "0") == ""
}

// VirusTotalCandidates lists the distinct, valid, non-trivial file hashes in a
// case's events, each with the events that held it.
func (s *Service) VirusTotalCandidates(caseID string) ([]VTCandidate, error) {
	fields, err := s.store.EventFieldsByKey(caseID, hashFieldKeys)
	if err != nil {
		return nil, err
	}
	by := map[string]*VTCandidate{}
	for _, f := range fields {
		h := strings.ToLower(strings.TrimSpace(f.Value))
		if !virustotal.ValidHash(h) || trivialHash(h) {
			continue
		}
		c := by[h]
		if c == nil {
			c = &VTCandidate{Hash: h, Type: virustotal.HashType(h)}
			by[h] = c
		}
		if len(c.EventIDs) < vtMaxEventRefs && (len(c.EventIDs) == 0 || c.EventIDs[len(c.EventIDs)-1] != f.EventID) {
			c.EventIDs = append(c.EventIDs, f.EventID)
		}
	}
	out := make([]VTCandidate, 0, len(by))
	for _, c := range by {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hash < out[j].Hash })
	return out, nil
}

// ---------- the run ----------

// VTRunStatus is the state of a lookup run.
type VTRunStatus struct {
	State      string `json:"state"` // running, finished, stopped, cancelled
	Total      int    `json:"total"`
	Done       int    `json:"done"`
	Found      int    `json:"found"`
	NotFound   int    `json:"not_found"`
	Errors     int    `json:"errors"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

type vtRun struct {
	mu     sync.Mutex
	st     VTRunStatus
	cancel context.CancelFunc
}

func (r *vtRun) snapshot() VTRunStatus { r.mu.Lock(); defer r.mu.Unlock(); return r.st }

type enrichManager struct {
	mu   sync.Mutex
	runs map[string]*vtRun
}

func newEnrichManager() *enrichManager { return &enrichManager{runs: map[string]*vtRun{}} }

// VTStatus is what the API reports about VirusTotal for a case.
type VTStatus struct {
	Configured      bool         `json:"configured"`
	EgressLevel     string       `json:"egress_level"`
	Allowed         bool         `json:"allowed"`
	Candidates      int          `json:"candidates"`
	AlreadyAnswered int          `json:"already_answered"`
	Pending         int          `json:"pending"`
	DailyUsed       int          `json:"daily_used"`
	DailyLimit      int          `json:"daily_limit"`
	Run             *VTRunStatus `json:"run,omitempty"`
}

func answered(e model.Enrichment) bool {
	return e.Status == model.EnrichmentFound || e.Status == model.EnrichmentNotFound
}

// VirusTotalStatus describes where a case stands. It sends nothing.
func (s *Service) VirusTotalStatus(caseID string) (VTStatus, error) {
	lvl, err := s.EgressLevel(caseID)
	if err != nil {
		return VTStatus{}, err
	}
	cands, err := s.VirusTotalCandidates(caseID)
	if err != nil {
		return VTStatus{}, err
	}
	have, err := s.store.ListEnrichments(caseID, model.EnrichmentVirusTotal)
	if err != nil {
		return VTStatus{}, err
	}
	done := map[string]bool{}
	for _, e := range have {
		if answered(e) {
			done[e.Indicator] = true
		}
	}
	st := VTStatus{Configured: s.vt.Configured(), EgressLevel: string(lvl), Allowed: lvl.AtLeast(egress.Hashes), Candidates: len(cands), DailyLimit: vtDailyLimit}
	for _, c := range cands {
		if done[c.Hash] {
			st.AlreadyAnswered++
		} else {
			st.Pending++
		}
	}
	st.DailyUsed, err = s.store.CountEnrichmentRequestsSince(model.EnrichmentVirusTotal, time.Now().UTC().Add(-24*time.Hour))
	if err != nil {
		return VTStatus{}, err
	}
	s.enrich.mu.Lock()
	run := s.enrich.runs[caseID]
	s.enrich.mu.Unlock()
	if run != nil {
		rs := run.snapshot()
		st.Run = &rs
	}
	return st, nil
}

// StartVirusTotal begins looking up the case's file hashes in the background.
// It refuses unless the case's egress level allows hashes to leave and a key is
// configured, and it never looks up a hash already answered.
func (s *Service) StartVirusTotal(caseID string) (VTStatus, error) {
	lvl, err := s.EgressLevel(caseID)
	if err != nil {
		return VTStatus{}, err
	}
	if !lvl.AtLeast(egress.Hashes) {
		return VTStatus{}, ErrEgressDenied
	}
	if !s.vt.Configured() {
		return VTStatus{}, ErrEnrichNotConfigured
	}
	cands, err := s.VirusTotalCandidates(caseID)
	if err != nil {
		return VTStatus{}, err
	}
	have, err := s.store.ListEnrichments(caseID, model.EnrichmentVirusTotal)
	if err != nil {
		return VTStatus{}, err
	}
	done := map[string]bool{}
	for _, e := range have {
		if answered(e) {
			done[e.Indicator] = true
		}
	}
	var pending []VTCandidate
	for _, c := range cands {
		if !done[c.Hash] {
			pending = append(pending, c)
		}
	}

	s.enrich.mu.Lock()
	if r := s.enrich.runs[caseID]; r != nil && r.snapshot().State == "running" {
		s.enrich.mu.Unlock()
		return VTStatus{}, ErrEnrichRunning
	}
	used, err := s.store.CountEnrichmentRequestsSince(model.EnrichmentVirusTotal, time.Now().UTC().Add(-24*time.Hour))
	if err != nil {
		s.enrich.mu.Unlock()
		return VTStatus{}, err
	}
	remaining := vtDailyLimit - used
	if len(pending) > 0 && remaining <= 0 {
		s.enrich.mu.Unlock()
		return VTStatus{}, ErrEnrichDailyLimit
	}
	reason := ""
	if len(pending) > remaining && remaining > 0 {
		pending = pending[:remaining]
		reason = "limited to the day's remaining allowance; start again later for the rest"
	}
	ctx, cancel := context.WithCancel(context.Background())
	run := &vtRun{cancel: cancel, st: VTRunStatus{State: "running", Total: len(pending), StartedAt: time.Now().UTC().Format(time.RFC3339), Reason: reason}}
	if len(pending) == 0 {
		run.st.State, run.st.FinishedAt, run.st.Reason = "finished", run.st.StartedAt, "nothing left to look up"
		cancel()
	}
	s.enrich.runs[caseID] = run
	s.enrich.mu.Unlock()

	if len(pending) > 0 {
		hashes := make([]string, len(pending))
		for i, p := range pending {
			hashes[i] = p.Hash
		}
		sum := sha256.Sum256([]byte(strings.Join(hashes, "\n")))
		s.audit(caseID, model.AuditEnrichmentSent, model.TargetCase, caseID, fmt.Sprintf(
			"Sending %d file hash(es) to VirusTotal at egress level hashes. Only the hashes are sent: no file name, path, host, user or case detail, and no file. SHA-256 of the sorted list sent: %s.",
			len(hashes), hex.EncodeToString(sum[:])))
		go s.runVirusTotal(ctx, caseID, pending, run)
	}
	return s.VirusTotalStatus(caseID)
}

// CancelVirusTotal stops a running lookup. Answers already stored are kept.
func (s *Service) CancelVirusTotal(caseID string) error {
	if _, err := s.GetCase(caseID); err != nil {
		return err
	}
	s.enrich.mu.Lock()
	run := s.enrich.runs[caseID]
	s.enrich.mu.Unlock()
	if run != nil {
		run.cancel()
	}
	return nil
}

func (s *Service) runVirusTotal(ctx context.Context, caseID string, pending []VTCandidate, run *vtRun) {
	finish := func(state, reason string) {
		run.mu.Lock()
		run.st.State, run.st.FinishedAt = state, time.Now().UTC().Format(time.RFC3339)
		if reason != "" {
			run.st.Reason = reason
		}
		st := run.st
		run.mu.Unlock()
		run.cancel()
		s.audit(caseID, model.AuditEnrichmentFinished, model.TargetCase, caseID, fmt.Sprintf(
			"VirusTotal lookup %s: %d of %d answered (%d known to VirusTotal, %d not found, %d errors).%s",
			state, st.Done-st.Errors, st.Total, st.Found, st.NotFound, st.Errors, map[bool]string{true: " " + st.Reason + ".", false: ""}[st.Reason != ""]))
	}
	consecutive := 0
	for _, c := range pending {
		res, err := s.vtLookup(ctx, c.Hash)
		var qe *virustotal.QuotaError
		switch {
		case errors.Is(err, context.Canceled):
			finish("cancelled", "")
			return
		case errors.Is(err, virustotal.ErrAuth):
			finish("stopped", "VirusTotal refused the API key")
			return
		case errors.As(err, &qe) && qe.Daily:
			finish("stopped", "VirusTotal's daily quota is used up")
			return
		case errors.As(err, &qe):
			wait := qe.RetryAfter
			if wait > vtRetryCap {
				wait = vtRetryCap
			}
			select {
			case <-ctx.Done():
				finish("cancelled", "")
				return
			case <-time.After(wait):
			}
			res, err = s.vtLookup(ctx, c.Hash)
			if errors.As(err, &qe) {
				finish("stopped", "VirusTotal's rate limit did not clear")
				return
			}
		}
		if ctx.Err() != nil {
			// cancelled while the request was in flight: that is not an answer
			finish("cancelled", "")
			return
		}
		e := model.Enrichment{ID: uuid.NewString(), CaseID: caseID, Provider: model.EnrichmentVirusTotal, IndicatorType: c.Type, Indicator: c.Hash,
			FetchedAt: time.Now().UTC(), SourceEventIDs: c.EventIDs}
		switch {
		case err != nil:
			e.Status, e.Error = model.EnrichmentError, safeEnrichError(err)
			consecutive++
		case !res.Found:
			e.Status = model.EnrichmentNotFound
			b, _ := json.Marshal(res)
			e.ResultJSON = string(b)
			consecutive = 0
		default:
			e.Status = model.EnrichmentFound
			b, _ := json.Marshal(res)
			e.ResultJSON = string(b)
			consecutive = 0
		}
		if serr := s.store.UpsertEnrichment(e); serr != nil {
			finish("stopped", "could not store an answer")
			return
		}
		run.mu.Lock()
		run.st.Done++
		switch e.Status {
		case model.EnrichmentFound:
			run.st.Found++
		case model.EnrichmentNotFound:
			run.st.NotFound++
		default:
			run.st.Errors++
		}
		run.mu.Unlock()
		if consecutive >= vtMaxConsecutiveErrors {
			finish("stopped", fmt.Sprintf("%d lookups in a row failed", consecutive))
			return
		}
	}
	finish("finished", "")
}

func (s *Service) vtLookup(parent context.Context, hash string) (virustotal.Result, error) {
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()
	return s.vt.Lookup(ctx, hash)
}

// safeEnrichError is a reason that is safe to store and show.
func safeEnrichError(err error) string {
	msg := err.Error()
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return msg
}

// VTResult is one stored answer with its parsed result.
type VTResult struct {
	Indicator     string             `json:"indicator"`
	IndicatorType string             `json:"indicator_type"`
	Status        string             `json:"status"`
	Error         string             `json:"error,omitempty"`
	FetchedAt     string             `json:"fetched_at"`
	EventIDs      []string           `json:"source_event_ids"`
	Result        *virustotal.Result `json:"result,omitempty"`
}

// VirusTotalResults lists the stored answers for a case.
func (s *Service) VirusTotalResults(caseID string) ([]VTResult, error) {
	if _, err := s.GetCase(caseID); err != nil {
		return nil, err
	}
	rows, err := s.store.ListEnrichments(caseID, model.EnrichmentVirusTotal)
	if err != nil {
		return nil, err
	}
	out := make([]VTResult, 0, len(rows))
	for _, e := range rows {
		r := VTResult{Indicator: e.Indicator, IndicatorType: e.IndicatorType, Status: e.Status, Error: e.Error, FetchedAt: e.FetchedAt.UTC().Format(time.RFC3339), EventIDs: e.SourceEventIDs}
		if e.Status != model.EnrichmentError && e.ResultJSON != "" {
			var res virustotal.Result
			if json.Unmarshal([]byte(e.ResultJSON), &res) == nil {
				r.Result = &res
			}
		}
		out = append(out, r)
	}
	return out, nil
}
