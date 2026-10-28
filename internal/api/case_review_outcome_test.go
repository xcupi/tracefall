package api

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"tracefall/internal/enrich/llm"
	"tracefall/internal/model"
	"tracefall/internal/store"
)

type reviewOutcomeChatter struct{ result string }

func (c reviewOutcomeChatter) Chat(context.Context, []llm.Message) (llm.Result, error) {
	return llm.Result{Content: c.result}, nil
}
func (reviewOutcomeChatter) Destination() (string, bool) { return "synthetic.invalid", false }
func (reviewOutcomeChatter) ModelName() string           { return "synthetic" }
func (reviewOutcomeChatter) Notice() string              { return "" }
func (reviewOutcomeChatter) Configured() bool            { return true }

// The second Err observation is the old pre-validation observation. Revocation
// may interleave only if that observation is outside durable outcome admission.
func TestCaseReviewOutcomeObservationSerialized(t *testing.T) {
	for _, mode := range []string{"cancel", "policy", "delete"} {
		t.Run(mode, func(t *testing.T) {
			mux, svc := newTestRouterWithService(t)
			id := caseWithFindings(t, svc, mux, nil)
			seedStoredReviewVT(t, svc, id)
			if _, err := svc.SetEgressLevel(id, "pseudonymized"); err != nil {
				t.Fatal(err)
			}
			pr, err := svc.prepareCaseReview(id)
			if err != nil {
				t.Fatal(err)
			}
			answer := "hypothesis | Stored opinion flagged 2 engines. [V1]"
			if d, err := pr.Validate(answer); err != nil || len(d.Sentences) != 1 {
				t.Fatalf("fixture must validate: %+v %v", d, err)
			}
			row := store.CaseReview{FrozenVT: pr.FrozenVT, Coverage: pr.Coverage, Fingerprint: pr.Fingerprint, Narrative: model.Narrative{ID: "outcome-review", CaseID: id, CreatedAt: time.Now().UTC(), Status: model.NarrativeError, SentencesJSON: "[]", PayloadSystem: pr.System, PayloadUser: pr.User, PayloadSHA256: payloadHash(pr.System, pr.User)}}
			if err := svc.store.SaveCaseReview(row); err != nil {
				t.Fatal(err)
			}
			base, cancel := context.WithCancel(context.Background())
			defer cancel()
			run := &narrativeRun{cancel: cancel, externalReview: true, st: NarrativeRun{State: "running"}}
			svc.review.runs[id] = run
			calls := 0
			interleaved := false
			ctx := &reviewOutcomeContext{Context: base, observe: func() {
				calls++
				if calls != 2 {
					return
				}
				if svc.review.mu.TryLock() {
					svc.review.mu.Unlock()
					interleaved = true
					switch mode {
					case "cancel":
						err = svc.CancelCaseReview(id)
					case "policy":
						_, err = svc.SetEgressLevel(id, "none")
					case "delete":
						err = svc.DeleteCase(id)
					}
					if err != nil {
						t.Fatal(err)
					}
				}
			}}
			svc.runCaseReview(ctx, id, pr, row, run, reviewOutcomeChatter{answer})
			saved, ok, err := svc.store.LatestCaseReview(id)
			if interleaved {
				t.Fatalf("%s interleaved after final observation: context=%v run=%+v durable=%+v present=%t err=%v", mode, base.Err(), run.snapshot(), saved.Narrative, ok, err)
			}
			if err != nil || !ok || saved.Narrative.Status != model.NarrativeOK || run.snapshot().State != "finished" {
				t.Fatalf("admission winner: %+v %t %v %+v", saved, ok, err, run.snapshot())
			}
		})
	}
}

type reviewOutcomeContext struct {
	context.Context
	observe func()
}

func (c *reviewOutcomeContext) Err() error { err := c.Context.Err(); c.observe(); return err }

// Pause precisely after successful V-cited validation, revoke through a
// WithActor copy, then admit the outcome. No transport or validation under lock.
func TestCaseReviewRevocationWinsValidatedOutcome(t *testing.T) {
	for _, mode := range []string{"cancel", "policy", "delete"} {
		t.Run(mode, func(t *testing.T) {
			mux, svc := newTestRouterWithService(t)
			stub := newLLMStub(t, svc, false)
			id := caseWithFindings(t, svc, mux, nil)
			seedStoredReviewVT(t, svc, id)
			if _, err := svc.SetEgressLevel(id, "pseudonymized"); err != nil {
				t.Fatal(err)
			}
			pr, err := svc.prepareCaseReview(id)
			if err != nil {
				t.Fatal(err)
			}
			answer := "hypothesis | Stored opinion flagged 2 engines. [V1]"
			d, err := pr.Validate(answer)
			if err != nil || len(d.Sentences) != 1 {
				t.Fatalf("validation: %v", err)
			}
			sentences, _ := json.Marshal(d.Sentences)
			row := store.CaseReview{FrozenVT: pr.FrozenVT, Coverage: pr.Coverage, Fingerprint: pr.Fingerprint, Narrative: model.Narrative{ID: "cancel-winner", CaseID: id, CreatedAt: time.Now().UTC(), Status: model.NarrativeOK, SentencesJSON: string(sentences), RawAnswer: answer, PayloadSystem: pr.System, PayloadUser: pr.User, PayloadSHA256: payloadHash(pr.System, pr.User)}}
			if err := svc.store.SaveCaseReview(row); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			run := &narrativeRun{cancel: cancel, externalReview: true, st: NarrativeRun{State: "running"}}
			svc.review.runs[id] = run
			validated, resume, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			go func() {
				close(validated)
				<-resume
				svc.admitCaseReviewOutcome(ctx, id, row, run, "finished", "")
				close(done)
			}()
			<-validated
			// A shallow request copy must share admission and the run pointer.
			scoped := *svc
			switch mode {
			case "cancel":
				err = scoped.CancelCaseReview(id)
			case "policy":
				_, err = scoped.SetEgressLevel(id, "none")
			case "delete":
				err = scoped.DeleteCase(id)
			}
			if err != nil {
				t.Fatal(err)
			}
			close(resume)
			<-done
			if got := run.snapshot(); got.State != "cancelled" {
				t.Fatalf("revocation won but run=%+v", got)
			}
			saved, ok, err := svc.store.LatestCaseReview(id)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "delete" {
				if ok {
					t.Fatal("deleted review resurrected")
				}
				return
			}
			if !ok || saved.Narrative.Status != model.NarrativeError || saved.Narrative.Error != "cancelled" || saved.Narrative.SentencesJSON != "[]" || saved.Narrative.RawAnswer != answer || saved.Narrative.PayloadSHA256 != row.Narrative.PayloadSHA256 || saved.Narrative.PayloadUser != pr.User || len(saved.FrozenVT) != 1 {
				t.Fatalf("cancelled outcome lost frozen attempt or earned commentary: %+v", saved)
			}
			var status CaseReviewStatus
			if rec := doJSON(t, mux, "GET", "/api/cases/"+id+"/enrich/case-review", nil, &status); rec.Code != 200 || status.Run.State != "cancelled" || status.Latest.Status != model.NarrativeError || len(status.Latest.Sentences) != 0 {
				t.Fatalf("API disagrees: %+v", status)
			}
			// Render the actual API DTO: no successful V commentary is visible.
			src, _ := os.ReadFile("../web/static/app.js")
			extract := func(name string) string {
				rest := string(src)[strings.Index(string(src), "function "+name+"("):]
				if loc := regexp.MustCompile(`\n(?:async )?function `).FindStringIndex(rest); loc != nil {
					rest = rest[:loc[0]]
				}
				return rest
			}
			b, _ := json.Marshal(status)
			script := ""
			for _, name := range []string{"esc", "externalCitation", "renderStoredVTCoverage", "renderReviewPrivacyOmissions", "renderReviewClaimGroups", "renderCaseReviewSection"} {
				script += extract(name) + "\n"
			}
			script += "const assert=require('node:assert/strict');const html=renderCaseReviewSection(" + string(b) + ");assert.match(html,/cancelled/);assert.ok(!html.includes('Stored opinion flagged'));"
			if out, err := exec.Command("node", "-e", script).CombinedOutput(); err != nil {
				t.Fatalf("API -> cancelled UI: %v %s", err, out)
			}
			// A fresh runtime reads the durable failure but never resumes a request.
			restarted := NewService(svc.store, svc.files)
			st, err := restarted.CaseReviewStatus(id)
			if err != nil || st.Run != nil || st.Latest.Status != model.NarrativeError || stub.count() != 0 {
				t.Fatalf("restart: %+v %v sends=%d", st, err, stub.count())
			}
		})
	}
}
