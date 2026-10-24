package narrative

import (
	"encoding/json"
	"strings"
	"testing"
	"tracefall/internal/model"
)

func claimReview(t *testing.T) *ReviewPrepared {
	t.Helper()
	p, err := PrepareReview(ReviewInput{CaseID: "c", Events: []model.Event{{ID: "original-event", CaseID: "c", Host: "host01"}}})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReviewClaimRejectsForgedPrefix(t *testing.T) {
	p := claimReview(t)
	for _, line := range []string{"proven | Fine. [E1]", "observation [E99] | Fine. [E1]", "hypothesis 999999 | Fine. [E1]", "[HOST_999] | Fine. [E1]", " | Fine. [E1]", "Observation | Fine. [E1]"} {
		d, err := p.Validate(line)
		if err == nil || d.Rejected != 1 || len(d.Sentences) != 0 {
			t.Errorf("accepted forged kind %q: %+v", line, d)
		}
	}
}

func TestReviewClaimLegacyAndSummary(t *testing.T) {
	p := claimReview(t)
	for _, text := range []string{"A hypothesis is unconfirmed.", "An observation is recorded.", "This proves success."} {
		d, err := p.Validate(text + " [E1]")
		if err != nil || d.Sentences[0].Kind != "unclassified" || d.Sentences[0].Text != text {
			t.Fatalf("legacy was classified: %+v %v", d, err)
		}
	}
	// Summary must not parse Review labels or acquire metadata.
	summary, _, _, _ := answerFor(t)
	d, err := summary.Validate("hypothesis | Fine. [F1]")
	if err != nil || d.Sentences[0].Text != "hypothesis | Fine." {
		t.Fatalf("Summary changed: %+v %v", d, err)
	}
	b, _ := json.Marshal(d.Sentences[0])
	var got map[string]any
	_ = json.Unmarshal(b, &got)
	if _, ok := got["kind"]; ok {
		t.Fatalf("Summary gained kind: %s", b)
	}
	var old Sentence
	if err := json.Unmarshal([]byte(`{"text":"Old row.","cites":[{"kind":"event","id":"e"}]}`), &old); err != nil || old.Kind != "" {
		t.Fatalf("old row: %+v %v", old, err)
	}
}

func TestReviewClaimPrompt(t *testing.T) {
	p := claimReview(t)
	for _, want := range []string{"review-output-v1", "observation | text [E1]", "possible_conflict", "hypothesis", "gap", "next_check", "unclassified", "not a proven contradiction", "unconfirmed", "not evidence of absence", "recommendation, not an action already taken", "validation does not establish semantic truth"} {
		if !strings.Contains(p.System, want) {
			t.Errorf("missing prompt contract %q", want)
		}
	}
}

func TestReviewClaimSynthesisPreservesKinds(t *testing.T) {
	in := ReviewInput{CaseID: "c", Events: []model.Event{{ID: "e", CaseID: "c", Host: "host01"}}}
	var comments []Sentence
	for _, kind := range []string{"hypothesis", "possible_conflict", "observation", "gap", "next_check", "unclassified", "", "arbitrary_kind_injection"} {
		comments = append(comments, Sentence{Kind: kind, Text: "Recorded on host01.", Cites: []Cite{{Kind: "event", ID: "e"}}})
	}
	p, omitted, err := PrepareReviewSynthesis(in, comments)
	if err != nil || omitted != 0 {
		t.Fatalf("%d %v", omitted, err)
	}
	for _, kind := range []string{"hypothesis", "possible_conflict", "observation", "gap", "next_check"} {
		if !strings.Contains(p.User, "commentary_only | kind="+kind+" | Recorded on [HOST_1]. [E1]") {
			t.Errorf("kind/citation lost: %s", kind)
		}
	}
	if strings.Count(p.User, "commentary_only | kind=unclassified |") != 3 || strings.Contains(p.User, "arbitrary_kind_injection") || strings.Contains(p.User, "host01") {
		t.Fatalf("unsafe metadata or text: %s", p.User)
	}
	if !strings.Contains(p.System, "Never promote a hypothesis or possible_conflict into an established observation") || strings.Contains(p.System, "reconcile only") {
		t.Fatal("unsafe synthesis instructions", p.System)
	}
	if p.Privacy.PayloadBytes != len(p.System)+len(p.User) {
		t.Fatal("incorrect byte receipt")
	}
	d, err := p.Validate("hypothesis | This proves success. [E1]")
	if err != nil || d.Sentences[0].Kind != "hypothesis" {
		t.Fatalf("validator upgraded/reasoned over claim: %+v %v", d, err)
	}
}

func TestReviewClaimPrefixCannotBypassValidation(t *testing.T) {
	p := claimReview(t)
	for _, body := range []string{"Missing reference.", "Foreign. [E99]", "Embedded [E1] reference. [E1]", "Invented [HOST_999]. [E1]", "Invented 999999. [E1]", "Visit https://example.invalid. [E1]", "[E1]", strings.Repeat("x", DefaultLimits.MaxSentenceRunes+1) + " [E1]"} {
		d, err := p.Validate("observation | " + body)
		if err == nil || len(d.Sentences) != 0 || d.Rejected != 1 {
			t.Errorf("prefix bypass: %q %+v %v", body, d, err)
		}
	}
	// Only the first separator is structural; preserve a real command pipe in text.
	d, err := p.Validate("hypothesis | A recorded command uses cat | sort. [E1]")
	if err != nil || d.Sentences[0].Text != "A recorded command uses cat | sort." || d.Sentences[0].Kind != "hypothesis" {
		t.Fatalf("body was reclassified: %+v %v", d, err)
	}
}

func TestReviewClaimKinds(t *testing.T) {
	p := claimReview(t)
	for _, kind := range []string{"observation", "possible_conflict", "hypothesis", "gap", "next_check", "unclassified"} {
		t.Run(kind, func(t *testing.T) {
			d, err := p.Validate(kind + " | Recorded on [HOST_1]. [E1]")
			if err != nil || len(d.Sentences) != 1 {
				t.Fatalf("%+v %v", d, err)
			}
			b, _ := json.Marshal(d.Sentences[0])
			var got map[string]any
			_ = json.Unmarshal(b, &got)
			if got["kind"] != kind || got["text"] != "Recorded on host01." || d.Sentences[0].Cites[0].ID != "original-event" {
				t.Fatalf("kind/text/citation: %s", b)
			}
		})
	}
}
