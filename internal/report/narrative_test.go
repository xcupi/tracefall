package report

import (
	stdhtml "html"
	"strings"
	"testing"
)

func renderNarr(t *testing.T, n Narrative) string {
	t.Helper()
	d := sampleData()
	d.Narrative = n
	b, err := Render(d)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func appendixE(t *testing.T, html string) string {
	t.Helper()
	i := strings.Index(html, "<h3>Appendix E")
	if i < 0 {
		t.Fatal("no Appendix E")
	}
	j := strings.Index(html[i:], "<footer>")
	return stdhtml.UnescapeString(html[i : i+j])
}

func usable() Narrative {
	return Narrative{Requested: true, Usable: true, RequestedAt: "2026-03-14T10:00:00Z", Destination: "llm.example.invalid", Model: "m-1",
		PayloadSHA256: strings.Repeat("ab", 32), PromptTokens: 321, CompletionTokens: 45,
		Sentences: []NarrativeSentence{{Text: "alice ran PowerShell on host01.", Cites: "F-001; event e-1"}, {Text: "A second line.", Cites: "F-002"}},
		Rejected:  2, Reasons: []KV{{"a number that is not in the facts", "1"}, {"no citation at the end of the line", "1"}}}
}

func TestAppendixE_WhenNothingWasRequested(t *testing.T) {
	html := renderNarr(t, Narrative{})
	h := appendixE(t, html)
	if !strings.Contains(h, "No language-model summary was requested for this case.") || strings.Contains(h, "<ol>") {
		t.Errorf("appendix:\n%s", h)
	}
	if !strings.Contains(html, "No artificial intelligence or large language model was used to produce any part of this report.") {
		t.Errorf("the statement that no model was used must stay when none was")
	}
}

func TestAppendixE_ADraftIsLabelledAsADraftAndSaysWhatWasAndWasNotChecked(t *testing.T) {
	html := renderNarr(t, usable())
	h := appendixE(t, html)
	for _, w := range []string{
		"Summary drafted by a language model (not evidence)", "2026-03-14T10:00:00Z", ">m-1<", "llm.example.invalid", "another machine",
		"replaced by tokens before the facts left", "secrets were removed", strings.Repeat("ab", 32), "321 in, 45 out",
		"not a finding and not evidence", "Whether a sentence is true was not checked", "can try to steer a model",
		"alice ran PowerShell on host01.", "[F-001; event e-1]", "[F-002]",
		"2 line(s) of the model's answer were dropped by validation", "a number that is not in the facts (1)", "no citation at the end of the line (1)",
	} {
		if !strings.Contains(h, w) {
			t.Errorf("missing %q in:\n%s", w, h)
		}
	}
	if strings.Contains(h, "changed after this draft") {
		t.Errorf("a fresh draft is not stale")
	}
	if strings.Index(h, "not a finding and not evidence") > strings.Index(h, "alice ran PowerShell") {
		t.Errorf("the label must come before the draft, not after it")
	}
}

func TestLimitations_TheNoAIStatementIsTrueInEveryCase(t *testing.T) {
	none := renderNarr(t, Narrative{})
	if !strings.Contains(none, "No artificial intelligence or large language model was used to produce any part of this report.") {
		t.Errorf("none requested")
	}
	with := renderNarr(t, usable())
	if strings.Contains(with, "No artificial intelligence or large language model was used") {
		t.Errorf("the report claims no model was used although Appendix E holds a draft by one")
	}
	if !strings.Contains(with, "A language model drafted the summary in Appendix E") || !strings.Contains(with, "No other part of this report was produced with one") {
		t.Errorf("the limitation does not name the exception")
	}
	failed := renderNarr(t, Narrative{Requested: true, Error: "the model's answer had no sentence that passed validation", Destination: "llm.example.invalid", Model: "m"})
	if strings.Contains(failed, "No artificial intelligence or large language model was used") || !strings.Contains(failed, "was asked for a summary (Appendix E) and returned nothing usable") {
		t.Errorf("a request that produced nothing must still be stated")
	}
}

func TestAppendixE_ARequestThatProducedNothingIsStatedBecauseDataWasSent(t *testing.T) {
	h := appendixE(t, renderNarr(t, Narrative{Requested: true, Error: "the model's answer had no sentence that passed validation", Destination: "llm.example.invalid", Model: "m", PayloadSHA256: "abc"}))
	for _, w := range []string{"returned nothing that passed validation", "no sentence that passed validation", "Case data was sent for this request", "llm.example.invalid", "abc"} {
		if !strings.Contains(h, w) {
			t.Errorf("missing %q in:\n%s", w, h)
		}
	}
	if strings.Contains(h, "<ol>") {
		t.Errorf("a list for an empty draft")
	}
}

func TestAppendixE_LocalModelAndStaleDraft(t *testing.T) {
	n := usable()
	n.Local, n.Destination, n.Stale = true, "127.0.0.1", true
	h := appendixE(t, renderNarr(t, n))
	if !strings.Contains(h, "a model on the machine that made this report (127.0.0.1)") || strings.Contains(h, "another machine") {
		t.Errorf("local: %s", h)
	}
	if !strings.Contains(h, "The findings of this case changed after this draft was written.") {
		t.Errorf("stale draft is not flagged")
	}
}

func TestAppendixE_ModelTextIsEscaped(t *testing.T) {
	n := usable()
	n.Sentences = []NarrativeSentence{{Text: "<script>alert(1)</script> and <img src=x onerror=alert(1)>", Cites: "<b>F-001</b>"}}
	n.Model = "<i>m</i>"
	html := renderNarr(t, n)
	i := strings.Index(html, "<h3>Appendix E")
	raw := html[i:]
	if strings.Contains(raw, "<script>") || strings.Contains(raw, "<img") || strings.Contains(raw, "<b>F-001") || strings.Contains(raw, "<i>m</i>") {
		t.Errorf("unescaped markup from the model reached the report")
	}
}

func TestAppendixE_NoRepeatedBlankDraftWhenThereAreNoSentences(t *testing.T) {
	n := usable()
	n.Usable, n.Sentences = false, nil
	if h := appendixE(t, renderNarr(t, n)); strings.Contains(h, "<ol>") {
		t.Errorf("an empty list")
	}
}
