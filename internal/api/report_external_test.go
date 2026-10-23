package api

import (
	stdhtml "html"
	"net/http"
	"strings"
	"testing"
	"time"
	"tracefall/internal/enrich/virustotal"
	"tracefall/internal/model"
)

func extSection(t *testing.T, html string) string {
	t.Helper()
	i := strings.Index(html, "<h3>Appendix D")
	if i < 0 {
		t.Fatal("no Appendix D in the report")
	}
	j := strings.Index(html[i:], "<footer>")
	return stdhtml.UnescapeString(html[i : i+j])
}

func TestReport_AppendixDForACaseThatNeverLeftTheServer(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newVTStub(t, svc)
	id := caseWithHashes(t, svc, mux, map[string]string{"sha256": hA})
	b, err := svc.buildReport(id, time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	h := extSection(t, string(b.HTML))
	if !strings.Contains(h, ">none<") || !strings.Contains(h, "No VirusTotal lookup has been made") {
		t.Errorf("appendix:\n%s", h)
	}
	if stub.count() != 0 {
		t.Errorf("building a report sent %d request(s)", stub.count())
	}
}

func TestReport_AppendixDShowsStoredAnswersAndGeneratingItSendsNothing(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newVTStub(t, svc)
	stub.answers[hA] = ok(vtKnown)
	stub.answers[hC] = status(500, "boom", nil)
	id := caseWithHashes(t, svc, mux, map[string]string{"sha256": hA}, map[string]string{"sha1": hB}, map[string]string{"md5": hC})
	setLevel(t, mux, id, "hashes")
	doJSON(t, mux, "POST", "/api/cases/"+id+"/enrich/virustotal", nil, nil)
	waitRun(t, svc, id)
	sent := stub.count()

	b, err := svc.buildReport(id, time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	h := extSection(t, string(b.HTML))
	for _, w := range []string{">hashes<", "2 hash(es) were answered (1 known to VirusTotal, 1 not known); 1 could not be answered",
		"60 of 68 engines flagged it (60 malicious, 0 suspicious)", "virus.eicar", "not known to VirusTotal", "no answer (", hA, hB, hC, "ev-a"} {
		if !strings.Contains(h, w) {
			t.Errorf("missing %q", w)
		}
	}
	// most-detected first, then not known, then no answer
	iA, iB, iC := strings.Index(h, hA), strings.Index(h, hB), strings.Index(h, hC)
	if !(iA < iB && iB < iC) {
		t.Errorf("order: known %d, not known %d, no answer %d", iA, iB, iC)
	}
	if stub.count() != sent {
		t.Errorf("building the report sent %d more request(s)", stub.count()-sent)
	}
	// the same case at the same instant is the same bytes
	b2, err := svc.buildReport(id, time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC))
	if err != nil || string(b2.HTML) != string(b.HTML) {
		t.Errorf("the report with an appendix is not deterministic (err %v)", err)
	}
	// a finding is untouched by the lookup: no finding mentions VirusTotal
	if strings.Contains(strings.Join(b.Data.Limitations, " "), "VirusTotal") {
		t.Errorf("an outside answer leaked into the limitations")
	}
}

func TestReport_AnUnreadableStoredAnswerIsAnErrorNotNotKnown(t *testing.T) {
	rows := []VTResult{{Indicator: hA, IndicatorType: "sha256", Status: "found", Result: nil}}
	p := buildVTSection(rows)
	if p.Errors != 1 || p.Unknown != 0 || p.Known != 0 || p.Answered != 0 {
		t.Errorf("section = %+v", p)
	}
}

func TestReport_AppendixDIsBoundedAndSaysSo(t *testing.T) {
	var rows []VTResult
	for i := 0; i < maxExternalListed+5; i++ {
		rows = append(rows, VTResult{Indicator: strings.Repeat("0", 60) + string(rune('a'+i/26)) + string(rune('a'+i%26)) + "1", IndicatorType: "sha256", Status: "not_found", Result: nil})
	}
	for i := range rows {
		rows[i].Result = nil
	}
	p := buildVTSection(rows)
	if len(p.Rows) != maxExternalListed {
		t.Errorf("listed %d rows", len(p.Rows))
	}
	if p.Omitted != 5 {
		t.Errorf("omitted = %d", p.Omitted)
	}
}

var _ = http.StatusOK

func TestAppendixD_RowsStateTheServicesAnswerPlainly(t *testing.T) {
	long := strings.Repeat("x", 500)
	p := buildVTSection([]VTResult{
		{Indicator: hA, IndicatorType: "sha256", Status: "found", FetchedAt: "2026-03-14T09:00:00Z",
			EventIDs: []string{"e1", "e2", "e3", "e4", "e5", "e6", "e7", "e8", "e9", "e10"},
			Result: &virustotal.Result{Found: true, Malicious: 3, Suspicious: 2, Harmless: 1, Undetected: 4, Link: "https://example.invalid/a",
				ThreatLabel: long, MeaningfulName: "a\n\tb  c", TypeDescription: long}},
		{Indicator: hB, IndicatorType: "sha1", Status: "not_found", FetchedAt: "2026-03-14T09:00:01Z",
			Result: &virustotal.Result{Found: false, Link: "https://example.invalid/b"}},
	})
	if len(p.Rows) != 2 {
		t.Fatalf("rows = %+v", p.Rows)
	}
	k, u := p.Rows[0], p.Rows[1]
	if k.Verdict != "5 of 10 engines flagged it (3 malicious, 2 suspicious)" {
		t.Errorf("a suspicious verdict counts toward the engines that flagged it: %q", k.Verdict)
	}
	if k.Events != "e1, e2, e3 (+7 more)" {
		t.Errorf("events = %q", k.Events)
	}
	if len([]rune(k.Label)) > 125 || !strings.HasSuffix(k.Label, "...") || len([]rune(k.FileType)) > 125 {
		t.Errorf("text from the outside service is not bounded: label %d runes", len([]rune(k.Label)))
	}
	if k.ReportedName != "a b c" {
		t.Errorf("reported name = %q: it is shown in one table cell, flattened to one line", k.ReportedName)
	}
	if u.Verdict != "not known to VirusTotal" || u.Link != "https://example.invalid/b" || k.Link != "https://example.invalid/a" {
		t.Errorf("links/verdict: known %q unknown %+v", k.Link, u)
	}
}

func appendixEOf(t *testing.T, html string) string {
	t.Helper()
	i := strings.Index(html, "<h3>Appendix E")
	if i < 0 {
		t.Fatal("no Appendix E in the report")
	}
	j := strings.Index(html[i:], "<footer>")
	return stdhtml.UnescapeString(html[i : i+j])
}

func TestReport_AppendixEWithoutARequestAndTheNoAIStatement(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newLLMStub(t, svc, false)
	id := caseWithFindings(t, svc, mux, nil)
	b, err := svc.buildReport(id, time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(appendixEOf(t, string(b.HTML)), "No language-model summary was requested") || !strings.Contains(string(b.HTML), "No artificial intelligence or large language model was used") {
		t.Errorf("a case that never asked a model must say so")
	}
	if stub.count() != 0 {
		t.Errorf("building a report sent %d request(s) to a model", stub.count())
	}
}

func TestReport_AppendixEShowsTheDraftWithTheReportsOwnFindingNumbers(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newLLMStub(t, svc, false)
	id := caseWithFindings(t, svc, mux, nil)
	setLevel(t, mux, id, "pseudonymized")
	startNarr(t, mux, id, true)
	waitNarr(t, svc, id)
	sent := stub.count()

	b, err := svc.buildReport(id, time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	h := appendixEOf(t, string(b.HTML))
	for _, w := range []string{"alice ran PowerShell from a document on host01 and contacted 203.0.113.9", "llm.example.invalid", "stub-model", "another machine",
		"Whether a sentence is true was not checked", "3 line(s) of the model's answer were dropped", "a web address in the sentence (1)"} {
		if !strings.Contains(h, w) {
			t.Errorf("missing %q in:\n%s", w, h)
		}
	}
	// citations use the report's numbers, not internal ids
	var f1, f2 string
	for _, f := range b.Data.Findings {
		switch f.ID {
		case "fnd-1":
			f1 = f.Number
		case "fnd-2":
			f2 = f.Number
		}
	}
	if f1 == "" || f2 == "" || !strings.Contains(h, "["+f1+"; event ev-1]") || !strings.Contains(h, "["+f2+"]") || strings.Contains(h, "fnd-1") {
		t.Errorf("citations (%s, %s) in:\n%s", f1, f2, h)
	}
	if strings.Contains(string(b.HTML), "No artificial intelligence or large language model was used") || !strings.Contains(string(b.HTML), "A language model drafted the summary in Appendix E") {
		t.Errorf("the limitation must name the model-drafted summary")
	}
	if stub.count() != sent {
		t.Errorf("building the report sent %d more request(s)", stub.count()-sent)
	}
	b2, _ := svc.buildReport(id, time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC))
	if string(b2.HTML) != string(b.HTML) {
		t.Errorf("a report with a draft is not deterministic")
	}
	// the sha in the report is the one in the audit trail
	if !strings.Contains(h, sha256hex(stub.last().System+"\x00"+stub.last().User)) {
		t.Errorf("the report does not carry the hash of what was sent")
	}
}

func TestReport_AFailedRequestIsStatedInTheReport(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newLLMStub(t, svc, false)
	stub.answer = func(string) (int, string) { return 200, chatBody("nothing with ids") }
	id := caseWithFindings(t, svc, mux, nil)
	setLevel(t, mux, id, "pseudonymized")
	startNarr(t, mux, id, true)
	waitNarr(t, svc, id)
	b, _ := svc.buildReport(id, time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC))
	h := appendixEOf(t, string(b.HTML))
	if !strings.Contains(h, "returned nothing that passed validation") || !strings.Contains(h, "Case data was sent for this request") || strings.Contains(h, "<ol>") {
		t.Errorf("appendix:\n%s", h)
	}
	if strings.Contains(string(b.HTML), "No artificial intelligence or large language model was used") {
		t.Errorf("data was sent to a model; the report must not claim none was used")
	}
}

func TestReport_AppendixEFlagsAStaleDraftAndStatesAFailureReason(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newLLMStub(t, svc, false)
	id := caseWithFindings(t, svc, mux, nil)
	setLevel(t, mux, id, "pseudonymized")
	startNarr(t, mux, id, true)
	waitNarr(t, svc, id)
	more := model.Finding{ID: "fnd-3", CaseID: id, RuleID: "r", Title: "Another", Severity: "critical", Confidence: "high", Description: "d",
		SupportingEvents: []string{"ev-1"}, FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(), CreatedAt: time.Now().UTC()}
	if err := svc.store.SaveFindings([]model.Finding{more}); err != nil {
		t.Fatal(err)
	}
	b, _ := svc.buildReport(id, time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC))
	if !strings.Contains(appendixEOf(t, string(b.HTML)), "The findings of this case changed after this draft was written.") {
		t.Errorf("a stale draft is not flagged in the report")
	}
	// a failed request states why
	stub.answer = func(string) (int, string) { return 500, `{"error":{"message":"overloaded"}}` }
	startNarr(t, mux, id, true)
	waitNarr(t, svc, id)
	b, _ = svc.buildReport(id, time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC))
	if h := appendixEOf(t, string(b.HTML)); !strings.Contains(h, "HTTP 500") {
		t.Errorf("the failure reason is not in the report:\n%s", h)
	}
}
