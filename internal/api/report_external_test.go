package api

import (
	stdhtml "html"
	"net/http"
	"strings"
	"testing"
	"time"
	"tracefall/internal/enrich/virustotal"
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
