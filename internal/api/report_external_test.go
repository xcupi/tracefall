package api

import (
	stdhtml "html"
	"net/http"
	"strings"
	"testing"
	"time"
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
