package report

import (
	stdhtml "html"
	"strings"
	"testing"
)

func renderExt(t *testing.T, e External) string {
	t.Helper()
	d := sampleData()
	d.External = e
	b, err := Render(d)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func appendixD(t *testing.T, html string) string {
	t.Helper()
	i := strings.Index(html, "<h3>Appendix D")
	if i < 0 {
		t.Fatal("no Appendix D")
	}
	j := strings.Index(html[i:], "<footer>")
	return stdhtml.UnescapeString(html[i : i+j])
}

func TestAppendixD_AlwaysStatesTheEgressLevelAndThatNothingWasLookedUp(t *testing.T) {
	h := appendixD(t, renderExt(t, External{EgressLevel: "none", EgressDescription: "Nothing leaves the server."}))
	for _, w := range []string{"Outside services (not evidence)", "Egress level of this case", ">none<", "Nothing leaves the server.", "No VirusTotal lookup has been made for this case."} {
		if !strings.Contains(h, w) {
			t.Errorf("missing %q in:\n%s", w, h)
		}
	}
	if strings.Contains(h, "<table>") {
		t.Errorf("a table with no answers")
	}
}

func TestAppendixD_AnswersAreLabelledAsOpinionsAndNeverAsFindings(t *testing.T) {
	e := External{EgressLevel: "hashes", EgressDescription: "d", VirusTotal: ExternalProvider{
		Answered: 2, Known: 1, Unknown: 1, Errors: 1,
		Rows: []ExternalRow{
			{Indicator: strings.Repeat("a", 64), IndicatorType: "sha256", Verdict: "64 of 67 engines flagged it (64 malicious, 0 suspicious)", Label: "virus.eicar/test", FileType: "EICAR", ReportedName: "eicar.com", LastAnalysis: "2026-10-23T05:06:53Z", CheckedAt: "2026-10-23T06:00:00Z", Events: "ev-1, ev-2 (+3 more)", Link: "https://www.virustotal.com/gui/file/aa"},
			{Indicator: strings.Repeat("b", 40), IndicatorType: "sha1", Verdict: "not known to VirusTotal", CheckedAt: "2026-10-23T06:00:01Z"},
			{Indicator: strings.Repeat("c", 32), IndicatorType: "md5", Verdict: "no answer (virustotal: HTTP 500)", CheckedAt: "2026-10-23T06:00:02Z"},
		}}}
	h := appendixD(t, renderExt(t, e))
	for _, w := range []string{
		"2 hash(es) were answered (1 known to VirusTotal, 1 not known); 1 could not be answered",
		"not evidence about this case", "did not change any finding or its severity",
		"does not mean the file is safe", "a count of engines, not proof of malicious use on this system",
		"64 of 67 engines flagged it", "Label: virus.eicar/test", "Name seen by VirusTotal: eicar.com",
		"ev-1, ev-2 (+3 more)", "not known to VirusTotal", "no answer (virustotal: HTTP 500)", "2026-10-23T06:00:00Z",
		"Only the hashes were sent",
	} {
		if !strings.Contains(h, w) {
			t.Errorf("missing %q", w)
		}
	}
	if !strings.Contains(h, strings.Repeat("a", 64)) || !strings.Contains(h, strings.Repeat("c", 32)) {
		t.Errorf("hashes are not printed in full")
	}
}

func TestAppendixD_ServiceControlledTextIsEscaped(t *testing.T) {
	e := External{EgressLevel: "hashes", VirusTotal: ExternalProvider{Answered: 1, Known: 1, Rows: []ExternalRow{
		{Indicator: strings.Repeat("a", 64), IndicatorType: "sha256", Verdict: "v", Label: "<script>alert(1)</script>", ReportedName: "\"><img src=x onerror=alert(1)>", FileType: "<b>x</b>"}}}}
	html := renderExt(t, e)
	i := strings.Index(html, "<h3>Appendix D")
	h := html[i:]
	if strings.Contains(h, "<script>") || strings.Contains(h, "<img") || strings.Contains(h, "<b>x") {
		t.Errorf("unescaped markup from the outside service:\n%s", h)
	}
	if !strings.Contains(h, "&lt;script&gt;") {
		t.Errorf("the text is not shown, escaped")
	}
}

func TestAppendixD_TheOmissionIsDisclosedAndOnlyWhenThereIsOne(t *testing.T) {
	p := ExternalProvider{Answered: 1, Known: 1, Rows: []ExternalRow{{Indicator: "a", IndicatorType: "md5", Verdict: "v"}}}
	if h := appendixD(t, renderExt(t, External{EgressLevel: "hashes", VirusTotal: p})); strings.Contains(h, "further answers are not shown") {
		t.Errorf("an omission is claimed that did not happen")
	}
	p.Omitted = 7
	if h := appendixD(t, renderExt(t, External{EgressLevel: "hashes", VirusTotal: p})); !strings.Contains(h, "7 further answers are not shown") {
		t.Errorf("the omission is not disclosed")
	}
}

func TestAppendixD_ErrorsAloneAreStillReported(t *testing.T) {
	h := appendixD(t, renderExt(t, External{EgressLevel: "hashes", VirusTotal: ExternalProvider{Errors: 2, Rows: []ExternalRow{{Indicator: "a", IndicatorType: "md5", Verdict: "no answer (x)"}}}}))
	if strings.Contains(h, "No VirusTotal lookup has been made") || !strings.Contains(h, "0 hash(es) were answered") || !strings.Contains(h, "2 could not be answered") {
		t.Errorf("a lookup that only failed must not read as no lookup:\n%s", h)
	}
}

func TestLimitations_NamesTheOneLabelledExceptionToFixedText(t *testing.T) {
	html := renderExt(t, External{EgressLevel: "none"})
	if !strings.Contains(html, "with one labelled exception: Appendix D") {
		t.Errorf("the limitations still claim every statement is case data")
	}
}
