package narrative

import (
	"fmt"
	"strings"
	"testing"
	"tracefall/internal/model"
)

func vtFixture() ReviewInput {
	h := strings.Repeat("a", 64)
	return ReviewInput{CaseID: "case01", Events: []model.Event{{ID: "original-event", CaseID: "case01", EventType: "file", Extra: map[string]string{"content_sha256": h}}}, Enrichments: []model.Enrichment{{ID: "original-enrichment", CaseID: "case01", Provider: "virustotal", IndicatorType: "sha256", Indicator: h, Status: "found", ResultJSON: `{"found":true,"malicious":2,"suspicious":1,"harmless":3,"undetected":4,"timeout":5,"failure":6,"type_unsupported":7,"meaningful_name":"private-secret-name","link":"https://secret.invalid/key"}`, Error: "secret-error", SourceEventIDs: []string{"original-event"}}}}
}
func TestReviewVTStatesAndLinks(t *testing.T) {
	for _, tc := range []struct {
		name, status, raw, want string
		invalid                 int
	}{
		{"clean", "found", `{"found":true,"malicious":0,"suspicious":0,"harmless":0,"undetected":0,"timeout":0,"failure":0,"type_unsupported":0}`, "found", 0},
		{"missing", "found", `{"found":true}`, "unusable", 1},
		{"negative", "found", `{"found":true,"malicious":-1}`, "unusable", 1},
		{"overflow", "found", `{"found":true,"malicious":999999999999999999999}`, "unusable", 1},
		{"not-found", "not_found", `{}`, "not_found", 0},
		{"error", "error", `{}`, "error", 0},
		{"unknown", "secret-provider-status", `{}`, "unusable", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := vtFixture()
			in.Enrichments[0].Status = tc.status
			in.Enrichments[0].ResultJSON = tc.raw
			p, err := PrepareReview(in)
			if err != nil {
				t.Fatal(err)
			}
			if p.Coverage.VTInvalid != tc.invalid || p.FrozenVT[0].Status != tc.want {
				t.Fatalf("coverage=%+v frozen=%+v", p.Coverage, p.FrozenVT)
			}
		})
	}
	in := vtFixture()
	in.Events[0].Extra["content_sha256"] = strings.Repeat("b", 64)
	p, err := PrepareReview(in)
	if err != nil {
		t.Fatal(err)
	}
	if p.Coverage.VTUnlinked != 1 || p.Coverage.VTIncluded != 0 {
		t.Fatal(p.Coverage)
	}
}
func TestReviewVTSynthesisExternalCitation(t *testing.T) {
	in := vtFixture()
	p, omitted, err := PrepareReviewSynthesis(in, []Sentence{{Kind: "hypothesis", Text: "Stored external opinion.", Cites: []Cite{{Kind: "enrichment", ID: "original-enrichment"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if omitted != 0 || !strings.Contains(p.User, "kind=hypothesis | Stored external opinion. [V1]") {
		t.Fatalf("omitted=%d user=%s", omitted, p.User)
	}
}
func TestReviewVTTrivialHashesAndCaps(t *testing.T) {
	for _, h := range []string{strings.Repeat("0", 64), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "d41d8cd98f00b204e9800998ecf8427e"} {
		in := vtFixture()
		in.Enrichments[0].Indicator = h
		if len(h) == 32 {
			in.Enrichments[0].IndicatorType = "md5"
		}
		in.Events[0].Extra["content_sha256"] = h
		p, err := PrepareReview(in)
		if err != nil {
			t.Fatal(err)
		}
		if p.Coverage.VTIncluded != 0 || p.Coverage.VTInvalid != 1 {
			t.Fatalf("trivial hash accepted %+v", p.Coverage)
		}
	}
}
func TestReviewVTCountsCapsAndForeignIsolation(t *testing.T) {
	in := vtFixture()
	base := in.Enrichments[0]
	ev := in.Events[0]
	in.Enrichments = nil
	in.Events = nil
	for i := 0; i < ReviewMaxVT+2; i++ {
		e := base
		e.ID = fmt.Sprintf("v%03d", i)
		e.Indicator = fmt.Sprintf("%064x", i+1)
		e.SourceEventIDs = []string{fmt.Sprintf("e%03d", i), fmt.Sprintf("e%03d", i)}
		v := ev
		v.ID = e.SourceEventIDs[0]
		v.Extra = map[string]string{"sha256": e.Indicator}
		in.Events = append(in.Events, v)
		in.Enrichments = append(in.Enrichments, e)
	}
	foreign := base
	foreign.CaseID = "foreign"
	in.Enrichments = append(in.Enrichments, foreign)
	foreign.CaseID = in.CaseID
	foreign.Provider = "other"
	in.Enrichments = append(in.Enrichments, foreign)
	p, err := PrepareReview(in)
	if err != nil {
		t.Fatal(err)
	}
	if cv := p.Coverage; cv.VTTotal != 62 || cv.VTIncluded != 60 || cv.VTOmitted != 2 || cv.VTInvalid != 0 || cv.VTUnlinked != 0 {
		t.Fatalf("coverage %+v", cv)
	}
	for _, v := range p.FrozenVT {
		if len(v.SourceEventIDs) != 1 {
			t.Fatalf("duplicate links %+v", v)
		}
	}
	in = vtFixture()
	in.Enrichments = append(in.Enrichments, in.Enrichments[0])
	p, err = PrepareReview(in)
	if err != nil {
		t.Fatal(err)
	}
	if p.Coverage.VTTotal != 1 {
		t.Fatalf("duplicate opinion count %+v", p.Coverage)
	}
}
func TestReviewVTBudgetOmissions(t *testing.T) {
	base := vtFixture()
	var near ReviewInput
	for width := 300; width <= 400; width += 20 {
		in := ReviewInput{CaseID: base.CaseID}
		for i := 0; i < 25; i++ {
			in.Findings = append(in.Findings, model.Finding{ID: fmt.Sprintf("f%d", i), CaseID: in.CaseID, Title: strings.Repeat("record ", 20), Description: strings.Repeat("recorded context ", 40)})
			in.Correlations = append(in.Correlations, model.Correlation{ID: fmt.Sprintf("c%d", i), CaseID: in.CaseID, Title: strings.Repeat("record ", 20), Description: strings.Repeat("recorded context ", 40)})
		}
		for i := 0; i < 120; i++ {
			e := base.Events[0]
			e.ID = fmt.Sprintf("event%03d", i)
			e.CommandLine = strings.Repeat("echo ", width/5)
			e.FilePath = strings.Repeat("directory/", 24)
			e.RegistryPath = strings.Repeat("subkey/", 35)
			e.ProcessName = strings.Repeat("utility ", 15)
			e.ParentProcessName = e.ProcessName
			e.Extra = map[string]string{"sha256": fmt.Sprintf("%064x", i+1)}
			in.Events = append(in.Events, e)
		}
		p, err := PrepareReview(in)
		if err == nil && len(p.System)+len(p.User) > ReviewMaxBytes-10000 {
			near = in
			break
		}
	}
	if len(near.Events) == 0 {
		t.Fatal("fixture never reached real admission boundary")
	}
	for i, e := range near.Events[:60] {
		v := base.Enrichments[0]
		v.ID = fmt.Sprintf("opinion%03d", i)
		v.Indicator = e.Extra["sha256"]
		v.SourceEventIDs = []string{e.ID}
		near.Enrichments = append(near.Enrichments, v)
	}
	p, err := PrepareReview(near)
	if err != nil {
		t.Fatalf("VT should be omitted, not displace admitted primary context: %v", err)
	}
	if p.Coverage.VTOmitted == 0 || p.Privacy.PayloadBytes > ReviewMaxBytes {
		t.Fatalf("budget omissions %+v bytes=%d", p.Coverage, p.Privacy.PayloadBytes)
	}
}
func TestReviewVTAlgorithmFieldMismatch(t *testing.T) {
	in := vtFixture()
	in.Enrichments[0].Indicator = strings.Repeat("b", 40)
	in.Enrichments[0].IndicatorType = "sha1"
	in.Events[0].Extra["content_sha256"] = in.Enrichments[0].Indicator
	p, err := PrepareReview(in)
	if err != nil {
		t.Fatal(err)
	}
	if p.Coverage.VTIncluded != 0 || p.Coverage.VTUnlinked != 1 {
		t.Fatalf("wrong field algorithm linked %+v", p.Coverage)
	}
}
func TestReviewVTAliasesAndAlgorithms(t *testing.T) {
	for _, tc := range []struct {
		algorithm, key string
		n              int
	}{{"md5", "md5", 32}, {"sha1", "sha1", 40}, {"sha256", "response_sha256", 64}} {
		in := vtFixture()
		in.Enrichments[0].Indicator = strings.Repeat("a", tc.n)
		in.Enrichments[0].IndicatorType = tc.algorithm
		in.Events[0].Extra = map[string]string{tc.key: in.Enrichments[0].Indicator}
		p, err := PrepareReview(in)
		if err != nil {
			t.Fatal(err)
		}
		d, err := p.Validate("hypothesis | Stored opinion. [V1]")
		if err != nil || len(d.Sentences) != 1 || d.Sentences[0].Kind != "hypothesis" || d.Sentences[0].Cites[0] != (Cite{Kind: "enrichment", ID: "original-enrichment"}) {
			t.Fatalf("V citation %+v %v", d, err)
		}
		if _, err = p.Validate("hypothesis | Stored opinion. [V2]"); err == nil {
			t.Fatal("invented V alias accepted")
		}
		in.Events[0].CaseID = "foreign"
		p, err = PrepareReview(in)
		if err == nil && p.Coverage.VTIncluded != 0 {
			t.Fatal("foreign event linked")
		}
	}
}
func TestReviewVTStoredOpinion(t *testing.T) {
	p, err := PrepareReview(vtFixture())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"V1 |", "status=found", "engines=10", "fetched_at=unknown", "events=E1"} {
		if !strings.Contains(p.User, want) {
			t.Errorf("missing %s in %s", want, p.User)
		}
	}
	for _, bad := range []string{strings.Repeat("a", 64), "original-enrichment", "original-event", "private-secret-name", "secret.invalid", "secret-error", "0001"} {
		if strings.Contains(p.System+p.User, bad) {
			t.Errorf("leaked %s", bad)
		}
	}
}
