package narrative

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"tracefall/internal/detect"
	"tracefall/internal/model"
)

// Exercise real detector prose, not a reconstructed finding that bypasses Redact.
func TestReviewPrivacy_DetectorProseAmbiguousURL(t *testing.T) {
	command := "powershell -nop -Command curl \"https://api.example.test/download?private=first`\"DummyQuery@vault.example.test#DummyFragment\"; echo keep"
	events := []model.Event{{ID: "e", CaseID: "c", EventType: model.EventProcessCreate, ProcessName: "powershell.exe", CommandLine: command}}
	var findings []model.Finding
	for _, rule := range detect.All() {
		if rule.ID() == "powershell-encoded-command" {
			findings = rule.Evaluate(events)
		}
	}
	if len(findings) != 1 || !strings.Contains(findings[0].Description, "DummyQuery") {
		t.Fatal("fixture must produce actual command-derived detector prose")
	}
	before, _ := json.Marshal(findings)
	p, err := PrepareReview(ReviewInput{CaseID: "c", Events: events, Findings: findings})
	if err != nil {
		t.Fatal(err)
	}
	assertNoPrivateIngress(t, p)
	if p.Coverage.CommandLinesOmitted != 1 {
		t.Errorf("command omission=%d want 1", p.Coverage.CommandLinesOmitted)
	}
	if !strings.Contains(p.User, "description=omitted_ambiguous_url") {
		t.Error("finding prose must have fixed omission reason")
	}
	if !strings.Contains(p.User, "title=PowerShell command/script review") {
		t.Error("safe finding title lost")
	}
	if !strings.Contains(p.User, "prose_values_omitted=1") {
		t.Error("prose omission coverage missing or inaccurate")
	}
	after, _ := json.Marshal(findings)
	if string(before) != string(after) || events[0].CommandLine != command {
		t.Fatal("stored evidence or findings changed")
	}
}

func TestReviewPrivacy_EscapedWhitespaceURL(t *testing.T) {
	for _, escape := range []string{"\\", "`"} {
		for _, space := range []string{" ", "\t", "\n", "\r", "\r\n"} {
			t.Run(fmt.Sprintf("%q_%q", escape, space), func(t *testing.T) {
				command := "curl https://api.example.test/download?private=first" + escape + space + "DummyQuery@vault.example.test#DummyFragment; echo keep"
				assertAmbiguousURLCommandOmitted(t, command)
				events := []model.Event{{ID: "e", CaseID: "c", EventType: model.EventProcessCreate, ProcessName: "powershell.exe", CommandLine: "powershell -nop -Command " + command}}
				findings := ingressDetectorFindings(t, events)
				before, _ := json.Marshal(findings)
				p, err := PrepareReview(ReviewInput{CaseID: "c", Events: events, Findings: findings})
				if err != nil {
					t.Fatal(err)
				}
				assertNoPrivateIngress(t, p)
				if p.Coverage.CommandLinesOmitted != 1 || p.Coverage.ProseValuesOmitted == nil || *p.Coverage.ProseValuesOmitted != 1 {
					t.Fatalf("wrong omission counts: %+v", p.Coverage)
				}
				after, _ := json.Marshal(findings)
				if string(before) != string(after) || events[0].CommandLine != "powershell -nop -Command "+command {
					t.Fatal("source changed")
				}
			})
		}
	}
}

func ingressDetectorFindings(t *testing.T, events []model.Event) []model.Finding {
	t.Helper()
	for _, r := range detect.All() {
		if r.ID() == "powershell-encoded-command" {
			fs := r.Evaluate(events)
			if len(fs) != 1 {
				t.Fatalf("expected actual production finding, got %d", len(fs))
			}
			return fs
		}
	}
	t.Fatal("production rule not registered")
	return nil
}

func TestReviewPrivacy_ProseIngressAndCoverage(t *testing.T) {
	ambiguous := "curl https://api.example.test/download?private=first` DummyQuery@vault.example.test#DummyFragment"
	// Each allowed free-text ingress uses the same pre-Apply gate. Correlation
	// descriptions are also command-derived in production; events have no command.
	in := ReviewInput{CaseID: "c", Findings: []model.Finding{{ID: "f", CaseID: "c", Title: ambiguous, Description: ambiguous}}, Correlations: []model.Correlation{{ID: "l", CaseID: "c", Title: ambiguous, Description: ambiguous}}, Events: []model.Event{{ID: "e", CaseID: "c", ProcessName: ambiguous, ParentProcessName: ambiguous, FilePath: ambiguous, RegistryPath: ambiguous, NetworkSource: ambiguous, NetworkDest: ambiguous}}}
	p, err := PrepareReview(in)
	if err != nil {
		t.Fatal(err)
	}
	assertNoPrivateIngress(t, p)
	if p.Coverage.ProseValuesOmitted == nil || *p.Coverage.ProseValuesOmitted != 10 || !strings.Contains(p.User, "prose_values_omitted=10") || p.Coverage.CommandLinesOmitted != 0 {
		t.Fatalf("wrong prose-only coverage: %+v", p.Coverage)
	}
	var old ReviewCoverage
	if err := json.Unmarshal([]byte(`{"command_lines_omitted":0}`), &old); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(old)
	if old.ProseValuesOmitted != nil || strings.Contains(string(b), "prose_values_omitted") {
		t.Fatal("invented historical prose measurement")
	}
}

func TestReviewPrivacy_DetectorSafeProseAndWhitespaceControls(t *testing.T) {
	for _, escape := range []string{"", `\\\\`, "``"} {
		for _, space := range []string{" ", "\t", "\n", "\r"} {
			t.Run(fmt.Sprintf("%q_%q", escape, space), func(t *testing.T) {
				command := "powershell -nop -Command curl https://api.example.test/download?q=DummyQuery#DummyFragment" + escape + space + "; echo keep"
				events := []model.Event{{ID: "e", CaseID: "c", EventType: model.EventProcessCreate, ProcessName: "powershell.exe", CommandLine: command}}
				fs := ingressDetectorFindings(t, events)
				p, err := PrepareReview(ReviewInput{CaseID: "c", Events: events, Findings: fs})
				if err != nil {
					t.Fatal(err)
				}
				if p.Coverage.CommandLinesOmitted != 0 || p.Coverage.ProseValuesOmitted == nil || *p.Coverage.ProseValuesOmitted != 0 {
					t.Fatalf("safe context omitted: %+v", p.Coverage)
				}
				for _, want := range []string{"description=PowerShell activity", "echo keep", "cmd=powershell", "does not establish successful execution"} {
					if !strings.Contains(p.User, want) {
						t.Errorf("missing safe context %q", want)
					}
				}
				for _, bad := range []string{"DummyQuery", "DummyFragment"} {
					if strings.Contains(p.User+fmt.Sprint(p.Entities()), bad) {
						t.Errorf("private residual %s", bad)
					}
				}
			})
		}
	}
}

func TestReviewPrivacy_AmbiguousIdentityNotExported(t *testing.T) {
	ambiguous := "https://api.example.test/?x=first` DummyQuery@vault.example.test#DummyFragment"
	p, err := PrepareReview(ReviewInput{CaseID: "c", Names: Names{Hosts: []string{ambiguous}, Users: []string{ambiguous}, Domains: []string{ambiguous}}, Events: []model.Event{{ID: "e", CaseID: "c", Host: ambiguous, User: ambiguous}}})
	if err != nil {
		t.Fatal(err)
	}
	assertNoPrivateIngress(t, p)
	if p.Coverage.ProseValuesOmitted == nil || *p.Coverage.ProseValuesOmitted != 2 {
		t.Fatalf("wrong coverage: %+v", p.Coverage)
	}
}

func TestReviewPrivacy_SynthesisProseOmissionCoverage(t *testing.T) {
	in := ReviewInput{CaseID: "c", Events: []model.Event{{ID: "e", CaseID: "c", CommandLine: "echo keep"}}}
	commentary := []Sentence{{Text: "curl https://api.example.test/?x=first` DummyQuery@vault.example.test#DummyFragment", Cites: []Cite{{Kind: "event", ID: "e"}}}}
	p, omitted, err := PrepareReviewSynthesis(in, commentary)
	if err != nil {
		t.Fatal(err)
	}
	assertNoPrivateIngress(t, p)
	if omitted != 0 || p.Coverage.ProseValuesOmitted == nil || *p.Coverage.ProseValuesOmitted != 1 || !strings.Contains(p.User, "prose_values_omitted=1") || strings.Contains(p.User, "prose_values_omitted=0") {
		t.Fatalf("wrong synthesis prose coverage: %+v %s", p.Coverage, p.User)
	}
}

func assertNoPrivateIngress(t *testing.T, p *ReviewPrepared) {
	t.Helper()
	for _, bad := range []string{"DummyQuery", "DummyFragment", "vault.example.test", "api.example.test"} {
		if strings.Contains(p.User, bad) {
			t.Errorf("private input in packet: %s", bad)
		}
		for _, e := range p.Entities() {
			if strings.Contains(e.Value, bad) {
				t.Errorf("private input learned in dictionary: %s", bad)
			}
		}
	}
}
