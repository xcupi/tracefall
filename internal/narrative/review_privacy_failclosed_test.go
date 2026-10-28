package narrative

import (
	"strings"
	"testing"
	"tracefall/internal/cmdsem"
	"tracefall/internal/model"
)

func TestReviewPrivacy_AmbiguousURLCommandOmittedBeforeDictionary(t *testing.T) {
	assertAmbiguousURLCommandOmitted(t, `curl "https://api.example.test/download?private=first\"DummyQuery#DummyFragment"; echo keep`)
}

func TestReviewPrivacy_UncertainURLFormsFailClosed(t *testing.T) {
	for name, command := range map[string]string{
		"doubled_single_quote": `curl 'https://api.example.test/download?private=first''DummyQuery#DummyFragment'; echo keep`,
		"doubled_double_quote": `curl "https://api.example.test/download?private=first""DummyQuery#DummyFragment"; echo keep`,
		"backtick":             "curl \"https://api.example.test/download?private=first`\"DummyQuery#DummyFragment\"; echo keep",
		"odd_backslashes":      `curl "https://api.example.test/download?private=first\\\"DummyQuery#DummyFragment"; echo keep`,
		"escaped_opening":      `curl \"https://api.example.test/download?private=DummyQuery#DummyFragment\"; echo keep`,
		"unclosed_double":      `curl "https://api.example.test/download?private=DummyQuery#DummyFragment`,
		"unclosed_single":      `curl 'https://api.example.test/download?private=DummyQuery#DummyFragment`,
		"incomplete_marker":    `curl https://<redactedDummyQuery@api.example.test/download#DummyFragment; echo keep`,
		"unknown_marker":       `curl https://<masked>@api.example.test/download?private=DummyQuery#DummyFragment; echo keep`,
		"invalid_host":         `curl "https://api.example.test:invalid/download?private=DummyQuery#DummyFragment"; echo keep`,
		"invalid_escape":       `curl "https://api.example.test/down%ZZload?private=DummyQuery#DummyFragment"; echo keep`,
	} {
		t.Run(name, func(t *testing.T) { assertAmbiguousURLCommandOmitted(t, command) })
	}
}

func TestReviewPrivacy_CertainURLBoundariesRetainUsefulContext(t *testing.T) {
	for name, command := range map[string]string{
		"single":            `curl 'https://alice:DummyPassword@api.example.test/download?DummyQuery=DummyValue#DummyFragment'; echo keep`,
		"double_apostrophe": `curl "https://ali'ce:DummyPassword@api.example.test/download?DummyQuery=Du'mmyValue#DummyFragment"; echo keep`,
		"bare_apostrophe":   `curl https://ali'ce:DummyPassword@api.example.test/download?DummyQuery=Du'mmyValue#DummyFragment ; echo keep`,
		"adjacent":          `curl "https://api.example.test/download?DummyQuery=DummyValue#DummyFragment"'https://other.example.test/other?DummyQuery=DummyValue'; echo keep`,
		"even_backslashes":  `curl "https://api.example.test/download?DummyQuery=DummyValue\\"; echo keep`,
		"even_backticks":    "curl \"https://api.example.test/download?DummyQuery=DummyValue``\"; echo keep",
		"reserved_encoded":  `curl "https://api.example.test/download%2Fsegment?q=%22%27%3C%3E%40%3F%23#DummyFragment"; echo keep`,
	} {
		t.Run(name, func(t *testing.T) {
			events := []model.Event{{ID: "e", CaseID: "c", CommandLine: command}}
			p, err := PrepareReview(ReviewInput{CaseID: "c", Events: events})
			if err != nil {
				t.Fatal(err)
			}
			if p.Coverage.CommandLinesOmitted != 0 || !strings.Contains(p.User, "command_context=bounded_redacted_normalized") {
				t.Fatal("unambiguous command omitted")
			}
			for _, want := range []string{"cmd=curl", "/download", "echo keep"} {
				if !strings.Contains(p.User, want) {
					t.Errorf("useful context missing: %s", want)
				}
			}
			if name == "adjacent" && !strings.Contains(p.User, "/other") {
				t.Error("following URL consumed")
			}
			foundHost := false
			for _, entry := range p.Entities() {
				if strings.Contains(entry.Value, "api.example.test") {
					foundHost = true
				}
			}
			if !foundHost {
				t.Error("normalized host not retained")
			}
			for _, bad := range []string{"DummyPassword", "DummyQuery", "DummyValue", "DummyFragment", "Du'mmyValue"} {
				if strings.Contains(p.User, bad) {
					t.Error("URL private material in packet")
				}
				for _, entry := range p.Entities() {
					if strings.Contains(entry.Value, bad) {
						t.Error("URL private material in dictionary")
					}
				}
			}
			if events[0].CommandLine != command {
				t.Fatal("raw evidence changed")
			}
		})
	}
}

func TestReviewPrivacy_NonURLAndGeneralRedactorContractsUnchanged(t *testing.T) {
	command := `echo alice@example.test keep`
	p, err := PrepareReview(ReviewInput{CaseID: "c", Events: []model.Event{{ID: "e", CaseID: "c", CommandLine: command}}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Coverage.CommandLinesOmitted != 0 || !strings.Contains(p.User, "cmd=echo") {
		t.Fatal("non-URL command omitted")
	}
	got := cmdsem.Redact(`curl "https://alice:DummyPassword@api.example.test/download?ordinary=value#fragment"; echo keep`)
	want := `curl "https://<redacted>@api.example.test/download?ordinary=value#fragment"; echo keep`
	if got != want {
		t.Fatal("generic redactor URL contract changed")
	}
}

func assertAmbiguousURLCommandOmitted(t *testing.T, command string) {
	t.Helper()
	events := []model.Event{{ID: "e", CaseID: "c", CommandLine: command}}
	p, err := PrepareReview(ReviewInput{CaseID: "c", Events: events})
	if err != nil {
		t.Fatal(err)
	}
	if p.Coverage.CommandLinesOmitted != 1 || !strings.Contains(p.User, "command_context=omitted_ambiguous_url") {
		t.Error("ambiguous URL command omission and bounded reason missing")
	}
	if strings.Contains(p.User, "cmd=") {
		t.Error("entire ambiguous command context must be omitted")
	}
	for _, bad := range []string{"DummyQuery", "DummyFragment", "api.example.test", "keep"} {
		if strings.Contains(p.User, bad) {
			t.Error("ambiguous command reached packet")
		}
		for _, e := range p.Entities() {
			if strings.Contains(e.Value, bad) {
				t.Error("ambiguous command reached reversible dictionary")
			}
		}
	}
	if events[0].CommandLine != command {
		t.Fatal("raw evidence changed")
	}
}
