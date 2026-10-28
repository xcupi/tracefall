package narrative

import (
	"strings"
	"testing"

	"tracefall/internal/model"
)

// Exercise the production packet preparation, not only the URL helper. A
// redaction marker is not a reversible identity and query names are not context.
func TestReviewPrivacy_URLMarkerAndBoundaryVariants(t *testing.T) {
	for name, command := range map[string]string{
		"encoded userinfo":    `curl "https://alice:Dummy%27Secret@api.example.test/download?private=DummyQuery#DummyFragment"`,
		"apostrophe userinfo": `curl "https://alice:Dummy'Secret@api.example.test/download?private=DummyQuery#DummyFragment"`,
		"angle marker":        `curl "https://<redacted>@api.example.test/download?private=DummyQuery#DummyFragment"`,
		"bracket marker":      `curl "https://[REDACTED]@api.example.test/download?private=DummyQuery#DummyFragment"`,
		"literal stars":       "curl \"https://\x2a\x2a\x2a@api.example.test/download?private=DummyQuery#DummyFragment\"",
		"no auth":             `curl "https://api.example.test/download?private=DummyQuery#DummyFragment"`,
		"query only":          `curl 'https://api.example.test/download?private=DummyQuery'`,
		"fragment only":       `curl "https://api.example.test/download#DummyFragment"`,
		"repeated quoted":     `curl "https://alice:DummySecret@api.example.test/download?access_token=DummyQuery" 'https://api.example.test/second?private=DummyQuery#DummyFragment'`,
	} {
		t.Run(name, func(t *testing.T) {
			in := ReviewInput{CaseID: "c", Events: []model.Event{{ID: "e", CaseID: "c", CommandLine: command}}}
			p, err := PrepareReview(in)
			if err != nil {
				t.Fatal(err)
			}
			for _, bad := range []string{"Dummy", "alice", "access_token=", "private=", "?", "#"} {
				if strings.Contains(p.User, bad) {
					t.Errorf("protected URL component reached packet: %s", bad)
				}
				for _, entry := range p.Entities() {
					if strings.Contains(entry.Value, bad) {
						t.Errorf("protected URL component retained in dictionary: %s", bad)
					}
				}
			}
			if !strings.Contains(p.User, "curl") || !strings.Contains(p.User, "/download") {
				t.Error("useful command/path lost")
			}
			host := false
			for _, entry := range p.Entities() {
				if entry.Value == "api.example.test" {
					host = true
				}
				if strings.Contains(strings.ToLower(entry.Value), "redacted") {
					t.Error("redaction marker retained as entity")
				}
			}
			if !host {
				t.Error("useful hostname lost")
			}
			if name == "repeated quoted" && !strings.Contains(p.User, "/second") {
				t.Error("following URL swallowed")
			}
			if in.Events[0].CommandLine != command {
				t.Error("stored input mutated")
			}
		})
	}
}
