package narrative

import (
	"strings"
	"testing"
	"tracefall/internal/model"
)

func TestReviewPrivacy_URLLiteralAndContiguousControls(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"double apostrophe", `curl "https://api.example.test/down'load?private=first'DummyQuery#DummyFragment"; echo keep`, `curl "https://api.example.test/down'load"; echo keep`},
		{"bare apostrophe", `curl https://api.example.test/download?private=first'DummyQuery#DummyFragment`, `curl https://api.example.test/download`},
		{"single closes", `curl 'https://api.example.test/download?private=DummyQuery'; echo keep`, `curl 'https://api.example.test/download'; echo keep`},
		{"single literal suffix", `echo 'https://api.example.test/download?private=DummyQuery'ordinary`, `echo 'https://api.example.test/download'ordinary`},
		{"contiguous", `curl 'https://api.example.test/download?private=DummyQuery'"https://second.example.test/second#first'DummyFragment"; echo keep`, `curl 'https://api.example.test/download'"https://second.example.test/second"; echo keep`},
		{"nested", `echo "$(curl 'https://api.example.test/download?private=DummyQuery')"`, `echo "$(curl 'https://api.example.test/download')"`},
		{"not URLs", `cat alice's-download.txt; echo alice@example.test`, `cat alice's-download.txt; echo alice@example.test`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := redactReviewValue(tc.in); got != tc.want {
				t.Errorf("got %q; want %q", got, tc.want)
			}
		})
	}
}

func TestReviewPrivacy_ApostropheQueryFragmentBoundary(t *testing.T) {
	for name, command := range map[string]string{
		"query double":              `curl "https://api.example.test/download?private=first'DummyQuery#DummyFragment"`,
		"fragment double":           `curl "https://api.example.test/download#first'DummyFragment"`,
		"query bare":                `curl https://api.example.test/download?private=first'DummyQuery#DummyFragment`,
		"filename prefix":           `cat carol's-download.txt; curl "https://api.example.test/download?private=first'DummyQuery#DummyFragment"`,
		"filename prefix bare":      `cat carol's-download.txt; curl https://api.example.test/download?private=first'DummyQuery#DummyFragment`,
		"userinfo and query double": `curl "https://alice:Dummy'Secret@api.example.test/download?private=first'DummyQuery#first'DummyFragment"`,
		"userinfo and query bare":   `curl https://alice:Dummy'Secret@api.example.test/download?private=first'DummyQuery#first'DummyFragment`,
		"encoded single":            `curl 'https://alice:Dummy%27Secret@api.example.test/download?private=first%27DummyQuery#first%27DummyFragment'`,
		"path apostrophe double":    `curl "https://api.example.test/down'load/download?private=first'DummyQuery#DummyFragment"`,
		"uppercase http":            `curl "HTTP://api.example.test/download?private=first'DummyQuery#DummyFragment"`,
		"consecutive quoted":        `curl 'https://api.example.test/download?private=DummyQuery'"https://second.example.test/second?private=first'DummyQuery#DummyFragment"; echo keep`,
		"multiline":                 "curl \"https://api.example.test/download?private=first'DummyQuery\"\ncurl 'https://second.example.test/second#DummyFragment'",
		"nested expression":         `echo "$(curl 'https://api.example.test/download?private=DummyQuery')"; curl "https://second.example.test/second#first'DummyFragment"`,
	} {
		t.Run(name, func(t *testing.T) {
			p, err := PrepareReview(ReviewInput{CaseID: "c", Events: []model.Event{{ID: "e", CaseID: "c", CommandLine: command}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, bad := range []string{"Dummy", "alice", "private=", "first", "?", "#"} {
				if strings.Contains(p.User, bad) {
					t.Errorf("packet leaked %s", bad)
				}
				for _, e := range p.Entities() {
					if strings.Contains(e.Value, bad) {
						t.Errorf("dictionary leaked %s", bad)
					}
				}
			}
			if !strings.Contains(p.User, "curl") || !strings.Contains(p.User, "/download") {
				t.Error("useful command/path lost")
			}
			host := false
			for _, e := range p.Entities() {
				if e.Value == "api.example.test" {
					host = true
				}
			}
			if !host {
				t.Error("useful hostname lost")
			}
			if strings.Contains(command, "/second") && !strings.Contains(p.User, "/second") {
				t.Error("following URL lost")
			}
			if strings.Contains(command, "echo keep") && !strings.Contains(p.User, "echo keep") {
				t.Error("following command lost")
			}
		})
	}
}
