package narrative

import (
	"errors"
	"strings"
	"testing"

	"tracefall/internal/model"
)

func TestReviewPrivacy_SourceStatusCannotCarryParserErrors(t *testing.T) {
	in := ReviewInput{CaseID: "c", Events: []model.Event{{ID: "e", CaseID: "c"}}, Sources: []model.SourceFile{{ID: "s", CaseID: "c", ImportStatus: "read error at /srv/examiner/private-case/source"}}}
	p, err := PrepareReview(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(p.User, "/srv/examiner") || strings.Contains(p.User, "private-case") {
		t.Fatal("unknown import status carried a raw parser/server value")
	}
	if !strings.Contains(p.User, "status=unclassified_status_not_sent") {
		t.Fatal("unknown status was silently treated as complete or known")
	}
}

func TestReviewPrivacy_URLCredentialsAndQueryNeverBecomeEvidenceContext(t *testing.T) {
	in := ReviewInput{CaseID: "c", Events: []model.Event{{ID: "e", CaseID: "c", CommandLine: `curl "https://alice:UserInfoSecret@api.example.test/download?access_token=ShortSecret42&session_id=SessionSecret9#ResetSecret7"`}}}
	p, err := PrepareReview(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"UserInfoSecret", "ShortSecret42", "SessionSecret9", "ResetSecret7", "access_token=", "session_id="} {
		if strings.Contains(p.User, bad) {
			t.Errorf("URL credential/query/fragment reached packet: %s", bad)
		}
	}
	if !strings.Contains(p.User, "curl") || !strings.Contains(p.User, "/download") {
		t.Fatal("useful normalized command context lost")
	}
	for _, entry := range p.Entities() {
		if strings.Contains(entry.Value, "Secret") {
			t.Fatal("a secret was retained in the reversible dictionary")
		}
	}
}

func TestReviewPrivacy_ShortEnvironmentCredentialsAreIrreversible(t *testing.T) {
	in := ReviewInput{CaseID: "c", Events: []model.Event{{ID: "e", CaseID: "c", CommandLine: `AWS_SECRET_ACCESS_KEY=EnvSecret7 AWS_SESSION_TOKEN=SessionSecret8 tool --refresh-token RefreshSecret9`}}}
	p, err := PrepareReview(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"EnvSecret7", "SessionSecret8", "RefreshSecret9"} {
		if strings.Contains(p.User, bad) {
			t.Errorf("short credential reached packet: %s", bad)
		}
		for _, entry := range p.Entities() {
			if strings.Contains(entry.Value, bad) {
				t.Fatal("credential retained in reversible dictionary")
			}
		}
	}
}

func TestReviewPrivacy_RecognizableRequestBodiesAndKeysAreOmitted(t *testing.T) {
	for _, command := range []string{`curl --data '{"cookie":"ShortCookie7"}' https://api.example.test`, `curl -b session=ShortCookie7 https://api.example.test`, `Invoke-WebRequest https://api.example.test -Body '{"value":"PrivateBody7"}'`, `SELECT 'PrivateSQL7'`, "-----BEGIN PRIVATE KEY-----\nPrivateKey7\n-----END PRIVATE KEY-----"} {
		p, err := PrepareReview(ReviewInput{CaseID: "c", Events: []model.Event{{ID: "e", CaseID: "c", CommandLine: command}}})
		if err != nil {
			t.Fatal(err)
		}
		if p.Coverage.CommandLinesOmitted != 1 || !strings.Contains(p.User, "command_context=omitted_prohibited_body") {
			t.Errorf("recognizable protected body was not omitted: %q", command)
		}
		for _, bad := range []string{"ShortCookie7", "PrivateBody7", "PrivateSQL7", "PrivateKey7"} {
			if strings.Contains(p.User, bad) {
				t.Errorf("body leaked: %s", bad)
			}
		}
	}
}

func TestReviewPrivacy_ProtectedBodiesCannotUseEnumFieldsAsAnExit(t *testing.T) {
	for _, body := range []string{`SELECT payroll FROM employee`, `Cookie: session=ShortCookie7`, `access_token=ShortToken7`} {
		p, err := PrepareReview(ReviewInput{CaseID: "c", Events: []model.Event{{ID: "e", CaseID: "c", EventType: body}}})
		if !errors.Is(err, ErrLeak) || p != nil {
			t.Errorf("untrusted enum bypassed privacy gate: %q (%v)", body, err)
		}
	}
}
