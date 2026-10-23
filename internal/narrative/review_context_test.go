package narrative

import (
	"fmt"
	"strings"
	"testing"
	"tracefall/internal/model"
)

func TestReview_NormalizedUnflaggedCommandsRemainUsefulWithoutSecrets(t *testing.T) {
	const secret = "SyntheticCredentialPassword"
	in := ReviewInput{CaseID: "c", Events: []model.Event{
		{ID: "e1", CaseID: "c", EventType: model.EventBashHistoryCommand, User: "alice", ProcessName: "bash", CommandLine: "chmod +x /home/alice/helper.sh", Extra: map[string]string{"timestamp_partial": "Mar 14 03:36:03"}},
		{ID: "e2", CaseID: "c", EventType: "process_creation", User: "alice", CommandLine: "net user alice " + secret + " /add"},
	}}
	p, err := PrepareReview(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"cmd=chmod +x", "net user", "Mar 14 03:36:03", "time_basis=unknown"} {
		if !strings.Contains(p.User, want) {
			t.Errorf("useful parsed context %q missing", want)
		}
	}
	if strings.Contains(p.User, secret) || strings.Contains(p.User, "alice") {
		t.Fatal("command key/name leaked")
	}
}

func TestReview_GlobalSourceFailuresCannotDisappearOutsideCoverageSample(t *testing.T) {
	in := ReviewInput{CaseID: "c", Events: []model.Event{{ID: "e", CaseID: "c"}}}
	for i := 0; i < ReviewMaxSources; i++ {
		in.Sources = append(in.Sources, model.SourceFile{ID: fmt.Sprintf("s%03d", i), CaseID: "c", ImportStatus: "imported", Supported: true})
	}
	in.Sources = append(in.Sources, model.SourceFile{ID: "z-failed", CaseID: "c", ImportStatus: "failed", Supported: true}, model.SourceFile{ID: "z-unsupported", CaseID: "c", Supported: false})
	p, err := PrepareReview(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"sources_imported=60", "sources_failed=1", "sources_unsupported=1", "sources_omitted=2"} {
		if !strings.Contains(p.User, want) {
			t.Errorf("global source limit %q lost outside sample", want)
		}
	}
}
