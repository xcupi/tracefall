package narrative

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"tracefall/internal/model"
)

func TestReview_MetadataCoverageCaveatsAndPrivacy(t *testing.T) {
	for _, state := range []string{"clean", "replayed", "replayed_partial", "not_recoverable", "no_logs", "https://secret-marker@example.test/private?token=secret-marker"} {
		for _, measured := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%t", state, measured), func(t *testing.T) {
				c := &model.ParseCoverage{Notes: []string{"secret-marker /server/private/path https://secret-marker@example.test/private?token=secret-marker"}, HiveReplay: &model.HiveReplay{State: state, Reason: "secret-marker", LogsApplied: []string{"/server/private/path"}, Companions: []model.HiveCompanion{{Path: "/server/private/path", Status: model.CompanionFailed, Detail: "secret-marker"}}}}
				if measured {
					zero := 0
					c.EmittedEvents = &zero
				}
				in := ReviewInput{CaseID: "c", Events: []model.Event{{ID: "e", CaseID: "c"}}, Sources: []model.SourceFile{{ID: "s", CaseID: "c", ParseCoverage: c}}}
				p, err := PrepareReview(in)
				if err != nil {
					t.Fatal(err)
				}
				wantState := state
				if strings.HasPrefix(state, "https:") {
					wantState = "unclassified_state_not_sent"
				}
				for _, want := range []string{"notes_present=true", "hive_replay=" + wantState, "logs_applied=1", "companions_not_extracted=1", "recovery_caveat_present=true"} {
					if !strings.Contains(p.User, want) {
						t.Errorf("missing %q: %s", want, p.User)
					}
				}
				if !measured && (!strings.Contains(p.User, "parse_coverage=not_recorded") || strings.Contains(p.User, "records_read=0")) {
					t.Errorf("fabricated metrics: %s", p.User)
				}
				dictionary, _ := json.Marshal(p.Entities())
				for _, bad := range []string{"secret-marker", "/server/private/path", "example.test"} {
					if strings.Contains(p.User+string(dictionary), bad) {
						t.Errorf("private metadata entered packet/dictionary: %q", bad)
					}
				}
			})
		}
	}
}
