package narrative

import (
	"strings"
	"testing"

	"tracefall/internal/model"
)

// A transaction-log companion is labeled in its parse coverage (CompanionOf),
// but nothing was read from it. The packet must not turn that label into a
// measured "records_read=0".
func TestReview_CompanionLabelIsNotRecordedCoverage(t *testing.T) {
	in := ReviewInput{CaseID: "c",
		Findings: []model.Finding{{ID: "f", CaseID: "c", Title: "A rule lead", SupportingEvents: []string{"e1"}}},
		Events:   []model.Event{{ID: "e1", CaseID: "c", CollectionID: "a", SourceFileID: "s1", EventType: "process_creation"}},
		Sources: []model.SourceFile{
			{ID: "s1", CaseID: "c", CollectionID: "a", ImportStatus: "imported", ParseCoverage: &model.ParseCoverage{RecordsRead: 0, Mapped: 0}},
			{ID: "s2", CaseID: "c", CollectionID: "a", ImportStatus: "unsupported", ArtifactType: model.ArtifactRegistryTransactionLog, ParseCoverage: &model.ParseCoverage{CompanionOf: "vol1/config/SYSTEM"}},
		}}
	p, err := PrepareReview(in)
	if err != nil {
		t.Fatal(err)
	}
	var companion, measured string
	for _, line := range strings.Split(p.User, "\n") {
		switch {
		case strings.Contains(line, "status=unsupported"):
			companion = line
		case strings.Contains(line, "status=imported") && strings.Contains(line, "parse_coverage"):
			measured = line
		}
	}
	if companion == "" || measured == "" {
		t.Fatalf("source lines missing:\n%s", p.User)
	}
	if strings.Contains(companion, "parse_coverage=recorded") || strings.Contains(companion, "records_read=0") || !strings.Contains(companion, "parse_coverage=not_recorded") {
		t.Errorf("companion row fabricates a measured zero: %s", companion)
	}
	if !strings.Contains(measured, "parse_coverage=recorded records_read=0") {
		t.Errorf("a genuinely recorded zero must stay recorded: %s", measured)
	}
	if !strings.Contains(p.User, "parse_coverage_not_recorded=1") {
		t.Errorf("not-recorded count must include the companion row only: %s", p.User)
	}
}
