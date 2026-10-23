package api

import (
	"strings"
	"testing"
	"tracefall/internal/model"
	"tracefall/internal/report"
)

func TestReport_UndatedSupportingEvidenceRemainsHonest(t *testing.T) {
	svc := newTestService(t)
	c := model.Case{ID: "case01"}
	e := model.Event{ID: "event01", CaseID: c.ID, Host: "host01", EventType: model.EventBashHistoryCommand, CommandLine: "systemctl enable app.service", SourceReference: "line:1"}
	f := model.Finding{ID: "finding01", CaseID: c.ID, RuleID: "system-change-command", Severity: model.SeverityLow, Confidence: model.ConfidenceLow, Title: "Recorded command", SupportingEvents: []string{e.ID}}
	d := svc.assembleReportData(reportInputs{c: c, events: []model.Event{e}, timeline: &timelineAgg{}, findings: []model.Finding{f}})
	html, err := report.Render(d)
	if err != nil {
		t.Fatal(err)
	}
	text := string(html)
	if strings.Contains(text, "0001-") || !strings.Contains(text, "time not recorded") || !strings.Contains(text, e.ID) {
		t.Fatalf("undated report text is dishonest or evidence lost")
	}
}
