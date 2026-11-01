package api

import (
	"os/exec"
	"strings"
	"testing"

	"tracefall/internal/model"
	"tracefall/internal/report"
)

func srumCoverageFixture() *model.ParseCoverage {
	clean := false
	return &model.ParseCoverage{
		RecordsRead: 9, Mapped: 4, Unmapped: 5,
		Notes:         []string{"table {X}: 5 records not interpreted (no known layout)"},
		DatabaseState: "dirty shutdown", CleanShutdown: &clean,
		Tables: []model.CoverageTable{
			{Table: "{A}", Rows: 3, Interpreted: true, Event: model.EventSRUMAppUsage},
			{Table: "{B}", Rows: 1, Interpreted: true, Event: model.EventSRUMSDPNetwork},
			{Table: "{C}", Rows: 5},
			{Table: "{D}", Rows: 0},
		},
	}
}

const srumSummary = "4 tables, 2 interpreted, 5 rows not interpreted"

func TestReport_SRUMCensusIsShownAndNeverReadsAsComplete(t *testing.T) {
	c := srumCoverageFixture()
	got := reportCoverage([]model.SourceFile{{Path: "vol1/Windows/System32/sru/SRUDB.dat", ArtifactType: model.ArtifactSRUM, ParseCoverage: c}})
	if len(got.ParserDiagnostics) != 1 {
		t.Fatalf("diagnostics = %+v", got.ParserDiagnostics)
	}
	text := got.ParserDiagnostics[0].Value
	for _, want := range []string{srumSummary, "dirty shutdown"} {
		if !strings.Contains(text, want) {
			t.Errorf("source coverage lacks %q: %s", want, text)
		}
	}
	lim := strings.Join(reportLimitations(report.Data{}, reportInputs{sourceFiles: []model.SourceFile{{Path: "SRUDB.dat", ParseCoverage: c}}}), "\n")
	if !strings.Contains(lim, srumSummary) {
		t.Errorf("report limitations lack the table census: %s", lim)
	}
	// An unlisted tail must be said, not hidden.
	c.TablesUnlisted = 2
	got = reportCoverage([]model.SourceFile{{Path: "SRUDB.dat", ParseCoverage: c}})
	if !strings.Contains(got.ParserDiagnostics[0].Value, "2 more tables not listed") {
		t.Errorf("unlisted tables hidden: %s", got.ParserDiagnostics[0].Value)
	}
}

func TestUI_SRUMCensusIsShownInSourceCoverage(t *testing.T) {
	src := appJS(t)
	js := `const assert=require('node:assert/strict');
function parseCoverageText(` + functionBody(t, src, "function parseCoverageText(") + `
const c={records_read:9,mapped:4,unmapped:5,notes:['n'],database_state:'dirty shutdown',clean_shutdown:false,tables:[{table:'{A}',rows:3,interpreted:true},{table:'{B}',rows:1,interpreted:true},{table:'{C}',rows:5,interpreted:false},{table:'{D}',rows:0,interpreted:false}]};
assert.match(parseCoverageText(c),/4 tables, 2 interpreted, 5 rows not interpreted/);
assert.match(parseCoverageText(c),/dirty shutdown/);
assert.match(parseCoverageText({...c,tables_unlisted:2}),/2 more tables not listed/);
assert.doesNotMatch(parseCoverageText({records_read:1,mapped:1}),/tables/);
console.log('srum census ui ok');`
	out, err := exec.Command("node", "-e", js).CombinedOutput()
	if err != nil {
		t.Fatalf("UI assertion: %v\n%s", err, out)
	}
}

func TestReport_SRUMNetworkEventsCarryTheirLimitsAndNeverWordATransfer(t *testing.T) {
	for _, typ := range []string{model.EventSRUMNetworkUsage, model.EventSRUMNetworkConnection, model.EventSRUMSDPNetwork} {
		e := model.Event{ID: "e1", EventType: typ, ArtifactType: model.ArtifactSRUM, ProcessName: "tool.exe", Extra: map[string]string{
			"bytes_sent": "53687091200", "bytes_out_bound": "53687091200",
			"evidence_meaning": "interval total, not a flow", "limitations": "Not a flow: carries no destination, protocol or content.",
			"time_basis": "End of the aggregation interval; not been calibrated.",
		}}
		got := map[string]string{}
		for _, kv := range reportEventDetails(e) {
			got[kv.Key] = kv.Value
		}
		for _, k := range []string{"evidence_meaning", "limitations", "time_basis"} {
			if got[k] == "" {
				t.Errorf("%s: report details omit %s", typ, k)
			}
		}
		ref := eventRef(e, nil)
		all := ref.Summary
		for _, kv := range ref.Details {
			all += " " + kv.Value
		}
		for _, w := range []string{"exfiltrat", "upload", "stolen", "sent to"} {
			if strings.Contains(strings.ToLower(all), w) {
				t.Errorf("%s: report wording %q in %q", typ, w, all)
			}
		}
	}
}
