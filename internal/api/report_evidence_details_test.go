package api

import (
	"strings"
	"testing"
	"tracefall/internal/model"
	"tracefall/internal/report"
)

func TestReport_NewEvidenceDetailsAreReadableAndCommandsAreRedacted(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	tests := []struct {
		name string
		e    model.Event
		want []string
		deny string
	}{
		{"http", model.Event{EventType: model.EventWebRequest, Extra: map[string]string{"method": "GET", "http_host": "files.example", "uri": "/tool.exe", "status": "200", "response_sha256": hash, "reassembly": "complete"}}, []string{"GET", "files.example", "/tool.exe", "200", hash}, ""},
		{"http-response-only", model.Event{EventType: model.EventWebRequest, Extra: map[string]string{"request_in_capture": "false: only the response was captured", "response_utc": "2025-01-01T01:00:00Z"}}, []string{"false: only the response was captured", "2025-01-01T01:00:00Z"}, ""},
		{"dns-response-only", model.Event{EventType: model.EventDNSQuery, Extra: map[string]string{"query_in_capture": "false: only the response was captured", "response_utc": "2025-01-01T01:00:00Z"}}, []string{"false: only the response was captured", "2025-01-01T01:00:00Z"}, ""},
		{"clock", model.Event{EventType: model.EventClockObservation, Extra: map[string]string{"subject_ip": "203.0.113.8", "observed_utc": "2025-01-01T01:00:00Z", "capture_utc": "2025-01-01T00:00:00Z"}}, []string{"203.0.113.8", "2025-01-01T01:00:00Z", "2025-01-01T00:00:00Z"}, ""},
		{"recovered", model.Event{EventType: model.EventMemoryFileContent, FilePath: `\Tools\tool.exe`, Extra: map[string]string{"sha256": hash, "file_signature": "Windows executable", "sparse": "true", "zero_pages": "9 of 10", "memory_cache": "ImageSectionObject", "timestamp_basis": "memory_snapshot"}}, []string{hash, "9 of 10", "ImageSectionObject", "memory_snapshot"}, ""},
		{"rdp", model.Event{EventType: model.EventNetworkConnection, Extra: map[string]string{"connections": "120", "client_port": "51000", "packets": "500", "application": "rdp"}}, []string{"120", "51000", "500", "rdp"}, ""},
		{"account", model.Event{EventType: model.EventAccountChange, Extra: map[string]string{"action": "created", "object_type": "user", "object_name": "alice"}}, []string{"created", "alice", "object_name"}, ""},
		{"redaction", model.Event{EventType: model.EventMemoryConsole, CommandLine: "net user alice FakeSecretForReport123 /add"}, []string{"alice"}, "FakeSecretForReport123"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref := eventRef(tt.e, nil)
			html, err := report.Render(report.Data{Timeline: report.Timeline{Key: []report.EventRef{ref}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, w := range tt.want {
				if !strings.Contains(string(html), w) {
					t.Errorf("missing %q", w)
				}
			}
			if tt.deny != "" && strings.Contains(string(html), tt.deny) {
				t.Error("report leaks a command credential")
			}
		})
	}
}

func TestReport_FindingMissingEvidenceIsExplicit(t *testing.T) {
	svc := newTestService(t)
	d := svc.assembleReportData(reportInputs{c: model.Case{ID: "case"}, timeline: &timelineAgg{}, findings: []model.Finding{{ID: "f1", SupportingEvents: []string{"gone"}}}})
	html, err := report.Render(d)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(html), "Evidence incomplete") || strings.Contains(string(html), "and 1 more events not shown") {
		t.Fatal("missing evidence is misrepresented as an omitted available event")
	}
}

func TestReport_TimeBasisDoesNotInventUTCForUnknownLocalReadings(t *testing.T) {
	svc := newTestService(t)
	d := svc.assembleReportData(reportInputs{c: model.Case{ID: "case"}, timeline: &timelineAgg{}})
	h, err := report.Render(d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(h), "interpreted as UTC") {
		t.Error("report claims unknown-zone readings are UTC")
	}
	if !strings.Contains(string(h), "unknown") {
		t.Error("missing explicit unknown time basis")
	}
}

func TestReport_CaseCaveatsIncludeCaptureAndMemorySemantics(t *testing.T) {
	in := reportInputs{sourceFiles: []model.SourceFile{{ArtifactType: model.ArtifactNetworkCapture}, {ArtifactType: model.ArtifactMemoryAnalysis}}}
	text := strings.Join(reportLimitations(report.Data{}, in), " ")
	for _, w := range []string{"capture clock", "snapshot", "zero", "execution"} {
		if !strings.Contains(text, w) {
			t.Errorf("missing caveat %q", w)
		}
	}
}
