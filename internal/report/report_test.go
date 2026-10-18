package report

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"testing"
	"time"
)

func sampleData() Data {
	return Data{
		Meta: Meta{
			Title: "Digital Forensic Analysis Report", CaseID: "case-1", CaseName: "WKSTN-042 triage",
			CaseStatus: "open", Priority: "high", CreatedAt: "2026-10-01T08:00:00Z",
			AnalyzedAt: "2026-10-01T09:00:00Z", GeneratedAt: "2026-10-02T10:00:00Z",
			GeneratedBy: "local-user", ToolName: "Tracefall", ToolVersion: "0.11.0-phase11",
			TimeBasis: "All timestamps are UTC.",
		},
		Summary: Summary{Collections: 1, SourceFiles: 5, ImportedFiles: 4, Events: 120, Findings: 1,
			Severity: []Count{{"critical", 0}, {"high", 1}, {"medium", 0}, {"low", 0}}},
		Analysis: Analysis{Current: true},
		Evidence: []Evidence{{
			Label: "Collection 1", SourceType: "AD1 forensic image", OriginalName: "disk.ad1",
			SHA256: strings.Repeat("ab", 32), SHA512: strings.Repeat("cd", 64),
			HashKind: "AD1 segment bytes, in order", Status: "ingested", Files: 5, Imported: 4, Events: 120,
			Integrity: "Not re-verified since ingestion",
		}},
		Findings: []Finding{{
			Number: "F-001", ID: "f1", Title: "Office application spawned PowerShell", Severity: "high",
			Confidence: "medium", RuleID: "office-spawns-powershell", Description: "winword.exe -> powershell.exe",
			Techniques: []Technique{{"T1059.001", "PowerShell", "Execution"}},
			FirstSeen:  "2026-10-01T07:00:00Z", LastSeen: "2026-10-01T07:01:00Z", ReviewStatus: "new",
			Why: []string{"Base level for this rule."}, EventCount: 1,
			Events: []EventRef{{ID: "e1", Time: "2026-10-01T07:00:00Z", Type: "process_creation",
				Artifact: "Windows Event Log", Summary: "powershell.exe -enc AAA", Source: "Windows/System32/winevt/Logs/Security.evtx", Ref: "record 42"}},
		}},
		Timeline: Timeline{Total: 120, Dated: 118, Undated: 2, Earliest: "2026-09-30T00:00:00Z", Latest: "2026-10-01T09:00:00Z",
			ByArtifact: []Count{{"Windows Event Log", 100}, {"Prefetch", 20}}, PeriodUnit: "day",
			ByPeriod: []Count{{"2026-09-30", 10}, {"2026-10-01", 108}}},
		Coverage: Coverage{Discovered: 5, Supported: 4, Unsupported: 1, Imported: 4,
			ByType: []CoverageRow{{Type: "Windows Event Log (EVTX)", Family: "Event Log", Priority: "critical", Supported: true, Files: 3, Imported: 3},
				{Type: "SRUM database", Family: "Other", Priority: "high", Supported: false, Files: 1, Note: "No ESE database parser"}}},
		Attachments: []Attachment{{Name: "timeline.csv", Description: "Full timeline", SHA256: strings.Repeat("ef", 32), Bytes: 1000, Rows: 120}},
		Rules:       []RuleInfo{{ID: "office-spawns-powershell", Title: "Office spawned PowerShell", Detects: "d", Basis: "b", Base: "high", Max: "high", Fired: 1}},
		Audit:       []AuditEntry{{Time: "2026-10-01T08:00:00Z", Actor: "local-user", Action: "case_created", Summary: "Case created"}},
	}
}

func render(t *testing.T, d Data) string {
	t.Helper()
	out, err := Render(d)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	return string(out)
}

func TestRender_HasTheSectionsAForensicReportNeeds(t *testing.T) {
	html := render(t, sampleData())
	for _, want := range []string{
		"Executive summary", "Evidence inventory", "Methodology", "Findings", "Timeline",
		"Coverage and limitations", "Appendix", "F-001", "Office application spawned PowerShell",
		"T1059.001", "Windows/System32/winevt/Logs/Security.evtx", "SRUM database",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("report is missing %q", want)
		}
	}
}

func TestRender_PrintsCompleteEvidenceHashes(t *testing.T) {
	d := sampleData()
	html := render(t, d)
	for _, h := range []string{d.Evidence[0].SHA256, d.Evidence[0].SHA512} {
		if !strings.Contains(html, h) {
			t.Errorf("full digest %q is not printed; a truncated hash cannot be checked", h)
		}
	}
}

func TestRender_EscapesEvidenceControlledStrings(t *testing.T) {
	d := sampleData()
	d.Findings[0].Title = `<script>alert(1)</script>`
	d.Findings[0].Events[0].Summary = `"><img src=x onerror=alert(1)>`
	d.Evidence[0].OriginalName = `</td><script>x</script>`
	html := render(t, d)
	for _, bad := range []string{"<script", "<img", "</td><script"} {
		if strings.Contains(html, bad) {
			t.Errorf("unescaped markup %q reached the report", bad)
		}
	}
	if !strings.Contains(html, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("the hostile title should be present, but only as escaped text")
	}
}

func TestRender_LoadsNothingExternalAndRunsNoScript(t *testing.T) {
	html := render(t, sampleData())
	if !strings.Contains(html, "Content-Security-Policy") {
		t.Error("no CSP: a report built from evidence strings should refuse script and network by policy")
	}
	for _, bad := range []string{"<script", "<link", "@import", "url(", " src=", "http://", "https://"} {
		if strings.Contains(html, bad) {
			t.Errorf("report contains %q; it must be self-contained and inert", bad)
		}
	}
}

func TestRender_IsDeterministic(t *testing.T) {
	a, _ := Render(sampleData())
	b, _ := Render(sampleData())
	if !bytes.Equal(a, b) {
		t.Fatal("same Data rendered to different bytes")
	}
}

func TestRender_WarnsWhenAnalysisIsNotCurrent(t *testing.T) {
	d := sampleData()
	d.Analysis = Analysis{Current: false, Note: "Evidence changed after the last analysis."}
	html := render(t, d)
	if !strings.Contains(html, "may not reflect") || !strings.Contains(html, "Evidence changed after the last analysis.") {
		t.Error("a stale analysis must be flagged prominently, with the reason")
	}
	d.Analysis.Current = true
	if strings.Contains(render(t, d), "may not reflect") {
		t.Error("a current analysis must not carry the stale warning")
	}
}

func TestRender_StatesWhatTheReportDoesNotClaim(t *testing.T) {
	html := render(t, sampleData())
	for _, want := range []string{
		"not a legal chain of custody", "No artificial intelligence", "not been verified as an examiner",
		"observed", "interpretation",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("limitations section does not state %q", want)
		}
	}
}

func TestRender_ShowsCaseSpecificLimitations(t *testing.T) {
	d := sampleData()
	d.Limitations = []string{"3 supported files failed to parse."}
	if !strings.Contains(render(t, d), "3 supported files failed to parse.") {
		t.Error("caller-computed limitations were dropped")
	}
}

func TestRender_LongUnbrokenValuesCannotOverflowThePage(t *testing.T) {
	d := sampleData()
	d.Findings[0].Events[0].Summary = strings.Repeat("A", 4000)
	html := render(t, d)
	if !strings.Contains(html, "overflow-wrap: anywhere") {
		t.Error("no wrapping rule: an encoded command line would run off the page and be cut in print")
	}
	if !strings.Contains(html, ".nowrap") {
		t.Error("timestamps have no no-wrap rule and will break mid-value")
	}
}

func TestRender_TruncationIsDisclosed(t *testing.T) {
	d := sampleData()
	d.Findings[0].EventsOmitted = 40
	d.Timeline.KeyOmitted = 900
	d.AuditOmitted = 12
	html := render(t, d)
	for _, want := range []string{"40 more", "900", "12"} {
		if !strings.Contains(html, want) {
			t.Errorf("omission count %q is not disclosed; a cut list must say it is cut", want)
		}
	}
}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func TestManifest_RecordsReportAndAttachmentHashes(t *testing.T) {
	d := sampleData()
	html := []byte("<html>report</html>")
	att := []File{{Name: "timeline.csv", Data: []byte("a,b\n1,2\n")}, {Name: "findings.csv", Data: []byte("x\n")}}
	m := NewManifest(d, "report.html", html, att)

	if m.Report.SHA256 != sum(html) || m.Report.Name != "report.html" || m.Report.Bytes != int64(len(html)) {
		t.Errorf("report entry wrong: %+v", m.Report)
	}
	if len(m.Attachments) != 2 || m.Attachments[0].Name != "findings.csv" {
		t.Errorf("attachments must be sorted by name for a stable manifest: %+v", m.Attachments)
	}
	for _, a := range m.Attachments {
		want := sum(map[string][]byte{"timeline.csv": att[0].Data, "findings.csv": att[1].Data}[a.Name])
		if a.SHA256 != want {
			t.Errorf("%s hash = %s, want %s", a.Name, a.SHA256, want)
		}
	}
	if len(m.Evidence) != 1 || m.Evidence[0].SHA256 != d.Evidence[0].SHA256 || m.Evidence[0].SHA512 != d.Evidence[0].SHA512 {
		t.Errorf("evidence digests missing from manifest: %+v", m.Evidence)
	}
	if m.HashAlgorithm != "SHA-256" || m.CaseID != "case-1" || m.GeneratedAt != d.Meta.GeneratedAt {
		t.Errorf("header fields wrong: %+v", m)
	}
	a, _ := m.JSON()
	b, _ := NewManifest(d, "report.html", html, att).JSON()
	if !bytes.Equal(a, b) || len(a) == 0 {
		t.Error("manifest JSON must be non-empty and deterministic")
	}
}

func TestVerify_DetectsAlteredMissingAndUnlistedFiles(t *testing.T) {
	d := sampleData()
	html := []byte("<html>report</html>")
	att := []File{{Name: "timeline.csv", Data: []byte("a,b\n")}}
	mj, err := NewManifest(d, "report.html", html, att).JSON()
	if err != nil {
		t.Fatal(err)
	}
	good := []File{{Name: "report.html", Data: html}, att[0]}

	if mm, err := Verify(mj, good); err != nil || len(mm) != 0 {
		t.Fatalf("an untouched bundle must verify: %v %+v", err, mm)
	}
	altered := []File{{Name: "report.html", Data: []byte("<html>REPORT</html>")}, att[0]}
	if mm, _ := Verify(mj, altered); len(mm) != 1 || mm[0].Name != "report.html" {
		t.Errorf("altered report not caught: %+v", mm)
	}
	if mm, _ := Verify(mj, good[:1]); len(mm) != 1 || mm[0].Name != "timeline.csv" {
		t.Errorf("missing attachment not caught: %+v", mm)
	}
	extra := append(append([]File{}, good...), File{Name: "notes.txt", Data: []byte("x")})
	if mm, _ := Verify(mj, extra); len(mm) != 1 || mm[0].Name != "notes.txt" {
		t.Errorf("a file the manifest does not list must be flagged: %+v", mm)
	}
	if _, err := Verify([]byte("not json"), good); err == nil {
		t.Error("a corrupt manifest must be an error, not a pass")
	}
}

func TestBundle_IsDeterministicAndReadable(t *testing.T) {
	when := time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)
	files := []File{{Name: "b.txt", Data: []byte("B")}, {Name: "a.txt", Data: []byte("A")}}
	z1, err := Bundle(when, files)
	if err != nil {
		t.Fatal(err)
	}
	z2, _ := Bundle(when, []File{files[1], files[0]})
	if !bytes.Equal(z1, z2) {
		t.Error("bundle bytes depend on input order or wall clock")
	}
	zr, err := zip.NewReader(bytes.NewReader(z1), int64(len(z1)))
	if err != nil {
		t.Fatal(err)
	}
	if len(zr.File) != 2 || zr.File[0].Name != "a.txt" {
		t.Fatalf("entries must be name-ordered: %v", zr.File)
	}
	rc, _ := zr.File[1].Open()
	got, _ := io.ReadAll(rc)
	rc.Close()
	if string(got) != "B" {
		t.Errorf("content = %q", got)
	}
	if !zr.File[0].Modified.UTC().Equal(when) {
		t.Errorf("entry time = %v, want the report time %v", zr.File[0].Modified, when)
	}
}

func TestBundle_RejectsUnsafeNames(t *testing.T) {
	for _, name := range []string{"../x", "/abs", "a/../b", "", "dir\\x"} {
		if _, err := Bundle(time.Now(), []File{{Name: name, Data: nil}}); err == nil {
			t.Errorf("name %q accepted", name)
		}
	}
}
