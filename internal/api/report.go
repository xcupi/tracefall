package api

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"tracefall/internal/attck"
	"tracefall/internal/detect"
	"tracefall/internal/model"
	"tracefall/internal/report"
	"tracefall/internal/version"
)

// The forensic report (item 1 of the professional-DFIR roadmap).
//
// This file ASSEMBLES a report.Data from stored case data and nothing
// else. It runs no detection and decides nothing about severity: every
// number and sentence it passes on was already computed, and the report
// package that renders it cannot reach the store or the parsers.
//
// # Determinism
//
// buildReport takes the generation time as a parameter and performs no
// writes, so the same case at the same instant yields the same bytes.
// Only the exported entry points below record the issuance in the audit
// trail, AFTER the report is built -- a report therefore lists the
// reports issued before it, never itself.

const (
	reportTitle = "Digital Forensic Analysis Report"

	// Bounds on list sections. Each is DISCLOSED in the report when it
	// cuts anything, and the full data is always in an attachment.
	maxFindingEvents        = 10
	maxKeyEvents            = 300
	maxAuditEntries         = 500
	maxFailedListed         = 100
	maxInvestigationsListed = 50
	maxDetailRunes          = 300
)

// reportBuild is a finished report and everything derived from it.
type reportBuild struct {
	Data         report.Data
	HTML         []byte
	Files        []report.File // attachments, not including the report or manifest
	Manifest     report.Manifest
	ManifestJSON []byte

	// spool is the timeline file written to disk for this build, empty when
	// there is none. The caller removes it once the bundle is written.
	spool string
}

// release removes the spooled timeline, if any. Call it after the bundle is
// written.
func (b reportBuild) release() {
	if b.spool != "" {
		os.Remove(b.spool)
	}
}

// buildReport assembles, renders and hashes the report. Its only write is the
// timeline spool in the case's reports folder, which the caller releases.
func (s *Service) buildReport(caseID string, now time.Time) (reportBuild, error) {
	var spool string
	b, err := s.assembleAndRender(caseID, now, &spool)
	if err != nil {
		if spool != "" {
			os.Remove(spool)
		}
		return reportBuild{}, err
	}
	b.spool = spool
	return b, nil
}

func (s *Service) assembleAndRender(caseID string, now time.Time, spool *string) (reportBuild, error) {
	c, err := s.GetCase(caseID)
	if err != nil {
		return reportBuild{}, err
	}
	collections, err := s.store.ListCollections(caseID)
	if err != nil {
		return reportBuild{}, fmt.Errorf("loading collections: %w", err)
	}
	sourceFiles, err := s.store.ListSourceFiles(caseID)
	if err != nil {
		return reportBuild{}, fmt.Errorf("loading source files: %w", err)
	}
	findings, err := s.store.ListFindings(caseID)
	if err != nil {
		return reportBuild{}, fmt.Errorf("loading findings: %w", err)
	}
	correlations, err := s.store.ListCorrelations(caseID)
	if err != nil {
		return reportBuild{}, fmt.Errorf("loading correlations: %w", err)
	}
	runs, err := s.store.ListAnalysisRuns(caseID)
	if err != nil {
		return reportBuild{}, fmt.Errorf("loading analysis runs: %w", err)
	}
	auditLog, err := s.store.ListAuditLog(caseID)
	if err != nil {
		return reportBuild{}, fmt.Errorf("loading audit log: %w", err)
	}
	statuses, err := s.AnalystStatusIndex(caseID)
	if err != nil {
		return reportBuild{}, fmt.Errorf("loading analyst statuses: %w", err)
	}
	notes, err := s.store.ListNotes(caseID, "", "")
	if err != nil {
		return reportBuild{}, fmt.Errorf("loading notes: %w", err)
	}
	summary, err := s.CaseSummary(caseID)
	if err != nil {
		return reportBuild{}, err
	}

	// The events are not held as a set: the timeline streams past once, and
	// only the events the findings and correlations cite are loaded by id.
	eventTotal, err := s.store.CountEvents(caseID)
	if err != nil {
		return reportBuild{}, fmt.Errorf("counting events: %w", err)
	}
	cited, err := s.store.EventsByIDs(findingEventIDs(findings))
	if err != nil {
		return reportBuild{}, fmt.Errorf("loading cited events: %w", err)
	}
	invs, err := s.caseInvestigations(caseID, findings, correlations)
	if err != nil {
		return reportBuild{}, fmt.Errorf("computing investigations: %w", err)
	}

	// Attachments first: the report prints their hashes. The timeline is the
	// case's whole event list as CSV, so it is spooled to disk rather than held
	// in memory; its digest is computed while it is written.
	tlPath, timeline, tlSHA, tlSize, err := s.spoolTimeline(caseID, s.reportsDir(caseID))
	if err != nil {
		return reportBuild{}, fmt.Errorf("building timeline.csv: %w", err)
	}
	*spool = tlPath
	var fl bytes.Buffer
	if err := writeFindingsCSV(findings, statuses, &fl); err != nil {
		return reportBuild{}, fmt.Errorf("building findings.csv: %w", err)
	}
	files := []report.File{
		report.SpooledFile("timeline.csv", tlPath, tlSHA, tlSize),
		report.NewFile("findings.csv", fl.Bytes()),
	}

	d := s.assembleReportData(reportInputs{
		c: c, now: now, collections: collections, sourceFiles: sourceFiles, events: cited,
		eventTotal: eventTotal, timeline: timeline, invs: invs,
		findings: findings, correlations: correlations, runs: runs, audit: auditLog,
		statuses: statuses, notes: notes, summary: summary,
		timelineCSV: files[0], findingsCSV: files[1],
	})

	html, err := report.Render(d)
	if err != nil {
		return reportBuild{}, err
	}
	m := report.NewManifest(d, "report.html", html, files)
	mj, err := m.JSON()
	if err != nil {
		return reportBuild{}, err
	}
	return reportBuild{Data: d, HTML: html, Files: files, Manifest: m, ManifestJSON: mj}, nil
}

type reportInputs struct {
	c           model.Case
	now         time.Time
	collections []model.Collection
	sourceFiles []model.SourceFile
	// events holds the events the report resolves by id (cited by a finding
	// or a correlation); eventTotal is the whole case, and timeline is the
	// streamed aggregate of all of it.
	events       []model.Event
	eventTotal   int
	timeline     *timelineAgg
	invs         []model.Investigation
	findings     []model.Finding
	correlations []model.Correlation
	runs         []model.AnalysisRun
	audit        []model.AuditEvent
	statuses     map[string]model.AnalystStatus
	notes        []model.Note
	summary      Summary
	timelineCSV  report.File
	findingsCSV  report.File
}

func (s *Service) assembleReportData(in reportInputs) report.Data {
	c := in.c
	srcByID := make(map[string]model.SourceFile, len(in.sourceFiles))
	for _, sf := range in.sourceFiles {
		srcByID[sf.ID] = sf
	}
	evByID := make(map[string]model.Event, len(in.events))
	for _, e := range in.events {
		evByID[e.ID] = e
	}

	d := report.Data{}
	d.Meta = report.Meta{
		Title: reportTitle, CaseID: c.ID, CaseName: c.Name, Description: c.Description,
		CaseStatus: c.CaseStatus, Priority: c.Priority, CreatedAt: reportTime(c.CreatedAt),
		GeneratedAt: reportTime(in.now), GeneratedBy: s.auditActor(),
		ToolName: version.Name, ToolVersion: version.Version,
		TimeBasis: "All timestamps are shown in UTC. Source timestamps without an explicit zone were interpreted as UTC (see section 7).",
	}
	if c.AnalyzedAt != nil {
		d.Meta.AnalyzedAt = reportTime(*c.AnalyzedAt)
	}

	d.Evidence = reportEvidence(in.collections, in.audit)
	s.attachImageInfo(d.Evidence, in.collections)
	s.attachMemoryInfo(d.Evidence, in.collections)
	d.Analysis = reportAnalysis(c, in.summary, in.runs)

	// Findings, ordered most severe first, then by when they began.
	fs := append([]model.Finding(nil), in.findings...)
	sort.SliceStable(fs, func(i, j int) bool {
		if ri, rj := severityRank[fs[i].Severity], severityRank[fs[j].Severity]; ri != rj {
			return ri > rj
		}
		if !fs[i].FirstSeen.Equal(fs[j].FirstSeen) {
			return fs[i].FirstSeen.Before(fs[j].FirstSeen)
		}
		return fs[i].ID < fs[j].ID
	})
	notesByTarget := map[string][]string{}
	for _, n := range in.notes {
		notesByTarget[n.TargetID] = append(notesByTarget[n.TargetID], n.Text)
	}
	cited := map[string]bool{}
	ruleFired := map[string]int{}
	for i, f := range fs {
		d.Findings = append(d.Findings, reportFinding(i+1, f, evByID, srcByID, in.statuses, notesByTarget))
		ruleFired[f.RuleID]++
		for _, id := range f.SupportingEvents {
			cited[id] = true
		}
	}

	d.Investigations = reportInvestigations(in, &d)
	d.Timeline = reportTimeline(in.timeline, in.events, cited, srcByID)
	d.Coverage = reportCoverage(in.sourceFiles)
	d.Rules = reportRules(fs, ruleFired)

	d.Summary = report.Summary{
		Collections: in.summary.Collections, SourceFiles: in.summary.SourceFiles,
		ImportedFiles: in.summary.ImportedSourceFiles, Events: in.summary.Events,
		Findings: in.summary.Findings, Correlations: in.summary.Correlations,
		Investigations: in.summary.Investigations, Techniques: in.summary.TechniqueCount,
	}
	for _, sev := range []string{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow} {
		d.Summary.Severity = append(d.Summary.Severity, report.Count{Name: sev, N: in.summary.SeverityCounts[sev]})
	}

	d.Attachments = []report.Attachment{
		{Name: in.timelineCSV.Name, Description: "Complete normalized timeline, one row per event, UTC.",
			SHA256: in.timelineCSV.SHA256, Bytes: in.timelineCSV.Size, Rows: in.eventTotal},
		{Name: in.findingsCSV.Name, Description: "All findings with analyst review status.",
			SHA256: reportSHA256(in.findingsCSV.Data), Bytes: int64(len(in.findingsCSV.Data)), Rows: len(in.findings)},
	}

	d.Audit, d.AuditOmitted = reportAudit(in.audit)
	d.TimeZones = reportTimeZones(in.collections)
	d.Limitations = reportLimitations(d, in)
	return d
}

// reportTimeZones states, per collection, the host time zone its SYSTEM hive
// recorded, or why none was recorded.
func reportTimeZones(collections []model.Collection) []report.TimeZoneRow {
	rows := make([]report.TimeZoneRow, 0, len(collections))
	for i, c := range collections {
		row := report.TimeZoneRow{Label: fmt.Sprintf("Collection #%d", i+1), Recorded: c.TimeZone.Recorded}
		if c.TimeZone.Recorded {
			row.Basis = timeZoneBasisText(c.TimeZone)
			row.Source = c.TimeZone.Source
		} else {
			row.Reason = c.TimeZone.Reason
		}
		rows = append(rows, row)
	}
	return rows
}

// timeZoneBasisText renders a recorded bias as the usual UTC offset, e.g.
// "UTC+07:00 (SE Asia Standard Time)". UTC = local + bias, so the offset from
// UTC is -bias.
func timeZoneBasisText(tz model.TimeZoneBasis) string {
	off := -tz.ActiveBiasMinutes
	sign := "+"
	if off < 0 {
		sign, off = "-", -off
	}
	text := fmt.Sprintf("UTC%s%02d:%02d", sign, off/60, off%60)
	if tz.KeyName != "" {
		text += " (" + tz.KeyName + ")"
	}
	return text
}

// ---------------------------------------------------------------- pieces

func reportEvidence(collections []model.Collection, audit []model.AuditEvent) []report.Evidence {
	// Latest integrity re-verification per collection, from the audit
	// trail: the trail is where Tracefall records that one happened.
	latest := map[string]model.AuditEvent{}
	for _, a := range audit {
		if a.Action != model.AuditIntegrityVerified || a.TargetID == "" {
			continue
		}
		if prev, ok := latest[a.TargetID]; !ok || a.Timestamp.After(prev.Timestamp) {
			latest[a.TargetID] = a
		}
	}
	out := make([]report.Evidence, 0, len(collections))
	for i, col := range collections {
		integrity := "Not re-verified since ingestion."
		if a, ok := latest[col.ID]; ok {
			integrity = a.Summary + " (" + reportTime(a.Timestamp) + ")"
		}
		out = append(out, report.Evidence{
			Label:        fmt.Sprintf("Collection %d", i+1),
			SourceType:   sourceTypeLabel(col.SourceType),
			OriginalName: reportEvidenceName(col.OriginalFilename),
			SHA256:       col.ArchiveHash,
			SHA512:       col.IntegritySHA512,
			HashKind:     evidenceKindFor(col.SourceType),
			Status:       col.IngestionStatus,
			Files:        col.FileCount, Supported: col.SupportedFileCount, Unsupported: col.UnsupportedFileCount,
			Imported: col.ImportedFileCount, Events: col.ParsedEventCount,
			Integrity: integrity,
		})
	}
	return out
}

// reportEvidenceName is how a collection's original name appears in a
// report. A report is a document that leaves the machine, and for a
// collection ingested from a local path the "original filename" is a
// directory layout on the server. Only the final path element is kept,
// and the report says a path was withheld.
func reportEvidenceName(name string) string {
	norm := strings.ReplaceAll(name, `\`, "/")
	norm = strings.TrimRight(norm, "/")
	if !strings.Contains(norm, "/") {
		return name
	}
	base := norm[strings.LastIndex(norm, "/")+1:]
	if base == "" {
		return "(local path withheld)"
	}
	return base + " (server path withheld)"
}

func sourceTypeLabel(t string) string {
	switch t {
	case model.SourceTypeAD1:
		return "AD1 logical image"
	case model.SourceTypeDiskImage:
		return "Disk image"
	case model.SourceTypeMemoryImage:
		return "Memory image"
	case model.SourceTypeUpload:
		return "KAPE ZIP upload"
	case model.SourceTypeLocalPath:
		return "Local directory"
	case model.SourceTypeLegacy:
		return "Legacy (ingested before collections existed)"
	}
	return t
}

func reportAnalysis(c model.Case, sum Summary, runs []model.AnalysisRun) report.Analysis {
	a := report.Analysis{Current: c.Status == model.CaseStatusAnalyzed && !sum.AnalysisInvalidated}
	switch {
	case sum.AnalysisInvalidated:
		a.Note = "The evidence this analysis was derived from has since been deleted."
	case c.Status != model.CaseStatusAnalyzed && len(runs) == 0 && sum.Collections == 0:
		a.Note = "No evidence has been added to this case, so no analysis has been run."
	case c.Status != model.CaseStatusAnalyzed && len(runs) == 0:
		a.Note = "Analysis has not been run on this case."
	case c.Status != model.CaseStatusAnalyzed:
		a.Note = "Evidence was added or removed after the last analysis."
	}
	for _, r := range runs {
		ri := report.RunInfo{
			ID: r.ID, Started: reportTime(r.StartedAt), Status: r.Status, ToolVersion: r.ToolVersion,
			Events: r.EventCount, Findings: r.FindingCount, Correlations: r.CorrelationCount,
		}
		if r.CompletedAt != nil {
			ri.Completed = reportTime(*r.CompletedAt)
		}
		if r.InvalidatedAt != nil {
			ri.Invalidated = reportTime(*r.InvalidatedAt)
		}
		a.Runs = append(a.Runs, ri)
	}
	sort.SliceStable(a.Runs, func(i, j int) bool { return a.Runs[i].Started < a.Runs[j].Started })
	return a
}

func reportFinding(n int, f model.Finding, evByID map[string]model.Event, srcByID map[string]model.SourceFile,
	statuses map[string]model.AnalystStatus, notes map[string][]string) report.Finding {

	supporting := make([]model.Event, 0, len(f.SupportingEvents))
	for _, id := range f.SupportingEvents {
		if e, ok := evByID[id]; ok {
			supporting = append(supporting, e)
		}
	}
	sortEvents(supporting)

	out := report.Finding{
		Number: fmt.Sprintf("F-%03d", n), ID: f.ID, Title: f.Title, Severity: f.Severity, Confidence: f.Confidence,
		RuleID: f.RuleID, Description: f.Description, FirstSeen: reportTime(f.FirstSeen), LastSeen: reportTime(f.LastSeen),
		ReviewStatus: model.ReviewNew, EventCount: len(f.SupportingEvents), Notes: notes[f.ID],
	}
	if st, ok := statuses[f.ID]; ok {
		out.ReviewStatus, out.ReviewNote = st.Status, st.Note
	}
	for _, t := range attck.Resolve(f.Techniques) {
		out.Techniques = append(out.Techniques, report.Technique{ID: t.ID, Name: t.Name, Tactic: t.Tactic})
	}

	ex := explainFinding(f, supporting)
	out.Escalated = ex.Escalated
	if ex.Rule != nil && ex.Rule.Basis != "" {
		out.Why = append(out.Why, "Rule basis: "+ex.Rule.Basis)
	}
	for _, fac := range ex.Factors {
		out.Why = append(out.Why, fac.Label+": "+fac.Detail)
	}

	shown := supporting
	if len(shown) > maxFindingEvents {
		shown = shown[:maxFindingEvents]
	}
	for _, e := range shown {
		out.Events = append(out.Events, eventRef(e, srcByID))
	}
	// Counted against the finding's own list, not the resolved events:
	// an id that no longer resolves is still part of what it stood on.
	if omitted := len(f.SupportingEvents) - len(out.Events); omitted > 0 {
		out.EventsOmitted = omitted
	}
	return out
}

func reportInvestigations(in reportInputs, d *report.Data) []report.Investigation {
	invs := append([]model.Investigation{}, in.invs...)
	sort.SliceStable(invs, func(i, j int) bool {
		if invs[i].Score != invs[j].Score {
			return invs[i].Score > invs[j].Score
		}
		if !invs[i].StartTime.Equal(invs[j].StartTime) {
			return invs[i].StartTime.Before(invs[j].StartTime)
		}
		return invs[i].ID < invs[j].ID
	})
	omitted := 0
	if len(invs) > maxInvestigationsListed {
		omitted = len(invs) - maxInvestigationsListed
		invs = invs[:maxInvestigationsListed]
	}
	out := make([]report.Investigation, 0, len(invs))
	for _, iv := range invs {
		status := model.ReviewNew
		if st, ok := in.statuses[iv.ID]; ok {
			status = st.Status
		}
		out = append(out, report.Investigation{
			Title: iv.Title, Category: iv.Category, Severity: iv.Severity, Confidence: iv.Confidence,
			Score: iv.Score, Start: reportTime(iv.StartTime), End: reportTime(iv.EndTime),
			Hosts: strings.Join(iv.Hosts, ", "), Users: strings.Join(iv.Users, ", "),
			FindingCount: len(iv.FindingIDs), Summary: iv.Summary, Rationale: iv.ScoreRationale, ReviewStatus: status,
		})
	}
	if omitted > 0 {
		d.Limitations = append(d.Limitations,
			fmt.Sprintf("%d lower-ranked investigation(s) are not listed in section 4.", omitted))
	}
	return out
}

// reportTimeline is the timeline section: the streamed aggregate plus the
// events a finding cites, which are the only events it names.
func reportTimeline(a *timelineAgg, events []model.Event, cited map[string]bool, srcByID map[string]model.SourceFile) report.Timeline {
	var key []model.Event
	for _, e := range events {
		if cited[e.ID] {
			key = append(key, e)
		}
	}
	return timelineFromAgg(a, key, srcByID)
}

func reportCoverage(files []model.SourceFile) report.Coverage {
	triaged := triageAll(files)
	cov := computeCoverage(triaged)
	out := report.Coverage{
		Discovered: cov.Discovered, Supported: cov.Supported, Unsupported: cov.Unsupported,
		Duplicates: cov.Duplicates, Imported: cov.Imported, ParseFailed: cov.ParseFailed,
	}
	for _, b := range cov.ByType {
		note := b.Reason
		if note == "" {
			note = b.Note
		}
		out.ByType = append(out.ByType, report.CoverageRow{
			Type: b.TypeLabel, Family: b.FamilyLabel, Priority: b.Priority, Supported: b.Supported,
			Files: b.Files, Imported: b.ImportedFiles, Note: note,
		})
	}
	var failed []string
	for _, f := range triaged {
		if f.ImportStatus == model.SourceFileFailed {
			failed = append(failed, f.Path)
		}
	}
	sort.Strings(failed)
	if len(failed) > maxFailedListed {
		out.FailedOmitted = len(failed) - maxFailedListed
		failed = failed[:maxFailedListed]
	}
	out.Failed = failed
	return out
}

func reportRules(fs []model.Finding, fired map[string]int) []report.RuleInfo {
	docs := map[string]detect.RuleDoc{}
	for _, rd := range detect.Catalog() {
		docs[rd.ID] = rd
	}
	ids := make([]string, 0, len(fired))
	for id := range fired {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]report.RuleInfo, 0, len(ids))
	for _, id := range ids {
		ri := report.RuleInfo{ID: id, Title: id, Fired: fired[id]}
		if rd, ok := docs[id]; ok {
			ri.Title, ri.Detects, ri.Basis = rd.Title, rd.Detects, rd.Basis
			ri.Base, ri.Max = rd.BaseSeverity, rd.MaxSeverity
			ri.TechList = strings.Join(rd.Techniques, ", ")
		} else {
			ri.Detects = "This build no longer defines this rule; the finding was produced by an earlier version."
		}
		out = append(out, ri)
	}
	return out
}

func reportAudit(audit []model.AuditEvent) ([]report.AuditEntry, int) {
	a := append([]model.AuditEvent(nil), audit...)
	sort.SliceStable(a, func(i, j int) bool {
		if !a[i].Timestamp.Equal(a[j].Timestamp) {
			return a[i].Timestamp.Before(a[j].Timestamp)
		}
		return a[i].ID < a[j].ID
	})
	omitted := 0
	if len(a) > maxAuditEntries {
		omitted = len(a) - maxAuditEntries
		a = a[omitted:]
	}
	out := make([]report.AuditEntry, 0, len(a))
	for _, e := range a {
		out = append(out, report.AuditEntry{Time: reportTime(e.Timestamp), Actor: e.Actor, Action: e.Action, Summary: redactLocalPath(e.Summary)})
	}
	return out, omitted
}

// localPathInSummary matches the quoted path in the audit summary that
// records a local-path discovery.
var localPathInSummary = regexp.MustCompile(`(from local path )"([^"]*)"`)

// redactLocalPath keeps a server directory layout out of a report. Only
// the report's copy is changed; the audit log itself is untouched.
func redactLocalPath(summary string) string {
	return localPathInSummary.ReplaceAllStringFunc(summary, func(m string) string {
		sub := localPathInSummary.FindStringSubmatch(m)
		return sub[1] + `"` + reportEvidenceName(sub[2]) + `"`
	})
}

// reportLimitations states the caveats specific to THIS case's data.
// The fixed ones are in the template.
func reportLimitations(d report.Data, in reportInputs) []string {
	lim := append([]string(nil), d.Limitations...)
	if !d.Analysis.Current {
		lim = append(lim, "The analysis does not necessarily describe the current evidence: "+strings.TrimSpace(d.Analysis.Note))
	}
	for _, tz := range d.TimeZones {
		if !tz.Recorded {
			lim = append(lim, tz.Label+": host time zone not recorded ("+tz.Reason+"). Local-time registry readings in this collection are shown as local readings and are not converted to UTC.")
		}
	}
	if n := d.Coverage.ParseFailed; n > 0 {
		lim = append(lim, fmt.Sprintf("%d supported file(s) failed to parse; the events they would have contributed are absent from this analysis.", n))
	}
	var names []string
	for _, r := range d.Coverage.ByType {
		if !r.Supported && (r.Priority == "critical" || r.Priority == "high") {
			names = append(names, r.Type)
		}
	}
	if len(names) > 0 {
		lim = append(lim, "Present in the evidence but not parsed by this tool, and rated high or critical forensic value: "+
			strings.Join(names, "; ")+". They need to be examined by other means.")
	}
	pending := 0
	for _, sf := range in.sourceFiles {
		if sf.ImportStatus == model.SourceFileDiscovered && sf.Supported {
			pending++
		}
	}
	if pending > 0 {
		lim = append(lim, fmt.Sprintf("%d supported file(s) were cataloged but not imported, so they are not part of this analysis.", pending))
	}
	if d.Timeline.Undated > 0 {
		lim = append(lim, fmt.Sprintf("%d event(s) record no timestamp and are not placed on the timeline.", d.Timeline.Undated))
	}
	notVerified := 0
	for _, e := range d.Evidence {
		if strings.HasPrefix(e.Integrity, "Not re-verified") {
			notVerified++
		}
	}
	if notVerified > 0 {
		lim = append(lim, fmt.Sprintf("%d evidence collection(s) have not been re-verified since ingestion.", notVerified))
	}
	if len(d.Evidence) == 0 {
		lim = append(lim, "No evidence has been added to this case.")
	}
	return lim
}

// ---------------------------------------------------------------- helpers

func reportTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func isDatedEvent(e model.Event) bool { return !e.Timestamp.IsZero() && e.Timestamp.UTC().Year() > 1 }

func sortEvents(evs []model.Event) {
	sort.SliceStable(evs, func(i, j int) bool {
		if !evs[i].Timestamp.Equal(evs[j].Timestamp) {
			return evs[i].Timestamp.Before(evs[j].Timestamp)
		}
		return evs[i].ID < evs[j].ID
	})
}

func eventRef(e model.Event, srcByID map[string]model.SourceFile) report.EventRef {
	ts := "no timestamp"
	if isDatedEvent(e) {
		ts = reportTime(e.Timestamp)
	}
	src := "unknown source"
	if sf, ok := srcByID[e.SourceFileID]; ok {
		src = sf.Path
	}
	return report.EventRef{
		ID: e.ID, Time: ts, Type: e.EventType, Artifact: artifactTypeLabel(e.ArtifactType),
		Summary: eventDetail(e), Source: src, Ref: e.SourceReference,
	}
}

// eventDetail picks the value an examiner would read first for an event.
func eventDetail(e model.Event) string {
	var parts []string
	switch {
	case e.CommandLine != "":
		parts = append(parts, e.CommandLine)
	case e.ProcessPath != "":
		parts = append(parts, e.ProcessPath)
	case e.ProcessName != "":
		parts = append(parts, e.ProcessName)
	case e.FilePath != "":
		parts = append(parts, e.FilePath)
	case e.RegistryPath != "":
		parts = append(parts, e.RegistryPath)
	case e.NetworkDest != "":
		dest := e.NetworkDest
		if e.NetworkDestPort != 0 {
			dest = fmt.Sprintf("%s:%d", dest, e.NetworkDestPort)
		}
		if e.NetworkSource != "" {
			dest = e.NetworkSource + " -> " + dest
		}
		parts = append(parts, dest)
	}
	if e.User != "" {
		parts = append(parts, "user "+e.User)
	}
	if e.Host != "" {
		parts = append(parts, "host "+e.Host)
	}
	if len(parts) == 0 {
		return e.EventType
	}
	return truncateRunes(strings.Join(parts, " | "), maxDetailRunes)
}

func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n]) + "..."
}

func reportSHA256(b []byte) string {
	return report.SHA256Hex(b)
}

// ---------------------------------------------------------------- entry points

// ReportHTML renders the report and records its issuance. It returns the
// document and its SHA-256.
func (s *Service) ReportHTML(caseID string) ([]byte, string, error) {
	b, err := s.buildReport(caseID, time.Now().UTC())
	if err != nil {
		return nil, "", err
	}
	sum := b.Manifest.Report.SHA256
	s.audit(caseID, model.AuditExport, model.TargetCase, caseID,
		fmt.Sprintf("Forensic report issued as HTML (report.html SHA-256 %s)", sum))
	return b.HTML, sum, nil
}

// ReportBundle returns a ZIP of report.html, manifest.json and the CSV
// attachments, built from one consistent read so the manifest matches the
// files by construction.
func (s *Service) ReportBundle(caseID string) ([]byte, report.Manifest, error) {
	now := time.Now().UTC()
	z, manifest, err := s.reportBundleBytes(caseID, now)
	if err != nil {
		return nil, report.Manifest{}, err
	}
	s.audit(caseID, model.AuditExport, model.TargetCase, caseID,
		fmt.Sprintf("Forensic report bundle issued (report.html SHA-256 %s)", manifest.Report.SHA256))
	return z, manifest, nil
}

// ReportPDF prints the report to PDF. It returns report.ErrNoRenderer
// when the server has no browser able to do so; nothing is faked.
func (s *Service) ReportPDF(ctx context.Context, caseID string) ([]byte, error) {
	b, err := s.buildReport(caseID, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	pdf, err := report.RenderPDF(ctx, b.HTML)
	if err != nil {
		return nil, err
	}
	s.audit(caseID, model.AuditExport, model.TargetCase, caseID,
		fmt.Sprintf("Forensic report issued as PDF (rendered from report.html SHA-256 %s; the PDF itself is not byte-reproducible)", b.Manifest.Report.SHA256))
	return pdf, nil
}
