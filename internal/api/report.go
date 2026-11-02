package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"tracefall/internal/attck"
	"tracefall/internal/cmdsem"
	"tracefall/internal/detect"
	"tracefall/internal/model"
	"tracefall/internal/regf"
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

	// spools are owned temporary attachments, released after every consumer.
	spools []string
}

// release removes every temporary attachment. Call it after the last consumer.
func (b reportBuild) release() {
	for _, path := range b.spools {
		os.Remove(path)
	}
}

// buildReport assembles, renders and hashes the report. Its only writes are
// temporary attachments in the case's reports folder, released by the caller.
func (s *Service) buildReport(caseID string, now time.Time) (reportBuild, error) {
	var spools []string
	b, err := s.assembleAndRender(caseID, now, &spools)
	if err != nil {
		(reportBuild{spools: spools}).release()
		return reportBuild{}, err
	}
	b.spools = spools
	return b, nil
}

func (s *Service) assembleAndRender(caseID string, now time.Time, spools *[]string) (reportBuild, error) {
	if err := s.checkpoint("start"); err != nil {
		return reportBuild{}, err
	}
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
	if err := s.checkpoint("loaded"); err != nil {
		return reportBuild{}, err
	}
	citedIDs := findingEventIDs(findings)
	for _, c := range correlations {
		citedIDs = append(citedIDs, c.EventIDs...)
	}
	citedFile, cited, err := s.spoolReportCited(s.opCtx(), caseID, citedIDs, findings, correlations)
	if err != nil {
		return reportBuild{}, fmt.Errorf("building cited-events.json: %w", err)
	}
	*spools = append(*spools, citedFile.Path)
	if err := s.checkpoint("cited"); err != nil {
		return reportBuild{}, err
	}
	invs, err := s.caseInvestigationsCtx(s.opCtx(), caseID, findings, correlations)
	if err != nil {
		return reportBuild{}, fmt.Errorf("computing investigations: %w", err)
	}
	if err := s.checkpoint("investigations"); err != nil {
		return reportBuild{}, err
	}

	// Attachments first: the report prints their hashes. The timeline is the
	// case's whole event list as CSV, so it is spooled to disk rather than held
	// in memory; its digest is computed while it is written.
	tlPath, timeline, tlSHA, tlSize, err := s.spoolTimelineCtx(s.opCtx(), caseID, s.reportsDir(caseID))
	if err != nil {
		return reportBuild{}, fmt.Errorf("building timeline.csv: %w", err)
	}
	*spools = append(*spools, tlPath)
	if err := s.checkpoint("timeline"); err != nil {
		return reportBuild{}, err
	}
	var fl bytes.Buffer
	if err := writeFindingsCSV(findings, statuses, &fl); err != nil {
		return reportBuild{}, fmt.Errorf("building findings.csv: %w", err)
	}
	// Keep every correlation reference in the bundle, even when its evidence
	// table is capped. Sort a copy; never mutate stored data for presentation.
	fullCorrelations := append([]model.Correlation{}, correlations...)
	sort.Slice(fullCorrelations, func(i, j int) bool { return fullCorrelations[i].ID < fullCorrelations[j].ID })
	cj, err := json.MarshalIndent(fullCorrelations, "", "  ")
	if err != nil {
		return reportBuild{}, fmt.Errorf("building correlations.json: %w", err)
	}
	files := []report.File{
		report.SpooledFile("timeline.csv", tlPath, tlSHA, tlSize),
		report.NewFile("findings.csv", fl.Bytes()),
		report.NewFile("correlations.json", cj),
		citedFile,
	}

	if err := s.checkpoint("attachments"); err != nil {
		return reportBuild{}, err
	}
	ext, err := s.reportExternal(caseID)
	if err != nil {
		return reportBuild{}, fmt.Errorf("loading outside-service answers: %w", err)
	}

	d := s.assembleReportData(reportInputs{
		c: c, now: now, collections: collections, sourceFiles: sourceFiles, cited: cited,
		eventTotal: eventTotal, timeline: timeline, invs: invs,
		findings: findings, correlations: correlations, runs: runs, audit: auditLog,
		statuses: statuses, notes: notes, summary: summary,
		timelineCSV: files[0], findingsCSV: files[1], external: ext,
	})

	d.Attachments = append(d.Attachments, report.Attachment{Name: files[2].Name, Description: "All correlations and their complete ordered event-reference lists.", SHA256: files[2].SHA256, Bytes: files[2].Size, Rows: len(correlations)})
	// Preserve the legacy HTML inventory's empty digest/size for this attachment;
	// the bundle manifest carries its actual streamed digest and size. Correcting
	// the presentation inventory is separate from this byte-compatible rewrite.
	d.Attachments = append(d.Attachments, report.Attachment{Name: files[3].Name, Description: "All resolved cited events, with complete normalized fields and record references (sensitive evidence, not redacted).", Rows: cited.rows})
	// the model-drafted summary cites findings by the numbers this report gave them
	d.Narrative, err = s.reportNarrative(caseID, d.Findings, findings)
	if err != nil {
		return reportBuild{}, fmt.Errorf("loading the model-drafted summary: %w", err)
	}
	if err := s.checkpoint("render"); err != nil {
		return reportBuild{}, err
	}
	html, err := report.RenderContext(s.opCtx(), d)
	if err != nil {
		return reportBuild{}, err
	}
	if err := s.checkpoint("rendered"); err != nil {
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
	cited        *reportCited
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
	// external is the outside-services appendix, already assembled.
	external report.External
}

func (s *Service) assembleReportData(in reportInputs) report.Data {
	c := in.c
	srcByID := make(map[string]model.SourceFile, len(in.sourceFiles))
	for _, sf := range in.sourceFiles {
		srcByID[sf.ID] = sf
	}
	evByID := make(map[string]model.Event, len(in.events))
	for _, e := range in.events {
		if e.CaseID != c.ID {
			continue
		}
		evByID[e.ID] = e
	}

	lookup := func(id string) (model.Event, bool) { e, ok := evByID[id]; return e, ok }
	if in.cited != nil {
		lookup = in.cited.lookup
	}
	d := report.Data{}
	d.Meta = report.Meta{
		Title: reportTitle, CaseID: c.ID, CaseName: c.Name, Description: c.Description,
		CaseStatus: c.CaseStatus, Priority: c.Priority, CreatedAt: reportTime(c.CreatedAt),
		GeneratedAt: reportTime(in.now), GeneratedBy: s.auditActor(),
		ToolName: version.Name, ToolVersion: version.Version,
		TimeBasis: "Known instants are displayed in UTC; local readings with an unknown zone and partial dates remain as recorded, without an invented UTC timestamp (see section 8).",
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
		d.Findings = append(d.Findings, reportFinding(i+1, f, lookup, srcByID, in.statuses, notesByTarget))
		ruleFired[f.RuleID]++
		for _, id := range f.SupportingEvents {
			cited[id] = true
		}
	}

	cs := append([]model.Correlation(nil), in.correlations...)
	sort.Slice(cs, func(i, j int) bool {
		if !cs[i].FirstSeen.Equal(cs[j].FirstSeen) {
			return cs[i].FirstSeen.Before(cs[j].FirstSeen)
		}
		return cs[i].ID < cs[j].ID
	})
	for i, c := range cs {
		out := report.Correlation{Number: fmt.Sprintf("C-%03d", i+1), ID: c.ID, Type: c.Type, Title: c.Title, Description: c.Description, FirstSeen: reportTime(c.FirstSeen), LastSeen: reportTime(c.LastSeen), EventCount: len(c.EventIDs)}
		for _, id := range c.EventIDs {
			cited[id] = true
			e, ok := lookup(id)
			if !ok {
				out.MissingEvents++
				continue
			}
			if len(out.Events) < maxFindingEvents {
				out.Events = append(out.Events, eventRef(e, srcByID))
			} else {
				out.EventsOmitted++
			}
		}
		d.Correlations = append(d.Correlations, out)
	}
	d.Investigations = reportInvestigations(in, &d)
	caseEvents := make([]model.Event, 0, len(evByID))
	for _, e := range evByID {
		caseEvents = append(caseEvents, e)
	}
	if in.cited != nil {
		d.Timeline = timelineFromAgg(in.timeline, in.cited.key, srcByID)
		d.Timeline.KeyOmitted = in.cited.keyOmitted
	} else {
		d.Timeline = reportTimeline(in.timeline, caseEvents, cited, srcByID)
	}
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

	d.External = in.external
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

func reportFinding(n int, f model.Finding, lookup func(string) (model.Event, bool), srcByID map[string]model.SourceFile,
	statuses map[string]model.AnalystStatus, notes map[string][]string) report.Finding {

	supporting := make([]model.Event, 0, len(f.SupportingEvents))
	for _, id := range f.SupportingEvents {
		if e, ok := lookup(id); ok {
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
	out.MissingEvents = len(f.SupportingEvents) - len(supporting)
	out.EventsOmitted = len(supporting) - len(out.Events)
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
	companions := 0
	var notExtracted []string
	for _, sf := range files {
		if c := sf.ParseCoverage; c != nil {
			if c.CompanionOf != "" && sf.ArtifactType == model.ArtifactRegistryTransactionLog && !c.Measured() && len(c.Notes) == 0 && c.HiveReplay == nil {
				// Summarised in one line below, outside the capped list.
				companions++
				continue
			}
			summary := "parse coverage: not recorded"
			if c.Measured() {
				summary = fmt.Sprintf("read=%d mapped=%d unmapped=%d undated=%d records_failed=%d chunks_failed=%d capped=%t", c.RecordsRead, c.Mapped, c.Unmapped, c.Undated, c.RecordsFailed, c.ChunksFailed, c.LimitReached)
			}
			if len(c.Notes) > 0 {
				summary += "; " + strings.Join(c.Notes, "; ")
			}
			if ns := c.NtfsSummary(); ns != "" {
				summary += "; " + ns
			} else if model.IsNtfsArtifact(sf.ArtifactType) {
				// Imported before NTFS detail was recorded: unknown, not complete.
				summary += "; NTFS coverage detail: not recorded"
			}
			for _, v := range c.ByEvent {
				summary += fmt.Sprintf("; %s/%s %d: %d read, %d mapped", v.Channel, v.Provider, v.EventID, v.Records, v.Mapped)
			}
			if c.UnlistedRecords > 0 {
				summary += fmt.Sprintf("; %d records beyond the per-ID census limit", c.UnlistedRecords)
			}
			if ts := c.TableSummary(); ts != "" {
				summary += "; table census: " + ts
				if c.DatabaseState != "" {
					summary += "; database state: " + c.DatabaseState
				}
			}
			if hr := c.HiveReplay; hr != nil {
				summary += "; hive transaction logs: " + hr.State
				if hr.State == string(regf.RecoveryClean) && hr.Reason != "" {
					summary += " (" + hr.Reason + ")"
				}
				for _, comp := range hr.Companions {
					summary += fmt.Sprintf("; companion %s %s (%d bytes", comp.Path, comp.Status, comp.SizeBytes)
					if comp.SHA256 != "" {
						summary += ", sha256 " + comp.SHA256
					}
					summary += ")"
					if comp.Status != model.CompanionExtracted {
						notExtracted = append(notExtracted, fmt.Sprintf("%s (%s)", comp.Path, comp.Status))
					}
				}
			} else if sf.ArtifactType == model.ArtifactRegistryHive {
				// Imported before the replay status was recorded: unknown, not clean.
				summary += "; hive transaction logs: not recorded"
			}
			out.ParserDiagnostics = append(out.ParserDiagnostics, report.KV{Key: sf.Path, Value: summary})
		}
	}
	for _, sf := range files {
		if sf.ParseCoverage == nil && sf.ImportStatus == model.SourceFileFailed && model.IsNtfsArtifact(sf.ArtifactType) {
			// The worker died before it could report: still a coverage fact.
			out.ParserDiagnostics = append(out.ParserDiagnostics, report.KV{Key: sf.Path, Value: model.NtfsFailedWithoutDetail})
		}
	}
	sort.Slice(out.ParserDiagnostics, func(i, j int) bool { return out.ParserDiagnostics[i].Key < out.ParserDiagnostics[j].Key })
	if len(out.ParserDiagnostics) > maxFailedListed {
		out.DiagnosticsOmitted = len(out.ParserDiagnostics) - maxFailedListed
		out.ParserDiagnostics = out.ParserDiagnostics[:maxFailedListed]
	}
	if companions > 0 || len(notExtracted) > 0 {
		// One line for all companions, after the cap: they are not evidence of
		// their own and must not crowd out a real diagnostic.
		line := fmt.Sprintf("%d registry transaction logs were extracted with their hives and are not parsed as evidence of their own", companions)
		if len(notExtracted) > 0 {
			sort.Strings(notExtracted)
			const listed = 10
			shown := notExtracted
			if len(shown) > listed {
				shown = shown[:listed]
			}
			line += fmt.Sprintf("; %d not extracted: %s", len(notExtracted), strings.Join(shown, ", "))
			if len(notExtracted) > listed {
				line += fmt.Sprintf(", and %d more (see each hive's row and source details)", len(notExtracted)-listed)
			}
		}
		out.ParserDiagnostics = append(out.ParserDiagnostics, report.KV{Key: "Registry transaction-log companions", Value: line})
	}
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
	hasCapture, hasMemory := false, false
	for _, sf := range in.sourceFiles {
		hasCapture = hasCapture || sf.ArtifactType == model.ArtifactNetworkCapture
		hasMemory = hasMemory || sf.ArtifactType == model.ArtifactMemoryAnalysis
	}
	if hasCapture {
		lim = append(lim, "Network timestamps use the capture clock, not necessarily a participating host's clock. Clock-offset estimates are separate interpretations with uncertainty; they do not rewrite original event timestamps. An HTTP response or RDP connection is not proof of execution or successful authentication.")
	}
	if hasMemory {
		lim = append(lim, "Memory console text is retained history, not proof of command execution. Untimed memory objects are observations at the snapshot clock (when recorded), not creation times. Recovered bytes may be mapped or incomplete; zero pages can be genuine or missing resident pages, and their hashes need not match a file on disk. Static payload indicators are leads, not a malware verdict.")
	}
	for _, c := range d.Correlations {
		if c.MissingEvents > 0 {
			lim = append(lim, fmt.Sprintf("Correlation %s has %d unresolved event reference(s); its evidence is incomplete.", c.ID, c.MissingEvents))
		}
	}
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
	// Records with no mapping are normal (most event kinds in a log are not
	// analysed), so they are summarised in one line. Failed, undated or capped
	// reads are real losses and are listed per file, bounded, with the rest
	// counted.
	const maxCoverageLines = 20
	var problems []string
	unmappedOnly, unmappedRecords := 0, 0
	for _, sf := range in.sourceFiles {
		c := sf.ParseCoverage
		if c == nil && sf.ImportStatus == model.SourceFileFailed && model.IsNtfsArtifact(sf.ArtifactType) {
			problems = append(problems, sf.Path+": "+model.NtfsFailedWithoutDetail)
			continue
		}
		if !c.Incomplete() {
			continue
		}
		// Notes, parser losses and unsupported kinds are independent facts.
		// A harmless allocation note must not hide either loss counters or the
		// case-wide warning that unmapped records are not a benign verdict.
		if c.Unmapped > 0 {
			unmappedOnly++
			unmappedRecords += c.Unmapped
		}
		var details []string
		if len(c.Notes) > 0 {
			details = append(details, strings.Join(c.Notes, "; "))
		}
		if ts := c.TableSummary(); ts != "" {
			details = append(details, "table census: "+ts+" (an uninterpreted table is not evidence of nothing)")
		}
		if ns := c.NtfsSummary(); ns != "" {
			details = append(details, ns)
		}
		if c.Undated > 0 || c.RecordsFailed > 0 || c.ChunksFailed > 0 || c.LimitReached || c.UnlistedRecords > 0 {
			details = append(details, fmt.Sprintf("parser coverage is incomplete; records_failed=%d chunks_failed=%d undated=%d capped=%t unmapped=%d. See source-level parser coverage before drawing conclusions.", c.RecordsFailed, c.ChunksFailed, c.Undated, c.LimitReached, c.Unmapped))
		}
		if len(details) > 0 {
			// Keep one bounded diagnostic entry per source, not per caveat.
			problems = append(problems, sf.Path+": "+strings.Join(details, "; "))
		}
	}
	sort.Strings(problems)
	for i, l := range problems {
		if i == maxCoverageLines {
			lim = append(lim, fmt.Sprintf("%d more source file(s) have incomplete parser coverage; see each file's coverage.", len(problems)-maxCoverageLines))
			break
		}
		lim = append(lim, l)
	}
	if unmappedOnly > 0 {
		lim = append(lim, fmt.Sprintf("%d source file(s) contain %d record(s) of event kinds Tracefall does not map; they remain in the original evidence and in each file's parser coverage census. Unmapped is not the same as benign.", unmappedOnly, unmappedRecords))
	}
	importing := 0
	for _, sf := range in.sourceFiles {
		if sf.ImportStatus == model.SourceFileDiscovered && sf.Supported {
			pending++
		}
		if sf.ImportStatus == model.SourceFileImporting {
			importing++
		}
	}
	if pending > 0 {
		lim = append(lim, fmt.Sprintf("%d supported file(s) were cataloged but not imported, so they are not part of this analysis.", pending))
	}
	if importing > 0 {
		lim = append(lim, fmt.Sprintf("%d source file(s) are still being imported in segments; nothing from them is part of this analysis until the import finishes and is verified.", importing))
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
		Summary: eventDetail(e), Source: src, Ref: e.SourceReference, Details: reportEventDetails(e),
	}
}

// eventDetail picks the value an examiner would read first for an event.
func eventDetail(e model.Event) string {
	var parts []string
	switch {
	case e.CommandLine != "":
		parts = append(parts, cmdsem.Redact(e.CommandLine))
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
	release, err := s.heavyOp()
	if err != nil {
		return nil, "", err
	}
	defer release()
	b, err := s.buildReport(caseID, time.Now().UTC())
	if err != nil {
		return nil, "", err
	}
	// The HTML is already rendered; the spooled timeline is not part of it.
	defer b.release()
	sum := b.Manifest.Report.SHA256
	// Issuance commits at the audit entry: abandoned before it, nothing is
	// recorded; once recorded, the report stands.
	if err := s.checkpoint("pre-issue"); err != nil {
		return nil, "", err
	}
	s.audit(caseID, model.AuditExport, model.TargetCase, caseID,
		fmt.Sprintf("Forensic report issued as HTML (report.html SHA-256 %s)", sum))
	_ = s.checkpoint("issued") // observer only: the issuance above stands
	return b.HTML, sum, nil
}

// ReportPDF prints the report to PDF. It returns report.ErrNoRenderer
// when the server has no browser able to do so; nothing is faked.
func (s *Service) ReportPDF(ctx context.Context, caseID string) ([]byte, error) {
	release, err := s.heavyOp()
	if err != nil {
		return nil, err
	}
	defer release()
	b, err := s.buildReport(caseID, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	defer b.release()
	if err := s.checkpoint("pdf"); err != nil {
		return nil, err
	}
	pdf, err := report.RenderPDF(ctx, b.HTML)
	if err != nil {
		return nil, err
	}
	if err := s.checkpoint("pre-issue"); err != nil {
		return nil, err
	}
	s.audit(caseID, model.AuditExport, model.TargetCase, caseID,
		fmt.Sprintf("Forensic report issued as PDF (rendered from report.html SHA-256 %s; the PDF itself is not byte-reproducible)", b.Manifest.Report.SHA256))
	return pdf, nil
}
