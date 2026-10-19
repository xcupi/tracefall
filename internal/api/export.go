// Phase 6 export functionality: Case JSON, Investigation JSON, Timeline
// CSV, Findings CSV. Every export is read-only and deterministic (same
// underlying data always serializes the same way -- CSV rows in the same
// store-query order the rest of the API already uses, JSON field order
// fixed by the Go struct). No raw binary evidence and no secrets are
// ever included -- exports serialize the same normalized
// Event/Finding/Correlation/Investigation/Note/Tag/AuditEvent records
// the rest of the API already returns, nothing from disk.
package api

import (
	"encoding/csv"
	"fmt"
	"io"
	"time"

	"tracefall/internal/investigate"
	"tracefall/internal/model"
	"tracefall/internal/version"
)

// CaseExport is the full Case JSON export (Phase 6 section 13.1) --
// deliberately does NOT include the case's raw event timeline (that's
// Timeline CSV export's job; a case's event count can be large, and
// duplicating it here would make this export unnecessarily heavy) or
// raw evidence content.
type CaseExport struct {
	Case             model.Case            `json:"case"`
	Collections      []model.Collection    `json:"collections"`
	SourceFiles      []model.SourceFile    `json:"source_files"`
	Findings         []model.Finding       `json:"findings"`
	Correlations     []model.Correlation   `json:"correlations"`
	Investigations   []model.Investigation `json:"investigations"`
	AttackTechniques []AttackTechnique     `json:"attack_techniques"`
	AnalystStatuses  []model.AnalystStatus `json:"analyst_statuses"`
	Notes            []model.Note          `json:"notes"`
	Tags             []model.Tag           `json:"tags"`
	AuditLog         []model.AuditEvent    `json:"audit_log"`
	ExportedAt       time.Time             `json:"exported_at"`

	// Provenance (Phase 11) is ADDITIVE: every field above keeps its
	// name, type and position, so an existing consumer of this export is
	// unaffected. It records what produced the export and from what
	// state, which the export could previously only imply.
	//
	// The evidence hashes are not repeated here -- Collections above
	// already carries archive_hash and integrity_sha512 for every
	// collection, and duplicating them would create two copies that could
	// disagree.
	ToolVersion string `json:"tool_version"`
	// AnalysisRuns is the case's run history. Findings carry
	// analysis_run_id, so a reader can attribute each finding to the run
	// that produced it -- or see that it predates run tracking.
	AnalysisRuns []model.AnalysisRun `json:"analysis_runs"`
}

// ExportCase assembles the full Case JSON export.
func (s *Service) ExportCase(caseID string) (CaseExport, error) {
	c, err := s.GetCase(caseID)
	if err != nil {
		return CaseExport{}, err
	}
	collections, err := s.store.ListCollections(caseID)
	if err != nil {
		return CaseExport{}, fmt.Errorf("loading collections: %w", err)
	}
	sourceFiles, err := s.store.ListSourceFiles(caseID)
	if err != nil {
		return CaseExport{}, fmt.Errorf("loading source files: %w", err)
	}
	findings, err := s.store.ListFindings(caseID)
	if err != nil {
		return CaseExport{}, fmt.Errorf("loading findings: %w", err)
	}
	correlations, err := s.store.ListCorrelations(caseID)
	if err != nil {
		return CaseExport{}, fmt.Errorf("loading correlations: %w", err)
	}
	events, err := s.store.ListEvents(caseID)
	if err != nil {
		return CaseExport{}, fmt.Errorf("loading events: %w", err)
	}
	investigations := investigate.Run(caseID, events, findings, correlations)
	attackTechniques, err := s.AttackSummary(caseID)
	if err != nil {
		return CaseExport{}, fmt.Errorf("loading ATT&CK summary: %w", err)
	}
	analystStatuses, err := s.store.ListAnalystStatusForCase(caseID)
	if err != nil {
		return CaseExport{}, fmt.Errorf("loading analyst statuses: %w", err)
	}
	notes, err := s.store.ListNotes(caseID, "", "")
	if err != nil {
		return CaseExport{}, fmt.Errorf("loading notes: %w", err)
	}
	tags, err := s.store.ListTags(caseID, "", "")
	if err != nil {
		return CaseExport{}, fmt.Errorf("loading tags: %w", err)
	}
	auditLog, err := s.store.ListAuditLog(caseID)
	if err != nil {
		return CaseExport{}, fmt.Errorf("loading audit log: %w", err)
	}

	// Best-effort, like the audit write below: an export must not fail
	// because its run history could not be read. An empty list is the
	// honest representation of "no runs recorded".
	runs, err := s.store.ListAnalysisRuns(caseID)
	if err != nil {
		runs = []model.AnalysisRun{}
	}

	s.audit(caseID, model.AuditExport, model.TargetCase, caseID, "Case exported as JSON")
	return CaseExport{
		ToolVersion:      version.String(),
		AnalysisRuns:     runs,
		Case:             c,
		Collections:      collections,
		SourceFiles:      sourceFiles,
		Findings:         findings,
		Correlations:     correlations,
		Investigations:   investigations,
		AttackTechniques: attackTechniques,
		AnalystStatuses:  analystStatuses,
		Notes:            notes,
		Tags:             tags,
		AuditLog:         auditLog,
		ExportedAt:       time.Now().UTC(),
	}, nil
}

// ExportInvestigation returns one investigation's full detail for export
// -- identical shape to GET .../investigations/{id} (InvestigationDetail
// already resolves every reference inline), reused rather than
// duplicated.
func (s *Service) ExportInvestigation(caseID, investigationID string) (InvestigationDetail, error) {
	detail, err := s.Investigation(caseID, investigationID)
	if err != nil {
		return InvestigationDetail{}, err
	}
	s.audit(caseID, model.AuditExport, model.TargetInvestigation, investigationID, "Investigation exported as JSON")
	return detail, nil
}

// timelineCSVHeader/findingsCSVHeader are each export's fixed column
// order -- part of what makes the export deterministic; never reordered
// based on which fields happen to be non-empty for a given row.
var timelineCSVHeader = []string{
	"timestamp_utc", "event_type", "host", "user", "process_name", "process_path",
	"parent_process", "pid", "ppid", "command_line", "file_path", "registry_path",
	"network_source", "network_dest", "network_dest_port", "artifact_type",
	"collection_id", "source_file_id", "parser", "event_id",
}

// ExportTimelineCSV writes the case's full unified timeline as CSV to w.
func (s *Service) ExportTimelineCSV(caseID string, w io.Writer) error {
	tw, err := newTimelineCSVWriter(w)
	if err != nil {
		return err
	}
	n := 0
	err = s.store.ForEachEvent(caseID, func(e model.Event) error {
		n++
		return tw.add(e)
	})
	if err != nil {
		return fmt.Errorf("loading events: %w", err)
	}
	if err := tw.close(); err != nil {
		return err
	}
	s.audit(caseID, model.AuditExport, model.TargetCase, caseID, fmt.Sprintf("Timeline exported as CSV (%d events)", n))
	return nil
}

// writeTimelineCSV is the one place the timeline CSV is produced. The
// forensic report attaches a timeline.csv and records its hash, so the
// file in a report bundle and the file from the export endpoint must be
// the same bytes by construction rather than by two copies agreeing.
func writeTimelineCSV(events []model.Event, w io.Writer) error {
	tw, err := newTimelineCSVWriter(w)
	if err != nil {
		return err
	}
	for _, e := range events {
		if err := tw.add(e); err != nil {
			return err
		}
	}
	return tw.close()
}

// timelineCSVWriter writes the timeline one event at a time, so a case's
// timeline never has to be held in memory to be written.
type timelineCSVWriter struct{ cw *csv.Writer }

func newTimelineCSVWriter(w io.Writer) (*timelineCSVWriter, error) {
	cw := csv.NewWriter(w)
	if err := cw.Write(timelineCSVHeader); err != nil {
		return nil, err
	}
	return &timelineCSVWriter{cw: cw}, nil
}

func (t *timelineCSVWriter) add(e model.Event) error {
	row := []string{
		e.Timestamp.UTC().Format(time.RFC3339Nano), e.EventType, e.Host, e.User, e.ProcessName, e.ProcessPath,
		e.ParentProcessName, fmt.Sprint(e.PID), fmt.Sprint(e.PPID), e.CommandLine, e.FilePath, e.RegistryPath,
		e.NetworkSource, e.NetworkDest, fmt.Sprint(e.NetworkDestPort), e.ArtifactType,
		e.CollectionID, e.SourceFileID, e.Parser, fmt.Sprint(e.EventID),
	}
	return t.cw.Write(csvSafeRow(row))
}

func (t *timelineCSVWriter) close() error {
	t.cw.Flush()
	return t.cw.Error()
}

var findingsCSVHeader = []string{
	"finding_id", "rule_id", "title", "severity", "confidence", "description",
	"attack_techniques", "first_seen_utc", "last_seen_utc", "supporting_event_count",
	"analyst_status", "analyst_note",
}

// ExportFindingsCSV writes the case's findings as CSV to w, one row per
// finding, each enriched with its current analyst review status (see
// model.AnalystStatus) if one has been set -- "new" and empty note
// otherwise, never blank/absent, so the export is self-describing
// without a second lookup.
func (s *Service) ExportFindingsCSV(caseID string, w io.Writer) error {
	findings, err := s.store.ListFindings(caseID)
	if err != nil {
		return fmt.Errorf("loading findings: %w", err)
	}
	statusIdx, err := s.AnalystStatusIndex(caseID)
	if err != nil {
		return fmt.Errorf("loading analyst statuses: %w", err)
	}
	if err := writeFindingsCSV(findings, statusIdx, w); err != nil {
		return err
	}
	s.audit(caseID, model.AuditExport, model.TargetCase, caseID, fmt.Sprintf("Findings exported as CSV (%d findings)", len(findings)))
	return nil
}

// writeFindingsCSV is the shared writer behind ExportFindingsCSV and the
// report bundle's findings.csv. See writeTimelineCSV.
func writeFindingsCSV(findings []model.Finding, statusIdx map[string]model.AnalystStatus, w io.Writer) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(findingsCSVHeader); err != nil {
		return err
	}
	for _, f := range findings {
		status, note := model.ReviewNew, ""
		if a, ok := statusIdx[f.ID]; ok {
			status, note = a.Status, a.Note
		}
		row := []string{
			f.ID, f.RuleID, f.Title, f.Severity, f.Confidence, f.Description,
			joinStrings(f.Techniques), f.FirstSeen.UTC().Format(time.RFC3339Nano), f.LastSeen.UTC().Format(time.RFC3339Nano),
			fmt.Sprint(len(f.SupportingEvents)), status, note,
		}
		if err := cw.Write(csvSafeRow(row)); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// csvSafeRow neutralises spreadsheet formula injection. Evidence fields (file
// names, command lines, registry values, page titles) are attacker-controlled,
// and an examiner who opens the export in Excel or LibreOffice would execute a
// cell beginning with = + - @ or a tab/CR. Prefixing a single quote makes the
// spreadsheet treat the cell as text. The same writers feed the report bundle,
// so the manifest hash still matches the bytes examiners download.
func csvSafeRow(row []string) []string {
	out := make([]string, len(row))
	for i, cell := range row {
		if cell != "" {
			switch cell[0] {
			case '=', '+', '-', '@', '	', '\r':
				cell = "'" + cell
			}
		}
		out[i] = cell
	}
	return out
}

func joinStrings(vals []string) string {
	out := ""
	for i, v := range vals {
		if i > 0 {
			out += "; "
		}
		out += v
	}
	return out
}
