package api

import (
	"sort"

	"tracefall/internal/model"
	"tracefall/internal/version"
)

// Provenance views (Phase 11).
//
// # What was already here
//
// Almost the whole chain. Collection.CaseID, SourceFile.CollectionID,
// Event.SourceFileID/CollectionID/Parser, EventObservation (one per
// collection an event was seen in), Finding.SupportingEvents, and
// Investigation.FindingIDs/EventIDs/CollectionIDs/SourceFileIDs all
// existed before this phase and are REUSED here rather than duplicated.
// This file adds no parallel identifier system; it assembles and
// exposes relationships that were already stored.
//
// # What was missing
//
// The links were queryable one at a time but never presented as a
// chain, so "what evidence is this finding standing on?" took an
// analyst several manual hops. And each hop that did exist resolved a
// source file by scanning every source file in the case -- fine for a
// dozen files, quadratic-feeling on a 7,000-file image.
//
// # Honesty rules
//
// A link that cannot be resolved is reported as missing, never guessed.
// A deleted source file is reported as deleted, not omitted -- evidence
// that WAS there and is now gone is a fact about the case, and hiding
// it would make the provenance view quietly wrong.

// ProvenanceCollection is a collection as a provenance view sees it:
// identity and integrity, without the operational counters.
type ProvenanceCollection struct {
	CollectionID     string `json:"collection_id"`
	SourceType       string `json:"source_type"`
	OriginalFilename string `json:"original_filename,omitempty"`
	// ArchiveSHA256 is the dedup identity; IntegritySHA512 the integrity
	// attestation. Both complete, never truncated -- truncation is a
	// display choice and belongs in the UI, not the API.
	ArchiveSHA256   string `json:"archive_sha256,omitempty"`
	IntegritySHA512 string `json:"integrity_sha512,omitempty"`
	// IntegrityRecorded distinguishes "no digest was captured" (a
	// pre-Phase-10A collection) from a digest that merely wasn't loaded.
	IntegrityRecorded bool `json:"integrity_recorded"`
	// ImportedAt is when Tracefall RECEIVED this evidence. It is
	// deliberately not called an acquisition time: Tracefall did not
	// acquire the evidence and does not know when it was collected from
	// the source machine.
	ImportedAt string `json:"imported_at,omitempty"`
}

func provenanceCollection(c model.Collection) ProvenanceCollection {
	return ProvenanceCollection{
		CollectionID:      c.ID,
		SourceType:        c.SourceType,
		OriginalFilename:  c.OriginalFilename,
		ArchiveSHA256:     c.ArchiveHash,
		IntegritySHA512:   c.IntegritySHA512,
		IntegrityRecorded: c.IntegritySHA512 != "",
		ImportedAt:        c.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
}

// ProvenanceSourceFile is a source file as a provenance view sees it.
type ProvenanceSourceFile struct {
	SourceFileID     string `json:"source_file_id"`
	CollectionID     string `json:"collection_id"`
	OriginalFilename string `json:"original_filename"`
	// Path is the evidence-relative path INSIDE the collection, which is
	// forensically meaningful. It is never a server filesystem path.
	Path         string `json:"path"`
	ArtifactType string `json:"artifact_type,omitempty"`
	Parser       string `json:"parser,omitempty"`
	SHA256       string `json:"sha256,omitempty"`
	ImportStatus string `json:"import_status"`
	ImportedAt   string `json:"imported_at,omitempty"`
	// Deleted marks a source file removed from the case. The row is
	// retained (source files are soft-deleted), so provenance can say
	// "this evidence existed and was deleted" instead of silently
	// dropping the link and implying it never existed.
	Deleted   bool   `json:"deleted"`
	DeletedAt string `json:"deleted_at,omitempty"`
}

func provenanceSourceFile(sf model.SourceFile) ProvenanceSourceFile {
	out := ProvenanceSourceFile{
		SourceFileID:     sf.ID,
		CollectionID:     sf.CollectionID,
		OriginalFilename: sf.OriginalFilename,
		Path:             sf.Path,
		ArtifactType:     sf.ArtifactType,
		Parser:           sf.Parser,
		SHA256:           sf.SHA256,
		ImportStatus:     sf.ImportStatus,
		Deleted:          sf.DeletedAt != nil,
	}
	if sf.ImportedAt != nil {
		out.ImportedAt = sf.ImportedAt.UTC().Format("2006-01-02T15:04:05Z")
	}
	if sf.DeletedAt != nil {
		out.DeletedAt = sf.DeletedAt.UTC().Format("2006-01-02T15:04:05Z")
	}
	return out
}

// FindingProvenance answers "why does this finding exist, and what
// evidence is it standing on?" in one response.
type FindingProvenance struct {
	FindingID string `json:"finding_id"`
	CaseID    string `json:"case_id"`
	RuleID    string `json:"rule_id"`
	Title     string `json:"title"`

	// AnalysisRun is the run that produced this finding, when known.
	// Nil for a finding written before runs were recorded; the UI shows
	// that as legacy rather than inventing a run.
	AnalysisRun          *model.AnalysisRun `json:"analysis_run,omitempty"`
	AnalysisRunAvailable bool               `json:"analysis_run_available"`

	// SupportingEventCount counts the finding's own event references.
	// ResolvedEventCount counts how many of those events still exist --
	// they can differ after evidence deletion, and the difference is
	// itself provenance worth showing.
	SupportingEventCount int `json:"supporting_event_count"`
	ResolvedEventCount   int `json:"resolved_event_count"`

	SourceFiles []ProvenanceSourceFile `json:"source_files"`
	Collections []ProvenanceCollection `json:"collections"`

	// TimestamplessEventCount is how many supporting events come from an
	// artifact that records no time. Surfaced because it changes how the
	// finding's time range should be read.
	TimestamplessEventCount int `json:"timestampless_event_count"`
}

// FindingProvenanceFor assembles a finding's evidence chain.
//
// It loads the case's events, source files and collections ONCE each and
// indexes them, rather than issuing a query per supporting event. On a
// finding with 500 supporting events the naive shape would be 500 event
// lookups plus 500 source-file scans plus 500 collection reads; this is
// three reads and some map lookups.
func (s *Service) FindingProvenanceFor(caseID, findingID string) (FindingProvenance, error) {
	f, err := s.store.GetFinding(findingID)
	if err != nil || f.CaseID != caseID {
		return FindingProvenance{}, ErrFindingNotFound
	}

	events, err := s.store.ListEvents(caseID)
	if err != nil {
		return FindingProvenance{}, err
	}
	eventByID := make(map[string]model.Event, len(events))
	for _, e := range events {
		eventByID[e.ID] = e
	}

	// Source files INCLUDING deleted ones: a finding may still reference
	// an event whose evidence has since been removed, and reporting that
	// honestly is the point.
	sourceFiles, err := s.store.ListSourceFilesIncludingDeleted(caseID)
	if err != nil {
		return FindingProvenance{}, err
	}
	sfByID := make(map[string]model.SourceFile, len(sourceFiles))
	for _, sf := range sourceFiles {
		sfByID[sf.ID] = sf
	}

	collections, err := s.store.ListCollections(caseID)
	if err != nil {
		return FindingProvenance{}, err
	}
	colByID := make(map[string]model.Collection, len(collections))
	for _, c := range collections {
		colByID[c.ID] = c
	}

	out := FindingProvenance{
		FindingID:            findingID,
		CaseID:               caseID,
		RuleID:               f.RuleID,
		Title:                f.Title,
		SupportingEventCount: len(f.SupportingEvents),
	}

	if f.AnalysisRunID != "" {
		if run, err := s.store.GetAnalysisRun(f.AnalysisRunID); err == nil {
			out.AnalysisRun = &run
			out.AnalysisRunAvailable = true
		}
	}

	seenSF := map[string]bool{}
	seenCol := map[string]bool{}
	for _, eid := range f.SupportingEvents {
		ev, ok := eventByID[eid]
		if !ok {
			continue // event no longer exists; counted by the difference above
		}
		out.ResolvedEventCount++
		if ev.Timestamp.IsZero() {
			out.TimestamplessEventCount++
		}
		if sf, ok := sfByID[ev.SourceFileID]; ok && !seenSF[sf.ID] {
			seenSF[sf.ID] = true
			out.SourceFiles = append(out.SourceFiles, provenanceSourceFile(sf))
		}
		if c, ok := colByID[ev.CollectionID]; ok && !seenCol[c.ID] {
			seenCol[c.ID] = true
			out.Collections = append(out.Collections, provenanceCollection(c))
		}
	}

	if out.SourceFiles == nil {
		out.SourceFiles = []ProvenanceSourceFile{}
	}
	if out.Collections == nil {
		out.Collections = []ProvenanceCollection{}
	}
	sort.Slice(out.SourceFiles, func(i, j int) bool { return out.SourceFiles[i].Path < out.SourceFiles[j].Path })
	return out, nil
}

// SourceFileProvenance describes one source file and what it produced.
type SourceFileProvenance struct {
	SourceFile ProvenanceSourceFile  `json:"source_file"`
	Collection *ProvenanceCollection `json:"collection,omitempty"`

	// EventCount and FindingCount are DERIVED by counting real
	// relationships at read time, not read from a stored counter. A
	// stored counter would drift from the truth after evidence deletion
	// or re-analysis; a count taken from the rows cannot.
	EventCount   int `json:"event_count"`
	FindingCount int `json:"finding_count"`
}

// SourceFileProvenanceFor assembles one source file's provenance.
func (s *Service) SourceFileProvenanceFor(caseID, sourceFileID string) (SourceFileProvenance, error) {
	sf, err := s.store.GetSourceFile(sourceFileID)
	if err != nil || sf.CaseID != caseID {
		return SourceFileProvenance{}, ErrSourceFileNotFound
	}

	out := SourceFileProvenance{SourceFile: provenanceSourceFile(sf)}
	if c, err := s.store.GetCollection(sf.CollectionID); err == nil && c.CaseID == caseID {
		pc := provenanceCollection(c)
		out.Collection = &pc
	}

	events, err := s.store.ListEvents(caseID)
	if err != nil {
		return SourceFileProvenance{}, err
	}
	fromThisFile := map[string]bool{}
	for _, e := range events {
		if e.SourceFileID == sourceFileID {
			fromThisFile[e.ID] = true
		}
	}
	out.EventCount = len(fromThisFile)

	findings, err := s.store.ListFindings(caseID)
	if err != nil {
		return SourceFileProvenance{}, err
	}
	for _, f := range findings {
		for _, eid := range f.SupportingEvents {
			if fromThisFile[eid] {
				out.FindingCount++
				break // one finding counts once, however many of its events came from here
			}
		}
	}
	return out, nil
}

// CaseProvenance is the case-level chain-of-custody summary.
type CaseProvenance struct {
	CaseID      string `json:"case_id"`
	CaseName    string `json:"case_name"`
	ToolVersion string `json:"tool_version"`

	Collections []ProvenanceCollection `json:"collections"`

	// Counts describing the case's current state.
	SourceFileCount        int `json:"source_file_count"`
	DeletedSourceFileCount int `json:"deleted_source_file_count"`
	EventCount             int `json:"event_count"`
	FindingCount           int `json:"finding_count"`

	// AnalysisRuns is the case's run history, most recent first.
	// Superseded runs are retained: their findings are gone, but the
	// record that the run happened is chain-of-custody information.
	AnalysisRuns []model.AnalysisRun `json:"analysis_runs"`

	// LegacyFindingCount is how many current findings carry no run id.
	// Reported rather than backfilled.
	LegacyFindingCount int `json:"legacy_finding_count"`
}

// CaseProvenanceFor assembles the case-level view in a fixed number of
// queries, independent of how many collections or findings exist.
func (s *Service) CaseProvenanceFor(caseID string) (CaseProvenance, error) {
	c, err := s.GetCase(caseID)
	if err != nil {
		return CaseProvenance{}, err
	}
	collections, err := s.store.ListCollections(caseID)
	if err != nil {
		return CaseProvenance{}, err
	}
	sourceFiles, err := s.store.ListSourceFilesIncludingDeleted(caseID)
	if err != nil {
		return CaseProvenance{}, err
	}
	events, err := s.store.ListEvents(caseID)
	if err != nil {
		return CaseProvenance{}, err
	}
	findings, err := s.store.ListFindings(caseID)
	if err != nil {
		return CaseProvenance{}, err
	}
	runs, err := s.store.ListAnalysisRuns(caseID)
	if err != nil {
		return CaseProvenance{}, err
	}

	out := CaseProvenance{
		CaseID:       caseID,
		CaseName:     c.Name,
		ToolVersion:  version.String(),
		Collections:  make([]ProvenanceCollection, 0, len(collections)),
		EventCount:   len(events),
		FindingCount: len(findings),
		AnalysisRuns: runs,
	}
	for _, col := range collections {
		out.Collections = append(out.Collections, provenanceCollection(col))
	}
	for _, sf := range sourceFiles {
		if sf.DeletedAt != nil {
			out.DeletedSourceFileCount++
			continue
		}
		out.SourceFileCount++
	}
	for _, f := range findings {
		if f.AnalysisRunID == "" {
			out.LegacyFindingCount++
		}
	}
	return out, nil
}
