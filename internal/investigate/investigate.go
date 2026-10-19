// Package investigate is Tracefall's investigation-assessment layer. It
// sits above internal/detect and internal/correlate, never below or
// beside them: it takes their already-computed, already-persisted output
// (Findings, Correlations) plus the case's Events, and groups,
// categorizes, scores, and narrates them into a small number of
// evidence-backed "investigations" -- the story an analyst would
// otherwise have to reconstruct by hand from a dozen separate findings.
//
// Like detect and correlate, this package is a pure, deterministic
// function of its input: no network calls, no LLM, no randomness, no
// wall-clock dependence in the grouping/scoring/narrative logic itself.
// Running Run twice on the same findings/correlations/events always
// produces the same investigations, in the same order. It never rewrites
// or hides a Finding: every Finding in an analyzed case is referenced by
// exactly one Investigation (see group.go), and the individual
// Findings/Correlations endpoints are completely unaffected by this
// package's existence.
//
// Investigations are never persisted (see internal/api/service.go's
// Investigations method, which calls Run at read time against whatever
// Findings/Correlations are currently stored) -- deleting evidence and
// re-running analysis can therefore never leave a stale investigation
// behind: the next GET simply recomputes from the current
// Findings/Correlations, which AnalyzeCase keeps authoritative via
// store.ReplaceAnalysis (one atomic transaction -- see that method's
// doc comment for why the earlier separate-calls approach was a
// correctness gap Phase 6 fixed).
package investigate

import (
	"sort"

	"tracefall/internal/attck"
	"tracefall/internal/model"
)

// Run groups caseID's findings and correlations into Investigations,
// scored and narrated from events. events/findings/correlations should
// be the case's complete current sets (as store.ListEvents/ListFindings/
// ListCorrelations return them) -- Run itself does no filtering by
// collection or time range; that's a job for the API layer if ever
// needed, not this package.
func Run(caseID string, events []model.Event, findings []model.Finding, correlations []model.Correlation) []model.Investigation {
	eventsByID := make(map[string]model.Event, len(events))
	for _, e := range events {
		eventsByID[e.ID] = e
	}
	findingsByID := make(map[string]model.Finding, len(findings))
	for _, f := range findings {
		findingsByID[f.ID] = f
	}
	correlationsByID := make(map[string]model.Correlation, len(correlations))
	for _, c := range correlations {
		correlationsByID[c.ID] = c
	}

	groups := buildGroups(findings, correlations)

	out := make([]model.Investigation, 0, len(groups))
	for _, g := range groups {
		inv := buildInvestigation(caseID, g, eventsByID, findingsByID, correlationsByID)
		out = append(out, inv)
	}

	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].StartTime.Equal(out[j].StartTime) {
			return out[i].StartTime.Before(out[j].StartTime)
		}
		return out[i].Title < out[j].Title
	})
	return out
}

// isChainCorrelation reports whether t is one of the "genuine multi-step
// narrative" correlation types, as opposed to the weaker
// temporal/entity/process_chain types.
func isChainCorrelation(t string) bool {
	return t == model.CorrelationActivityChain || t == model.CorrelationCredentialChain || t == model.CorrelationServiceChain
}

func buildInvestigation(caseID string, g group, eventsByID map[string]model.Event, findingsByID map[string]model.Finding, correlationsByID map[string]model.Correlation) model.Investigation {
	var groupEvents []model.Event
	// Map iteration order is random: the ids are walked in sorted order, and
	// every sort breaks ties by id, so the same case always reads the same.
	for _, id := range sortedKeys(g.eventIDs) {
		if e, ok := eventsByID[id]; ok {
			groupEvents = append(groupEvents, e)
		}
	}
	sort.SliceStable(groupEvents, func(i, j int) bool {
		if !groupEvents[i].Timestamp.Equal(groupEvents[j].Timestamp) {
			return groupEvents[i].Timestamp.Before(groupEvents[j].Timestamp)
		}
		return groupEvents[i].ID < groupEvents[j].ID
	})

	var groupFindings []model.Finding
	var ruleIDs []string
	for _, id := range sortedKeys(g.findingIDs) {
		if f, ok := findingsByID[id]; ok {
			groupFindings = append(groupFindings, f)
			ruleIDs = append(ruleIDs, f.RuleID)
		}
	}
	sort.SliceStable(groupFindings, func(i, j int) bool {
		if !groupFindings[i].FirstSeen.Equal(groupFindings[j].FirstSeen) {
			return groupFindings[i].FirstSeen.Before(groupFindings[j].FirstSeen)
		}
		return groupFindings[i].ID < groupFindings[j].ID
	})

	var groupCorrelations []model.Correlation
	var chainCorr *model.Correlation
	for _, id := range sortedKeys(g.correlationIDs) {
		if c, ok := correlationsByID[id]; ok {
			groupCorrelations = append(groupCorrelations, c)
			if isChainCorrelation(c.Type) && (chainCorr == nil || len(c.EventIDs) > len(chainCorr.EventIDs)) {
				cCopy := c
				chainCorr = &cCopy
			}
		}
	}
	sort.SliceStable(groupCorrelations, func(i, j int) bool {
		if !groupCorrelations[i].FirstSeen.Equal(groupCorrelations[j].FirstSeen) {
			return groupCorrelations[i].FirstSeen.Before(groupCorrelations[j].FirstSeen)
		}
		return groupCorrelations[i].ID < groupCorrelations[j].ID
	})

	// -------- descriptive fields (never used for grouping, only display) --------
	var hosts, users, collectionIDs, sourceFileIDs, artifactTypes []string
	var processNames []string
	lastProcess := ""
	for _, e := range groupEvents {
		hosts = append(hosts, e.Host)
		users = append(users, e.User)
		collectionIDs = append(collectionIDs, e.CollectionID)
		sourceFileIDs = append(sourceFileIDs, e.SourceFileID)
		artifactTypes = append(artifactTypes, e.ArtifactType)
		if e.EventType == model.EventProcessCreate && e.ProcessName != "" && e.ProcessName != lastProcess {
			processNames = append(processNames, e.ProcessName)
			lastProcess = e.ProcessName
		}
	}
	if len(processNames) > 3 {
		processNames = processNames[:3]
	}

	// -------- ATT&CK: techniques (from findings) and their resolved tactics --------
	var techniqueIDs []string
	for _, f := range groupFindings {
		techniqueIDs = append(techniqueIDs, f.Techniques...)
	}
	techniqueIDs = sortedUniqueStrings(techniqueIDs)
	tactics := tacticsForTechniques(techniqueIDs)

	// -------- category + title --------
	facets := facetsFor(ruleIDs)
	category := categorize(facets)
	chainTitle := ""
	if chainCorr != nil {
		chainTitle = chainCorr.Title
	}
	primaryHost := ""
	if len(groupEvents) > 0 {
		primaryHost = groupEvents[0].Host
	}
	title := buildTitle(category, chainTitle, processNames, primaryHost)

	// -------- score --------
	distinctCollections := sortedUniqueStrings(collectionIDs)
	distinctArtifacts := sortedUniqueStrings(artifactTypes)
	hasChain := chainCorr != nil
	hasAnyCorr := len(groupCorrelations) > 0
	score, scoreRationale := computeScore(scoreInput{
		highestSeverity:  highestSeverity(groupFindings),
		facets:           facets,
		hasChainCorr:     hasChain,
		hasAnyCorr:       hasAnyCorr,
		distinctTactics:  len(tactics),
		distinctArtifact: len(distinctArtifacts),
		distinctCollect:  len(distinctCollections),
	})
	severity := severityForScore(score)

	// -------- confidence (independent of severity/score) --------
	bestFindingConf := model.ConfidenceLow
	for _, f := range groupFindings {
		if confidenceRank[f.Confidence] > confidenceRank[bestFindingConf] {
			bestFindingConf = f.Confidence
		}
	}
	confidence, confRationale := computeConfidence(confidenceInput{
		bestFindingConfidence: bestFindingConf,
		findingCount:          len(groupFindings),
		hasChainCorr:          hasChain,
		hasAnyCorr:            hasAnyCorr,
		distinctArtifact:      len(distinctArtifacts),
		distinctCollect:       len(distinctCollections),
	})

	// -------- narrative --------
	summary := buildNarrative(groupEvents)

	var start, end model.Event
	if len(groupEvents) > 0 {
		start, end = groupEvents[0], groupEvents[len(groupEvents)-1]
	}

	findingIDs := make([]string, 0, len(groupFindings))
	for _, f := range groupFindings {
		findingIDs = append(findingIDs, f.ID)
	}
	correlationIDs := make([]string, 0, len(groupCorrelations))
	for _, c := range groupCorrelations {
		correlationIDs = append(correlationIDs, c.ID)
	}
	eventIDs := make([]string, 0, len(groupEvents))
	for _, e := range groupEvents {
		eventIDs = append(eventIDs, e.ID)
	}

	return model.Investigation{
		ID:                  stableID(caseID, findingIDs),
		CaseID:              caseID,
		Category:            category,
		Title:               title,
		Summary:             summary,
		Severity:            severity,
		Confidence:          confidence,
		StartTime:           start.Timestamp,
		EndTime:             end.Timestamp,
		Hosts:               sortedUniqueStrings(hosts),
		Users:               sortedUniqueStrings(users),
		EventIDs:            eventIDs,
		FindingIDs:          findingIDs,
		CorrelationIDs:      correlationIDs,
		Techniques:          techniqueIDs,
		Tactics:             tactics,
		CollectionIDs:       distinctCollections,
		SourceFileIDs:       sortedUniqueStrings(sourceFileIDs),
		Score:               score,
		ScoreRationale:      scoreRationale,
		ConfidenceRationale: confRationale,
	}
}

// tacticsForTechniques resolves technique IDs to their full metadata via
// internal/attck (the single source of truth for technique->tactic
// mapping -- see that package's doc comment) and returns the sorted,
// deduplicated union of tactics, splitting each technique's possibly
// comma-joined Tactic string (a technique can span more than one MITRE
// tactic) exactly as the dashboard's splitTactics already does
// client-side for the existing ATT&CK tab.
func tacticsForTechniques(techniqueIDs []string) []string {
	var tactics []string
	for _, t := range attck.Resolve(techniqueIDs) {
		tactics = append(tactics, splitTactics(t.Tactic)...)
	}
	return sortedUniqueStrings(tactics)
}

// sortedKeys returns a map's keys in ascending order, so a walk over the set
// is the same on every run.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
