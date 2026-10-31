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
	"fmt"
	"sort"
	"strings"

	"tracefall/internal/attck"
	"tracefall/internal/cmdsem"
	"tracefall/internal/model"
)

// MaxEventIDSample bounds Investigation.EventIDs: the sample is the first
// events in time order, and EventCount always gives the full count.
const MaxEventIDSample = 100

// Run groups caseID's findings and correlations into Investigations,
// scored and narrated from events. events/findings/correlations should
// be the case's complete current sets (as store.ListEvents/ListFindings/
// ListCorrelations return them) -- Run itself does no filtering by
// collection or time range; that's a job for the API layer if ever
// needed, not this package.
func Run(caseID string, events []model.Event, findings []model.Finding, correlations []model.Correlation) []model.Investigation {
	each := func(fn func(model.Event) error) error {
		for _, e := range events {
			if err := fn(e); err != nil {
				return err
			}
		}
		return nil
	}
	out, _ := RunStreamed(caseID, each, findings, correlations)
	return out
}

// isChainCorrelation reports whether t is one of the "genuine multi-step
// narrative" correlation types, as opposed to the weaker
// temporal/entity/process_chain types.
func isChainCorrelation(t string) bool {
	return t == model.CorrelationActivityChain || t == model.CorrelationCredentialChain || t == model.CorrelationServiceChain
}

// Contextual chains retain configuration leads, not independent corroboration.
// Their explicit title marker is produced by the correlation builders and
// preserved in stored analysis; historical chains need re-analysis.
func contextualChain(c model.Correlation) bool {
	return isChainCorrelation(c.Type) && strings.HasPrefix(c.Title, "Contextual ")
}

func buildInvestigation(caseID string, g group, acc *groupAcc, findingsByID map[string]model.Finding, correlationsByID map[string]model.Correlation) model.Investigation {
	// Map iteration order is random: the ids are walked in sorted order, and
	// every sort breaks ties by id, so the same case always reads the same.
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
			if isChainCorrelation(c.Type) && !contextualChain(c) && (chainCorr == nil || len(c.EventIDs) > len(chainCorr.EventIDs)) {
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
	primaryHost := acc.primaryHost()
	title := buildTitle(category, chainTitle, acc.processNames, primaryHost)

	// Context-only members remain visible evidence, but do not supply scoring
	// diversity or a causal/ordered narrative. A separately supported member
	// remains genuine corroboration even when also in a contextual chain.
	supported := map[string]bool{}
	for _, f := range groupFindings {
		for _, id := range f.SupportingEvents {
			supported[id] = true
		}
	}
	for _, c := range groupCorrelations {
		if !contextualChain(c) {
			for _, id := range c.EventIDs {
				supported[id] = true
			}
		}
	}
	scoring := newGroupAcc()
	for _, m := range acc.members {
		if supported[m.id] && m.typ != model.EventAntimalwareHistory && m.typ != model.EventWMISnapshot {
			// Defender history is same-producer context, never independent diversity.
			scoring.add(m)
		}
	}
	scoring.finish()

	// -------- score --------
	distinctCollections := sortedUniqueStrings(setKeys(acc.colls))
	distinctArtifacts := sortedUniqueStrings(setKeys(scoring.artifacts))
	scoringCollections := sortedUniqueStrings(setKeys(scoring.colls))
	hasChain := chainCorr != nil
	hasAnyCorr := false
	for _, c := range groupCorrelations {
		if !contextualChain(c) {
			hasAnyCorr = true
		}
	}
	score, scoreRationale := computeScore(scoreInput{
		highestSeverity:  highestSeverity(groupFindings),
		facets:           facets,
		hasChainCorr:     hasChain,
		hasAnyCorr:       hasAnyCorr,
		distinctTactics:  len(tactics),
		distinctArtifact: len(distinctArtifacts),
		distinctCollect:  len(scoringCollections),
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
		distinctCollect:       len(scoringCollections),
	})

	// -------- narrative --------
	summary := buildNarrative(scoring.seq)
	for _, m := range acc.members {
		if supported[m.id] {
			continue
		}
		path := ""
		if m.ev != nil {
			path = m.ev.ProcessPath
			if path == "" {
				path = m.ev.FilePath
			}
		}
		summary += fmt.Sprintf(" Contextual observation: %s record on %s (event %s), path %q; this record alone does not establish execution or ordering relative to the supported activity.", m.typ, m.host, m.id, cmdsem.Redact(path))
	}
	limitations := map[string]bool{}
	for _, c := range groupCorrelations {
		if contextualChain(c) && !limitations[c.Description] && len(limitations) < 2 {
			limitations[c.Description] = true
			summary += " Contextual correlation limitation: " + c.Description
		}
	}
	start, end := acc.bounds()

	findingIDs := make([]string, 0, len(groupFindings))
	for _, f := range groupFindings {
		findingIDs = append(findingIDs, f.ID)
	}
	correlationIDs := make([]string, 0, len(groupCorrelations))
	for _, c := range groupCorrelations {
		correlationIDs = append(correlationIDs, c.ID)
	}
	eventIDs := make([]string, 0, MaxEventIDSample)
	for _, m := range acc.members {
		if len(eventIDs) == MaxEventIDSample {
			break
		}
		eventIDs = append(eventIDs, m.id)
	}

	return model.Investigation{
		ID:                  stableID(caseID, findingIDs),
		CaseID:              caseID,
		Category:            category,
		Title:               title,
		Summary:             summary,
		Severity:            severity,
		Confidence:          confidence,
		StartTime:           start,
		EndTime:             end,
		Hosts:               sortedUniqueStrings(setKeys(acc.hosts)),
		Users:               sortedUniqueStrings(setKeys(acc.users)),
		EventCount:          len(acc.members),
		EventIDs:            eventIDs,
		FindingIDs:          findingIDs,
		CorrelationIDs:      correlationIDs,
		Techniques:          techniqueIDs,
		Tactics:             tactics,
		CollectionIDs:       distinctCollections,
		SourceFileIDs:       sortedUniqueStrings(setKeys(acc.sfs)),
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
