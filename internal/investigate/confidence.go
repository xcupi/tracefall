package investigate

import (
	"fmt"

	"tracefall/internal/model"
)

// confidenceRank maps model.Confidence* to a 1-3 scale for arithmetic.
var confidenceRank = map[string]int{model.ConfidenceLow: 1, model.ConfidenceMedium: 2, model.ConfidenceHigh: 3}

// confidenceInput bundles what computeConfidence needs -- deliberately
// disjoint from scoreInput/severity: confidence must never be derived
// from the risk score or from Severity (see this package's doc comment
// and the task's explicit "confidence should depend on evidence quality
// and correlation strength, not severity").
type confidenceInput struct {
	bestFindingConfidence string // the highest Finding.Confidence among the group's findings
	findingCount          int
	hasChainCorr          bool
	hasAnyCorr            bool
	distinctArtifact      int
	distinctCollect       int
}

// computeConfidence scores evidence QUALITY and CORROBORATION STRENGTH,
// entirely independent of how severe the finding looks:
//
//   - Start from the group's own best-reported Finding.Confidence (1-3).
//   - +2 if a genuine multi-step chain correlation (activity/credential/
//     service chain) backs the group, +1 for any weaker correlation
//     (entity/process-chain -- temporal never reaches here, see
//     group.go's mergeworthy) instead.
//   - +1 if the group is corroborated by 2+ independent artifact types
//     (e.g. a process-create AND a Prefetch record for the same
//     execution) -- the same cross-source corroboration principle
//     internal/correlate's entity correlation already uses.
//   - +1 if the group's evidence spans 2+ evidence collections
//     independently (never merely because the same duplicate artifact
//     was re-observed twice -- see score.go's identical caveat).
//
// A single finding with nothing else backing it therefore lands at
// MEDIUM at best (a HIGH-confidence finding alone: 3, no corroboration,
// combined=3 -> MEDIUM) -- exactly the worked example from the task spec
// ("a suspicious PowerShell command may be Severity HIGH, Confidence
// MEDIUM"), while a rich, chain-correlated, multi-artifact investigation
// reaches HIGH.
func computeConfidence(in confidenceInput) (string, string) {
	combined := confidenceRank[in.bestFindingConfidence]
	var parts []string
	parts = append(parts, fmt.Sprintf("best supporting finding confidence: %s", in.bestFindingConfidence))

	switch {
	case in.hasChainCorr:
		combined += 2
		parts = append(parts, "backed by a multi-step activity/credential/service chain")
	case in.hasAnyCorr:
		combined += 1
		parts = append(parts, "backed by an entity/process-chain correlation")
	}

	if in.distinctArtifact >= 2 {
		combined += 1
		parts = append(parts, fmt.Sprintf("corroborated by %d independent artifact types", in.distinctArtifact))
	}

	if in.distinctCollect >= 2 {
		combined += 1
		parts = append(parts, fmt.Sprintf("independently observed across %d evidence collections", in.distinctCollect))
	}

	var confidence string
	switch {
	case combined >= 5:
		confidence = model.ConfidenceHigh
	case combined >= 2:
		confidence = model.ConfidenceMedium
	default:
		confidence = model.ConfidenceLow
	}

	rationale := fmt.Sprintf("Confidence %s: %s.", confidence, joinComma(parts))
	return confidence, rationale
}

func joinComma(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += "; "
		}
		out += p
	}
	return out
}
