package investigate

import (
	"strings"

	"tracefall/internal/model"
)

// stableID derives a deterministic Investigation ID from the case and
// the sorted set of Finding IDs it groups -- NOT a random UUID. Because
// Investigations are computed fresh on every read (see this package's
// doc comment), a random ID would make GET .../investigations/{id}
// unable to find what an earlier GET .../investigations just listed:
// two Run() calls against the same unchanged Findings/Correlations must
// assign the same ID to what is recognizably the same investigation.
// The ID changes only when the investigation's actual finding
// membership changes (evidence added/removed and reanalyzed), which is
// the correct behavior -- it genuinely is a different grouping then. As
// of Phase 6, Finding IDs are themselves stable (model.StableID, see
// internal/detect.Run) rather than random, so an investigation whose
// finding membership is unchanged gets the same ID across a genuine
// re-analysis too, not just across repeated reads of the same analysis.
func stableID(caseID string, findingIDs []string) string {
	return model.StableID("inv", append([]string{caseID}, findingIDs...)...)
}

// splitTactics turns attck.Technique's comma-joined Tactic string (e.g.
// "Persistence, Privilege Escalation") into a list -- the Go-side
// equivalent of app.js's splitTactics, kept in sync by convention since
// both read the same internal/attck data.
func splitTactics(tacticStr string) []string {
	var out []string
	for _, s := range strings.Split(tacticStr, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
