package narrative

// knownReviewKind accepts only the model's structural commentary labels. It
// neither classifies text nor checks the semantic truth of a labelled claim.
func knownReviewKind(kind string) bool {
	switch kind {
	case "observation", "possible_conflict", "hypothesis", "gap", "next_check", "unclassified":
		return true
	}
	return false
}
