package narrative

import "tracefall/internal/pseudonym"

// ReviewIdentity refuses to teach recognizable credentials or prohibited bodies
// as reversible identities. Redaction is not permission to learn the raw value.
func ReviewIdentity(value string) string {
	if redactReviewValue(value) != value || reviewProhibitedBody.MatchString(value) {
		return ""
	}
	return value
}

// DiscoverReviewNames extracts shape-recognizable identities from allowlisted
// values during the streamed snapshot pass. It does not retain packet prose or
// raw bodies. The caller must cap the accumulated dictionary and fail closed.
func DiscoverReviewNames(values ...string) Names {
	var p *pseudonym.Pseudonymizer
	for _, raw := range values {
		if raw == "" {
			continue
		}
		value := redactReviewValue(raw)
		if reviewProhibitedBody.MatchString(value) {
			continue
		}
		if p == nil {
			p = pseudonym.New()
		}
		p.Apply(value)
	}
	if p == nil {
		return Names{}
	}
	return newNames(p.Entries(), Names{})
}
