package narrative

import (
	"net/url"
	"regexp"
	"strings"

	"tracefall/internal/cmdsem"
	"tracefall/internal/pseudonym"
)

// Review has a richer contract than legacy Summary. Keep its preparation here
// rather than silently changing Summary's allowed text or output contract.
// ReviewPrivacyContract versions the preparation contract, not case egress.
// Bumping it invalidates preview acknowledgements even if the text is unchanged.
const ReviewPrivacyContract = "parsed-review-privacy-v2"

// ReviewPrivacy describes a local check. It never grants transmission permission
// and is intentionally kept outside the model's system/user evidence packet.
type ReviewPrivacy struct {
	Contract                   string `json:"contract"`
	Status                     string `json:"status"`
	PayloadBytes               int    `json:"payload_bytes"`
	RequiresSeparatePermission bool   `json:"requires_separate_permission"`
}

const reviewCredentialKeys = `(?:access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?(?:token|id)|sessionid|aws[_-](?:access[_-]key[_-]id|secret[_-]access[_-]key|session[_-]token)|client[_-]secret|private[_-]key)`

var reviewCredentialAssignment = regexp.MustCompile(`(?i)(\b` + reviewCredentialKeys + `\b["']?\s*[=:]\s*)("[^"]*"|'[^']*'|\S+)`)
var reviewCredentialFlag = regexp.MustCompile(`(?i)((?:--?|/)` + reviewCredentialKeys + `(?:[=:]|\s+))("[^"]*"|'[^']*'|\S+)`)

func redactReviewValue(value string) string {
	// Query strings and fragments can hold credentials under arbitrary key names.
	// Remove URLs' sensitive components before assignment masking can consume a
	// closing quote or a following URL, and before pseudonymization/truncation.
	// Malformed URLs fail closed for this value; never retain raw parse errors.
	value = cmdsem.MapURLs(value, func(raw string) string {
		// Remove authority userinfo before parsing: redaction markers themselves
		// are not necessarily valid URL userinfo and must never become entities.
		start := strings.Index(raw, "://") + 3
		end := len(raw)
		if i := strings.IndexAny(raw[start:], "/?#"); i >= 0 {
			end = start + i
		}
		if at := strings.LastIndexByte(raw[start:end], '@'); at >= 0 {
			raw = raw[:start] + raw[start+at+1:]
		}
		u, err := url.Parse(raw)
		if err != nil {
			return pseudonym.Redacted
		}
		u.User = nil
		u.RawQuery = ""
		u.ForceQuery = false
		u.Fragment = ""
		u.RawFragment = ""
		return u.String()
	})
	value = cmdsem.Redact(value)
	value = reviewCredentialAssignment.ReplaceAllString(value, "${1}"+pseudonym.Redacted)
	return reviewCredentialFlag.ReplaceAllString(value, "${1}"+pseudonym.Redacted)
}
