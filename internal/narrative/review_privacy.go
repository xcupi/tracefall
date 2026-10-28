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
const ReviewPrivacyContract = "parsed-review-privacy-v3"

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

func reviewCommandURLsCertain(command string) bool {
	if !cmdsem.URLBoundariesCertain(command) {
		return false
	}
	certain := true
	cmdsem.MapURLs(command, func(raw string) string {
		if _, ok := reviewURL(raw); !ok {
			certain = false
		}
		return raw
	})
	return certain
}

// Remove authority userinfo before parsing: existing redaction markers are not
// valid URL userinfo. Never retain a parser error or a malformed URL suffix.
func reviewURL(raw string) (string, bool) {
	start := strings.Index(raw, "://") + 3
	end := len(raw)
	if i := strings.IndexAny(raw[start:], "/?#"); i >= 0 {
		end = start + i
	}
	if at := strings.LastIndexByte(raw[start:end], '@'); at >= 0 {
		raw = raw[:start] + raw[start+at+1:]
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", false
	}
	u.User = nil
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	u.RawFragment = ""
	return u.String(), true
}

func redactReviewValue(value string) string {
	// Query strings and fragments can hold credentials under arbitrary key names.
	// Remove URLs' sensitive components before assignment masking can consume a
	// closing quote or a following URL, and before pseudonymization/truncation.
	// Malformed URLs fail closed for this value; never retain raw parse errors.
	value = cmdsem.MapURLs(value, func(raw string) string {
		clean, ok := reviewURL(raw)
		if !ok {
			return pseudonym.Redacted
		}
		return clean
	})
	value = cmdsem.Redact(value)
	value = reviewCredentialAssignment.ReplaceAllString(value, "${1}"+pseudonym.Redacted)
	return reviewCredentialFlag.ReplaceAllString(value, "${1}"+pseudonym.Redacted)
}
