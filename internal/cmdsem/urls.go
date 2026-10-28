package cmdsem

import (
	"regexp"
	"strings"
)

var urlStart = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]{1,15}://`)

// MapURLs maps bounded URL spans in command-derived text, not shell syntax.
// Apostrophes are URL data in bare/double-quoted spans, but close an outer
// single quote. Hard double quotes, whitespace and angle brackets bound spans;
// only the exact existing userinfo marker <redacted> is accepted as URL data.
// Candidates inside an already consumed URL are skipped, keeping the scan linear.
func MapURLs(text string, replace func(string) string) string {
	var out strings.Builder
	cursor, scanned := 0, 0
	var quote byte
	for _, loc := range urlStart.FindAllStringIndex(text, -1) {
		start := loc[0]
		if start < scanned {
			continue
		}
		for i := scanned; i < start; i++ {
			c := text[i]
			if (c == '\\' || c == '`') && i+1 < start {
				i++
				continue
			}
			if c == quote {
				quote = 0
			} else if quote == 0 && (c == '"' || (c == '\'' && (i == 0 || text[i-1] <= ' ' || strings.ContainsRune("=(:,;|&", rune(text[i-1]))))) {
				// A bare word's apostrophe (e.g. a filename) is not an
				// opening wrapper for a later URL.
				quote = c
			}
		}
		end := loc[1]
		// An immediate wrapping quote also bounds URLs in nested expressions;
		// this does not attempt to interpret or evaluate command grammar.
		singleQuoted := quote == '\''
		if start > 0 && (text[start-1] == '\'' || text[start-1] == '"') {
			singleQuoted = text[start-1] == '\''
		}
		for end < len(text) {
			c := text[end]
			if c <= ' ' || c == '"' || c == '>' || (c == '\'' && singleQuoted) {
				break
			}
			if c == '<' {
				if strings.HasPrefix(text[end:], "<redacted>") {
					end += len("<redacted>")
					continue
				}
				break
			}
			end++
		}
		out.WriteString(text[cursor:start])
		out.WriteString(replace(text[start:end]))
		cursor, scanned = end, end
	}
	if cursor == 0 {
		return text
	}
	out.WriteString(text[cursor:])
	return out.String()
}
