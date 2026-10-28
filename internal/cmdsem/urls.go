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
	out, _ := mapURLs(text, replace)
	return out
}

// URLBoundariesCertain reports whether the bounded scanner can safely delimit
// every URL. It does not parse shell languages or validate URL syntax. Callers
// exporting command context must omit uncertain commands before learning entities.
// Generic redaction deliberately retains its existing string-only contract.
func URLBoundariesCertain(text string) bool {
	_, certain := mapURLs(text, func(raw string) string { return raw })
	return certain
}

func mapURLs(text string, replace func(string) string) (string, bool) {
	certain := true
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
		wrapper := quote
		if start > 0 && (text[start-1] == '\'' || text[start-1] == '"') {
			wrapper = text[start-1]
			if urlQuoteEscaped(text, start-1) {
				certain = false
			}
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
				certain = false // Incomplete/unknown marker is not a safe boundary.
				break
			}
			end++
		}
		if wrapper != 0 && (end == len(text) || text[end] != wrapper) {
			certain = false
		}
		if end+1 < len(text) && (text[end] == '\'' || text[end] == '"') && text[end+1] == text[end] {
			// Doubled quotes can be escaped URL data rather than two wrappers.
			certain = false
		}
		if end < len(text) && ((text[end] == '"' || text[end] == '\'') && urlQuoteEscaped(text, end) || text[end] == '>') {
			certain = false
		}
		out.WriteString(text[cursor:start])
		out.WriteString(replace(text[start:end]))
		cursor, scanned = end, end
	}
	if cursor == 0 {
		return text, certain
	}
	out.WriteString(text[cursor:])
	return out.String(), certain
}

// Odd runs may escape a quote in common command grammars; even runs leave a
// genuine closing quote. Mixed escape runs are unsupported, hence uncertain.
func urlQuoteEscaped(text string, at int) bool {
	i := at
	for i > 0 && (text[i-1] == '\\' || text[i-1] == '`') {
		i--
	}
	run := text[i:at]
	return len(run)%2 != 0 || (strings.Contains(run, "\\") && strings.Contains(run, "`"))
}
