package detect

import (
	"strings"
	"tracefall/internal/model"
	"unicode"
)

// temporalTargetPath compares only literal full Windows target paths. It does
// not parse command lines, expand environment variables, resolve short names,
// clean dot segments, or infer filesystem/content identity.
func temporalTargetPath(e model.Event) (string, bool) {
	target := strings.ToLower(e.ProcessName)
	path := temporalFullPath(e.ProcessPath)
	if path != "" && model.LastElement(path) != target {
		return "", true
	}
	// Scheduled-task FilePath is the source XML, not its configured action.
	// Other FilePath values are usable only when they explicitly name the target.
	file := ""
	if e.EventType != model.EventScheduledTaskCreate && model.LastElement(e.FilePath) == target {
		file = temporalFullPath(e.FilePath)
	}
	if path != "" && file != "" && path != file {
		return "", true
	}
	if path != "" {
		return path, false
	}
	return file, false
}

func temporalFullPath(raw string) string {
	p := strings.ReplaceAll(raw, "/", `\`)
	if strings.IndexFunc(p, unicode.IsControl) >= 0 {
		return ""
	}
	if strings.TrimSpace(p) != p || strings.ContainsAny(p, "\"%*?\x00\r\n\t") {
		return ""
	}
	drive := len(p) > 3 && ((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z')) && p[1] == ':' && p[2] == '\\'
	unc := strings.HasPrefix(p, `\\`) && len(strings.Split(p[2:], `\`)) >= 3
	if !drive && !unc {
		return ""
	}
	rest := p
	if drive {
		rest = p[3:]
	} else {
		rest = p[2:]
	}
	if strings.Contains(rest, ":") {
		return ""
	}
	for _, segment := range strings.Split(rest, `\`) {
		if segment == "" || segment == "." || segment == ".." || strings.HasSuffix(segment, " ") || strings.HasSuffix(segment, ".") {
			return ""
		}
	}
	return strings.ToLower(p)
}
