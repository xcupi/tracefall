package detect

import (
	"regexp"
	"sort"
	"strings"
	"tracefall/internal/model"
	"tracefall/internal/procclass"
)

const (
	psEncoded   = "encoded command option (payload not decoded)"
	psHidden    = "hidden window option"
	psNoProfile = "no-profile option"
	psBypass    = "execution policy bypass option"
	psDownload  = "download invocation"
	psDynamic   = "dynamic expression invocation"
	psDecode    = "Base64 conversion with dynamic expression invocation"
)

var psExecutable = regexp.MustCompile(`(?i)^\s*(?:"(?:[^"\r\n]*\\)?(?:powershell|pwsh)(?:\.exe)?"|(?:[^\s"]*\\)?(?:powershell|pwsh)(?:\.exe)?)(?:\s+|$)`)
var optionToken = regexp.MustCompile(`"[^"\r\n]*"|'[^'\r\n]*'|[^\s]+`)
var dynamicInvocation = regexp.MustCompile(`(?im)(?:^|[;|&=({])\s*(?:iex|invoke-expression)(?:\s|\(|$)`)
var downloadInvocation = regexp.MustCompile(`(?i)\.\s*(?:downloadstring|downloadfile)\s*\(`)
var webRequestInvocation = regexp.MustCompile(`(?im)(?:^|[;|&=({])\s*(?:invoke-webrequest|iwr|invoke-restmethod|irm)(?:\s|\(|$)`)
var decodeInvocation = regexp.MustCompile(`(?i)::\s*frombase64string\s*\(`)

// powerShellRuleIndicators reads invocation positions, not arbitrary keyword
// occurrences. This is a lexical lead selector, not a PowerShell parser or a
// claim that a recorded expression completed. It never executes/decodes code.
// Other rules deliberately retain their existing gates in indicatorsIn.
func powerShellRuleIndicators(cmd string, script bool) []string {
	var labels []string
	body := cmd
	if !script {
		loc := psExecutable.FindStringIndex(cmd)
		if loc == nil {
			return nil
		}
		rest := cmd[loc[1]:]
		body = ""
		tokens := optionToken.FindAllStringIndex(rest, -1)
		for i := 0; i < len(tokens); i++ {
			at := tokens[i]
			token := strings.ToLower(strings.Trim(rest[at[0]:at[1]], `"'`))
			value := ""
			if i+1 < len(tokens) {
				n := tokens[i+1]
				value = strings.ToLower(strings.Trim(rest[n[0]:n[1]], `"'`))
			}
			switch token {
			case "-nop", "-noprofile":
				labels = append(labels, psNoProfile)
			case "-ep", "-exec", "-executionpolicy":
				if value == "bypass" {
					labels = append(labels, psBypass)
				}
				i++
			case "-w", "-windowstyle":
				if value == "hidden" || value == "1" {
					labels = append(labels, psHidden)
				}
				i++
			case "-e", "-ec", "-enc", "-encodedcommand":
				labels = append(labels, psEncoded)
				i = len(tokens)
			case "-f", "-file":
				i = len(tokens) // Remaining tokens belong to the script.
			case "-c", "-command":
				body = strings.TrimSpace(rest[at[1]:])
				if len(body) >= 2 && ((body[0] == '"' && body[len(body)-1] == '"') || (body[0] == '\'' && body[len(body)-1] == '\'')) {
					body = body[1 : len(body)-1]
				}
				i = len(tokens)
			default:
				if !strings.HasPrefix(token, "-") {
					body = rest[at[0]:]
					i = len(tokens)
				}
			}
		}
	}
	code := withoutPowerShellLiterals(body)
	dynamic := dynamicInvocation.MatchString(code)
	if downloadInvocation.MatchString(code) || (dynamic && webRequestInvocation.MatchString(code)) {
		labels = append(labels, psDownload)
	}
	if dynamic {
		labels = append(labels, psDynamic)
	}
	// Base64 is also ordinary data conversion. Without a dynamic invocation it
	// does not select a finding; no claim about the decoded data is made.
	if dynamic && decodeInvocation.MatchString(code) {
		labels = append(labels, psDecode)
	}
	return labels
}

// Blank quoted data and comments before looking for invocation constructs.
// Delimiters are kept apart so removing a literal cannot join two identifiers.
func withoutPowerShellLiterals(s string) string {
	b := []byte(s)
	var quote byte
	lineComment, blockComment := false, false
	for i := 0; i < len(b); i++ {
		ch := b[i]
		if lineComment {
			if ch == '\n' {
				lineComment = false
			} else {
				b[i] = ' '
			}
			continue
		}
		if blockComment {
			b[i] = ' '
			if ch == '#' && i+1 < len(b) && b[i+1] == '>' {
				b[i+1] = ' '
				i++
				blockComment = false
			}
			continue
		}
		if quote != 0 {
			b[i] = ' '
			if ch == '`' && quote == '"' && i+1 < len(b) {
				b[i+1] = ' '
				i++
				continue
			}
			if ch == quote {
				if quote == '\'' && i+1 < len(b) && b[i+1] == '\'' {
					b[i+1] = ' '
					i++
				} else {
					quote = 0
				}
			}
			continue
		}
		switch ch {
		case '\'', '"':
			quote = ch
			b[i] = ' '
		case '#':
			lineComment = true
			b[i] = ' '
		case '<':
			if i+1 < len(b) && b[i+1] == '#' {
				blockComment = true
				b[i] = ' '
				b[i+1] = ' '
				i++
			}
		}
	}
	return string(b)
}

var cmdCommand = regexp.MustCompile(`(?i)^\s*(?:"(?:[^"\r\n]*\\)?cmd(?:\.exe)?"|(?:[^\s"]*\\)?cmd(?:\.exe)?)\s+(?:/d\s+)?/[ck]\s+(.+)$`)

func strongNestedInvocation(e model.Event) bool {
	severity, _ := powerShellEvidenceLevel(interpreterInvocationIndicators(e))
	return severity == model.SeverityHigh
}

func interpreterInvocationIndicators(e model.Event) []string {
	cmd := e.CommandLine
	if e.ProcessName == "cmd.exe" {
		m := cmdCommand.FindStringSubmatch(cmd)
		if m == nil {
			return nil
		}
		cmd = strings.TrimSpace(m[1])
		if len(cmd) > 1 && cmd[0] == '"' && cmd[len(cmd)-1] == '"' {
			cmd = cmd[1 : len(cmd)-1]
		}
	} else if !procclass.IsPowerShell(e.ProcessName) {
		return nil
	}
	return powerShellRuleIndicators(cmd, false)
}

func taskActionEvidence(e model.Event) (string, string, []string) {
	tokens := optionToken.FindAllString(e.CommandLine, -1)
	if len(tokens) == 0 {
		return "", "", nil
	}
	first := strings.Trim(tokens[0], `"'`)
	base := strings.ToLower(first)
	if i := strings.LastIndexAny(base, `\\/`); i >= 0 {
		base = base[i+1:]
	}
	// The normalized action identity and the recorded command must agree.
	if e.ProcessName == "" || strings.TrimSuffix(base, ".exe") != strings.TrimSuffix(e.ProcessName, ".exe") {
		return "", "", nil
	}
	labels := interpreterInvocationIndicators(e)
	writable := taskWritableTarget(first)
	if procclass.IsPowerShell(e.ProcessName) {
		for i, t := range tokens[1:] {
			option := strings.ToLower(strings.Trim(t, `"'`))
			if option == "-c" || option == "-command" || option == "-e" || option == "-ec" || option == "-enc" || option == "-encodedcommand" {
				break // Subsequent -File text belongs to code/data, not launch options.
			}
			if option == "-file" || option == "-f" {
				if i+2 < len(tokens) {
					writable = writable || taskWritableTarget(strings.Trim(tokens[i+2], `"'`))
				}
				break // The rest are script arguments, not another executable target.
			}
		}
	}
	// ProgramData alone is routine application storage. Temp/AppData executable
	// targets remain low-confidence review leads, not high-severity verdicts.
	if writable {
		labels = append(labels, "user-writable action target")
	}
	remote := false
	switch e.ProcessName {
	case "mshta.exe", "wscript.exe", "cscript.exe", "rundll32.exe", "regsvr32.exe":
		for _, t := range tokens[1:] {
			t = strings.ToLower(strings.Trim(t, `"'`))
			t = strings.TrimPrefix(t, "/i:")
			if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") || strings.HasPrefix(t, `\\`) {
				remote = true
			}
		}
	}
	if remote {
		labels = append(labels, "remote script/loader action")
	}
	if len(labels) == 0 {
		return "", "", nil
	}
	severity, confidence := powerShellEvidenceLevel(labels)
	if writable {
		severity, confidence = "medium", "low"
	}
	for _, l := range labels {
		if l == psHidden && writable {
			severity, confidence = "high", "medium"
		}
	}
	psSeverity, psConfidence := powerShellEvidenceLevel(labels)
	if psSeverity == "high" || remote {
		severity, confidence = "high", "medium"
	} else if psSeverity == "medium" && severity != "high" {
		severity, confidence = psSeverity, psConfidence
	}
	return severity, confidence, labels
}

func taskWritableTarget(path string) bool {
	p := strings.ToLower(path)
	for _, marker := range []string{`\appdata\`, `\temp\`, `\users\public\`, `\downloads\`} {
		if strings.Contains(p, marker) {
			return true
		}
	}
	return false
}

// Each affected rule emits one finding per event. A time/ID tie-break makes
// direct and filtered sources deterministic without changing other rules.
func orderInvocationFindings(fs []model.Finding) []model.Finding {
	sort.Slice(fs, func(i, j int) bool {
		if !fs[i].FirstSeen.Equal(fs[j].FirstSeen) {
			return fs[i].FirstSeen.Before(fs[j].FirstSeen)
		}
		return fs[i].SupportingEvents[0] < fs[j].SupportingEvents[0]
	})
	return fs
}

func powerShellEvidenceLevel(labels []string) (string, string) {
	seen := map[string]bool{}
	for _, l := range labels {
		seen[l] = true
	}
	if (seen[psEncoded] && seen[psHidden]) || (seen[psDynamic] && (seen[psDownload] || seen[psDecode])) {
		return "high", "medium"
	}
	if seen[psEncoded] || seen[psDynamic] || seen[psDownload] || seen[psHidden] {
		return "medium", "medium"
	}
	return "low", "low"
}
