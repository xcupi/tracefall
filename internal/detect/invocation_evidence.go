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

var psExecutable = regexp.MustCompile(`(?i)^\s*(?:"(?:[^"\r\n]*[\\/])?(?:powershell|pwsh)(?:\.exe)?"|(?:[^\s"]*[\\/])?(?:powershell|pwsh)(?:\.exe)?)(?:\s+|$)`)
var nestedPowerShellHost = regexp.MustCompile(`(?im)(?:^|[;|&=({])\s*(?:[^\s"']*[\\/])?(?:powershell|pwsh)(?:\.exe)?(?:\s+|$)`)
var optionToken = regexp.MustCompile(`"[^"\r\n]*"|'[^'\r\n]*'|[^\s]+`)
var quotedPowerShellCall = regexp.MustCompile(`(?m)(?:^|[;|({])\s*&\s+`)
var dynamicInvocation = regexp.MustCompile(`(?im)(?:^|[;|&=({])\s*(?:iex|invoke-expression)(?:\s|\(|$)`)
var downloadInvocation = regexp.MustCompile(`(?i)\.\s*(?:downloadstring|downloadfile)\s*\(`)
var webRequestInvocation = regexp.MustCompile(`(?im)(?:^|[;|&=({])\s*(?:invoke-webrequest|iwr|invoke-restmethod|irm)(?:\s|\(|$)`)
var decodeInvocation = regexp.MustCompile(`(?i)::\s*frombase64string\s*\(`)

// powerShellRuleIndicators reads invocation positions, not arbitrary keyword
// occurrences. This is a lexical lead selector, not a PowerShell parser or a
// claim that a recorded expression completed. It never executes/decodes code.
// Other rules deliberately retain their existing gates in indicatorsIn.
func powerShellRuleIndicators(cmd string, script bool) []string {
	labels, _ := powerShellInvocationEvidence(cmd, script)
	return labels
}

func powerShellInvocationEvidence(cmd string, script bool) ([]string, string) {
	labels, target, _ := classifiedPowerShellEvidence(cmd, script)
	return labels, target
}

type invocationState uint8

const (
	invocationContext   invocationState = iota // known literal/argument or routine context
	invocationUncertain                        // unsupported grammar; never permission to drop baseline lead
	invocationSelected                         // affirmative labels, independently calibrated by evidence level
)

// Classification is independent of selection: unsupported syntax is not benign.
func classifiedPowerShellEvidence(cmd string, script bool) ([]string, string, invocationState) {
	var labels []string
	uncertain := false
	target := ""
	body := cmd
	if !script {
		loc := psExecutable.FindStringIndex(cmd)
		if loc == nil {
			return nil, "", invocationUncertain
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
			inline := false
			colon := strings.IndexByte(token, ':')
			if colon > 0 && strings.HasPrefix(token, "-") {
				value, token, inline = token[colon+1:], token[:colon], true
			}
			token = canonicalPowerShellOption(token)
			// Recognized host value options consume exactly one token. Do not
			// guess unknown abbreviations or consume a following switch as a value.
			if powerShellHostValueOption(token, cmd) {
				if value == "" || strings.HasPrefix(value, "-") {
					uncertain = true
					break
				}
				if !inline {
					i++
				}
				continue
			}
			switch token {
			case "-nop", "-noprofile":
				labels = append(labels, psNoProfile)
			case "-ep", "-exec", "-executionpolicy":
				if value == "" || strings.HasPrefix(value, "-") {
					uncertain = true
					i = len(tokens)
					break
				}
				if value == "bypass" {
					labels = append(labels, psBypass)
				}
				if !inline {
					i++
				}
			case "-w", "-windowstyle":
				if value == "" || strings.HasPrefix(value, "-") {
					uncertain = true
					i = len(tokens)
					break
				}
				if value == "hidden" || value == "1" {
					labels = append(labels, psHidden)
				}
				if !inline {
					i++
				}
			case "-e", "-ec", "-enc", "-encodedcommand":
				if value == "" || strings.HasPrefix(value, "-") {
					uncertain = true
					i = len(tokens)
					break
				}
				labels = append(labels, psEncoded)
				if !inline {
					i++
				} // One opaque payload; subsequent tokens remain host options.
			case "-f", "-file":
				if value == "" || strings.HasPrefix(value, "-") {
					uncertain = true
					i = len(tokens)
					break
				}
				if value != "" && !strings.HasPrefix(value, "-") {
					if inline {
						target = strings.Trim(rest[at[0]+colon+1:at[1]], `"'`)
					} else {
						n := tokens[i+1]
						target = strings.Trim(rest[n[0]:n[1]], `"'`)
					}
				}
				i = len(tokens) // Remaining tokens belong to the script.
			case "-c", "-command":
				bodyStart := at[1]
				if inline {
					bodyStart = at[0] + colon + 1
				}
				body = strings.TrimSpace(rest[bodyStart:])
				if len(body) >= 2 && ((body[0] == '"' && body[len(body)-1] == '"') || (body[0] == '\'' && body[len(body)-1] == '\'')) {
					body = body[1 : len(body)-1]
				}
				i = len(tokens)
			case "-nologo", "-nol", "-noexit", "-noe", "-noninteractive", "-noni", "-sta", "-mta", "-interactive", "-i", "-login", "-l", "-noprofileloadtime", "-sshservermode", "-sshs":
				// Supported valueless host switches.
			default:
				uncertain = strings.HasPrefix(token, "-")
				if !strings.HasPrefix(token, "-") {
					if strings.HasSuffix(token, ".ps1") {
						target = strings.Trim(rest[at[0]:at[1]], `"'`)
					} else {
						body = rest[at[0]:]
					}
				}
				i = len(tokens) // Unknown options are not permission to scan their data.
			}
		}
	}
	code, incomplete := maskPowerShellLiterals(body)
	uncertain = uncertain || incomplete || strings.Contains(body, "@'") || strings.Contains(body, `@"`) || quotedPowerShellCall.MatchString(code)
	if script {
		// Masked text supplies positions; original bytes preserve host payload and
		// -Command quoting. One nested-host level only, never recursive evaluation.
		for _, loc := range nestedPowerShellHost.FindAllStringIndex(code, -1) {
			start := loc[0]
			for start < loc[1] && strings.ContainsRune(" \t\r\n;|&=({", rune(code[start])) {
				start++
			}
			end := start
			for end < len(code) && !strings.ContainsRune(";|", rune(code[end])) && code[end] != 10 && code[end] != 13 {
				end++
			}
			nested, _ := powerShellInvocationEvidence(body[start:end], false)
			labels = append(labels, nested...)
		}
	}
	if target == "" {
		target = commandPositionTarget(body, true)
	}
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
	if len(labels) == 0 && len(indicatorsIn(code)) != 0 {
		uncertain = true
	}
	state := invocationContext
	if uncertain {
		state = invocationUncertain
	}
	if len(labels) != 0 && !uncertain {
		state = invocationSelected
	}
	return labels, target, state
}

// Keep baseline-eligible weak/unsupported text visible without treating keyword
// matches as invocation proof. Known quoted/comment data and -File arguments
// remain non-selected when the supported lexical form establishes that boundary.
func conservativePowerShellIndicators(cmd string, script bool) []string {
	labels, _, state := classifiedPowerShellEvidence(cmd, script)
	if state == invocationUncertain && len(indicatorsIn(cmd)) != 0 {
		labels = append(labels, "baseline keyword lead; invocation interpretation uncertain (not execution evidence)")
	}
	return labels
}

// Unique prefixes only for the supported host parameters; explicit historical
// aliases remain in the switch. Do not infer arbitrary abbreviated options.
func canonicalPowerShellOption(s string) string {
	for _, full := range []string{"-encodedcommand", "-windowstyle", "-executionpolicy", "-command"} {
		min := len(full)
		switch full {
		case "-encodedcommand":
			min = len("-encodedc")
		case "-windowstyle":
			min = len("-wi")
		case "-executionpolicy":
			min = len("-ex")
		case "-command":
			min = len("-com")
		}
		if len(s) >= min && strings.HasPrefix(full, s) {
			return full
		}
	}
	return s
}

// Explicit host options from about_PowerShell_exe/about_Pwsh; this is not
// generic prefix matching (which could turn a script argument into host data).
func powerShellHostValueOption(option, cmd string) bool {
	exe := strings.Trim(strings.TrimSpace(psExecutable.FindString(cmd)), `"'`)
	if i := strings.LastIndexAny(exe, `\\/`); i >= 0 {
		exe = exe[i+1:]
	}
	pwsh := strings.EqualFold(strings.TrimSuffix(strings.ToLower(exe), ".exe"), "pwsh")
	switch option {
	case "-inputformat", "-inp", "-if", "-outputformat", "-o", "-of", "-configurationname", "-config", "-encodedarguments", "-ea":
		return true
	case "-psconsolefile", "-version":
		return !pwsh
	case "-workingdirectory", "-wd", "-wo", "-configurationfile", "-custompipename", "-settingsfile", "-settings":
		return pwsh
	}
	return false
}

// Blank quoted data and comments before looking for invocation constructs.
// Delimiters are kept apart so removing a literal cannot join two identifiers.
func withoutPowerShellLiterals(s string) string {
	code, _ := maskPowerShellLiterals(s)
	return code
}

func maskPowerShellLiterals(s string) (string, bool) {
	b := []byte(s)
	var quote byte
	lineComment, blockComment := false, false
	tokenBoundary := true
	for i := 0; i < len(b); i++ {
		ch := b[i]
		if lineComment {
			if ch == '\n' {
				lineComment = false
				tokenBoundary = true
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
		// Outside literals a backtick escapes exactly the next character too.
		// Mask both so an escaped #/quote/semicolon is neither a comment,
		// string opener nor an executable statement boundary.
		if ch == '`' {
			b[i] = ' '
			if i+1 < len(b) {
				b[i+1] = ' '
				i++
			}
			continue
		}
		switch ch {
		case '\'', '"':
			quote = ch
			b[i] = ' '
		case '#':
			if tokenBoundary {
				lineComment = true
				b[i] = ' '
			}
		case '<':
			if tokenBoundary && i+1 < len(b) && b[i+1] == '#' {
				blockComment = true
				b[i] = ' '
				b[i+1] = ' '
				i++
			}
		}
		// Comment openers embedded in non-comment tokens are literal. Keep
		// lexical state: masked escapes must not manufacture token boundaries.
		tokenBoundary = strings.ContainsRune(" 	\r\n;|&=(){},", rune(ch))
	}
	return string(b), quote != 0 || blockComment
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
	targets := taskLoaderTargets(e.ProcessName, tokens[1:])
	if e.ProcessName == "cmd.exe" {
		if m := cmdCommand.FindStringSubmatch(e.CommandLine); m != nil {
			targets = []string{commandPositionTarget(m[1], false)}
		}
	}
	if procclass.IsPowerShell(e.ProcessName) {
		_, target := powerShellInvocationEvidence(e.CommandLine, false)
		targets = []string{target}
	}
	writable := taskWritableTarget(first)
	for _, target := range targets {
		writable = writable || taskWritableTarget(target)
	}
	// ProgramData alone is routine application storage. Temp/AppData executable
	// targets remain low-confidence review leads, not high-severity verdicts.
	if writable {
		labels = append(labels, "user-writable action target")
	}
	remote := false
	for _, loaderTarget := range targets {
		remote = remote || strings.HasPrefix(strings.ToLower(loaderTarget), `\\`)
		if e.ProcessName == "mshta.exe" || e.ProcessName == "regsvr32.exe" {
			remote = remote || strings.HasPrefix(strings.ToLower(loaderTarget), "http://") || strings.HasPrefix(strings.ToLower(loaderTarget), "https://")
		}
	}
	if remote {
		labels = append(labels, "remote script/loader action")
	}
	inline := false
	if e.ProcessName == "mshta.exe" || e.ProcessName == "rundll32.exe" {
		for _, target := range targets {
			t := strings.ToLower(target)
			inline = inline || strings.HasPrefix(t, "javascript:") || strings.HasPrefix(t, "vbscript:")
		}
		if inline {
			labels = append(labels, "inline active-code loader action (outcome unknown)")
		}
	}
	if len(labels) == 0 {
		return "", "", nil
	}
	severity, confidence := powerShellEvidenceLevel(labels)
	if inline {
		severity, confidence = "medium", "medium"
	}
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

// Select only executable-specific loader positions, never subsequent data.
// URL loading is supported here only for mshta and scrobj /i, not WSH/DLL paths.
func taskLoaderTargets(proc string, args []string) []string {
	clean := func(s string) string {
		if len(s) >= 2 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'')) {
			return s[1 : len(s)-1]
		}
		return s
	}
	switch proc {
	case "mshta.exe", "rundll32.exe":
		if len(args) > 0 {
			return []string{strings.SplitN(clean(args[0]), ",", 2)[0]}
		}
	case "wscript.exe", "cscript.exe":
		for _, arg := range args {
			t := clean(arg)
			if !strings.HasPrefix(t, "/") {
				return []string{t}
			}
			s := strings.ToLower(strings.TrimLeft(t, "/"))
			switch s {
			case "b", "d", "i", "logo", "nologo", "x":
				continue
			}
			if strings.HasPrefix(s, "e:") || strings.HasPrefix(s, "job:") || strings.HasPrefix(s, "t:") {
				continue
			}
			return nil
		}
	case "regsvr32.exe":
		var install, dll string
		for _, arg := range args {
			t := clean(arg)
			s := strings.ToLower(t)
			if s == "/s" || s == "/u" || s == "/n" {
				continue
			}
			if strings.HasPrefix(s, "/i:") {
				install = clean(t[3:])
				continue
			}
			if strings.HasPrefix(s, "/") || dll != "" {
				return nil
			}
			dll = t
		}
		base := strings.ToLower(dll)
		if i := strings.LastIndexAny(base, `\\/`); i >= 0 {
			base = base[i+1:]
		}
		if base == "scrobj.dll" && install != "" {
			return []string{dll, install}
		}
		return []string{dll}
	}
	return nil
}

// Bounded first-command selection only; subsequent arguments are never targets.
// CMD's outer /c quoting and PowerShell's explicit call operator are supported.
func commandPositionTarget(body string, ps bool) string {
	s := strings.TrimSpace(body)
	if !ps && len(s) > 1 && s[0] == '"' && s[len(s)-1] == '"' {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	call := ps && strings.HasPrefix(s, "&")
	if call {
		s = strings.TrimSpace(s[1:])
	}
	tokens := optionToken.FindAllString(s, 1)
	if len(tokens) == 0 {
		return ""
	}
	token := tokens[0]
	if ps && !call && (token[0] == '\'' || token[0] == '"') {
		return ""
	}
	target := strings.Trim(token, `"'`)
	lower := strings.ToLower(target)
	for _, ext := range []string{".ps1", ".bat", ".cmd", ".exe", ".com"} {
		if strings.HasSuffix(lower, ext) {
			return target
		}
	}
	return ""
}

func taskWritableTarget(path string) bool {
	p := strings.ToLower(path)
	if strings.HasPrefix(p, "javascript:") || strings.HasPrefix(p, "vbscript:") {
		return false
	}
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
