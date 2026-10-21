// Package webattack recognises the shape of common web attacks in a logged
// request.
//
// It reads the request as the server logged it -- method, URL, user agent --
// and returns the kinds of attack the text resembles. That is all it can
// say. A request that looks like SQL injection is an attempt: the log does
// not show what the application did with it. A 200 answer is not proof the
// attack worked, and a 404 is not proof it failed. Callers must keep that
// wording.
//
// The URL is decoded (percent-encoding, repeatedly, and "+" as a space)
// before matching, because attackers encode precisely to defeat a match on
// the raw text. Matching is on the decoded text only; the logged text is
// never altered.
package webattack

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Categories.
const (
	SQLInjection        = "sql_injection"
	PathTraversal       = "path_traversal"
	CommandInjection    = "command_injection"
	CrossSiteScripting  = "cross_site_scripting"
	WebShell            = "web_shell"
	Scanner             = "scanner_user_agent"
	AdminInterfaceProbe = "admin_interface_probe"
)

// Technique returns the ATT&CK technique a category corresponds to.
func Technique(category string) string {
	switch category {
	case WebShell:
		return "T1505.003"
	case Scanner:
		return "T1595.002"
	case AdminInterfaceProbe:
		return "T1595.003"
	case CrossSiteScripting:
		return "T1189"
	default:
		return "T1190"
	}
}

// Label is a short human name for a category.
func Label(category string) string {
	switch category {
	case SQLInjection:
		return "SQL injection"
	case PathTraversal:
		return "path traversal / file inclusion"
	case CommandInjection:
		return "command injection"
	case CrossSiteScripting:
		return "cross-site scripting"
	case WebShell:
		return "web shell access"
	case Scanner:
		return "vulnerability scanner"
	case AdminInterfaceProbe:
		return "administration interface probe"
	}
	return category
}

type pattern struct {
	category string
	re       *regexp.Regexp
}

func p(category, expr string) pattern {
	return pattern{category, regexp.MustCompile(`(?i)` + expr)}
}

// Patterns run over the decoded URL. They aim at constructs that do not occur
// in ordinary browsing, not at single words: "select" alone is a word, while
// "union select" is an attack.
var urlPatterns = []pattern{
	p(SQLInjection, `union[\s/*+(]+(?:all[\s/*+(]+)?select\b`),
	p(SQLInjection, `information_schema|sqlite_master|sysobjects|pg_catalog`),
	p(SQLInjection, `\b(?:sleep|benchmark|pg_sleep)\s*\(\s*\d`),
	p(SQLInjection, `waitfor\s+delay`),
	p(SQLInjection, `\b(?:extractvalue|updatexml|load_file)\s*\(`),
	p(SQLInjection, `into\s+(?:out|dump)file`),
	p(SQLInjection, `['"]\s*(?:or|and)\s+['"]?\w+['"]?\s*=\s*['"]?\w+`),
	p(SQLInjection, `\b(?:or|and)\s+\d+\s*=\s*\d+`),
	p(SQLInjection, `;\s*(?:drop|insert|update|delete|alter|truncate)\s+\w`),
	p(SQLInjection, `\bchar\(\s*\d+(?:\s*,\s*\d+)+\s*\)`),
	p(SQLInjection, `0x[0-9a-f]{8,}`),
	p(PathTraversal, `(?:\.\.[/\\]){2,}|(?:^|[/\\=])\.\.[/\\]`),
	p(PathTraversal, `/etc/(?:passwd|shadow|group|hosts)\b|/proc/self/|boot\.ini|win\.ini|\\windows\\system32|c:[/\\]windows`),
	p(PathTraversal, `(?:php|expect|data|zip|phar|file|gopher)://`),
	p(CommandInjection, `[;|&]\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|ncat|bash|sh|python|perl|powershell|cmd)(?:\s|$|[;|&<>])`),
	p(CommandInjection, "`[^`]+`|\\$\\([^)]+\\)"),
	p(CommandInjection, `(?:cmd|command|exec|execute|shell|run)=.*(?:/bin/(?:ba)?sh|cmd\.exe|powershell)`),
	p(CommandInjection, `\(\)\s*\{\s*[:\w]*;?\s*\}\s*;`), // () { :;}; (shellshock)
	p(CrossSiteScripting, `<\s*script|javascript:|\bon(?:error|load|mouseover|focus)\s*=|<\s*(?:img|svg|iframe)[^>]*\s(?:src|onload)`),
}

// Admin interfaces that attackers probe. Matched against the path only.
var adminPaths = regexp.MustCompile(`(?i)/(?:phpmyadmin|pma|myadmin|mysqladmin|phpmanager|adminer(?:\.php)?|manager/html|wp-login\.php|xmlrpc\.php|server-status|\.git/(?:config|head)|\.env|\.svn/entries|\.htpasswd)(?:/|$|\?)`)

// Names that web shells are commonly dropped under, matched against the last
// path element.
var shellNames = regexp.MustCompile(`(?i)^(?:c99|r57|b374k|wso|webshell|shell|cmd|backdoor|eval|up|uploader|alfa|indoxploit|china|chopper)(?:\d*)\.(?:php\d?|phtml|asp|aspx|jsp|jspx|cfm|pl|cgi)$`)

// A script path plus a parameter that carries a command.
var shellParam = regexp.MustCompile(`(?i)\.(?:php\d?|phtml|asp|aspx|jsp|jspx|cgi)\b[^#]*[?&](?:cmd|exec|command|shell|execute|system|passthru)=[^&]+`)

var scannerAgents = regexp.MustCompile(`(?i)sqlmap|nikto|nmap|masscan|acunetix|nessus|openvas|w3af|dirbuster|gobuster|wpscan|havij|zgrab|nuclei|burp|metasploit|hydra|arachni|skipfish|whatweb|jaeles|wfuzz|ffuf|feroxbuster|netsparker|appscan|webinspect`)

// Decode percent-decodes s up to three rounds and turns "+" into a space, so
// double-encoded input is reached. It stops when a round changes nothing or
// fails.
func Decode(s string) string {
	for i := 0; i < 3; i++ {
		s2 := strings.ReplaceAll(s, "+", " ")
		d, err := url.PathUnescape(s2)
		if err != nil {
			// A stray % makes PathUnescape fail; decode what is decodable.
			d = lenientUnescape(s2)
		}
		if d == s {
			break
		}
		s = d
	}
	return s
}

func lenientUnescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	}
	return c - 'A' + 10
}

// Classify returns the attack categories a request resembles, sorted and
// without duplicates. uri is the logged request URL (path and query).
func Classify(uri, userAgent string) []string {
	found := map[string]bool{}
	decoded := Decode(uri)
	for _, pt := range urlPatterns {
		if pt.re.MatchString(decoded) {
			found[pt.category] = true
		}
	}
	path := decoded
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	if adminPaths.MatchString(decoded) {
		found[AdminInterfaceProbe] = true
	}
	last := path
	if i := strings.LastIndexByte(last, '/'); i >= 0 {
		last = last[i+1:]
	}
	if shellNames.MatchString(last) || shellParam.MatchString(decoded) {
		found[WebShell] = true
	}
	if userAgent != "" && scannerAgents.MatchString(userAgent) {
		found[Scanner] = true
	}
	out := make([]string, 0, len(found))
	for c := range found {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}
