// Package cmdsem says what a command line is trying to change on the host it
// ran on: the firewall, something that makes code run again later, or an
// account.
//
// It reads the text of a command and nothing else. A command line shows an
// intent. It does not show that the command ran to completion, that the
// change took effect, or that the person who typed it was entitled to: a
// sudo line records an authorisation, a shell history line records what was
// typed, and a process-creation record shows a start but not an outcome.
// Callers must say so in whatever they build from a Semantic.
//
// The match is deliberately narrow. A command that only lists state
// (iptables -L, crontab -l, net user) has no semantic. Secrets typed on a
// command line (net user NAME PASSWORD /add) never appear in a Semantic:
// Detail names the account, not the password.
package cmdsem

import (
	"regexp"
	"sort"
	"strings"
)

// Categories.
const (
	Firewall    = "firewall"
	Persistence = "persistence"
	Account     = "account"
)

// Severity levels, matching model's strings.
const (
	Low    = "low"
	Medium = "medium"
	High   = "high"
)

// Semantic is one thing a command line tries to do.
type Semantic struct {
	Category  string // Firewall, Persistence or Account
	Action    string // short stable name, for grouping
	Detail    string // one line for a person, never containing a secret
	Technique string // ATT&CK technique ID
	Severity  string
}

type rule struct {
	re        *regexp.Regexp
	category  string
	action    string
	technique string
	severity  string
	detail    func(m []string) string
}

func ci(p string) *regexp.Regexp { return regexp.MustCompile(`(?i)` + p) }

func static(s string) func([]string) string { return func([]string) string { return s } }

// privilegedGroups are groups whose membership grants administrative power
// or remote access. Compared case-insensitively, quotes removed.
var privilegedGroups = map[string]bool{
	"administrators": true, "domain admins": true, "enterprise admins": true, "schema admins": true,
	"remote desktop users": true, "backup operators": true, "account operators": true,
	"sudo": true, "wheel": true, "admin": true, "root": true, "adm": true, "docker": true, "lxd": true,
}

func unquote(s string) string { return strings.Trim(strings.TrimSpace(s), `"'`+"`") }

// iptablesRest captures what follows the iptables program name.
var iptablesRest = ci(`(?:^|[\s;&|/'"])ip6?tables(?:-nft|-legacy)?(?:\.exe)?\s+(.*)$`)

var (
	ipFlagAppend = regexp.MustCompile(`(?:^|\s)(?:-A|--append|-I|--insert)\s+(\S+)`)
	ipFlagDelete = regexp.MustCompile(`(?:^|\s)(?:-D|--delete)\s+(\S+)`)
	ipFlagFlush  = regexp.MustCompile(`(?:^|\s)(?:-F|--flush)(?:\s|$)`)
	ipFlagPolicy = regexp.MustCompile(`(?:^|\s)(?:-P|--policy)\s+(\S+)\s+(\S+)`)
	ipTarget     = regexp.MustCompile(`(?:^|\s)-j\s+(\S+)`)
	ipDport      = regexp.MustCompile(`--dports?\s+(\S+)`)
	ipSource     = regexp.MustCompile(`(?:^|\s)(?:-s|--source)\s+(\S+)`)
)

var rules = []rule{
	// ---- Windows firewall ----
	{ci(`netsh(?:\.exe)?\s+(?:adv)?firewall\s+(?:firewall\s+)?add\s+rule\b(.*)`), Firewall, "rule_added", "T1562.004", Low,
		func(m []string) string { return "Windows firewall rule added" + netshRuleDetail(m[1]) }},
	{ci(`netsh(?:\.exe)?\s+(?:adv)?firewall\s+(?:firewall\s+)?delete\s+rule\b`), Firewall, "rule_deleted", "T1562.004", Low, static("Windows firewall rule deleted")},
	{ci(`netsh(?:\.exe)?\s+advfirewall\s+set\s+\w*profile\s+state\s+off\b`), Firewall, "firewall_disabled", "T1562.004", Medium, static("Windows firewall turned off for a profile")},
	{ci(`netsh(?:\.exe)?\s+(?:adv)?firewall\s+set\s+(?:opmode|allprofiles)\s+(?:mode\s*=\s*)?(?:disable|state\s+off)\b`), Firewall, "firewall_disabled", "T1562.004", Medium, static("Windows firewall turned off")},
	{ci(`netsh(?:\.exe)?\s+firewall\s+set\s+opmode\s+(?:mode\s*=\s*)?disable\b`), Firewall, "firewall_disabled", "T1562.004", Medium, static("Windows firewall turned off")},
	{ci(`netsh(?:\.exe)?\s+(?:interface\s+)?portproxy\s+add\b`), Firewall, "port_forward", "T1090.001", Medium, static("Port forwarding configured with netsh portproxy")},
	{ci(`\bNew-NetFirewallRule\b`), Firewall, "rule_added", "T1562.004", Low, static("Windows firewall rule added (PowerShell)")},
	{ci(`\bSet-NetFirewallProfile\b.*-Enabled\s+(?:False|0|\$false)`), Firewall, "firewall_disabled", "T1562.004", Medium, static("Windows firewall turned off (PowerShell)")},
	{ci(`\b(?:Disable|Remove)-NetFirewallRule\b`), Firewall, "rule_deleted", "T1562.004", Low, static("Windows firewall rule disabled or removed (PowerShell)")},
	{ci(`\b(?:net1?\s+stop|sc(?:\.exe)?\s+(?:stop|config))\s+"?(?:mpssvc|sharedaccess|windows firewall)"?`), Firewall, "firewall_disabled", "T1562.004", Medium, static("Windows firewall service stopped or reconfigured")},
	// ---- Linux firewall (iptables handled in code, below) ----
	{ci(`(?:^|[\s;&|/])ufw\s+(?:--force\s+)?disable\b`), Firewall, "firewall_disabled", "T1562.004", Medium, static("ufw turned off")},
	{ci(`(?:^|[\s;&|/])ufw\s+(?:--force\s+)?reset\b`), Firewall, "rules_flushed", "T1562.004", Medium, static("ufw rules reset")},
	{ci(`(?:^|[\s;&|/])ufw\s+(?:allow|deny|reject|limit)\b(.*)`), Firewall, "rule_added", "T1562.004", Low, static("ufw rule added")},
	{ci(`(?:^|[\s;&|/])firewall-cmd\b.*--(?:add|remove)-(?:port|service|rich-rule|source)\b`), Firewall, "rule_added", "T1562.004", Low, static("firewalld rule changed")},
	{ci(`(?:^|[\s;&|/])nft\s+(?:add|insert|delete)\s+rule\b`), Firewall, "rule_added", "T1562.004", Low, static("nftables rule changed")},
	{ci(`(?:^|[\s;&|/])nft\s+flush\s+ruleset\b`), Firewall, "rules_flushed", "T1562.004", Medium, static("nftables ruleset flushed")},
	{ci(`(?:^|[\s;&|/])systemctl\s+(?:stop|disable|mask)\s+(?:firewalld|ufw|iptables|netfilter-persistent)\b`), Firewall, "firewall_disabled", "T1562.004", Medium, static("firewall service stopped or disabled")},
	{ci(`(?:^|[\s;&|/])service\s+(?:iptables|ip6tables|ufw|firewalld)\s+stop\b`), Firewall, "firewall_disabled", "T1562.004", Medium, static("firewall service stopped")},

	// ---- persistence ----
	{ci(`\bschtasks(?:\.exe)?\b.*\s/create\b(.*)`), Persistence, "scheduled_task_created", "T1053.005", Medium,
		func(m []string) string { return "Scheduled task created" + schtasksDetail(m[0]) }},
	{ci(`\bsc(?:\.exe)?\s+(?:\\\\\S+\s+)?create\s+"?([^\s"]+)"?`), Persistence, "service_created", "T1543.003", Medium,
		func(m []string) string { return "Windows service created: " + m[1] }},
	{ci(`\bNew-Service\b`), Persistence, "service_created", "T1543.003", Medium, static("Windows service created (PowerShell)")},
	{ci(`\breg(?:\.exe)?\s+add\s+"?[^"]*\\(?:Run|RunOnce|RunServices|RunServicesOnce)\b`), Persistence, "run_key_set", "T1547.001", Medium, static("Run key value set with reg add")},
	{ci(`\b(?:Set|New)-ItemProperty\b.*\\(?:Run|RunOnce)\b`), Persistence, "run_key_set", "T1547.001", Medium, static("Run key value set (PowerShell)")},
	{ci(`\breg(?:\.exe)?\s+add\s+"?[^"]*Image File Execution Options`), Persistence, "ifeo_set", "T1546.012", High, static("Image File Execution Options key set")},
	{ci(`\breg(?:\.exe)?\s+add\s+"?[^"]*\\Winlogon\b`), Persistence, "winlogon_set", "T1547.004", Medium, static("Winlogon key value set with reg add")},
	{ci(`\\Start Menu\\Programs\\Startup\b`), Persistence, "startup_folder", "T1547.001", Medium, static("File placed in a Startup folder")},
	{ci(`\b__EventFilter\b|\bCommandLineEventConsumer\b|\bActiveScriptEventConsumer\b`), Persistence, "wmi_subscription", "T1546.003", High, static("WMI event subscription created")},
	{ci(`(?:^|[\s;&|/])crontab\s+(?:-u\s+\S+\s+)?(?:-e\b|-\s*$|-\s|[^-\s]\S*)`), Persistence, "cron_installed", "T1053.003", Medium, static("Crontab edited or replaced")},
	{ci(`>>?\s*\S*(?:/etc/cron\.\S+|/etc/crontab|/var/spool/cron\S*)`), Persistence, "cron_installed", "T1053.003", Medium, static("Text written into a cron location")},
	{ci(`(?:^|[\s;&|/])systemctl\s+(?:--now\s+)?enable\s+(\S+)`), Persistence, "service_enabled", "T1543.002", Low,
		func(m []string) string { return "systemd unit enabled: " + m[1] }},
	{ci(`(?:^|[\s;&|/])(?:update-rc\.d\s+\S+\s+(?:defaults|enable)|chkconfig\s+\S+\s+on)\b`), Persistence, "service_enabled", "T1543.002", Low, static("Service enabled at boot")},
	{ci(`>>?\s*\S*(?:\.bashrc|\.bash_profile|\.profile|\.zshrc|/etc/profile\S*|/etc/bash\.bashrc)\b`), Persistence, "shell_profile_edit", "T1546.004", Medium, static("Text written into a shell start-up file")},
	{ci(`>>?\s*\S*/etc/rc\.local\b`), Persistence, "rc_local_edit", "T1037.004", Medium, static("Text written into rc.local")},
	{ci(`>>?\s*\S*authorized_keys\b`), Persistence, "ssh_key_added", "T1098.004", High, static("Key appended to authorized_keys")},

	// ---- accounts ----
	{ci(`\bnet1?(?:\.exe)?\s+user\s+("[^"]+"|\S+)\s+(?:"[^"]*"\s+|\S+\s+)?(?:/\w+(?::\S+)?\s+)*/add\b`), Account, "user_added", "T1136.001", Medium,
		func(m []string) string { return "Local account added: " + unquote(m[1]) }},
	{ci(`\bnet1?(?:\.exe)?\s+user\s+("[^"]+"|\S+)\s+/delete\b`), Account, "user_deleted", "T1531", Low,
		func(m []string) string { return "Local account deleted: " + unquote(m[1]) }},
	{ci(`\bnet1?(?:\.exe)?\s+user\s+("[^"]+"|[^/\s]+)\s+("[^"]+"|[^/\s]+)\s*$`), Account, "password_set", "T1098", Low,
		func(m []string) string { return "Password set for account: " + unquote(m[1]) }},
	{ci(`\bnet1?(?:\.exe)?\s+(?:local)?group\s+("[^"]+"|[^\s/]+)\s+("[^"]+"|[^\s/]+)\s+/add\b`), Account, "group_member_added", "T1098", Medium,
		func(m []string) string { return "Added " + unquote(m[2]) + " to group " + unquote(m[1]) }},
	{ci(`\b(?:New-LocalUser|Set-LocalUser)\b`), Account, "user_added", "T1136.001", Medium, static("Local account created or changed (PowerShell)")},
	{ci(`\bAdd-LocalGroupMember\b.*-Group\s+("[^"]+"|\S+)`), Account, "group_member_added", "T1098", Medium,
		func(m []string) string { return "Member added to group " + unquote(m[1]) + " (PowerShell)" }},
	{ci(`(?:^|[\s;&|/])(?:useradd|adduser)\s+(.*)`), Account, "user_added", "T1136.001", Medium,
		func(m []string) string { return "Local account added" + lastToken(m[1], " ") }},
	{ci(`(?:^|[\s;&|/])userdel\s+(?:-\w+\s+)*(\S+)`), Account, "user_deleted", "T1531", Low,
		func(m []string) string { return "Local account deleted: " + m[1] }},
	{ci(`(?:^|[\s;&|/])usermod\s+.*(?:-aG|-G|--append\s+--groups|--groups)\s+(\S+)`), Account, "group_member_added", "T1098", Medium,
		func(m []string) string { return "User added to group(s) " + m[1] }},
	{ci(`\bchpasswd\b`), Account, "password_set", "T1098", Low, static("Password set with chpasswd")},
	{ci(`(?:^|[\s;&|/])gpasswd\s+(?:-a|--add)\s+(\S+)\s+(\S+)`), Account, "group_member_added", "T1098", Medium,
		func(m []string) string { return "Added " + m[1] + " to group " + m[2] }},
}

// Analyze returns every semantic the command line carries, ordered by
// category, action and detail so the result is the same on every run. An
// empty command or one that only lists state returns nil.
func Analyze(cmdline string) []Semantic {
	cmd := strings.TrimSpace(cmdline)
	if cmd == "" {
		return nil
	}
	seen := map[Semantic]bool{}
	var out []Semantic
	add := func(s Semantic) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, r := range rules {
		m := r.re.FindStringSubmatch(cmd)
		if m == nil {
			continue
		}
		s := Semantic{Category: r.category, Action: r.action, Detail: r.detail(m), Technique: r.technique, Severity: r.severity}
		if r.action == "group_member_added" {
			s = escalateGroup(s, cmd)
		}
		if r.action == "user_added" && regexp.MustCompile(`(?i)(?:^|\s)(?:-u\s+0\b|--uid\s+0\b)`).MatchString(cmd) {
			s.Severity, s.Detail = High, s.Detail+" with UID 0 (root-equivalent)"
		}
		add(s)
	}
	for _, s := range iptablesSemantics(cmd) {
		add(s)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		if a.Action != b.Action {
			return a.Action < b.Action
		}
		return a.Detail < b.Detail
	})
	return out
}

// escalateGroup raises a group-membership change to High when the group
// grants administrative power. The group name is read from the Detail.
func escalateGroup(s Semantic, cmd string) Semantic {
	low := strings.ToLower(cmd)
	for g := range privilegedGroups {
		if strings.Contains(low, `"`+g+`"`) || strings.Contains(low, " "+g+" ") || strings.HasSuffix(low, " "+g) ||
			strings.Contains(low, ","+g) || strings.Contains(low, g+",") {
			s.Severity = High
			s.Detail += " (privileged group)"
			return s
		}
	}
	return s
}

func iptablesSemantics(cmd string) []Semantic {
	m := iptablesRest.FindStringSubmatch(cmd)
	if m == nil {
		return nil
	}
	rest := m[1]
	var out []Semantic
	if ipFlagFlush.MatchString(rest) {
		out = append(out, Semantic{Firewall, "rules_flushed", "iptables rules flushed", "T1562.004", Medium})
	}
	if p := ipFlagPolicy.FindStringSubmatch(rest); p != nil {
		sev, action := Low, "policy_set"
		if strings.EqualFold(p[2], "ACCEPT") && strings.EqualFold(p[1], "INPUT") {
			sev, action = Medium, "policy_accept_all"
		}
		out = append(out, Semantic{Firewall, action, "iptables default policy of " + p[1] + " set to " + p[2], "T1562.004", sev})
	}
	if a := ipFlagAppend.FindStringSubmatch(rest); a != nil {
		d := "iptables rule added to " + a[1]
		if t := ipTarget.FindStringSubmatch(rest); t != nil {
			d += " (" + t[1] + ")"
		}
		if p := ipDport.FindStringSubmatch(rest); p != nil {
			d += " port " + p[1]
		}
		if s := ipSource.FindStringSubmatch(rest); s != nil {
			d += " from " + s[1]
		}
		out = append(out, Semantic{Firewall, "rule_added", d, "T1562.004", Low})
	}
	if d := ipFlagDelete.FindStringSubmatch(rest); d != nil {
		out = append(out, Semantic{Firewall, "rule_deleted", "iptables rule deleted from " + d[1], "T1562.004", Low})
	}
	return out
}

func netshRuleDetail(rest string) string {
	var parts []string
	for _, k := range []string{"name", "dir", "action", "localport", "program", "protocol"} {
		re := ci(`\b` + k + `\s*=\s*("[^"]*"|\S+)`)
		if m := re.FindStringSubmatch(rest); m != nil {
			parts = append(parts, k+"="+unquote(m[1]))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

func schtasksDetail(cmd string) string {
	var parts []string
	for _, k := range []string{"tn", "tr", "sc", "ru"} {
		re := ci(`/` + k + `\s+("[^"]*"|\S+)`)
		if m := re.FindStringSubmatch(cmd); m != nil {
			parts = append(parts, "/"+k+" "+unquote(m[1]))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

// lastToken returns ": <last word>" when the command ends in a word that is
// not an option, which for useradd is the account name.
func lastToken(rest, sep string) string {
	f := strings.Fields(rest)
	if len(f) == 0 || strings.HasPrefix(f[len(f)-1], "-") {
		return ""
	}
	return ": " + f[len(f)-1]
}

var redactions = []struct {
	re   *regexp.Regexp
	repl string
}{
	// Only the authority component: ordinary emails and path/query @ remain.
	{ci(`(https?://)[^\s/\x3f#"'<>]+@`), `${1}<redacted>@`},
	// net user NAME PASSWORD [/add ...]
	{ci(`(\bnet1?(?:\.exe)?\s+user\s+(?:"[^"]+"|[^/\s]+)\s+)("[^"]+"|[^/\s]+)`), `${1}<redacted>`},
	// echo "user:secret" | chpasswd
	{ci(`("?[\w.-]+:)[^"\s|]+("?\s*\|\s*(?:sudo\s+)?chpasswd)`), `${1}<redacted>${2}`},
	{ci(`(\b(?:useradd|usermod)\b[^|;&]*?\s(?:-p|--password)\s+)\S+`), `${1}<redacted>`},
	{ci(`(\bsshpass\s+-p\s*)\S+`), `${1}<redacted>`},
	{ci(`(\bmysql(?:admin)?\b[^|;&]*?\s-p)\S+`), `${1}<redacted>`},
	{ci(`(/rp\s+)("[^"]*"|\S+)`), `${1}<redacted>`},
	{ci(`(-Password\s+)\(?ConvertTo-SecureString\s+("[^"]*"|'[^']*'|\S+)`), `${1}<redacted>`},
	{ci(`(\bConvertTo-SecureString\s+)("[^"]*"|'[^']*')`), `${1}<redacted>`},
	{ci(`(\b(?:-pass(?:word)?|--pass(?:word)?|/pass(?:word)?:?)[ =:]\s*)("[^"]*"|\S+)`), `${1}<redacted>`},
	// SQL Server: [OLD_]PASSWORD = [N]'secret' in CREATE/ALTER LOGIN or USER.
	{ci(`(\b(?:old_)?password\s*=\s*N?)'(?:[^']|'')*'`), `${1}'<redacted>'`},
	// Stored-procedure parameters that carry a secret: @rmtpassword, @new,
	// @old, @password, @pwd (quoted value).
	{ci(`(@(?:rmtpassword|password|pwd|new|old)\s*=\s*N?)'(?:[^']|'')*'`), `${1}'<redacted>'`},
	// Connection-string keys: Password= / Pwd= up to the next semicolon.
	{ci(`(\b(?:password|pwd)\s*=\s*)("[^"]*"|'[^']*'|[^;'"\s][^;]*)`), `${1}<redacted>`},
	// sqlcmd / osql / bcp -P secret (a capital P; -p is something else).
	{regexp.MustCompile(`(\b(?:sqlcmd|osql|bcp)(?:\.exe)?\b[^|;&\n]*?\s-P\s*)("[^"]*"|'[^']*'|\S+)`), `${1}<redacted>`},
}

// Redact masks the secrets a command line can carry -- the password in
// "net user NAME PASSWORD /add", the right-hand side of a chpasswd pair, a
// password given to useradd, sshpass, mysql or schtasks. Use it on any
// command text that is copied into a finding or a report. It is a
// best-effort mask of known shapes, not a guarantee that no secret remains.
func Redact(cmd string) string {
	for _, r := range redactions {
		cmd = r.re.ReplaceAllString(cmd, r.repl)
	}
	return cmd
}
