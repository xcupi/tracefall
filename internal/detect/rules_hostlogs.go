package detect

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"tracefall/internal/cmdsem"
	"tracefall/internal/model"
	"tracefall/internal/partialtime"
	"tracefall/internal/webattack"
)

// Rules for Linux and server logs: authentication bursts in logs that carry
// no year, web attacks in access logs, account changes, database warnings and
// system-changing commands.

// supportingCap bounds how many events one finding lists. A single source can
// produce tens of thousands of failures; the finding states the true count
// and lists the ends of the run, where the evidence that matters is.
const supportingCap = 24

// capEvents keeps the first and last events of a run when it is longer than
// supportingCap, always keeping the final event.
func capEvents(ev []model.Event) []model.Event {
	if len(ev) <= supportingCap {
		return ev
	}
	half := supportingCap / 2
	out := append([]model.Event{}, ev[:half]...)
	return append(out, ev[len(ev)-half:]...)
}

// ---------- Brute force then success, in logs with no year ----------

type bruteForceSequence struct{}

func (bruteForceSequence) ID() string { return "brute-force-then-success-sequence" }

func (bruteForceSequence) Inputs() model.EventFilter {
	return model.EventFilter{Types: []string{model.EventLogonFailure, model.EventLogonSuccess}}
}

func (r bruteForceSequence) Evaluate(events []model.Event) []model.Finding {
	type key struct{ host, user, src, file string }
	type placed struct {
		ev  model.Event
		pos partialtime.Position
	}
	// One list per (account, address, file) holding failures and successes
	// together, because a success ends the run of failures before it.
	byKey := map[key][]placed{}
	hasFailures := map[key]bool{}
	for _, e := range events {
		if !e.Timestamp.IsZero() || e.NetworkSource == "" {
			continue // a dated event is the other rule's business
		}
		if e.EventType != model.EventLogonFailure && e.EventType != model.EventLogonSuccess {
			continue
		}
		pos, ok := partialtime.PositionOf(e.SourceFileID, e.Extra)
		if !ok {
			continue
		}
		k := key{e.Host, e.User, e.NetworkSource, e.SourceFileID}
		byKey[k] = append(byKey[k], placed{e, pos})
		if e.EventType == model.EventLogonFailure {
			hasFailures[k] = true
		}
	}
	keys := make([]key, 0, len(byKey))
	for k := range byKey {
		if hasFailures[k] {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.host != b.host {
			return a.host < b.host
		}
		if a.user != b.user {
			return a.user < b.user
		}
		if a.src != b.src {
			return a.src < b.src
		}
		return a.file < b.file
	})
	var out []model.Finding
	for _, k := range keys {
		list := byKey[k]
		sort.SliceStable(list, func(i, j int) bool { return list[i].pos.Line < list[j].pos.Line })
		its := make([]partialtime.Item, len(list))
		for i, p := range list {
			its[i] = partialtime.Item{Pos: p.pos, Success: p.ev.EventType == model.EventLogonSuccess}
		}
		for _, b := range partialtime.BurstsBeforeSuccess(its, bruteForceThreshold, bruteForceGapWindow, bruteForceSuccessWindow) {
			first, last := list[b.Failures[0]], list[b.Failures[len(b.Failures)-1]]
			succ := list[b.Success]
			burst := make([]model.Event, len(b.Failures))
			for i, idx := range b.Failures {
				burst[i] = list[idx].ev
			}
			supporting := append(capEvents(burst), succ.ev)
			span, _ := partialtime.Delta(first.pos, last.pos)
			title := fmt.Sprintf("%d failed logons followed by success for %s from %s (order within one log)", len(b.Failures), orDash(k.user), k.src)
			desc := fmt.Sprintf(
				"On host %s, %d failed logons for %q from %s were written to one log, each within %s of the one before, "+
					"over %s of log time (%q to %q as written). The next successful logon for the same account from the same "+
					"address follows on line %d, at %q. This pattern is consistent with password guessing that then succeeded. "+
					"The log carries no year, so this is established from line order and the distances between stamps in this "+
					"one file; the calendar date is not known. It is a lead, not a verdict: a person mistyping a password "+
					"produces the same shape.",
				orDash(k.host), len(b.Failures), k.user, k.src, bruteForceGapWindow, span.Round(time.Second),
				first.ev.Extra[partialtime.KeyStamp], last.ev.Extra[partialtime.KeyStamp],
				succ.pos.Line, succ.ev.Extra[partialtime.KeyStamp])
			out = append(out, newFinding(succ.ev.CaseID, r.ID(), title, model.SeverityHigh, model.ConfidenceMedium,
				desc, []string{"T1110", "T1078"}, supporting))
		}
	}
	return out
}

// ---------- Web attack indicators in access logs ----------

type webAttackIndicators struct{}

func (webAttackIndicators) ID() string { return "web-attack-indicators" }

func (webAttackIndicators) Inputs() model.EventFilter {
	return model.EventFilter{Types: []string{model.EventWebRequest}}
}

// minRequests is how many requests of a kind from one source make a finding.
// A single hit on an admin page or a login URL is background noise on any
// public server; a scan or an injection attempt is reported at once.
var minRequests = map[string]int{webattack.AdminInterfaceProbe: 3}

func (r webAttackIndicators) Evaluate(events []model.Event) []model.Finding {
	type key struct{ host, src, category string }
	groups := map[key][]model.Event{}
	catsBySource := map[[2]string]map[string]bool{}
	for _, e := range byType(events, model.EventWebRequest) {
		for _, c := range webattack.Classify(e.Extra["uri"], e.Extra["user_agent"]) {
			k := key{e.Host, e.NetworkSource, c}
			groups[k] = append(groups[k], e)
			sk := [2]string{e.Host, e.NetworkSource}
			if catsBySource[sk] == nil {
				catsBySource[sk] = map[string]bool{}
			}
			catsBySource[sk][c] = true
		}
	}
	keys := make([]key, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.host != b.host {
			return a.host < b.host
		}
		if a.src != b.src {
			return a.src < b.src
		}
		return a.category < b.category
	})
	var out []model.Finding
	for _, k := range keys {
		reqs := groups[k]
		if len(reqs) < max(1, minRequests[k.category]) {
			continue
		}
		sort.SliceStable(reqs, func(i, j int) bool {
			if !reqs[i].Timestamp.Equal(reqs[j].Timestamp) {
				return reqs[i].Timestamp.Before(reqs[j].Timestamp)
			}
			return reqs[i].ID < reqs[j].ID
		})
		status := map[string]int{}
		any2xx := false
		for _, e := range reqs {
			status[statusClass(e.Extra["status"])]++
			if strings.HasPrefix(e.Extra["status"], "2") {
				any2xx = true
			}
		}
		sev, conf := model.SeverityMedium, model.ConfidenceLow
		switch k.category {
		case webattack.Scanner:
			sev, conf = model.SeverityLow, model.ConfidenceMedium
		case webattack.AdminInterfaceProbe:
			sev = model.SeverityLow
		case webattack.WebShell:
			if any2xx {
				sev = model.SeverityHigh
			}
		}
		if len(reqs) >= 5 || len(catsBySource[[2]string{k.host, k.src}]) >= 2 {
			if conf == model.ConfidenceLow {
				conf = model.ConfidenceMedium
			}
		}
		title := fmt.Sprintf("%d web requests resembling %s from %s", len(reqs), webattack.Label(k.category), orDash(k.src))
		desc := fmt.Sprintf(
			"Source %s sent %d request(s) to host %s between %s and %s whose %s resembles %s. Answers: %s. Example: %s. "+
				"A request of this shape is an attempt. The access log records the status the server returned, not what the "+
				"application did with the request: a 2xx answer does not prove the attack worked, and a 4xx answer does not "+
				"prove it failed.",
			orDash(k.src), len(reqs), orDash(k.host), fmtTime(reqs[0].Timestamp), fmtTime(reqs[len(reqs)-1].Timestamp),
			whatWasRead(k.category), webattack.Label(k.category), statusSummary(status), clipText(reqs[0].Extra["uri"], 160))
		out = append(out, newFinding(reqs[0].CaseID, r.ID(), title, sev, conf, desc,
			[]string{webattack.Technique(k.category)}, capEvents(reqs)))
	}
	return out
}

func whatWasRead(category string) string {
	if category == webattack.Scanner {
		return "user agent"
	}
	return "URL"
}

func statusClass(s string) string {
	if len(s) == 3 {
		return s[:1] + "xx"
	}
	return "no status"
}

func statusSummary(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + strconv.Itoa(m[k])
	}
	return strings.Join(parts, ", ")
}

func clipText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ---------- Account and group changes ----------

type accountChangeObserved struct{}

func (accountChangeObserved) ID() string { return "account-change-observed" }

func (accountChangeObserved) Inputs() model.EventFilter {
	return model.EventFilter{Types: []string{model.EventAccountChange}}
}

var privilegedGroupNames = map[string]bool{
	"administrators": true, "domain admins": true, "enterprise admins": true, "schema admins": true,
	"remote desktop users": true, "backup operators": true, "account operators": true,
	"sudo": true, "wheel": true, "admin": true, "root": true, "adm": true, "docker": true, "lxd": true,
}

// isServiceAccount reports a Linux account that looks created by a package:
// no login shell and an id in the system range. Package installs create
// these routinely, and reporting each would bury the accounts a person made.
func isServiceAccount(e model.Event) bool {
	shell := e.Extra["shell"]
	if shell == "" {
		return false
	}
	noLogin := strings.HasSuffix(shell, "/nologin") || strings.HasSuffix(shell, "/false")
	uid, err := strconv.Atoi(e.Extra["uid"])
	return noLogin && err == nil && uid > 0 && uid < 1000
}

func (r accountChangeObserved) Evaluate(events []model.Event) []model.Finding {
	var out []model.Finding
	for _, e := range byType(events, model.EventAccountChange) {
		action, name := e.Extra["action"], e.Extra["object_name"]
		var title, desc string
		sev, conf := model.SeverityLow, model.ConfidenceMedium
		var tech []string
		switch action {
		case "user_created":
			// Package-created service accounts and Windows computer
			// accounts (a trailing $, created whenever a machine joins a
			// domain) are routine and would bury the accounts a person made.
			if isServiceAccount(e) || strings.HasSuffix(name, "$") {
				continue
			}
			title = fmt.Sprintf("Local account created: %s", orDash(name))
			desc = fmt.Sprintf("The system recorded the creation of local account %q on host %s", name, orDash(e.Host))
			tech = []string{"T1136.001"}
			if e.Extra["uid"] == "0" {
				sev, conf = model.SeverityHigh, model.ConfidenceHigh
				desc += " with user id 0, which gives it root's rights"
			}
		case "group_member_added":
			group, member := name, e.Extra["member"]
			if !privilegedGroupNames[strings.ToLower(group)] {
				continue
			}
			sev = model.SeverityHigh
			title = fmt.Sprintf("Account added to privileged group %s: %s", group, orDash(member))
			desc = fmt.Sprintf("The system recorded %q being added to group %q on host %s, a group that grants administrative power or remote access", member, group, orDash(e.Host))
			tech = []string{"T1098"}
		default:
			continue
		}
		who := ""
		if e.User != "" {
			who = fmt.Sprintf(" by %q", e.User)
		}
		desc += who + ". The record shows the change was applied. It does not show who was entitled to request it; package installs and administrators create accounts routinely, so this is a lead to compare with what was expected on the host."
		out = append(out, newFinding(e.CaseID, r.ID(), title, sev, conf, desc, tech, []model.Event{e}))
	}
	return out
}

// ---------- Database service warnings ----------

type databaseInsecureAccount struct{}

func (databaseInsecureAccount) ID() string { return "database-insecure-account" }

func (databaseInsecureAccount) Inputs() model.EventFilter {
	return model.EventFilter{Types: []string{model.EventServiceMessage}}
}

func (r databaseInsecureAccount) Evaluate(events []model.Event) []model.Finding {
	byHost := map[string][]model.Event{}
	for _, e := range byType(events, model.EventServiceMessage) {
		if e.Extra["category"] == "database_insecure_account" {
			byHost[e.Host] = append(byHost[e.Host], e)
		}
	}
	hosts := make([]string, 0, len(byHost))
	for h := range byHost {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	var out []model.Finding
	for _, h := range hosts {
		ev := byHost[h]
		sort.SliceStable(ev, func(i, j int) bool {
			if ev[i].SourceFileID != ev[j].SourceFileID {
				return ev[i].SourceFileID < ev[j].SourceFileID
			}
			return lineOf(ev[i]) < lineOf(ev[j])
		})
		title := fmt.Sprintf("Database server reported administrator accounts without a password (%d times)", len(ev))
		desc := fmt.Sprintf(
			"On host %s the database server's own start-up check logged %d time(s) that administrator accounts have no password, "+
				"first as %q. An administrator account with no password lets anyone who can reach the database log in as an "+
				"administrator. The warning shows the weakness was present when the check ran. It does not show that anyone used "+
				"it, and the log carries no year, so how long it lasted is read from the number of warnings, not a date.",
			orDash(h), len(ev), ev[0].Extra["message"])
		out = append(out, newFinding(ev[0].CaseID, r.ID(), title, model.SeverityMedium, model.ConfidenceHigh,
			desc, []string{"T1078.001"}, capEvents(ev)))
	}
	return out
}

func lineOf(e model.Event) int {
	n, _ := strconv.Atoi(e.Extra[partialtime.KeyLine])
	return n
}

// ---------- Firewall, persistence and account commands ----------

type systemChangeCommand struct{}

func (systemChangeCommand) ID() string { return "system-change-command" }

func (systemChangeCommand) Inputs() model.EventFilter {
	return model.EventFilter{Types: []string{
		model.EventProcessCreate, model.EventPowerShellScript, model.EventPowerShellHistoryCommand,
		model.EventBashHistoryCommand, model.EventSudoCommand, model.EventScheduledJobRun, model.EventMemoryConsole,
	}}
}

func sevRank(s string) int {
	switch s {
	case cmdsem.High:
		return 3
	case cmdsem.Medium:
		return 2
	}
	return 1
}

// commandBasis says what the event type proves about the command, which is
// the whole difference in confidence between sources.
func commandBasis(eventType string) (basis string, conf string) {
	switch eventType {
	case model.EventSudoCommand:
		return "sudo authorised the command; the log does not show that it ran or succeeded", model.ConfidenceLow
	case model.EventBashHistoryCommand, model.EventPowerShellHistoryCommand:
		return "the shell history shows the command was typed; it does not show that it ran or succeeded", model.ConfidenceLow
	case model.EventScheduledJobRun:
		return "cron started the job; the log does not show its result", model.ConfidenceLow
	case model.EventMemoryConsole:
		return "a console still held the command in memory at capture, so it was typed there; the console does not show that it ran, succeeded, or when", model.ConfidenceLow
	default:
		return "the command line of a process that started; the record does not show that the change took effect", model.ConfidenceMedium
	}
}

func (r systemChangeCommand) Evaluate(events []model.Event) []model.Finding {
	type key struct{ host, user, category, actions, evType string }
	type group struct {
		events []model.Event
		sems   []cmdsem.Semantic
	}
	groups := map[key]*group{}
	for _, e := range events {
		switch e.EventType {
		case model.EventProcessCreate, model.EventPowerShellScript, model.EventPowerShellHistoryCommand,
			model.EventBashHistoryCommand, model.EventSudoCommand, model.EventScheduledJobRun, model.EventMemoryConsole:
		default:
			continue
		}
		sems := cmdsem.Analyze(e.CommandLine)
		if len(sems) == 0 {
			continue
		}
		byCat := map[string][]cmdsem.Semantic{}
		for _, s := range sems {
			byCat[s.Category] = append(byCat[s.Category], s)
		}
		for cat, ss := range byCat {
			acts := make([]string, len(ss))
			for i, s := range ss {
				acts[i] = s.Action
			}
			sort.Strings(acts)
			k := key{e.Host, e.User, cat, strings.Join(acts, "+"), e.EventType}
			g := groups[k]
			if g == nil {
				g = &group{sems: ss}
				groups[k] = g
			}
			g.events = append(g.events, e)
		}
	}
	keys := make([]key, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.host != b.host {
			return a.host < b.host
		}
		if a.user != b.user {
			return a.user < b.user
		}
		if a.category != b.category {
			return a.category < b.category
		}
		if a.actions != b.actions {
			return a.actions < b.actions
		}
		return a.evType < b.evType
	})
	catTitle := map[string]string{cmdsem.Firewall: "Firewall change", cmdsem.Persistence: "Persistence mechanism", cmdsem.Account: "Account change"}
	var out []model.Finding
	for _, k := range keys {
		g := groups[k]
		sort.SliceStable(g.events, func(i, j int) bool {
			if !g.events[i].Timestamp.Equal(g.events[j].Timestamp) {
				return g.events[i].Timestamp.Before(g.events[j].Timestamp)
			}
			return g.events[i].ID < g.events[j].ID
		})
		worst := cmdsem.Low
		techSet := map[string]bool{}
		var details []string
		for _, s := range g.sems {
			if sevRank(s.Severity) > sevRank(worst) {
				worst = s.Severity
			}
			techSet[s.Technique] = true
			details = append(details, s.Detail)
		}
		var tech []string
		for t := range techSet {
			tech = append(tech, t)
		}
		sort.Strings(tech)
		sev := model.SeverityLow
		switch worst {
		case cmdsem.High:
			sev = model.SeverityHigh
		case cmdsem.Medium:
			sev = model.SeverityMedium
		}
		basis, conf := commandBasis(k.evType)
		first := g.events[0]
		times := ""
		if !first.Timestamp.IsZero() {
			times = fmt.Sprintf(" first at %s", fmtTime(first.Timestamp))
		} else if st := first.Extra[partialtime.KeyStamp]; st != "" {
			times = fmt.Sprintf(" first at %q (no year in the log)", st)
		}
		title := fmt.Sprintf("%s: %s", catTitle[k.category], strings.Join(details, "; "))
		if n := len(g.events); n > 1 {
			title += fmt.Sprintf(" (x%d)", n)
		}
		desc := fmt.Sprintf(
			"Account %q on host %s ran a command that %s, seen %d time(s)%s. Command: %s. Evidence basis: %s. "+
				"Administrators make these changes as routinely as attackers do, so this is a lead to compare with what was "+
				"authorised on the host.",
			orDash(k.user), orDash(k.host), strings.ToLower(strings.Join(details, "; ")), len(g.events), times,
			clipText(cmdsem.Redact(first.CommandLine), 240), basis)
		out = append(out, newFinding(first.CaseID, r.ID(), title, sev, conf, desc, tech, capEvents(g.events)))
	}
	return out
}
