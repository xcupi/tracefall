package detect

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"tracefall/internal/cmdsem"
	"tracefall/internal/model"
)

// SQL Server rules over the events the mssql, winevent and mssqlxe parsers
// produce.
//
// Two time forms meet here. The Windows Application log gives real
// instants. The text logs (ERRORLOG, SQLAGENT.OUT) have no zone: their events
// keep a zero Timestamp and the full local reading in Extra["timestamp_local"].
// Within ONE source file a single clock applies, so order and distance are
// computed from that reading; it is parsed into a zone-less value used only
// for arithmetic and is never printed as an instant. Undated events from
// different files are never compared, and a dated event is never compared
// with an undated one.

func sqlRules() []Rule {
	return []Rule{sqlLoginFailureBurst{}, sqlRiskyConfigEnabled{}, sqlDisabledComponentAttempt{}, sqlAuditStoppedWhileRunning{}}
}

const (
	sqlBurstMinFailures = 5
	sqlBurstGap         = 2 * time.Minute
	sqlSuccessWindow    = 30 * time.Minute
	sqlNamesListed      = 10
)

// ---------- shared placement helpers ----------

type sqlPlaced struct {
	ev       model.Event
	local    time.Time // zone-less reading, arithmetic only; zero when unparsable
	hasLocal bool
	line     int // 1-based source line, 0 when unknown
}

func sqlPlace(e model.Event) sqlPlaced {
	p := sqlPlaced{ev: e}
	if e.Timestamp.IsZero() {
		if s := strings.Replace(strings.TrimSpace(e.Extra["timestamp_local"]), "T", " ", 1); s != "" {
			if t, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
				p.local, p.hasLocal = t, true
			}
		}
	}
	ref := e.Extra["line_number"]
	if strings.HasPrefix(e.SourceReference, "line:") {
		ref = e.SourceReference[len("line:"):]
	}
	if n, err := strconv.Atoi(ref); err == nil && n > 0 {
		p.line = n
	}
	return p
}

func (p sqlPlaced) dated() bool { return !p.ev.Timestamp.IsZero() }

// sqlScope names the clock an event belongs to: a source file for undated
// events, a host and instance for dated ones. An undated event with no source
// file belongs to no shared clock, so it gets a scope of its own.
func sqlScope(e model.Event) string {
	if !e.Timestamp.IsZero() {
		return "dated|" + e.CaseID + "|" + e.Host + "|" + e.Extra["instance"]
	}
	if e.SourceFileID == "" {
		return "alone|" + e.ID
	}
	return "file|" + e.CaseID + "|" + e.SourceFileID
}

// sqlLess is the one order used everywhere: instant, then local reading, then
// line, then ID. Events with an unparsable reading sort after those with one.
func sqlLess(a, b sqlPlaced) bool {
	if !a.ev.Timestamp.Equal(b.ev.Timestamp) {
		return a.ev.Timestamp.Before(b.ev.Timestamp)
	}
	if a.hasLocal != b.hasLocal {
		return a.hasLocal
	}
	if a.hasLocal && !a.local.Equal(b.local) {
		return a.local.Before(b.local)
	}
	if a.line != b.line {
		return a.line < b.line
	}
	return a.ev.ID < b.ev.ID
}

// sqlGap is the distance from a to b (a sorted before b, same scope). It is
// unknown for undated events without a parsable reading.
func sqlGap(a, b sqlPlaced) (time.Duration, bool) {
	if a.dated() != b.dated() {
		return 0, false
	}
	if a.dated() {
		return b.ev.Timestamp.Sub(a.ev.Timestamp), true
	}
	if !a.hasLocal || !b.hasLocal {
		return 0, false
	}
	return b.local.Sub(a.local), true
}

// sqlAfter reports whether b was written strictly after a. Two events with
// equal readings are ordered only when both carry a line number; equal
// instants carry no order.
func sqlAfter(a, b sqlPlaced) bool {
	if a.dated() != b.dated() {
		return false
	}
	if a.dated() {
		return b.ev.Timestamp.After(a.ev.Timestamp)
	}
	if !a.hasLocal || !b.hasLocal {
		return false
	}
	if b.local.After(a.local) {
		return true
	}
	return b.local.Equal(a.local) && a.line > 0 && b.line > a.line
}

// sqlWhen renders an event time for finding text. A dated event gets its
// instant; an undated one gets its local reading with the basis stated; one
// with neither is "time not recorded".
func sqlWhen(p sqlPlaced) string {
	if p.dated() {
		return fmtTime(p.ev.Timestamp)
	}
	if raw := strings.TrimSpace(p.ev.Extra["timestamp_local"]); raw != "" {
		basis := strings.TrimSpace(p.ev.Extra["timestamp_basis"])
		if basis == "" {
			basis = "basis not recorded"
		}
		return fmt.Sprintf("%s [%s]", raw, basis)
	}
	return fmtTime(time.Time{})
}

// sqlText is the message text of an event, from whichever form carries it.
func sqlText(e model.Event) string {
	for _, k := range []string{"message", "sql_data.Message", "rendered_description"} {
		if s := e.Extra[k]; s != "" {
			return s
		}
	}
	return ""
}

func sqlPlaceAll(events []model.Event, types ...string) map[string][]sqlPlaced {
	want := map[string]bool{}
	for _, t := range types {
		want[t] = true
	}
	out := map[string][]sqlPlaced{}
	for _, e := range events {
		if want[e.EventType] {
			k := sqlScope(e)
			out[k] = append(out[k], sqlPlace(e))
		}
	}
	for _, l := range out {
		l := l
		sort.Slice(l, func(i, j int) bool { return sqlLess(l[i], l[j]) })
	}
	return out
}

func sqlSortedKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sqlEvents(l []sqlPlaced) []model.Event {
	out := make([]model.Event, len(l))
	for i, p := range l {
		out[i] = p.ev
	}
	return out
}

func sqlPlural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// ---------- sql-login-failure-burst ----------

type sqlLoginFailureBurst struct{}

func (sqlLoginFailureBurst) ID() string { return "sql-login-failure-burst" }

func (sqlLoginFailureBurst) Inputs() model.EventFilter {
	return model.EventFilter{Types: []string{model.EventSQLLoginFailed, model.EventSQLLoginSuccess}}
}

var sqlReasonRe = regexp.MustCompile(`(?i)Reason:\s*(.*?)\s*(?:\[CLIENT:|$)`)

func sqlClient(e model.Event) string {
	if e.NetworkSource != "" {
		return e.NetworkSource
	}
	return e.Extra["client"]
}

func sqlLogin(e model.Event) string {
	if l := e.Extra["login"]; l != "" {
		return l
	}
	return e.User
}

func sqlReason(e model.Event) string {
	if m := sqlReasonRe.FindStringSubmatch(sqlText(e)); m != nil {
		if r := strings.TrimRight(strings.TrimSpace(m[1]), "."); r != "" {
			return r
		}
	}
	return "reason not recorded"
}

func (r sqlLoginFailureBurst) Evaluate(events []model.Event) []model.Finding {
	type key struct{ scope, client string }
	failures := map[key][]sqlPlaced{}
	successes := map[key][]sqlPlaced{}
	for _, e := range events {
		client := sqlClient(e)
		if client == "" {
			continue
		}
		k := key{sqlScope(e), client}
		switch e.EventType {
		case model.EventSQLLoginFailed:
			failures[k] = append(failures[k], sqlPlace(e))
		case model.EventSQLLoginSuccess:
			successes[k] = append(successes[k], sqlPlace(e))
		}
	}
	keys := make([]key, 0, len(failures))
	for k := range failures {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].scope != keys[j].scope {
			return keys[i].scope < keys[j].scope
		}
		return keys[i].client < keys[j].client
	})
	var out []model.Finding
	for _, k := range keys {
		list := failures[k]
		sort.Slice(list, func(i, j int) bool { return sqlLess(list[i], list[j]) })
		succ := successes[k]
		sort.Slice(succ, func(i, j int) bool { return sqlLess(succ[i], succ[j]) })
		start := 0
		for i := 1; i <= len(list); i++ {
			if i < len(list) {
				if g, ok := sqlGap(list[i-1], list[i]); ok && g <= sqlBurstGap {
					continue
				}
			}
			if i-start >= sqlBurstMinFailures {
				out = append(out, r.finding(k.client, list[start:i], succ))
			}
			start = i
		}
	}
	return out
}

func (r sqlLoginFailureBurst) finding(client string, run []sqlPlaced, successes []sqlPlaced) model.Finding {
	first, last := run[0], run[len(run)-1]
	logins := map[string]bool{}
	reasons := map[string]int{}
	missing := map[string]bool{}
	for _, p := range run {
		l := sqlLogin(p.ev)
		logins[l] = true
		reason := sqlReason(p.ev)
		reasons[reason]++
		if strings.Contains(strings.ToLower(reason), "could not find a login matching") {
			missing[l] = true
		}
	}
	names := sqlSortedKeys(logins)
	shown := names
	if len(shown) > sqlNamesListed {
		shown = shown[:sqlNamesListed]
	}
	quoted := make([]string, len(shown))
	for i, n := range shown {
		quoted[i] = "'" + cmdsem.Redact(n) + "'"
	}
	more := ""
	if len(names) > len(shown) {
		more = fmt.Sprintf(" (first %d of %d, sorted)", len(shown), len(names))
	}
	type rc struct {
		reason string
		n      int
	}
	var rcs []rc
	for reason, n := range reasons {
		rcs = append(rcs, rc{reason, n})
	}
	sort.Slice(rcs, func(i, j int) bool {
		if rcs[i].n != rcs[j].n {
			return rcs[i].n > rcs[j].n
		}
		return rcs[i].reason < rcs[j].reason
	})
	parts := make([]string, len(rcs))
	for i, c := range rcs {
		parts[i] = fmt.Sprintf("%s (%d)", cmdsem.Redact(c.reason), c.n)
	}

	confidence := model.ConfidenceMedium
	if len(logins) >= 2 || len(missing) >= 3 {
		confidence = model.ConfidenceHigh
	}

	var follow *sqlPlaced
	for i := range successes {
		s := successes[i]
		if !logins[sqlLogin(s.ev)] || !sqlAfter(last, s) {
			continue
		}
		if g, ok := sqlGap(last, s); ok && g <= sqlSuccessWindow {
			follow = &successes[i]
			break
		}
	}

	severity := model.SeverityMedium
	title := fmt.Sprintf("%d failed SQL Server logins from %s", len(run), client)
	followText := ""
	supporting := capEvents(sqlEvents(run))
	if follow != nil {
		severity = model.SeverityHigh
		title += " followed by a successful login from the same client"
		followText = fmt.Sprintf(" Within %s of the last failure, a successful login from the same client follows (login '%s', at %s). "+
			"It matches the client address and one of the failed names; that does not show a guess worked.",
			sqlSuccessWindow, cmdsem.Redact(sqlLogin(follow.ev)), sqlWhen(*follow))
		supporting = append(supporting, follow.ev)
	}
	desc := fmt.Sprintf(
		"%d failed SQL Server logins from client %s, each within %s of the one before, from %s to %s. "+
			"%d distinct login %s: %s%s. Reasons recorded: %s.%s "+
			"Limits: these are failed attempts recorded by the engine. The ERRORLOG does not record successful logins by default, "+
			"so nothing here shows whether a guess later worked. The client address can be a proxy or container gateway, "+
			"so it may not be the real origin. For logs with no zone, order and distance come from the local reading inside one "+
			"file only. A person mistyping a password produces a similar shape. This is a lead, not a verdict.",
		len(run), client, sqlBurstGap, sqlWhen(first), sqlWhen(last),
		len(names), sqlPlural(len(names), "name", "names"), strings.Join(quoted, ", "), more,
		strings.Join(parts, "; "), followText)
	return newFinding(first.ev.CaseID, r.ID(), title, severity, confidence, desc, []string{"T1110"}, supporting)
}

// ---------- sql-risky-config-enabled ----------

type sqlRiskyConfigEnabled struct{}

func (sqlRiskyConfigEnabled) ID() string { return "sql-risky-config-enabled" }

func (sqlRiskyConfigEnabled) Inputs() model.EventFilter {
	return model.EventFilter{Types: []string{model.EventSQLMessage}}
}

var sqlConfigRe = regexp.MustCompile(`(?i)Configuration option '([^']+)' changed from (\d+) to (\d+)`)

// sqlRiskyOptions maps a lower-cased option name to its severity. Options not
// listed (show advanced options, Agent XPs, and every other setting) are routine.
var sqlRiskyOptions = map[string]string{
	"xp_cmdshell":                 model.SeverityMedium,
	"ole automation procedures":   model.SeverityMedium,
	"external scripts enabled":    model.SeverityMedium,
	"ad hoc distributed queries":  model.SeverityMedium,
	"clr enabled":                 model.SeverityLow,
	"clr strict security":         model.SeverityLow, // risky only when turned off
	"database mail xps":           model.SeverityLow,
	"cross db ownership chaining": model.SeverityLow,
	"remote admin connections":    model.SeverityLow,
	"scan for startup procs":      model.SeverityLow,
}

func (r sqlRiskyConfigEnabled) Evaluate(events []model.Event) []model.Finding {
	groups := sqlPlaceAll(events, model.EventSQLMessage)
	var out []model.Finding
	for _, scope := range sqlSortedKeys(groups) {
		for _, p := range groups[scope] {
			m := sqlConfigRe.FindStringSubmatch(sqlText(p.ev))
			if m == nil {
				continue
			}
			opt := strings.ToLower(strings.TrimSpace(m[1]))
			sev, listed := sqlRiskyOptions[opt]
			if !listed {
				continue
			}
			from, _ := strconv.Atoi(m[2])
			to, _ := strconv.Atoi(m[3])
			strict := opt == "clr strict security"
			if from == to || (strict && to != 0) || (!strict && to == 0) {
				continue
			}
			what := fmt.Sprintf("configuration option '%s' was changed from %d to %d", m[1], from, to)
			ttp := []string{"T1059"}
			if strict {
				what = fmt.Sprintf("CLR strict security was disabled: option '%s' was changed from %d to %d, which lets assemblies run without the signing requirement", m[1], from, to)
				ttp = []string{"T1562"}
			}
			title := fmt.Sprintf("SQL Server option %s changed from %d to %d", m[1], from, to)
			desc := fmt.Sprintf(
				"On host %s, SQL Server recorded that %s (at %s); the message says a RECONFIGURE statement installs it. "+
					"The log records that the change was applied. It does not show who made the change or from where, or whether the "+
					"feature was used afterwards; absence of later records is not evidence it went unused. Administrators change these "+
					"options for legitimate work too, so this is a lead to check against change records.",
				orDash(p.ev.Host), what, sqlWhen(p))
			out = append(out, newFinding(p.ev.CaseID, r.ID(), title, sev, model.ConfidenceHigh, desc, ttp, []model.Event{p.ev}))
		}
	}
	return out
}

// ---------- sql-disabled-component-attempt ----------

type sqlDisabledComponentAttempt struct{}

func (sqlDisabledComponentAttempt) ID() string { return "sql-disabled-component-attempt" }

func (sqlDisabledComponentAttempt) Inputs() model.EventFilter {
	return model.EventFilter{Types: []string{model.EventSQLMessage}}
}

var sqlBlockedRe = regexp.MustCompile(`(?i)SQL Server blocked access to procedure '([^']+)' of component '([^']+)'`)

func (r sqlDisabledComponentAttempt) Evaluate(events []model.Event) []model.Finding {
	groups := sqlPlaceAll(events, model.EventSQLMessage)
	var out []model.Finding
	for _, scope := range sqlSortedKeys(groups) {
		byProc := map[string][]sqlPlaced{}
		component := map[string]string{}
		procName := map[string]string{}
		for _, p := range groups[scope] {
			m := sqlBlockedRe.FindStringSubmatch(sqlText(p.ev))
			if m == nil {
				continue
			}
			k := strings.ToLower(m[1])
			byProc[k] = append(byProc[k], p)
			if _, ok := procName[k]; !ok {
				procName[k], component[k] = m[1], m[2]
			}
		}
		for _, k := range sqlSortedKeys(byProc) {
			list := byProc[k]
			first, last := list[0], list[len(list)-1]
			title := fmt.Sprintf("SQL Server blocked %d %s to use %s", len(list), sqlPlural(len(list), "attempt", "attempts"), cmdsem.Redact(procName[k]))
			desc := fmt.Sprintf(
				"On host %s, SQL Server recorded %d %s that access to procedure '%s' of component '%s' was blocked because the component "+
					"is turned off (first at %s, last at %s). An attempt to use a disabled component was recorded and blocked. "+
					"Blocked means it did not run on this instance at that time. The message says nothing about who or what made "+
					"the call, or which statement; routine tools can trigger it too. It does not show whether the component was "+
					"enabled and used before or after.",
				orDash(first.ev.Host), len(list), sqlPlural(len(list), "time", "times"),
				cmdsem.Redact(procName[k]), cmdsem.Redact(component[k]), sqlWhen(first), sqlWhen(last))
			out = append(out, newFinding(first.ev.CaseID, r.ID(), title, model.SeverityLow, model.ConfidenceMedium, desc,
				[]string{"T1059"}, capEvents(sqlEvents(list))))
		}
	}
	return out
}

// ---------- sql-audit-stopped-while-running ----------

type sqlAuditStoppedWhileRunning struct{}

func (sqlAuditStoppedWhileRunning) ID() string { return "sql-audit-stopped-while-running" }

func (sqlAuditStoppedWhileRunning) Inputs() model.EventFilter {
	return model.EventFilter{Types: []string{model.EventSQLMessage, model.EventSQLLoginFailed, model.EventSQLLoginSuccess}}
}

var (
	sqlAuditStopRe = regexp.MustCompile(`(?i)Audit: Server Audit: (\d+),\s*State changed from: STARTED to: (SHUTTING_DOWN|STOPPED)`)
	// Messages that belong to an instance shutting down; they continue after
	// the audits stop on a normal stop.
	sqlShutdownRe = regexp.MustCompile(`(?i)terminat|shut ?down|shutting down|deregister|service control manager|was stopped|has been stopped`)
)

func sqlIsAuditText(s string) bool {
	l := strings.ToLower(strings.TrimSpace(s))
	return strings.HasPrefix(l, "audit:") || strings.Contains(l, "sql server audit")
}

func (r sqlAuditStoppedWhileRunning) Evaluate(events []model.Event) []model.Finding {
	groups := sqlPlaceAll(events, model.EventSQLMessage, model.EventSQLLoginFailed, model.EventSQLLoginSuccess)
	var out []model.Finding
	for _, scope := range sqlSortedKeys(groups) {
		list := groups[scope]
		for _, stop := range list {
			if stop.ev.EventType != model.EventSQLMessage {
				continue
			}
			m := sqlAuditStopRe.FindStringSubmatch(sqlText(stop.ev))
			if m == nil {
				continue
			}
			var later []sqlPlaced
			for _, p := range list {
				text := sqlText(p.ev)
				if sqlIsAuditText(text) || sqlShutdownRe.MatchString(text) || !sqlAfter(stop, p) {
					continue
				}
				later = append(later, p)
			}
			if len(later) == 0 {
				continue
			}
			firstLater, lastLater := later[0], later[len(later)-1]
			supporting := []model.Event{stop.ev, firstLater.ev}
			if lastLater.ev.ID != firstLater.ev.ID {
				supporting = append(supporting, lastLater.ev)
			}
			title := fmt.Sprintf("SQL Server audit %s stopped while the log continues", m[1])
			desc := fmt.Sprintf(
				"On host %s, a Server Audit (id %s) state change from STARTED to %s was recorded at %s, and %d later engine %s "+
					"that %s not shutdown messages follow in the same log (first at %s, last at %s). A normal instance shutdown also "+
					"stops audits, which is why this only fires when the log continues afterwards. The record does not show who stopped "+
					"the audit or why, nor whether auditing was restarted by another route; maintenance can stop an audit too. "+
					"Order is taken from this one log's own readings and line order. This is a low-confidence lead.",
				orDash(stop.ev.Host), m[1], strings.ToUpper(m[2]), sqlWhen(stop), len(later), sqlPlural(len(later), "record", "records"),
				sqlPlural(len(later), "is", "are"), sqlWhen(firstLater), sqlWhen(lastLater))
			out = append(out, newFinding(stop.ev.CaseID, r.ID(), title, model.SeverityLow, model.ConfidenceLow, desc,
				[]string{"T1562"}, supporting))
		}
	}
	return out
}
