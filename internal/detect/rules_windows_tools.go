package detect

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"tracefall/internal/cmdsem"
	"tracefall/internal/model"
)

// Rules over two Windows tool artifacts that attackers use to fetch files with
// signed Microsoft binaries: the CryptoAPI URL cache (certutil -urlcache -f) and
// MpCmdRun.exe -DownloadFile. Both findings are leads: the artifacts show that a
// URL was retrieved or that a command was run, not what the file did afterwards.

func windowsToolRules() []Rule {
	return []Rule{cryptnetExecutableRetrieval{}, defenderMpCmdRunMisuse{}, avThreatDetected{}}
}

// ---------- cryptnet-executable-retrieval ----------

type cryptnetExecutableRetrieval struct{}

func (cryptnetExecutableRetrieval) ID() string { return "cryptnet-executable-retrieval" }

func (cryptnetExecutableRetrieval) Inputs() model.EventFilter {
	return model.EventFilter{Types: []string{model.EventCryptoURLRetrieval}}
}

// fetchedExt is the file name endings that make a retrieved URL worth a look when
// the cached object itself is not there to be examined.
var fetchedExt = regexp.MustCompile(`(?i)\.(?:exe|dll|scr|sys|msi|ps1|bat|cmd|vbs|vbe|js|jse|hta|jar|zip|7z|rar|iso|lnk)$`)

func urlPath(u string) string {
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		u = u[:i]
	}
	return u
}

func (r cryptnetExecutableRetrieval) Evaluate(events []model.Event) []model.Finding {
	type key struct{ caseID, url string }
	groups := map[key][]model.Event{}
	for _, e := range events {
		if e.EventType != model.EventCryptoURLRetrieval {
			continue
		}
		k := key{e.CaseID, e.Extra["url"]}
		groups[k] = append(groups[k], e)
	}
	keys := make([]key, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].caseID != keys[j].caseID {
			return keys[i].caseID < keys[j].caseID
		}
		return keys[i].url < keys[j].url
	})
	var out []model.Finding
	for _, k := range keys {
		es := groups[k]
		ctr := func(l []model.Event) {
			sort.SliceStable(l, func(i, j int) bool {
				if !l[i].Timestamp.Equal(l[j].Timestamp) {
					return l[i].Timestamp.Before(l[j].Timestamp)
				}
				return l[i].ID < l[j].ID
			})
		}
		ctr(es)
		e := es[0]
		magic, present := e.Extra["content_magic"], e.Extra["content_present"] == "true"
		sev, conf := "", model.ConfidenceMedium
		basis := ""
		switch {
		case present && magic == "pe":
			sev, basis = model.SeverityHigh, "the cached object starts with an executable header (MZ)"
		case present && (magic == "zip" || magic == "7z" || magic == "rar" || magic == "elf"):
			sev, basis = model.SeverityMedium, "the cached object is an "+magic+" file"
		case (!present || magic == "" || magic == "text" || magic == "unknown") && fetchedExt.MatchString(urlPath(k.url)):
			sev, conf = model.SeverityMedium, model.ConfidenceLow
			if present && magic != "" {
				basis = "the URL ends like a program or script and the cached object is " + magic
			} else {
				basis = "the URL ends like a program, script or archive; the cached object is not available, so its type is not known"
			}
		default:
			continue
		}
		urlText := cmdsem.Redact(k.url)
		host := e.Extra["url_host"]
		hash := ""
		if h := e.Extra["content_sha256"]; h != "" {
			hash = fmt.Sprintf(" Its SHA-256 is %s.", h)
		}
		profile := ""
		if p := e.Extra["cache_profile"]; p != "" {
			profile = fmt.Sprintf(" The entry is in the %s profile's cache.", p)
		}
		title := fmt.Sprintf("A file was retrieved through the Windows CryptoAPI URL cache from %s", orDash(host))
		desc := fmt.Sprintf(
			"The CryptoAPI URL cache holds an entry for %s, last retrieved at %s (%d entr%s). Why it is reported: %s.%s%s "+
				"Limits: an entry shows that Windows retrieved the URL and when; it does not name the program that asked. certutil -urlcache -f is one way to produce it, "+
				"and so is Windows validating a certificate, which is why only executables, archives and program-like names are reported. "+
				"Whether the file was run is a separate question: look for execution evidence for the cached object. This is a lead, not a verdict.",
			urlText, fmtTime(e.Timestamp), len(es), map[bool]string{true: "y", false: "ies"}[len(es) == 1], basis, hash, profile)
		out = append(out, newFinding(e.CaseID, r.ID(), title, sev, conf, desc, []string{"T1105"}, es))
	}
	return out
}

// ---------- defender-mpcmdrun-misuse ----------

type defenderMpCmdRunMisuse struct{}

func (defenderMpCmdRunMisuse) ID() string { return "defender-mpcmdrun-misuse" }

func (defenderMpCmdRunMisuse) Inputs() model.EventFilter {
	return model.EventFilter{Types: []string{model.EventDefenderCommand}}
}

func hasToken(cmd, want string) bool {
	for _, t := range strings.Fields(cmd) {
		if strings.EqualFold(strings.Trim(t, `"`), want) {
			return true
		}
	}
	return false
}

func (r defenderMpCmdRunMisuse) Evaluate(events []model.Event) []model.Finding {
	var runs []model.Event
	for _, e := range events {
		if e.EventType == model.EventDefenderCommand {
			runs = append(runs, e)
		}
	}
	sort.SliceStable(runs, func(i, j int) bool {
		a, b := runs[i], runs[j]
		if a.CaseID != b.CaseID {
			return a.CaseID < b.CaseID
		}
		if a.Extra["timestamp_local"] != b.Extra["timestamp_local"] {
			return a.Extra["timestamp_local"] < b.Extra["timestamp_local"]
		}
		return a.ID < b.ID
	})
	var out []model.Finding
	for _, e := range runs {
		cmd := e.Extra["command_line"]
		when := "its local time " + e.Extra["timestamp_local"] + " (the log records no zone)"
		if u := e.Extra["timestamp_utc"]; u != "" {
			when = u + " UTC (" + e.Extra["timestamp_utc_basis"] + ")"
		}
		if e.Extra["timestamp_local"] == "" && e.Extra["timestamp_utc"] == "" {
			when = "a time the log does not give in a form this tool reads"
		}
		switch {
		case hasToken(cmd, "-DownloadFile"):
			url, path := cmdsem.Redact(e.Extra["download_url"]), cmdsem.Redact(e.Extra["download_path"])
			title := "MpCmdRun.exe was run with -DownloadFile"
			desc := fmt.Sprintf(
				"The Defender command-line tool's own log records a run with -DownloadFile at %s. URL: %s. Destination: %s. "+
					"MpCmdRun.exe is a signed Microsoft binary and -DownloadFile makes it fetch a file, a known way to bring a tool onto a host without a download program. "+
					"Limits: the log shows the command, not that the download succeeded or that the file was used; check whether a file exists at the destination and whether it ran. This is a lead, not a verdict.",
				when, orDash(url), orDash(path))
			out = append(out, newFinding(e.CaseID, r.ID(), title, model.SeverityHigh, model.ConfidenceMedium, desc, []string{"T1105"}, []model.Event{e}))
		case hasToken(cmd, "-RemoveDefinitions") && hasToken(cmd, "-All"):
			title := "MpCmdRun.exe was run to remove all Defender signatures"
			desc := fmt.Sprintf(
				"The Defender command-line tool's own log records a run with -RemoveDefinitions -All at %s, which deletes every signature set and leaves Defender unable to detect until they are replaced. "+
					"Limits: administrators also run this to repair a broken update, and the log does not show the outcome. Compare it with what happened on the host next. This is a lead, not a verdict.", when)
			out = append(out, newFinding(e.CaseID, r.ID(), title, model.SeverityMedium, model.ConfidenceMedium, desc, []string{"T1562"}, []model.Event{e}))
		}
	}
	return out
}
