package detect

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"tracefall/internal/cmdsem"
	"tracefall/internal/model"
)

// Rules over container engine files and Grafana. They read what the parsers
// recorded: Grafana request lines (as web_request events), rows of grafana.db,
// and a container's stored configuration. None of them observes what ran inside
// a container, and each finding says so.

func containerRules() []Rule {
	return []Rule{grafanaLoginFailureBurst{}, grafanaExtraServerAdmin{}, grafanaDatasourceCredential{}, containerRiskyConfiguration{}, containerSecretInEnvironment{}}
}

func ctrByTimeThenID(l []model.Event) {
	sort.SliceStable(l, func(i, j int) bool {
		if !l[i].Timestamp.Equal(l[j].Timestamp) {
			return l[i].Timestamp.Before(l[j].Timestamp)
		}
		return l[i].ID < l[j].ID
	})
}

// ---------- grafana-login-failure-burst ----------

type grafanaLoginFailureBurst struct{}

func (grafanaLoginFailureBurst) ID() string { return "grafana-login-failure-burst" }

func (grafanaLoginFailureBurst) Inputs() model.EventFilter {
	return model.EventFilter{Types: []string{model.EventWebRequest, model.EventGrafanaSession}}
}

const (
	grafanaBurstMin    = 5
	grafanaBurstGap    = 2 * time.Minute
	grafanaSessionWait = 30 * time.Minute
)

func grafanaSource(artifact string) string {
	switch artifact {
	case model.ArtifactContainerLog:
		return "container log"
	case model.ArtifactGrafanaLog:
		return "grafana.log"
	}
	return artifact
}

// grafanaLoginFailure is a Grafana POST /login answered 401. The handler field
// is what ties the request to Grafana: an access log from another application
// with a /login path is not claimed.
func grafanaLoginFailure(e model.Event) bool {
	return e.EventType == model.EventWebRequest && e.Extra["status"] == "401" &&
		strings.EqualFold(e.Extra["method"], "POST") && e.Extra["grafana_handler"] == "/login" &&
		e.NetworkSource != "" && !e.Timestamp.IsZero()
}

func (r grafanaLoginFailureBurst) Evaluate(events []model.Event) []model.Finding {
	type key struct{ caseID, host, artifact, addr string }
	fails := map[key][]model.Event{}
	sessions := map[string][]model.Event{}
	for _, e := range events {
		switch {
		case grafanaLoginFailure(e):
			k := key{e.CaseID, e.Host, e.ArtifactType, e.NetworkSource}
			fails[k] = append(fails[k], e)
		case e.EventType == model.EventGrafanaSession && e.Extra["client_ip"] != "" && !e.Timestamp.IsZero():
			sessions[e.CaseID] = append(sessions[e.CaseID], e)
		}
	}
	keys := make([]key, 0, len(fails))
	for k := range fails {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.caseID != b.caseID {
			return a.caseID < b.caseID
		}
		if a.host != b.host {
			return a.host < b.host
		}
		if a.artifact != b.artifact {
			return a.artifact < b.artifact
		}
		return a.addr < b.addr
	})
	var out []model.Finding
	for _, k := range keys {
		list := fails[k]
		ctrByTimeThenID(list)
		ss := sessions[k.caseID]
		ctrByTimeThenID(ss)
		start := 0
		for i := 1; i <= len(list); i++ {
			if i < len(list) && list[i].Timestamp.Sub(list[i-1].Timestamp) <= grafanaBurstGap {
				continue
			}
			if i-start >= grafanaBurstMin {
				out = append(out, r.finding(k.addr, list[start:i], ss))
			}
			start = i
		}
	}
	return out
}

func (r grafanaLoginFailureBurst) finding(addr string, run []model.Event, sessions []model.Event) model.Finding {
	first, last := run[0], run[len(run)-1]
	severity := model.SeverityMedium
	supporting := capEvents(run)
	title := fmt.Sprintf("%d failed Grafana logins from %s", len(run), addr)
	follow := ""
	for _, s := range sessions {
		if s.Extra["client_ip"] == addr && s.Timestamp.After(last.Timestamp) && s.Timestamp.Sub(last.Timestamp) <= grafanaSessionWait {
			severity = model.SeverityHigh
			title += " followed by a session from the same address"
			follow = fmt.Sprintf(" Within %s of the last failure, a session was created from the same address (at %s, in Grafana's database). "+
				"It matches the address only; it does not show that a guess worked, or which account the session belongs to.", grafanaSessionWait, fmtTime(s.Timestamp))
			supporting = append(supporting, s)
			break
		}
	}
	desc := fmt.Sprintf(
		"%d failed Grafana logins (POST /login answered 401) from %s, as recorded in the %s, each within %s of the one before, from %s to %s.%s "+
			"Limits: Grafana's default log does not record which account was tried, so the names are unknown here; its database lists attempts only for accounts "+
			"that exist and prunes old rows, so it cannot fill that in. The address can be a proxy or a container network gateway. "+
			"The same requests can appear in the container log and in grafana.log; counts from different sources are not added together, "+
			"so a second finding for this address can describe the same attempts. A person mistyping a password produces a similar shape. This is a lead, not a verdict.",
		len(run), addr, grafanaSource(first.ArtifactType), grafanaBurstGap, fmtTime(first.Timestamp), fmtTime(last.Timestamp), follow)
	return newFinding(first.CaseID, r.ID(), title, severity, model.ConfidenceMedium, desc, []string{"T1110"}, supporting)
}

// ---------- grafana-extra-server-admin ----------

type grafanaExtraServerAdmin struct{}

func (grafanaExtraServerAdmin) ID() string { return "grafana-extra-server-admin" }

func (grafanaExtraServerAdmin) Inputs() model.EventFilter {
	return model.EventFilter{Types: []string{model.EventGrafanaUser}}
}

func grafanaUserID(e model.Event) int {
	if n, err := strconv.Atoi(e.Extra["grafana_user_id"]); err == nil {
		return n
	}
	return int(^uint(0) >> 1)
}

func (r grafanaExtraServerAdmin) Evaluate(events []model.Event) []model.Finding {
	type key struct{ caseID, file string }
	byDB := map[key][]model.Event{}
	for _, e := range events {
		if e.EventType == model.EventGrafanaUser {
			k := key{e.CaseID, e.SourceFileID}
			byDB[k] = append(byDB[k], e)
		}
	}
	keys := make([]key, 0, len(byDB))
	for k := range byDB {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].caseID != keys[j].caseID {
			return keys[i].caseID < keys[j].caseID
		}
		return keys[i].file < keys[j].file
	})
	var out []model.Finding
	for _, k := range keys {
		users := byDB[k]
		sort.SliceStable(users, func(i, j int) bool {
			a, b := grafanaUserID(users[i]), grafanaUserID(users[j])
			if a != b {
				return a < b
			}
			return users[i].ID < users[j].ID
		})
		firstID := grafanaUserID(users[0])
		for _, u := range users {
			if grafanaUserID(u) == firstID || u.Extra["server_admin"] != "true" || u.Extra["service_account"] == "true" {
				continue
			}
			login := cmdsem.Redact(u.Extra["login"])
			never := ""
			if u.Extra["last_seen"] == "never" {
				never = " Grafana records that this account has never been seen logging in, so no login is recorded for it."
			}
			role := ""
			if u.Extra["org_role"] != "" {
				role = fmt.Sprintf(" Its organisation role is %s.", cmdsem.Redact(u.Extra["org_role"]))
			}
			title := fmt.Sprintf("Grafana account '%s' has server-administrator rights and is not the first account", login)
			desc := fmt.Sprintf(
				"Grafana's database lists account '%s' (id %s) with server-administrator rights, created at %s. The first account in this database (the one Grafana creates at install) "+
					"is not reported.%s%s Limits: the record does not show who created it or from where, and administrators are added for legitimate work. "+
					"Server-administrator rights let an account manage every user, token and data source. Compare it with change records and with the "+
					"data sources and tokens in the same database. This is a lead, not a verdict.",
				login, cmdsem.Redact(u.Extra["grafana_user_id"]), fmtTime(u.Timestamp), role, never)
			out = append(out, newFinding(u.CaseID, r.ID(), title, model.SeverityMedium, model.ConfidenceMedium, desc, []string{"T1136"}, []model.Event{u}))
		}
	}
	return out
}

// ---------- grafana-datasource-credential ----------

type grafanaDatasourceCredential struct{}

func (grafanaDatasourceCredential) ID() string { return "grafana-datasource-credential" }

func (grafanaDatasourceCredential) Inputs() model.EventFilter {
	return model.EventFilter{Types: []string{model.EventGrafanaDataSource}}
}

func (r grafanaDatasourceCredential) Evaluate(events []model.Event) []model.Finding {
	var stored []model.Event
	for _, e := range events {
		if e.EventType == model.EventGrafanaDataSource && e.Extra["secrets_stored"] == "true" {
			stored = append(stored, e)
		}
	}
	sort.SliceStable(stored, func(i, j int) bool {
		a, b := stored[i], stored[j]
		if a.CaseID != b.CaseID {
			return a.CaseID < b.CaseID
		}
		if a.Extra["name"] != b.Extra["name"] {
			return a.Extra["name"] < b.Extra["name"]
		}
		return a.ID < b.ID
	})
	var out []model.Finding
	for _, e := range stored {
		name, typ, url := cmdsem.Redact(e.Extra["name"]), cmdsem.Redact(e.Extra["type"]), cmdsem.Redact(e.Extra["url"])
		who := ""
		if u := e.Extra["user"]; u != "" {
			who = fmt.Sprintf(" as user '%s'", cmdsem.Redact(u))
		}
		title := fmt.Sprintf("Grafana stores a credential for data source '%s' (%s) at %s", name, typ, url)
		desc := fmt.Sprintf(
			"Grafana's database holds a stored credential for data source '%s' of type %s, reaching %s%s. The credential is stored encrypted and its value is never shown. "+
				"Anyone with Grafana administrator access, or with this database together with Grafana's secret key, can use or recover it. If this Grafana was reached by an attacker, "+
				"treat the credential as exposed: rotate it and check the target server's own logs for logins by that account. "+
				"This lists what is stored; it is not evidence that it was used.",
			name, typ, url, who)
		out = append(out, newFinding(e.CaseID, r.ID(), title, model.SeverityLow, model.ConfidenceHigh, desc, []string{"T1552"}, []model.Event{e}))
	}
	return out
}

// ---------- container-risky-configuration ----------

type containerRiskyConfiguration struct{}

func (containerRiskyConfiguration) ID() string { return "container-risky-configuration" }

func (containerRiskyConfiguration) Inputs() model.EventFilter {
	return model.EventFilter{Types: []string{model.EventContainerHostConfig, model.EventContainerConfig}}
}

// ctrTagText says in words what a risky tag gives a process that controls the
// container, and how severe that is.
func ctrTagText(tag string) (text, severity string) {
	switch tag {
	case "docker_socket_mount":
		return "mounts the Docker control socket, which lets a process in the container start containers with any privileges on the host", model.SeverityHigh
	case "privileged":
		return "runs privileged, with nearly all kernel capabilities and access to the host's devices", model.SeverityHigh
	case "host_root_mount":
		return "mounts the root of the host filesystem", model.SeverityHigh
	case "sensitive_host_mount":
		return "mounts a sensitive host directory (such as /etc, /root, /proc, /sys or Docker's own data)", model.SeverityMedium
	case "host_pid":
		return "shares the host's process namespace", model.SeverityMedium
	case "host_network":
		return "shares the host's network stack", model.SeverityMedium
	case "published_all_interfaces":
		return "publishes a port on all network interfaces", model.SeverityLow
	}
	if strings.HasPrefix(tag, "cap_") {
		return "adds the Linux capability " + strings.ToUpper(strings.TrimPrefix(tag, "cap_")), model.SeverityMedium
	}
	return "carries the setting '" + cmdsem.Redact(tag) + "'", model.SeverityLow
}

var ctrSeverityRank = map[string]int{model.SeverityLow: 1, model.SeverityMedium: 2, model.SeverityHigh: 3}

func (r containerRiskyConfiguration) Evaluate(events []model.Event) []model.Finding {
	names := map[string]string{} // case|container id -> name
	var hosts []model.Event
	for _, e := range events {
		switch e.EventType {
		case model.EventContainerConfig:
			if n := e.Extra["container_name"]; n != "" {
				names[e.CaseID+"|"+e.Extra["container_id"]] = n
			}
		case model.EventContainerHostConfig:
			if strings.TrimSpace(e.Extra["risky"]) != "" {
				hosts = append(hosts, e)
			}
		}
	}
	sort.SliceStable(hosts, func(i, j int) bool {
		a, b := hosts[i], hosts[j]
		if a.CaseID != b.CaseID {
			return a.CaseID < b.CaseID
		}
		if a.Extra["container_id"] != b.Extra["container_id"] {
			return a.Extra["container_id"] < b.Extra["container_id"]
		}
		return a.ID < b.ID
	})
	var out []model.Finding
	for _, h := range hosts {
		id := h.Extra["container_id"]
		label := id
		if len(label) > 12 {
			label = label[:12]
		}
		if n := names[h.CaseID+"|"+id]; n != "" {
			label = n
		}
		label = cmdsem.Redact(label)
		tags := strings.Split(h.Extra["risky"], ",")
		sort.Strings(tags)
		var texts []string
		severity := model.SeverityLow
		for _, tag := range tags {
			if tag = strings.TrimSpace(tag); tag == "" {
				continue
			}
			text, sev := ctrTagText(tag)
			texts = append(texts, text)
			if ctrSeverityRank[sev] > ctrSeverityRank[severity] {
				severity = sev
			}
		}
		if len(texts) == 0 {
			continue
		}
		title := fmt.Sprintf("Container '%s' is configured with host access: %s", label, strings.Join(texts, "; "))
		desc := fmt.Sprintf(
			"The stored configuration of container '%s' (id %s) shows that it %s. This is configuration, not an incident: it records what the container was allowed to do, "+
				"not that anything used it. It matters because a process that takes over such a container inherits that reach, so it widens what an attacker "+
				"in the container could affect on the host. The file does not show what ran inside the container.",
			label, id, strings.Join(texts, "; and "))
		out = append(out, newFinding(h.CaseID, r.ID(), title, severity, model.ConfidenceHigh, desc, []string{"T1611"}, []model.Event{h}))
	}
	return out
}

// ---------- container-secret-in-environment ----------

type containerSecretInEnvironment struct{}

func (containerSecretInEnvironment) ID() string { return "container-secret-in-environment" }

func (containerSecretInEnvironment) Inputs() model.EventFilter {
	return model.EventFilter{Types: []string{model.EventContainerConfig}}
}

func (r containerSecretInEnvironment) Evaluate(events []model.Event) []model.Finding {
	var cfgs []model.Event
	for _, e := range events {
		if e.EventType == model.EventContainerConfig && strings.TrimSpace(e.Extra["env_secret_names"]) != "" {
			cfgs = append(cfgs, e)
		}
	}
	sort.SliceStable(cfgs, func(i, j int) bool {
		a, b := cfgs[i], cfgs[j]
		if a.CaseID != b.CaseID {
			return a.CaseID < b.CaseID
		}
		if a.Extra["container_id"] != b.Extra["container_id"] {
			return a.Extra["container_id"] < b.Extra["container_id"]
		}
		return a.ID < b.ID
	})
	var out []model.Finding
	for _, c := range cfgs {
		label := c.Extra["container_name"]
		if label == "" {
			label = c.Extra["container_id"]
			if len(label) > 12 {
				label = label[:12]
			}
		}
		label = cmdsem.Redact(label)
		names := cmdsem.Redact(strings.ReplaceAll(c.Extra["env_secret_names"], ",", ", "))
		title := fmt.Sprintf("Container '%s' keeps secrets in its environment (%s)", label, names)
		desc := fmt.Sprintf(
			"The stored configuration of container '%s' (image %s) sets environment variables whose names indicate secrets: %s. The values are not shown here. "+
				"Anyone who can read the container's configuration file or run docker inspect on it can read them, as can any process in the container, "+
				"and they are inherited by everything the container starts. If the container or the host was reached by an attacker, treat these secrets as exposed and rotate them. "+
				"The name matching is a guess from the variable name; a variable can be harmless, and a secret can sit under an ordinary name.",
			label, cmdsem.Redact(c.Extra["image"]), names)
		out = append(out, newFinding(c.CaseID, r.ID(), title, model.SeverityLow, model.ConfidenceHigh, desc, []string{"T1552"}, []model.Event{c}))
	}
	return out
}
