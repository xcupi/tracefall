package detect

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
)

const (
	gfBurstRule   = "grafana-login-failure-burst"
	gfAdminRule   = "grafana-extra-server-admin"
	gfDSRule      = "grafana-datasource-credential"
	ctrRiskyRule  = "container-risky-configuration"
	ctrSecretRule = "container-secret-in-environment"

	cid = "abababababababababababababababababababababababababababababababab"
)

var gfBase = time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)

// gfLoginFail is a Grafana "Request Completed" line for POST /login answered 401,
// as the grafanalog reader emits it: anonymous, so no user.
func gfLoginFail(id, artifact string, at time.Time, client string) model.Event {
	return model.Event{
		ID: id, CaseID: "case1", Timestamp: at, SourceFileID: artifact + "-file",
		EventType: model.EventWebRequest, ArtifactType: artifact, NetworkSource: client,
		Extra: map[string]string{"method": "POST", "uri": "/login", "status": "401", "grafana_handler": "/login", "grafana_user_id": "0"},
	}
}

func gfBurst(prefix, artifact string, n int, start time.Time, client string) []model.Event {
	var out []model.Event
	for i := 0; i < n; i++ {
		out = append(out, gfLoginFail(fmt.Sprintf("%s%02d", prefix, i), artifact, start.Add(time.Duration(i)*time.Second), client))
	}
	return out
}

func gfSession(id string, at time.Time, client string) model.Event {
	return model.Event{
		ID: id, CaseID: "case1", Timestamp: at, SourceFileID: "db-file",
		EventType: model.EventGrafanaSession, ArtifactType: model.ArtifactGrafanaDB,
		Extra: map[string]string{"client_ip": client, "user_id": "1"},
	}
}

func gfUser(id, file, uid, login, admin, sa, lastSeen string) model.Event {
	x := map[string]string{"grafana_user_id": uid, "login": login, "server_admin": admin, "service_account": sa, "org_role": "Admin"}
	if lastSeen != "" {
		x["last_seen"] = lastSeen
	}
	return model.Event{
		ID: id, CaseID: "case1", Timestamp: gfBase.Add(time.Duration(len(uid)) * time.Second), SourceFileID: file,
		EventType: model.EventGrafanaUser, ArtifactType: model.ArtifactGrafanaDB, Extra: x,
	}
}

func gfDataSource(id, name, typ, url, user, secrets string) model.Event {
	return model.Event{
		ID: id, CaseID: "case1", Timestamp: gfBase, SourceFileID: "db-file",
		EventType: model.EventGrafanaDataSource, ArtifactType: model.ArtifactGrafanaDB,
		Extra: map[string]string{"name": name, "type": typ, "url": url, "user": user, "secrets_stored": secrets},
	}
}

func ctrHost(id, risky string) model.Event {
	return model.Event{
		ID: id, CaseID: "case1", SourceFileID: "hc-" + id,
		EventType: model.EventContainerHostConfig, ArtifactType: model.ArtifactContainerConfig,
		Extra: map[string]string{"container_id": cid, "risky": risky, "privileged": fmt.Sprint(strings.Contains(risky, "privileged"))},
	}
}

func ctrConfig(id, name, secrets string) model.Event {
	return model.Event{
		ID: id, CaseID: "case1", SourceFileID: "cfg-" + id,
		EventType: model.EventContainerConfig, ArtifactType: model.ArtifactContainerConfig,
		Extra: map[string]string{"container_id": cid, "container_name": name, "image": "example/web:1", "env_secret_names": secrets},
	}
}

// ---------- grafana-login-failure-burst ----------

func TestGrafanaLoginBurst_FiresAndSaysWhatTheLogCannotShow(t *testing.T) {
	got := sqlFindings(gfBurstRule, gfBurst("g", model.ArtifactGrafanaLog, 7, gfBase, "203.0.113.9"))
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	f := got[0]
	if f.Severity != model.SeverityMedium || f.Confidence != model.ConfidenceMedium {
		t.Errorf("severity/confidence = %s/%s", f.Severity, f.Confidence)
	}
	for _, w := range []string{"7 failed Grafana logins", "203.0.113.9", "2026-03-01T09:00:00Z", "does not record which account", "grafana.log", "not added together", "lead, not a verdict"} {
		if !strings.Contains(f.Title+" "+f.Description, w) {
			t.Errorf("finding lacks %q: %s", w, f.Description)
		}
	}
	noZeroTime(t, f)
}

func TestGrafanaLoginBurst_BelowThresholdWideGapsAndOtherRequestsDoNotFire(t *testing.T) {
	if got := sqlFindings(gfBurstRule, gfBurst("g", model.ArtifactGrafanaLog, 4, gfBase, "203.0.113.9")); len(got) != 0 {
		t.Errorf("4 failures fired")
	}
	var wide []model.Event
	for i := 0; i < 6; i++ {
		wide = append(wide, gfLoginFail(fmt.Sprintf("w%d", i), model.ArtifactGrafanaLog, gfBase.Add(time.Duration(i)*3*time.Minute), "203.0.113.9"))
	}
	if got := sqlFindings(gfBurstRule, wide); len(got) != 0 {
		t.Errorf("failures 3 minutes apart fired")
	}
	var other []model.Event
	for i := 0; i < 8; i++ {
		e := gfLoginFail(fmt.Sprintf("o%d", i), model.ArtifactGrafanaLog, gfBase.Add(time.Duration(i)*time.Second), "203.0.113.9")
		switch i % 3 {
		case 0:
			e.Extra["status"] = "200"
		case 1:
			e.Extra["uri"], e.Extra["grafana_handler"] = "/api/health", "/api/health"
		default:
			e.Extra["method"] = "GET"
		}
		other = append(other, e)
	}
	if got := sqlFindings(gfBurstRule, other); len(got) != 0 {
		t.Errorf("non-login or successful requests fired: %d", len(got))
	}
}

// An access log from another application can also show POST /login answered 401.
// Only a request Grafana itself logged (it carries the handler) is claimed.
func TestGrafanaLoginBurst_AnotherApplicationsLoginFailuresAreNotClaimed(t *testing.T) {
	var ev []model.Event
	for i := 0; i < 8; i++ {
		e := gfLoginFail(fmt.Sprintf("w%d", i), model.ArtifactWebAccessLog, gfBase.Add(time.Duration(i)*time.Second), "203.0.113.9")
		delete(e.Extra, "grafana_handler")
		delete(e.Extra, "grafana_user_id")
		ev = append(ev, e)
	}
	if got := sqlFindings(gfBurstRule, ev); len(got) != 0 {
		t.Fatalf("a non-Grafana access log made %d Grafana findings", len(got))
	}
}

func TestGrafanaLoginBurst_DifferentClientsAndSourcesAreNeverSummed(t *testing.T) {
	var ev []model.Event
	ev = append(ev, gfBurst("a", model.ArtifactGrafanaLog, 3, gfBase, "203.0.113.9")...)
	ev = append(ev, gfBurst("b", model.ArtifactGrafanaLog, 3, gfBase, "203.0.113.10")...)
	ev = append(ev, gfBurst("c", model.ArtifactContainerLog, 3, gfBase, "203.0.113.9")...)
	if got := sqlFindings(gfBurstRule, ev); len(got) != 0 {
		t.Fatalf("3+3+3 across clients and sources fired %d", len(got))
	}
	ev = append(gfBurst("a", model.ArtifactGrafanaLog, 5, gfBase, "203.0.113.9"), gfBurst("c", model.ArtifactContainerLog, 5, gfBase, "203.0.113.9")...)
	got := sqlFindings(gfBurstRule, ev)
	if len(got) != 2 {
		t.Fatalf("want one finding per source, got %d", len(got))
	}
	names := got[0].Description + got[1].Description
	if !strings.Contains(names, "grafana.log") || !strings.Contains(names, "container log") {
		t.Errorf("sources not named: %s", names)
	}
}

func TestGrafanaLoginBurst_SessionFromTheSameAddressRaisesSeverity(t *testing.T) {
	ev := gfBurst("g", model.ArtifactGrafanaLog, 6, gfBase, "203.0.113.9")
	same := append(append([]model.Event{}, ev...), gfSession("s1", gfBase.Add(10*time.Minute), "203.0.113.9"))
	got := sqlFindings(gfBurstRule, same)
	if len(got) != 1 || got[0].Severity != model.SeverityHigh || !strings.Contains(got[0].Description, "a session was created from the same address") {
		t.Fatalf("same-address session not recognised: %+v", got)
	}
	for _, s := range []model.Event{
		gfSession("s2", gfBase.Add(10*time.Minute), "203.0.113.77"), // another address
		gfSession("s3", gfBase.Add(3*time.Hour), "203.0.113.9"),     // too late
		gfSession("s4", gfBase.Add(-time.Minute), "203.0.113.9"),    // before the failures
	} {
		got = sqlFindings(gfBurstRule, append(append([]model.Event{}, ev...), s))
		if len(got) != 1 || got[0].Severity != model.SeverityMedium {
			t.Errorf("session %s raised severity: %+v", s.ID, got)
		}
	}
}

func TestGrafanaLoginBurst_OrderIndependent(t *testing.T) {
	ev := gfBurst("g", model.ArtifactGrafanaLog, 7, gfBase, "203.0.113.9")
	ev = append(ev, gfSession("s1", gfBase.Add(time.Minute), "203.0.113.9"))
	ev = append(ev, gfBurst("c", model.ArtifactContainerLog, 5, gfBase, "203.0.113.4")...)
	sameFindings(t, gfBurstRule, ev)
}

// ---------- grafana-extra-server-admin ----------

func TestGrafanaExtraAdmin_NamesAccountsBesideTheFirstOne(t *testing.T) {
	ev := []model.Event{
		gfUser("u1", "db-file", "1", "admin01", "true", "false", ""),
		gfUser("u2", "db-file", "2", "backdoor01", "true", "false", "never"),
		gfUser("u3", "db-file", "3", "sa-1-svc", "false", "true", "never"),
		gfUser("u10", "db-file", "10", "alice01", "false", "false", ""),
	}
	got := sqlFindings(gfAdminRule, ev)
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	f := got[0]
	if f.Severity != model.SeverityMedium || f.Confidence != model.ConfidenceMedium {
		t.Errorf("severity/confidence = %s/%s", f.Severity, f.Confidence)
	}
	for _, w := range []string{"backdoor01", "no login is recorded", "does not show who created it", "first account"} {
		if !strings.Contains(f.Title+" "+f.Description, w) {
			t.Errorf("finding lacks %q: %s", w, f.Description)
		}
	}
	if strings.Contains(f.Description, "admin01") && !strings.Contains(f.Description, "first account") {
		t.Errorf("the first account was presented as extra")
	}
}

func TestGrafanaExtraAdmin_NumericIDOrderAndNoFalsePositives(t *testing.T) {
	// id 10 sorts before id 2 as text; the first account is still id 2.
	ev := []model.Event{
		gfUser("a", "db-file", "10", "late01", "true", "false", ""),
		gfUser("b", "db-file", "2", "first01", "true", "false", ""),
	}
	got := sqlFindings(gfAdminRule, ev)
	if len(got) != 1 || !strings.Contains(got[0].Title, "late01") {
		t.Fatalf("numeric order wrong: %+v", got)
	}
	for _, only := range [][]model.Event{
		{gfUser("x", "db-file", "1", "first01", "true", "false", "")},
		{gfUser("x", "db-file", "1", "first01", "true", "false", ""), gfUser("y", "db-file", "2", "svc", "true", "true", "")}, // service account
		{gfUser("x", "db-file", "1", "first01", "true", "false", ""), gfUser("y", "db-file", "2", "bob01", "false", "false", "")},
	} {
		if got := sqlFindings(gfAdminRule, only); len(got) != 0 {
			t.Errorf("fired on %d users: %+v", len(only), got)
		}
	}
	// Two databases never share a "first account".
	two := []model.Event{
		gfUser("a1", "db-a", "1", "one01", "true", "false", ""),
		gfUser("b1", "db-b", "1", "two01", "true", "false", ""),
	}
	if got := sqlFindings(gfAdminRule, two); len(got) != 0 {
		t.Errorf("two databases each with a first admin fired: %d", len(got))
	}
}

func TestGrafanaExtraAdmin_OrderIndependent(t *testing.T) {
	ev := []model.Event{
		gfUser("u1", "db-file", "1", "admin01", "true", "false", ""),
		gfUser("u2", "db-file", "2", "backdoor01", "true", "false", "never"),
		gfUser("u4", "db-file", "4", "other01", "true", "false", ""),
	}
	sameFindings(t, gfAdminRule, ev)
}

// ---------- grafana-datasource-credential ----------

func TestGrafanaDatasource_StoredCredentialIsAnExposureLead(t *testing.T) {
	ev := []model.Event{
		gfDataSource("d1", "db01", "mssql", "db01.example.invalid:1433", "reader01", "true"),
		gfDataSource("d2", "public", "prometheus", "http://203.0.113.20:9090", "", "false"),
	}
	got := sqlFindings(gfDSRule, ev)
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	f := got[0]
	if f.Severity != model.SeverityLow || f.Confidence != model.ConfidenceHigh {
		t.Errorf("severity/confidence = %s/%s", f.Severity, f.Confidence)
	}
	for _, w := range []string{"db01", "mssql", "db01.example.invalid:1433", "reader01", "never shown", "not evidence that it was used"} {
		if !strings.Contains(f.Title+" "+f.Description, w) {
			t.Errorf("finding lacks %q: %s", w, f.Description)
		}
	}
}

func TestGrafanaDatasource_URLCredentialsAreRedactedAndOrderIsStable(t *testing.T) {
	ev := []model.Event{
		gfDataSource("d1", "db01", "postgres", "Server=db01;User Id=app;Password=P@ssw0rdX;", "app", "true"),
		gfDataSource("d2", "db02", "mysql", "db02.example.invalid:3306", "app", "true"),
	}
	got := sqlFindings(gfDSRule, ev)
	if len(got) != 2 {
		t.Fatalf("want 2, got %d", len(got))
	}
	for _, f := range got {
		if strings.Contains(f.Description, "P@ssw0rdX") {
			t.Errorf("a secret reached the finding: %s", f.Description)
		}
	}
	sameFindings(t, gfDSRule, ev)
}

// ---------- container-risky-configuration ----------

func TestContainerRisky_SeverityFollowsWhatItWouldHand(t *testing.T) {
	cases := []struct {
		risky string
		sev   string
		want  []string
	}{
		{"docker_socket_mount", model.SeverityHigh, []string{"Docker control socket"}},
		{"privileged", model.SeverityHigh, []string{"privileged"}},
		{"host_root_mount,sensitive_host_mount", model.SeverityHigh, []string{"root of the host"}},
		{"host_pid", model.SeverityMedium, []string{"host's process namespace"}},
		{"cap_sys_admin", model.SeverityMedium, []string{"SYS_ADMIN"}},
		{"published_all_interfaces", model.SeverityLow, []string{"all network interfaces"}},
	}
	for _, c := range cases {
		got := sqlFindings(ctrRiskyRule, []model.Event{ctrConfig("c1", "web01", ""), ctrHost("h1", c.risky)})
		if len(got) != 1 || got[0].Severity != c.sev || got[0].Confidence != model.ConfidenceHigh {
			t.Errorf("%s: %+v", c.risky, got)
			continue
		}
		for _, w := range append(c.want, "web01", "configuration, not an incident") {
			if !strings.Contains(got[0].Title+" "+got[0].Description, w) {
				t.Errorf("%s: finding lacks %q: %s", c.risky, w, got[0].Description)
			}
		}
		noZeroTime(t, got[0])
	}
}

func TestContainerRisky_NothingRiskyAndMissingConfigStillWork(t *testing.T) {
	if got := sqlFindings(ctrRiskyRule, []model.Event{ctrHost("h1", "")}); len(got) != 0 {
		t.Errorf("empty risky fired")
	}
	got := sqlFindings(ctrRiskyRule, []model.Event{ctrHost("h1", "privileged")})
	if len(got) != 1 || !strings.Contains(got[0].Description, cid[:12]) {
		t.Errorf("without its config the container is named by id: %+v", got)
	}
}

func TestContainerRisky_OrderIndependent(t *testing.T) {
	ev := []model.Event{ctrConfig("c1", "web01", ""), ctrHost("h1", "docker_socket_mount,host_pid")}
	other := ctrHost("h2", "published_all_interfaces")
	other.Extra["container_id"] = strings.Repeat("cd", 32)
	ev = append(ev, other)
	sameFindings(t, ctrRiskyRule, ev)
}

// ---------- container-secret-in-environment ----------

func TestContainerSecret_NamesOnlyAndNeverValues(t *testing.T) {
	got := sqlFindings(ctrSecretRule, []model.Event{ctrConfig("c1", "web01", "DB_PASSWORD,API_TOKEN"), ctrConfig("c2", "web02", "")})
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	f := got[0]
	if f.Severity != model.SeverityLow || f.Confidence != model.ConfidenceHigh {
		t.Errorf("severity/confidence = %s/%s", f.Severity, f.Confidence)
	}
	for _, w := range []string{"web01", "DB_PASSWORD", "API_TOKEN", "values are not shown", "docker inspect"} {
		if !strings.Contains(f.Title+" "+f.Description, w) {
			t.Errorf("finding lacks %q: %s", w, f.Description)
		}
	}
	sameFindings(t, ctrSecretRule, []model.Event{ctrConfig("c1", "web01", "DB_PASSWORD,API_TOKEN"), ctrConfig("c3", "web03", "KEY")})
}

// ---------- inputs ----------

func TestContainerRules_InputsAreASupersetOfWhatTheyRead(t *testing.T) {
	var ev []model.Event
	ev = append(ev, gfBurst("g", model.ArtifactGrafanaLog, 6, gfBase, "203.0.113.9")...)
	ev = append(ev, gfSession("s1", gfBase.Add(time.Minute), "203.0.113.9"),
		gfUser("u1", "db-file", "1", "admin01", "true", "false", ""),
		gfUser("u2", "db-file", "2", "backdoor01", "true", "false", "never"),
		gfDataSource("d1", "db01", "mssql", "db01.example.invalid:1433", "reader01", "true"),
		ctrConfig("c1", "web01", "DB_PASSWORD"), ctrHost("h1", "privileged"),
		model.Event{ID: "x1", CaseID: "case1", EventType: "unrelated_event"})
	src := model.SliceSource(ev)
	for _, id := range []string{gfBurstRule, gfAdminRule, gfDSRule, ctrRiskyRule, ctrSecretRule} {
		var found bool
		for _, r := range All() {
			if r.ID() != id {
				continue
			}
			found = true
			in, ok := r.(interface{ Inputs() model.EventFilter })
			if !ok {
				t.Fatalf("%s declares no Inputs", id)
			}
			full, _ := src.Load(model.EventFilter{All: true})
			typed, _ := src.Load(in.Inputs())
			if len(r.Evaluate(full)) == 0 {
				t.Errorf("%s: fixture does not trigger the rule", id)
			}
			if mustJSON(t, withoutCreatedAt(r.Evaluate(full))) != mustJSON(t, withoutCreatedAt(r.Evaluate(typed))) {
				t.Errorf("%s: declared inputs change the findings", id)
			}
		}
		if !found {
			t.Errorf("%s is not registered", id)
		}
	}
}
