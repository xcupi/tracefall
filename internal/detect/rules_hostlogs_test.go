package detect

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
	"tracefall/internal/parsers/authlog"
	"tracefall/internal/parsers/syslog"
	"tracefall/internal/parsers/webaccess"
)

// load parses body with p, as the pipeline would, and gives every event the
// identity and provenance the pipeline adds.
func load(t *testing.T, p parsers.ArtifactParser, fileID, name, body string) []model.Event {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := p.Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := range res.Events {
		res.Events[i].ID = fmt.Sprintf("%s-%d", fileID, i)
		res.Events[i].CaseID = "case1"
		res.Events[i].SourceFileID = fileID
		if res.Events[i].Host == "" {
			res.Events[i].Host = "host01"
		}
	}
	return res.Events
}

func ssh(stamp, verb, user, src string) string {
	return fmt.Sprintf("%s host01 sshd[1]: %s password for %s from %s port 4000 ssh2\n", stamp, verb, user, src)
}

func findingsFor(ruleID string, events []model.Event) []model.Finding {
	var out []model.Finding
	for _, f := range Run("case1", events) {
		if f.RuleID == ruleID {
			out = append(out, f)
		}
	}
	return out
}

const seqRule = "brute-force-then-success-sequence"

func TestBruteForceSequence_FindsTheBurstWithoutAYear(t *testing.T) {
	body := ssh("Mar 18 10:00:01", "Failed", "alice", "203.0.113.9") +
		ssh("Mar 18 10:00:05", "Failed", "alice", "203.0.113.9") +
		ssh("Mar 18 10:00:09", "Failed", "alice", "203.0.113.9") +
		ssh("Mar 18 10:00:14", "Failed", "alice", "203.0.113.9") +
		ssh("Mar 18 10:01:30", "Accepted", "alice", "203.0.113.9")
	ev := load(t, authlog.New(), "f1", "auth.log", body)
	got := findingsFor(seqRule, ev)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	f := got[0]
	if f.Confidence != model.ConfidenceMedium || f.Severity != model.SeverityHigh {
		t.Errorf("severity/confidence %s/%s", f.Severity, f.Confidence)
	}
	if len(f.SupportingEvents) != 5 {
		t.Errorf("supporting %d, want 4 failures + 1 success", len(f.SupportingEvents))
	}
	if !f.FirstSeen.IsZero() {
		t.Errorf("no year is known; FirstSeen must stay zero, got %v", f.FirstSeen)
	}
	for _, want := range []string{"Mar 18 10:00:01", "Mar 18 10:01:30", "no year", "not a verdict"} {
		if !strings.Contains(f.Description, want) {
			t.Errorf("description lacks %q: %s", want, f.Description)
		}
	}
	if strings.Contains(f.Description, "0001") {
		t.Errorf("a zero time leaked into the description: %s", f.Description)
	}
}

func TestBruteForceSequence_RefusesWhatItCannotSupport(t *testing.T) {
	burst := ssh("Mar 18 10:00:01", "Failed", "alice", "203.0.113.9") +
		ssh("Mar 18 10:00:05", "Failed", "alice", "203.0.113.9") +
		ssh("Mar 18 10:00:09", "Failed", "alice", "203.0.113.9")
	cases := map[string]string{
		"success from another address": burst + ssh("Mar 18 10:01:00", "Accepted", "alice", "203.0.113.77"),
		"success for another account":  burst + ssh("Mar 18 10:01:00", "Accepted", "carol", "203.0.113.9"),
		"success too long after":       burst + ssh("Mar 18 11:00:00", "Accepted", "alice", "203.0.113.9"),
		"success before the failures":  ssh("Mar 18 09:59:00", "Accepted", "alice", "203.0.113.9") + burst,
		"only two failures": ssh("Mar 18 10:00:01", "Failed", "alice", "203.0.113.9") +
			ssh("Mar 18 10:00:05", "Failed", "alice", "203.0.113.9") + ssh("Mar 18 10:01:00", "Accepted", "alice", "203.0.113.9"),
		"failures too far apart": ssh("Mar 18 10:00:01", "Failed", "alice", "203.0.113.9") +
			ssh("Mar 18 10:20:00", "Failed", "alice", "203.0.113.9") + ssh("Mar 18 10:40:00", "Failed", "alice", "203.0.113.9") +
			ssh("Mar 18 10:41:00", "Accepted", "alice", "203.0.113.9"),
		"a year change in between": ssh("Dec 31 23:58:00", "Failed", "alice", "203.0.113.9") +
			ssh("Dec 31 23:58:30", "Failed", "alice", "203.0.113.9") + ssh("Dec 31 23:59:00", "Failed", "alice", "203.0.113.9") +
			ssh("Jan  1 00:00:20", "Accepted", "alice", "203.0.113.9"),
	}
	for name, body := range cases {
		if got := findingsFor(seqRule, load(t, authlog.New(), "f1", "auth.log", body)); len(got) != 0 {
			t.Errorf("%s: got %d finding(s), want none", name, len(got))
		}
	}
}

func TestBruteForceSequence_NeverJoinsTwoFiles(t *testing.T) {
	fails := load(t, authlog.New(), "f1", "auth.log.1",
		ssh("Mar 18 10:00:01", "Failed", "alice", "203.0.113.9")+
			ssh("Mar 18 10:00:05", "Failed", "alice", "203.0.113.9")+
			ssh("Mar 18 10:00:09", "Failed", "alice", "203.0.113.9"))
	succ := load(t, authlog.New(), "f2", "auth.log", ssh("Mar 18 10:01:00", "Accepted", "alice", "203.0.113.9"))
	if got := findingsFor(seqRule, append(fails, succ...)); len(got) != 0 {
		t.Fatalf("two rotations may cover different years; got %d finding(s)", len(got))
	}
}

func TestBruteForceSequence_LongBurstIsCappedButCounted(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 300; i++ {
		b.WriteString(ssh(fmt.Sprintf("Mar 18 10:%02d:%02d", i/60, i%60), "Failed", "root", "203.0.113.9"))
	}
	b.WriteString(ssh("Mar 18 10:05:30", "Accepted", "root", "203.0.113.9"))
	got := findingsFor(seqRule, load(t, authlog.New(), "f1", "auth.log", b.String()))
	if len(got) != 1 {
		t.Fatalf("got %d findings", len(got))
	}
	if n := len(got[0].SupportingEvents); n > supportingCap+1 {
		t.Errorf("supporting list %d exceeds the cap", n)
	}
	if !strings.Contains(got[0].Title, "300 failed logons") {
		t.Errorf("the true count must be in the title: %s", got[0].Title)
	}
}

func TestWebAttackIndicators(t *testing.T) {
	line := func(ip, ts, req, status, ua string) string {
		return fmt.Sprintf("%s - - [%s +0000] \"%s\" %s 100 \"-\" \"%s\"\n", ip, ts, req, status, ua)
	}
	body := "" +
		line("203.0.113.9", "19/Apr/2020:10:00:00", "GET /item.php?id=1+union+select+1,2 HTTP/1.1", "200", "Mozilla") +
		line("203.0.113.9", "19/Apr/2020:10:00:02", "GET /item.php?id=1%20and%201=1 HTTP/1.1", "200", "Mozilla") +
		line("203.0.113.9", "19/Apr/2020:10:00:03", "GET /uploads/c99.php HTTP/1.1", "200", "Mozilla") +
		line("198.51.100.4", "19/Apr/2020:10:01:00", "GET / HTTP/1.1", "200", "sqlmap/1.4") +
		line("198.51.100.5", "19/Apr/2020:10:02:00", "GET /phpmyadmin/ HTTP/1.1", "404", "Mozilla") +
		line("192.0.2.1", "19/Apr/2020:10:03:00", "GET /feed/ HTTP/1.1", "200", "Mozilla")
	ev := load(t, webaccess.New(), "w1", "access.log", body)
	got := findingsFor("web-attack-indicators", ev)
	byCat := map[string]model.Finding{}
	for _, f := range got {
		for _, c := range []string{"SQL injection", "web shell access", "vulnerability scanner", "administration interface"} {
			if strings.Contains(f.Title, c) {
				byCat[c] = f
			}
		}
	}
	if f, ok := byCat["SQL injection"]; !ok || !strings.Contains(f.Title, "from 203.0.113.9") || len(f.SupportingEvents) != 2 {
		t.Errorf("sql injection: %+v", f)
	}
	if f, ok := byCat["web shell access"]; !ok || f.Severity != model.SeverityHigh {
		t.Errorf("a web shell answered 200 is high: %+v", f)
	}
	if f, ok := byCat["vulnerability scanner"]; !ok || f.Severity != model.SeverityLow {
		t.Errorf("scanner: %+v", f)
	}
	if _, ok := byCat["administration interface"]; ok {
		t.Error("one admin-page request is background noise and needs three")
	}
	for _, f := range got {
		if strings.Contains(f.Title, "192.0.2.1") {
			t.Errorf("an ordinary request was flagged: %s", f.Title)
		}
		if !strings.Contains(f.Description, "does not prove") {
			t.Errorf("a web finding must say a status is not proof: %s", f.Description)
		}
	}
}

func TestAccountChangeObserved(t *testing.T) {
	body := "" +
		"Mar 16 08:12:13 host01 useradd[1]: new user: name=alice, UID=1001, GID=1001, home=/home/alice, shell=/bin/bash\n" +
		"Mar 16 08:25:22 host01 useradd[2]: new user: name=svc, UID=104, GID=65534, home=/var/run/svc, shell=/usr/sbin/nologin\n" +
		"Mar 16 08:26:00 host01 useradd[3]: new user: name=toor, UID=0, GID=0, home=/root, shell=/bin/bash\n" +
		"Mar 16 08:27:00 host01 usermod[4]: add 'alice' to group 'sudo'\n" +
		"Mar 16 08:27:10 host01 usermod[4]: add 'alice' to group 'staff'\n" +
		"Mar 16 08:28:00 host01 passwd[5]: pam_unix(passwd:chauthtok): password changed for alice\n"
	got := findingsFor("account-change-observed", load(t, authlog.New(), "f1", "auth.log", body))
	titles := map[string]model.Finding{}
	for _, f := range got {
		titles[f.Title] = f
	}
	if len(got) != 3 {
		t.Fatalf("got %d findings: %v", len(got), titles)
	}
	if f := titles["Local account created: toor"]; f.Severity != model.SeverityHigh || f.Confidence != model.ConfidenceHigh {
		t.Errorf("uid 0 account: %+v", f)
	}
	if f := titles["Local account created: alice"]; f.Severity != model.SeverityLow {
		t.Errorf("ordinary account: %+v", f)
	}
	if f := titles["Account added to privileged group sudo: alice"]; f.Severity != model.SeverityHigh {
		t.Errorf("sudo membership: %+v", f)
	}
	if _, ok := titles["Local account created: svc"]; ok {
		t.Error("a package-created service account must not be reported")
	}
}

func TestDatabaseInsecureAccount_OneFindingPerHost(t *testing.T) {
	body := "" +
		"Mar 18 10:18:42 host01 /etc/mysql/debian-start[7566]: WARNING: mysql.user contains 2 root accounts without password!\n" +
		"Mar 18 17:01:44 host01 /etc/mysql/debian-start[14717]: WARNING: mysql.user contains 2 root accounts without password!\n" +
		"Apr 14 14:44:36 host01 /etc/mysql/debian-start[5624]: WARNING: mysqlcheck has found corrupt tables\n"
	got := findingsFor("database-insecure-account", load(t, syslog.New(), "d1", "daemon.log", body))
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	f := got[0]
	if len(f.SupportingEvents) != 2 || !strings.Contains(f.Title, "2 times") {
		t.Errorf("only the insecure-account lines support it: %+v", f)
	}
	if !strings.Contains(f.Description, "does not show that anyone used") {
		t.Errorf("must not claim exploitation: %s", f.Description)
	}
}

func cmdEvent(id, typ, user, cmd string) model.Event {
	return model.Event{ID: id, CaseID: "case1", EventType: typ, Host: "host01", User: user, CommandLine: cmd}
}

func TestSystemChangeCommand(t *testing.T) {
	ev := []model.Event{
		cmdEvent("a1", model.EventSudoCommand, "alice", "/sbin/iptables -A INPUT -p tcp --dport 22 -j DROP"),
		cmdEvent("a2", model.EventSudoCommand, "alice", "/sbin/iptables -A INPUT -p tcp --dport 80 -j DROP"),
		cmdEvent("a3", model.EventSudoCommand, "alice", "/sbin/iptables -L -n"),
		cmdEvent("b1", model.EventProcessCreate, "carol", `net localgroup administrators dave /add`),
		cmdEvent("b2", model.EventProcessCreate, "carol", `net user dave Sup3rS3cret! /add`),
		cmdEvent("c1", model.EventBashHistoryCommand, "alice", "crontab -e"),
	}
	got := findingsFor("system-change-command", ev)
	by := map[string]model.Finding{}
	for _, f := range got {
		by[f.Title] = f
		if strings.Contains(f.Description, "Sup3rS3cret") || strings.Contains(f.Title, "Sup3rS3cret") {
			t.Fatalf("a secret reached a finding: %s", f.Description)
		}
	}
	var fw, adm, usr, cron *model.Finding
	for i := range got {
		f := &got[i]
		switch {
		case strings.HasPrefix(f.Title, "Firewall change"):
			fw = f
		case strings.Contains(f.Title, "privileged group"):
			adm = f
		case strings.Contains(f.Title, "Local account added"):
			usr = f
		case strings.HasPrefix(f.Title, "Persistence"):
			cron = f
		}
	}
	if fw == nil || !strings.HasSuffix(fw.Title, "(x2)") || len(fw.SupportingEvents) != 2 || fw.Confidence != model.ConfidenceLow {
		t.Errorf("two sudo iptables lines are one finding with a count and low confidence: %+v", fw)
	}
	if adm == nil || adm.Severity != model.SeverityHigh || adm.Confidence != model.ConfidenceMedium {
		t.Errorf("admin group add from a process record: %+v", adm)
	}
	if usr == nil || usr.Severity != model.SeverityMedium {
		t.Errorf("account add: %+v", usr)
	}
	if cron == nil || cron.Confidence != model.ConfidenceLow {
		t.Errorf("shell history proves typing only: %+v", cron)
	}
	if len(got) != 4 {
		t.Errorf("got %d findings, want 4 (the listing command has no semantic): %v", len(got), by)
	}
}

func TestBruteForceSequence_ASourceThatKeepsGuessingAfterGettingIn(t *testing.T) {
	// The failures never stop, and a success lands in the middle of them. A
	// success must be tied to the failures just before it, not to the end of
	// the whole attack.
	var b strings.Builder
	n := 0
	stamp := func() string { n++; return fmt.Sprintf("Mar 18 10:%02d:%02d", n/60, n%60) }
	for i := 0; i < 5; i++ {
		b.WriteString(ssh(stamp(), "Failed", "root", "203.0.113.9"))
	}
	b.WriteString(ssh(stamp(), "Accepted", "root", "203.0.113.9"))
	for i := 0; i < 4; i++ {
		b.WriteString(ssh(stamp(), "Failed", "root", "203.0.113.9"))
	}
	b.WriteString(ssh(stamp(), "Accepted", "root", "203.0.113.9"))
	for i := 0; i < 6; i++ {
		b.WriteString(ssh(stamp(), "Failed", "root", "203.0.113.9"))
	}
	got := findingsFor(seqRule, load(t, authlog.New(), "f1", "auth.log", b.String()))
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2 (one per success that follows a run)", len(got))
	}
	if !strings.Contains(got[0].Title, "5 failed logons") && !strings.Contains(got[1].Title, "5 failed logons") {
		t.Errorf("titles: %q / %q", got[0].Title, got[1].Title)
	}
	for _, f := range got {
		if len(f.SupportingEvents) > 6 {
			t.Errorf("a success must not collect failures from after it: %d events", len(f.SupportingEvents))
		}
	}
}

func TestSystemChangeCommand_ACommandRecoveredFromAConsoleInMemoryIsALowConfidenceLead(t *testing.T) {
	e := model.Event{ID: "c1", Host: "host01", EventType: model.EventMemoryConsole, CommandLine: "netsh advfirewall set allprofiles state off",
		Timestamp: time.Date(2021, 1, 2, 3, 4, 5, 0, time.UTC), ArtifactType: model.ArtifactMemoryAnalysis}
	got := systemChangeCommand{}.Evaluate([]model.Event{e})
	if len(got) != 1 {
		t.Fatalf("got %d findings", len(got))
	}
	if got[0].Confidence != model.ConfidenceLow || !strings.Contains(got[0].Description, "does not show that it ran") {
		t.Errorf("%s / %s", got[0].Confidence, got[0].Description)
	}
}
