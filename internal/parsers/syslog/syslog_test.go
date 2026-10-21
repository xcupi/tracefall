package syslog

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

func writeLog(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDetect(t *testing.T) {
	p := New()
	for _, ok := range []string{"syslog", "var/log/syslog", `[root]\var\log\syslog`, "SYSLOG", "syslog.1"} {
		if !p.Detect(ok) {
			t.Errorf("Detect(%q) = false, want true", ok)
		}
	}
	for _, no := range []string{"syslog.2.gz", "syslog.1.gz", "syslogd", "messages", "auth.log"} {
		if p.Detect(no) {
			t.Errorf("Detect(%q) = true; compressed or unrelated files must not be claimed", no)
		}
	}
	if p.DetectContent([]byte("Mar 21 16:25:01 h CRON[1]: (root) CMD (x)")) {
		t.Error("DetectContent claimed a text file; syslog has no signature")
	}
}

func TestParse_CronJobsBecomeEventsWithCommandAndAccount(t *testing.T) {
	body := "" +
		"Mar 21 16:25:01 host01 CRON[1705]: (root) CMD (command -v debian-sa1 > /dev/null && debian-sa1 1 1)\n" +
		"Mar 21 16:30:01 host01 CRON[1800]: (alice) CMD (/home/alice/backup.sh --full)\n" +
		"Mar 21 17:17:01 host01 CRON[1900]: (root) CMD (  [ -x /usr/lib/php/sessionclean ] && if [ ! -d /run/systemd/system ]; then /usr/lib/php/sessionclean; fi)\n"
	res, err := New().ParseWithContext(writeLog(t, "syslog", body), parsers.ParseContext{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 3 {
		t.Fatalf("events = %d, want 3", len(res.Events))
	}
	first := res.Events[0]
	if first.EventType != model.EventScheduledJobRun || first.User != "root" || first.Host != "HOST01" {
		t.Errorf("first = %q user %q host %q", first.EventType, first.User, first.Host)
	}
	if first.CommandLine != "command -v debian-sa1 > /dev/null && debian-sa1 1 1" {
		t.Errorf("command = %q; parentheses inside the command must not truncate it", first.CommandLine)
	}
	if first.PID != 1705 {
		t.Errorf("pid = %d, want 1705", first.PID)
	}
	if res.Events[1].User != "alice" {
		t.Errorf("non-root job user = %q, want alice", res.Events[1].User)
	}
	// The outer parentheses are cron's wrapper and are removed; the inner
	// ones belong to the command and must survive.
	if !strings.HasSuffix(res.Events[2].CommandLine, "sessionclean; fi") || !strings.Contains(res.Events[2].CommandLine, "[ ! -d /run/systemd/system ]") {
		t.Errorf("command = %q; wrapper parens must go, inner parens must stay", res.Events[2].CommandLine)
	}
	for i, ev := range res.Events {
		if !ev.Timestamp.IsZero() || ev.Extra["timestamp_known"] != "false" {
			t.Errorf("event %d has a full timestamp; syslog carries no year", i)
		}
	}
	if got := first.Extra["timestamp_partial"]; got != "Mar 21 16:25:01" {
		t.Errorf("partial = %q", got)
	}
	if !strings.Contains(first.Extra["records_execution"], "false") {
		t.Error("the event must say cron does not record the job's result")
	}
}

func TestParse_NoiseAndUnattributedLinesProduceNothing(t *testing.T) {
	body := "" +
		"Mar 22 04:59:43 host01 [1240]: gsd-media-keys: Fatal IO error 11\n" +
		"Mar 21 16:18:27 host01 anacron[501]: Job `cron.daily' terminated\n" +
		"Mar 21 16:25:01 host01 CRON[1705]: pam_unix(cron:session): session opened for user root by (uid=0)\n" +
		"Mar 21 16:25:01 host01 kernel: usb 1-1: new high-speed USB device number 2\n"
	res, err := New().Parse(writeLog(t, "syslog", body))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 0 {
		t.Errorf("noise produced %d events; only CRON CMD lines are emitted", len(res.Events))
	}
}

func TestParse_SingleDigitDayIsKeptAsWritten(t *testing.T) {
	res, err := New().Parse(writeLog(t, "syslog", "Mar  5 08:00:00 h CRON[1]: (root) CMD (true)\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Events[0].Extra["timestamp_partial"]; got != "Mar  5 08:00:00" {
		t.Errorf("partial = %q, want %q", got, "Mar  5 08:00:00")
	}
}

// Real-sample test: a Linux /var/log/syslog, read from TRACEFALL_REAL_SYSLOG.
// Skipped unless TRACEFALL_REAL_SYSLOG points at an extracted copy. The
// SHA-256 pins the exact bytes. The count of 105 was computed by an
// independent pass counting "CRON[...]: ... CMD (" lines in the raw file.
func TestReal_SyslogSample(t *testing.T) {
	path := os.Getenv("TRACEFALL_REAL_SYSLOG")
	if path == "" {
		t.Skip("set TRACEFALL_REAL_SYSLOG to an extracted /var/log/syslog to run")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	const wantSHA = "1f0a69d21d88b2eef89802a4853636bdaf6a2807ec0be319a754b5fa5dfa3172"
	if got := hex.EncodeToString(sum[:]); got != wantSHA {
		t.Fatalf("sample sha256 = %s, want %s", got, wantSHA)
	}
	res, err := New().Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 105 {
		t.Fatalf("events = %d, want 105 (one per CRON CMD line)", len(res.Events))
	}
	// Grouped by what the command is, from the raw file: 71 debian-sa1 runs
	// (70 of "1 1" and 1 of "60 2"), 23 sessionclean (starts with "[ -x"),
	// and 11 run-parts for cron.hourly (starts with "cd /").
	groups := map[string]int{}
	for _, ev := range res.Events {
		if ev.User != "root" {
			t.Errorf("job %s ran as %q, want root", ev.SourceReference, ev.User)
		}
		if !ev.Timestamp.IsZero() {
			t.Fatalf("line %s got a full timestamp", ev.SourceReference)
		}
		c := ev.CommandLine
		switch {
		case strings.HasPrefix(c, "command -v debian-sa1"):
			groups["debian-sa1"]++
		case strings.HasPrefix(c, "[ -x /usr/lib/php/sessionclean"):
			groups["sessionclean"]++
		case strings.HasPrefix(c, "cd / && run-parts"):
			groups["run-parts"]++
		default:
			groups["other"]++
		}
	}
	want := map[string]int{"debian-sa1": 71, "sessionclean": 23, "run-parts": 11}
	for k, v := range want {
		if groups[k] != v {
			t.Errorf("%s = %d, want %d (groups %v)", k, groups[k], v, groups)
		}
	}
	if groups["other"] != 0 {
		t.Errorf("%d jobs matched no known group; the sample changed or the parser mangled a command", groups["other"])
	}
}

func parseText(t *testing.T, name, body string) parsers.ParseResult {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := New().Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestDetect_DaemonLogButNotMessages(t *testing.T) {
	p := New()
	for _, ok := range []string{"daemon.log", "var/log/daemon.log", "DAEMON.LOG", "daemon.log.1"} {
		if !p.Detect(ok) {
			t.Errorf("Detect(%q) = false", ok)
		}
	}
	for _, no := range []string{"messages", "daemon.log.gz", "daemon.logger", "kern.log"} {
		if p.Detect(no) {
			t.Errorf("Detect(%q) = true", no)
		}
	}
}

func TestParse_DatabaseServiceMessages(t *testing.T) {
	body := "" +
		"Mar 18 10:18:30 host01 mysqld_safe[7136]: 100318 10:18:30 [ERROR] Aborting\n" +
		"Mar 18 10:18:33 host01 mysqld[7355]: 100318 10:18:33  InnoDB: Database was not shut down normally!\n" +
		"Mar 18 10:18:42 host01 /etc/mysql/debian-start[7526]: mysql.user                                         OK\n" +
		"Mar 18 10:18:42 host01 /etc/mysql/debian-start[7566]: WARNING: mysql.user contains 2 root accounts without password!\n" +
		"Apr 14 14:44:36 host01 /etc/mysql/debian-start[5624]: WARNING: mysqlcheck has found corrupt tables\n" +
		"Mar 18 10:18:31 host01 mysqld[7275]: 100318 10:18:31 [Note] /usr/sbin/mysqld: ready for connections.\n" +
		"Mar 18 10:18:31 host01 dhclient: can't create /var/lib/dhcp3/dhclient.eth0.leases: Permission denied\n" +
		"Mar 18 10:18:31 host01 ntpd[1]: failed to initialize interface for address ::1\n"
	res := parseText(t, "daemon.log", body)
	var cats []string
	for _, e := range res.Events {
		if e.EventType != model.EventServiceMessage {
			t.Fatalf("unexpected type %q", e.EventType)
		}
		cats = append(cats, e.Extra["category"])
		if !e.Timestamp.IsZero() {
			t.Error("no year in the log; Timestamp must stay zero")
		}
		if e.Extra["meaning"] == "" || e.Extra["message"] == "" {
			t.Errorf("an event must say what the line does and does not show: %v", e.Extra)
		}
	}
	want := []string{"database_error", "database_integrity", "database_insecure_account", "database_integrity", "database_lifecycle"}
	if strings.Join(cats, ",") != strings.Join(want, ",") {
		t.Fatalf("categories %v, want %v (other daemons and the 'OK' check line are not on the allow-list)", cats, want)
	}
	if got := res.Events[0].Extra["embedded_stamp"]; got != "100318 10:18:30" {
		t.Errorf("embedded stamp %q must be kept verbatim", got)
	}
	if res.Events[2].ProcessName != "debian-start" || res.Events[2].Extra["program"] != "debian-start" {
		t.Errorf("program should be the base name: %q", res.Events[2].ProcessName)
	}
	if res.Events[2].SourceReference != "line:4" {
		t.Errorf("source reference %q", res.Events[2].SourceReference)
	}
}

func TestParse_AMessageFromAnotherProgramIsNotClaimed(t *testing.T) {
	// The same words from a program that is not a MySQL component are not
	// evidence about MySQL.
	res := parseText(t, "syslog", "Mar 18 10:18:42 host01 someapp[1]: WARNING: mysql.user contains 2 root accounts without password!\n")
	if len(res.Events) != 0 {
		t.Fatalf("got %d events from the wrong program", len(res.Events))
	}
}
