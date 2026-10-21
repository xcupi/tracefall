package authlog

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
	"tracefall/internal/partialtime"
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
	for _, ok := range []string{"auth.log", "var/log/auth.log", `[root]\var\log\auth.log`, "AUTH.LOG", "auth.log.1"} {
		if !p.Detect(ok) {
			t.Errorf("Detect(%q) = false, want true", ok)
		}
	}
	for _, no := range []string{"auth.log.gz", "auth.log.1.gz", "auth.logger", "syslog", "auth.log.bak", "secure"} {
		if p.Detect(no) {
			t.Errorf("Detect(%q) = true; compressed or unrelated files must not be claimed", no)
		}
	}
	if p.DetectContent([]byte("Mar 20 11:26:22 host su[1]: Successful su")) {
		t.Error("DetectContent claimed a text file; syslog has no signature")
	}
}

func TestParse_SuSudoAndSSHAreEmittedWithPartialTimestamps(t *testing.T) {
	body := "" +
		"Mar 20 11:26:22 host01 su[4060]: Successful su for postgres by root\n" +
		"Mar 20 11:26:22 host01 su[4061]: FAILED su for root by carol\n" +
		"Mar 20 11:27:01 host01 sudo:     root : TTY=pts/0 ; PWD=/root/Documents ; USER=root ; COMMAND=/usr/bin/apt install moo\n" +
		"Mar 20 11:28:00 host01 sshd[900]: Accepted password for alice from 10.0.0.5 port 51234 ssh2\n" +
		"Mar 20 11:28:09 host01 sshd[901]: Failed password for invalid user bob from 203.0.113.9 port 40022 ssh2\n"
	res, err := New().ParseWithContext(writeLog(t, "auth.log", body), parsers.ParseContext{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 5 {
		t.Fatalf("events = %d, want 5", len(res.Events))
	}
	for i, ev := range res.Events {
		if !ev.Timestamp.IsZero() {
			t.Errorf("event %d has a full timestamp %v; auth.log lines carry no year", i, ev.Timestamp)
		}
		if ev.Extra["timestamp_known"] != "false" || ev.Extra["timestamp_partial"] == "" {
			t.Errorf("event %d lost its partial timestamp: known=%q partial=%q", i, ev.Extra["timestamp_known"], ev.Extra["timestamp_partial"])
		}
		if ev.ArtifactType != model.ArtifactAuthLog || ev.Parser != parserName {
			t.Errorf("event %d artifact/parser = %q/%q", i, ev.ArtifactType, ev.Parser)
		}
	}
	if got := res.Events[0].Extra["timestamp_partial"]; got != "Mar 20 11:26:22" {
		t.Errorf("partial timestamp = %q, want exactly as written", got)
	}

	su := res.Events[0]
	if su.EventType != model.EventPrivilegeSwitch || su.User != "root" || su.Extra["target_user"] != "postgres" || su.Extra["outcome"] != "success" {
		t.Errorf("successful su = %q user %q target %q outcome %q", su.EventType, su.User, su.Extra["target_user"], su.Extra["outcome"])
	}
	if res.Events[1].Extra["outcome"] != "failed" {
		t.Errorf("failed su outcome = %q", res.Events[1].Extra["outcome"])
	}

	sudo := res.Events[2]
	if sudo.EventType != model.EventSudoCommand || sudo.User != "root" || sudo.CommandLine != "/usr/bin/apt install moo" || sudo.ProcessName != "apt" {
		t.Errorf("sudo = %q user %q cmd %q proc %q", sudo.EventType, sudo.User, sudo.CommandLine, sudo.ProcessName)
	}
	if sudo.Extra["target_user"] != "root" || sudo.Extra["working_dir"] != "/root/Documents" {
		t.Errorf("sudo extra = %v", sudo.Extra)
	}
	if !strings.Contains(sudo.Extra["records_execution"], "false") {
		t.Error("sudo must say it does not prove execution")
	}

	ok := res.Events[3]
	if ok.EventType != model.EventLogonSuccess || ok.User != "alice" || ok.NetworkSource != "10.0.0.5" || ok.Extra["auth_method"] != "password" {
		t.Errorf("sshd accept = %q user %q from %q method %q", ok.EventType, ok.User, ok.NetworkSource, ok.Extra["auth_method"])
	}
	bad := res.Events[4]
	if bad.EventType != model.EventLogonFailure || bad.User != "bob" || bad.NetworkSource != "203.0.113.9" || bad.Extra["invalid_user"] != "true" {
		t.Errorf("sshd failure = %q user %q from %q invalid %q", bad.EventType, bad.User, bad.NetworkSource, bad.Extra["invalid_user"])
	}
}

func TestParse_NoiseProducesNoEvents(t *testing.T) {
	body := "" +
		"Mar 20 11:25:01 host01 CRON[1542]: pam_unix(cron:session): session opened for user root by (uid=0)\n" +
		"Mar 20 11:26:22 host01 su[4060]: pam_unix(su:session): session opened for user postgres by (uid=0)\n" +
		"Mar 20 11:26:22 host01 su[4060]: + ??? root:postgres\n" +
		"Mar 20 11:26:22 host01 sudo: pam_unix(sudo:session): session closed for user root\n" +
		"not a syslog line at all\n"
	res, err := New().Parse(writeLog(t, "auth.log", body))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 0 || len(res.Raw) != 0 {
		t.Errorf("PAM session and CRON noise produced %d events; they repeat the action lines and must not", len(res.Events))
	}
}

func TestParse_SingleDigitDayIsKeptAsWritten(t *testing.T) {
	res, err := New().Parse(writeLog(t, "auth.log", "Mar  5 08:00:00 host su[1]: Successful su for root by alice\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Events[0].Extra["timestamp_partial"]; got != "Mar  5 08:00:00" {
		t.Errorf("partial = %q, want %q (the padding is part of what was written)", got, "Mar  5 08:00:00")
	}
}

func TestParse_LineReferencesCountEveryLine(t *testing.T) {
	body := "noise line\n\nMar 20 11:26:22 h su[1]: Successful su for root by alice\n"
	res, err := New().Parse(writeLog(t, "auth.log", body))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 1 || res.Events[0].SourceReference != "line:3" {
		t.Fatalf("events %d, ref %q; want 1 event at line:3, so the reference opens to the same line an examiner sees", len(res.Events), res.Events[0].SourceReference)
	}
}

// Real-sample test: a Linux /var/log/auth.log, read from TRACEFALL_REAL_AUTHLOG.
// Skipped unless TRACEFALL_REAL_AUTHLOG points at an extracted copy. The
// SHA-256 pins the exact bytes. The expected counts were computed with an
// independent Python pass over the raw file, not from this parser: 6
// successful su (all Mar 20 11:26:22-23, target postgres, by root), 4 sudo
// COMMAND lines, and no sshd lines.
func TestReal_AuthLogSample(t *testing.T) {
	path := os.Getenv("TRACEFALL_REAL_AUTHLOG")
	if path == "" {
		t.Skip("set TRACEFALL_REAL_AUTHLOG to an extracted /var/log/auth.log to run")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	const wantSHA = "8b3ca5d0a8d88ed78e5e013a475c3c0356b77dbac51b30b2430985a609ac5106"
	if got := hex.EncodeToString(sum[:]); got != wantSHA {
		t.Fatalf("sample sha256 = %s, want %s", got, wantSHA)
	}
	res, err := New().Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, ev := range res.Events {
		counts[ev.EventType]++
		if !ev.Timestamp.IsZero() {
			t.Fatalf("line %s got a full timestamp; the year is not in the file", ev.SourceReference)
		}
	}
	if counts[model.EventPrivilegeSwitch] != 6 || counts[model.EventSudoCommand] != 4 || counts[model.EventLogonSuccess] != 0 || counts[model.EventLogonFailure] != 0 {
		t.Errorf("counts = %v, want privilege_switch 6, sudo_command 4, no logons", counts)
	}
	if len(res.Events) != 10 {
		t.Errorf("events = %d, want 10", len(res.Events))
	}
	for _, ev := range res.Events {
		if ev.EventType == model.EventPrivilegeSwitch && (ev.Extra["target_user"] != "postgres" || ev.Extra["outcome"] != "success" || ev.User != "root" || !strings.HasPrefix(ev.Extra["timestamp_partial"], "Mar 20 11:26:2")) {
			t.Errorf("su %s: target %q outcome %q user %q at %q", ev.SourceReference, ev.Extra["target_user"], ev.Extra["outcome"], ev.User, ev.Extra["timestamp_partial"])
		}
	}
}

func parseBody(t *testing.T, body string) parsers.ParseResult {
	t.Helper()
	res, err := New().Parse(writeLog(t, "auth.log", body))
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestParse_AccountLifecycle(t *testing.T) {
	body := "" +
		"Mar 16 08:12:13 host01 groupadd[4691]: new group: name=alice, GID=1001\n" +
		"Mar 16 08:12:13 host01 useradd[4692]: new user: name=alice, UID=1001, GID=1001, home=/home/alice, shell=/bin/bash\n" +
		"Mar 16 08:12:17 host01 passwd[4695]: pam_unix(passwd:chauthtok): password changed for alice\n" +
		"Mar 16 08:12:20 host01 usermod[4696]: add 'alice' to group 'sudo'\n" +
		"Mar 16 08:12:20 host01 usermod[4696]: add 'alice' to shadow group 'sudo'\n" +
		"Mar 16 08:12:25 host01 usermod[4697]: lock user 'alice' password\n" +
		"Mar 16 08:12:31 host01 userdel[4700]: delete user `alice'\n" +
		"Mar 16 08:12:31 host01 userdel[4700]: removed group `alice' owned by `alice'\n" +
		"Mar 16 08:12:32 host01 userdel[4700]: removed shadow group `alice' owned by `alice'\n"
	res := parseBody(t, body)
	type want struct{ action, object, name string }
	wants := []want{
		{"group_created", "group", "alice"},
		{"user_created", "user", "alice"},
		{"password_changed", "user", "alice"},
		{"group_member_added", "group", "sudo"},
		{"password_locked", "user", "alice"},
		{"user_deleted", "user", "alice"},
		{"group_deleted", "group", "alice"},
	}
	if len(res.Events) != len(wants) {
		t.Fatalf("got %d events, want %d (the shadow-group twins repeat a line and are not emitted)", len(res.Events), len(wants))
	}
	for i, w := range wants {
		e := res.Events[i]
		if e.EventType != model.EventAccountChange {
			t.Fatalf("event %d type %q", i, e.EventType)
		}
		if e.Extra["action"] != w.action || e.Extra["object_type"] != w.object || e.Extra["object_name"] != w.name {
			t.Errorf("event %d = %v, want %+v", i, e.Extra, w)
		}
		if e.User != "" {
			t.Errorf("event %d: the log does not say who asked for the change, User must stay empty, got %q", i, e.User)
		}
		if !e.Timestamp.IsZero() {
			t.Errorf("event %d: no year in the log, Timestamp must stay zero", i)
		}
	}
	if e := res.Events[1]; e.Extra["uid"] != "1001" || e.Extra["home"] != "/home/alice" || e.Extra["shell"] != "/bin/bash" {
		t.Errorf("useradd details lost: %v", e.Extra)
	}
	if e := res.Events[3]; e.Extra["member"] != "alice" {
		t.Errorf("member lost: %v", e.Extra)
	}
}

func TestParse_RelativePositionIsRecordedWithoutAYear(t *testing.T) {
	body := "" +
		"Mar  5 23:59:50 host01 sshd[1]: Failed password for alice from 203.0.113.9 port 1000 ssh2\n" +
		"Mar  6 00:00:20 host01 sshd[1]: Accepted password for alice from 203.0.113.9 port 1001 ssh2\n"
	res := parseBody(t, body)
	if len(res.Events) != 2 {
		t.Fatalf("got %d events", len(res.Events))
	}
	a, b := res.Events[0], res.Events[1]
	pa, ok := partialtime.PositionOf("f", a.Extra)
	pb, ok2 := partialtime.PositionOf("f", b.Extra)
	if !ok || !ok2 {
		t.Fatalf("no position: %v %v", a.Extra, b.Extra)
	}
	if d, ok := partialtime.Delta(pa, pb); !ok || d != 30*time.Second {
		t.Fatalf("delta %v %v, want 30s across the padded-day boundary", d, ok)
	}
	for _, e := range res.Events {
		if !e.Timestamp.IsZero() {
			t.Error("a relative position must never become a timestamp")
		}
		if e.Extra["timestamp_known"] != "false" {
			t.Error("timestamp_known must stay false")
		}
	}
}

func TestParse_LeapCalendarComesFromTheWholeFile(t *testing.T) {
	// The leap day is on the LAST line; the first line must still be read
	// against the leap calendar, or two lines of one file would disagree.
	body := "" +
		"Mar  1 10:00:00 host01 sshd[1]: Failed password for alice from 203.0.113.9 port 1 ssh2\n" +
		"Feb 29 10:00:00 host01 sshd[1]: Failed password for alice from 203.0.113.9 port 2 ssh2\n"
	res := parseBody(t, body)
	for _, e := range res.Events {
		if e.Extra["partial_calendar"] != "leap" {
			t.Errorf("calendar %q, want leap on every event of the file", e.Extra["partial_calendar"])
		}
	}
}
