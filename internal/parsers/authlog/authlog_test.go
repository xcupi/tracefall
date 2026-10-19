package authlog

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
