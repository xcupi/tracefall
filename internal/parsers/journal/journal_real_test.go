package journal

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

// Real-file test: one journal from a real image. Skipped unless
// TRACEFALL_REAL_JOURNAL points at an extracted .journal file and journalctl
// is installed. journalctl is the reference: it reads every entry with its own
// decoder, and the parser must agree with it entry by entry.
//
// Plain entries are compared as (realtime, process, PID, message) tuples.
// Audit records are grouped by their serial on both sides. Each execve group
// must become one process_create event with the same time, PID, process name
// and argument list; any other audit group must match record by record.
func TestReal_JournalMatchesJournalctl(t *testing.T) {
	path := os.Getenv("TRACEFALL_REAL_JOURNAL")
	if path == "" {
		t.Skip("set TRACEFALL_REAL_JOURNAL to an extracted .journal file to run")
	}
	if _, err := exec.LookPath("journalctl"); err != nil {
		t.Skip("journalctl is not installed; it is the reference for this test")
	}

	res, st, err := New().ParseDetailed(path, parsers.ParseContext{})
	if err != nil {
		t.Fatal(err)
	}
	if st.UnsupportedObjects != 0 || st.UndecodableObjects != 0 {
		t.Fatalf("decoding problems on this file: %+v", st)
	}

	ref := journalctlEntries(t, path)
	if len(ref) != st.Entries {
		t.Fatalf("entries: parser read %d, journalctl reads %d", st.Entries, len(ref))
	}

	excluded := map[string]bool{"sshd": true, "sudo": true, "su": true, "CRON": true, "cron": true}

	// Reference audit groups, keyed by serial.
	groups := map[string][]refEntry{}
	for _, e := range ref {
		if e.transport == "audit" && e.auditID != "" {
			groups[e.auditID] = append(groups[e.auditID], e)
		}
	}
	execGroup := map[string]bool{}
	var wantPlain []string
	// wantCmd maps each expected execution, by (realtime, comm, pid), to its
	// reconstructed command line, or to "*" when journalctl's arguments are not
	// reconstructable here (bare-hex or chunked). Those are checked on time,
	// process and PID only.
	wantCmd := map[string]string{}
	var wantLoose []string
	for id, recs := range groups {
		sys := refSyscall(recs)
		if sys == nil {
			continue
		}
		execGroup[id] = true
		if excluded[sys.comm] || excluded[sys.ident] {
			continue
		}
		loose := key(sys.realtime, sys.comm, sys.pid)
		cmd := refArgs(recs)
		if cmd == "" {
			cmd = "*"
		}
		wantCmd[loose] = cmd
		wantLoose = append(wantLoose, loose)
	}
	nonText := map[string]bool{}

	for _, e := range ref {
		if e.transport == "audit" && e.auditID != "" && execGroup[e.auditID] {
			continue // covered by the execution comparison
		}
		if excluded[e.comm] || excluded[e.ident] {
			continue
		}
		if !e.messageIsText {
			// journalctl prints these as byte arrays; the parser keeps them as
			// text with replacement characters, so they are matched by key.
			nonText[key(e.realtime, e.comm, e.pid)] = true
			continue
		}
		wantPlain = append(wantPlain, tuple(e.realtime, e.comm, e.pid, e.message))
	}

	var gotExec, gotPlain []string
	for _, ev := range res.Events {
		if ev.EventType == model.EventProcessCreate {
			loose := key(ev.Timestamp.UnixMicro(), ev.ProcessName, ev.PID)
			cmd := ev.CommandLine
			if want, ok := wantCmd[loose]; ok && want == "*" {
				cmd = "*"
			}
			gotExec = append(gotExec, loose+"|"+cmd)
			continue
		}
		k := key(ev.Timestamp.UnixMicro(), ev.ProcessName, ev.PID)
		if nonText[k] {
			delete(nonText, k)
			continue
		}
		gotPlain = append(gotPlain, tuple(ev.Timestamp.UnixMicro(), ev.ProcessName, ev.PID, ev.Extra["message"]))
	}
	if len(nonText) != 0 {
		t.Fatalf("%d non-text reference entries had no matching event", len(nonText))
	}

	var wantExec []string
	for _, loose := range wantLoose {
		wantExec = append(wantExec, loose+"|"+wantCmd[loose])
	}
	sort.Strings(wantExec)
	sort.Strings(gotExec)
	if len(gotExec) != len(wantExec) {
		t.Fatalf("executions: parser emitted %d, journalctl groups give %d", len(gotExec), len(wantExec))
	}
	for i := range wantExec {
		if gotExec[i] != wantExec[i] {
			t.Fatalf("execution %d differs:\n  parser:     %s\n  journalctl: %s", i, gotExec[i], wantExec[i])
		}
	}

	sort.Strings(wantPlain)
	sort.Strings(gotPlain)
	if len(gotPlain) != len(wantPlain) {
		t.Fatalf("plain events: parser emitted %d, journalctl expects %d", len(gotPlain), len(wantPlain))
	}
	for i := range wantPlain {
		if gotPlain[i] != wantPlain[i] {
			t.Fatalf("plain entry %d differs:\n  parser:     %s\n  journalctl: %s", i, gotPlain[i], wantPlain[i])
		}
	}

	t.Logf("%s: %d entries; %d executions (from %d audit groups) and %d plain events match journalctl; %d excluded; %d non-text",
		path, st.Entries, len(wantExec), len(groups), len(wantPlain), st.Excluded, countNonText(ref))
}

func countNonText(ref []refEntry) int {
	n := 0
	for _, e := range ref {
		if !e.messageIsText {
			n++
		}
	}
	return n
}

type refEntry struct {
	realtime      int64
	comm          string
	ident         string
	pid           int64
	message       string
	messageIsText bool
	transport     string
	auditID       string
}

func key(realtime int64, comm string, pid int64) string {
	return fmt.Sprintf("%d|%s|%d", realtime, comm, pid)
}

func tuple(realtime int64, comm string, pid int64, msg string) string {
	return fmt.Sprintf("%d|%s|%d|%s", realtime, comm, pid, msg)
}

func execKey(realtime int64, comm string, pid int64, cmd string) string {
	return fmt.Sprintf("%d|%s|%d|%s", realtime, comm, pid, cmd)
}

var (
	sysCallRe = regexp.MustCompile(`\bsyscall=(\d+)`)
	archRe    = regexp.MustCompile(`\barch=([0-9A-Fa-f]+)`)
	execArgRe = regexp.MustCompile(`\ba([0-9]+)="([^"]*)"`)
	bareArgRe = regexp.MustCompile(`\ba[0-9]+=[0-9A-Fa-f]+(\s|$)`)
)

// refSyscall returns the execve SYSCALL record of an audit group, from
// journalctl's own fields. It uses the same arch-aware rule as the parser.
func refSyscall(recs []refEntry) *refEntry {
	for i := range recs {
		if !strings.HasPrefix(recs[i].message, "SYSCALL ") {
			continue
		}
		nr := sysCallRe.FindStringSubmatch(recs[i].message)
		arch := archRe.FindStringSubmatch(recs[i].message)
		if nr != nil && arch != nil && isExecSyscall(arch[1], nr[1]) {
			return &recs[i]
		}
	}
	return nil
}

// refArgs rebuilds the argument list from journalctl's EXECVE record. Only
// quoted, unchunked arguments are reconstructed here; an execution with
// bare-hex or chunked arguments is compared without its command line ("").
func refArgs(recs []refEntry) string {
	for _, r := range recs {
		if !strings.HasPrefix(r.message, "EXECVE ") {
			continue
		}
		if strings.Contains(r.message, "[") || bareArgRe.MatchString(r.message) {
			return ""
		}
		args := map[int]string{}
		for _, m := range execArgRe.FindAllStringSubmatch(r.message, -1) {
			n, _ := strconv.Atoi(m[1])
			args[n] = m[2]
		}
		idx := make([]int, 0, len(args))
		for i := range args {
			idx = append(idx, i)
		}
		sort.Ints(idx)
		parts := make([]string, 0, len(idx))
		for _, i := range idx {
			parts = append(parts, args[i])
		}
		return strings.Join(parts, " ")
	}
	return ""
}

// journalctlEntries reads every entry of one file through journalctl's JSON
// output, which is an independent decoder.
func journalctlEntries(t *testing.T, path string) []refEntry {
	t.Helper()
	out, err := exec.Command("journalctl", "--file", path, "--no-pager", "-o", "json").Output()
	if err != nil {
		t.Fatalf("journalctl: %v", err)
	}
	var entries []refEntry
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		e := refEntry{}
		e.realtime, _ = strconv.ParseInt(str(m["__REALTIME_TIMESTAMP"]), 10, 64)
		e.comm = str(m["_COMM"])
		e.ident = str(m["SYSLOG_IDENTIFIER"])
		e.pid, _ = strconv.ParseInt(str(m["_PID"]), 10, 64)
		e.transport = str(m["_TRANSPORT"])
		e.auditID = str(m["_AUDIT_ID"])
		if s, ok := m["MESSAGE"].(string); ok {
			e.message = s
			e.messageIsText = true
		}
		entries = append(entries, e)
	}
	return entries
}

func str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return ""
}
