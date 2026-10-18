package journal

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"testing"

	"tracefall/internal/parsers"
)

// Real-file test: one journal from the CyberDefenders AzurePot image. It is
// skipped unless TRACEFALL_REAL_JOURNAL points at an extracted .journal file
// and journalctl is installed. journalctl is the reference: the parser must
// emit the same (realtime, process, PID, message) tuples for every entry that
// is not left to the text-log parsers, and the same total entry count.
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

	// Reference tuples for the entries that should become events, skipping
	// entries whose message is not valid text on the journalctl side (it
	// prints those as byte arrays; the parser keeps them as text, so they are
	// not comparable tuple-for-tuple).
	excluded := map[string]bool{"sshd": true, "sudo": true, "su": true, "CRON": true, "cron": true}
	var want []string
	// nonText holds the key of every entry journalctl prints as bytes. The
	// parser keeps those as text (with replacement characters), so they are
	// removed from both sides by key and counted, not compared.
	nonText := map[string]bool{}
	for _, e := range ref {
		if excluded[e.comm] || excluded[e.ident] {
			continue
		}
		if !e.messageIsText {
			nonText[key(e.realtime, e.comm, e.pid)] = true
			continue
		}
		want = append(want, tuple(e.realtime, e.comm, e.pid, e.message))
	}

	var got []string
	for _, ev := range res.Events {
		k := key(ev.Timestamp.UnixMicro(), ev.ProcessName, ev.PID)
		if nonText[k] {
			delete(nonText, k) // consumed: this is the non-text entry
			continue
		}
		got = append(got, tuple(ev.Timestamp.UnixMicro(), ev.ProcessName, ev.PID, ev.Extra["message"]))
	}
	if len(nonText) != 0 {
		t.Fatalf("%d non-text reference entries had no matching event", len(nonText))
	}

	sort.Strings(want)
	sort.Strings(got)
	if len(got) != len(want) {
		t.Fatalf("emitted %d text events, journalctl expects %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("entry %d differs:\n  parser:     %s\n  journalctl: %s", i, got[i], want[i])
		}
	}
	nonTextCount := 0
	for _, e := range ref {
		if !excluded[e.comm] && !excluded[e.ident] && !e.messageIsText {
			nonTextCount++
		}
	}
	t.Logf("%s: %d entries, %d emitted, %d excluded, %d non-text messages (matched by key), all text tuples equal",
		path, st.Entries, st.Emitted, st.Excluded, nonTextCount)
}

type refEntry struct {
	realtime      int64
	comm          string
	ident         string
	pid           int64
	message       string
	messageIsText bool
}

func key(realtime int64, comm string, pid int64) string {
	return fmt.Sprintf("%d|%s|%d", realtime, comm, pid)
}

func tuple(realtime int64, comm string, pid int64, msg string) string {
	return fmt.Sprintf("%d|%s|%d|%s", realtime, comm, pid, msg)
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
		if s, ok := m["MESSAGE"].(string); ok {
			e.message = s
			e.messageIsText = true
		}
		entries = append(entries, e)
	}
	return entries
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
