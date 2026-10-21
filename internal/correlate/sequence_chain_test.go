package correlate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tracefall/internal/model"
	"tracefall/internal/parsers/authlog"
)

func authEvents(t *testing.T, fileID, body string) []model.Event {
	t.Helper()
	p := filepath.Join(t.TempDir(), "auth.log")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := authlog.New().Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	for i := range res.Events {
		res.Events[i].ID = fmt.Sprintf("%s-%d", fileID, i)
		res.Events[i].SourceFileID = fileID
		res.Events[i].Host = "host01"
	}
	return res.Events
}

func sshLine(stamp, verb, user, src string) string {
	return fmt.Sprintf("%s host01 sshd[1]: %s password for %s from %s port 4000 ssh2\n", stamp, verb, user, src)
}

func TestSequenceChain_LinksAFailureRunToTheSuccessWithoutAYear(t *testing.T) {
	body := sshLine("Mar 18 10:00:01", "Failed", "alice", "203.0.113.9") +
		sshLine("Mar 18 10:00:05", "Failed", "alice", "203.0.113.9") +
		sshLine("Mar 18 10:00:09", "Failed", "alice", "203.0.113.9") +
		sshLine("Mar 18 10:00:30", "Accepted", "alice", "203.0.113.9")
	got := BuildCredentialChains("case1", authEvents(t, "f1", body))
	if len(got) != 1 {
		t.Fatalf("got %d chains, want 1", len(got))
	}
	c := got[0]
	if c.Type != model.CorrelationCredentialChain || len(c.EventIDs) != 4 {
		t.Errorf("chain %+v", c)
	}
	if !c.FirstSeen.IsZero() || !c.LastSeen.IsZero() {
		t.Error("no year is known; the chain must not carry a date")
	}
	if strings.Contains(c.Description, "0001") || !strings.Contains(c.Description, "no year") {
		t.Errorf("description: %s", c.Description)
	}
}

func TestSequenceChain_DoesNotCrossAddressesFilesOrYears(t *testing.T) {
	fails := sshLine("Mar 18 10:00:01", "Failed", "alice", "203.0.113.9") +
		sshLine("Mar 18 10:00:05", "Failed", "alice", "203.0.113.9") +
		sshLine("Mar 18 10:00:09", "Failed", "alice", "203.0.113.9")
	if got := BuildCredentialChains("c", authEvents(t, "f1", fails+sshLine("Mar 18 10:00:30", "Accepted", "alice", "203.0.113.77"))); len(got) != 0 {
		t.Errorf("another address: %d chains", len(got))
	}
	both := append(authEvents(t, "f1", fails), authEvents(t, "f2", sshLine("Mar 18 10:00:30", "Accepted", "alice", "203.0.113.9"))...)
	if got := BuildCredentialChains("c", both); len(got) != 0 {
		t.Errorf("two files: %d chains", len(got))
	}
	ny := sshLine("Dec 31 23:58:00", "Failed", "alice", "203.0.113.9") + sshLine("Dec 31 23:58:30", "Failed", "alice", "203.0.113.9") +
		sshLine("Dec 31 23:59:00", "Failed", "alice", "203.0.113.9") + sshLine("Jan  1 00:00:20", "Accepted", "alice", "203.0.113.9")
	if got := BuildCredentialChains("c", authEvents(t, "f1", ny)); len(got) != 0 {
		t.Errorf("across a New Year: %d chains", len(got))
	}
}
