package api

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tracefall/internal/casefiles"
	"tracefall/internal/model"
	"tracefall/internal/store"
)

// openPolicyStore opens a fresh store, the same way newTestService does.
func openPolicyStore(t *testing.T) *store.Store {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "policy.db"))
	if err != nil {
		t.Fatalf("opening test store: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// policyService builds a service with the given policy and one case, and
// returns both. NewService is used directly (not the permissive test helper),
// so the product default is what these tests exercise.
func policyService(t *testing.T, roots []string, allowUnrooted bool) (*Service, model.Case) {
	t.Helper()
	db := openPolicyStore(t)
	svc := NewService(db, casefiles.NewStore(t.TempDir()))
	if err := svc.SetEvidencePathPolicy(roots, allowUnrooted); err != nil {
		t.Fatalf("SetEvidencePathPolicy: %v", err)
	}
	c, err := svc.CreateCase("policy", "")
	if err != nil {
		t.Fatalf("CreateCase: %v", err)
	}
	return svc, c
}

// evidenceFolder creates a folder with one ordinary file and returns its path.
func evidenceFolder(t *testing.T, parent string) string {
	t.Helper()
	dir := filepath.Join(parent, "evidence")
	if err := os.MkdirAll(filepath.Join(dir, "Windows"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Windows", "notes.txt"), []byte("plain file"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestServerPathPolicy_DefaultRefusesServerPaths(t *testing.T) {
	svc, c := policyService(t, nil, false)
	dir := evidenceFolder(t, t.TempDir())

	_, err := svc.DiscoverEvidenceFromPath(c.ID, dir)
	if !errors.Is(err, ErrServerPathRefused) {
		t.Fatalf("err = %v; with no roots and no local-operator mode, server paths must be refused", err)
	}
	if cols, _ := svc.ListCollections(c.ID); len(cols) != 0 {
		t.Errorf("a refused path created %d collection(s)", len(cols))
	}
}

func TestServerPathPolicy_LocalOperatorModeAllowsAnyPath(t *testing.T) {
	svc, c := policyService(t, nil, true)
	dir := evidenceFolder(t, t.TempDir())
	if _, err := svc.DiscoverEvidenceFromPath(c.ID, dir); err != nil {
		t.Fatalf("local no-auth mode with no roots must accept a path: %v", err)
	}
}

func TestServerPathPolicy_RootsAcceptInsideAndRefuseOutside(t *testing.T) {
	root := t.TempDir()
	inside := evidenceFolder(t, root)
	outside := evidenceFolder(t, t.TempDir())
	svc, c := policyService(t, []string{root}, false)

	if _, err := svc.DiscoverEvidenceFromPath(c.ID, inside); err != nil {
		t.Fatalf("a folder inside the root must be accepted: %v", err)
	}
	_, err := svc.DiscoverEvidenceFromPath(c.ID, outside)
	if !errors.Is(err, ErrServerPathRefused) {
		t.Fatalf("err = %v; a folder outside the roots must be refused", err)
	}
	// A sibling that shares the root's name as a prefix is not inside it.
	sibling := root + "-evil"
	if err := os.MkdirAll(sibling, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sibling) })
	if _, err := svc.DiscoverEvidenceFromPath(c.ID, sibling); !errors.Is(err, ErrServerPathRefused) {
		t.Fatalf("err = %v; %q must not count as inside %q", err, sibling, root)
	}
}

func TestServerPathPolicy_SymlinkedRootIsResolved(t *testing.T) {
	realRoot := t.TempDir()
	link := filepath.Join(t.TempDir(), "root-link")
	if err := os.Symlink(realRoot, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	inside := evidenceFolder(t, realRoot)
	// The policy is given the link; the folder is named through the link too.
	svc, c := policyService(t, []string{link}, false)
	if _, err := svc.DiscoverEvidenceFromPath(c.ID, filepath.Join(link, filepath.Base(inside))); err != nil {
		t.Fatalf("a root given through a symlink must still admit its folders: %v", err)
	}
}

func TestServerPathPolicy_SymlinkLeavingTheRootIsRefused(t *testing.T) {
	root := t.TempDir()
	dir := evidenceFolder(t, root)
	secret := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(secret, []byte("not part of the evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(dir, "Windows", "shadow.txt")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	svc, c := policyService(t, []string{root}, false)

	_, err := svc.DiscoverEvidenceFromPath(c.ID, dir)
	if !errors.Is(err, ErrEvidenceTreeEscapes) {
		t.Fatalf("err = %v; a link to a file outside the folder must refuse the whole folder", err)
	}
	if !strings.Contains(err.Error(), "shadow.txt") {
		t.Errorf("the refusal must name the link, got %q", err)
	}
	if cols, _ := svc.ListCollections(c.ID); len(cols) != 0 {
		t.Errorf("a refused folder left %d collection(s) behind", len(cols))
	}
}

func TestServerPathPolicy_SymlinkStayingInsideIsAccepted(t *testing.T) {
	root := t.TempDir()
	dir := evidenceFolder(t, root)
	if err := os.Symlink(filepath.Join(dir, "Windows", "notes.txt"), filepath.Join(dir, "alias.txt")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	svc, c := policyService(t, []string{root}, false)
	if _, err := svc.DiscoverEvidenceFromPath(c.ID, dir); err != nil {
		t.Fatalf("a link that stays inside the folder must not block ingest: %v", err)
	}
}

func TestServerPathPolicy_PathItselfThroughALinkOutsideIsRefused(t *testing.T) {
	root := t.TempDir()
	outside := evidenceFolder(t, t.TempDir())
	link := filepath.Join(root, "sneaky")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	svc, c := policyService(t, []string{root}, false)
	_, err := svc.DiscoverEvidenceFromPath(c.ID, link)
	if !errors.Is(err, ErrServerPathRefused) {
		t.Fatalf("err = %v; a path under the root that resolves outside it must be refused", err)
	}
}

func TestSetEvidencePathPolicy_RejectsAMissingRoot(t *testing.T) {
	svc := NewService(openPolicyStore(t), casefiles.NewStore(t.TempDir()))
	if err := svc.SetEvidencePathPolicy([]string{filepath.Join(t.TempDir(), "typo")}, false); err == nil {
		t.Fatal("a root that does not exist must be an error at startup, not a silent refusal of every path")
	}
}

func TestAuditVerify_ChainHoldsAfterRealWorkAndDeletionLeavesATombstone(t *testing.T) {
	root := t.TempDir()
	dir := evidenceFolder(t, root)
	svc, c := policyService(t, []string{root}, false)
	if _, err := svc.DiscoverEvidenceFromPath(c.ID, dir); err != nil {
		t.Fatal(err)
	}

	st, err := svc.VerifyAudit(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Valid || st.Chained == 0 {
		t.Fatalf("status = %+v; the audit chain of a case with real work must verify", st)
	}

	if err := svc.DeleteCase(c.ID); err != nil {
		t.Fatalf("DeleteCase: %v", err)
	}
	events, err := svc.store.ListSecurityLog(50)
	if err != nil {
		t.Fatal(err)
	}
	var tomb *model.AuditEvent
	for i := range events {
		if events[i].Action == "case_deleted" && events[i].CaseID == c.ID {
			tomb = &events[i]
		}
	}
	if tomb == nil {
		t.Fatal("deleting a case must leave a case_deleted tombstone in security_log")
	}
	if !strings.Contains(tomb.Summary, "chain valid=true") {
		t.Errorf("tombstone summary = %q; it must state the chain's state at deletion", tomb.Summary)
	}
}
