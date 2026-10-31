package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNonregularDiscoveryPersistsUnsupportedReason(t *testing.T) {
	svc := newTestService(t)
	c := mustCreateCase(t, routerFor(svc), "Neutral link inventory")
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "ConsoleHost_history.txt"), []byte("Get-Date\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("ConsoleHost_history.txt", filepath.Join(root, "linked_history")); err != nil {
		t.Fatal(err)
	}
	d, err := svc.DiscoverEvidenceFromPath(c.ID, root)
	if err != nil {
		t.Fatal(err)
	}
	if d.DiscoveredCount != 2 || d.UnsupportedCount != 1 {
		t.Fatalf("lost inventory: %+v", d)
	}
	rows, err := svc.store.ListSourceFilesByCollection(d.Collection.ID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range rows {
		if r.Path == "linked_history" {
			found = true
			v := triage(r)
			if v.Supported || v.SHA256 != "" || !strings.Contains(v.UnsupportedReason, "not followed") {
				t.Fatalf("unsafe or unexplained link: %+v", v)
			}
		}
	}
	if !found {
		t.Fatal("persisted catalog lost link")
	}
}
