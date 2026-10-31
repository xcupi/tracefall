package ingest

import (
	"os"
	"path/filepath"
	"testing"
	"tracefall/internal/model"
	"tracefall/internal/wmitest"
)

func TestWMIDiscoveryDoesNotFollowUnadmittedSymlinks(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(outside, wmitest.Bundle("")["OBJECTS.DATA"], 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "OBJECTS.DATA")); err != nil {
		t.Fatal(err)
	}
	files, err := Discover(root, Registry())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if f.ArtifactType == model.ArtifactWMIRepository || f.SHA256 != "" {
			t.Fatal("discovery followed and hashed an unadmitted external link")
		}
	}
}
