//go:build linux

package wmirepository

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"tracefall/internal/evidencepath"
	"tracefall/internal/wmirepo"
)

func TestUnsafeMemberPreservesAdmissionCause(t *testing.T) {
	root := t.TempDir()
	if err := os.Symlink(filepath.Join(t.TempDir(), "absent"), filepath.Join(root, "INDEX.BTR")); err != nil {
		t.Fatal(err)
	}
	f, err := openMember(root, "INDEX.BTR")
	if err == nil {
		f.Close()
		t.Fatal("unsafe member accepted")
	}
	if !errors.Is(err, evidencepath.ErrUnsafe) || !errors.Is(err, wmirepo.ErrUnsupported) {
		t.Fatalf("unsafe cause misreported: %v", err)
	}
}
