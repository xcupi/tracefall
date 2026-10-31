//go:build linux

package evidencepath

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAdmittedRootPrefixMayResolveButMembersNeverFollowLinks(t *testing.T) {
	real := t.TempDir()
	root := filepath.Join(real, "evidence")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "operator-data")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	admitted := filepath.Join(link, "evidence")
	f, err := Create(admitted, "sub/member")
	if err != nil {
		t.Fatalf("operator root prefix rejected: %v", err)
	}
	if _, err = f.Write([]byte("neutral")); err != nil {
		t.Fatal(err)
	}
	f.Close()
	f, err = Open(admitted, "sub/member")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err = os.Symlink(filepath.Join(root, "sub"), filepath.Join(root, "inside-link")); err != nil {
		t.Fatal(err)
	}
	for _, fn := range []func(string, string) (*os.File, error){Open, Create} {
		f, err = fn(admitted, "inside-link/member")
		if err == nil {
			f.Close()
			t.Fatal("followed link beneath admitted root")
		}
	}
}
