package credentials

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSavedCredentialRoundTripPermissionsAndRemoval(t *testing.T) {
	p := filepath.Join(t.TempDir(), ".integrations", "virustotal.key")
	key := strings.Repeat("ab", 32)
	if got, err := Read(p); err != nil || got != "" {
		t.Fatalf("missing: %q %v", got, err)
	}
	if err := Write(p, key); err != nil {
		t.Fatal(err)
	}
	got, err := Read(p)
	if err != nil || got != key {
		t.Fatalf("saved key not restored: %q %v", got, err)
	}
	for path, perm := range map[string]os.FileMode{p: 0600, filepath.Dir(p): 0700} {
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != perm {
			t.Fatalf("%s mode %o want %o", path, st.Mode().Perm(), perm)
		}
	}
	if err := Write(p, strings.Repeat("cd", 32)); err != nil {
		t.Fatal(err)
	}
	if got, _ := Read(p); got != strings.Repeat("cd", 32) {
		t.Fatal("replacement not saved")
	}
	entries, _ := os.ReadDir(filepath.Dir(p))
	if len(entries) != 1 {
		t.Fatal("temporary secret left behind")
	}
	if err := Remove(p); err != nil {
		t.Fatal(err)
	}
	if got, err := Read(p); err != nil || got != "" {
		t.Fatal("removed key still present")
	}
	if err := Remove(p); err != nil {
		t.Fatal("remove must be idempotent", err)
	}
}

func TestCredentialRefusesSymlinkAndMalformedStorage(t *testing.T) {
	d := t.TempDir()
	target := filepath.Join(d, "unrelated")
	os.WriteFile(target, []byte("DO-NOT-CHANGE"), 0600)
	p := filepath.Join(d, "key")
	if err := os.Symlink(target, p); err != nil {
		t.Skip(err)
	}
	if _, err := Read(p); err == nil {
		t.Error("read followed a symlink")
	}
	if err := Write(p, strings.Repeat("ab", 32)); err == nil {
		t.Error("write accepted a symlink")
	}
	if err := Remove(p); err == nil {
		t.Error("remove accepted a symlink")
	}
	b, _ := os.ReadFile(target)
	if string(b) != "DO-NOT-CHANGE" {
		t.Fatal("unrelated file changed")
	}
	os.Remove(p)
	os.Mkdir(p, 0700)
	if _, err := Read(p); err == nil {
		t.Error("directory accepted as a secret")
	}
	os.Remove(p)
	os.WriteFile(p, []byte(strings.Repeat("s", 1024)), 0600)
	if _, err := Read(p); err == nil {
		t.Error("oversized secret accepted")
	}
}
