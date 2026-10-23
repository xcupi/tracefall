// Package credentials stores server-owned integration credentials separately
// from case evidence and the case database. Files are owner-readable, NOT
// encrypted: the OS account running Tracefall and administrators can read them.
package credentials

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var errStorage = errors.New("integration credential storage is unavailable or unsafe")

func prepareDir(path string, create bool) error {
	d := filepath.Dir(path)
	if create {
		if err := os.MkdirAll(d, 0700); err != nil {
			return errStorage
		}
	}
	st, err := os.Lstat(d)
	if os.IsNotExist(err) && !create {
		return nil
	}
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return errStorage
	}
	if err = os.Chmod(d, 0700); err != nil {
		return errStorage
	}
	return nil
}

func checkFile(path string) error {
	st, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !st.Mode().IsRegular() || st.Size() > 256 {
		return errStorage
	}
	return nil
}

// Read returns a saved credential, or an empty string if none is saved.
func Read(path string) (string, error) {
	if err := prepareDir(path, false); err != nil {
		return "", err
	}
	if err := checkFile(path); err != nil {
		return "", err
	}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", errStorage
	}
	defer f.Close()
	if err = f.Chmod(0600); err != nil {
		return "", errStorage
	}
	b, err := io.ReadAll(io.LimitReader(f, 257))
	if err != nil || len(b) > 256 {
		return "", errStorage
	}
	key := strings.TrimSpace(string(b))
	if key == "" {
		return "", errStorage
	}
	return key, nil
}

// Write atomically replaces the saved credential with mode 0600. The caller
// validates the provider's key format; errors never contain a key or its path.
func Write(path, key string) error {
	if key == "" || len(key) > 256 {
		return errStorage
	}
	if err := prepareDir(path, true); err != nil {
		return err
	}
	if err := checkFile(path); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".credential-*")
	if err != nil {
		return errStorage
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	defer f.Close()
	if err = f.Chmod(0600); err != nil {
		return errStorage
	}
	if _, err = f.WriteString(key); err != nil {
		return errStorage
	}
	if err = f.Sync(); err != nil {
		return errStorage
	}
	if err = f.Close(); err != nil {
		return errStorage
	}
	if err = os.Rename(tmp, path); err != nil {
		return errStorage
	}
	return syncDir(filepath.Dir(path))
}

// Remove deletes the saved credential; it does not erase filesystem snapshots,
// backups, swap or process memory. Removing an absent key is idempotent.
func Remove(path string) error {
	if err := prepareDir(path, false); err != nil {
		return err
	}
	if err := checkFile(path); err != nil {
		return err
	}
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return errStorage
	}
	return syncDir(filepath.Dir(path))
}

func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return errStorage
	}
	defer f.Close()
	if err = f.Sync(); err != nil {
		return errStorage
	}
	return nil
}
