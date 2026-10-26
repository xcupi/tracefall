//go:build windows

package parsestaging

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// Windows cannot byte-lock a directory handle; keep a separate lock file open.
func lockDirectory(dir *os.File) (*os.File, error) {
	path := filepath.Join(dir.Name(), ".owner.lock")
	if st, err := os.Lstat(path); err == nil && !st.Mode().IsRegular() {
		return nil, fmt.Errorf("parser staging lock must be a regular file")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	var overlapped windows.Overlapped
	if err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
