package parsestaging

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Workspace owns only parser staging, never evidence or case records. The
// directory lock is held for the server lifetime. A crash releases it in the
// kernel; a subsequent exclusive owner discards incomplete staging and retries
// sources from byte zero. This is recovery/cleanup, not resumable parsing.
type Workspace struct {
	dir  *os.File
	lock *os.File
}

func Open(root string) (*Workspace, error) {
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("parser staging root must be a real directory")
	}
	f, err := os.Open(root)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
		}
	}()
	lock, err := lockDirectory(f)
	if err != nil {
		return nil, fmt.Errorf("parser staging workspace is already owned or cannot be locked: %w", err)
	}
	defer func() {
		if !ok && lock != nil {
			lock.Close()
		}
	}()
	if err := f.Chmod(0700); err != nil {
		return nil, err
	}
	// Read entries in bounded pages. Only our regular temporary files qualify;
	// symlinks/subdirectories and unknown names are never followed or removed.
	for {
		entries, err := f.ReadDir(128)
		for _, e := range entries {
			if e.Type().IsRegular() && strings.HasPrefix(e.Name(), "tracefall-parse-") && strings.HasSuffix(e.Name(), ".partial") {
				if err := os.Remove(filepath.Join(root, e.Name())); err != nil {
					return nil, err
				}
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
	}
	ok = true
	return &Workspace{dir: f, lock: lock}, nil
}
func (w *Workspace) Close() error {
	if w.lock != nil {
		_ = w.lock.Close()
	}
	return w.dir.Close()
}
