//go:build linux

package evidencepath

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Each component is opened relative to a pinned descriptor with O_NOFOLLOW.
// Containment does not depend on a racy Lstat followed by path-based Open.
func open(root, rel string, create bool) (*os.File, error) {
	if !filepath.IsAbs(root) || rel == "" || strings.Contains(rel, `\`) || filepath.IsAbs(rel) || filepath.Clean(rel) != rel || rel == ".." || strings.HasPrefix(rel, "../") {
		return nil, ErrUnsafe
	}
	cleanRoot := strings.TrimPrefix(filepath.Clean(root), "/")
	parts := strings.Split(cleanRoot+"/"+rel, "/")
	rootParts := len(strings.Split(cleanRoot, "/"))
	if cleanRoot == "" {
		parts = strings.Split(rel, "/")
		rootParts = 0
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnsafe
	}
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			syscall.Close(fd)
			return nil, ErrUnsafe
		}
		last := i == len(parts)-1
		flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK
		if !last {
			flags |= syscall.O_DIRECTORY
		} else if create {
			flags = syscall.O_WRONLY | syscall.O_CREAT | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK
		}
		next, e := syscall.Openat(fd, part, flags, 0600)
		if e == syscall.ENOENT && create && !last && i >= rootParts {
			if e = syscall.Mkdirat(fd, part, 0700); e == nil || e == syscall.EEXIST {
				next, e = syscall.Openat(fd, part, flags, 0)
			}
		}
		syscall.Close(fd)
		if e != nil {
			return nil, ErrUnsafe
		}
		fd = next
	}
	f := os.NewFile(uintptr(fd), "admitted-evidence-member")
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, ErrUnsafe
	}
	if create {
		if err = f.Truncate(0); err != nil {
			f.Close()
			return nil, ErrUnsafe
		}
	}
	return f, nil
}
