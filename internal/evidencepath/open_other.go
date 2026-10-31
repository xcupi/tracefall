//go:build !linux

package evidencepath

import "os"

// No path fallback until a no-symlink component walker is platform-validated.
func open(root, rel string, create bool) (*os.File, error) { return nil, ErrUnsafe }
