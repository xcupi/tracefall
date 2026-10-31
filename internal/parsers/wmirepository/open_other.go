//go:build !linux

package wmirepository

import (
	"os"
	"tracefall/internal/wmirepo"
)

// The native byte reader is portable. Filesystem admission remains fail-closed
// until a no-symlink component walker has been validated for this platform.
func openMember(root, rel string) (*os.File, error) { return nil, wmirepo.ErrUnsupported }
