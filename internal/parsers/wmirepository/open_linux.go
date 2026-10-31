//go:build linux

package wmirepository

import (
	"fmt"
	"os"
	"tracefall/internal/evidencepath"
	"tracefall/internal/wmirepo"
)

func openMember(root, rel string) (*os.File, error) {
	f, err := evidencepath.Open(root, rel)
	if err != nil {
		return nil, fmt.Errorf("%w: unsafe or unavailable admitted member: %w", wmirepo.ErrUnsupported, err)
	}
	return f, nil
}
