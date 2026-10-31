//go:build linux

package wmirepository

import (
	"os"
	"tracefall/internal/evidencepath"
	"tracefall/internal/wmirepo"
)

func openMember(root, rel string) (*os.File, error) {
	f, err := evidencepath.Open(root, rel)
	if err != nil {
		return nil, wmirepo.ErrMissingBundle
	}
	return f, nil
}
