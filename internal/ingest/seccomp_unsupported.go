//go:build !linux || !(amd64 || arm64)

package ingest

import "errors"

func installSeccomp() error {
	return errors.New("seccomp filter is only built for linux on amd64 and arm64")
}

// DeniedSyscallNames is empty where there is no filter.
func DeniedSyscallNames() []string { return nil }
