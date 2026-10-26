//go:build linux || darwin

package parsestaging

import (
	"os"
	"syscall"
)

func lockDirectory(f *os.File) (*os.File, error) {
	return nil, syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}
