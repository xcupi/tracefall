//go:build !linux && !darwin && !windows

package parsestaging

import (
	"fmt"
	"os"
)

func lockDirectory(f *os.File) (*os.File, error) {
	return nil, fmt.Errorf("exclusive parser staging directory locking is unsupported on this platform")
}
