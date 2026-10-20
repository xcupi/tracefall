//go:build !linux

package ingest

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
)

func workerEnv(memMB int, _ bool) []string {
	return []string{"TRACEFALL_PARSER_MEM_MB=" + strconv.Itoa(memMB), "TMPDIR=" + os.TempDir()}
}

func configureChild(*exec.Cmd, bool) {}

func sandboxArgs(string, string) []string { return nil }

// FindSandbox is empty off Linux.
func FindSandbox() string { return "" }

// NetworkIsolationAvailable is false off Linux.
func NetworkIsolationAvailable() bool { return false }

// ApplyWorkerLimits applies nothing off Linux. The caller must say so rather
// than claim a memory limit.
func ApplyWorkerLimits() ([]string, error) {
	return nil, errors.New("resource limits are only applied on Linux")
}
