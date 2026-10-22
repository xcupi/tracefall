package regf

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// SiblingLogs returns the transaction logs that sit beside a hive file:
// HIVE.LOG1, HIVE.LOG2 and the older HIVE.LOG. Names are matched without regard
// to case, because collections keep the case the original file system gave them
// and a Linux file system tells them apart. Only regular files are returned, in
// name order. A missing directory has no logs.
func SiblingLogs(hivePath string) []string {
	dir, base := filepath.Split(hivePath)
	if dir == "" {
		dir = "."
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	lower := strings.ToLower(base)
	var out []string
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		n := strings.ToLower(e.Name())
		if n == lower+".log1" || n == lower+".log2" || n == lower+".log" {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(out)
	return out
}

// OpenReplayed opens a hive and, if it was not cleanly written, replays the
// transaction logs found beside it, in memory. Callers that read a hive for its
// content should use this so that every reader of the same file sees the same
// state; Recovery says what was done. A clean hive is read exactly as Open reads
// it.
func OpenReplayed(path string, lim Limits) (*Hive, error) {
	h, _, err := OpenWithLogs(path, SiblingLogs(path), lim)
	return h, err
}
