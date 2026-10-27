package regf

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// MaxLogFileBytes is the largest transaction log OpenWithLogs will read. A
// caller that copies logs out of a container uses the same ceiling, so a log it
// refuses to extract is one the reader would have refused anyway.
const MaxLogFileBytes = maxLogFileBytes

// IsCompanionLogName reports whether candidate is a transaction log of the hive
// called hiveName: the hive's name plus .LOG1, .LOG2 or .LOG, in any case. It is
// the one naming rule shared by SiblingLogs and by the extraction of a disk
// image, so what is extracted is exactly what a reader would look for.
func IsCompanionLogName(hiveName, candidate string) bool {
	h, c := strings.ToLower(hiveName), strings.ToLower(candidate)
	return h != "" && (c == h+".log1" || c == h+".log2" || c == h+".log")
}

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
	var out []string
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		if IsCompanionLogName(base, e.Name()) {
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
