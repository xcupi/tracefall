package memory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"tracefall/internal/payload"
)

// Recovery statuses.
const (
	RecoveredOK       = "recovered"
	RecoveredNone     = "not_in_memory"
	RecoveredTooLarge = "too_large"
	RecoveredFailed   = "failed"
)

// RecoveredPart is one piece of a file that Volatility read back from memory.
type RecoveredPart struct {
	// Cache is where in memory it came from: DataSectionObject (the file's
	// cached data), ImageSectionObject (the file as mapped for execution) or
	// SharedCacheMap.
	Cache string `json:"cache"`
	Size  int64  `json:"size"`
	// ZeroPages and TotalPages count the 4 KiB pages that are entirely zero.
	// A page that was not resident in memory comes back as zeros, so a high
	// share means much of the file was simply not there.
	ZeroPages  int            `json:"zero_pages"`
	TotalPages int            `json:"total_pages"`
	Report     payload.Report `json:"report"`
}

// RecoveredFile is the outcome for one file name.
type RecoveredFile struct {
	Name       string          `json:"name"`
	FileObject uint64          `json:"file_object"`
	Status     string          `json:"status"`
	Error      string          `json:"error,omitempty"`
	Tried      int             `json:"offsets_tried"`
	Parts      []RecoveredPart `json:"parts,omitempty"`
}

const (
	dumpPlugin      = "windows.dumpfiles.DumpFiles"
	defaultMaxFiles = 60
	defaultMaxBytes = 32 << 20
	// The same name can be found at several offsets (a freed copy of the
	// object still sits in the pool). Only the first few are worth trying.
	offsetsPerName = 4
)

// candidate is a file name worth reading and every offset it was found at.
type candidate struct {
	name    string
	offsets []uint64
	rank    int
}

// recoveryCandidates picks the runnable files outside the routine locations,
// users' and temporary locations first, then by name, so the choice is the same
// every time.
func recoveryCandidates(rows []map[string]any, max int) []candidate {
	byName := map[string]*candidate{}
	var order []string
	for _, r := range rows {
		name, _ := r["Name"].(string)
		if ClassifyFile(name) != FileInteresting || !Runnable(name) {
			continue
		}
		off, ok := offsetOf(r["Offset"])
		if !ok {
			continue
		}
		k := strings.ToLower(name)
		c := byName[k]
		if c == nil {
			c = &candidate{name: name, rank: rankOf(k)}
			byName[k] = c
			order = append(order, k)
		}
		if len(c.offsets) < offsetsPerName {
			c.offsets = append(c.offsets, off)
		}
	}
	out := make([]candidate, 0, len(order))
	for _, k := range order {
		out = append(out, *byName[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].rank != out[j].rank {
			return out[i].rank < out[j].rank
		}
		return strings.ToLower(out[i].name) < strings.ToLower(out[j].name)
	})
	if len(out) > max {
		out = out[:max]
	}
	return out
}

// rankOf puts the places a program an intruder dropped is likely to sit first.
func rankOf(lower string) int {
	// A browser's cache holds what pages sent, not programs someone ran.
	for _, p := range []string{`\cache\`, `\inetcache\`, `\appcache\`, `\code cache\`} {
		if strings.Contains(lower, p) {
			return 2
		}
	}
	for _, p := range []string{`\users\`, `\temp\`, `\programdata\`, `\downloads\`, `\perflogs\`, `\$recycle.bin\`} {
		if strings.Contains(lower, p) {
			return 0
		}
	}
	return 1
}

func offsetOf(v any) (uint64, bool) {
	switch n := v.(type) {
	case float64:
		if n >= 0 {
			return uint64(n), true
		}
	case json.Number:
		if i, err := n.Int64(); err == nil && i >= 0 {
			return uint64(i), true
		}
	case int64:
		if n >= 0 {
			return uint64(n), true
		}
	case uint64:
		return n, true
	case int:
		if n >= 0 {
			return uint64(n), true
		}
	}
	return 0, false
}

// Recover reads back the contents of the files filescan found, so that what
// they are can be examined. It returns what it recovered and a note saying why
// it did nothing when it did nothing. The bytes are inspected and discarded;
// only their hashes and the inspection are kept.
//
// What comes back is what was in memory: pages that were resident, laid out as
// the cache or the loader held them. An image-section dump of a program is
// laid out as mapped, so its hash is not the hash of the file on disk.
func (r *Runner) Recover(ctx context.Context, image string, filescan []map[string]any, available map[string]bool, progress func(string)) ([]RecoveredFile, string) {
	max := r.cfg.DumpMaxFiles
	if max < 0 {
		return nil, "file recovery is turned off"
	}
	if max == 0 {
		max = defaultMaxFiles
	}
	limit := r.cfg.DumpMaxBytes
	if limit <= 0 {
		limit = defaultMaxBytes
	}
	if !available[dumpPlugin] {
		return nil, "this Volatility does not offer " + dumpPlugin
	}
	cands := recoveryCandidates(filescan, max)
	if len(cands) == 0 {
		return nil, "no runnable file outside the operating system's own locations was found to recover"
	}
	if progress != nil {
		progress(dumpPlugin)
	}
	out := make([]RecoveredFile, 0, len(cands))
	for _, c := range cands {
		if ctx.Err() != nil {
			break
		}
		rf := RecoveredFile{Name: c.name, Status: RecoveredNone}
		for _, off := range c.offsets {
			rf.Tried++
			rf.FileObject = off
			parts, status, err := r.dumpOne(ctx, image, off, limit)
			if errors.Is(err, context.Canceled) {
				return out, "recovery was cancelled"
			}
			if err != nil {
				rf.Status, rf.Error = RecoveredFailed, clipErr(err)
				continue
			}
			rf.Status, rf.Error = status, ""
			if status == RecoveredOK || status == RecoveredTooLarge {
				rf.Parts = parts
				break
			}
		}
		out = append(out, rf)
	}
	return out, ""
}

func clipErr(err error) string {
	s := err.Error()
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

// dumpOne dumps the file object at one address into a private directory,
// inspects what came out and removes the directory.
func (r *Runner) dumpOne(ctx context.Context, image string, off uint64, limit int64) ([]RecoveredPart, string, error) {
	dir, err := os.MkdirTemp(r.cfg.CacheDir, "dump-")
	if err != nil {
		return nil, "", err
	}
	defer os.RemoveAll(dir)
	raw, _, err := r.RunInto(ctx, image, dir, dumpPlugin, "--virtaddr", fmt.Sprintf("%d", off))
	if err != nil {
		return nil, "", err
	}
	rows, err := ParseRows(raw)
	if err != nil {
		return nil, "", err
	}
	var parts []RecoveredPart
	tooLarge := false
	for _, row := range rows {
		res, _ := row["Result"].(string)
		cache, _ := row["Cache"].(string)
		if res == "" || res == "Error" {
			continue
		}
		// The name is whatever Volatility wrote; only a plain file inside the
		// private directory is ever opened.
		path := filepath.Join(dir, filepath.Base(res))
		if filepath.Dir(path) != dir {
			continue
		}
		st, err := os.Lstat(path)
		if err != nil || !st.Mode().IsRegular() {
			continue
		}
		if st.Size() > limit {
			tooLarge = true
			parts = append(parts, RecoveredPart{Cache: cache, Size: st.Size()})
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		rep, ierr := payload.Inspect(f, st.Size())
		f.Close()
		if ierr != nil {
			continue
		}
		zero, total := zeroPages(path)
		parts = append(parts, RecoveredPart{Cache: cache, Size: st.Size(), ZeroPages: zero, TotalPages: total, Report: rep})
	}
	switch {
	case len(parts) == 0:
		return nil, RecoveredNone, nil
	case tooLarge && !hasReport(parts):
		return parts, RecoveredTooLarge, nil
	}
	return parts, RecoveredOK, nil
}

func hasReport(parts []RecoveredPart) bool {
	for _, p := range parts {
		if p.Report.SHA256 != "" {
			return true
		}
	}
	return false
}

// zeroPages counts the 4 KiB pages of a file that are entirely zero.
func zeroPages(path string) (zero, total int) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	buf := make([]byte, 4096)
	for {
		n, err := io.ReadFull(f, buf)
		if n > 0 {
			total++
			allZero := true
			for _, b := range buf[:n] {
				if b != 0 {
					allZero = false
					break
				}
			}
			if allZero {
				zero++
			}
		}
		if err != nil {
			break
		}
	}
	return zero, total
}
