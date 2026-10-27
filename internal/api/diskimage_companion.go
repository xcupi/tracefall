package api

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"tracefall/internal/fsvol"
	"tracefall/internal/image"
	"tracefall/internal/model"
	"tracefall/internal/regf"
)

// Registry transaction-log companions of a hive extracted from a disk image.
//
// A hive copied while Windows runs is usually missing its newest changes; they
// sit in HIVE.LOG1/LOG2 (or the older HIVE.LOG) in the same directory, and
// regf.OpenReplayed applies them when it finds them beside the hive on disk.
// The extractor used to copy only files a parser claims, so those logs stayed
// in the image and the hive was read without them.
//
// Policy (docs/registry-transaction-logs.md):
//   - A log is extracted with its hive only when its name is the hive's name
//     plus .LOG1, .LOG2 or .LOG (any case: regf.IsCompanionLogName, the rule
//     SiblingLogs uses), it is a regular in-use file, and it is in the same
//     directory of the same volume. Nothing else is copied.
//   - It is hashed like any extracted file, labeled companion-of its hive in the
//     catalog, and stays "unsupported": it yields no events.
//   - Size is bounded by maxCompanionLogBytes per log and by
//     maxCompanionTotalBytes per import. A log that is too large or cannot be
//     copied is not extracted, the hive is still parsed, and the hive's
//     coverage says which log was not extracted and why.
//   - Anything persisted or rendered about a failure is a fixed, path-free class
//     (permission, io, corrupt, oversize). The raw error, which can name the
//     server's absolute evidence path, goes to the server log only.

// maxCompanionTotalBytes bounds all companion logs copied for one import.
var maxCompanionTotalBytes int64 = 1 << 30

// companionFailureClass reduces an extraction error to a fixed class that is
// safe to store and print: it names no path and no OS message.
func companionFailureClass(err error) string {
	switch {
	case errors.Is(err, fs.ErrPermission):
		return "permission"
	case errors.Is(err, fsvol.ErrCorrupt), errors.Is(err, image.ErrCorrupt):
		return "corrupt"
	default:
		return "io"
	}
}

var companionSuffixes = []string{".LOG1", ".LOG2", ".LOG"}

// companionLogName reports whether name could be a hive's transaction log, by
// its suffix alone. The hive it belongs to is decided separately.
func companionLogName(name string) bool {
	low := strings.ToLower(name)
	for _, s := range companionSuffixes {
		if strings.HasSuffix(low, strings.ToLower(s)) && len(low) > len(s) {
			return true
		}
	}
	return false
}

// companionHiveOf finds the cataloged hive whose log logPath is: the same
// directory and volume, and exactly the hive's name plus a log suffix.
func companionHiveOf(logPath string, hiveByLower map[string]string) (string, bool) {
	dir, name := path.Split(logPath)
	for _, s := range companionSuffixes {
		if len(name) <= len(s) || !strings.EqualFold(name[len(name)-len(s):], s) {
			continue
		}
		hiveName := name[:len(name)-len(s)]
		if hive, ok := hiveByLower[strings.ToLower(dir+hiveName)]; ok && regf.IsCompanionLogName(hiveName, name) {
			return hive, true
		}
	}
	return "", false
}

// companionRows loads the catalog rows by path, once, so that an extracted log
// can be given its hash and label.
func (x *diskExtractor) companionRow(p string) (model.SourceFile, bool) {
	if x.rows == nil {
		x.rows = map[string]model.SourceFile{}
		if files, err := x.svc.store.ListSourceFilesByCollection(x.collectionID); err == nil {
			for _, f := range files {
				if f.ArtifactType == model.ArtifactRegistryTransactionLog {
					x.rows[f.Path] = f
				}
			}
		}
	}
	f, ok := x.rows[p]
	return f, ok
}

// extractCompanions copies the transaction logs that sit beside an already
// extracted hive and records what became of each. It never returns an error: a
// log that cannot be had is a visible status on the hive, not a failed import.
func (x *diskExtractor) extractCompanions(hive model.SourceFile) {
	var res []model.HiveCompanion
	dir, name := path.Split(hive.Path)
	for _, suf := range companionSuffixes {
		for _, c := range x.logs[strings.ToLower(dir+name+suf)] {
			if !regf.IsCompanionLogName(name, path.Base(c.path)) {
				continue
			}
			res = append(res, x.extractCompanion(hive, c))
		}
	}
	x.companions[hive.Path] = res
}

func (x *diskExtractor) extractCompanion(hive model.SourceFile, c companionLog) model.HiveCompanion {
	out := model.HiveCompanion{Path: c.path, SizeBytes: c.size}
	dest := filepath.Join(x.svc.files.EvidenceDir(x.caseID, x.collectionID), filepath.FromSlash(c.path))
	// A log that is not extracted now must not keep what an earlier extraction
	// left: not the copy on disk and not its recorded hash.
	notExtracted := func() {
		_ = os.Remove(dest)
		if row, ok := x.companionRow(c.path); ok {
			_ = x.svc.store.SetSourceFileSHA256(row.ID, "")
		}
	}
	switch {
	case c.size > maxCompanionLogBytes:
		notExtracted()
		out.Status = model.CompanionOversize
		out.Detail = fmt.Sprintf("%d bytes is above the %d byte limit for a transaction log, so it was not extracted and could not be replayed", c.size, maxCompanionLogBytes)
		return out
	case x.companionBytes+c.size > maxCompanionTotalBytes:
		notExtracted()
		out.Status = model.CompanionOversize
		out.Detail = fmt.Sprintf("extracting it would pass the %d byte per-import limit for all transaction logs (%d bytes already extracted), so it was not extracted and could not be replayed", maxCompanionTotalBytes, x.companionBytes)
		return out
	}
	sum, err := x.writeFile(c.path, c.loc)
	if err != nil {
		notExtracted()
		out.Status = model.CompanionFailed
		class := companionFailureClass(err)
		// The raw error can carry the server's absolute evidence path; it stays
		// in the server log and out of everything stored or shown.
		log.Printf("registry companion %s of %s not extracted (%s): %v", c.path, hive.Path, class, err)
		out.Detail = fmt.Sprintf("it could not be extracted (%s)", class)
		return out
	}
	x.companionBytes += c.size
	out.Status, out.SHA256 = model.CompanionExtracted, sum
	if row, ok := x.companionRow(c.path); ok {
		// The hash is Tracefall's own, like any extracted file's. The label is
		// set at discovery; set again here for a catalog made before it existed.
		_ = x.svc.store.SetSourceFileSHA256(row.ID, sum)
		if row.ParseCoverage == nil || row.ParseCoverage.CompanionOf != hive.Path {
			_ = x.svc.store.SetSourceFileCompanion(row.ID, hive.Path)
		}
	}
	return out
}

// mergeHiveReplay adds the extraction side to the hive's replay status once the
// hive has been parsed: the logs that were beside it, and what the extraction
// could not do. events are the hive's parsed events.
//
// Two kinds of statement are made, and only one of them marks the result
// incomplete:
//   - a caveat, for a hive that was not cleanly written: its logs matter, so a
//     log that was not extracted, or that may be missing from a truncated index,
//     means the replay may be incomplete. It goes to Reason, to the coverage
//     Notes (which make the coverage Incomplete) and to the hive's events.
//   - information, for a cleanly written hive: its logs were not consulted, so
//     nothing is missing from the result. It goes to Reason only.
func (x *diskExtractor) mergeHiveReplay(sf *model.SourceFile, events []model.Event) {
	if sf.ArtifactType != model.ArtifactRegistryHive || sf.ParseCoverage == nil || sf.ParseCoverage.HiveReplay == nil {
		return
	}
	hr := sf.ParseCoverage.HiveReplay
	comps := x.companions[sf.Path]
	hr.Companions = append([]model.HiveCompanion(nil), comps...)

	dirty := hr.State != string(regf.RecoveryClean)
	var statements []string
	for _, c := range comps {
		if c.Status != model.CompanionExtracted {
			statements = append(statements, fmt.Sprintf("%s was not extracted (%s): %s", path.Base(c.Path), c.Status, c.Detail))
		}
	}
	noLogs := len(comps) == 0 && hr.State == string(regf.RecoveryNoLogs)
	switch {
	case noLogs && !x.logsTruncated:
		hr.Reason += "; the disk image holds no .LOG1, .LOG2 or .LOG file in this hive's directory, so there was nothing to extract"
	case noLogs:
		statements = append(statements, fmt.Sprintf("none found in the (truncated) index of log files in the image, which reached its limit of %d entries; a log of this hive may exist that was never seen, so replay may be incomplete", x.companionIndexLimit))
	case x.logsTruncated && dirty:
		statements = append(statements, fmt.Sprintf("the index of log files in the image is truncated (limit %d entries), so a log of this hive may have gone unseen and replay may be incomplete", x.companionIndexLimit))
	case x.logsTruncated:
		statements = append(statements, fmt.Sprintf("the index of log files in the image is truncated (limit %d entries); this hive was cleanly written, so a log that went unseen would not have been used", x.companionIndexLimit))
	}
	if len(statements) == 0 {
		return
	}
	text := strings.Join(statements, "; ")
	if !dirty {
		hr.Reason = joinReason(hr.Reason, "the hive was cleanly written, so its transaction logs were not consulted; "+text)
		return
	}
	hr.Reason = joinReason(hr.Reason, text)
	sf.ParseCoverage.Notes = append(sf.ParseCoverage.Notes, truncateNote(text))
	for i := range events {
		if events[i].Extra != nil && events[i].Extra["hive_state"] != "" {
			events[i].Extra["hive_recovery"] = truncateNote(events[i].Extra["hive_recovery"] + "; " + text)
		}
	}
}

func joinReason(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

func truncateNote(s string) string {
	const max = 600
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
