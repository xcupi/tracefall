package api

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

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
//   - Size is bounded by maxCompanionLogBytes. A log that is too large or cannot
//     be copied is not extracted, the hive is still parsed, and the hive's
//     coverage says which log was not extracted and why.

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
	// A copy left by an earlier run must not outlive a decision not to extract.
	drop := func() { _ = os.Remove(dest) }
	if c.size > maxCompanionLogBytes {
		drop()
		out.Status = model.CompanionOversize
		out.Detail = fmt.Sprintf("%d bytes is above the %d byte limit for a transaction log, so it was not extracted and could not be replayed", c.size, maxCompanionLogBytes)
		return out
	}
	sum, err := x.writeFile(c.path, c.loc)
	if err != nil {
		drop()
		out.Status = model.CompanionFailed
		out.Detail = fmt.Sprintf("it could not be extracted from the image (%v)", err)
		return out
	}
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
// hive has been parsed: the logs that were beside it, and, when logs existed
// but were not extracted, a visible statement that the result lacks them. events
// are the hive's parsed events; those already marked as coming from a hive that
// was not cleanly written get the same statement.
func (x *diskExtractor) mergeHiveReplay(sf *model.SourceFile, events []model.Event) {
	if sf.ArtifactType != model.ArtifactRegistryHive || sf.ParseCoverage == nil || sf.ParseCoverage.HiveReplay == nil {
		return
	}
	hr := sf.ParseCoverage.HiveReplay
	comps := x.companions[sf.Path]
	hr.Companions = append([]model.HiveCompanion(nil), comps...)

	var missed []string
	for _, c := range comps {
		if c.Status != model.CompanionExtracted {
			missed = append(missed, fmt.Sprintf("%s was not extracted: %s", path.Base(c.Path), c.Detail))
		}
	}
	dirty := hr.State != string(regf.RecoveryClean)
	switch {
	case len(comps) == 0 && hr.State == string(regf.RecoveryNoLogs):
		hr.Reason += "; the disk image holds no .LOG1, .LOG2 or .LOG file in this hive's directory, so there was nothing to extract"
		if x.logsTruncated {
			hr.Reason += " (the index of log files in the image reached its limit, so a log may have gone unseen)"
		}
	case len(missed) > 0 && dirty:
		text := strings.Join(missed, "; ")
		hr.Reason = joinReason(hr.Reason, text)
		sf.ParseCoverage.Notes = append(sf.ParseCoverage.Notes, truncateNote(text))
		for i := range events {
			if events[i].Extra != nil && events[i].Extra["hive_state"] != "" {
				events[i].Extra["hive_recovery"] = truncateNote(events[i].Extra["hive_recovery"] + "; " + text)
			}
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
