package api

import (
	"sort"

	"tracefall/internal/artifacts"
	"tracefall/internal/ingest"
	"tracefall/internal/model"
)

// This file adds the evidence-triage VIEW over a collection's catalog:
// what each discovered file is, how forensically valuable its artifact
// class is, and a summary of the whole catalog.
//
// Every field here is computed at READ TIME from the capability registry
// (internal/artifacts) plus the source file rows already stored. Nothing
// is persisted, so there is no migration, no new column, and no way for
// a stored triage judgement to go stale when the parser registry or the
// priority table changes -- reclassification happens simply by shipping
// a new build.

// capabilities is the process-wide capability registry, derived from the
// live parser registry. It is immutable after construction and safe to
// share.
var capabilities = artifacts.NewRegistry(ingest.Registry())

// TriagedSourceFile is a cataloged file plus its triage classification.
//
// model.SourceFile is EMBEDDED rather than nested, so the JSON is purely
// additive: every field the dashboard already read (id, path, sha256,
// import_status, ...) stays exactly where it was, and the triage fields
// appear alongside them.
type TriagedSourceFile struct {
	model.SourceFile
	// TypeLabel is the human-readable artifact class -- for a supported
	// file the parser's artifact type, for an unsupported one whatever
	// the capability registry recognized from its path.
	TypeLabel   string `json:"type_label"`
	Family      string `json:"family"`
	FamilyLabel string `json:"family_label"`
	Priority    string `json:"priority"`
	// PriorityReason states why this artifact class carries that
	// priority. Always present, for supported and unsupported files
	// alike -- priority is a judgement about the artifact, and a
	// judgement an analyst cannot inspect is one they cannot check.
	PriorityReason string `json:"priority_reason,omitempty"`
	// UnsupportedReason explains, in plain language, why Tracefall cannot
	// parse this file. Empty for supported files.
	UnsupportedReason string `json:"unsupported_reason,omitempty"`
	// Note qualifies a SUPPORTED file -- currently a cache container,
	// which is parsed but is not an event source. Kept apart from
	// UnsupportedReason so a note can never be read as a failure.
	Note string `json:"note,omitempty"`
	// Recognized distinguishes "Tracefall knows what this is and has no
	// parser for it" (NTFS $MFT) from "Tracefall has no idea what this
	// is". Both are unsupported; only one is actionable.
	Recognized bool `json:"recognized"`
	// ParsedInstead / NotParsed carry the capability boundary for this
	// file's family, so an unsupported row can say what IS covered
	// instead of implying the whole family is a gap.
	ParsedInstead []string `json:"parsed_instead,omitempty"`
	NotParsed     []string `json:"not_parsed,omitempty"`
	// Recommended marks high-value evidence that can actually be
	// imported -- what "Select recommended" acts on.
	Recommended bool `json:"recommended"`
	// CompanionOf names the hive a registry transaction log was extracted
	// with. Such a file is read only together with that hive: it is not an
	// independent source, produces no events and is not an unparsed gap.
	CompanionOf string `json:"companion_of,omitempty"`
}

// triage classifies one source file.
func triage(sf model.SourceFile) TriagedSourceFile {
	cap := capabilities.Classify(sf.Path, sf.ArtifactType)
	if sf.ParseCoverage != nil && sf.ParseCoverage.CompanionOf != "" && sf.ArtifactType == model.ArtifactRegistryTransactionLog {
		// Extracted with its hive and replayed over it in memory: present and
		// used, not a file Tracefall failed to read.
		cap.Reason = ""
		cap.Note = "Companion of " + sf.ParseCoverage.CompanionOf + ". It is extracted with that hive and, when the hive was not cleanly " +
			"written, replayed over it in memory. It is not an independent source: it produces no events of its own, " +
			"and the hive's own coverage says whether it was applied."
		cap.Recognized = true
	}
	companionOf := ""
	if sf.ParseCoverage != nil {
		companionOf = sf.ParseCoverage.CompanionOf
	}
	return TriagedSourceFile{
		CompanionOf:       companionOf,
		SourceFile:        sf,
		TypeLabel:         cap.Label,
		Family:            string(cap.Family),
		FamilyLabel:       cap.FamilyLabel,
		Priority:          string(cap.Priority),
		PriorityReason:    cap.PriorityReason,
		UnsupportedReason: cap.Reason,
		Note:              cap.Note,
		Recognized:        cap.Recognized,
		ParsedInstead:     cap.ParsedInstead,
		NotParsed:         cap.NotParsed,
		// Only a file that is still selectable can be recommended:
		// recommending something already imported, duplicated or failed
		// would put entries in "Select recommended" that do nothing.
		Recommended: cap.Recommended() && sf.ImportStatus == model.SourceFileDiscovered,
	}
}

// triageAll classifies a whole catalog, preserving order.
func triageAll(files []model.SourceFile) []TriagedSourceFile {
	out := make([]TriagedSourceFile, 0, len(files))
	for _, sf := range files {
		out = append(out, triage(sf))
	}
	return out
}

// CoverageBucket is one artifact class's share of a catalog.
type CoverageBucket struct {
	TypeLabel      string `json:"type_label"`
	Family         string `json:"family"`
	FamilyLabel    string `json:"family_label"`
	Priority       string `json:"priority"`
	PriorityReason string `json:"priority_reason,omitempty"`
	Supported      bool   `json:"supported"`
	// Files is how many files of this class the catalog holds;
	// SupportedFiles how many of them Tracefall can actually parse
	// (equal to Files for a supported class, zero otherwise);
	// ImportedFiles how many have actually become evidence.
	Files          int `json:"files"`
	SupportedFiles int `json:"supported_files"`
	ImportedFiles  int `json:"imported_files"`
	// Reason (unsupported) and Note (supported but qualified) are the
	// two halves of the Notes column. They are never both set.
	Reason string `json:"reason,omitempty"`
	Note   string `json:"note,omitempty"`
}

// Coverage summarizes what an evidence collection actually contains.
// This is the answer to "I just added a 7,000-file image -- what is in
// it and what will Tracefall do with it?", which the catalog alone could
// not give.
//
// Every number is counted from the real catalog; none is estimated.
type Coverage struct {
	Discovered  int `json:"discovered"`
	Supported   int `json:"supported"`
	Unsupported int `json:"unsupported"`
	Duplicates  int `json:"duplicates"`
	Imported    int `json:"imported"`
	// NotImported counts supported files still awaiting selection.
	NotImported int `json:"not_imported"`
	ParseFailed int `json:"parse_failed"`
	Recommended int `json:"recommended"`
	// Companions counts registry transaction logs extracted with their hive. They
	// are still part of Discovered and Unsupported (no parser reads them on their
	// own); this says how many of those are not gaps.
	Companions int `json:"companions,omitempty"`
	// ByType breaks the catalog down by artifact class, most valuable
	// first, so the highest-priority evidence is what an investigator
	// reads first.
	ByType []CoverageBucket `json:"by_type"`
}

// computeCoverage summarizes an already-triaged catalog.
func computeCoverage(files []TriagedSourceFile) Coverage {
	cov := Coverage{Discovered: len(files)}

	type key struct{ label, priority string }
	buckets := map[key]*CoverageBucket{}

	for _, f := range files {
		if f.Supported {
			cov.Supported++
		} else {
			cov.Unsupported++
		}
		if f.CompanionOf != "" {
			cov.Companions++
		}
		switch f.ImportStatus {
		case model.SourceFileImported:
			cov.Imported++
		case model.SourceFileDuplicate:
			cov.Duplicates++
		case model.SourceFileFailed:
			cov.ParseFailed++
		case model.SourceFileDiscovered:
			cov.NotImported++
		}
		if f.Recommended {
			cov.Recommended++
		}

		k := key{f.TypeLabel, f.Priority}
		b, ok := buckets[k]
		if !ok {
			b = &CoverageBucket{
				TypeLabel: f.TypeLabel, Family: f.Family, FamilyLabel: f.FamilyLabel,
				Priority: f.Priority, PriorityReason: f.PriorityReason, Supported: f.Supported,
				Reason: f.UnsupportedReason, Note: f.Note,
			}
			buckets[k] = b
		}
		b.Files++
		if f.Supported {
			b.SupportedFiles++
		}
		if f.ImportStatus == model.SourceFileImported {
			b.ImportedFiles++
		}
	}

	cov.ByType = make([]CoverageBucket, 0, len(buckets))
	for _, b := range buckets {
		cov.ByType = append(cov.ByType, *b)
	}
	// Most forensically valuable first, then largest, then by name --
	// fully deterministic, so the same catalog always renders the same
	// way.
	sort.Slice(cov.ByType, func(i, j int) bool {
		a, b := cov.ByType[i], cov.ByType[j]
		if ra, rb := artifacts.Priority(a.Priority).Rank(), artifacts.Priority(b.Priority).Rank(); ra != rb {
			return ra < rb
		}
		if a.Supported != b.Supported {
			return a.Supported // supported classes first within a priority
		}
		if a.Files != b.Files {
			return a.Files > b.Files
		}
		return a.TypeLabel < b.TypeLabel
	})
	return cov
}

// CapabilityReport is what GET /api/capabilities returns: exactly what
// this build of Tracefall can and cannot parse, so the dashboard renders
// the registry rather than restating it.
type CapabilityReport struct {
	Supported   []artifacts.Capability `json:"supported"`
	Unsupported []artifacts.Capability `json:"unsupported"`
	// Priorities and Families are the vocabularies the UI's filters are
	// built from, so a new priority or family added in Go appears in the
	// UI without a frontend change.
	Priorities []LabeledValue `json:"priorities"`
	Families   []LabeledValue `json:"families"`
	Statuses   []LabeledValue `json:"statuses"`
}

// LabeledValue is a filter vocabulary entry: the value the API uses and
// the text a human reads.
type LabeledValue struct {
	Value string `json:"value"`
	Label string `json:"label"`
	// Count is how many records in the whole catalog carry this value.
	// Omitted where it is not meaningful (the capability report, which
	// describes the build rather than a case).
	Count int `json:"count,omitempty"`
}

// Capabilities reports this build's artifact coverage.
func (s *Service) Capabilities() CapabilityReport {
	supported := capabilities.Supported()
	unsupported := capabilities.Unsupported()

	families := map[string]string{}
	for _, c := range supported {
		families[string(c.Family)] = c.FamilyLabel
	}
	for _, c := range unsupported {
		families[string(c.Family)] = c.FamilyLabel
	}
	famList := make([]LabeledValue, 0, len(families))
	for v, l := range families {
		famList = append(famList, LabeledValue{Value: v, Label: l})
	}
	sort.Slice(famList, func(i, j int) bool { return famList[i].Label < famList[j].Label })

	return CapabilityReport{
		Supported:   supported,
		Unsupported: unsupported,
		Priorities: []LabeledValue{
			{Value: string(artifacts.PriorityCritical), Label: "Critical"},
			{Value: string(artifacts.PriorityHigh), Label: "High"},
			{Value: string(artifacts.PriorityMedium), Label: "Medium"},
			{Value: string(artifacts.PriorityLow), Label: "Low"},
			{Value: string(artifacts.PriorityUnknown), Label: "Unknown"},
		},
		Families: famList,
		Statuses: []LabeledValue{
			{Value: "supported", Label: "Supported"},
			{Value: "unsupported", Label: "Unsupported"},
			{Value: model.SourceFileImported, Label: "Imported"},
			{Value: model.SourceFileDiscovered, Label: "Not imported"},
			{Value: model.SourceFileDuplicate, Label: "Duplicate"},
			{Value: model.SourceFileFailed, Label: "Parse error"},
		},
	}
}
