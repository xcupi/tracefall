package api

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"tracefall/internal/detect"
	"tracefall/internal/model"
)

// Finding severity transparency.
//
// Severity and confidence on a Finding are decided by the detection rule
// that produced it (see internal/detect), from concrete conditions in
// the evidence. This file does NOT change, re-score, or second-guess
// them -- it explains them.
//
// The explanation has exactly two sources, and no third:
//
//  1. The rule's own declared reasoning (internal/detect.Catalog), which
//     says what the rule looks for, what it assigns at minimum, and what
//     would raise that.
//  2. Facts counted from THIS finding's own supporting events -- how many
//     there are, how many distinct artifact types and evidence
//     collections they came from, which hosts and accounts they touch,
//     what timespan they cover.
//
// Nothing is inferred beyond those. There is no factor that says
// "probably" or "typically" about this particular finding, because the
// data to support such a claim does not exist. An explanation an
// investigator cannot check against the evidence would be worse than no
// explanation at all.

// FactorKind groups explanation factors so the UI can present them
// without needing to interpret their text.
const (
	FactorRule          = "rule"          // what the rule detects, and why it rates it as it does
	FactorLevel         = "level"         // whether this finding sits at the rule's base level or above it
	FactorEvidence      = "evidence"      // counted from the supporting events
	FactorCorroboration = "corroboration" // independent sources agreeing
	FactorAttack        = "attack"        // ATT&CK mapping
)

// ExplanationFactor is one checkable statement about a finding.
type ExplanationFactor struct {
	Kind   string `json:"kind"`
	Label  string `json:"label"`
	Detail string `json:"detail"`
}

// SeverityExplanation answers "why is this finding this severe?".
type SeverityExplanation struct {
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	// Rule is the producing rule's declared reasoning, when this build
	// still has that rule. Absent for a finding from a retired rule.
	Rule *detect.RuleDoc `json:"rule,omitempty"`
	// Escalated reports whether this finding sits above its rule's base
	// severity -- which means at least one of the rule's escalating
	// conditions was met by this evidence.
	Escalated bool                `json:"escalated"`
	Factors   []ExplanationFactor `json:"factors"`
}

var severityRank = map[string]int{
	model.SeverityLow: 1, model.SeverityMedium: 2, model.SeverityHigh: 3, model.SeverityCritical: 4,
}

// explainFinding builds the explanation for one finding from its own
// supporting events.
func explainFinding(f model.Finding, supporting []model.Event) SeverityExplanation {
	out := SeverityExplanation{
		Severity:   f.Severity,
		Confidence: f.Confidence,
		Factors:    []ExplanationFactor{},
	}

	if doc, ok := detect.DocFor(f.RuleID); ok {
		out.Rule = &doc
		out.Factors = append(out.Factors, ExplanationFactor{
			Kind: FactorRule, Label: "Detection rule", Detail: doc.Detects,
		})
		out.Factors = append(out.Factors, ExplanationFactor{
			Kind: FactorRule, Label: "Why this level", Detail: doc.Basis,
		})

		out.Escalated = severityRank[f.Severity] > severityRank[doc.BaseSeverity]
		switch {
		case out.Escalated && len(doc.Escalates) > 0:
			// The rule raised this finding above its floor, so at least
			// one of its escalating conditions was met by this evidence.
			// Which one is not recorded on the finding, so the honest
			// statement names the candidates rather than picking one.
			out.Factors = append(out.Factors, ExplanationFactor{
				Kind:  FactorLevel,
				Label: fmt.Sprintf("Raised above the rule's baseline (%s)", doc.BaseSeverity),
				Detail: "This finding met at least one of the rule's escalating conditions: " +
					joinSentence(doc.Escalates) + ".",
			})
		case len(doc.Escalates) > 0:
			out.Factors = append(out.Factors, ExplanationFactor{
				Kind:  FactorLevel,
				Label: "At the rule's baseline",
				Detail: "None of the rule's escalating conditions were met: " +
					joinSentence(doc.Escalates) + ".",
			})
		default:
			out.Factors = append(out.Factors, ExplanationFactor{
				Kind:   FactorLevel,
				Label:  "Fixed severity",
				Detail: "This rule assigns one level; it has no escalating conditions.",
			})
		}
	} else {
		out.Factors = append(out.Factors, ExplanationFactor{
			Kind:   FactorRule,
			Label:  "Detection rule",
			Detail: fmt.Sprintf("Produced by rule %q, which this build of Tracefall no longer has. Its reasoning cannot be shown.", f.RuleID),
		})
	}

	// ---- facts counted from the actual supporting evidence ----

	if n := len(supporting); n > 0 {
		out.Factors = append(out.Factors, ExplanationFactor{
			Kind:   FactorEvidence,
			Label:  plural(n, "supporting event", "supporting events"),
			Detail: describeSpan(supporting),
		})
	}

	artifacts := distinct(supporting, func(e model.Event) string { return e.ArtifactType })
	if len(artifacts) > 1 {
		// Two artifact types describing the same behaviour is genuine
		// corroboration: an event log and a registry hive are collected
		// and written independently of each other.
		out.Factors = append(out.Factors, ExplanationFactor{
			Kind:   FactorCorroboration,
			Label:  "Corroborated across artifact types",
			Detail: "Supporting evidence comes from " + joinSentence(labelAll(artifacts)) + ".",
		})
	} else if len(artifacts) == 1 {
		out.Factors = append(out.Factors, ExplanationFactor{
			Kind:   FactorEvidence,
			Label:  "Single artifact type",
			Detail: "All supporting evidence comes from " + artifactTypeLabel(artifacts[0]) + ".",
		})
	}

	if collections := distinct(supporting, func(e model.Event) string { return e.CollectionID }); len(collections) > 1 {
		out.Factors = append(out.Factors, ExplanationFactor{
			Kind:   FactorCorroboration,
			Label:  "Observed in multiple evidence collections",
			Detail: fmt.Sprintf("The supporting events span %d separate collections added to this case.", len(collections)),
		})
	}

	if hosts := distinct(supporting, func(e model.Event) string { return e.Host }); len(hosts) > 0 {
		label := "Host"
		if len(hosts) > 1 {
			label = "Hosts"
		}
		out.Factors = append(out.Factors, ExplanationFactor{
			Kind: FactorEvidence, Label: label, Detail: strings.Join(hosts, ", "),
		})
	}
	if users := distinct(supporting, func(e model.Event) string { return e.User }); len(users) > 0 {
		label := "Account"
		if len(users) > 1 {
			label = "Accounts"
		}
		out.Factors = append(out.Factors, ExplanationFactor{
			Kind: FactorEvidence, Label: label, Detail: strings.Join(users, ", "),
		})
	}

	if len(f.Techniques) > 0 {
		out.Factors = append(out.Factors, ExplanationFactor{
			Kind:   FactorAttack,
			Label:  plural(len(f.Techniques), "ATT&CK technique", "ATT&CK techniques"),
			Detail: strings.Join(f.Techniques, ", "),
		})
	}

	return out
}

// describeSpan states the timespan the supporting events cover, in UTC.
func describeSpan(events []model.Event) string {
	if len(events) == 0 {
		return ""
	}
	var first, last time.Time
	undated := 0
	for _, e := range events {
		if e.Timestamp.IsZero() {
			undated++
			continue
		}
		if first.IsZero() || e.Timestamp.Before(first) {
			first = e.Timestamp
		}
		if last.IsZero() || e.Timestamp.After(last) {
			last = e.Timestamp
		}
	}
	unknown := ""
	if undated > 0 {
		unknown = fmt.Sprintf("%d supporting event(s): time not recorded (a partial timestamp, if present, is not a complete instant); temporal order relative to other events is not established.", undated)
	}
	if first.IsZero() {
		return unknown
	}
	if unknown != "" {
		unknown = " " + unknown
	}
	const layout = "2006-01-02 15:04:05 UTC"
	if first.Equal(last) {
		tie := ""
		if len(events)-undated > 1 {
			tie = " Dated supporting events share the same timestamp; their order is not established."
		}
		return "At " + first.UTC().Format(layout) + "." + tie + unknown
	}
	return fmt.Sprintf("Dated supporting events: from %s to %s (%s).%s",
		first.UTC().Format(layout), last.UTC().Format(layout), humanDuration(last.Sub(first)), unknown)
}

func humanDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d seconds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%.1f hours", d.Hours())
	default:
		return fmt.Sprintf("%.1f days", d.Hours()/24)
	}
}

func distinct(events []model.Event, key func(model.Event) string) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range events {
		v := strings.TrimSpace(key(e))
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func labelAll(artifactTypes []string) []string {
	out := make([]string, 0, len(artifactTypes))
	for _, t := range artifactTypes {
		out = append(out, artifactTypeLabel(t))
	}
	return out
}

// artifactTypeLabel reuses the capability registry's label, so an
// artifact is named identically here and in the evidence triage view.
func artifactTypeLabel(artifactType string) string {
	return capabilities.Classify("", artifactType).Label
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// joinSentence renders a list as "a, b and c".
func joinSentence(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	case 2:
		return items[0] + " and " + items[1]
	default:
		return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
	}
}

// SeverityModel is the read-only description of how Tracefall decides
// severity, served to the dashboard so the model can be inspected rather
// than taken on trust.
type SeverityModel struct {
	// Configurable is false and is expected to stay false -- see the
	// Note field and docs/investigation-filtering.md.
	Configurable bool             `json:"configurable"`
	Note         string           `json:"note"`
	Levels       []LabeledValue   `json:"levels"`
	Confidences  []LabeledValue   `json:"confidences"`
	Rules        []detect.RuleDoc `json:"rules"`
}

// SeverityModelReport describes the finding-severity model.
func (s *Service) SeverityModelReport() SeverityModel {
	return SeverityModel{
		Configurable: false,
		Note: "Finding severity is decided by the detection rule that produced the finding, from concrete conditions " +
			"in the evidence. It is not a configurable score. Findings are recomputed from scratch on every " +
			"re-analysis, so a runtime-editable severity table would silently rewrite the severity of historical " +
			"findings the next time a case was analyzed -- which is why the model is fixed in the build and " +
			"published here for inspection instead.",
		Levels: []LabeledValue{
			{Value: model.SeverityCritical, Label: "Critical"},
			{Value: model.SeverityHigh, Label: "High"},
			{Value: model.SeverityMedium, Label: "Medium"},
			{Value: model.SeverityLow, Label: "Low"},
		},
		Confidences: []LabeledValue{
			{Value: model.ConfidenceHigh, Label: "High"},
			{Value: model.ConfidenceMedium, Label: "Medium"},
			{Value: model.ConfidenceLow, Label: "Low"},
		},
		Rules: detect.Catalog(),
	}
}
