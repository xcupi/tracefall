package model

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// StableID derives a deterministic, content-addressed identifier from
// parts -- used wherever an ID must be the SAME across repeated
// computation of the same underlying content (Finding/Correlation IDs
// assigned by internal/detect and internal/correlate; Investigation IDs
// assigned by internal/investigate), as opposed to a random
// uuid.NewString() that would differ every time even for byte-identical
// input.
//
// This matters beyond cosmetics: Findings and Correlations are wiped and
// recomputed from scratch on every case re-analysis (see
// internal/store.Store.ReplaceAnalysis). Phase 6 added analyst workflow
// state (status, notes, tags) keyed by finding_id/correlation_id/
// investigation_id in tables entirely separate from the findings/
// correlations tables themselves specifically so that state isn't wiped
// alongside them -- but that separation only actually preserves an
// analyst's assessment across a re-analysis if the SAME real-world
// finding gets the SAME ID both times. A random ID would silently orphan
// every analyst status/note/tag on every re-run, even one that changed
// nothing about the underlying evidence.
//
// idPrefix distinguishes ID namespaces at a glance in logs/URLs (e.g.
// "finding", "corr", "inv") -- purely cosmetic, not parsed by anything.
func StableID(idPrefix string, parts ...string) string {
	sorted := append([]string{}, parts...)
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(strings.Join(sorted, "\x1f")))
	return idPrefix + "-" + hex.EncodeToString(sum[:])[:24]
}
