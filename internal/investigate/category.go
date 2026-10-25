package investigate

import (
	"fmt"
	"strings"

	"tracefall/internal/model"
)

// facet is a coarse behavioral dimension a detection rule's finding
// belongs to -- used only for Investigation categorization and scoring,
// never for grouping (see group.go's doc comment: facets describe WHAT
// was found in a group already formed by real evidence links, they never
// become a reason to merge unrelated findings).
type facet int

const (
	facetExecution facet = 1 << iota
	facetScriptInterpreter
	facetPersistence
	facetService
	facetCredential
	facetNetwork
)

// ruleFacets maps every detection rule ID (internal/detect/rules.go's
// All()) to the facet(s) its finding represents. An unmapped rule ID
// contributes no facet and falls through categorize's default case --
// that's a gap to fix here when a new rule is added, not a crash.
var ruleFacets = map[string]facet{
	"office-spawns-powershell":         facetExecution | facetScriptInterpreter,
	"powershell-encoded-command":       facetExecution | facetScriptInterpreter,
	"new-registry-run-key":             facetPersistence,
	"new-scheduled-task":               facetPersistence,
	"suspicious-process-chain":         facetExecution,
	"brute-force-then-success":         facetCredential,
	"execution-persistence-temporal":   facetExecution | facetPersistence,
	"office-spawns-script-interpreter": facetExecution | facetScriptInterpreter,
	"suspicious-parent-child-lineage":  facetExecution,
	"service-persistence":              facetPersistence | facetService,
	"registry-persistence-extended":    facetPersistence,
	"explicit-credential-use":          facetCredential,
	"privileged-logon-observed":        facetCredential,
	"network-after-execution":          facetExecution | facetNetwork,
	"remote-logon-observed":            facetCredential,
	"sql-login-failure-burst":          facetCredential,
	"grafana-login-failure-burst":      facetCredential,
	"grafana-datasource-credential":    facetCredential,
}

// facetsFor unions the facets of every rule ID present in ruleIDs.
func facetsFor(ruleIDs []string) facet {
	var f facet
	for _, id := range ruleIDs {
		f |= ruleFacets[id]
	}
	return f
}

func (f facet) has(x facet) bool { return f&x != 0 }

// categoryLabels are the fixed, small set of analyst-level groupings --
// deliberately not one per detection rule (15 rules, 7 categories). See
// categorize's doc comment for the deterministic decision tree.
var categoryLabels = map[string]string{
	model.InvestigationSuspiciousExecution: "Suspicious Execution",
	model.InvestigationPersistence:         "Persistence",
	model.InvestigationCredentialAttack:    "Credential/Authentication Attack",
	model.InvestigationSuspiciousNetwork:   "Suspicious Network Activity",
	model.InvestigationServicePersistence:  "Service-Based Persistence",
	model.InvestigationScriptBasedAttack:   "Script-Based Attack",
	model.InvestigationMultiStageAttack:    "Multi-Stage Attack",
}

// categorize assigns one of the fixed Investigation categories to a
// group's combined facets, via an explicit, ordered decision tree:
//
//  1. If the group's evidence spans 3 or more of {execution, persistence,
//     credential, network} -- e.g. Office -> PowerShell -> payload ->
//     persistence -> network -- it's a multi-stage attack, regardless of
//     which specific rules fired.
//  2. A group whose ONLY facet is credential activity (brute force,
//     explicit creds, privileged logon, remote logon) is a
//     credential/authentication attack.
//  3. Persistence evidence backed specifically by a service_install event
//     is service-based persistence, distinct from a plain Run
//     key/scheduled task.
//  4. Any other persistence evidence is persistence.
//  5. Network evidence without an execution facet (rare, but possible if
//     a network-after-execution finding's execution step didn't itself
//     produce a separate execution-facet finding) is suspicious network
//     activity.
//  6. Execution evidence involving a scripting interpreter is a
//     script-based attack.
//  7. Any other execution evidence is suspicious execution.
//  8. Fallback (credential or network facet alone, reached only if step 2
//     didn't already match because another facet was also present but
//     none of the above matched it) resolves to the most specific facet
//     still set.
func categorize(f facet) string {
	count := 0
	for _, x := range []facet{facetExecution, facetPersistence, facetCredential, facetNetwork} {
		if f.has(x) {
			count++
		}
	}
	switch {
	case count >= 3:
		return model.InvestigationMultiStageAttack
	case f.has(facetCredential) && !f.has(facetExecution) && !f.has(facetPersistence) && !f.has(facetNetwork):
		return model.InvestigationCredentialAttack
	case f.has(facetPersistence) && f.has(facetService):
		return model.InvestigationServicePersistence
	case f.has(facetPersistence):
		return model.InvestigationPersistence
	case f.has(facetNetwork) && !f.has(facetExecution):
		return model.InvestigationSuspiciousNetwork
	case f.has(facetScriptInterpreter):
		return model.InvestigationScriptBasedAttack
	case f.has(facetExecution):
		return model.InvestigationSuspiciousExecution
	case f.has(facetCredential):
		return model.InvestigationCredentialAttack
	case f.has(facetNetwork):
		return model.InvestigationSuspiciousNetwork
	default:
		return model.InvestigationSuspiciousExecution
	}
}

// buildTitle composes a short analyst-facing title: the category label,
// plus whatever distinguishing detail is available -- the arrow-joined
// steps of a chain correlation if one exists in the group (the most
// specific, narrative detail available), otherwise up to 3 distinct
// process names involved, otherwise just the host.
func buildTitle(category string, chainTitle string, processNames []string, host string) string {
	label := categoryLabels[category]
	switch {
	case chainTitle != "":
		// Correlation titles are formatted "<Prefix>: <arrow steps>"
		// (see internal/correlate's buildTypedChainCorrelation) -- reuse
		// just the arrow-steps portion so the Investigation title doesn't
		// read "Multi-Stage Attack: Activity chain: ...".
		if idx := strings.Index(chainTitle, ": "); idx >= 0 {
			return fmt.Sprintf("%s: %s", label, chainTitle[idx+2:])
		}
		return fmt.Sprintf("%s: %s", label, chainTitle)
	case len(processNames) > 0:
		return fmt.Sprintf("%s: %s", label, strings.Join(processNames, " -> "))
	case host == "":
		return fmt.Sprintf("%s (host not recorded)", label)
	default:
		return fmt.Sprintf("%s on %s", label, host)
	}
}
