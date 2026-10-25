package artifacts_test

import (
	"testing"

	"tracefall/internal/artifacts"
	"tracefall/internal/model"
)

// The Defender support log is read selectively; the registry must say it is
// supported, High priority, and state what is and is not read.
func TestDefenderMPLogIsSupportedAndStatesItsLimits(t *testing.T) {
	c := reg().Classify("ProgramData/Microsoft/Windows Defender/Support/MPLog-20260901-120000.log", model.ArtifactDefenderMPLog)
	if !c.Supported || c.Priority != artifacts.PriorityHigh || c.Label == "" || c.Family == "" || c.PriorityReason == "" {
		t.Fatalf("%+v", c)
	}
	if c.FamilyLabel == "" {
		t.Errorf("family %q has no label", c.Family)
	}
	if c.Note == "" {
		t.Errorf("a selective reader must carry a note on what is not read")
	}
}
