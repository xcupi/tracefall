package api

import (
	"os/exec"
	"strings"
	"testing"
)

func TestUI_VTIntegrationSettingsAreDiscoverableAndSecretSafe(t *testing.T) {
	src := appJS(t)
	for _, want := range []string{"/settings/integrations", "Settings", "renderVTIntegrationForm("} {
		if !strings.Contains(string(src), want) {
			t.Errorf("missing integration settings UI: %s", want)
		}
	}
	if !strings.Contains(string(src), "function renderVTIntegrationForm(") {
		return
	}
	js := "const esc=s=>String(s);\nfunction renderVTIntegrationForm(" + strings.Split(functionBody(t, src, "function renderVTIntegrationForm("), "\nasync function ")[0] + "\nconsole.log(renderVTIntegrationForm({configured:true,source:'saved',editable:true}));"
	out, err := exec.Command("node", "-e", js).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v", out, err)
	}
	html := string(out)
	for _, want := range []string{`type="password"`, `autocomplete="new-password"`, `id="vt-key-input"`, `id="vt-key-save"`, `id="vt-key-test"`, `id="vt-key-remove"`, `id="vt-test-ack"`, "not encrypted", "no case data"} {
		if !strings.Contains(html, want) {
			t.Errorf("missing safe integration form element %s", want)
		}
	}
	if strings.Contains(html, `value="saved"`) || strings.Contains(html, "localStorage") {
		t.Fatal("saved credential is being reflected into UI")
	}
}
