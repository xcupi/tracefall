package api

import (
	"strings"
	"testing"
)

func TestUI_ChatGPTSettingsUsesOfficialAuthorizationAndSeparateVerification(t *testing.T) {
	s := string(appJS(t))
	for _, want := range []string{"renderChatGPTIntegration", `id="chatgpt-authorize"`, `id="chatgpt-user-code"`, `id="chatgpt-verify-ack"`, `id="chatgpt-provider"`, "Request verified", "Signed in", "Not connected", "/admin/integrations/chatgpt", "/authorize", "/cancel", "/verify", "Disconnect the Tracefall ChatGPT session", "environment_managed", "No case data"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing authorization UI contract: %s", want)
		}
	}
}
