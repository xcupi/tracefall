package detect

import (
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
)

var netBase = time.Date(2020, 9, 19, 2, 21, 47, 0, time.UTC)

func rdpConv(connections string) model.Event {
	return model.Event{ID: "c1", CaseID: "case", ArtifactType: model.ArtifactNetworkCapture, EventType: model.EventNetworkConnection,
		Timestamp: netBase, NetworkSource: "198.51.100.7", NetworkDest: "10.0.0.5", NetworkDestPort: 3389,
		Extra: map[string]string{"application": "rdp", "connections": connections, "rdp_cookie_user": "admin"}}
}

func rdpSession(id string) model.Event {
	return model.Event{ID: id, CaseID: "case", ArtifactType: model.ArtifactNetworkCapture, EventType: model.EventNetworkConnection,
		Timestamp: netBase.Add(time.Hour), NetworkSource: "198.51.100.7", NetworkDest: "10.0.0.5", NetworkDestPort: 3389,
		Extra: map[string]string{"application": "rdp", "session": "true", "client_port": "50123", "packets": "900"}}
}

func TestRDPBurst_ABurstAloneIsALowConfidenceLead(t *testing.T) {
	got := (rdpConnectionBurst{}).Evaluate([]model.Event{rdpConv("14000")})
	if len(got) != 1 || got[0].Severity != model.SeverityMedium || got[0].Confidence != model.ConfidenceLow {
		t.Fatalf("%+v", got)
	}
	for _, want := range []string{"14000", "password guessing", "scanner", `"admin"`, "not an authenticated identity", "No connection from this client went beyond a handshake"} {
		if !strings.Contains(got[0].Description, want) {
			t.Errorf("description lacks %q:\n%s", want, got[0].Description)
		}
	}
}

func TestRDPBurst_ASessionAfterTheBurstRaisesItAndPointsAtTheServerLogs(t *testing.T) {
	got := (rdpConnectionBurst{}).Evaluate([]model.Event{rdpConv("14000"), rdpSession("s1")})
	if len(got) != 1 || got[0].Severity != model.SeverityHigh || got[0].Confidence != model.ConfidenceMedium || len(got[0].SupportingEvents) != 2 {
		t.Fatalf("%+v", got)
	}
	if !strings.Contains(got[0].Description, "client port 50123") || !strings.Contains(got[0].Description, "4624") {
		t.Errorf("%s", got[0].Description)
	}
}

func TestRDPBurst_OrdinaryReconnectionAndOtherTrafficAreNotReported(t *testing.T) {
	if got := (rdpConnectionBurst{}).Evaluate([]model.Event{rdpConv("49")}); len(got) != 0 {
		t.Errorf("49 connections is ordinary: %+v", got)
	}
	e := rdpConv("5000")
	e.Extra["application"] = "http"
	if got := (rdpConnectionBurst{}).Evaluate([]model.Event{e}); len(got) != 0 {
		t.Errorf("only Remote Desktop: %+v", got)
	}
	e = rdpConv("5000")
	e.ArtifactType = model.ArtifactMemoryAnalysis
	if got := (rdpConnectionBurst{}).Evaluate([]model.Event{e}); len(got) != 0 {
		t.Errorf("only a capture counts a connection burst: %+v", got)
	}
}

func fetch(id, host, status, sig, reassembly string) model.Event {
	return model.Event{ID: id, CaseID: "case", ArtifactType: model.ArtifactNetworkCapture, EventType: model.EventWebRequest,
		Timestamp: netBase, NetworkSource: "10.0.0.5", NetworkDest: "203.0.113.9", NetworkDestPort: 80,
		Extra: map[string]string{"http_host": host, "uri": "/tool.exe", "status": status, "file_signature": sig, "reassembly": reassembly,
			"filename": "tool.exe", "response_sha256": strings.Repeat("cd", 32), "response_size": "4096"}}
}

func TestExecutableFromBareAddress(t *testing.T) {
	got := (executableFromBareAddress{}).Evaluate([]model.Event{
		fetch("a", "203.0.113.9", "200", "Windows executable (MZ)", "complete"),
		fetch("b", "203.0.113.9", "200", "Windows executable (MZ)", "complete"), // the same object again
	})
	if len(got) != 1 || got[0].Severity != model.SeverityMedium || len(got[0].SupportingEvents) != 2 {
		t.Fatalf("%+v", got)
	}
	for _, want := range []string{"2 time(s)", strings.Repeat("cd", 32), "does not show they were saved, run"} {
		if !strings.Contains(got[0].Description, want) {
			t.Errorf("lacks %q:\n%s", want, got[0].Description)
		}
	}
}

func TestExecutableFromBareAddress_NamedSitesAndNonProgramsAreNotReported(t *testing.T) {
	for name, e := range map[string]model.Event{
		"named site":   fetch("a", "dl.example", "200", "Windows executable (MZ)", "complete"),
		"image":        fetch("b", "203.0.113.9", "200", "PNG image", "complete"),
		"not found":    fetch("c", "203.0.113.9", "404", "Windows executable (MZ)", "complete"),
		"only a range": fetch("d", "203.0.113.9", "206", "Windows executable (MZ)", "complete"),
		"incomplete":   fetch("e", "203.0.113.9", "200", "Windows executable (MZ)", "incomplete"),
	} {
		if got := (executableFromBareAddress{}).Evaluate([]model.Event{e}); len(got) != 0 {
			t.Errorf("%s: %+v", name, got)
		}
	}
	if !ipLiteral("203.0.113.9:8080") || !ipLiteral("[2001:db8::1]") || ipLiteral("dl.example:80") {
		t.Error("ipLiteral")
	}
}

func TestRDPBurst_ShortConnectionsAreNotASession(t *testing.T) {
	probe := rdpSession("s1")
	probe.Extra["packets"] = "22"
	got := (rdpConnectionBurst{}).Evaluate([]model.Event{rdpConv("14000"), probe})
	if len(got) != 1 || got[0].Severity != model.SeverityMedium || got[0].Confidence != model.ConfidenceLow {
		t.Fatalf("a 22-packet connection is negotiation, not a session: %+v", got)
	}
	if !strings.Contains(got[0].Description, "only 22 packets") {
		t.Errorf("%s", got[0].Description)
	}
}
