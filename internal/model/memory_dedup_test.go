package model

import (
	"maps"
	"testing"
	"time"
)

// Change one object attribute at a time under an identical PID/time. These
// attributes belong to the memory observation, unlike renderer notes or source
// row numbers, which must remain irrelevant to identity.
func TestDedupHash_MemoryObjectAttributesRemainDistinct(t *testing.T) {
	for _, tc := range []struct {
		name, typ, field, a, b string
	}{
		{"region start", EventMemoryInjection, "start_vpn", "0x1000", "0x2000"},
		{"region end", EventMemoryInjection, "end_vpn", "0x1fff", "0x2fff"},
		{"service name", EventMemoryService, "service_name", "BITS", "Schedule"},
		{"service state", EventMemoryService, "state", "SERVICE_RUNNING", "SERVICE_STOPPED"},
		{"service start", EventMemoryService, "start_type", "SERVICE_AUTO_START", "SERVICE_DISABLED"},
		{"service type", EventMemoryService, "service_type", "SERVICE_WIN32_SHARE_PROCESS", "SERVICE_WIN32_OWN_PROCESS"},
		{"service dll", EventMemoryService, "dll", `C:\Windows\a.dll`, `C:\Windows\b.dll`},
		{"service registry binary", EventMemoryService, "binary_registry", `C:\a.exe`, `C:\b.exe`},
		{"connection local port", EventNetworkConnection, "local_port", "51000", "51001"},
		{"connection protocol", EventNetworkConnection, "protocol", "TCPv4", "UDPv4"},
		{"connection state", EventNetworkConnection, "state", "ESTABLISHED", "CLOSED"},
		{"listener local port", EventNetworkListener, "local_port", "135", "445"},
		{"listener protocol", EventNetworkListener, "protocol", "TCPv4", "UDPv4"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := Event{EventType: tc.typ, ArtifactType: ArtifactMemoryAnalysis, PID: 600,
				Timestamp: time.Date(2024, 7, 15, 7, 0, 8, 0, time.UTC), Extra: map[string]string{tc.field: tc.a}}
			b := a
			b.Extra = map[string]string{tc.field: tc.b}
			if a.ComputeDedupHash() == b.ComputeDedupHash() {
				t.Fatalf("different %s collapsed at the same snapshot time", tc.name)
			}
		})
	}
}

func TestDedupHash_MemoryLocalAddressesRemainDistinct(t *testing.T) {
	for _, typ := range []string{EventNetworkConnection, EventNetworkListener} {
		a := Event{EventType: typ, ArtifactType: ArtifactMemoryAnalysis, PID: 600,
			NetworkSource: "10.0.0.5", Timestamp: time.Date(2024, 7, 15, 7, 0, 8, 0, time.UTC)}
		b := a
		b.NetworkSource = "127.0.0.1"
		if a.ComputeDedupHash() == b.ComputeDedupHash() {
			t.Errorf("%s: sockets bound to different local addresses collapsed", typ)
		}
	}
}

func TestDedupHash_MemoryDuplicateIgnoresProvenanceAndRendererDetails(t *testing.T) {
	for _, typ := range []string{EventMemoryInjection, EventMemoryService, EventNetworkConnection, EventNetworkListener} {
		a := Event{EventType: typ, ArtifactType: ArtifactMemoryAnalysis, PID: 600,
			Timestamp: time.Date(2024, 7, 15, 7, 0, 8, 0, time.UTC), Extra: map[string]string{
				"start_vpn": "0x1000", "end_vpn": "0x1fff", "service_name": "BITS", "local_port": "135", "protocol": "TCPv4"}}
		b := a
		b.Extra = maps.Clone(a.Extra)
		b.CollectionID, b.SourceFileID, b.SourceReference = "another-collection", "another-file", "another-row"
		b.Parser, b.RawEvidenceID, b.Confidence = "another-renderer", "another-raw", 0.1
		b.Extra["notes"], b.Extra["disasm_head"], b.Extra["plugins"] = "different rendering", "different assembly", "different plugin version"
		if a.ComputeDedupHash() != b.ComputeDedupHash() {
			t.Errorf("%s: genuine recollection stopped deduplicating", typ)
		}
	}
}

func TestDedupHash_MemoryFixPreservesHistoricalNonMemoryIdentity(t *testing.T) {
	const beforeFix = "c43a32e7f45bf590f77d17eaa88479b1e67103800d309e86a1f93308dcd4e066"
	a := sampleEvent()
	a.Extra = map[string]string{"start_vpn": "0x1000", "end_vpn": "0x1fff", "service_name": "BITS", "protocol": "TCPv4", "state": "CLOSED"}
	if got := a.ComputeDedupHash(); got != beforeFix {
		t.Fatalf("non-memory event hash changed: %s, want historical %s", got, beforeFix)
	}
	b := a
	b.Extra = map[string]string{"start_vpn": "0x2000", "service_name": "Schedule", "protocol": "UDPv4"}
	b.NetworkSource = "127.0.0.1"
	if b.ComputeDedupHash() != beforeFix {
		t.Fatal("memory-only attributes now affect non-memory evidence identity")
	}

	// NetworkConnection is reused by Windows logs and memory analysis.
	// Pin its historical log identity too, to protect the artifact guard.
	network := sampleEvent()
	network.EventType, network.NetworkDest, network.NetworkDestPort = EventNetworkConnection, "203.0.113.77", 443
	network.NetworkSource = "10.0.0.5"
	network.Extra = map[string]string{"local_port": "51000", "protocol": "TCPv4", "state": "ESTABLISHED"}
	const historicalNetwork = "8bf5ee24b4c3c963ff1461cc06341e190dd296054cef6866111b4ca60765cede"
	if got := network.ComputeDedupHash(); got != historicalNetwork {
		t.Fatalf("non-memory network event changed identity: %s", got)
	}
}
