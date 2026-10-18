package volatility

import (
	"testing"

	"tracefall/internal/model"
)

func TestMemoryRegions_DifferentEndBoundsAreNotDiscardedBeforePersistence(t *testing.T) {
	a := baseAnalysis()
	a.Plugins = nil
	first := row{"PID": 4242.0, "Process": "powershell.exe", "Start VPN": 4096.0,
		"End VPN": 8191.0, "Protection": "PAGE_EXECUTE_READWRITE"}
	second := row{"PID": 4242.0, "Process": "powershell.exe", "Start VPN": 4096.0,
		"End VPN": 12287.0, "Protection": "PAGE_EXECUTE_READWRITE"}
	a.Plugins = append(a.Plugins, ok("malfind", "windows.malware.malfind.Malfind", first, second, first))
	hits := byType(parseAll(t, a), model.EventMemoryInjection)
	if len(hits) != 2 {
		t.Fatalf("parser retained %d regions, want both different bounds but not an exact duplicate", len(hits))
	}
	if hits[0].ComputeDedupHash() == hits[1].ComputeDedupHash() {
		t.Fatal("different region bounds will collapse at persistence")
	}
}
