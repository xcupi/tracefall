package detect

import (
	"testing"

	"tracefall/internal/model"
)

func TestRegistryPersistenceExtended_StockWinlogonValuesAreNotLeads(t *testing.T) {
	const key = `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\`
	mk := func(name, data string) model.Event {
		return model.Event{ID: name, CaseID: "c", EventType: model.EventRegistryPersistence, RegistryPath: key + name, FilePath: data,
			Extra: map[string]string{"registry_persistence_type": "winlogon"}}
	}
	got := registryPersistenceExtended{}.Evaluate([]model.Event{
		mk("Shell", "explorer.exe"),
		mk("Userinit", `C:\Windows\system32\userinit.exe,`),
		mk("Userinit", "userinit.exe"),
		mk("VMApplet", "SystemPropertiesPerformance.exe /pagefile"),
	})
	if len(got) != 0 {
		t.Fatalf("stock values produced %d findings", len(got))
	}
	got = registryPersistenceExtended{}.Evaluate([]model.Event{
		mk("Shell", `explorer.exe, C:\Users\alice\AppData\Local\Temp\x.exe`),
		mk("Userinit", `C:\Windows\system32\userinit.exe,C:\ProgramData\y.exe`),
	})
	if len(got) != 2 {
		t.Fatalf("modified values produced %d findings, want 2", len(got))
	}
}
