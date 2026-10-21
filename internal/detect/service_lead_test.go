package detect

import (
	"testing"

	"tracefall/internal/model"
)

func TestRegistryPersistenceExtended_SnapshotServiceImagePathLeadsOnlyWhenSuspicious(t *testing.T) {
	mk := func(id, path, lead string) model.Event {
		x := map[string]string{"registry_persistence_type": "service_image_path"}
		if lead != "" {
			x["persistence_lead"] = lead
		}
		return model.Event{ID: id, CaseID: "c", EventType: model.EventRegistryPersistence, RegistryPath: `HKLM\SYSTEM\ControlSet001\Services\svc\ImagePath`, FilePath: path, Extra: x}
	}
	got := registryPersistenceExtended{}.Evaluate([]model.Event{
		mk("stock", `C:\Windows\System32\svc.exe`, "false"),
		mk("temp", `C:\Users\alice\AppData\Local\Temp\svc.exe`, ""),
	})
	if len(got) != 1 || got[0].SupportingEvents[0] != "temp" {
		t.Fatalf("findings = %+v, want only the user-writable service", got)
	}
}
