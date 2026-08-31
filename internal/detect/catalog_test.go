package detect

import (
	"testing"
	"time"

	"tracefall/internal/model"
)

// The catalog documents each rule's severity reasoning. It is only
// trustworthy if it cannot drift from the rules themselves, which is
// what these tests enforce.

func TestCatalog_CoversEveryRegisteredRule(t *testing.T) {
	registered := map[string]bool{}
	for _, r := range All() {
		registered[r.ID()] = true
	}

	for id := range registered {
		if _, ok := DocFor(id); !ok {
			t.Errorf("rule %q is registered but has no catalog entry -- its severity would be unexplainable", id)
		}
	}
	for _, doc := range Catalog() {
		if !registered[doc.ID] {
			t.Errorf("catalog documents %q, which is not a registered rule", doc.ID)
		}
	}
	if len(Catalog()) != len(registered) {
		t.Errorf("catalog has %d entries, %d rules are registered", len(Catalog()), len(registered))
	}
}

func TestCatalog_EntriesAreWellFormed(t *testing.T) {
	valid := map[string]bool{
		model.SeverityLow: true, model.SeverityMedium: true,
		model.SeverityHigh: true, model.SeverityCritical: true,
	}
	validConf := map[string]bool{
		model.ConfidenceLow: true, model.ConfidenceMedium: true, model.ConfidenceHigh: true,
	}
	rank := map[string]int{
		model.SeverityLow: 1, model.SeverityMedium: 2, model.SeverityHigh: 3, model.SeverityCritical: 4,
	}
	confRank := map[string]int{model.ConfidenceLow: 1, model.ConfidenceMedium: 2, model.ConfidenceHigh: 3}

	for _, d := range Catalog() {
		if d.Title == "" || d.Detects == "" || d.Basis == "" {
			t.Errorf("%s: incomplete entry %+v", d.ID, d)
		}
		if !valid[d.BaseSeverity] || !valid[d.MaxSeverity] {
			t.Errorf("%s: invalid severity levels %q/%q", d.ID, d.BaseSeverity, d.MaxSeverity)
		}
		if !validConf[d.BaseConfidence] || !validConf[d.MaxConfidence] {
			t.Errorf("%s: invalid confidence levels %q/%q", d.ID, d.BaseConfidence, d.MaxConfidence)
		}
		if rank[d.MaxSeverity] < rank[d.BaseSeverity] {
			t.Errorf("%s: max severity %q is below base %q", d.ID, d.MaxSeverity, d.BaseSeverity)
		}
		if confRank[d.MaxConfidence] < confRank[d.BaseConfidence] {
			t.Errorf("%s: max confidence %q is below base %q", d.ID, d.MaxConfidence, d.BaseConfidence)
		}
		// A rule that can escalate must say on what basis; one that
		// cannot must not claim it can.
		if rank[d.MaxSeverity] > rank[d.BaseSeverity] && len(d.Escalates) == 0 {
			t.Errorf("%s: escalates to %q but lists no escalating condition", d.ID, d.MaxSeverity)
		}
		if rank[d.MaxSeverity] == rank[d.BaseSeverity] && confRank[d.MaxConfidence] == confRank[d.BaseConfidence] && len(d.Escalates) > 0 {
			t.Errorf("%s: lists escalating conditions but base and max levels are identical", d.ID)
		}
	}
}

// The catalog must describe the levels the rules ACTUALLY assign. This
// runs every rule over evidence engineered to trigger it and checks the
// finding's severity/confidence falls inside the documented band --
// which is what stops the documentation quietly becoming fiction.
func TestCatalog_DocumentedBandsContainWhatRulesAssign(t *testing.T) {
	rank := map[string]int{
		model.SeverityLow: 1, model.SeverityMedium: 2, model.SeverityHigh: 3, model.SeverityCritical: 4,
	}
	confRank := map[string]int{model.ConfidenceLow: 1, model.ConfidenceMedium: 2, model.ConfidenceHigh: 3}

	// Findings produced by the shared scenario fixtures cover most rules;
	// any rule that does not fire here is still covered by the structural
	// tests above.
	events := catalogScenarioEvents()
	for _, r := range All() {
		doc, ok := DocFor(r.ID())
		if !ok {
			continue
		}
		for _, f := range r.Evaluate(events) {
			if rank[f.Severity] < rank[doc.BaseSeverity] || rank[f.Severity] > rank[doc.MaxSeverity] {
				t.Errorf("%s assigned severity %q, outside its documented band %q..%q",
					r.ID(), f.Severity, doc.BaseSeverity, doc.MaxSeverity)
			}
			if confRank[f.Confidence] < confRank[doc.BaseConfidence] || confRank[f.Confidence] > confRank[doc.MaxConfidence] {
				t.Errorf("%s assigned confidence %q, outside its documented band %q..%q",
					r.ID(), f.Confidence, doc.BaseConfidence, doc.MaxConfidence)
			}
		}
	}
}

// catalogScenarioEvents composes one event set that triggers as many
// rules as possible, in both their base and escalated forms, so the
// band-containment check above exercises real rule output rather than
// asserting against nothing. Rules that do not fire here are still
// covered by the structural tests; the loop only inspects findings that
// were actually produced, so this can never false-fail.
func catalogScenarioEvents() []model.Event {
	base := mustTime("2026-01-15T09:00:00Z")
	ev := func(i int, off int, e model.Event) model.Event {
		e.ID = itoa(i)
		e.CaseID = "catalog-case"
		e.Timestamp = base.Add(durMinutes(off))
		e.Host = "WKSTN-042"
		return e
	}

	var out []model.Event
	n := 0
	add := func(off int, e model.Event) {
		n++
		out = append(out, ev(n, off, e))
	}

	// Office -> PowerShell, and Office -> script host.
	add(0, model.Event{EventType: model.EventProcessCreate, ParentProcessName: "winword.exe", ProcessName: "powershell.exe",
		CommandLine: "powershell.exe -nop -w hidden -enc AAAA", User: "jdoe"})
	add(1, model.Event{EventType: model.EventProcessCreate, ParentProcessName: "excel.exe", ProcessName: "wscript.exe", User: "jdoe"})

	// Benign and suspicious persistence, to reach both ends of the band.
	add(2, model.Event{EventType: model.EventRegistryRunKey, FilePath: `C:\Program Files\Vendor\app.exe`,
		RegistryPath: `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Vendor`})
	add(3, model.Event{EventType: model.EventRegistryRunKey, FilePath: `C:\Users\jdoe\AppData\Local\Temp\update.exe`,
		RegistryPath: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater`})
	add(4, model.Event{EventType: model.EventRegistryPersistence, FilePath: `C:\Users\jdoe\AppData\Local\Temp\inject.dll`,
		RegistryPath: `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs`,
		Extra:        map[string]string{"registry_persistence_type": "appinit_dlls"}})

	// Scheduled task and service persistence.
	add(5, model.Event{EventType: model.EventScheduledTaskCreate, ProcessName: "powershell.exe",
		ProcessPath: `C:\Users\jdoe\AppData\Local\Temp\run.ps1`, Extra: map[string]string{"task_name": "AcmeUpdate"}})
	add(6, model.Event{EventType: model.EventServiceInstall, FilePath: `C:\Users\jdoe\AppData\Local\Temp\svc.exe`,
		ProcessName: "svc.exe", Extra: map[string]string{"service_name": "AcmeSvc"}})

	// Execution from a user-writable path, then an outbound connection.
	add(7, model.Event{EventType: model.EventProcessCreate, ProcessName: "update.exe",
		ProcessPath: `C:\Users\jdoe\AppData\Local\Temp\update.exe`, ParentProcessName: "cmd.exe", PID: 4242})
	add(8, model.Event{EventType: model.EventNetworkConnection, ProcessName: "update.exe",
		ProcessPath: `C:\Users\jdoe\AppData\Local\Temp\update.exe`, NetworkDest: "203.0.113.77", NetworkDestPort: 443, PID: 4242})

	// Authentication: failures into a success, privileges, explicit creds.
	for i := 0; i < 4; i++ {
		add(10+i, model.Event{EventType: model.EventLogonFailure, User: "jdoe"})
	}
	add(15, model.Event{EventType: model.EventLogonSuccess, User: "jdoe", Extra: map[string]string{"logon_type": "3"}})
	add(16, model.Event{EventType: model.EventPrivilegedLogon, User: "jdoe"})
	add(17, model.Event{EventType: model.EventLogonExplicitCreds, User: "jdoe", ProcessName: "cmd.exe"})

	return out
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func durMinutes(n int) time.Duration { return time.Duration(n) * time.Minute }
