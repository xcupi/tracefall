package scheduledtasks

import "testing"

func TestDetect_TaskNamesWithDotsAndSpacesAreStillTasks(t *testing.T) {
	cases := map[string]bool{
		"Windows/System32/Tasks/Microsoft/Windows/Maintenance/Idle Maintenance": true,
		"Windows/System32/Tasks/Vendor/Runtime Updater v4.0.30319":              true,
		"Windows/System32/Tasks/Vendor/Runtime Updater v4.0.30319 64 Critical":  true,
		"Windows/System32/Tasks/Vendor/report.exe task":                         true,
		"Windows/System32/Tasks/Vendor/Task.xml":                                true,
		"Windows/System32/Tasks/Vendor/notes.txt":                               false,
		"Windows/System32/Tasks/Vendor/backup.bak":                              false,
		"Windows/Tasks/legacy.job":                                              false,
		"Windows/System32/config/SYSTEM":                                        false,
	}
	for path, want := range cases {
		if got := (Parser{}).Detect(path); got != want {
			t.Errorf("Detect(%q) = %v, want %v", path, got, want)
		}
	}
}
