package regpersist

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct {
		name      string
		keyPath   string
		valueName string
		want      Kind
	}{
		{"run key", `Software\Microsoft\Windows\CurrentVersion\Run`, "Updater", KindRunKey},
		{"run once key", `Software\Microsoft\Windows\CurrentVersion\RunOnce`, "Updater", KindRunKey},
		{"HKLM run key", `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`, "Updater", KindRunKey},
		{"winlogon shell", `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`, "Shell", KindWinlogon},
		{"ifeo debugger", `Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe`, "Debugger", KindIFEO},
		{"appinit dlls", `Software\Microsoft\Windows NT\CurrentVersion\Windows`, "AppInit_DLLs", KindAppInitDLLs},
		{"appinit dlls wrong value name", `Software\Microsoft\Windows NT\CurrentVersion\Windows`, "LoadAppInit_DLLs", KindNone},
		{"service image path", `System\CurrentControlSet\Services\WeirdSvc`, "ImagePath", KindServiceImagePath},
		{"service other value", `System\CurrentControlSet\Services\WeirdSvc`, "Start", KindNone},
		{"unrelated key", `Software\Microsoft\Office\16.0\Word\Security`, "VBAWarnings", KindNone},
		{"case insensitive", `SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN`, "x", KindRunKey},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Classify(c.keyPath, c.valueName); got != c.want {
				t.Errorf("Classify(%q, %q) = %q, want %q", c.keyPath, c.valueName, got, c.want)
			}
		})
	}
}
