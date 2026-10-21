package regpersist

import "testing"

func TestClassify_OnlyLaunchLocationsArePersistence(t *testing.T) {
	const wl = `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
	const ifeo = `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
	cases := []struct {
		key, val string
		want     Kind
	}{
		{wl, "Shell", KindWinlogon},
		{wl, "Userinit", KindWinlogon},
		{wl, "SomeOtherSetting", KindNone},
		{wl + `\GPExtensions\{guid}`, "DllName", KindNone},
		{wl + `\Notify\pkg`, "Shell", KindNone},
		{ifeo + `\tool.exe`, "Debugger", KindIFEO},
		{ifeo + `\tool.exe`, "GlobalFlag", KindNone},
		{ifeo + `\DllNXOptions`, "Debugger", KindNone},
		{ifeo + `\DllNXOptions\x.dll`, "Debugger", KindNone},
		{`HKLM\SYSTEM\ControlSet001\Services\svc01`, "ImagePath", KindServiceImagePath},
		{`HKLM\SYSTEM\ControlSet001\Services\svc01\Parameters`, "ImagePath", KindNone},
		{`HKLM\SYSTEM\ControlSet001\Services\svc01`, "Start", KindNone},
	}
	for _, c := range cases {
		if got := Classify(c.key, c.val); got != c.want {
			t.Errorf("Classify(%q,%q) = %q, want %q", c.key, c.val, got, c.want)
		}
	}
}
