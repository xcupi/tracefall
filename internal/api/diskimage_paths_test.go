package api

import "testing"

// Path rules for the disk catalog. The cases are real paths from the
// A default Windows install: an installed-app wallpaper and a shell
// wallpaper that must not be sniffed, and the artifacts that must still be
// reachable. Windows is case-insensitive, so case must not change the answer.
func TestSniffSkipped(t *testing.T) {
	cases := []struct {
		rel  string
		want bool
	}{
		{"Program Files/WindowsApps/Microsoft.BingWeather_4.25/Assets/AppTiles/a.jpg", true},
		{"Program Files (x86)/Windows Media Player/Media Renderer/DMR_48.jpg", true},
		{"Windows/Web/Wallpaper/Theme1/img1.jpg", true},
		{"PROGRAM FILES/WindowsApps/x.jpg", true},
		{"Windows/appcompat/Programs/Amcache.hve", false},
		{"Users/alice/AppData/Roaming/Microsoft/Windows/Recent/notes.txt.lnk", false},
		{"Windows/System32/config/SOFTWARE", false},
		{"Users/alice/Pictures/IMG_0001.jpg", false},
		// A prefix that merely starts the same way is not a folder match.
		{"Program FilesBackup/x.jpg", false},
	}
	for _, c := range cases {
		if got := sniffSkipped(c.rel); got != c.want {
			t.Errorf("sniffSkipped(%q) = %v, want %v", c.rel, got, c.want)
		}
	}
}

// $MFTMirr must never be cataloged: it repeats the first $MFT records.
func TestMirrorOfMFT(t *testing.T) {
	for rel, want := range map[string]bool{
		"$MFTMirr":         true,
		"$mftmirr":         true,
		"$MFT":             false,
		"$LogFile":         false,
		"Windows/$MFTMirr": false,
	} {
		if got := mirrorOfMFT(rel); got != want {
			t.Errorf("mirrorOfMFT(%q) = %v, want %v", rel, got, want)
		}
	}
}
