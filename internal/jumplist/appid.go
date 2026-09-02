package jumplist

import (
	"strings"
)

// Application identity from a Jump List filename.
//
// A Jump List is named for a 16-hex-digit AppID: a hash Windows derives
// from the application's executable path (or, for some applications, an
// explicitly declared identifier). The hash is one-way, so an AppID
// cannot be turned back into a path -- it can only be LOOKED UP against
// identifiers that have been observed and published.
//
// That shapes the rule this file follows absolutely: an AppID that is
// not in the table below resolves to nothing. It is never guessed at,
// never approximated from a similar-looking identifier, and never
// dropped -- the raw AppID is always preserved, and an unresolved one is
// reported as unknown so an analyst can look it up themselves.

// knownAppIDs maps published AppIDs to application names.
//
// Deliberately small and conservative. Every entry here is an identifier
// that is stable across installations because it derives from a fixed
// system path; per-user or per-install applications hash differently on
// every machine and are correctly absent. A short table of certainties
// is worth more than a long one of guesses.
var knownAppIDs = map[string]string{
	"5f7b5f1e01b83767":  "Quick Access / Explorer",
	"f01b4d95cf55d32a":  "Windows Explorer (Windows 8.1+)",
	"1b4dd67f29cb1962":  "Windows Explorer (Windows 7)",
	"9d1f905ce5044aee":  "Windows Explorer (star pinned)",
	"12dc1ea8e34b5a6":   "Windows Media Player",
	"7e4dca80246863e3":  "Control Panel",
	"6824f4a902c78fbd":  "Microsoft Word 2010",
	"a7bd71699cd38d1c":  "Microsoft Word 2013",
	"adecfb853d77462a":  "Microsoft Word 2016/365",
	"ce32b3857c1a2573":  "Microsoft Excel 2013",
	"aa28c3f0a2b9394e":  "Microsoft Excel 2016/365",
	"fa7a3d5cd4d0e5d8":  "Microsoft PowerPoint 2016/365",
	"2b53c4ddf6f7f0e4":  "Notepad",
	"918e0ecb43d17e23":  "Notepad (Windows 10)",
	"9b9cdc69c1c24e2b":  "Notepad (Windows 11)",
	"5d696d521de238c3":  "Google Chrome",
	"69639db3c4f9afef":  "Microsoft Edge",
	"28c8b86deab549a1":  "Internet Explorer 11",
	"e0f5cc9a4f8fa0e0":  "Mozilla Firefox",
	"5afe4de1b92fc382":  "Windows Command Processor (cmd.exe)",
	"b0459de4674aab56":  "Windows PowerShell",
	"969252ce11249fdd":  "Windows PowerShell ISE",
	"e36bfc8b0fe1a1cb":  "Remote Desktop Connection (mstsc.exe)",
	"7c5a40ef8f2c6a6e":  "Windows Installer / Program Files",
	"271e609288e1210a":  "7-Zip",
	"918e0ecb43d17e23c": "Notepad++",
	"de9e6de99e2e8e5b":  "Adobe Acrobat Reader DC",
	"3594aab44bca414b":  "Windows Photo Viewer",
	"4cb9c5750d51c07f":  "VLC media player",
	"1bc392b8e104a00e":  "Remote Desktop (Windows 10)",
	"b8ab77100df80ab2":  "WinRAR",
	"9c1b53aa2c4dcbd0":  "Windows Search / Cortana",
	"d00655d2aa12ff6d":  "Microsoft Paint",
	"47bcd7dcd2b1a6b0":  "Sublime Text",
	"bc0c37e84e063727":  "Visual Studio Code",
}

// AppIDFromFilename extracts the AppID from a Jump List filename and
// resolves it where the mapping is known.
//
// A Jump List is named "<appid>.automaticDestinations-ms". The AppID is
// returned raw whether or not it resolves; the resolved name is empty
// when the identifier is not in the table, and callers report that as an
// unknown application rather than inventing one.
//
// A renamed file has no AppID to extract. That is reported as an absent
// identifier, not as an unknown one: "the name carries no AppID" and
// "the AppID is not one we recognize" are different facts.
func AppIDFromFilename(name string) (appID, application string) {
	base := name
	for _, suffix := range []string{
		".automaticDestinations-ms", ".customDestinations-ms",
	} {
		if len(base) > len(suffix) && strings.EqualFold(base[len(base)-len(suffix):], suffix) {
			base = base[:len(base)-len(suffix)]
			break
		}
	}
	if base == name {
		// No Jump List suffix: the file was renamed.
		return "", ""
	}
	if !plausibleAppID(base) {
		return "", ""
	}
	id := strings.ToLower(base)
	return id, knownAppIDs[id]
}

// ResolveAppID looks up an AppID that was obtained some other way.
func ResolveAppID(appID string) string {
	return knownAppIDs[strings.ToLower(appID)]
}

// ApplicationLabel renders an application for display, keeping the raw
// identifier visible in every case.
//
// An unresolved AppID is shown as unknown WITH its identifier, because
// the identifier is the thing an analyst can search for; hiding it
// behind "Unknown application" would discard the only lead available.
func ApplicationLabel(appID, application string) string {
	switch {
	case appID == "" && application == "":
		return "Unknown application (no AppID in the filename)"
	case application == "":
		return "Unknown application (AppID " + appID + ")"
	default:
		return application
	}
}

// plausibleAppID reports whether a string has the shape of an AppID:
// hexadecimal, and of the length Windows produces.
//
// Length is checked as a range rather than exactly 16 because a handful
// of published identifiers are shorter; anything outside it is not an
// AppID and is not treated as one.
func plausibleAppID(s string) bool {
	if len(s) < 8 || len(s) > 20 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}
