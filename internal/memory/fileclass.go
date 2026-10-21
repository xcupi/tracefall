package memory

import (
	"strings"
	"unicode"
)

// FileClass says how much a file object found in memory is worth a reader's
// time. The classes are deliberately about where the file is and what kind it
// is, never about what it might be.
type FileClass int

const (
	// FileGarbage is a name that is not a readable path: the pool scan reads
	// freed or partly overwritten objects.
	FileGarbage FileClass = iota
	// FileRoutine is under the operating system's or installed software's own
	// locations.
	FileRoutine
	// FileOther is of a type nobody asked about (fonts, caches, temporary
	// data).
	FileOther
	// FileInteresting is a runnable, document, archive or data file outside the
	// routine locations.
	FileInteresting
)

var routinePathPrefixes = []string{
	`\windows\system32\`, `\windows\syswow64\`, `\windows\winsxs\`, `\windows\assembly\`, `\windows\microsoft.net\`,
	`\windows\servicing\`, `\windows\fonts\`, `\windows\globalization\`, `\windows\systemapps\`, `\windows\immersivecontrolpanel\`,
	`\windows\inf\`, `\windows\branding\`, `\windows\resources\`, `\windows\media\`, `\windows\cursors\`,
	`\program files\`, `\program files (x86)\`, `\programdata\microsoft\windows defender\`, `\programdata\package cache\`,
}

// Extensions of things a person runs, opens as a document, or unpacks.
var interestingExt = map[string]bool{
	".exe": true, ".dll": true, ".scr": true, ".sys": true, ".bat": true, ".cmd": true, ".ps1": true, ".vbs": true, ".vbe": true,
	".js": true, ".jse": true, ".wsf": true, ".hta": true, ".jar": true, ".lnk": true, ".msi": true, ".com": true, ".cpl": true,
	".doc": true, ".docx": true, ".docm": true, ".xls": true, ".xlsx": true, ".xlsm": true, ".ppt": true, ".pptx": true, ".pdf": true,
	".rtf": true, ".zip": true, ".rar": true, ".7z": true, ".gz": true, ".tar": true, ".iso": true, ".img": true, ".vhd": true,
	".txt": true, ".csv": true, ".kdbx": true, ".pst": true, ".ost": true, ".dmp": true, ".mem": true, ".pcap": true, ".pcapng": true,
	".sql": true, ".bak": true, ".evtx": true, ".reg": true,
}

// Extensions of things that run or are loaded, the ones whose content is worth
// reading for what it is.
var runnableExt = map[string]bool{
	".exe": true, ".dll": true, ".scr": true, ".sys": true, ".bat": true, ".cmd": true, ".ps1": true, ".vbs": true, ".vbe": true,
	".js": true, ".jse": true, ".wsf": true, ".hta": true, ".jar": true, ".msi": true, ".com": true, ".cpl": true,
}

// PlausibleName rejects the garbage the pool scan returns for a freed or partly
// overwritten object: control characters, the replacement character and
// private-use code points.
func PlausibleName(n string) bool {
	if !strings.HasPrefix(n, `\`) || len(n) < 3 {
		return false
	}
	for _, r := range n {
		if r == unicode.ReplacementChar || r == 0xFFFF || unicode.IsControl(r) || (r >= 0xE000 && r <= 0xF8FF) || r > 0xFFFF {
			return false
		}
	}
	return true
}

func extOf(lower string) string {
	if i := strings.LastIndexAny(lower, `\.`); i >= 0 && lower[i] == '.' {
		return lower[i:]
	}
	return ""
}

// ClassifyFile classifies a file object's name.
func ClassifyFile(name string) FileClass {
	if !PlausibleName(name) {
		return FileGarbage
	}
	lower := strings.ToLower(name)
	for _, p := range routinePathPrefixes {
		if strings.HasPrefix(lower, p) {
			return FileRoutine
		}
	}
	if !interestingExt[extOf(lower)] {
		return FileOther
	}
	return FileInteresting
}

// Runnable reports whether the name has the extension of something that runs
// or is loaded.
func Runnable(name string) bool { return runnableExt[extOf(strings.ToLower(name))] }
