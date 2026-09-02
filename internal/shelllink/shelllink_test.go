package shelllink_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tracefall/internal/shelllink"
	"tracefall/internal/shelllink/lnkgen"
)

var (
	created  = time.Date(2026, 2, 11, 8, 30, 0, 0, time.UTC)
	accessed = time.Date(2026, 3, 4, 17, 45, 12, 0, time.UTC)
	written  = time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC)
)

func fullLink(unicode bool) lnkgen.Link {
	return lnkgen.Link{
		Unicode:        unicode,
		FileAttributes: 0x20, // FILE_ATTRIBUTE_ARCHIVE
		Creation:       created,
		Access:         accessed,
		Write:          written,
		FileSize:       184320,
		ShowCommand:    1,
		Name:           "Quarterly report",
		RelativePath:   `..\..\Documents\report.docx`,
		WorkingDir:     `C:\Users\jdoe\Documents`,
		Arguments:      `/embedding /q`,
		IconLocation:   `C:\Windows\System32\imageres.dll`,
		LocalBasePath:  `C:\Users\jdoe\Documents\report.docx`,
		DriveType:      3,
		VolumeSerial:   0xC0FFEE01,
		VolumeLabel:    "OSDisk",
		IDList: []lnkgen.Item{
			{Kind: "volume", Name: `C:\`},
			{Kind: "dir", Name: "Users", Attrs: 0x10},
			{Kind: "dir", Name: "jdoe", Attrs: 0x10},
			{Kind: "file", Name: "report.docx", Size: 184320, Modified: written, Attrs: 0x20},
		},
		TrackerMachineID: "WKSTN-042",
	}
}

func write(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A complete Unicode shortcut: every documented structure present.
func TestLNK_UnicodeShortcutIsFullyParsed(t *testing.T) {
	l, err := shelllink.Parse(lnkgen.Build(fullLink(true)), shelllink.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if l.StringEncoding != "unicode" {
		t.Errorf("encoding = %q", l.StringEncoding)
	}
	if !l.CreationTime.Equal(created) {
		t.Errorf("creation = %s, want %s", l.CreationTime, created)
	}
	if !l.AccessTime.Equal(accessed) {
		t.Errorf("access = %s, want %s", l.AccessTime, accessed)
	}
	if !l.WriteTime.Equal(written) {
		t.Errorf("write = %s, want %s", l.WriteTime, written)
	}
	for _, ts := range []time.Time{l.CreationTime, l.AccessTime, l.WriteTime} {
		if ts.Location() != time.UTC {
			t.Errorf("%s is not UTC", ts)
		}
	}
	if l.FileSize != 184320 {
		t.Errorf("file size = %d", l.FileSize)
	}
	if l.FileAttributes != 0x20 {
		t.Errorf("attributes = %#x", l.FileAttributes)
	}
	if got := shelllink.ShowCommandName(l.ShowCommand); got != "SW_SHOWNORMAL" {
		t.Errorf("show command = %q", got)
	}
	// StringData.
	if l.Name != "Quarterly report" {
		t.Errorf("name = %q", l.Name)
	}
	if l.RelativePath != `..\..\Documents\report.docx` {
		t.Errorf("relative path = %q", l.RelativePath)
	}
	if l.WorkingDir != `C:\Users\jdoe\Documents` {
		t.Errorf("working dir = %q", l.WorkingDir)
	}
	if l.Arguments != `/embedding /q` {
		t.Errorf("arguments = %q", l.Arguments)
	}
	if l.IconLocation != `C:\Windows\System32\imageres.dll` {
		t.Errorf("icon location = %q", l.IconLocation)
	}
	// LinkInfo.
	if l.LocalBasePath != `C:\Users\jdoe\Documents\report.docx` {
		t.Errorf("local base path = %q", l.LocalBasePath)
	}
	if !l.Volume.Present || l.Volume.DriveType != 3 || l.Volume.SerialNumber != 0xC0FFEE01 {
		t.Errorf("volume = %+v", l.Volume)
	}
	if l.Volume.Label != "OSDisk" {
		t.Errorf("volume label = %q", l.Volume.Label)
	}
	if got := shelllink.DriveTypeName(l.Volume.DriveType); got != "DRIVE_FIXED" {
		t.Errorf("drive type = %q", got)
	}
	if l.TrackerMachineID != "WKSTN-042" {
		t.Errorf("machine id = %q", l.TrackerMachineID)
	}
	if len(l.Warnings) != 0 {
		t.Errorf("a well-formed shortcut produced warnings: %v", l.Warnings)
	}
}

// The same shortcut with ANSI strings parses identically.
func TestLNK_ANSIStringsAreReadPerTheFlag(t *testing.T) {
	l, err := shelllink.Parse(lnkgen.Build(fullLink(false)), shelllink.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if l.StringEncoding != "ansi" {
		t.Errorf("encoding = %q", l.StringEncoding)
	}
	if l.Name != "Quarterly report" || l.WorkingDir != `C:\Users\jdoe\Documents` {
		t.Errorf("ANSI strings misread: name=%q workingdir=%q", l.Name, l.WorkingDir)
	}
	if l.Arguments != `/embedding /q` {
		t.Errorf("arguments = %q", l.Arguments)
	}
}

// The ID list is walked, and its reconstruction is kept SEPARATE from
// the LinkInfo path rather than replacing it.
func TestLNK_IDListIsParsedAndKeptSeparate(t *testing.T) {
	l, err := shelllink.Parse(lnkgen.Build(fullLink(true)), shelllink.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if !l.HasIDList {
		t.Fatal("the ID list was not recorded as present")
	}
	if len(l.IDListItems) != 4 {
		t.Fatalf("got %d shell items, want 4", len(l.IDListItems))
	}
	kinds := make([]string, 0, 4)
	for _, it := range l.IDListItems {
		kinds = append(kinds, it.Kind)
		if it.Offset <= 0 {
			t.Errorf("shell item %q has no recorded offset", it.Name)
		}
	}
	want := []string{"volume", "directory_entry", "directory_entry", "file_entry"}
	if strings.Join(kinds, ",") != strings.Join(want, ",") {
		t.Errorf("item kinds = %v, want %v", kinds, want)
	}
	last := l.IDListItems[3]
	if last.Name != "report.docx" || last.Size != 184320 {
		t.Errorf("file entry = %q / %d", last.Name, last.Size)
	}
	if !last.HasAttrs || last.Attributes != 0x20 {
		t.Errorf("file entry attributes = %#x", last.Attributes)
	}
	if last.Modified.IsZero() {
		t.Error("the file entry's DOS timestamp was not decoded")
	}
	if l.IDListPath != `C:\Users\jdoe\report.docx` {
		t.Errorf("id list path = %q", l.IDListPath)
	}
	// Both representations survive; TargetPath prefers LinkInfo's.
	if l.LinkInfoPath == "" {
		t.Error("the LinkInfo path was discarded")
	}
	if l.TargetPath() != l.LinkInfoPath {
		t.Errorf("TargetPath = %q, want the LinkInfo path %q", l.TargetPath(), l.LinkInfoPath)
	}
}

// A shortcut with no optional structures at all still parses, and the
// absent fields stay empty rather than being filled in.
func TestLNK_MissingOptionalStructuresAreAbsentNotInvented(t *testing.T) {
	l, err := shelllink.Parse(lnkgen.Build(lnkgen.Link{
		Unicode: true, Creation: created, Write: written,
	}), shelllink.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if l.HasIDList || l.HasLinkInfo {
		t.Error("structures that were never written were reported as present")
	}
	for name, v := range map[string]string{
		"name": l.Name, "relative_path": l.RelativePath, "working_dir": l.WorkingDir,
		"arguments": l.Arguments, "icon_location": l.IconLocation,
		"local_base_path": l.LocalBasePath, "id_list_path": l.IDListPath,
		"target_path": l.TargetPath(),
	} {
		if v != "" {
			t.Errorf("%s = %q for a shortcut that carries none", name, v)
		}
	}
	if l.Volume.Present || l.Network.Present {
		t.Error("volume or network info was invented")
	}
	// The header is still fully read.
	if !l.CreationTime.Equal(created) || !l.WriteTime.Equal(written) {
		t.Error("header timestamps were lost")
	}
	if !l.AccessTime.IsZero() {
		t.Errorf("an unset access time became %s", l.AccessTime)
	}
}

// A network target keeps its share path.
func TestLNK_NetworkTargetIsRead(t *testing.T) {
	l, err := shelllink.Parse(lnkgen.Build(lnkgen.Link{
		Unicode: true, Write: written,
		NetName:          `\\fileserver\share`,
		CommonPathSuffix: `finance\budget.xlsx`,
	}), shelllink.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if !l.Network.Present || l.Network.NetName != `\\fileserver\share` {
		t.Fatalf("network = %+v", l.Network)
	}
	if want := `\\fileserver\share\finance\budget.xlsx`; l.TargetPath() != want {
		t.Errorf("target path = %q, want %q", l.TargetPath(), want)
	}
}

// Zero FILETIME values mean "not recorded" and stay zero.
func TestLNK_ZeroTimestampsStayZero(t *testing.T) {
	l, err := shelllink.Parse(lnkgen.Build(lnkgen.Link{Unicode: true, Name: "no times"}), shelllink.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	for name, ts := range map[string]time.Time{
		"creation": l.CreationTime, "access": l.AccessTime, "write": l.WriteTime,
	} {
		if !ts.IsZero() {
			t.Errorf("%s = %s; a zero FILETIME must not become 1601", name, ts)
		}
	}
	if l.HasAnyTimestamp() {
		t.Error("a shortcut with no timestamps claims to have one")
	}
}

// Detection is structural: header size AND class identifier.
func TestLNK_SniffRequiresSizeAndCLSID(t *testing.T) {
	good := lnkgen.Build(fullLink(true))
	if !shelllink.Sniff(good) {
		t.Fatal("a valid shortcut was not detected")
	}
	for name, data := range map[string][]byte{
		"wrong header size": lnkgen.Corrupt(good, "header-size"),
		"wrong clsid":       lnkgen.Corrupt(good, "clsid"),
		"too short":         good[:40],
		"zeros":             make([]byte, 512),
		"text":              []byte(strings.Repeat("this is not a shortcut ", 30)),
		"empty":             {},
	} {
		if shelllink.Sniff(data) {
			t.Errorf("%s was detected as a shortcut", name)
		}
	}
	// And a file that fails the sniff is refused by name.
	if _, err := shelllink.Parse(lnkgen.Corrupt(good, "clsid"), shelllink.Limits{}); err == nil {
		t.Error("a file with the wrong CLSID parsed")
	}
}

// Truncation at every offset must never panic, and must never yield a
// field decoded from bytes that are not there.
func TestLNK_TruncationIsSurvivable(t *testing.T) {
	good := lnkgen.Build(fullLink(true))
	for n := 0; n < len(good); n++ {
		l, err := shelllink.Parse(lnkgen.Truncate(good, n), shelllink.Limits{})
		if err != nil {
			continue // a classified error is a fine outcome
		}
		// Whatever survived must be self-consistent.
		if l.TargetPath() != "" && !strings.Contains(l.TargetPath(), `\`) {
			t.Fatalf("truncated at %d produced %q as a path", n, l.TargetPath())
		}
		if n < len(good) && n > 0x4C && len(l.Warnings) == 0 &&
			l.Arguments == "" && l.IconLocation == "" && l.HasIDList {
			// A shortcut cut mid-structure must say so.
			t.Fatalf("truncated at %d parsed silently with no warning", n)
		}
	}
}

// Corrupt size fields must be rejected, not trusted.
func TestLNK_CorruptSizeFieldsAreRejected(t *testing.T) {
	// A declared ID list larger than the file.
	l, err := shelllink.Parse(lnkgen.Corrupt(lnkgen.Build(fullLink(true)), "huge-idlist"), shelllink.Limits{})
	if err == nil && len(l.Warnings) == 0 {
		t.Error("huge-idlist: a corrupt size was accepted without a warning")
	}
	if l.IDListPath != "" {
		t.Errorf("huge-idlist: a path was reconstructed from a list that does not fit: %q", l.IDListPath)
	}

	// A declared string longer than the file. Built without an ID list
	// or LinkInfo so StringData starts right after the header, which is
	// the only place the corruption can be aimed deterministically.
	stringsOnly := lnkgen.Build(lnkgen.Link{Unicode: true, Name: "target", WorkingDir: `C:	mp`})
	l, err = shelllink.Parse(lnkgen.Corrupt(stringsOnly, "huge-string-count"), shelllink.Limits{})
	if err == nil {
		if len(l.Warnings) == 0 {
			t.Error("huge-string-count: a corrupt size was accepted without a warning")
		}
		if l.Name != "" {
			t.Errorf("huge-string-count: a string was decoded anyway: %q", l.Name)
		}
	}
}

// Byte-flip fuzzing: no panic, no unbounded allocation, no invented path.
func TestLNK_ByteFlipsAreSurvivable(t *testing.T) {
	good := lnkgen.Build(fullLink(true))
	for i := 0; i < len(good); i++ {
		bad := append([]byte(nil), good...)
		bad[i] ^= 0xFF
		l, err := shelllink.Parse(bad, shelllink.Limits{})
		if err != nil {
			continue
		}
		if len(l.IDListItems) > 512 {
			t.Fatalf("offset %d produced %d shell items", i, len(l.IDListItems))
		}
		for _, s := range []string{l.Name, l.WorkingDir, l.Arguments, l.TargetPath()} {
			if len(s) > 64<<10 {
				t.Fatalf("offset %d produced a %d-character string", i, len(s))
			}
		}
	}
}

// Parsing is deterministic.
func TestLNK_IsDeterministic(t *testing.T) {
	path := write(t, "report.lnk", lnkgen.Build(fullLink(true)))
	first, err := shelllink.ParseFile(path, shelllink.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := shelllink.ParseFile(path, shelllink.Limits{})
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if again.TargetPath() != first.TargetPath() || again.IDListPath != first.IDListPath ||
			len(again.IDListItems) != len(first.IDListItems) {
			t.Fatalf("run %d differed", i)
		}
	}
}

// Offsets are recorded so a field can be traced to a byte range.
func TestLNK_StructureOffsetsAreRecorded(t *testing.T) {
	l, err := shelllink.Parse(lnkgen.Build(fullLink(true)), shelllink.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"header", "link_target_id_list", "link_info",
		"name_string", "relative_path", "working_dir",
		"command_line_arguments", "icon_location",
	} {
		if _, ok := l.Offsets[want]; !ok {
			t.Errorf("no recorded offset for %q", want)
		}
	}
	if l.Offsets["header"] != 0 {
		t.Errorf("header offset = %d", l.Offsets["header"])
	}
	if l.Offsets["link_target_id_list"] != 0x4C {
		t.Errorf("id list offset = %d, want 76", l.Offsets["link_target_id_list"])
	}
}

// Flags are surfaced by their spec names.
func TestLNK_FlagNamesAreReported(t *testing.T) {
	l, err := shelllink.Parse(lnkgen.Build(fullLink(true)), shelllink.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	names := strings.Join(shelllink.FlagNames(l.LinkFlags), ",")
	for _, want := range []string{
		"HasLinkTargetIDList", "HasLinkInfo", "HasName", "HasRelativePath",
		"HasWorkingDir", "HasArguments", "HasIconLocation", "IsUnicode",
	} {
		if !strings.Contains(names, want) {
			t.Errorf("flag %q not reported: %s", want, names)
		}
	}
}
