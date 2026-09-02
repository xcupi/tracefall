package jumplist_test

import (
	"strings"
	"testing"
	"time"

	"tracefall/internal/jumplist"
	"tracefall/internal/jumplist/jlgen"
	"tracefall/internal/olecf/olegen"
	"tracefall/internal/shelllink/lnkgen"
)

var (
	created  = time.Date(2026, 2, 11, 8, 30, 0, 0, time.UTC)
	written  = time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC)
	accessed = time.Date(2026, 3, 4, 17, 45, 12, 0, time.UTC)
	lastUsed = time.Date(2026, 3, 5, 9, 15, 30, 0, time.UTC)
)

func link(name, target string) lnkgen.Link {
	return lnkgen.Link{
		Unicode: true, FileAttributes: 0x20,
		Creation: created, Write: written, Access: accessed,
		FileSize: 184320, ShowCommand: 1,
		Name: name, LocalBasePath: target,
		WorkingDir: `C:\Users\jdoe\Documents`,
		DriveType:  3, VolumeSerial: 0xC0FFEE01, VolumeLabel: "OSDisk",
		TrackerMachineID: "WKSTN-042",
	}
}

func threeItems() []jlgen.Item {
	return []jlgen.Item{
		{Link: link("report", `C:\Users\jdoe\Documents\report.docx`), EntryNumber: 1,
			AccessCount: 7, LastAccess: lastUsed, Hostname: "wkstn-042"},
		{Link: link("budget", `\\fileserver\finance\budget.xlsx`), EntryNumber: 2,
			AccessCount: 2, LastAccess: lastUsed.Add(-time.Hour), Pinned: true},
		{Link: link("photos", `E:\photos\DSC0001.jpg`), EntryNumber: 3,
			AccessCount: 1, LastAccess: lastUsed.Add(-24 * time.Hour)},
	}
}

// A complete Automatic Destinations file: streams, DestList, ordering.
func TestJL_AutomaticIsFullyParsed(t *testing.T) {
	jl, err := jumplist.Parse(jlgen.BuildAutomatic(jlgen.Automatic{Items: threeItems()}), jumplist.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if jl.Kind != jumplist.KindAutomatic {
		t.Errorf("kind = %q", jl.Kind)
	}
	if jl.DestListVersion != 3 {
		t.Errorf("DestList version = %d", jl.DestListVersion)
	}
	if len(jl.Entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(jl.Entries))
	}
	if jl.DeclaredEntries != 3 {
		t.Errorf("declared entries = %d", jl.DeclaredEntries)
	}
	if jl.PinnedEntries != 1 {
		t.Errorf("pinned entries = %d, want 1", jl.PinnedEntries)
	}

	byPath := map[string]jumplist.Entry{}
	for _, e := range jl.Entries {
		if e.LinkError != nil {
			t.Errorf("entry %s failed: %v", e.StreamName, e.LinkError)
			continue
		}
		p, src := e.TargetPath()
		byPath[p] = e
		if src != "embedded shortcut" {
			t.Errorf("%s: path source = %q", e.StreamName, src)
		}
		// Provenance: which stream, at which directory index.
		if e.StreamName == "" || e.StreamIndex < 0 {
			t.Errorf("%s: incomplete stream provenance (index %d)", e.StreamName, e.StreamIndex)
		}
		if e.Bytes <= 0 {
			t.Errorf("%s: no stream length recorded", e.StreamName)
		}
		if e.Dest == nil {
			t.Errorf("%s: no DestList row was matched", e.StreamName)
		}
	}

	report, ok := byPath[`C:\Users\jdoe\Documents\report.docx`]
	if !ok {
		t.Fatalf("the report entry is missing; got %v", keys(byPath))
	}
	// The embedded shortcut's own fields survive intact.
	if !report.Link.CreationTime.Equal(created) || !report.Link.WriteTime.Equal(written) ||
		!report.Link.AccessTime.Equal(accessed) {
		t.Error("the embedded shortcut's target timestamps were lost")
	}
	if report.Link.FileSize != 184320 {
		t.Errorf("target size = %d", report.Link.FileSize)
	}
	if report.Link.Volume.SerialNumber != 0xC0FFEE01 {
		t.Errorf("volume serial = %08X", report.Link.Volume.SerialNumber)
	}
	// The Jump List's own metadata.
	if report.Dest.AccessCount != 7 {
		t.Errorf("access count = %d, want 7", report.Dest.AccessCount)
	}
	if !report.Dest.LastRecordedAccess.Equal(lastUsed) {
		t.Errorf("last recorded access = %s, want %s", report.Dest.LastRecordedAccess, lastUsed)
	}
	if report.Dest.Hostname != "wkstn-042" {
		t.Errorf("hostname = %q", report.Dest.Hostname)
	}
	if report.Dest.Pinned {
		t.Error("an unpinned entry reports itself pinned")
	}
	if !byPath[`\\fileserver\finance\budget.xlsx`].Dest.Pinned {
		t.Error("a pinned entry does not report itself pinned")
	}
	// MRU order is an order, and is recorded as one.
	seen := map[int]bool{}
	for _, e := range jl.Entries {
		if e.Dest != nil {
			seen[e.Dest.MRUPosition] = true
		}
	}
	if len(seen) != 3 {
		t.Errorf("MRU positions are not distinct: %v", seen)
	}
	if len(jl.Warnings) != 0 {
		t.Errorf("a well-formed Jump List produced warnings: %v", jl.Warnings)
	}
}

// DestList version 1 (Windows 7) has a different row layout and is read
// with its own offsets.
func TestJL_DestListVersion1(t *testing.T) {
	jl, err := jumplist.Parse(jlgen.BuildAutomatic(jlgen.Automatic{
		DestListVersion: 1, Items: threeItems(),
	}), jumplist.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if jl.DestListVersion != 1 {
		t.Fatalf("version = %d", jl.DestListVersion)
	}
	for _, e := range jl.Entries {
		if e.Dest == nil {
			t.Fatalf("%s: no DestList row decoded for version 1", e.StreamName)
		}
		if e.Dest.LastRecordedAccess.IsZero() {
			t.Errorf("%s: version 1 access time was not decoded", e.StreamName)
		}
	}
}

// An unknown DestList version is reported, and the shortcuts still parse.
func TestJL_UnknownDestListVersionKeepsShortcuts(t *testing.T) {
	good := jlgen.BuildAutomatic(jlgen.Automatic{Items: threeItems()})
	jl, err := jumplist.Parse(jlgen.CorruptDestListVersion(good, 99), jumplist.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if jl.DestListVersion != 99 {
		t.Errorf("version = %d, want the declared 99", jl.DestListVersion)
	}
	if len(jl.Entries) != 3 {
		t.Fatalf("got %d entries; an unreadable DestList must not lose the shortcuts", len(jl.Entries))
	}
	for _, e := range jl.Entries {
		if e.LinkError != nil {
			t.Errorf("%s: shortcut lost with the DestList: %v", e.StreamName, e.LinkError)
		}
		if e.Dest != nil {
			t.Errorf("%s: a row was decoded from an unsupported layout", e.StreamName)
		}
	}
	if !strings.Contains(strings.Join(jl.Warnings, " "), "version 99") {
		t.Errorf("the unsupported version was not reported: %v", jl.Warnings)
	}
}

// A missing DestList is reported; every shortcut still parses.
func TestJL_MissingDestListKeepsShortcuts(t *testing.T) {
	jl, err := jumplist.Parse(jlgen.BuildAutomatic(jlgen.Automatic{
		Items: threeItems(), OmitDestList: true,
	}), jumplist.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(jl.Entries) != 3 {
		t.Fatalf("got %d entries", len(jl.Entries))
	}
	for _, e := range jl.Entries {
		if e.Dest != nil {
			t.Errorf("%s: a DestList row appeared with no DestList", e.StreamName)
		}
		if e.LinkError != nil {
			t.Errorf("%s: %v", e.StreamName, e.LinkError)
		}
	}
	if !strings.Contains(strings.Join(jl.Warnings, " "), "no DestList") {
		t.Errorf("the missing DestList was not reported: %v", jl.Warnings)
	}
}

// One malformed embedded shortcut must not cost the valid ones.
func TestJL_OneMalformedEntryDoesNotLoseTheRest(t *testing.T) {
	items := threeItems()
	items[1].RawLink = []byte("this stream is not a shortcut at all, just text")
	jl, err := jumplist.Parse(jlgen.BuildAutomatic(jlgen.Automatic{Items: items}), jumplist.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(jl.Entries) != 3 {
		t.Fatalf("got %d entries, want all 3 reported", len(jl.Entries))
	}
	var good, bad int
	for _, e := range jl.Entries {
		if e.LinkError != nil {
			bad++
			// The failed entry is still evidence, and its DestList row
			// survives it.
			if e.Dest == nil {
				t.Error("a failed entry lost its DestList row too")
			}
			if p, src := e.TargetPath(); p == "" || src != "DestList record" {
				t.Errorf("a failed entry did not fall back to the DestList path: %q / %q", p, src)
			}
			continue
		}
		good++
	}
	if good != 2 || bad != 1 {
		t.Errorf("got %d good and %d failed entries, want 2 and 1", good, bad)
	}
}

// A DestList row whose stream is missing is still reported.
func TestJL_DestListRowWithoutStreamIsReported(t *testing.T) {
	items := threeItems()
	items[2].OmitStream = true
	jl, err := jumplist.Parse(jlgen.BuildAutomatic(jlgen.Automatic{Items: items}), jumplist.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(jl.Entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(jl.Entries))
	}
	var orphan *jumplist.Entry
	for i := range jl.Entries {
		if jl.Entries[i].StreamIndex == -1 {
			orphan = &jl.Entries[i]
		}
	}
	if orphan == nil {
		t.Fatal("the row with no stream was not reported")
	}
	if orphan.Dest == nil || orphan.Dest.AccessCount != 1 {
		t.Errorf("the orphaned row lost its metadata: %+v", orphan.Dest)
	}
	if orphan.LinkError == nil {
		t.Error("a row with no stream reported no problem")
	}
}

// A stream with no DestList row is still an entry.
func TestJL_StreamWithoutDestListRowIsReported(t *testing.T) {
	items := threeItems()
	items[0].OmitDestList = true
	jl, err := jumplist.Parse(jlgen.BuildAutomatic(jlgen.Automatic{Items: items}), jumplist.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(jl.Entries) != 3 {
		t.Fatalf("got %d entries", len(jl.Entries))
	}
	var without int
	for _, e := range jl.Entries {
		if e.Dest == nil {
			without++
			if e.LinkError != nil {
				t.Error("a shortcut with no DestList row also failed to parse")
			}
		}
	}
	if without != 1 {
		t.Errorf("%d entries lack a DestList row, want 1", without)
	}
}

// Custom Destinations is a different format and is read as one.
func TestJL_CustomIsParsedSeparately(t *testing.T) {
	jl, err := jumplist.Parse(jlgen.BuildCustom([]lnkgen.Link{
		link("task one", `C:\Program Files\App\app.exe`),
		link("task two", `C:\Program Files\App\helper.exe`),
		link("recent", `D:\work\notes.txt`),
	}), jumplist.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if jl.Kind != jumplist.KindCustom {
		t.Errorf("kind = %q", jl.Kind)
	}
	if jl.DestListVersion != 0 {
		t.Errorf("a Custom Destinations file reported a DestList version: %d", jl.DestListVersion)
	}
	if len(jl.Entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(jl.Entries))
	}
	for i, e := range jl.Entries {
		if e.LinkError != nil {
			t.Errorf("entry %d: %v", i, e.LinkError)
			continue
		}
		if e.Dest != nil {
			t.Errorf("entry %d: Custom Destinations has no DestList rows", i)
		}
		// Provenance is the byte offset, since there are no streams.
		if e.Offset <= 0 {
			t.Errorf("entry %d: no offset recorded", i)
		}
		if e.Bytes <= 0 {
			t.Errorf("entry %d: no length recorded", i)
		}
		if e.StreamIndex != -1 {
			t.Errorf("entry %d: reported a compound-file stream index", i)
		}
	}
	if p, _ := jl.Entries[0].TargetPath(); p != `C:\Program Files\App\app.exe` {
		t.Errorf("first target = %q", p)
	}
	// Offsets ascend, and each entry's length reaches the next.
	for i := 1; i < len(jl.Entries); i++ {
		if jl.Entries[i].Offset <= jl.Entries[i-1].Offset {
			t.Errorf("entry %d does not follow entry %d", i, i-1)
		}
		if jl.Entries[i-1].Offset+jl.Entries[i-1].Bytes != jl.Entries[i].Offset {
			t.Errorf("entry %d's length does not reach entry %d", i-1, i)
		}
	}
}

// A malformed entry among valid ones in Custom Destinations costs one
// item, not the rest of the file.
func TestJL_CustomSurvivesAMalformedEntry(t *testing.T) {
	good := lnkgen.Build(link("ok", `C:\a\one.txt`))
	bad := lnkgen.Corrupt(lnkgen.Build(link("bad", `C:\a\two.txt`)), "huge-idlist")
	third := lnkgen.Build(link("ok3", `C:\a\three.txt`))

	jl, err := jumplist.Parse(jlgen.BuildCustomRaw([][]byte{good, bad, third}), jumplist.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(jl.Entries) < 2 {
		t.Fatalf("got %d entries; a damaged entry took the others with it", len(jl.Entries))
	}
	var paths []string
	for _, e := range jl.Entries {
		if p, _ := e.TargetPath(); p != "" {
			paths = append(paths, p)
		}
	}
	joined := strings.Join(paths, "|")
	for _, want := range []string{`C:\a\one.txt`, `C:\a\three.txt`} {
		if !strings.Contains(joined, want) {
			t.Errorf("the valid entry %q was lost: %s", want, joined)
		}
	}
}

// Detection is structural for both containers, and a renamed file is
// still found.
func TestJL_DetectionIsStructural(t *testing.T) {
	auto := jlgen.BuildAutomatic(jlgen.Automatic{Items: threeItems()})
	custom := jlgen.BuildCustom([]lnkgen.Link{link("a", `C:\a\b.txt`)})
	for name, data := range map[string][]byte{"automatic": auto, "custom": custom} {
		if !jumplist.Sniff(data) {
			t.Errorf("%s was not detected", name)
		}
	}
	for name, data := range map[string][]byte{
		"text":         []byte(strings.Repeat("not a jump list at all ", 60)),
		"zeros":        make([]byte, 4096),
		"short":        {0x4C, 0x00, 0x00},
		"empty":        {},
		"a bare .lnk?": {},
	} {
		if len(data) == 0 && name == "a bare .lnk?" {
			continue
		}
		if jumplist.Sniff(data) {
			t.Errorf("%q was detected as a Jump List", name)
		}
	}
	// An impostor: right extension, wrong content. Parsing must refuse.
	if _, err := jumplist.Parse([]byte(strings.Repeat("impostor ", 100)), jumplist.Limits{}); err == nil {
		t.Error("an impostor file parsed as a Jump List")
	}
}

// Truncation and corruption are survivable, and never silent.
func TestJL_MalformedContainersFailSafely(t *testing.T) {
	auto := jlgen.BuildAutomatic(jlgen.Automatic{Items: threeItems()})
	for _, how := range []string{"signature", "version", "sector-shift", "fat-count", "dir-start", "minifat-start"} {
		jl, err := jumplist.Parse(olegen.Corrupt(auto, how), jumplist.Limits{})
		if err != nil {
			continue
		}
		for _, e := range jl.Entries {
			if e.LinkError == nil && e.Link.TargetPath() != "" &&
				!strings.Contains(e.Link.TargetPath(), `\`) {
				t.Errorf("%s: produced %q as a target path", how, e.Link.TargetPath())
			}
		}
	}
	for n := 0; n < len(auto); n += 128 {
		if _, err := jumplist.Parse(olegen.Truncate(auto, n), jumplist.Limits{}); err != nil {
			continue
		}
	}
}

// Byte-flip fuzzing over both containers.
func TestJL_ByteFlipsAreSurvivable(t *testing.T) {
	for _, data := range [][]byte{
		jlgen.BuildAutomatic(jlgen.Automatic{Items: threeItems()}),
		jlgen.BuildCustom([]lnkgen.Link{link("a", `C:\a\b.txt`), link("c", `C:\c\d.txt`)}),
	} {
		for i := 0; i < len(data); i += 23 {
			bad := append([]byte(nil), data...)
			bad[i] ^= 0xFF
			jl, err := jumplist.Parse(bad, jumplist.Limits{})
			if err != nil {
				continue
			}
			if len(jl.Entries) > 4096 {
				t.Fatalf("offset %d produced %d entries", i, len(jl.Entries))
			}
			for _, e := range jl.Entries {
				if p, _ := e.TargetPath(); len(p) > 64<<10 {
					t.Fatalf("offset %d produced a %d-character path", i, len(p))
				}
			}
		}
	}
}

// Duplicate targets are kept: two entries for one file is a real state.
func TestJL_DuplicateTargetsAreBothKept(t *testing.T) {
	items := []jlgen.Item{
		{Link: link("a", `C:\same\file.docx`), EntryNumber: 1, AccessCount: 3, LastAccess: lastUsed},
		{Link: link("b", `C:\same\file.docx`), EntryNumber: 2, AccessCount: 1, LastAccess: lastUsed.Add(-time.Hour)},
	}
	jl, err := jumplist.Parse(jlgen.BuildAutomatic(jlgen.Automatic{Items: items}), jumplist.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(jl.Entries) != 2 {
		t.Fatalf("got %d entries; duplicates must not be collapsed", len(jl.Entries))
	}
}

// Long and Unicode paths survive both containers.
func TestJL_LongAndUnicodePaths(t *testing.T) {
	long := `C:\Users\jdoe\` + strings.Repeat(`deeply-nested-directory\`, 15) + "file.docx"
	unicode := `C:\Users\田中\書類\報告書.xlsx`
	items := []jlgen.Item{
		{Link: link("long", long), EntryNumber: 1, AccessCount: 1, LastAccess: lastUsed},
		{Link: link("unicode", unicode), EntryNumber: 2, AccessCount: 1, LastAccess: lastUsed},
	}
	jl, err := jumplist.Parse(jlgen.BuildAutomatic(jlgen.Automatic{Items: items}), jumplist.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, e := range jl.Entries {
		p, _ := e.TargetPath()
		got[p] = true
		if e.Dest != nil && e.Dest.Path != "" && e.Dest.Path != p {
			t.Errorf("the DestList path and the shortcut path disagree unexpectedly: %q vs %q", e.Dest.Path, p)
		}
	}
	for _, want := range []string{long, unicode} {
		if !got[want] {
			t.Errorf("path did not survive: %q", want)
		}
	}
}

// A shortcut with no optional structures still yields an entry.
func TestJL_MissingOptionalLinkFieldsAreAbsentNotInvented(t *testing.T) {
	items := []jlgen.Item{{
		Link:        lnkgen.Link{Unicode: true, Write: written},
		EntryNumber: 1, AccessCount: 1, LastAccess: lastUsed,
		DestPath: `C:\only\in\destlist.txt`,
	}}
	jl, err := jumplist.Parse(jlgen.BuildAutomatic(jlgen.Automatic{Items: items}), jumplist.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(jl.Entries) != 1 {
		t.Fatalf("got %d entries", len(jl.Entries))
	}
	e := jl.Entries[0]
	if e.LinkError != nil {
		t.Fatalf("a minimal shortcut failed: %v", e.LinkError)
	}
	if e.Link.Volume.Present || e.Link.WorkingDir != "" || e.Link.Arguments != "" {
		t.Error("absent shortcut fields were invented")
	}
	// With no path in the shortcut, the DestList's path is used -- and
	// the source says so.
	p, src := e.TargetPath()
	if p != `C:\only\in\destlist.txt` || src != "DestList record" {
		t.Errorf("fallback path = %q from %q", p, src)
	}
}

// A disagreement between the two recorded paths is surfaced, not
// resolved silently.
func TestJL_PathDisagreementIsDetectable(t *testing.T) {
	items := []jlgen.Item{{
		Link: link("a", `C:\shortcut\path.docx`), EntryNumber: 1,
		AccessCount: 1, LastAccess: lastUsed, DestPath: `C:\destlist\path.docx`,
	}}
	jl, err := jumplist.Parse(jlgen.BuildAutomatic(jlgen.Automatic{Items: items}), jumplist.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if !jl.Entries[0].PathsDisagree() {
		t.Error("a disagreement between the shortcut and DestList paths was not detected")
	}
	if jl.Entries[0].Dest.Path != `C:\destlist\path.docx` {
		t.Error("the DestList's own path was overwritten by the shortcut's")
	}
}

// Parsing is deterministic.
func TestJL_IsDeterministic(t *testing.T) {
	data := jlgen.BuildAutomatic(jlgen.Automatic{Items: threeItems()})
	first, err := jumplist.Parse(data, jumplist.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := jumplist.Parse(data, jumplist.Limits{})
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if len(again.Entries) != len(first.Entries) {
			t.Fatalf("run %d: %d entries vs %d", i, len(again.Entries), len(first.Entries))
		}
		for j := range first.Entries {
			p1, _ := first.Entries[j].TargetPath()
			p2, _ := again.Entries[j].TargetPath()
			if p1 != p2 || again.Entries[j].StreamName != first.Entries[j].StreamName {
				t.Fatalf("run %d entry %d differed", i, j)
			}
		}
	}
}

// AppID resolution: known resolves, unknown is preserved, never guessed.
func TestJL_AppIDResolution(t *testing.T) {
	id, app := jumplist.AppIDFromFilename("5f7b5f1e01b83767.automaticDestinations-ms")
	if id != "5f7b5f1e01b83767" {
		t.Errorf("appid = %q", id)
	}
	if app == "" {
		t.Error("a known AppID did not resolve")
	}

	id, app = jumplist.AppIDFromFilename("ffffffffffffffff.automaticDestinations-ms")
	if id != "ffffffffffffffff" {
		t.Errorf("an unknown AppID was not preserved: %q", id)
	}
	if app != "" {
		t.Errorf("an unknown AppID was given the name %q", app)
	}
	if label := jumplist.ApplicationLabel(id, app); !strings.Contains(label, id) ||
		!strings.Contains(label, "Unknown application") {
		t.Errorf("the unknown-application label hides the identifier: %q", label)
	}

	// A renamed file carries no AppID at all -- distinct from unknown.
	id, app = jumplist.AppIDFromFilename("renamed-evidence.bin")
	if id != "" || app != "" {
		t.Errorf("a renamed file produced appid=%q app=%q", id, app)
	}
	if label := jumplist.ApplicationLabel("", ""); !strings.Contains(label, "no AppID") {
		t.Errorf("the no-AppID case is not distinguished: %q", label)
	}
	// Names that are not AppIDs are not treated as one.
	for _, name := range []string{
		"nothex.automaticDestinations-ms", "short.automaticDestinations-ms",
		"zzzzzzzzzzzzzzzz.automaticDestinations-ms",
	} {
		if got, _ := jumplist.AppIDFromFilename(name); got != "" {
			t.Errorf("%q yielded an AppID: %q", name, got)
		}
	}
	if jumplist.ResolveAppID("5F7B5F1E01B83767") == "" {
		t.Error("AppID resolution is case-sensitive")
	}
}

func keys(m map[string]jumplist.Entry) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
