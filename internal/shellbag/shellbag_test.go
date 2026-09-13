package shellbag_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"tracefall/internal/shellbag"
	"tracefall/internal/shellbag/sbgen"
)

const thisPC = "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"

// Wall-clock readings, deliberately not "UTC" -- the DOS fields carry no
// timezone, and the test names them the way the format means them.
var (
	wallModified = time.Date(2021, 4, 29, 18, 17, 38, 0, time.UTC)
	wallCreated  = time.Date(2020, 1, 2, 3, 4, 10, 0, time.UTC)
	wallAccessed = time.Date(2021, 5, 1, 9, 30, 0, 0, time.UTC)
)

func TestDecodeItem_RootIsNamedFromItsDocumentedCLSID(t *testing.T) {
	it, size, err := shellbag.DecodeItem(sbgen.Root(thisPC), 0, shellbag.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if size == 0 {
		t.Fatal("root item consumed no bytes")
	}
	if it.Kind != shellbag.KindRoot {
		t.Errorf("kind = %q, want root", it.Kind)
	}
	if it.CLSID != thisPC {
		t.Errorf("CLSID = %q, want %q", it.CLSID, thisPC)
	}
	if it.CLSIDMeaning == "" || it.Name == "" {
		t.Errorf("documented CLSID was not named: meaning=%q name=%q", it.CLSIDMeaning, it.Name)
	}
}

// An undocumented CLSID must be reported as the GUID itself, never given
// an invented name.
func TestDecodeItem_UnknownRootCLSIDIsNotNamed(t *testing.T) {
	const unknown = "{DEADBEEF-1111-2222-3333-444444444444}"
	it, _, err := shellbag.DecodeItem(sbgen.Root(unknown), 0, shellbag.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if it.CLSIDMeaning != "" {
		t.Errorf("an unknown CLSID was named %q", it.CLSIDMeaning)
	}
	if it.Name != unknown {
		t.Errorf("name = %q, want the raw CLSID %q", it.Name, unknown)
	}
}

func TestDecodeItem_VolumeRoundTrip(t *testing.T) {
	it, _, err := shellbag.DecodeItem(sbgen.Volume(`C:\`), 0, shellbag.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if it.Kind != shellbag.KindVolume {
		t.Errorf("kind = %q, want volume", it.Kind)
	}
	if it.Name != `C:\` {
		t.Errorf("name = %q, want %q", it.Name, `C:\`)
	}
	if seg := shellbag.PathSegment(it); seg != "C:" {
		t.Errorf("path segment = %q, want %q (the trailing separator must not double up on join)", seg, "C:")
	}
}

// The long name from the 0xBEEF0004 block must win over the short name,
// and the short name must still be retained.
func TestDecodeItem_DirectoryWithExtensionBlockRoundTrip(t *testing.T) {
	for _, version := range []uint16{3, 7, 8, 9} {
		item := sbgen.File(sbgen.FileEntry{
			ShortName: "QUARTE~1", LongName: "Quarterly Reports",
			IsDirectory: true, Attributes: 0x10,
			Modified: wallModified, Created: wallCreated, Accessed: wallAccessed,
			ExtVersion: version, MFTEntry: 4242, MFTSequence: 3,
		})
		it, _, err := shellbag.DecodeItem(item, 0, shellbag.Limits{})
		if err != nil {
			t.Fatalf("version %d: %v", version, err)
		}
		if it.Kind != shellbag.KindDirectory {
			t.Errorf("version %d: kind = %q, want directory", version, it.Kind)
		}
		if it.Name != "Quarterly Reports" {
			t.Errorf("version %d: name = %q, want the long name", version, it.Name)
		}
		if it.ShortName != "QUARTE~1" {
			t.Errorf("version %d: short name = %q, want it retained", version, it.ShortName)
		}
		if !contains(it.AttributeNames, "directory") {
			t.Errorf("version %d: attributes = %v", version, it.AttributeNames)
		}
		if version >= 7 && (it.MFTEntry != 4242 || it.MFTSequence != 3) {
			t.Errorf("version %d: MFT reference = %d/%d, want 4242/3", version, it.MFTEntry, it.MFTSequence)
		}
	}
}

// DOS timestamps must round-trip as WALL-CLOCK readings, and must not be
// exposed as instants.
func TestDecodeItem_DOSTimestampsAreWallClockReadings(t *testing.T) {
	item := sbgen.File(sbgen.FileEntry{
		ShortName: "notes.txt", LongName: "notes.txt",
		FileSize: 1024, Attributes: 0x20,
		Modified: wallModified, Created: wallCreated, Accessed: wallAccessed,
		ExtVersion: 9,
	})
	it, _, err := shellbag.DecodeItem(item, 0, shellbag.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	// Two-second granularity: 18:17:38 survives exactly; an odd second
	// would be floored, which is the format's own behaviour.
	if got, want := it.Modified.String(), "2021-04-29 18:17:38"; got != want {
		t.Errorf("modified = %q, want %q", got, want)
	}
	if got, want := it.Created.String(), "2020-01-02 03:04:10"; got != want {
		t.Errorf("created = %q, want %q", got, want)
	}
	if got, want := it.Accessed.String(), "2021-05-01 09:30:00"; got != want {
		t.Errorf("accessed = %q, want %q", got, want)
	}
	if !it.Modified.Valid || !it.Created.Valid || !it.Accessed.Valid {
		t.Error("recorded DOS times were marked invalid")
	}
}

// An unset DOS field is all-zero, and must read as absent rather than as
// a date in 1980.
func TestDecodeItem_UnsetDOSTimestampIsAbsentNotNineteenEighty(t *testing.T) {
	item := sbgen.File(sbgen.FileEntry{ShortName: "x.txt", LongName: "x.txt", ExtVersion: 9})
	it, _, err := shellbag.DecodeItem(item, 0, shellbag.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	for name, d := range map[string]shellbag.DOSTime{
		"modified": it.Modified, "created": it.Created, "accessed": it.Accessed,
	} {
		if d.Valid {
			t.Errorf("%s: an unset field decoded as %s", name, d)
		}
		if d.String() != "" {
			t.Errorf("%s: an absent reading rendered as %q", name, d.String())
		}
	}
}

// A well-formed item of an undecoded type is a coverage gap, not
// corruption, and the two must stay distinguishable.
func TestDecodeItem_UnknownTypeIsReportedNotRejected(t *testing.T) {
	it, size, err := shellbag.DecodeItem(sbgen.Unknown(0x52, []byte("payload")), 0, shellbag.Limits{})
	if err != nil {
		t.Fatalf("a well-formed unknown item was rejected: %v", err)
	}
	if size == 0 {
		t.Fatal("unknown item consumed no bytes; a list containing one could not be walked")
	}
	if it.Kind != shellbag.KindUnknown {
		t.Errorf("kind = %q, want unknown", it.Kind)
	}
	if it.TypeByte != 0x52 {
		t.Errorf("raw type = 0x%02X, want 0x52", it.TypeByte)
	}
	if len(it.Warnings) == 0 {
		t.Error("an undecoded item type produced no warning explaining it")
	}
}

// A size that does not fit the buffer must be refused, not followed.
func TestDecodeItem_InconsistentSizeIsRefused(t *testing.T) {
	good := sbgen.File(sbgen.FileEntry{ShortName: "a.txt", LongName: "a.txt", ExtVersion: 9})
	for _, size := range []uint16{1, 2, 0xFFFF, uint16(len(good) + 1)} {
		_, _, err := shellbag.DecodeItem(sbgen.CorruptSize(good, size), 0, shellbag.Limits{})
		if err == nil {
			t.Errorf("declared size %d was accepted against a %d-byte buffer", size, len(good))
		}
		if size == 0xFFFF && !errors.Is(err, shellbag.ErrBadSize) {
			t.Errorf("oversized item: err = %v, want ErrBadSize", err)
		}
	}
}

func TestDecodeItem_TruncatedItemIsRefused(t *testing.T) {
	good := sbgen.File(sbgen.FileEntry{ShortName: "a.txt", LongName: "a.txt", ExtVersion: 9})
	for _, keep := range []int{0, 1, 2, 5, len(good) - 1} {
		if keep < 0 {
			continue
		}
		_, _, err := shellbag.DecodeItem(sbgen.Truncate(good, keep), 0, shellbag.Limits{})
		if keep >= 2 && err == nil {
			t.Errorf("a %d-byte truncation of a %d-byte item was accepted", keep, len(good))
		}
	}
}

// An item declaring a size beyond the limit must be refused before it is
// allocated against.
func TestDecodeItem_OversizedItemIsBounded(t *testing.T) {
	data := make([]byte, 70000)
	data[0], data[1] = 0x40, 0xFF // ~65KiB, over the default limit
	data[2] = 0x31
	_, _, err := shellbag.DecodeItem(data, 0, shellbag.Limits{MaxItemBytes: 4096})
	if err == nil {
		t.Fatal("an item far over the size limit was accepted")
	}
	if !errors.Is(err, shellbag.ErrBadSize) {
		t.Errorf("err = %v, want ErrBadSize", err)
	}
}

func TestDecodeList_WalksItemsAndStopsAtTheTerminator(t *testing.T) {
	data := sbgen.List(
		sbgen.Root(thisPC),
		sbgen.Volume(`C:\`),
		sbgen.File(sbgen.FileEntry{ShortName: "USERS", LongName: "Users", IsDirectory: true, ExtVersion: 9}),
	)
	items, err := shellbag.DecodeList(data, shellbag.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 {
		t.Fatalf("decoded %d items, want 3", len(items))
	}
	var segs []string
	for _, it := range items {
		segs = append(segs, shellbag.PathSegment(it))
	}
	if got, want := shellbag.JoinPath(segs), `This PC / My Computer\C:\Users`; got != want {
		t.Errorf("reconstructed path = %q, want %q", got, want)
	}
	// Offsets must be recorded, and must increase.
	for i := 1; i < len(items); i++ {
		if items[i].Offset <= items[i-1].Offset {
			t.Errorf("item %d offset %d does not follow %d", i, items[i].Offset, items[i-1].Offset)
		}
	}
}

// A malformed item in the middle must not discard what came before it.
func TestDecodeList_ReturnsItemsDecodedBeforeAFailure(t *testing.T) {
	good := sbgen.File(sbgen.FileEntry{ShortName: "OK", LongName: "OK", IsDirectory: true, ExtVersion: 9})
	data := append([]byte{}, sbgen.Root(thisPC)...)
	data = append(data, sbgen.Volume(`C:\`)...)
	data = append(data, sbgen.CorruptSize(good, 0xFFFF)...)

	items, err := shellbag.DecodeList(data, shellbag.Limits{})
	if err == nil {
		t.Fatal("a malformed item was accepted")
	}
	if len(items) != 2 {
		t.Errorf("recovered %d items before the failure, want 2; earlier evidence must survive", len(items))
	}
}

func TestDecodeList_ItemCountIsBounded(t *testing.T) {
	var data []byte
	for i := 0; i < 500; i++ {
		data = append(data, sbgen.Volume(`C:\`)...)
	}
	items, err := shellbag.DecodeList(data, shellbag.Limits{MaxItemsPerKey: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 10 {
		t.Errorf("decoded %d items with a limit of 10", len(items))
	}
}

func TestDecodeItem_UnicodeAndLongNamesSurviveAndAreBounded(t *testing.T) {
	long := strings.Repeat("Ω", 5000)
	item := sbgen.File(sbgen.FileEntry{
		ShortName: "LONG~1", LongName: long, IsDirectory: true, ExtVersion: 9,
	})
	it, _, err := shellbag.DecodeItem(item, 0, shellbag.Limits{MaxNameBytes: 512})
	if err != nil {
		t.Fatal(err)
	}
	if len(it.Name) > 512+8 {
		t.Errorf("name not bounded: %d bytes", len(it.Name))
	}
	// A short Unicode name must survive intact.
	it2, _, err := shellbag.DecodeItem(sbgen.File(sbgen.FileEntry{
		ShortName: "JP", LongName: "日本語フォルダ", IsDirectory: true, ExtVersion: 9,
	}), 0, shellbag.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if it2.Name != "日本語フォルダ" {
		t.Errorf("unicode name = %q", it2.Name)
	}
}

// A name carrying control characters is not something Windows can
// record -- those bytes are illegal in a filename -- so this is either
// corruption or a deliberate attempt to confuse a reader.
//
// The requirement is therefore NOT that Tracefall reconstruct the
// "intended" name by deleting the offending bytes: presenting a name the
// system never recorded would be inventing evidence. It is that the
// output is safe to render, that the item survives, and that the analyst
// is TOLD the value is qualified rather than being handed a fragment
// that looks like a whole folder name.
func TestDecodeItem_ControlCharacterNameIsQualifiedNotPresentedAsWhole(t *testing.T) {
	it, _, err := shellbag.DecodeItem(sbgen.File(sbgen.FileEntry{
		ShortName: "A", LongName: "bad\u0001na\u0007me", IsDirectory: true, ExtVersion: 9,
	}), 0, shellbag.Limits{})
	if err != nil {
		t.Fatalf("an item with an illegal name became unreadable: %v", err)
	}
	// 1. Nothing that could corrupt a view reaches the output.
	for _, r := range it.Name {
		if r < 0x20 || r == 0x7F {
			t.Errorf("control character %q survived in %q", r, it.Name)
		}
	}
	// 2. The analyst is told the value cannot be trusted as complete.
	warned := false
	for _, w := range it.Warnings {
		if strings.Contains(w, "not valid in a Windows name") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("no warning qualifies the recovered name: %v", it.Warnings)
	}
	// 3. The item is still usable evidence.
	if it.Kind != shellbag.KindDirectory {
		t.Errorf("kind = %q, want directory", it.Kind)
	}
}

// An extension block with a signature other than 0xBEEF0004 must be
// skipped, not interpreted -- the item keeps its short name.
func TestDecodeItem_ForeignExtensionBlockIsSkippedNotGuessed(t *testing.T) {
	item := sbgen.File(sbgen.FileEntry{ShortName: "SHORT", LongName: "Long Name", IsDirectory: true, ExtVersion: 9})
	// Find and corrupt the block signature.
	idx := -1
	for i := 0; i+4 <= len(item); i++ {
		if item[i] == 0x04 && item[i+1] == 0x00 && item[i+2] == 0xEF && item[i+3] == 0xBE {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatal("fixture does not contain the 0xBEEF0004 signature")
	}
	corrupt := append([]byte{}, item...)
	corrupt[idx+3] = 0xAA

	it, _, err := shellbag.DecodeItem(corrupt, 0, shellbag.Limits{})
	if err != nil {
		t.Fatalf("a foreign extension block made the whole item unreadable: %v", err)
	}
	if it.Name != "SHORT" {
		t.Errorf("name = %q, want the short name kept when the long-name block is not recognized", it.Name)
	}
	if len(it.Warnings) == 0 {
		t.Error("skipping an unrecognized extension block produced no warning")
	}
}

func TestDecodeItem_NeverPanicsOnArbitraryData(t *testing.T) {
	patterns := [][]byte{
		{}, {0}, {0, 0}, {1, 0}, {2, 0}, {3, 0, 0x31},
		{0xFF, 0xFF, 0x31}, {4, 0, 0x1F, 0x50},
	}
	for _, p := range patterns {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on %v: %v", p, r)
				}
			}()
			_, _, _ = shellbag.DecodeItem(p, 0, shellbag.Limits{})
		}()
	}
	// Every prefix of a real item, and every single-byte mutation.
	good := sbgen.File(sbgen.FileEntry{ShortName: "A", LongName: "Alpha", IsDirectory: true, ExtVersion: 9})
	for i := 0; i <= len(good); i++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on prefix %d: %v", i, r)
				}
			}()
			_, _, _ = shellbag.DecodeItem(good[:i], 0, shellbag.Limits{})
		}()
	}
	for i := 0; i < len(good); i++ {
		mutated := append([]byte{}, good...)
		mutated[i] ^= 0xFF
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on mutation at %d: %v", i, r)
				}
			}()
			_, _, _ = shellbag.DecodeItem(mutated, 0, shellbag.Limits{})
		}()
	}
}

func TestDecodeItem_IsDeterministic(t *testing.T) {
	item := sbgen.File(sbgen.FileEntry{
		ShortName: "QUARTE~1", LongName: "Quarterly Reports", IsDirectory: true,
		Modified: wallModified, Created: wallCreated, ExtVersion: 9,
	})
	first, _, err := shellbag.DecodeItem(item, 0, shellbag.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		got, _, err := shellbag.DecodeItem(item, 0, shellbag.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		if got.Name != first.Name || got.Modified != first.Modified || got.Kind != first.Kind {
			t.Fatalf("iteration %d differs", i)
		}
	}
}

func TestJoinPath_MarksUndecodedLevelsRatherThanDroppingThem(t *testing.T) {
	// An undecoded level must SHOW. Dropping it silently asserted a
	// parent-child relationship the evidence does not contain: on a real
	// UsrClass.dat, ["This PC", "", "Contact"] was reported as
	// "This PC\\Contact", and the level between them was "Pictures".
	got := shellbag.JoinPath([]string{"C:", "", "Users", "", "jdoe"})
	want := `C:\` + shellbag.UndecodedSegment + `\Users\` + shellbag.UndecodedSegment + `\jdoe`
	if got != want {
		t.Errorf("join = %q, want %q", got, want)
	}
	// The placeholder must never look like a folder name.
	if !strings.HasPrefix(shellbag.UndecodedSegment, "(") {
		t.Errorf("the placeholder %q could be mistaken for a folder name", shellbag.UndecodedSegment)
	}
	// A trailing undecoded level says nothing about the leaf and is
	// trimmed; a path of nothing but placeholders is still empty.
	if got := shellbag.JoinPath([]string{"C:", ""}); got != "C:" {
		t.Errorf("trailing undecoded level: %q, want %q", got, "C:")
	}
	if got := shellbag.JoinPath([]string{"", ""}); got != "" {
		t.Errorf("all-undecoded path: %q, want empty", got)
	}
	if got := shellbag.JoinPath(nil); got != "" {
		t.Errorf("empty path: %q", got)
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
