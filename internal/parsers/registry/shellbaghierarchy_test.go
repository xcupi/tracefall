package registry_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
	parser "tracefall/internal/parsers/registry"
	"tracefall/internal/regf/regfgen"
	"tracefall/internal/shellbag"
	"tracefall/internal/shellbag/sbgen"
)

// ShellBags HIERARCHY reconstruction.
//
// A ShellBags entry means little on its own. What it establishes is
// where a folder sat, and that is a statement about its ancestors -- so
// the chain has to survive, including the levels that cannot be decoded.
//
// The failure these exist for: an undecoded level was DROPPED from the
// reconstructed path. On a real UsrClass.dat the segments
// ["This PC", "", "Contact"] were reported as "This PC\Contact", which
// asserts that Contact is a direct child of This PC. It is not -- the
// level between them was "Pictures", recorded as a folder GUID that the
// decoder did not read. A path that shows the gap is incomplete; a path
// that hides it is wrong.

const (
	thisPC       = "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
	picturesGUID = "{24AD3AD4-A569-4530-98E1-AB02F9417AA8}"
	unknownGUID  = "{0BADF00D-DEAD-BEEF-0000-000000000001}"
)

var sbWrite = time.Date(2024, 5, 2, 14, 30, 0, 0, time.UTC)

func dirItem(name string) []byte {
	return sbgen.List(sbgen.File(sbgen.FileEntry{
		ShortName: name, LongName: name, IsDirectory: true, Attributes: 0x10, ExtVersion: 9,
	}))
}

// bagTree builds a UsrClass.dat whose BagMRU is the chain given, one
// node per level, each keyed "0" under the one above.
func bagTree(t *testing.T, levels [][]byte) string {
	t.Helper()
	var build func(i int) *regfgen.Key
	build = func(i int) *regfgen.Key {
		k := regfgen.NewKey("0").WithLastWrite(sbWrite).WithValues(
			regfgen.BinaryValue("0", levels[i]),
			regfgen.BinaryValue("MRUListEx", sbgen.MRUListEx(0)),
		)
		if i+1 < len(levels) {
			k.Subkeys = append(k.Subkeys, build(i+1))
		}
		return k
	}
	bagMRU := regfgen.NewKey("BagMRU", build(1)).WithLastWrite(sbWrite).WithValues(
		regfgen.BinaryValue("0", levels[0]),
		regfgen.BinaryValue("MRUListEx", sbgen.MRUListEx(0)),
	)
	hive := regfgen.Build("UsrClass.dat", regfgen.NewKey("ROOT",
		regfgen.NewKey("Local Settings", regfgen.NewKey("Software",
			regfgen.NewKey("Microsoft", regfgen.NewKey("Windows",
				regfgen.NewKey("Shell", bagMRU)))))))
	p := filepath.Join(t.TempDir(), "UsrClass.dat")
	if err := os.WriteFile(p, hive, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func shellBagEvents(t *testing.T, path string) []model.Event {
	t.Helper()
	res, err := parser.New().Parse(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var out []model.Event
	for _, e := range res.Events {
		if e.ArtifactType == model.ArtifactShellBags {
			out = append(out, e)
		}
	}
	return out
}

func pathsOf(events []model.Event) []string {
	var out []string
	for _, e := range events {
		out = append(out, e.Extra["reconstructed_path"])
	}
	return out
}

func hasPath(events []model.Event, want string) bool {
	for _, p := range pathsOf(events) {
		if p == want {
			return true
		}
	}
	return false
}

// The whole point: a folder recorded by GUID is a LEVEL, and the level
// below it is its child -- not a child of the level above.
func TestShellBags_KnownFolderLevelIsNotCollapsed(t *testing.T) {
	events := shellBagEvents(t, bagTree(t, [][]byte{
		sbgen.List(sbgen.Root(thisPC)),
		sbgen.List(sbgen.KnownFolder(picturesGUID)),
		dirItem("Contact"),
	}))

	if !hasPath(events, `This PC / My Computer\Pictures`) {
		t.Errorf("the known-folder level was not decoded; paths: %q", pathsOf(events))
	}
	want := `This PC / My Computer\Pictures\Contact`
	if !hasPath(events, want) {
		t.Fatalf("path %q not reconstructed; got %q", want, pathsOf(events))
	}
	// The collapsed form must NOT appear: it asserts a parent-child
	// relationship the evidence does not contain.
	if hasPath(events, `This PC / My Computer\Contact`) {
		t.Error("the intermediate level was dropped, making Contact a direct child of This PC")
	}

	// The leaf must name its parent, from the registry hierarchy.
	for _, e := range events {
		if e.Extra["reconstructed_path"] != want {
			continue
		}
		if e.Extra["parent_name"] != "Pictures" {
			t.Errorf("parent_name = %q, want Pictures", e.Extra["parent_name"])
		}
		if e.Extra["parent_path"] != `This PC / My Computer\Pictures` {
			t.Errorf("parent_path = %q", e.Extra["parent_path"])
		}
		if !strings.Contains(e.Extra["parent_relationship"], "not an inference") {
			t.Errorf("the parent relationship is not described as recorded: %q", e.Extra["parent_relationship"])
		}
		if e.Extra["parent_registry_key"] == "" || e.Extra["shellbag_node"] == "" {
			t.Error("the BagMRU node and its parent key are not recorded")
		}
		if e.Extra["path_complete"] != "true" {
			t.Errorf("a fully decoded path is marked incomplete: %q", e.Extra["path_limitation"])
		}
	}
}

// An UNDECODED level must be visible in the path and declared, never
// silently removed.
func TestShellBags_UndecodedLevelIsShownNotDropped(t *testing.T) {
	events := shellBagEvents(t, bagTree(t, [][]byte{
		sbgen.List(sbgen.Root(thisPC)),
		sbgen.List(sbgen.Unknown(0x7A, []byte{1, 2, 3, 4, 5, 6, 7, 8})),
		dirItem("Contact"),
	}))

	want := `This PC / My Computer\` + shellbag.UndecodedSegment + `\Contact`
	if !hasPath(events, want) {
		t.Fatalf("path %q not produced; got %q", want, pathsOf(events))
	}
	if hasPath(events, `This PC / My Computer\Contact`) {
		t.Error("the undecoded level was dropped, fabricating a parent-child relationship")
	}
	for _, e := range events {
		if e.Extra["reconstructed_path"] != want {
			continue
		}
		if e.Extra["path_complete"] != "false" {
			t.Error("a path with an undecoded level is reported as complete")
		}
		if e.Extra["path_incomplete_levels"] != "1" {
			t.Errorf("incomplete levels = %q, want 1", e.Extra["path_incomplete_levels"])
		}
		if !strings.Contains(e.Extra["path_limitation"], "could not be decoded") {
			t.Errorf("the limitation is not stated: %q", e.Extra["path_limitation"])
		}
		// The ORDER is still evidence even when a name is not.
		if !strings.Contains(e.Extra["path_limitation"], "ORDER is evidence") {
			t.Errorf("the limitation does not say what IS still known: %q", e.Extra["path_limitation"])
		}
	}
}

// A folder GUID with no documented name is reported AS the GUID, never
// guessed at.
func TestShellBags_UnknownFolderGUIDIsReportedNotGuessed(t *testing.T) {
	events := shellBagEvents(t, bagTree(t, [][]byte{
		sbgen.List(sbgen.Root(thisPC)),
		sbgen.List(sbgen.KnownFolder(unknownGUID)),
		dirItem("Leaf"),
	}))
	if !hasPath(events, `This PC / My Computer\`+unknownGUID+`\Leaf`) {
		t.Errorf("an unlisted folder GUID was not reported as itself; paths: %q", pathsOf(events))
	}
	for _, e := range events {
		if e.Extra["shell_item_clsid"] != unknownGUID {
			continue
		}
		if !strings.Contains(strings.Join([]string{e.Extra["shell_item_name"]}, ""), unknownGUID) {
			t.Error("the GUID is not used as the name")
		}
	}
}

// A portable device's folders: the chain a phone produces. Names here
// are RECOVERED structurally and must be labelled as such.
func TestShellBags_PortableDeviceChainIsReconstructed(t *testing.T) {
	events := shellBagEvents(t, bagTree(t, [][]byte{
		sbgen.List(sbgen.Root(thisPC)),
		sbgen.List(sbgen.Device("LG Q7", `\\?\usb#vid_1004`)),
		sbgen.List(sbgen.Device("Internal storage")),
		sbgen.List(sbgen.Device("DCIM")),
		sbgen.List(sbgen.Device("Camera")),
	}))

	want := `This PC / My Computer\LG Q7\Internal storage\DCIM\Camera`
	if !hasPath(events, want) {
		t.Fatalf("the device chain was not reconstructed; got %q", pathsOf(events))
	}
	for _, e := range events {
		if e.Extra["reconstructed_path"] != want {
			continue
		}
		if e.Extra["parent_name"] != "DCIM" {
			t.Errorf("parent_name = %q, want DCIM", e.Extra["parent_name"])
		}
		// A structurally recovered name is a weaker claim than a decoded
		// one and must say so.
		if !strings.Contains(e.Extra["shell_item_name_source"], "recovered structurally") {
			t.Errorf("a recovered name is not labelled: %q", e.Extra["shell_item_name_source"])
		}
		if e.Extra["shell_item_recovered_strings"] == "" {
			t.Error("the strings the name was recovered from are not preserved")
		}
	}
	// The device node keeps the strings its own length table validates,
	// so a recovered name can be checked rather than taken on trust.
	// Only length-validated strings are kept: an unvalidated scan is
	// what previously reported a phone's folders as "\uffff\u5058\u4d54".
	for _, e := range events {
		if e.Extra["shell_item_name"] != "LG Q7" {
			continue
		}
		if !strings.Contains(e.Extra["shell_item_recovered_strings"], "LG Q7") {
			t.Errorf("the device node preserved no strings: %q", e.Extra["shell_item_recovered_strings"])
		}
	}
}

// Siblings under one level must each get their own full path, and must
// not borrow each other's.
func TestShellBags_SiblingsDoNotShareAPath(t *testing.T) {
	bag1 := regfgen.NewKey("0").WithLastWrite(sbWrite).WithValues(
		regfgen.BinaryValue("0", dirItem("Camera")),
		regfgen.BinaryValue("1", dirItem("Screenshots")),
		regfgen.BinaryValue("MRUListEx", sbgen.MRUListEx(0, 1)),
	)
	bagMRU := regfgen.NewKey("BagMRU", bag1).WithLastWrite(sbWrite).WithValues(
		regfgen.BinaryValue("0", sbgen.List(sbgen.Root(thisPC))),
		regfgen.BinaryValue("MRUListEx", sbgen.MRUListEx(0)),
	)
	hive := regfgen.Build("UsrClass.dat", regfgen.NewKey("ROOT",
		regfgen.NewKey("Local Settings", regfgen.NewKey("Software",
			regfgen.NewKey("Microsoft", regfgen.NewKey("Windows",
				regfgen.NewKey("Shell", bagMRU)))))))
	p := filepath.Join(t.TempDir(), "UsrClass.dat")
	if err := os.WriteFile(p, hive, 0o600); err != nil {
		t.Fatal(err)
	}
	events := shellBagEvents(t, p)
	for _, want := range []string{
		`This PC / My Computer\Camera`, `This PC / My Computer\Screenshots`,
	} {
		if !hasPath(events, want) {
			t.Errorf("sibling path %q missing; got %q", want, pathsOf(events))
		}
	}
	if hasPath(events, `This PC / My Computer\Camera\Screenshots`) {
		t.Error("siblings were nested into one another")
	}
}

// A malformed shell item must not take out the level, and must not
// produce a name.
func TestShellBags_MalformedItemKeepsTheLevelWithoutInventingAName(t *testing.T) {
	events := shellBagEvents(t, bagTree(t, [][]byte{
		sbgen.List(sbgen.Root(thisPC)),
		{0x08, 0x00, 0x31, 0xFF, 0xFF, 0xFF, 0x00, 0x00}, // a truncated file entry
		dirItem("Leaf"),
	}))
	if len(events) == 0 {
		t.Fatal("a malformed item removed every event")
	}
	for _, e := range events {
		p := e.Extra["reconstructed_path"]
		if strings.Contains(p, "\x00") || strings.Contains(p, "�") {
			t.Errorf("a malformed item produced a name from binary: %q", p)
		}
	}
}

// Deep chains must survive intact and in order.
func TestShellBags_LongChainIsReconstructedInOrder(t *testing.T) {
	levels := [][]byte{sbgen.List(sbgen.Root(thisPC))}
	var want []string
	want = append(want, "This PC / My Computer")
	for i := 0; i < 24; i++ {
		name := "level" + itoa(i)
		levels = append(levels, dirItem(name))
		want = append(want, name)
	}
	events := shellBagEvents(t, bagTree(t, levels))
	full := strings.Join(want, `\`)
	if !hasPath(events, full) {
		t.Errorf("the deep chain was not reconstructed:\n got %q", pathsOf(events))
	}
}

// The same bytes must reconstruct the same way every time.
func TestShellBags_ReconstructionIsDeterministic(t *testing.T) {
	p := bagTree(t, [][]byte{
		sbgen.List(sbgen.Root(thisPC)),
		sbgen.List(sbgen.KnownFolder(picturesGUID)),
		dirItem("Contact"),
	})
	var first string
	for i := 0; i < 3; i++ {
		got := strings.Join(pathsOf(shellBagEvents(t, p)), "\n")
		if i == 0 {
			first = got
			continue
		}
		if got != first {
			t.Fatalf("run %d differs:\n%s\n---\n%s", i, got, first)
		}
	}
}

// Provenance: every event must name the BagMRU key it came from, and
// carry the raw record.
func TestShellBags_ProvenanceNamesTheNode(t *testing.T) {
	p := bagTree(t, [][]byte{
		sbgen.List(sbgen.Root(thisPC)),
		sbgen.List(sbgen.KnownFolder(picturesGUID)),
		dirItem("Contact"),
	})
	res, err := parser.New().Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for i, e := range res.Events {
		if e.ArtifactType != model.ArtifactShellBags ||
			e.Extra["shell_item_name"] != "Contact" {
			continue
		}
		found = true
		if !strings.Contains(e.RegistryPath, "BagMRU") {
			t.Errorf("registry path %q does not name the BagMRU node", e.RegistryPath)
		}
		var raw map[string]any
		if err := json.Unmarshal([]byte(res.Raw[i].Raw), &raw); err != nil {
			t.Fatalf("raw record is not JSON: %v", err)
		}
		segs, _ := raw["path_segments"].([]any)
		if len(segs) != 3 {
			t.Errorf("raw path_segments = %v, want 3 levels", segs)
		}
		if raw["parent_path"] != `This PC / My Computer\Pictures` {
			t.Errorf("raw parent_path = %v", raw["parent_path"])
		}
		// ShellBags meaning must not drift.
		if !strings.Contains(e.Extra["evidence_meaning"], "not evidence that anything was executed") {
			t.Errorf("the ShellBags meaning changed: %q", e.Extra["evidence_meaning"])
		}
		if e.EventType != model.EventShellBagNavigation {
			t.Errorf("event type = %q", e.EventType)
		}
	}
	if !found {
		t.Fatal("no event for the leaf folder")
	}
}
