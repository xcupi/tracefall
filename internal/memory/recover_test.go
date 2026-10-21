package memory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fsRow(name string, off float64) map[string]any {
	return map[string]any{"Name": name, "Offset": off}
}

func TestRecoveryCandidates_PickRunnableFilesOutsideRoutineLocations(t *testing.T) {
	rows := []map[string]any{
		fsRow(`\Windows\System32\kernel32.dll`, 1),   // routine
		fsRow(`\Program Files\App\app.exe`, 2),       // routine
		fsRow(`\Users\alice\Documents\plan.docx`, 3), // not runnable
		fsRow("\ueba8\u765c\uffff", 4),               // garbage
		fsRow(`\Tools\b.exe`, 5),
		fsRow(`\Users\alice\Downloads\Z.EXE`, 6),
		fsRow(`\users\alice\downloads\z.exe`, 7), // another copy of the same file
		fsRow(`\Users\alice\AppData\Local\Temp\a.dll`, 8),
		fsRow(`\Tools\c.ps1`, 9),
	}
	got := recoveryCandidates(rows, 10)
	var names []string
	for _, c := range got {
		names = append(names, c.name)
	}
	want := []string{`\Users\alice\AppData\Local\Temp\a.dll`, `\Users\alice\Downloads\Z.EXE`, `\Tools\b.exe`, `\Tools\c.ps1`}
	if strings.Join(names, "|") != strings.Join(want, "|") {
		t.Fatalf("got %v\nwant %v", names, want)
	}
	if len(got[1].offsets) != 2 || got[1].offsets[0] != 6 || got[1].offsets[1] != 7 {
		t.Errorf("both copies' offsets are kept, in order: %v", got[1].offsets)
	}
	if got := recoveryCandidates(rows, 2); len(got) != 2 {
		t.Errorf("limit: %d", len(got))
	}
}

func TestRecoveryCandidates_OffsetsPerNameAreBounded(t *testing.T) {
	var rows []map[string]any
	for i := 0; i < 20; i++ {
		rows = append(rows, fsRow(`\Tools\x.exe`, float64(100+i)))
	}
	if got := recoveryCandidates(rows, 5); len(got) != 1 || len(got[0].offsets) != offsetsPerName {
		t.Fatalf("%+v", got)
	}
}

func hexSum(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func recoverDoc() map[string]any {
	return map[string]any{
		"dump:100": []any{map[string]any{"cache": "DataSectionObject", "result": "file.0x1.0x2.DataSectionObject.a.exe.dat", "content": "MZ" + strings.Repeat("A", 200)}},
		"dump:200": []any{}, // not cached
		"dump:300": map[string]any{"error": "boom"},
		"dump:400": []any{}, // first copy is empty
		"dump:401": []any{map[string]any{"cache": "ImageSectionObject", "result": "file.0x1.0x2.ImageSectionObject.d.exe.img", "content": "MZ" + strings.Repeat("B", 50)}},
		"dump:500": []any{map[string]any{"cache": "DataSectionObject", "result": "../../escape.dat", "content": "MZ"}},
		"dump:700": []any{map[string]any{"cache": "ImageSectionObject", "result": "file.sparse.img", "content": "MZ" + strings.Repeat("\x00", 9000)}},
		"dump:600": []any{map[string]any{"cache": "DataSectionObject", "result": "file.big.dat", "content": strings.Repeat("Z", 5000)}},
	}
}

func availableAll() map[string]bool { return map[string]bool{dumpPlugin: true} }

func scanRows() []map[string]any {
	return []map[string]any{
		fsRow(`\Tools\a.exe`, 100), fsRow(`\Tools\empty.exe`, 200), fsRow(`\Tools\bad.exe`, 300),
		fsRow(`\Tools\d.exe`, 400), fsRow(`\Tools\d.exe`, 401), fsRow(`\Tools\esc.exe`, 500), fsRow(`\Tools\big.exe`, 600),
	}
}

func TestRecover_ReadsBackInspectsAndForgetsTheBytes(t *testing.T) {
	r, img := fakeImage(t, recoverDoc())
	r.cfg.DumpMaxBytes = 1000
	got, note := r.Recover(context.Background(), img, scanRows(), availableAll(), nil)
	if note != "" {
		t.Fatalf("note %q", note)
	}
	by := map[string]RecoveredFile{}
	for _, f := range got {
		by[f.Name] = f
	}
	a := by[`\Tools\a.exe`]
	if a.Status != RecoveredOK || len(a.Parts) != 1 || a.Parts[0].Cache != "DataSectionObject" || a.Parts[0].Report.SHA256 != hexSum("MZ"+strings.Repeat("A", 200)) {
		t.Errorf("recovered: %+v", a)
	}
	if a.Parts[0].Report.Type != "Windows executable (MZ)" {
		t.Errorf("type %q", a.Parts[0].Report.Type)
	}
	if e := by[`\Tools\empty.exe`]; e.Status != RecoveredNone {
		t.Errorf("an uncached file is not an error: %+v", e)
	}
	if b := by[`\Tools\bad.exe`]; b.Status != RecoveredFailed || !strings.Contains(b.Error, "boom") {
		t.Errorf("failure is recorded with its reason: %+v", b)
	}
	if d := by[`\Tools\d.exe`]; d.Status != RecoveredOK || d.Tried != 2 || d.FileObject != 401 {
		t.Errorf("the second copy of the object is tried when the first is empty: %+v", d)
	}
	// A result name with ../ is reduced to its last element and only ever read
	// from inside the private directory.
	if e := by[`\Tools\esc.exe`]; e.Status != RecoveredOK || e.Parts[0].Size != 2 {
		t.Errorf("a result name that tries to leave the directory is confined to it: %+v", e)
	}
	if b := by[`\Tools\big.exe`]; b.Status != RecoveredTooLarge || b.Parts[0].Report.SHA256 != "" || b.Parts[0].Size != 5000 {
		t.Errorf("a file over the limit is sized, not read: %+v", b)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(r.cfg.CacheDir), "escape.dat")); err == nil {
		t.Error("something escaped the dump directory")
	}
	left, _ := filepath.Glob(filepath.Join(r.cfg.CacheDir, "dump-*"))
	if len(left) != 0 {
		t.Errorf("dump directories left behind: %v", left)
	}
}

func TestRecover_CountsThePagesThatWereNotInMemory(t *testing.T) {
	r, img := fakeImage(t, recoverDoc())
	got, _ := r.Recover(context.Background(), img, []map[string]any{fsRow(`\Tools\sparse.exe`, 700)}, availableAll(), nil)
	if len(got) != 1 || got[0].Status != RecoveredOK {
		t.Fatalf("%+v", got)
	}
	p := got[0].Parts[0]
	if p.TotalPages != 3 || p.ZeroPages != 2 {
		t.Errorf("a 9002-byte file is 3 pages and the last two are blank: %d of %d", p.ZeroPages, p.TotalPages)
	}
}

func TestRecoveryCandidates_BrowserCachesComeLast(t *testing.T) {
	got := recoveryCandidates([]map[string]any{
		fsRow(`\Users\a\AppData\Local\Packages\x\AC\#!001\MicrosoftEdge\Cache\H1\app[1].js`, 1),
		fsRow(`\Tools\b.exe`, 2),
	}, 5)
	if len(got) != 2 || got[0].name != `\Tools\b.exe` {
		t.Fatalf("%+v", got)
	}
}

func TestRecover_SaysWhyItDidNothing(t *testing.T) {
	r, img := fakeImage(t, recoverDoc())
	ctx := context.Background()
	if _, note := r.Recover(ctx, img, scanRows(), map[string]bool{}, nil); !strings.Contains(note, "does not offer") {
		t.Errorf("plugin missing: %q", note)
	}
	if _, note := r.Recover(ctx, img, []map[string]any{fsRow(`\Windows\System32\a.dll`, 1)}, availableAll(), nil); !strings.Contains(note, "no runnable file") {
		t.Errorf("nothing qualified: %q", note)
	}
	r.cfg.DumpMaxFiles = -1
	if got, note := r.Recover(ctx, img, scanRows(), availableAll(), nil); got != nil || !strings.Contains(note, "turned off") {
		t.Errorf("off: %v %q", got, note)
	}
}

func TestRunInto_RefusesAnOutputDirectoryOutsideTheCache(t *testing.T) {
	r, img := fakeImage(t, recoverDoc())
	if _, _, err := r.RunInto(context.Background(), img, t.TempDir(), dumpPlugin, "--virtaddr", "100"); err == nil {
		t.Fatal("the sandbox can only write to the cache directory; anything else must be refused")
	}
}

func TestCollect_RecoversFilesFoundByFilescan(t *testing.T) {
	doc := fullDoc()
	doc["windows.filescan.FileScan"] = rows(map[string]any{"Name": `\Tools\a.exe`, "Offset": 100})
	for k, v := range recoverDoc() {
		doc[k] = v
	}
	r, img := fakeImage(t, doc)
	a, err := Collect(context.Background(), r, img, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Recovered) != 1 || a.Recovered[0].Status != RecoveredOK || a.RecoveryNote != "" {
		t.Fatalf("%+v / %q", a.Recovered, a.RecoveryNote)
	}
}
