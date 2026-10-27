package api

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"tracefall/internal/regf/regfgen"
)

// Registry transaction-log companions on a disk image.
//
// The image testdata/images/companions.dd.gz is written by mkntfs + ntfs-3g +
// sgdisk (not by Tracefall) from the hives and logs built below with regfgen
// (documented REGF/HvLE layout, its own Marvin32). Everything is synthetic.
// Regenerate with:
//
//	TRACEFALL_WRITE_COMPANION_FIXTURE=1 go test ./internal/api -run TestCompanionFixture_Generate
//
// companions.manifest.json holds the SHA-256 of every file as read back from the
// MOUNTED volume, never from Tracefall.

const (
	companionImage    = "companions.dd.gz"
	companionManifest = "companions.manifest.json"
	cfgDir            = "Windows/System32/config/"
)

type companionFile struct {
	vol  int // 1-based partition number
	path string
	data []byte
}

// hiveStage builds the same hive at three points in time. Stage 0 is what a
// live-collected primary file holds; stage 1 and 2 are later states that exist
// only in transaction logs. Padding keys make the later states differ from the
// earlier one in several 4 KiB pages, as a real change of this size would.
func runHive(root, embedded string, path []string, stage int) []byte {
	leaf := regfgen.NewKey(path[len(path)-1]).WithValues(regfgen.StringValue("Base", `C:\Windows\System32\base.exe`))
	if stage >= 1 {
		leaf.Values = append(leaf.Values, regfgen.StringValue("Mid", `C:\Users\Public\mid.exe`))
	}
	if stage >= 2 {
		leaf.Values = append(leaf.Values, regfgen.StringValue("Final", `C:\Users\Public\final.exe`))
	}
	cur := leaf
	for i := len(path) - 2; i >= 0; i-- {
		cur = regfgen.NewKey(path[i], cur)
	}
	top := []*regfgen.Key{cur}
	if stage >= 1 {
		pads := regfgen.NewKey("Pads")
		for _, n := range []string{"P1", "P2", "P3", "P4"} {
			pads.Subkeys = append(pads.Subkeys, regfgen.NewKey(n).WithValues(regfgen.BinaryValue("blob", make([]byte, 3000))))
		}
		top = append(top, pads)
	}
	return regfgen.Build(embedded, regfgen.NewKey(root, top...))
}

var runPath = []string{"Microsoft", "Windows", "CurrentVersion", "Run"}

func softwareHive(stage int) []byte {
	return runHive("CMI-CreateHive{SOFTWARE}", `\REGISTRY\MACHINE\SOFTWARE`, runPath, stage)
}

func ntuserHive(user string, stage int) []byte {
	return runHive("CMI-CreateHive{NTUSER}", `\??\C:\Users\`+user+`\NTUSER.DAT`, append([]string{"Software"}, runPath...), stage)
}

func plainHive(name string, stage int) []byte {
	return runHive("CMI-CreateHive{"+name+"}", name, []string{"Data", "Entries"}, stage)
}

func systemHive(stage int) []byte {
	svcs := []*regfgen.Key{regfgen.NewKey("SvcBase").WithValues(regfgen.ExpandStringValue("ImagePath", `C:\Windows\System32\base.exe`), regfgen.DWordValue("Start", 2))}
	if stage >= 1 {
		svcs = append(svcs, regfgen.NewKey("SvcMid").WithValues(regfgen.ExpandStringValue("ImagePath", `C:\Users\Public\mid.exe`), regfgen.DWordValue("Start", 2)))
		for _, n := range []string{"P1", "P2", "P3", "P4"} {
			svcs = append(svcs, regfgen.NewKey(n).WithValues(regfgen.BinaryValue("blob", make([]byte, 3000))))
		}
	}
	if stage >= 2 {
		svcs = append(svcs, regfgen.NewKey("SvcFinal").WithValues(regfgen.ExpandStringValue("ImagePath", `C:\Users\Public\final.exe`), regfgen.DWordValue("Start", 2)))
	}
	cn := regfgen.NewKey("ComputerName", regfgen.NewKey("ComputerName").WithValues(regfgen.StringValue("ComputerName", "HOST01")))
	cs1 := regfgen.NewKey("ControlSet001", regfgen.NewKey("Control", cn), regfgen.NewKey("Services", svcs...))
	root := regfgen.NewKey("CMI-CreateHive{SYSTEM}", cs1, regfgen.NewKey("Select").WithValues(regfgen.DWordValue("Current", 1)))
	return regfgen.Build(`\REGISTRY\MACHINE\SYSTEM`, root)
}

// companionFiles is the content of the fixture. Comments say what each file is
// there to prove.
func companionFiles() []companionFile {
	sys0, sys1, sys2 := systemHive(0), systemHive(1), systemHive(2)
	sw0, sw2 := softwareHive(0), softwareHive(2)
	nu0, nu2 := ntuserHive("alice", 0), ntuserHive("alice", 2)
	sam0, sam2 := plainHive("SAM", 0), plainHive("SAM", 2)
	sec0, sec2 := plainHive("SECURITY", 0), plainHive("SECURITY", 2)
	def0, def2 := plainHive("DEFAULT", 0), plainHive("DEFAULT", 2)
	uc0, uc2 := plainHive("UsrClass", 0), plainHive("UsrClass", 2)
	am0, am2 := plainHive("Amcache", 0), plainHive("Amcache", 2)
	bob0, bob2 := ntuserHive("bob", 0), ntuserHive("bob", 2)
	rb0 := runHive("CMI-CreateHive{SOFTWARE}", `\REGISTRY\MACHINE\SOFTWARE-RegBack`, runPath, 0)
	dirty := func(h []byte) []byte { return regfgen.WithSequences(h, 3, 2) }
	return []companionFile{
		// Two logs chained: LOG1 holds SvcMid, LOG2 continues with SvcFinal.
		{1, cfgDir + "SYSTEM", regfgen.WithSequences(sys0, 4, 3)},
		{1, cfgDir + "SYSTEM.LOG1", regfgen.NewFormatLog(sys0, sys1, 3)},
		{1, cfgDir + "SYSTEM.LOG2", regfgen.NewFormatLog(sys1, sys2, 4)},
		// Lower-case log name; the change (Mid, Final) exists only in the log.
		{1, cfgDir + "SOFTWARE", dirty(sw0)},
		{1, cfgDir + "SOFTWARE.log1", regfgen.NewFormatLog(sw0, sw2, 3)},
		// Dirty, and its only log is on ANOTHER volume (vol2 SAM.LOG1): never attached.
		{1, cfgDir + "SAM", dirty(sam0)},
		{2, cfgDir + "SAM.LOG1", regfgen.NewFormatLog(sam0, sam2, 3)},
		// Clean primary with a log: the log is a companion, the state stays clean.
		{1, cfgDir + "SECURITY", sec0},
		{1, cfgDir + "SECURITY.LOG1", regfgen.NewFormatLog(sec0, sec2, 3)},
		// Dirty with a valid log (the oversize test lowers the cap below its size).
		{1, cfgDir + "DEFAULT", dirty(def0)},
		{1, cfgDir + "DEFAULT.LOG1", regfgen.NewFormatLog(def0, def2, 3)},
		// A copy in a sub-directory whose logs sit in the parent: never attached.
		{1, cfgDir + "RegBack/SOFTWARE", dirty(rb0)},
		// Per-user hives.
		{1, "Users/alice/NTUSER.DAT", dirty(nu0)},
		{1, "Users/alice/NTUSER.DAT.LOG1", regfgen.NewFormatLog(nu0, nu2, 3)},
		{1, "Users/alice/AppData/Local/Microsoft/Windows/UsrClass.dat", dirty(uc0)},
		{1, "Users/alice/AppData/Local/Microsoft/Windows/UsrClass.dat.LOG1", regfgen.NewFormatLog(uc0, uc2, 3)},
		{1, "Windows/AppCompat/Programs/Amcache.hve", dirty(am0)},
		{1, "Windows/AppCompat/Programs/Amcache.hve.LOG1", regfgen.NewFormatLog(am0, am2, 3)},
		// bob's hive is dirty and has no log; carol's directory holds a log with
		// bob's hive name that fits it, but carol has no such hive: never attached.
		{1, "Users/bob/NTUSER.DAT", dirty(bob0)},
		{1, "Users/carol/NTUSER.DAT.LOG1", regfgen.NewFormatLog(bob0, bob2, 3)},
		// A second volume with its own clean hive, so the image is not one volume.
		{2, "Users/zed/NTUSER.DAT", ntuserHive("zed", 0)},
	}
}

type companionTruth struct {
	Files map[string]string `json:"files"` // "volN/<path>" -> sha256 read back from the mounted volume
}

func loadCompanionTruth(t *testing.T) companionTruth {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(imageFixtures, companionManifest))
	if err != nil {
		t.Fatal(err)
	}
	var m companionTruth
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// TestCompanionFixture_Generate rewrites the committed fixture. It is skipped
// unless asked for, and needs mkntfs, ntfs-3g, fusermount3 and sgdisk.
func TestCompanionFixture_Generate(t *testing.T) {
	if os.Getenv("TRACEFALL_WRITE_COMPANION_FIXTURE") == "" {
		t.Skip("set TRACEFALL_WRITE_COMPANION_FIXTURE=1 to rewrite testdata/images/" + companionImage)
	}
	const volBytes = 8 << 20
	tmp := t.TempDir()
	truth := companionTruth{Files: map[string]string{}}
	var volImgs []string
	for v := 1; v <= 2; v++ {
		img := filepath.Join(tmp, fmt.Sprintf("vol%d.img", v))
		f, err := os.Create(img)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(volBytes); err != nil {
			t.Fatal(err)
		}
		f.Close()
		run := func(name string, args ...string) {
			if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
				t.Fatalf("%s %v: %v\n%s", name, args, err, out)
			}
		}
		run("mkntfs", "-F", "-Q", "-q", "-L", fmt.Sprintf("VOL%d", v), "-s", "512", "-c", "4096", img)
		mnt := filepath.Join(tmp, fmt.Sprintf("mnt%d", v))
		if err := os.Mkdir(mnt, 0o700); err != nil {
			t.Fatal(err)
		}
		run("ntfs-3g", "-o", "rw,streams_interface=windows", img, mnt)
		for _, cf := range companionFiles() {
			if cf.vol != v {
				continue
			}
			full := filepath.Join(mnt, filepath.FromSlash(cf.path))
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, cf.data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		for _, cf := range companionFiles() {
			if cf.vol != v {
				continue
			}
			b, err := os.ReadFile(filepath.Join(mnt, filepath.FromSlash(cf.path)))
			if err != nil {
				t.Fatal(err)
			}
			truth.Files[fmt.Sprintf("vol%d/%s", v, cf.path)] = sha256Hex(b)
		}
		run("fusermount3", "-u", mnt)
		volImgs = append(volImgs, img)
	}
	disk := filepath.Join(tmp, "disk.dd")
	f, err := os.Create(disk)
	if err != nil {
		t.Fatal(err)
	}
	const sector = 512
	if err := f.Truncate(2048*sector + 2*volBytes + 1<<20); err != nil {
		t.Fatal(err)
	}
	f.Close()
	vs := int64(volBytes / sector)
	if out, err := exec.Command("sgdisk", "-o",
		"-n", fmt.Sprintf("1:2048:%d", 2048+vs-1), "-t", "1:0700",
		"-n", fmt.Sprintf("2:%d:%d", 2048+vs, 2048+2*vs-1), "-t", "2:0700", disk).CombinedOutput(); err != nil {
		t.Fatalf("sgdisk: %v\n%s", err, out)
	}
	df, err := os.OpenFile(disk, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i, img := range volImgs {
		src, err := os.Open(img)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := df.Seek(2048*sector+int64(i)*volBytes, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(df, src); err != nil {
			t.Fatal(err)
		}
		src.Close()
	}
	df.Close()
	in, err := os.Open(disk)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.Create(filepath.Join(imageFixtures, companionImage))
	if err != nil {
		t.Fatal(err)
	}
	zw, _ := gzip.NewWriterLevel(out, gzip.BestCompression)
	if _, err := io.Copy(zw, in); err != nil {
		t.Fatal(err)
	}
	zw.Close()
	out.Close()
	mb, _ := json.MarshalIndent(truth, "", " ")
	if err := os.WriteFile(filepath.Join(imageFixtures, companionManifest), mb, 0o644); err != nil {
		t.Fatal(err)
	}
}
