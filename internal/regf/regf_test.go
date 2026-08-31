package regf_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tracefall/internal/regf"
	"tracefall/internal/regf/regfgen"
)

// writeHive materializes a synthetic hive on disk and returns its path.
func writeHive(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hive.dat")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

var testWrite = time.Date(2026, 1, 15, 9, 30, 0, 0, time.UTC)

// sampleHive is a small NTUSER-shaped hive used by several tests.
func sampleHive() []byte {
	run := regfgen.NewKey("Run").WithLastWrite(testWrite).WithValues(
		regfgen.StringValue("AcmeUpdater", `C:\Users\jdoe\AppData\Roaming\acme\updater.exe`),
		regfgen.StringValue("OneDrive", `C:\Program Files\Microsoft OneDrive\OneDrive.exe /background`),
	)
	runOnce := regfgen.NewKey("RunOnce").WithLastWrite(testWrite)
	version := regfgen.NewKey("CurrentVersion", run, runOnce)
	windows := regfgen.NewKey("Windows", version)
	microsoft := regfgen.NewKey("Microsoft", windows)
	software := regfgen.NewKey("Software", microsoft)
	root := regfgen.NewKey("CMI-CreateHive{TEST}", software).WithLastWrite(testWrite)
	return regfgen.Build(`\??\C:\Users\jdoe\NTUSER.DAT`, root)
}

func TestSniff(t *testing.T) {
	if !regf.Sniff([]byte("regf....")) {
		t.Error("Sniff rejected a valid REGF signature")
	}
	if regf.Sniff([]byte("ElfFile\x00")) {
		t.Error("Sniff accepted an EVTX file as a hive")
	}
	if regf.Sniff([]byte("re")) {
		t.Error("Sniff accepted a too-short header")
	}
}

func TestOpen_ReadsBaseBlockFacts(t *testing.T) {
	h, err := regf.Open(writeHive(t, sampleHive()), regf.Limits{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer h.Close()

	if h.MajorVersion() != 1 || h.MinorVersion() != 5 {
		t.Errorf("version = %d.%d, want 1.5", h.MajorVersion(), h.MinorVersion())
	}
	if got, want := h.EmbeddedName(), `\??\C:\Users\jdoe\NTUSER.DAT`; got != want {
		t.Errorf("embedded name = %q, want %q", got, want)
	}
	if !h.LastModified().Equal(testWrite) {
		t.Errorf("last modified = %v, want %v", h.LastModified(), testWrite)
	}
}

func TestOpenKey_ResolvesNestedPathCaseInsensitively(t *testing.T) {
	h, err := regf.Open(writeHive(t, sampleHive()), regf.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	// Windows registry paths are case-insensitive; so is this lookup.
	k, err := h.OpenKey(`software\MICROSOFT\windows\CurrentVersion\Run`)
	if err != nil {
		t.Fatalf("OpenKey: %v", err)
	}
	if k.Name != "Run" {
		t.Errorf("key name = %q, want Run", k.Name)
	}
	if !k.LastWrite.Equal(testWrite) {
		t.Errorf("last write = %v, want %v", k.LastWrite, testWrite)
	}
	if len(k.Values) != 2 {
		t.Fatalf("values = %d, want 2: %+v", len(k.Values), k.Values)
	}

	byName := map[string]regf.Value{}
	for _, v := range k.Values {
		byName[v.Name] = v
	}
	got := byName["AcmeUpdater"]
	if got.TypeName() != "REG_SZ" {
		t.Errorf("AcmeUpdater type = %s, want REG_SZ", got.TypeName())
	}
	if want := `C:\Users\jdoe\AppData\Roaming\acme\updater.exe`; got.String() != want {
		t.Errorf("AcmeUpdater = %q, want %q", got.String(), want)
	}
}

func TestOpenKey_MissingKeyIsAnError(t *testing.T) {
	h, err := regf.Open(writeHive(t, sampleHive()), regf.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	if _, err := h.OpenKey(`Software\Microsoft\NoSuchKey`); err == nil {
		t.Error("expected an error for a key that does not exist")
	}
}

func TestValueTypes_DecodeCorrectly(t *testing.T) {
	k := regfgen.NewKey("Types").WithValues(
		regfgen.StringValue("Str", "hello"),
		regfgen.ExpandStringValue("Expand", `%SystemRoot%\system32\svchost.exe`),
		regfgen.DWordValue("Dword", 4242),
		regfgen.MultiStringValue("Multi", []string{"alpha", "beta", "gamma"}),
		regfgen.BinaryValue("Bin", []byte{0xde, 0xad, 0xbe, 0xef, 0x01}),
	)
	root := regfgen.NewKey("Root", k)
	h, err := regf.Open(writeHive(t, regfgen.Build("TYPES", root)), regf.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	got, err := h.OpenKey("Types")
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]regf.Value{}
	for _, v := range got.Values {
		values[v.Name] = v
	}

	cases := []struct{ name, wantType, wantString string }{
		{"Str", "REG_SZ", "hello"},
		{"Expand", "REG_EXPAND_SZ", `%SystemRoot%\system32\svchost.exe`},
		{"Dword", "REG_DWORD", "4242"},
		{"Multi", "REG_MULTI_SZ", "alpha; beta; gamma"},
		{"Bin", "REG_BINARY", "deadbeef01"},
	}
	for _, tc := range cases {
		v, ok := values[tc.name]
		if !ok {
			t.Errorf("value %q missing", tc.name)
			continue
		}
		if v.TypeName() != tc.wantType {
			t.Errorf("%s type = %s, want %s", tc.name, v.TypeName(), tc.wantType)
		}
		if v.String() != tc.wantString {
			t.Errorf("%s = %q, want %q", tc.name, v.String(), tc.wantString)
		}
	}
}

// A DWORD is 4 bytes, which the format stores INSIDE the offset field
// rather than in its own cell. Getting that convention wrong yields a
// plausible-looking but completely wrong number, so it gets its own test.
func TestResidentValueData(t *testing.T) {
	root := regfgen.NewKey("Root", regfgen.NewKey("K").WithValues(regfgen.DWordValue("Start", 2)))
	h, err := regf.Open(writeHive(t, regfgen.Build("SYSTEM", root)), regf.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	k, err := h.OpenKey("K")
	if err != nil {
		t.Fatal(err)
	}
	if len(k.Values) != 1 || k.Values[0].String() != "2" {
		t.Errorf("resident DWORD decoded as %+v, want 2", k.Values)
	}
}

func TestWalk_VisitsEveryKeyWithFullPaths(t *testing.T) {
	h, err := regf.Open(writeHive(t, sampleHive()), regf.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	seen := map[string]bool{}
	stats, err := h.Walk(func(k regf.Key) error {
		seen[k.Path] = true
		return nil
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	for _, want := range []string{
		"",
		"Software",
		`Software\Microsoft`,
		`Software\Microsoft\Windows`,
		`Software\Microsoft\Windows\CurrentVersion`,
		`Software\Microsoft\Windows\CurrentVersion\Run`,
		`Software\Microsoft\Windows\CurrentVersion\RunOnce`,
	} {
		if !seen[want] {
			t.Errorf("Walk did not visit %q (saw %v)", want, keys(seen))
		}
	}
	if stats.KeysVisited != 7 {
		t.Errorf("KeysVisited = %d, want 7", stats.KeysVisited)
	}
	if stats.LimitReached {
		t.Error("LimitReached set on a 7-key hive")
	}
}

func TestSubkeys(t *testing.T) {
	h, err := regf.Open(writeHive(t, sampleHive()), regf.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	subs, err := h.Subkeys(`Software\Microsoft\Windows\CurrentVersion`)
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 2 {
		t.Fatalf("subkeys = %v, want Run and RunOnce", subs)
	}
}

// ---------- malformed input: must fail safely, never panic or hang ----------

func TestOpen_RejectsMalformedHives(t *testing.T) {
	valid := sampleHive()

	cases := []struct {
		name string
		data []byte
		want error
	}{
		{"bad signature", regfgen.CorruptSignature(valid), regf.ErrNotHive},
		{"empty file", nil, regf.ErrCorrupt},
		{"shorter than the header", make([]byte, 100), regf.ErrCorrupt},
		{"truncated before bins data", regfgen.Truncate(valid, 2048), regf.ErrCorrupt},
		{"transaction log, not a hive", regfgen.MakeTransactionLog(valid), regf.ErrNotHive},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := regf.Open(writeHive(t, tc.data), regf.Limits{})
			if err == nil {
				t.Fatal("expected an error")
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("error = %v, want one wrapping %v", err, tc.want)
			}
		})
	}
}

func TestOpen_RejectsOversizedHive(t *testing.T) {
	_, err := regf.Open(writeHive(t, sampleHive()), regf.Limits{MaxFileBytes: 1024})
	if !errors.Is(err, regf.ErrLimitExceeded) {
		t.Errorf("error = %v, want ErrLimitExceeded", err)
	}
}

// An offset pointing outside the hive is the canonical hostile input:
// the reader must reject it rather than reading arbitrary memory or
// looping.
func TestRootOffsetOutsideHiveIsRejected(t *testing.T) {
	h, err := regf.Open(writeHive(t, regfgen.CorruptRootOffset(sampleHive())), regf.Limits{})
	if err != nil {
		return // rejected at Open, which is fine
	}
	defer h.Close()
	if _, err := h.Root(); !errors.Is(err, regf.ErrCorrupt) {
		t.Errorf("Root() error = %v, want ErrCorrupt", err)
	}
}

// A subkey list pointing back at an ancestor must terminate. Without the
// visited-set this test hangs rather than fails, so it is bounded by the
// test timeout deliberately.
func TestWalk_CycleTerminates(t *testing.T) {
	h, err := regf.Open(writeHive(t, regfgen.CycleSubkeyList(sampleHive())), regf.Limits{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer h.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = h.Walk(func(regf.Key) error { return nil })
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Walk did not terminate on a hive with a cyclic subkey list")
	}
}

func TestWalk_RespectsKeyLimit(t *testing.T) {
	h, err := regf.Open(writeHive(t, sampleHive()), regf.Limits{MaxKeys: 3})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	stats, err := h.Walk(func(regf.Key) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if stats.KeysVisited != 3 || !stats.LimitReached {
		t.Errorf("stats = %+v, want 3 keys visited and LimitReached", stats)
	}
}

func TestWalk_RespectsDepthLimit(t *testing.T) {
	h, err := regf.Open(writeHive(t, sampleHive()), regf.Limits{MaxDepth: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	var deepest int
	stats, err := h.Walk(func(k regf.Key) error {
		if d := depthOf(k.Path); d > deepest {
			deepest = d
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if deepest > 2 {
		t.Errorf("walked to depth %d despite MaxDepth=2", deepest)
	}
	if !stats.LimitReached {
		t.Error("LimitReached not set despite the depth limit stopping the walk")
	}
}

// Every byte of a hive is attacker-controlled. Rather than enumerate
// specific corruptions, flip bytes throughout the structure and require
// that the reader always either succeeds or returns an error -- never
// panics, and never runs away.
func TestFuzzedHivesNeverPanic(t *testing.T) {
	valid := sampleHive()
	for offset := 0; offset < len(valid); offset += 37 {
		for _, b := range []byte{0x00, 0xff, 0x7f} {
			corrupt := append([]byte(nil), valid...)
			corrupt[offset] = b

			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("panic on byte %d set to %#x: %v", offset, b, r)
					}
				}()
				h, err := regf.Open(writeHive(t, corrupt), regf.Limits{MaxKeys: 1000})
				if err != nil {
					return
				}
				defer h.Close()
				_, _ = h.Walk(func(regf.Key) error { return nil })
			}()
		}
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func depthOf(path string) int {
	if path == "" {
		return 0
	}
	n := 1
	for _, c := range path {
		if c == '\\' {
			n++
		}
	}
	return n
}
