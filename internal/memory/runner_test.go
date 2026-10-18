package memory

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeVol writes a stand-in for the `vol` executable. What it does is
// chosen by the CONTENT of the image file passed with -f, because the
// sandbox deliberately clears the environment, so nothing else reaches it.
//
//	rows        prints a JSON result, after the blank line vol3 emits
//	sleep       sleeps (with a child) far past any test timeout
//	big         prints more output than the cap allows
//	nosymbols   fails the way vol3 does without a symbol table
//	garbage     prints something that is not JSON
//	probe       reports what the sandbox let it do
const fakeVolScript = `#!/bin/sh
# argument parsing: find -f IMAGE and the final plugin name
img=""; cache=""; prev=""; for a in "$@"; do
  if [ "$prev" = "-f" ]; then img="$a"; fi
  if [ "$prev" = "--cache-path" ]; then cache="$a"; fi
  prev="$a"
done
case "$1" in
  --version) echo "Volatility 3 Framework 2.99.0"; exit 0;;
  -h) cat <<'EOF'
Volatility 3 Framework 2.99.0
usage: vol [-h]
    plugin:
    windows.info.Info   Show OS & kernel details
    windows.malware.malfind.Malfind
    windows.pslist.PsList
    windows.psscan.PsScan
EOF
  exit 0;;
esac
mode=$(head -n1 "$img" 2>/dev/null)
marker=$(sed -n 2p "$img" 2>/dev/null)
imgdir=$(dirname "$img")
echo "$@" > "$cache/last-args" 2>/dev/null
case "$mode" in
  rows) echo; echo '[{"PID": 4, "ImageFileName": "System", "__children": []}]'; exit 0;;
  sleep) sleep 600 & sleep 600; exit 0;;
  big) echo; yes 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'; exit 0;;
  nosymbols) echo "Unsatisfied requirement plugins.Info.kernel.symbol_table_name: A symbol table requirement was not fulfilled" >&2; exit 1;;
  garbage) echo; echo 'this is not json'; exit 0;;
  probe)
    net=blocked; (exec 3<>/dev/tcp/127.0.0.1/9 ) 2>/dev/null && net=open
    cat /proc/net/dev 2>/dev/null | grep -qE '^ *(eth|en|wl)' && net=has-interface
    home=hidden; [ -e "$marker" ] && home=visible
    wr=denied; (echo x > "$imgdir/should-not-exist") 2>/dev/null && wr=allowed
    imgw=denied; (echo x >> "$img") 2>/dev/null && imgw=allowed
    cw=denied; (echo x > "$cache/cache-write") 2>/dev/null && cw=allowed
    envn=$(env | grep -c 'SECRET_TOKEN')
    echo; echo "[{\"net\": \"$net\", \"home\": \"$home\", \"write_beside_image\": \"$wr\", \"write_image\": \"$imgw\", \"write_cache\": \"$cw\", \"secret_env\": $envn}]"
    exit 0;;
esac
echo "unknown mode $mode" >&2; exit 2
`

func newFake(t *testing.T) (volPath, imgDir string) {
	t.Helper()
	dir := t.TempDir()
	volPath = filepath.Join(dir, "vol")
	if err := os.WriteFile(volPath, []byte(fakeVolScript), 0o755); err != nil {
		t.Fatal(err)
	}
	imgDir = t.TempDir()
	return volPath, imgDir
}

func writeImage(t *testing.T, dir, mode string) string {
	t.Helper()
	p := filepath.Join(dir, "mem.raw")
	if err := os.WriteFile(p, []byte(mode), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func newRunner(t *testing.T, vol string, mut func(*Config)) *Runner {
	t.Helper()
	cfg := Config{Vol: vol, CacheDir: t.TempDir(), Timeout: 20 * time.Second, SymbolDirs: []string{t.TempDir()}}
	if mut != nil {
		mut(&cfg)
	}
	r, err := NewRunner(cfg)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	return r
}

func needSandbox(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not installed")
	}
}

func TestRun_ReturnsTheRowsVolatilityPrinted(t *testing.T) {
	vol, dir := newFake(t)
	r := newRunner(t, vol, nil)
	out, info, err := r.Run(context.Background(), writeImage(t, dir, "rows"), "windows.pslist.PsList")
	if err != nil {
		t.Fatal(err)
	}
	rows, err := ParseRows(out)
	if err != nil || len(rows) != 1 || rows[0]["ImageFileName"] != "System" {
		t.Fatalf("rows = %v err %v", rows, err)
	}
	if info.Isolation != IsolationSandbox && info.Isolation != IsolationNone {
		t.Errorf("isolation not reported: %+v", info)
	}
}

func TestRun_PassesTheImageReadOnlyAndTheDocumentedFlags(t *testing.T) {
	vol, dir := newFake(t)
	cache := t.TempDir()
	syms := t.TempDir()
	r := newRunner(t, vol, func(c *Config) { c.CacheDir = cache; c.SymbolDirs = []string{syms} })
	img := writeImage(t, dir, "rows")
	if _, _, err := r.Run(context.Background(), img, "windows.pslist.PsList"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(cache, "last-args"))
	if err != nil {
		t.Skip("the fake could not record its arguments in this environment")
	}
	args := strings.Fields(string(b))
	want := []string{"-q", "-r", "json", "-f", img, "-s", syms, "--cache-path", cache, "windows.pslist.PsList"}
	if strings.Join(args, " ") != strings.Join(want, " ") {
		t.Errorf("args = %v\nwant   %v", args, want)
	}
}

func TestPlugins_ListsWhatThisVolatilityOffersAndResolvesNames(t *testing.T) {
	vol, _ := newFake(t)
	r := newRunner(t, vol, nil)
	got, err := r.Plugins(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"windows.info.Info", "windows.malware.malfind.Malfind", "windows.pslist.PsList"} {
		if !got[want] {
			t.Errorf("plugin %s not listed: %v", want, got)
		}
	}
	// malfind moved between versions; the first candidate that exists wins.
	name, ok := ResolvePlugin(got, "windows.malware.malfind.Malfind", "windows.malfind.Malfind")
	if !ok || name != "windows.malware.malfind.Malfind" {
		t.Errorf("resolved %q %v", name, ok)
	}
	name, ok = ResolvePlugin(got, "windows.malfind.Malfind", "windows.malware.malfind.Malfind")
	if !ok || name != "windows.malware.malfind.Malfind" {
		t.Errorf("fallback resolved %q %v", name, ok)
	}
	if _, ok := ResolvePlugin(got, "windows.netscan.NetScan"); ok {
		t.Error("a plugin this volatility lacks was resolved")
	}
	if v, err := r.Version(context.Background()); err != nil || v != "2.99.0" {
		t.Errorf("version = %q %v", v, err)
	}
}

func TestRun_TimeoutKillsTheWholeProcessTree(t *testing.T) {
	vol, dir := newFake(t)
	r := newRunner(t, vol, func(c *Config) { c.Timeout = 1500 * time.Millisecond })
	start := time.Now()
	_, _, err := r.Run(context.Background(), writeImage(t, dir, "sleep"), "windows.pslist.PsList")
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Errorf("took %v: the child outlived the timeout", time.Since(start))
	}
	// Nothing left behind sleeping for 600s.
	out, _ := exec.Command("pgrep", "-f", "sleep 600").Output()
	for _, pid := range strings.Fields(string(out)) {
		cmd, _ := os.ReadFile("/proc/" + pid + "/cmdline")
		if strings.Contains(string(cmd), "sleep") {
			// only ours if started by this test; give it a moment to die
			time.Sleep(500 * time.Millisecond)
			if _, err := os.Stat("/proc/" + pid); err == nil {
				t.Errorf("process %s survived the timeout", pid)
			}
		}
	}
}

func TestRun_CancelledContextStops(t *testing.T) {
	vol, dir := newFake(t)
	r := newRunner(t, vol, nil)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(500 * time.Millisecond); cancel() }()
	_, _, err := r.Run(ctx, writeImage(t, dir, "sleep"), "windows.pslist.PsList")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestRun_OutputBeyondTheCapIsStoppedNotBuffered(t *testing.T) {
	vol, dir := newFake(t)
	r := newRunner(t, vol, func(c *Config) { c.MaxOutputBytes = 1 << 20 })
	_, _, err := r.Run(context.Background(), writeImage(t, dir, "big"), "windows.pslist.PsList")
	if !errors.Is(err, ErrOutputTooLarge) {
		t.Errorf("err = %v, want ErrOutputTooLarge", err)
	}
}

func TestRun_MissingSymbolsIsRecognisedAndExplained(t *testing.T) {
	vol, dir := newFake(t)
	r := newRunner(t, vol, nil)
	_, _, err := r.Run(context.Background(), writeImage(t, dir, "nosymbols"), "windows.info.Info")
	if !errors.Is(err, ErrSymbols) {
		t.Fatalf("err = %v, want ErrSymbols", err)
	}
	if !strings.Contains(err.Error(), "symbol") {
		t.Errorf("the error does not mention symbols: %v", err)
	}
}

func TestRun_OutputThatIsNotJSONIsAnError(t *testing.T) {
	vol, dir := newFake(t)
	r := newRunner(t, vol, nil)
	out, _, err := r.Run(context.Background(), writeImage(t, dir, "garbage"), "windows.pslist.PsList")
	if err == nil {
		if _, perr := ParseRows(out); perr == nil {
			t.Error("garbage was accepted as rows")
		}
	}
}

func TestRun_NonZeroExitCarriesTheTail(t *testing.T) {
	vol, dir := newFake(t)
	r := newRunner(t, vol, nil)
	_, _, err := r.Run(context.Background(), writeImage(t, dir, "bogus"), "x")
	if err == nil || !strings.Contains(err.Error(), "unknown mode") {
		t.Errorf("err = %v", err)
	}
}

func TestSandbox_VolatilityCannotReachTheNetworkWriteOrSeeSecrets(t *testing.T) {
	needSandbox(t)
	vol, dir := newFake(t)
	t.Setenv("SECRET_TOKEN", "hunter2")
	home := t.TempDir()
	marker := filepath.Join(home, "marker")
	os.WriteFile(marker, []byte("x"), 0o600)
	t.Setenv("HOME", home)
	r := newRunner(t, vol, nil)
	if r.Isolation() != IsolationSandbox {
		t.Skip("user namespaces are unavailable here; the unsandboxed fallback is tested separately")
	}
	img := writeImage(t, dir, "probe\n"+marker)
	out, info, err := r.Run(context.Background(), img, "windows.info.Info")
	if err != nil {
		t.Fatal(err)
	}
	if info.Isolation != IsolationSandbox {
		t.Errorf("isolation = %s", info.Isolation)
	}
	rows, err := ParseRows(out)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %v err %v", rows, err)
	}
	p := rows[0]
	if p["net"] != "blocked" {
		t.Errorf("network: %v (a memory analysis must not be able to phone home)", p["net"])
	}
	if p["home"] != "hidden" {
		t.Errorf("the examiner's files are visible inside the sandbox: %v", p["home"])
	}
	if p["write_image"] != "denied" {
		t.Errorf("the evidence image is writable from inside the sandbox")
	}
	if p["write_beside_image"] != "denied" {
		t.Errorf("a file could be written next to the image")
	}
	if p["write_cache"] != "allowed" {
		t.Errorf("the cache directory must be writable, got %v", p["write_cache"])
	}
	if p["secret_env"] != float64(0) {
		t.Errorf("the parent's environment leaked into the sandbox: %v", p["secret_env"])
	}
}

func TestSandbox_RequiredByDefault(t *testing.T) {
	vol, _ := newFake(t)
	t.Setenv("PATH", "/nonexistent")
	_, err := NewRunner(Config{Vol: vol, CacheDir: t.TempDir()})
	if !errors.Is(err, ErrNoSandbox) {
		t.Errorf("err = %v, want ErrNoSandbox: running a parser of hostile memory with no containment must be an explicit choice", err)
	}
	r, err := NewRunner(Config{Vol: vol, CacheDir: t.TempDir(), AllowUnsandboxed: true})
	if err != nil || r.Isolation() != IsolationNone {
		t.Errorf("explicit opt-out: %v %v", r, err)
	}
}

func TestNewRunner_RejectsAMissingExecutable(t *testing.T) {
	if _, err := NewRunner(Config{Vol: filepath.Join(t.TempDir(), "nope"), CacheDir: t.TempDir(), AllowUnsandboxed: true}); err == nil {
		t.Error("a missing vol executable was accepted")
	}
	if _, err := NewRunner(Config{CacheDir: t.TempDir(), AllowUnsandboxed: true}); err == nil {
		t.Error("an empty configuration was accepted")
	}
}

func TestParseRows_FlattensChildrenAndToleratesTheLeadingBlankLine(t *testing.T) {
	rows, err := ParseRows([]byte("\n" + `[{"PID": 4, "__children": [{"PID": 5, "__children": []}]}, {"PID": 6, "__children": []}]`))
	if err != nil || len(rows) != 3 {
		t.Fatalf("rows = %v err %v", rows, err)
	}
	if _, ok := rows[0]["__children"]; ok {
		t.Error("__children leaked into a row")
	}
	if _, err := ParseRows([]byte("")); err == nil {
		t.Error("empty output accepted")
	}
	if _, err := ParseRows([]byte(`{"not": "a list"}`)); err == nil {
		t.Error("an object was accepted as a row list")
	}
}

func TestRealVolatility_ListsPluginsAndReportsItsVersion(t *testing.T) {
	vol := os.Getenv("TRACEFALL_TEST_VOL")
	if vol == "" {
		t.Skip("set TRACEFALL_TEST_VOL to a real vol executable to run this")
	}
	r, err := NewRunner(Config{Vol: vol, CacheDir: t.TempDir(), AllowUnsandboxed: true})
	if err != nil {
		t.Fatal(err)
	}
	plugins, err := r.Plugins(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"windows.info.Info", "windows.pslist.PsList", "windows.psscan.PsScan", "windows.cmdline.CmdLine", "windows.netscan.NetScan", "windows.svcscan.SvcScan"} {
		if !plugins[p] {
			t.Errorf("real volatility does not list %s", p)
		}
	}
	if _, ok := ResolvePlugin(plugins, "windows.malware.malfind.Malfind", "windows.malfind.Malfind"); !ok {
		t.Error("no malfind plugin resolved on the real volatility")
	}
	if v, err := r.Version(context.Background()); err != nil || !strings.Contains(v, ".") {
		t.Errorf("version = %q %v", v, err)
	}
}
