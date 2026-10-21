// Package memory runs Volatility 3 against a memory image in isolation and
// turns what it reports into data Tracefall can analyse.
//
// # Why Volatility is wrapped, not reimplemented
//
// Memory forensics is a large, fast-moving field: kernel structures change
// with every Windows build and are described by symbol tables. Volatility 3
// is the reference implementation and is maintained by people who track
// that. Tracefall's value is in what happens afterwards: normalising what
// Volatility finds, correlating it with disk and log evidence, and
// reporting it. So this package drives Volatility as a separate process and
// consumes its JSON output.
//
// # Why it runs contained
//
// A memory image is untrusted input from a compromised machine, and
// Volatility is a large Python program that parses it. A bug in that parse
// must not become a bug in the examiner's workstation. When bubblewrap is
// available (it is on any modern Linux) every run is made in new user,
// network, PID and IPC namespaces with:
//
//   - no network, so an analysis cannot send anything anywhere;
//   - an empty environment, so tokens and credentials of the parent are
//     not inherited;
//   - a read-only view of the system, of Volatility itself, of the
//     symbol tables and of the image;
//   - one writable directory, Volatility's own cache.
//
// Without bubblewrap the runner refuses to start unless the operator
// explicitly allows an unsandboxed run, in which case the isolation level
// is reported with every result, so a report never implies containment that
// did not exist.
//
// Not provided: a memory cap (Volatility maps the whole image, so an
// address-space limit would break it) and any protection on a host without
// user namespaces. Both are stated here and in docs/memory-analysis.md.
package memory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Isolation says how a run was contained.
type Isolation string

const (
	IsolationSandbox Isolation = "bubblewrap"
	IsolationNone    Isolation = "none"
)

var (
	// ErrNoSandbox means containment is unavailable and was not waived.
	ErrNoSandbox = errors.New("memory analysis requires a sandbox (bubblewrap), which is not usable here; install it, or explicitly allow an unsandboxed run")
	// ErrTimeout means a Volatility run exceeded its time limit.
	ErrTimeout = errors.New("volatility timed out")
	// ErrOutputTooLarge means Volatility produced more output than allowed.
	ErrOutputTooLarge = errors.New("volatility produced more output than the limit")
	// ErrSymbols means Volatility could not match the image to a kernel
	// symbol table. Volatility prints the SAME message whether the file is
	// not a supported Windows memory image at all or is one whose symbols
	// are simply not installed (the kernel layer cannot be built without
	// them), so this error says both rather than guessing which.
	ErrSymbols = errors.New("volatility could not match this image to a kernel symbol table: it is either not a supported Windows memory image, or the symbols for its Windows build are not installed")
	// ErrUnrecognised means Volatility could not make sense of the image
	// (not a Windows memory image, or a format it does not read).
	ErrUnrecognised = errors.New("volatility does not recognise this memory image")
	// ErrBadOutput means the output was not the JSON that was asked for.
	ErrBadOutput = errors.New("volatility output is not valid JSON")
)

// Config describes how to run Volatility.
type Config struct {
	// Vol is the path of the `vol` executable (or a name on PATH).
	Vol string
	// SymbolDirs are extra directories of symbol tables (ISF files).
	SymbolDirs []string
	// CacheDir is Volatility's writable cache. Created if missing.
	CacheDir string
	// ExtraROBinds are further read-only paths the sandbox needs (a
	// Python installation outside /usr, for example).
	ExtraROBinds []string
	// Timeout bounds one run. Default 2 hours.
	Timeout time.Duration
	// MaxOutputBytes bounds one run's output. Default 256 MiB.
	MaxOutputBytes int64
	// DumpMaxFiles bounds how many files are recovered from an image for
	// inspection. Zero means 60; a negative number turns recovery off.
	DumpMaxFiles int
	// DumpMaxBytes bounds one recovered file. Larger ones are not read.
	// Default 32 MiB.
	DumpMaxBytes int64
	// AllowUnsandboxed permits running without bubblewrap.
	AllowUnsandboxed bool
}

// RunInfo describes one run.
type RunInfo struct {
	Isolation Isolation
	Duration  time.Duration
}

// Runner runs Volatility.
type Runner struct {
	cfg       Config
	vol       string
	bwrap     string
	isolation Isolation

	helpOnce sync.Once
	helpOut  string
	helpErr  error
}

const (
	defaultTimeout   = 2 * time.Hour
	defaultMaxOutput = 256 << 20
	stderrKeep       = 8 << 10
)

// NewRunner validates the configuration and decides the isolation level.
func NewRunner(cfg Config) (*Runner, error) {
	if cfg.Vol == "" {
		return nil, errors.New("memory: the path of the volatility executable is not configured")
	}
	vol := cfg.Vol
	if !strings.ContainsRune(vol, os.PathSeparator) {
		p, err := exec.LookPath(vol)
		if err != nil {
			return nil, fmt.Errorf("memory: %q not found on PATH", cfg.Vol)
		}
		vol = p
	}
	vol, err := filepath.Abs(vol)
	if err != nil {
		return nil, err
	}
	if st, err := os.Stat(vol); err != nil || st.IsDir() {
		return nil, fmt.Errorf("memory: volatility executable %q not found", cfg.Vol)
	}
	if cfg.CacheDir == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			base = os.TempDir()
		}
		cfg.CacheDir = filepath.Join(base, "tracefall", "volatility")
	}
	if err := os.MkdirAll(cfg.CacheDir, 0o755); err != nil {
		return nil, fmt.Errorf("memory: cache directory: %w", err)
	}
	if cfg.CacheDir, err = filepath.Abs(cfg.CacheDir); err != nil {
		return nil, err
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.MaxOutputBytes <= 0 {
		cfg.MaxOutputBytes = defaultMaxOutput
	}
	r := &Runner{cfg: cfg, vol: vol, isolation: IsolationNone}
	if bw, err := exec.LookPath("bwrap"); err == nil && sandboxUsable(bw) {
		r.bwrap, r.isolation = bw, IsolationSandbox
	}
	if r.isolation == IsolationNone && !cfg.AllowUnsandboxed {
		return nil, ErrNoSandbox
	}
	return r, nil
}

// Isolation reports how runs are contained.
func (r *Runner) Isolation() Isolation { return r.isolation }

// sandboxUsable checks that bubblewrap can actually create the namespaces
// here (user namespaces may be disabled even when bwrap is installed).
func sandboxUsable(bwrap string) bool {
	truePath, err := exec.LookPath("true")
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, bwrap, "--unshare-all", "--ro-bind", "/usr", "/usr", "--proc", "/proc", "--dev", "/dev",
		"--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64", "--", truePath).Run() == nil
}

type tailBuffer struct {
	b []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if len(t.b) > stderrKeep {
		t.b = t.b[len(t.b)-stderrKeep:]
	}
	return len(p), nil
}

type capWriter struct {
	buf   bytes.Buffer
	limit int64
	over  bool
	onHit func()
}

func (c *capWriter) Write(p []byte) (int, error) {
	if int64(c.buf.Len())+int64(len(p)) > c.limit {
		if !c.over {
			c.over = true
			c.onHit()
		}
		return len(p), nil // swallow: the process is being killed
	}
	return c.buf.Write(p)
}

// exe builds the command line for args, adding containment.
func (r *Runner) command(ctx context.Context, image string, args []string) (*exec.Cmd, error) {
	if r.isolation == IsolationNone {
		cmd := exec.CommandContext(ctx, r.vol, args...)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + r.cfg.CacheDir, "LANG=C.UTF-8", "PYTHONDONTWRITEBYTECODE=1"}
		return cmd, nil
	}
	b := []string{"--die-with-parent", "--new-session", "--unshare-all", "--clearenv",
		"--setenv", "PATH", "/usr/bin:/bin", "--setenv", "HOME", "/tmp", "--setenv", "LANG", "C.UTF-8",
		"--setenv", "PYTHONDONTWRITEBYTECODE", "1",
		"--ro-bind", "/usr", "/usr"}
	for _, p := range []string{"/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"} {
		st, err := os.Lstat(p)
		if err != nil {
			continue
		}
		if st.Mode()&os.ModeSymlink != 0 {
			tgt, err := os.Readlink(p)
			if err == nil {
				b = append(b, "--symlink", tgt, p)
			}
		} else {
			b = append(b, "--ro-bind", p, p)
		}
	}
	b = append(b, "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp")
	seen := map[string]bool{"/usr": true}
	ro := func(p string) {
		if p == "" {
			return
		}
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		if real, err := filepath.EvalSymlinks(p); err == nil {
			p = real
		}
		if seen[p] || strings.HasPrefix(p, "/usr/") {
			return
		}
		seen[p] = true
		b = append(b, "--ro-bind", p, p)
	}
	ro(r.volRoot())
	for _, p := range r.cfg.ExtraROBinds {
		ro(p)
	}
	for _, p := range r.cfg.SymbolDirs {
		ro(p)
	}
	if image != "" {
		ro(image)
	}
	b = append(b, "--bind", r.cfg.CacheDir, r.cfg.CacheDir, "--remount-ro", "/", "--")
	b = append(b, r.vol)
	b = append(b, args...)
	return exec.CommandContext(ctx, r.bwrap, b...), nil
}

// volRoot is the directory tree Volatility lives in: the virtualenv or
// install prefix containing bin/vol, else the directory of the executable.
func (r *Runner) volRoot() string {
	real, err := filepath.EvalSymlinks(r.vol)
	if err != nil {
		real = r.vol
	}
	dir := filepath.Dir(real)
	if filepath.Base(dir) == "bin" {
		if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "pyvenv.cfg")); err == nil {
			return filepath.Dir(dir)
		}
	}
	return dir
}

// pyvenvHome returns the interpreter directory named in pyvenv.cfg when
// it lies outside /usr, so the sandbox can still run the virtualenv.
func (r *Runner) pyvenvBinds() []string {
	cfg := filepath.Join(r.volRoot(), "pyvenv.cfg")
	b, err := os.ReadFile(cfg)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok && strings.TrimSpace(k) == "home" {
			h := strings.TrimSpace(v)
			if h != "" && !strings.HasPrefix(h, "/usr/") && !strings.HasPrefix(h, "/bin") {
				out = append(out, filepath.Dir(h))
			}
		}
	}
	return out
}

func (r *Runner) run(ctx context.Context, image string, args []string, stdoutLimit int64) ([]byte, RunInfo, error) {
	start := time.Now()
	runCtx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
	defer cancel()

	saved := r.cfg.ExtraROBinds
	r.cfg.ExtraROBinds = append(append([]string(nil), saved...), r.pyvenvBinds()...)
	cmd, err := r.command(runCtx, image, args)
	r.cfg.ExtraROBinds = saved
	if err != nil {
		return nil, RunInfo{}, err
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	cmd.WaitDelay = 3 * time.Second

	out := &capWriter{limit: stdoutLimit, onHit: cancel}
	errTail := &tailBuffer{}
	cmd.Stdout, cmd.Stderr = out, errTail
	runErr := cmd.Run()
	info := RunInfo{Isolation: r.isolation, Duration: time.Since(start)}

	switch {
	case out.over:
		return nil, info, ErrOutputTooLarge
	case errors.Is(ctx.Err(), context.Canceled):
		return nil, info, context.Canceled
	case errors.Is(runCtx.Err(), context.DeadlineExceeded):
		return nil, info, fmt.Errorf("%w after %s", ErrTimeout, r.cfg.Timeout)
	case runErr != nil:
		return nil, info, classify(runErr, string(errTail.b))
	}
	return out.buf.Bytes(), info, nil
}

var (
	symbolRe = regexp.MustCompile(`(?i)symbol_table_name|symbol table requirement|no symbol|symbol tables?`)
	layerRe  = regexp.MustCompile(`(?i)translation layer requirement|kernel\.layer_name|primary\b.*requirement|unable to (?:read|find) the (?:image|banner)`)
)

func classify(runErr error, stderr string) error {
	tail := strings.TrimSpace(stderr)
	if len(tail) > 1500 {
		tail = tail[len(tail)-1500:]
	}
	switch {
	case symbolRe.MatchString(stderr):
		return fmt.Errorf("%w: %s", ErrSymbols, tail)
	case layerRe.MatchString(stderr):
		return fmt.Errorf("%w: %s", ErrUnrecognised, tail)
	}
	return fmt.Errorf("volatility failed (%v): %s", runErr, tail)
}

// Run runs one plugin against image and returns its raw JSON output.
func (r *Runner) Run(ctx context.Context, image, plugin string, extra ...string) ([]byte, RunInfo, error) {
	return r.RunInto(ctx, image, "", plugin, extra...)
}

// RunInto is Run for a plugin that writes files. outDir must lie inside the
// runner's cache directory, which is the only writable path the sandbox has.
func (r *Runner) RunInto(ctx context.Context, image, outDir, plugin string, extra ...string) ([]byte, RunInfo, error) {
	args := []string{"-q", "-r", "json", "-f", image}
	for _, d := range r.cfg.SymbolDirs {
		args = append(args, "-s", d)
	}
	args = append(args, "--cache-path", r.cfg.CacheDir)
	if outDir != "" {
		rel, err := filepath.Rel(r.cfg.CacheDir, outDir)
		if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
			return nil, RunInfo{}, fmt.Errorf("memory: output directory %q is not inside the cache directory", outDir)
		}
		args = append(args, "-o", outDir)
	}
	args = append(args, plugin)
	args = append(args, extra...)
	return r.run(ctx, image, args, r.cfg.MaxOutputBytes)
}

func (r *Runner) help(ctx context.Context) (string, error) {
	r.helpOnce.Do(func() {
		out, _, err := r.run(ctx, "", []string{"-h"}, 4<<20)
		r.helpOut, r.helpErr = string(out), err
	})
	return r.helpOut, r.helpErr
}

var (
	pluginRe  = regexp.MustCompile(`(?m)^\s+([a-z][a-z0-9_]*(?:\.[A-Za-z0-9_]+)+)\b`)
	versionRe = regexp.MustCompile(`Volatility 3 Framework\s+(\S+)`)
)

// Plugins returns the plugin names this Volatility offers.
func (r *Runner) Plugins(ctx context.Context) (map[string]bool, error) {
	h, err := r.help(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, m := range pluginRe.FindAllStringSubmatch(h, -1) {
		out[m[1]] = true
	}
	if len(out) == 0 {
		return nil, errors.New("memory: could not read the plugin list from volatility")
	}
	return out, nil
}

// Version returns the Volatility framework version.
func (r *Runner) Version(ctx context.Context) (string, error) {
	h, err := r.help(ctx)
	if err != nil {
		return "", err
	}
	if m := versionRe.FindStringSubmatch(h); m != nil {
		return m[1], nil
	}
	return "", errors.New("memory: could not read the volatility version")
}

// ResolvePlugin returns the first candidate this Volatility offers.
// Plugins move between versions (malfind is windows.malfind in older
// releases and windows.malware.malfind in newer), so names are looked up
// rather than assumed.
func ResolvePlugin(available map[string]bool, candidates ...string) (string, bool) {
	for _, c := range candidates {
		if available[c] {
			return c, true
		}
	}
	return "", false
}

// ParseRows decodes Volatility's JSON renderer output into flat rows.
// The output is a tree: each node carries its columns and "__children".
// Children are returned after their parent, in order, as ordinary rows.
func ParseRows(raw []byte) ([]map[string]any, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: empty output", ErrBadOutput)
	}
	var tree []map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&tree); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadOutput, err)
	}
	var out []map[string]any
	var walk func(n []map[string]any, depth int) error
	walk = func(n []map[string]any, depth int) error {
		if depth > 64 {
			return fmt.Errorf("%w: tree is implausibly deep", ErrBadOutput)
		}
		for _, row := range n {
			kids, _ := row["__children"].([]any)
			delete(row, "__children")
			out = append(out, row)
			var sub []map[string]any
			for _, k := range kids {
				if m, ok := k.(map[string]any); ok {
					sub = append(sub, m)
				}
			}
			if err := walk(sub, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(tree, 0); err != nil {
		return nil, err
	}
	// json.Number to plain numbers where they fit, so callers can type-switch.
	for _, row := range out {
		for k, v := range row {
			if n, ok := v.(json.Number); ok {
				if i, err := strconv.ParseInt(string(n), 10, 64); err == nil {
					row[k] = float64(i)
					if i > 1<<53 || i < -(1<<53) {
						row[k] = n // keep precision for huge values
					}
				} else if f, err := n.Float64(); err == nil {
					row[k] = f
				}
			}
		}
	}
	return out, nil
}

var _ = io.Discard
