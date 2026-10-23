//go:build unix

package llm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const fakeCodex = `#!/bin/sh
d="$(dirname "$0")"
printf '%s\n' "$@" > "$d/args.txt"
cat > "$d/stdin.txt"
env > "$d/env.txt"
pwd > "$d/pwd.txt"
out=""
while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift;; esac; shift; done
mode="$(cat "$d/mode.txt")"
case "$mode" in
  ok) printf 'The answer. [F1]\n' > "$out"; echo "model: fake-model-1" >&2; echo "user" >&2; cat "$d/stdin.txt" >&2 ;;
  auth) echo "ERROR: unexpected status 401 Unauthorized: Missing bearer" >&2; cat "$d/stdin.txt" >&2; exit 1 ;;
  fail) cat "$d/stdin.txt" >&2; echo SECRET-FROM-STDERR >&2; exit 3 ;;
  empty) : > "$out" ;;
  nofile) : ;;
  big) head -c 70000 /dev/zero | tr '\0' a > "$out" ;;
  slow) sleep 30 ;;
  child) sleep 30 & echo $! > "$d/child.pid"; wait ;;
esac
`

type fake struct {
	dir, bin, home string
}

func newFake(t *testing.T, mode string) (*CodexCLI, *fake) {
	t.Helper()
	d := t.TempDir()
	f := &fake{dir: d, bin: filepath.Join(d, "codex"), home: filepath.Join(d, "home")}
	if err := os.WriteFile(f.bin, []byte(fakeCodex), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(f.home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.home, "auth.json"), []byte(`{"not":"read"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	f.mode(t, mode)
	c := NewCodexCLI(f.bin, "")
	c.CodexHome = f.home
	return c, f
}

func (f *fake) mode(t *testing.T, m string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, "mode.txt"), []byte(m), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *fake) read(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(f.dir, name))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return string(b)
}

var msgsWithMarker = []Message{{"system", "INSTRUCTIONS-MARKER"}, {"user", "FACTS-MARKER-SECRET-PROMPT"}}

func TestCodex_ReturnsTheAnswerAndTheModelThatWasUsed(t *testing.T) {
	c, _ := newFake(t, "ok")
	r, err := c.Chat(context.Background(), msgsWithMarker)
	if err != nil {
		t.Fatal(err)
	}
	if r.Content != "The answer. [F1]\n" || r.Model != "fake-model-1" {
		t.Errorf("result = %+v", r)
	}
}

func TestCodex_TheCommandLineIsolatesTheModelAndCarriesNoCaseText(t *testing.T) {
	c, f := newFake(t, "ok")
	c.Model = "some-model"
	if _, err := c.Chat(context.Background(), msgsWithMarker); err != nil {
		t.Fatal(err)
	}
	args := strings.Split(strings.TrimSpace(f.read(t, "args.txt")), "\n")
	has := func(a ...string) bool {
		for i := 0; i+len(a) <= len(args); i++ {
			ok := true
			for j := range a {
				if args[i+j] != a[j] {
					ok = false
				}
			}
			if ok {
				return true
			}
		}
		return false
	}
	for _, want := range [][]string{{"exec"}, {"--ignore-user-config"}, {"--ignore-rules"}, {"--ephemeral"}, {"--skip-git-repo-check"}, {"-s", "read-only"},
		{"-c", `approval_policy="never"`}, {"-c", `web_search="disabled"`}, {"-m", "some-model"}} {
		if !has(want...) {
			t.Errorf("the command line lacks %v: %v", want, args)
		}
	}
	for _, feat := range codexDisabledFeatures {
		if !has("--disable", feat) {
			t.Errorf("feature %q is not disabled", feat)
		}
	}
	if args[len(args)-1] != "-" {
		t.Errorf("the prompt must come on standard input (last argument %q)", args[len(args)-1])
	}
	for _, a := range args {
		if strings.Contains(a, "MARKER") {
			t.Errorf("case text is in an argument, where the process list shows it: %q", a)
		}
	}
	if !strings.Contains(f.read(t, "stdin.txt"), "FACTS-MARKER-SECRET-PROMPT") || !strings.Contains(f.read(t, "stdin.txt"), "INSTRUCTIONS-MARKER") {
		t.Errorf("the prompt did not arrive on standard input")
	}
	if !strings.HasPrefix(f.read(t, "stdin.txt"), "Do not call any tool.") {
		t.Errorf("the prompt does not ask the model to use no tool")
	}
	// a request carries no model flag unless one was configured
	c2, f2 := newFake(t, "ok")
	if _, err := c2.Chat(context.Background(), msgsWithMarker); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(f2.read(t, "args.txt"), "-m\n") {
		t.Errorf("a model was forced although none was configured")
	}
}

func TestCodex_RunsInAnEmptyTemporaryDirectoryThatIsRemovedAfterwards(t *testing.T) {
	c, f := newFake(t, "ok")
	cwd, _ := os.Getwd()
	if _, err := c.Chat(context.Background(), msgsWithMarker); err != nil {
		t.Fatal(err)
	}
	ran := strings.TrimSpace(f.read(t, "pwd.txt"))
	if ran == cwd || !strings.Contains(filepath.Base(ran), "tracefall-codex-") {
		t.Errorf("ran in %q (server directory %q)", ran, cwd)
	}
	if _, err := os.Stat(ran); !os.IsNotExist(err) {
		t.Errorf("the working directory %s was left behind", ran)
	}
	args := f.read(t, "args.txt")
	if !strings.Contains(args, "-C\n"+ran+"\n") || !strings.Contains(args, "-o\n"+ran+"/answer.txt\n") {
		t.Errorf("-C and -o must point into the temporary directory: %s", args)
	}
}

func TestCodex_TheEnvironmentHoldsNoneOfTheServersSettings(t *testing.T) {
	t.Setenv("TRACEFALL_LLM_API_KEY", "SECRET-LLM")
	t.Setenv("TRACEFALL_VT_API_KEY", "SECRET-VT")
	t.Setenv("TRACEFALL_ADMIN_PASSWORD", "SECRET-ADMIN")
	t.Setenv("SOME_OTHER_SECRET", "SECRET-OTHER")
	t.Setenv("HTTPS_PROXY", "http://proxy.example.invalid:3128")
	c, f := newFake(t, "ok")
	if _, err := c.Chat(context.Background(), msgsWithMarker); err != nil {
		t.Fatal(err)
	}
	env := f.read(t, "env.txt")
	if strings.Contains(env, "SECRET-") {
		t.Errorf("a setting of this server reached the program:\n%s", env)
	}
	for _, want := range []string{"CODEX_HOME=" + f.home, "PATH=", "HOME=", "HTTPS_PROXY=http://proxy.example.invalid:3128"} {
		if !strings.Contains(env, want) {
			t.Errorf("the environment lacks %q", want)
		}
	}
}

func TestCodex_FailuresAreReportedWithoutAnythingFromStandardError(t *testing.T) {
	c, f := newFake(t, "auth")
	if _, err := c.Chat(context.Background(), msgsWithMarker); !errors.Is(err, ErrAuth) {
		t.Errorf("a refused sign-in: %v", err)
	}
	f.mode(t, "fail")
	_, err := c.Chat(context.Background(), msgsWithMarker)
	if err == nil || !strings.Contains(err.Error(), "status 3") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "SECRET-FROM-STDERR") || strings.Contains(err.Error(), "MARKER") {
		t.Errorf("standard error, which repeats the prompt, reached an error message: %v", err)
	}
	for _, m := range []string{"empty", "nofile", "big"} {
		f.mode(t, m)
		if r, err := c.Chat(context.Background(), msgsWithMarker); err == nil {
			t.Errorf("%s was accepted: %.30q", m, r.Content)
		}
	}
}

func TestCodex_CancellationKillsTheWholeProcessGroup(t *testing.T) {
	c, f := newFake(t, "child")
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.Chat(ctx, msgsWithMarker)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Errorf("cancellation took %v", time.Since(start))
	}
	pid, perr := strconv.Atoi(strings.TrimSpace(f.read(t, "child.pid")))
	if perr != nil {
		t.Fatal(perr)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if syscall.Kill(pid, 0) != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("the program's child process %d is still running after cancellation", pid)
}

func TestCodex_ACancelledContextStaysRecognisable(t *testing.T) {
	c, _ := newFake(t, "slow")
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(200 * time.Millisecond); cancel() }()
	if _, err := c.Chat(ctx, msgsWithMarker); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
}

func TestCodex_TheConfiguredTimeoutApplies(t *testing.T) {
	c, _ := newFake(t, "slow")
	c.Timeout = 300 * time.Millisecond
	start := time.Now()
	if _, err := c.Chat(context.Background(), msgsWithMarker); !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 10*time.Second {
		t.Errorf("err = %v after %v", err, time.Since(start))
	}
}

func TestCodex_ConfiguredNeedsTheProgramAndASignInAndNeverOpensIt(t *testing.T) {
	c, f := newFake(t, "ok")
	if !c.Configured() {
		t.Fatal("a program and a sign-in are present")
	}
	// the sign-in is only checked for existing: make it unreadable
	if err := os.Chmod(filepath.Join(f.home, "auth.json"), 0); err != nil {
		t.Fatal(err)
	}
	if !c.Configured() {
		t.Errorf("Configured read the sign-in file; it must only check that it exists")
	}
	_ = os.Chmod(filepath.Join(f.home, "auth.json"), 0o600)

	if err := os.Remove(filepath.Join(f.home, "auth.json")); err != nil {
		t.Fatal(err)
	}
	if c.Configured() {
		t.Errorf("not signed in must not be configured")
	}
	if _, err := c.Chat(context.Background(), msgsWithMarker); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("err = %v", err)
	}
	c2, f2 := newFake(t, "ok")
	if err := os.Chmod(f2.bin, 0o644); err != nil {
		t.Fatal(err)
	}
	if c2.Configured() {
		t.Errorf("a program that is not executable is not configured")
	}
	if (&CodexCLI{Binary: filepath.Join(t.TempDir(), "missing")}).Configured() || (*CodexCLI)(nil).Configured() || NewCodexCLI("", "").Binary == "x" {
		t.Errorf("missing program / nil")
	}
}

func TestCodex_SaysWhereTextGoesAndWhatToKnowAboutIt(t *testing.T) {
	c, _ := newFake(t, "ok")
	host, local := c.Destination()
	if local || !strings.Contains(host, "chatgpt.com") {
		t.Errorf("destination = %q local=%v: text goes to OpenAI, not to this machine", host, local)
	}
	if !strings.Contains(c.Notice(), "Improve the model for everyone") || !strings.Contains(c.Notice(), "cannot check") {
		t.Errorf("notice = %q", c.Notice())
	}
	if c.ModelName() != "the Codex CLI's default model" {
		t.Errorf("model = %q", c.ModelName())
	}
	c.Model = "m-x"
	if c.ModelName() != "m-x" {
		t.Errorf("model = %q", c.ModelName())
	}
}

func TestNone_IsNeverConfiguredAndSendsNothing(t *testing.T) {
	var n Chatter = None{}
	if n.Configured() {
		t.Errorf("None is configured")
	}
	if _, err := n.Chat(context.Background(), msgsWithMarker); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("err = %v", err)
	}
}

// requiredOff is written out here, apart from the list in the code, on purpose:
// a test that walked the code's own list would pass when a feature is dropped
// from it. Each of these gives a model a way to act, and each was found to be
// reachable until it was switched off.
var requiredOff = []string{
	"shell_tool", "unified_exec", "code_mode_host", "code_mode_interrupt", "computer_use", "browser_use", "browser_use_external",
	"plugins", "apps", "multi_agent", "hooks", "image_generation", "memories", "goals", "view_image",
}

func TestCodex_EveryFeatureThatLetsAModelActIsSwitchedOff(t *testing.T) {
	c, f := newFake(t, "ok")
	if _, err := c.Chat(context.Background(), msgsWithMarker); err != nil {
		t.Fatal(err)
	}
	args := f.read(t, "args.txt")
	for _, feat := range requiredOff {
		if !strings.Contains(args, "--disable\n"+feat+"\n") {
			t.Errorf("%s is not disabled", feat)
		}
	}
	// and the code's own list may not shrink below what is required
	have := map[string]bool{}
	for _, x := range codexDisabledFeatures {
		have[x] = true
	}
	for _, feat := range requiredOff {
		if !have[feat] {
			t.Errorf("%s is missing from the list in the code", feat)
		}
	}
}
