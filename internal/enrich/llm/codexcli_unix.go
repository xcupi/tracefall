//go:build unix

package llm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// The Codex CLI, signed in with a ChatGPT account, as a way to reach a model.
//
// This is the supported route to a ChatGPT subscription: the CLI does the
// sign-in, keeps the credentials fresh and speaks to whatever endpoint OpenAI
// currently uses, so this program never reads, copies or stores a token and
// does not depend on an undocumented endpoint.
//
// Codex is an agent, and its default is to have tools. For this use it is
// given none: a model that is asked to summarise findings has no reason to run
// anything, and the text it reads (command lines and descriptions taken from
// evidence) is text an attacker may have written. So it runs
//
//   - with no user configuration, no rules and no plugins (--ignore-user-config,
//     --ignore-rules, and every tool-giving feature disabled),
//   - in a read-only sandbox with approvals set to "never", in an empty
//     temporary directory that is removed afterwards,
//   - with the prompt on standard input (an argument would be visible in the
//     process list to every user of the machine),
//   - with a reduced environment, and
//   - in its own process group, which is killed as a whole on cancellation.
//
// What Codex writes to standard error repeats the prompt. It is therefore
// never put in an error, a log or the database: failures are reported from
// the exit status alone, with one exception, the recognition of a refused
// sign-in, which reads standard error without keeping it.

// codexDisabledFeatures are the Codex features switched off for every call.
// Each one gives a model a way to act (run a command, run JavaScript, drive a
// browser or a computer, call a plugin or another agent, open an image, wait,
// use memory). With them off the model could not read a file outside its
// working directory when told to try, which was checked with a file that held
// nothing secret.
var codexDisabledFeatures = []string{
	"shell_tool", "plugins", "apps", "browser_use", "browser_use_external", "computer_use", "multi_agent", "hooks",
	"image_generation", "memories", "code_mode_host", "code_mode_interrupt", "goals", "unified_exec", "unified_exec_tty",
	"sleep_tool", "view_image", "skill_search", "tool_suggest", "skill_mcp_dependency_install", "tool_call_mcp_elicitation",
	"worktrees", "shell_snapshot", "write_stdin_approval", "workspace_dependencies", "guardian_approval", "in_app_browser",
	"in_app_chat", "in_app_local_automation", "mentions_v2", "realtime_conversation", "remote_plugin", "plugin_sharing",
}

// CodexNotice is shown to the analyst before they acknowledge a request that
// goes through a ChatGPT sign-in.
const CodexNotice = "This request goes to OpenAI through the account the Codex CLI is signed in with. On a personal ChatGPT account, what is sent may be used to train models unless \"Improve the model for everyone\" is turned off in ChatGPT's data controls. This program cannot check that setting."

// CodexCLI reaches a model through the Codex command-line program.
type CodexCLI struct {
	// Binary is the path of the codex program.
	Binary string
	// Model is the model to ask. Empty means the CLI's own default.
	Model string
	// CodexHome is where the CLI keeps its sign-in; empty means $CODEX_HOME or ~/.codex.
	CodexHome string
	// Timeout bounds one request.
	Timeout time.Duration
}

var _ Chatter = (*CodexCLI)(nil)

// NewCodexCLI returns a client for the codex program at binary, or one found
// on the PATH or next to the ChatGPT desktop application when binary is empty.
func NewCodexCLI(binary, model string) *CodexCLI {
	if strings.TrimSpace(binary) == "" {
		binary = findCodex()
	}
	return &CodexCLI{Binary: strings.TrimSpace(binary), Model: strings.TrimSpace(model), Timeout: 5 * time.Minute}
}

func findCodex() string {
	if p, err := exec.LookPath("codex"); err == nil {
		return p
	}
	for _, p := range []string{"/usr/lib/chatgpt/resources/codex"} {
		if isExecutable(p) {
			return p
		}
	}
	return ""
}

func isExecutable(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0o111 != 0
}

func (c *CodexCLI) codexHome() string {
	if c.CodexHome != "" {
		return c.CodexHome
	}
	if h := os.Getenv("CODEX_HOME"); h != "" {
		return h
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".codex")
	}
	return ""
}

// Configured: the program exists and a sign-in is present. The sign-in file is
// only checked for existing; it is never opened.
func (c *CodexCLI) Configured() bool {
	if c == nil || c.Binary == "" || !isExecutable(c.Binary) {
		return false
	}
	h := c.codexHome()
	if h == "" {
		return false
	}
	st, err := os.Stat(filepath.Join(h, "auth.json"))
	return err == nil && st.Mode().IsRegular()
}

// Destination: text goes to OpenAI, never to this machine.
func (c *CodexCLI) Destination() (string, bool) { return "chatgpt.com (through the Codex CLI)", false }

// ModelName is the model asked, or says that the CLI's default is used.
func (c *CodexCLI) ModelName() string {
	if c == nil || c.Model == "" {
		return "the Codex CLI's default model"
	}
	return c.Model
}

// Notice is what to tell the analyst about this route.
func (c *CodexCLI) Notice() string { return CodexNotice }

// args is the whole command line apart from the program: nothing in it is
// taken from the case.
func (c *CodexCLI) args(dir, out string) []string {
	a := []string{"exec", "--ignore-user-config", "--ignore-rules", "--ephemeral", "--skip-git-repo-check",
		"-s", "read-only", "-C", dir, "-o", out}
	for _, f := range codexDisabledFeatures {
		a = append(a, "--disable", f)
	}
	a = append(a, "-c", `approval_policy="never"`, "-c", `web_search="disabled"`)
	if c.Model != "" {
		a = append(a, "-m", c.Model)
	}
	return append(a, "-")
}

// env is the environment the program gets: enough to find its sign-in and
// reach the network, and none of this server's own settings.
func (c *CodexCLI) env() []string {
	env := []string{"PATH=" + os.Getenv("PATH"), "LANG=C.UTF-8", "CODEX_HOME=" + c.codexHome(), "TMPDIR=" + os.TempDir()}
	if h, err := os.UserHomeDir(); err == nil {
		env = append(env, "HOME="+h)
	}
	for _, k := range []string{"HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR"} {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// codexPrompt joins the messages into one prompt. The first line tells the
// model not to use tools; that is a request, the real limit is the list above.
func codexPrompt(msgs []Message) string {
	var b strings.Builder
	b.WriteString("Do not call any tool. Answer only with the text requested below.\n\n")
	for i, m := range msgs {
		if i > 0 {
			b.WriteString("\n\n")
		}
		b.WriteString(m.Content)
	}
	return b.String()
}

// limitedBuffer keeps the first n bytes and drops the rest.
type limitedBuffer struct {
	buf bytes.Buffer
	n   int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := l.n - l.buf.Len(); room > 0 {
		if len(p) > room {
			l.buf.Write(p[:room])
		} else {
			l.buf.Write(p)
		}
	}
	return len(p), nil
}

var codexModelRe = regexp.MustCompile(`(?m)^model:\s*(\S+)\s*$`)

// Chat runs one request.
func (c *CodexCLI) Chat(ctx context.Context, msgs []Message) (Result, error) {
	if !c.Configured() {
		return Result{}, ErrNotConfigured
	}
	dir, err := os.MkdirTemp("", "tracefall-codex-")
	if err != nil {
		return Result{}, fmt.Errorf("llm: no temporary directory for the Codex CLI: %w", err)
	}
	defer os.RemoveAll(dir)
	out := filepath.Join(dir, "answer.txt")

	t := c.Timeout
	if t <= 0 {
		t = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, t)
	defer cancel()

	cmd := exec.CommandContext(ctx, c.Binary, c.args(dir, out)...)
	cmd.Dir = dir
	cmd.Env = c.env()
	cmd.Stdin = strings.NewReader(codexPrompt(msgs))
	cmd.Stdout = io.Discard
	var stderr limitedBuffer
	stderr.n = 256 << 10
	cmd.Stderr = &stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 5 * time.Second

	runErr := cmd.Run()
	if ctx.Err() != nil {
		return Result{}, ctx.Err()
	}
	if runErr != nil {
		// Standard error repeats the prompt, so none of it is kept. The one
		// thing read from it is whether the sign-in was refused.
		if bytes.Contains(stderr.buf.Bytes(), []byte("401 Unauthorized")) {
			return Result{}, ErrAuth
		}
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			return Result{}, fmt.Errorf("llm: the Codex CLI exited with status %d", ee.ExitCode())
		}
		return Result{}, fmt.Errorf("llm: the Codex CLI could not be run: %v", runErr)
	}
	f, err := os.Open(out)
	if err != nil {
		return Result{}, errors.New("llm: the Codex CLI wrote no answer")
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxOutput+1))
	if err != nil {
		return Result{}, fmt.Errorf("llm: reading the answer: %w", err)
	}
	if len(raw) > maxOutput {
		return Result{}, errors.New("llm: the answer is larger than allowed")
	}
	if strings.TrimSpace(string(raw)) == "" {
		return Result{}, errors.New("llm: the answer is empty")
	}
	res := Result{Content: string(raw)}
	if m := codexModelRe.FindSubmatch(stderr.buf.Bytes()); m != nil {
		res.Model = string(m[1])
	}
	return res, nil
}
