//go:build unix

package llm

import (
	"context"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

// DevicePrompt contains only the validated public link and transient user code.
type DevicePrompt struct{ URL, Code string }

const deviceOutputLimit = 16 << 10

var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;]*m`)
var deviceCode = regexp.MustCompile(`^[A-Z0-9]{4}-[A-Z0-9]{4,6}$`)
var errLogin = errors.New("Codex authorization command failed; no command output is exposed")

// Exact route from OpenAI codex-rs/login/src/device_code_auth.rs; fail closed
// on CLI format/issuer changes. No query, userinfo, explicit port or escapes.
func ParseDevicePrompt(text string) (DevicePrompt, error) {
	if len(text) > deviceOutputLimit {
		return DevicePrompt{}, errLogin
	}
	lines := strings.Split(ansiEscape.ReplaceAllString(text, ""), "\n")
	p := DevicePrompt{}
	codeNext := false
	for _, line := range lines[:len(lines)-1] {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "https://") || strings.HasPrefix(line, "http://") {
			u, e := url.Parse(line)
			if e != nil || u.Scheme != "https" || u.Host != "auth.openai.com" || u.Path != "/codex/device" || u.RawPath != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || line != "https://auth.openai.com/codex/device" {
				return DevicePrompt{}, errLogin
			}
			p.URL = line
		}
		if codeNext && line != "" {
			if !deviceCode.MatchString(line) {
				return DevicePrompt{}, errLogin
			}
			p.Code = line
			codeNext = false
		}
		if strings.HasPrefix(line, "2. Enter this one-time code") {
			codeNext = true
		}
	}
	if p.URL == "" || p.Code == "" {
		return DevicePrompt{}, errLogin
	}
	return p, nil
}

type authOutput struct {
	mu       sync.Mutex
	text     strings.Builder
	cancel   context.CancelFunc
	progress func(DevicePrompt)
	sent     bool
	overflow bool
}

func (o *authOutput) Write(b []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.text.Len()+len(b) > deviceOutputLimit {
		o.overflow = true
		o.cancel()
		return len(b), nil
	}
	o.text.Write(b)
	if !o.sent && o.progress != nil {
		if p, e := ParseDevicePrompt(o.text.String()); e == nil {
			o.sent = true
			o.progress(p)
		}
	}
	return len(b), nil
}
func (c *CodexCLI) authCommand(ctx context.Context, duration time.Duration, progress func(DevicePrompt), args ...string) (string, error) {
	// Unlike legacy model clients, auth commands must NEVER fall back to the
	// operator's CODEX_HOME or personal home, including when misconfigured.
	if c == nil || c.CodexHome == "" || !isExecutable(c.Binary) {
		return "", errLogin
	}
	if err := os.MkdirAll(c.CodexHome, 0700); err != nil {
		return "", errLogin
	}
	ctx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	argv := append([]string{"-c", `cli_auth_credentials_store="file"`, "-c", `forced_login_method="chatgpt"`}, args...)
	cmd := exec.CommandContext(ctx, c.Binary, argv...)
	cmd.Dir = c.CodexHome
	cmd.Env = c.env()
	for i, s := range cmd.Env {
		if strings.HasPrefix(s, "HOME=") {
			cmd.Env[i] = "HOME=" + c.CodexHome
		}
	}
	o := &authOutput{cancel: cancel, progress: progress}
	cmd.Stdout = o
	cmd.Stderr = o
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	if o.overflow {
		return "", errLogin
	}
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	return o.text.String(), err
}

// AuthorizationAvailable reports whether isolated auth subprocesses can run.
func (c *CodexCLI) AuthorizationAvailable() bool {
	return c != nil && c.CodexHome != "" && isExecutable(c.Binary)
}

// LoginStatus is a local CLI status check, not validation of token freshness or
// model access. Only the official ChatGPT status line counts as signed in.
func (c *CodexCLI) LoginStatus(ctx context.Context) (string, error) {
	text, err := c.authCommand(ctx, 4*time.Second, nil, "login", "status")
	lines := strings.Split(strings.TrimSpace(ansiEscape.ReplaceAllString(text, "")), "\n")
	// The installed CLI may prefix the status with PATH-alias warnings.
	// Recognize only its exact terminal status line, never reflect other text.
	text = strings.TrimSpace(lines[len(lines)-1])
	if err == nil && text == "Logged in using ChatGPT" {
		return "signed_in", nil
	}
	if text == "Not logged in" {
		return "not_connected", nil
	}
	return "failed", errLogin
}
func (c *CodexCLI) DeviceLogin(ctx context.Context, progress func(DevicePrompt)) error {
	text, err := c.authCommand(ctx, 15*time.Minute, progress, "login", "--device-auth")
	if _, parseErr := ParseDevicePrompt(text); err == nil && parseErr != nil {
		return errLogin
	}
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errLogin
	}
	st, err := c.LoginStatus(ctx)
	if err != nil || st != "signed_in" {
		return errLogin
	}
	return nil
}
func (c *CodexCLI) Logout(ctx context.Context) error {
	_, err := c.authCommand(ctx, 8*time.Second, nil, "logout")
	if err != nil {
		return errLogin
	}
	st, err := c.LoginStatus(ctx)
	if err != nil || st != "not_connected" {
		return errLogin
	}
	return nil
}
