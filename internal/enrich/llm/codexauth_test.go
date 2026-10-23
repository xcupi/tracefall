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

// Opt-in local inspection only: no device authorization or model request.
func TestInstalledCodexIsolatedNegativeControl(t *testing.T) {
	binary := os.Getenv("TRACEFALL_TEST_CODEX_BIN")
	if binary == "" {
		t.Skip("set TRACEFALL_TEST_CODEX_BIN for isolated local help/status inspection")
	}
	c := NewCodexCLI(binary, "")
	c.CodexHome = t.TempDir()
	help, err := c.authCommand(context.Background(), 4*time.Second, nil, "login", "--help")
	if err != nil || !strings.Contains(help, "--device-auth") {
		t.Fatal("official device auth CLI help unavailable")
	}
	st, err := c.LoginStatus(context.Background())
	if err != nil || st != "not_connected" {
		t.Fatalf("fresh isolated CLI negative status: %s %v", st, err)
	}
	if c.Configured() {
		t.Fatal("empty isolated home must not use operator credentials")
	}
	t.Log("official CLI help supports --device-auth; isolated status is not_connected; no authorization/model request performed")
}
func TestDeviceLoginCancellationKillsGroupAndReducesEnvironment(t *testing.T) {
	t.Setenv("TRACEFALL_LLM_API_KEY", "SYNTHETIC-SECRET")
	t.Setenv("OPENAI_API_KEY", "SYNTHETIC-SECRET")
	c, f := newFake(t, "ok")
	script := `#!/bin/sh
 d="$(dirname "$0")"
 env > "$d/auth-env"
 sleep 30 & echo $! > "$d/auth-child"
 printf 'https://auth.openai.com/codex/device\n2. Enter this one-time code\nABCD-12345\n'
 wait
 `
	os.WriteFile(f.bin, []byte(script), 0700)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := c.DeviceLogin(ctx, func(DevicePrompt) {}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancel not recognizable: %v", err)
	}
	env := f.read(t, "auth-env")
	if strings.Contains(env, "SYNTHETIC-SECRET") || !strings.Contains(env, "HOME="+f.home) || !strings.Contains(env, "CODEX_HOME="+f.home) {
		t.Fatal("auth environment not isolated")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(f.read(t, "auth-child")))
	if err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		if syscall.Kill(pid, 0) != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("authorization child survived cancellation")
}
func TestCodexChatDeadlineIncludesCLIReadiness(t *testing.T) {
	c, f := newFake(t, "ok")
	os.WriteFile(f.bin, []byte("#!/bin/sh\nsleep 30\n"), 0700)
	c.Timeout = 100 * time.Millisecond
	start := time.Now()
	_, err := c.Chat(context.Background(), msgsWithMarker)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("readiness escaped model deadline: %v after %v", err, time.Since(start))
	}
}
func TestDeviceLoginOutputIsBoundedAndNeverReflected(t *testing.T) {
	c, f := newFake(t, "ok")
	os.WriteFile(f.bin, []byte("#!/bin/sh\nprintf 'SECRET-RAW-OUTPUT' >&2\nhead -c 20000 /dev/zero >&2\nsleep 30\n"), 0700)
	start := time.Now()
	err := c.DeviceLogin(context.Background(), func(DevicePrompt) { t.Error("oversized output exposed") })
	if err == nil || strings.Contains(err.Error(), "SECRET") || time.Since(start) > 3*time.Second {
		t.Fatalf("unbounded or raw error: %v", err)
	}
}
func TestDevicePromptWaitsForCompleteCodeLine(t *testing.T) {
	text := "https://auth.openai.com/codex/device\n2. Enter this one-time code (expires in 15 minutes)\nABCD-1234"
	if _, err := ParseDevicePrompt(text); err == nil {
		t.Fatal("partial code line accepted before final byte")
	}
}
func TestCodexConfiguredUsesCLIStatusNotFile(t *testing.T) {
	c, f := newFake(t, "ok")
	os.WriteFile(f.bin, []byte("#!/bin/sh\necho 'Not logged in' >&2\nexit 1\n"), 0700)
	if c.Configured() {
		t.Fatal("auth.json existence incorrectly treated as signed in")
	}
	os.Remove(filepath.Join(f.home, "auth.json"))
	os.WriteFile(f.bin, []byte("#!/bin/sh\necho 'Logged in using ChatGPT' >&2\n"), 0700)
	if !c.Configured() {
		t.Fatal("CLI status must determine readiness, not auth.json")
	}
}
func TestCodexStatusAllowsInstalledCLIWarning(t *testing.T) {
	c, f := newFake(t, "ok")
	os.WriteFile(f.bin, []byte("#!/bin/sh\necho 'WARNING: proceeding, even though we could not create PATH aliases: Refusing to create helper binaries under temporary dir' >&2\necho 'Not logged in' >&2\nexit 1\n"), 0700)
	st, err := c.LoginStatus(context.Background())
	if err != nil || st != "not_connected" {
		t.Fatalf("installed CLI warning changed status: %s %v", st, err)
	}
}
func TestDeviceLoginRejectsUnrecognizedPromptEvenOnSuccess(t *testing.T) {
	c, f := newFake(t, "ok")
	os.WriteFile(f.bin, []byte("#!/bin/sh\nwhile [ \"$1\" = \"-c\" ]; do shift 2; done\nif [ \"$2\" = status ]; then echo 'Logged in using ChatGPT' >&2; else printf 'https://evil.invalid/device\\n2. Enter this one-time code\\nABCD-12345\\n'; fi\n"), 0700)
	count := 0
	if err := c.DeviceLogin(context.Background(), func(DevicePrompt) { count++ }); err == nil {
		t.Fatal("successful exit bypassed official prompt validation")
	}
	if count != 0 {
		t.Fatal("untrusted prompt exposed")
	}
}
func TestDevicePromptOfficialOnly(t *testing.T) {
	text := "\x1b[94mhttps://auth.openai.com/codex/device\x1b[0m\n2. Enter this one-time code (expires in 15 minutes)\n  ABCD-12345\n"
	p, err := ParseDevicePrompt(text)
	if err != nil || p.URL != "https://auth.openai.com/codex/device" || p.Code != "ABCD-12345" {
		t.Fatalf("validated prompt = %+v, %v", p, err)
	}
	for _, url := range []string{"http://auth.openai.com/codex/device", "https://auth.openai.com.evil.test/codex/device", "https://auth.openai.com/codex/device?token=secret", "https://user@auth.openai.com/codex/device", "https://auth.openai.com:443/codex/device", "https://auth.openai.com/codex/%64evice", "https://auth.openai.com/other"} {
		if _, err := ParseDevicePrompt(strings.ReplaceAll(text, "https://auth.openai.com/codex/device", url)); err == nil {
			t.Errorf("accepted %s", url)
		}
	}
	if _, err := ParseDevicePrompt(strings.Repeat("x", 17000) + text); err == nil {
		t.Error("unbounded output accepted")
	}
}

func TestCodexLoginStatusDoesNotTrustAuthFile(t *testing.T) {
	d := t.TempDir()
	bin := filepath.Join(d, "codex")
	home := filepath.Join(d, "isolated")
	os.Mkdir(home, 0700)
	os.WriteFile(filepath.Join(home, "auth.json"), []byte("not a credential"), 0600)
	os.WriteFile(bin, []byte("#!/bin/sh\nprintf 'Not logged in\\n' >&2\nexit 1\n"), 0700)
	c := NewCodexCLI(bin, "")
	c.CodexHome = home
	status, err := c.LoginStatus(context.Background())
	if err != nil || status != "not_connected" {
		t.Fatalf("status=%q err=%v", status, err)
	}
	os.WriteFile(bin, []byte("#!/bin/sh\nprintf 'Logged in using ChatGPT\\n' >&2\n"), 0700)
	status, err = c.LoginStatus(context.Background())
	if err != nil || status != "signed_in" {
		t.Fatalf("status=%q err=%v", status, err)
	}
	os.WriteFile(bin, []byte("#!/bin/sh\necho 'Logged in using an API key - SECRET' >&2\n"), 0700)
	if status, err = c.LoginStatus(context.Background()); err == nil || status == "signed_in" {
		t.Fatal("API key must not count as ChatGPT")
	}
	os.WriteFile(bin, []byte("#!/bin/sh\nsleep 30\n"), 0700)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err = c.LoginStatus(ctx); err == nil {
		t.Fatal("timeout accepted")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("subprocess timeout not bounded")
	}
}
