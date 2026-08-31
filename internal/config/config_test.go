package config

import (
	"errors"
	"strings"
	"testing"
)

func fakeEnv(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoad_Defaults(t *testing.T) {
	cfg, err := Load(nil, fakeEnv(nil))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Host != "127.0.0.1" {
		t.Errorf("default host = %q, want 127.0.0.1 (safe local default)", cfg.Host)
	}
	if cfg.Port != "8080" {
		t.Errorf("default port = %q, want 8080", cfg.Port)
	}
	if !cfg.IsLoopbackHost() {
		t.Error("default host should be considered loopback")
	}
	if cfg.Addr() != "127.0.0.1:8080" {
		t.Errorf("Addr() = %q, want 127.0.0.1:8080", cfg.Addr())
	}
}

func TestLoad_EnvOverridesDefault(t *testing.T) {
	// TRACEFALL_AUTH is required here since Phase 12: a non-loopback bind
	// without authentication is refused rather than started. See
	// TestLoad_RefusesUnauthenticatedLANExposure.
	env := fakeEnv(map[string]string{
		"TRACEFALL_HOST": "0.0.0.0",
		"TRACEFALL_PORT": "9090",
		"TRACEFALL_AUTH": "on",
	})
	cfg, err := Load(nil, env)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Host != "0.0.0.0" || cfg.Port != "9090" {
		t.Errorf("got host=%q port=%q, want 0.0.0.0:9090 from env", cfg.Host, cfg.Port)
	}
	if cfg.IsLoopbackHost() {
		t.Error("0.0.0.0 should not be considered loopback")
	}
}

func TestLoad_FlagOverridesEnv(t *testing.T) {
	env := fakeEnv(map[string]string{"TRACEFALL_PORT": "9090"})
	cfg, err := Load([]string{"-port", "7000"}, env)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Port != "7000" {
		t.Errorf("port = %q, want 7000 (explicit flag must beat env var)", cfg.Port)
	}
}

func TestLoad_MaxUploadBytes(t *testing.T) {
	cfg, err := Load([]string{"-max-upload-mb", "10"}, fakeEnv(nil))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, want := cfg.MaxUploadBytes(), int64(10*1024*1024); got != want {
		t.Errorf("MaxUploadBytes() = %d, want %d", got, want)
	}
}

func TestLoad_RejectsNonPositiveUploadLimit(t *testing.T) {
	if _, err := Load([]string{"-max-upload-mb", "0"}, fakeEnv(nil)); err == nil {
		t.Error("expected an error for -max-upload-mb 0")
	}
}

func TestLoad_InvalidEnvIntFallsBackToDefault(t *testing.T) {
	env := fakeEnv(map[string]string{"TRACEFALL_MAX_UPLOAD_MB": "not-a-number"})
	cfg, err := Load(nil, env)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.MaxUploadMB != defaultMaxUploadMB {
		t.Errorf("got %d, want default %d when env value is unparseable", cfg.MaxUploadMB, defaultMaxUploadMB)
	}
}

// ---------------- Phase 12: fail-closed deployment ----------------

// The control this phase exists to add: a non-loopback bind with no
// authentication must REFUSE TO START, not warn.
//
// Before Phase 12 this configuration started successfully and logged a
// warning, so one mis-set environment variable published every case, all
// evidence, the audit log and every destructive endpoint to the network.
func TestLoad_RefusesUnauthenticatedLANExposure(t *testing.T) {
	for _, host := range []string{"0.0.0.0", "192.168.1.50", "::", "10.0.0.7"} {
		t.Run(host, func(t *testing.T) {
			_, err := Load(nil, fakeEnv(map[string]string{"TRACEFALL_HOST": host}))
			if err == nil {
				t.Fatalf("host %q with auth disabled started successfully; it must be refused", host)
			}
			if !errors.Is(err, ErrUnsafeLANExposure) {
				t.Errorf("error = %v, want ErrUnsafeLANExposure", err)
			}
			// The refusal must tell the operator how to fix it.
			for _, want := range []string{"TRACEFALL_HOST=127.0.0.1", "TRACEFALL_AUTH=on", "docs/deployment.md"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("refusal does not mention %q:\n%s", want, err)
				}
			}
		})
	}
}

// Localhost development must stay exactly as easy as before.
func TestLoad_LoopbackWithoutAuthStillWorks(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "localhost", "::1"} {
		t.Run(host, func(t *testing.T) {
			cfg, err := Load(nil, fakeEnv(map[string]string{"TRACEFALL_HOST": host}))
			if err != nil {
				t.Fatalf("loopback host %q was refused: %v", host, err)
			}
			if cfg.AuthEnabled {
				t.Error("authentication was enabled implicitly; localhost use must stay unauthenticated by default")
			}
		})
	}
}

// LAN exposure WITH authentication is the supported shared deployment.
func TestLoad_AuthenticatedLANIsAllowed(t *testing.T) {
	cfg, err := Load(nil, fakeEnv(map[string]string{
		"TRACEFALL_HOST": "0.0.0.0",
		"TRACEFALL_AUTH": "true",
	}))
	if err != nil {
		t.Fatalf("authenticated LAN bind was refused: %v", err)
	}
	if !cfg.AuthEnabled {
		t.Error("TRACEFALL_AUTH=true did not enable authentication")
	}
	if cfg.IsLoopbackHost() {
		t.Error("0.0.0.0 reported as loopback")
	}
}

// The flag must be able to enable auth as well as the environment
// variable, and must win over it (established precedence).
func TestLoad_AuthFlagOverridesEnv(t *testing.T) {
	cfg, err := Load([]string{"-auth=true", "-host=0.0.0.0"},
		fakeEnv(map[string]string{"TRACEFALL_AUTH": "off"}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.AuthEnabled {
		t.Error("-auth=true did not win over TRACEFALL_AUTH=off")
	}
}

func TestLoad_AuthEnvSpellings(t *testing.T) {
	for _, on := range []string{"1", "true", "yes", "on", "enabled", "TRUE", "On"} {
		cfg, err := Load(nil, fakeEnv(map[string]string{"TRACEFALL_AUTH": on, "TRACEFALL_HOST": "0.0.0.0"}))
		if err != nil || !cfg.AuthEnabled {
			t.Errorf("TRACEFALL_AUTH=%q did not enable auth (err=%v)", on, err)
		}
	}
	for _, off := range []string{"0", "false", "no", "off", "disabled"} {
		if _, err := Load(nil, fakeEnv(map[string]string{"TRACEFALL_AUTH": off, "TRACEFALL_HOST": "127.0.0.1"})); err != nil {
			t.Errorf("TRACEFALL_AUTH=%q on loopback should be fine: %v", off, err)
		}
	}
}

func TestLoad_SessionTTLMustBePositive(t *testing.T) {
	if _, err := Load([]string{"-session-ttl-minutes=0"}, fakeEnv(nil)); err == nil {
		t.Error("a zero session lifetime was accepted")
	}
	cfg, err := Load(nil, fakeEnv(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SessionTTL() <= 0 {
		t.Errorf("default session TTL = %v, want positive", cfg.SessionTTL())
	}
}
