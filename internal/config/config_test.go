package config

import "testing"

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
	env := fakeEnv(map[string]string{
		"TRACEFALL_HOST": "0.0.0.0",
		"TRACEFALL_PORT": "9090",
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
