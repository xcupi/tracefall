// Package config resolves Tracefall's runtime configuration (listen
// address, database path, evidence data directory, upload size limit)
// from command-line flags and environment variables. It is a pure
// function of its inputs (args + a getenv lookup) specifically so it can
// be unit tested without mutating the real process environment or
// parsing os.Args -- see config_test.go.
//
// Precedence: an explicit CLI flag wins; otherwise the environment
// variable is used; otherwise a hardcoded default.
package config

import (
	"flag"
	"fmt"
	"net"
	"strconv"
)

// Config is Tracefall's fully-resolved runtime configuration.
type Config struct {
	Host        string // listen host, e.g. "127.0.0.1" or "0.0.0.0"
	Port        string
	DBPath      string
	DataDir     string // root directory for per-case uploaded/extracted evidence
	MaxUploadMB int64  // maximum accepted upload size, in megabytes
}

// Addr returns the host:port string suitable for http.ListenAndServe.
func (c Config) Addr() string {
	return net.JoinHostPort(c.Host, c.Port)
}

// MaxUploadBytes returns the configured upload size limit in bytes.
func (c Config) MaxUploadBytes() int64 {
	return c.MaxUploadMB * 1024 * 1024
}

// IsLoopbackHost reports whether the configured host is local-only. Used
// to decide whether to log a LAN-exposure warning at startup.
func (c Config) IsLoopbackHost() bool {
	if c.Host == "localhost" {
		return true
	}
	ip := net.ParseIP(c.Host)
	return ip != nil && ip.IsLoopback()
}

const (
	defaultHost        = "127.0.0.1"
	defaultPort        = "8080"
	defaultDB          = "tracefall.db"
	defaultDataDir     = "./data"
	defaultMaxUploadMB = int64(2048) // 2 GiB
)

// Load parses args (typically os.Args[1:]) into a Config, using getenv
// (typically os.Getenv) to source defaults for any flag not explicitly
// passed on the command line.
func Load(args []string, getenv func(string) string) (Config, error) {
	fs := flag.NewFlagSet("tracefall", flag.ContinueOnError)

	host := fs.String("host", envOr(getenv, "TRACEFALL_HOST", defaultHost),
		"host/IP to listen on. Use 0.0.0.0 to accept connections from other machines on the LAN.")
	port := fs.String("port", envOr(getenv, "TRACEFALL_PORT", defaultPort), "port to listen on")
	db := fs.String("db", envOr(getenv, "TRACEFALL_DB", defaultDB), "path to the SQLite database file")
	dataDir := fs.String("data-dir", envOr(getenv, "TRACEFALL_DATA_DIR", defaultDataDir),
		"root directory for uploaded/extracted case evidence")
	maxUploadMB := fs.Int64("max-upload-mb", envOrInt(getenv, "TRACEFALL_MAX_UPLOAD_MB", defaultMaxUploadMB),
		"maximum accepted KAPE package upload size, in megabytes")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	cfg := Config{Host: *host, Port: *port, DBPath: *db, DataDir: *dataDir, MaxUploadMB: *maxUploadMB}

	if cfg.MaxUploadMB <= 0 {
		return Config{}, fmt.Errorf("max-upload-mb must be positive, got %d", cfg.MaxUploadMB)
	}

	return cfg, nil
}

func envOr(getenv func(string) string, key, def string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return def
}

func envOrInt(getenv func(string) string, key string, def int64) int64 {
	v := getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return def
	}
	return n
}
