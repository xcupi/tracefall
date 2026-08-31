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
	"errors"
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Config is Tracefall's fully-resolved runtime configuration.
type Config struct {
	Host        string // listen host, e.g. "127.0.0.1" or "0.0.0.0"
	Port        string
	DBPath      string
	DataDir     string // root directory for per-case uploaded/extracted evidence
	MaxUploadMB int64  // maximum accepted upload size, in megabytes

	// AuthEnabled turns on session authentication (Phase 12).
	//
	// Default is FALSE for a loopback bind, so single-operator localhost
	// use stays exactly as easy as it was. It is forced TRUE for any
	// non-loopback bind: see Validate, which refuses to start rather than
	// serving evidence to a network with no authentication.
	AuthEnabled bool
	// SessionTTLMinutes bounds how long one login stays valid.
	SessionTTLMinutes int64
	// SecureCookies marks session cookies Secure, for a deployment behind
	// a TLS terminator. Off by default because Tracefall speaks plain
	// HTTP; enabling it without TLS makes login silently fail, so it is
	// opt-in rather than inferred.
	SecureCookies bool
}

// SessionTTL returns the configured session lifetime.
func (c Config) SessionTTL() time.Duration {
	return time.Duration(c.SessionTTLMinutes) * time.Minute
}

// ErrUnsafeLANExposure is returned when Tracefall is asked to listen on
// a non-loopback address without authentication.
//
// This is a REFUSAL, not a warning. Before Phase 12 the same
// configuration started successfully and logged a warning, which meant a
// single environment variable was enough to publish every case, every
// piece of evidence and every destructive endpoint to the network. A
// warning in a log nobody reads is not a control.
var ErrUnsafeLANExposure = errors.New(
	"refusing to start: Tracefall is configured to listen on a non-loopback address with authentication disabled.\n" +
		"  Every case, all evidence, the full audit log and every destructive endpoint would be reachable by anyone on the network.\n" +
		"  Either:\n" +
		"    * bind to localhost   -- TRACEFALL_HOST=127.0.0.1   (single-operator use), or\n" +
		"    * enable authentication -- TRACEFALL_AUTH=on        (shared/LAN use)\n" +
		"  See docs/deployment.md.")

// Validate rejects configurations that would be unsafe to serve.
//
// Fail-closed: an operator who mis-set one variable gets a refusal with
// the two ways to fix it, not a running server quietly exposing
// evidence.
func (c Config) Validate() error {
	if !c.IsLoopbackHost() && !c.AuthEnabled {
		return ErrUnsafeLANExposure
	}
	if c.MaxUploadMB <= 0 {
		return fmt.Errorf("max-upload-mb must be positive, got %d", c.MaxUploadMB)
	}
	if c.SessionTTLMinutes <= 0 {
		return fmt.Errorf("session-ttl-minutes must be positive, got %d", c.SessionTTLMinutes)
	}
	return nil
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
	defaultHost    = "127.0.0.1"
	defaultPort    = "8080"
	defaultDB      = "tracefall.db"
	defaultDataDir = "./data"
	// 12 hours: long enough for a working day of analysis, short enough
	// that an unattended browser is not authenticated indefinitely.
	defaultSessionTTLMinutes = 12 * 60
	defaultMaxUploadMB       = int64(2048) // 2 GiB
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
	authOn := fs.Bool("auth", envOrBool(getenv, "TRACEFALL_AUTH", false),
		"require username/password authentication. Mandatory for any non-loopback bind.")
	sessionTTL := fs.Int64("session-ttl-minutes", envOrInt(getenv, "TRACEFALL_SESSION_TTL_MINUTES", defaultSessionTTLMinutes),
		"how long a login stays valid, in minutes")
	secureCookies := fs.Bool("secure-cookies", envOrBool(getenv, "TRACEFALL_SECURE_COOKIES", false),
		"mark session cookies Secure. Only for a deployment behind HTTPS; breaks login over plain HTTP.")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	cfg := Config{
		Host: *host, Port: *port, DBPath: *db, DataDir: *dataDir, MaxUploadMB: *maxUploadMB,
		AuthEnabled: *authOn, SessionTTLMinutes: *sessionTTL, SecureCookies: *secureCookies,
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// envOrBool reads a boolean environment variable, accepting the spellings
// an operator actually types.
func envOrBool(getenv func(string) string, key string, def bool) bool {
	v := strings.TrimSpace(strings.ToLower(getenv(key)))
	switch v {
	case "":
		return def
	case "1", "true", "yes", "on", "enabled":
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	}
	return def
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
