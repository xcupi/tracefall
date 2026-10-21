// Tracefall is an automated forensic triage and investigation platform.
// This binary runs the full API and web dashboard, backed by a local
// SQLite database, with evidence uploaded through the browser or ingested
// from a local KAPE-output directory.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	// tzdata is embedded so timezone conversion works identically on
	// every host, including a container or a Windows machine with no
	// system timezone database. Without it, time.LoadLocation would fail
	// on such hosts and every analyst-facing timestamp would silently
	// fall back to UTC -- the exact class of quiet wrongness the display
	// timezone feature exists to prevent. Stdlib; no new dependency.
	_ "time/tzdata"

	"tracefall/internal/api"
	"tracefall/internal/casefiles"
	"tracefall/internal/config"
	"tracefall/internal/memory"
	"tracefall/internal/store"
	"tracefall/internal/web"
)

func main() {
	// Offline subcommand: checking a report bundle needs no database,
	// no server and no configuration, so it runs before any of them.
	if len(os.Args) > 1 && os.Args[1] == "parse-worker" {
		os.Exit(parseWorkerCmd())
	}
	if len(os.Args) > 1 && os.Args[1] == "verify-report" {
		os.Exit(verifyReportCmd(os.Args[2:], os.Stdout))
	}

	cfg, err := config.Load(os.Args[1:], os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tracefall:", err)
		os.Exit(2)
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Evidence, reports and the case database are sensitive. The data
	// directory is owner-only, which also covers every file under it whatever
	// its own mode; the database files are owner-only too.
	if err := lockDownStorage(cfg.DataDir, cfg.DBPath); err != nil {
		logger.Error("failed to restrict storage permissions", "error", err)
		os.Exit(1)
	}
	capacity := serverCapacityFromEnv()
	enableParserIsolation(logger, capacity)
	db, err := store.Open(cfg.DBPath)
	if err != nil {
		logger.Error("failed to open database", "error", err, "path", cfg.DBPath)
		os.Exit(1)
	}
	defer db.Close()

	files := casefiles.NewStore(cfg.DataDir)
	svc := api.NewService(db, files)
	capacity.apply(svc, logger)

	// Server-path ingest reads folders that already sit on this machine. The
	// policy decides which ones; see internal/api/evidence_policy.go.
	roots := splitList(os.Getenv("TRACEFALL_EVIDENCE_ROOTS"))
	allowUnrooted := !cfg.AuthEnabled && cfg.IsLoopbackHost()
	if err := svc.SetEvidencePathPolicy(roots, allowUnrooted); err != nil {
		logger.Error("invalid TRACEFALL_EVIDENCE_ROOTS", "error", err)
		os.Exit(1)
	}
	switch {
	case len(roots) > 0:
		logger.Info("server-path ingest is limited to the evidence roots", "roots", roots)
	case allowUnrooted:
		logger.Warn("server-path ingest accepts ANY path on this host (local no-auth, loopback). Set TRACEFALL_EVIDENCE_ROOTS to restrict it")
	default:
		logger.Info("server-path ingest is disabled (authentication on, or a non-loopback host); set TRACEFALL_EVIDENCE_ROOTS to allow listed folders")
	}

	// Bootstrap the first administrator when authentication is on and no
	// account exists yet. Without this an authenticated deployment would
	// have no way in at all.
	//
	// The generated password is printed ONCE, to stdout, and never
	// stored in plaintext or written to the log. It is generated rather
	// than defaulted because a well-known default password on a forensic
	// tool is worse than no authentication -- it looks secure.
	if cfg.AuthEnabled {
		if err := bootstrapAdmin(svc, os.Getenv("TRACEFALL_ADMIN_PASSWORD"), os.Stdout); err != nil {
			logger.Error("failed to create the initial administrator", "error", err)
			os.Exit(1)
		}
	}

	// Memory analysis is optional: it needs Volatility 3, which Tracefall
	// does not ship. Without it, memory images are refused with a message
	// that says how to enable it; everything else works as before.
	if vol := os.Getenv("TRACEFALL_VOLATILITY"); vol != "" {
		mcfg := memory.Config{
			Vol:              vol,
			SymbolDirs:       splitList(os.Getenv("TRACEFALL_VOLATILITY_SYMBOLS")),
			CacheDir:         os.Getenv("TRACEFALL_VOLATILITY_CACHE"),
			AllowUnsandboxed: os.Getenv("TRACEFALL_VOLATILITY_ALLOW_UNSANDBOXED") == "1",
		}
		if v := os.Getenv("TRACEFALL_VOLATILITY_TIMEOUT"); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				fmt.Fprintf(os.Stderr, "TRACEFALL_VOLATILITY_TIMEOUT: %v\n", err)
				os.Exit(1)
			}
			mcfg.Timeout = d
		}
		runner, err := memory.NewRunner(mcfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "memory analysis: %v\n", err)
			os.Exit(1)
		}
		svc.SetMemoryRunner(runner)
		slog.Info("memory analysis enabled", "isolation", string(runner.Isolation()))
	}

	// Server-side pipeline: work a previous process left running is put
	// back in the queue (or failed if it keeps killing the server), then
	// the single worker starts. Nothing here is graceful-shutdown
	// dependent: a job cut off mid-stage resumes from its checkpoint on
	// the next start.
	if requeued, failed, err := svc.RecoverPipeline(); err != nil {
		logger.Error("failed to recover pipeline jobs", "error", err)
	} else if requeued+failed > 0 {
		logger.Warn("recovered interrupted pipeline jobs", "requeued", requeued, "failed", failed)
	}
	stopPipeline := svc.StartPipeline(context.Background())
	defer stopPipeline()

	authCfg := api.AuthConfig{
		Enabled:        cfg.AuthEnabled,
		SessionTTL:     cfg.SessionTTL(),
		SecureCookies:  cfg.SecureCookies,
		TrustedProxies: cfg.TrustedProxies,
		BehindProxy:    cfg.InsecureHTTP,
	}
	if cfg.InsecureHTTP && len(cfg.TrustedProxies) == 0 {
		logger.Warn("behind a proxy with no --trusted-proxies: failed logins cannot be counted per client address, " +
			"so only the per-username limit applies")
	}

	mux := http.NewServeMux()
	apiMux := api.NewRouterWithAuth(svc, logger, cfg.MaxUploadBytes(), !cfg.IsLoopbackHost(), authCfg)
	mux.Handle("/api/", apiMux)
	// The dashboard shell and its assets get the baseline security
	// headers plus a Content-Security-Policy; the API mux applies its own
	// inside withSecurity.
	mux.Handle("/static/", api.SecurityHeaders(web.StaticHandler(), cfg.SecureCookies))
	mux.Handle("/", api.SecurityHeaders(web.Index(), cfg.SecureCookies))

	logger.Info("tracefall starting", "addr", cfg.Addr(), "db", cfg.DBPath, "data_dir", cfg.DataDir, "max_upload_mb", cfg.MaxUploadMB)
	printStartupBanner(os.Stdout, cfg)

	// config.Validate has already REFUSED an unauthenticated non-loopback
	// bind, so reaching here on a LAN address means authentication is on.
	// The remaining risk is transport, not access control.
	switch {
	case cfg.TLSEnabled():
		logger.Info("serving HTTPS", "min_tls", "1.2")
	case !cfg.IsLoopbackHost():
		logger.Warn("serving plain HTTP on a non-loopback host (--insecure-http): " +
			"TLS must be terminated by a reverse proxy in front of Tracefall.")
	}

	// Timeouts on the connection phases a client controls before the handler
	// runs. No overall read or write timeout: an evidence upload or a report
	// download legitimately takes minutes. A client that stalls mid-header, or
	// holds an idle connection open, is dropped.
	srv := &http.Server{
		Addr:              cfg.Addr(),
		Handler:           requestLogger(logger, mux),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	var serveErr error
	if cfg.TLSEnabled() {
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		serveErr = srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
	} else {
		serveErr = srv.ListenAndServe()
	}
	if err := serveErr; err != nil {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

// browserURL renders a URL host a browser can actually open. "0.0.0.0"
// (bind-to-all-interfaces) isn't itself a valid address to browse to, so
// the startup banner shows "localhost" for that case -- the server is
// still bound to every interface, this only affects what's printed.
func browserURL(host, port string) string {
	if host == "0.0.0.0" || host == "" {
		host = "localhost"
	}
	return net.JoinHostPort(host, port)
}

// printStartupBanner prints a short, human-readable summary of where
// Tracefall is listening and where its data lives -- deliberately plain
// text (not the structured slog line above it, which is for log
// aggregation) so it's easy to read at a glance when starting the server
// interactively. Takes an io.Writer (main passes os.Stdout) so this is
// testable without redirecting real stdout.
func printStartupBanner(w io.Writer, cfg config.Config) {
	fmt.Fprintln(w, "Tracefall")
	fmt.Fprintf(w, "Listening: %s\n", cfg.Addr())
	if cfg.IsLoopbackHost() {
		fmt.Fprintf(w, "URL: http://%s\n", browserURL(cfg.Host, cfg.Port))
	} else {
		// Actually detecting this machine's LAN IP would need to guess
		// which network interface is the right one, which isn't reliable
		// across platforms/configurations -- printing the bind address
		// and telling the user which piece to substitute is simpler and
		// never wrong.
		fmt.Fprintf(w, "LAN access: http://<host-ip>:%s\n", cfg.Port)
		fmt.Fprintln(w, "  (replace <host-ip> with this machine's LAN IP address -- Tracefall is listening on all interfaces)")
	}
	fmt.Fprintf(w, "Data: %s\n", cfg.DataDir)
	fmt.Fprintf(w, "Database: %s\n", cfg.DBPath)
}

func requestLogger(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Debug("request", "method", r.Method, "path", r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func splitList(v string) []string {
	var out []string
	for _, p := range filepath.SplitList(v) {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
