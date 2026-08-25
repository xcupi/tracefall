// Tracefall is an automated forensic triage and investigation platform.
// This binary runs the full API and web dashboard, backed by a local
// SQLite database, with evidence uploaded through the browser or ingested
// from a local KAPE-output directory.
package main

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"

	"tracefall/internal/api"
	"tracefall/internal/casefiles"
	"tracefall/internal/config"
	"tracefall/internal/store"
	"tracefall/internal/web"
)

func main() {
	cfg, err := config.Load(os.Args[1:], os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tracefall:", err)
		os.Exit(2)
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	db, err := store.Open(cfg.DBPath)
	if err != nil {
		logger.Error("failed to open database", "error", err, "path", cfg.DBPath)
		os.Exit(1)
	}
	defer db.Close()

	files := casefiles.NewStore(cfg.DataDir)
	svc := api.NewService(db, files)

	mux := http.NewServeMux()
	apiMux := api.NewRouter(svc, logger, cfg.MaxUploadBytes())
	mux.Handle("/api/", apiMux)
	mux.Handle("/static/", web.StaticHandler())
	mux.HandleFunc("/", web.Index())

	logger.Info("tracefall starting", "addr", cfg.Addr(), "db", cfg.DBPath, "data_dir", cfg.DataDir, "max_upload_mb", cfg.MaxUploadMB)
	printStartupBanner(os.Stdout, cfg)

	if !cfg.IsLoopbackHost() {
		logger.Warn("listening on a non-loopback host: Tracefall is reachable from other machines on this network. " +
			"There is no authentication in this phase -- do not expose this host/port beyond a trusted LAN, and never port-forward it to the public internet.")
	}

	if err := http.ListenAndServe(cfg.Addr(), requestLogger(logger, mux)); err != nil {
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
