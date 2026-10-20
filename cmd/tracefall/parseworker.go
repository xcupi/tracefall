package main

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	"tracefall/internal/api"
	"tracefall/internal/ingest"
)

// parseWorkerCmd is the child process the server starts to parse one file. It
// applies its own limits first, then reads a request on stdin and writes the
// result on stdout. It is not meant to be run by hand.
func parseWorkerCmd() int {
	// Stray output from a parser must not corrupt the response.
	out := os.Stdout
	os.Stdout = os.Stderr
	if _, err := ingest.ApplyWorkerLimits(); err != nil {
		// Off Linux there are no limits to apply; the server says so at start.
		fmt.Fprintln(os.Stderr, "limits:", err)
	}
	if err := ingest.WorkerMain(os.Stdin, out, api.ClassifyParseError); err != nil {
		fmt.Fprintln(os.Stderr, "parse-worker:", err)
		return 1
	}
	return 0
}

// enableParserIsolation makes the server run every parse in a child process,
// unless TRACEFALL_PARSER_ISOLATION=off. It logs exactly what protection is in
// effect, because a limit that did not apply must not be reported as applied.
func enableParserIsolation(logger *slog.Logger) {
	if os.Getenv("TRACEFALL_PARSER_ISOLATION") == "off" {
		logger.Warn("parser isolation is OFF (TRACEFALL_PARSER_ISOLATION=off): a crafted file can stop the server")
		return
	}
	exe, err := ingest.SelfPath()
	if err != nil {
		logger.Warn("parser isolation unavailable: cannot find the executable", "error", err)
		return
	}
	sub := ingest.Subprocess{Exe: exe, MemoryMB: 4096, Timeout: 20 * time.Minute}
	if v, err := strconv.Atoi(os.Getenv("TRACEFALL_PARSER_MEM_MB")); err == nil && v > 0 {
		sub.MemoryMB = v
	}
	if v, err := time.ParseDuration(os.Getenv("TRACEFALL_PARSER_TIMEOUT")); err == nil && v > 0 {
		sub.Timeout = v
	}
	sub.Sandbox = ingest.FindSandbox()
	if sub.Sandbox == "" {
		sub.NoNetwork = ingest.NetworkIsolationAvailable()
	}
	ingest.SetParserRunner(sub)
	level := "process, memory and time limits only"
	switch {
	case sub.Sandbox != "":
		level = "sandbox (bubblewrap): no network, read-only minimal file system"
	case sub.NoNetwork:
		level = "process limits and no network"
	}
	logger.Info("parser isolation on", "level", level, "memory_mb", sub.MemoryMB, "timeout", sub.Timeout.String())
	if sub.Sandbox == "" {
		logger.Warn("no sandbox is available (install bubblewrap): a crafted file cannot take the server down, " +
			"but the parser can still read the server's files" + map[bool]string{true: "", false: " and use the network"}[sub.NoNetwork])
	}
}
