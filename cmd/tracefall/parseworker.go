package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"tracefall/internal/api"
	"tracefall/internal/ingest"
)

// parseWorkerCmd is the child process the server starts to parse one file. It
// applies its own limits first, then reads a request on stdin and writes the
// result on stdout. It is not meant to be run by hand.
func parseWorkerCmd() int {
	if len(os.Args) > 2 && os.Args[2] == "-check" {
		return parseWorkerCheck()
	}
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

// parseWorkerCheck applies the worker's limits and reports, as one JSON line on
// stdout, which of them took effect. The server runs it at start-up so that its
// log states what protection is real instead of what was intended.
func parseWorkerCheck() int {
	applied, err := ingest.ApplyWorkerLimits()
	res := map[string]any{"applied": applied}
	if err != nil {
		res["error"] = err.Error()
	}
	_ = json.NewEncoder(os.Stdout).Encode(res)
	return 0
}

// workerLimits asks the worker binary what it can apply.
func workerLimits(exe string) (applied []string, problem string) {
	out, err := exec.Command(exe, "parse-worker", "-check").Output()
	if err != nil {
		return nil, "the worker could not start: " + err.Error()
	}
	var r struct {
		Applied []string `json:"applied"`
		Error   string   `json:"error"`
	}
	if json.Unmarshal(out, &r) != nil {
		return nil, "the worker's answer was unreadable"
	}
	return r.Applied, r.Error
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
	applied, problem := workerLimits(exe)
	hasSeccomp := false
	for _, a := range applied {
		hasSeccomp = hasSeccomp || a == "seccomp"
	}
	logger.Info("parser worker limits", "applied", strings.Join(applied, ","))
	if !hasSeccomp {
		logger.Warn("parser worker has NO system-call filter (seccomp); the other limits still apply", "reason", problem)
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
