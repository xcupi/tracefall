package main

import (
	"log/slog"
	"os"
	"strconv"

	"tracefall/internal/api"
)

// serverCapacity is how much expensive work the server does at once. Memory is
// bounded by these numbers instead of by how many requests arrive.
type serverCapacity struct {
	// Imports is how many evidence imports run at once. An import holds every
	// event of the files it parses until they are saved.
	Imports int
	// HeavyOps is how many report builds or analyses run at once.
	HeavyOps int
	// ParserWorkers is how many parser worker processes run at once, across
	// all imports. Each may use up to the worker memory limit.
	ParserWorkers int
}

// serverCapacityFromEnv reads the limits. A value that is not a positive number
// is ignored, not trusted: the default is the safe side.
func serverCapacityFromEnv() serverCapacity {
	c := serverCapacity{Imports: api.DefaultImports, HeavyOps: api.DefaultHeavyOps}
	if v := positiveEnv("TRACEFALL_MAX_IMPORTS"); v > 0 {
		c.Imports = v
	}
	if v := positiveEnv("TRACEFALL_MAX_HEAVY_OPS"); v > 0 {
		c.HeavyOps = v
	}
	// Each import parses one file at a time, so by default the workers never
	// outnumber the imports; raise it to allow more parses beside them.
	c.ParserWorkers = c.Imports
	if v := positiveEnv("TRACEFALL_PARSER_CONCURRENCY"); v > 0 {
		c.ParserWorkers = v
	}
	return c
}

func positiveEnv(name string) int {
	n, err := strconv.Atoi(os.Getenv(name))
	if err != nil || n < 1 {
		return 0
	}
	return n
}

func (c serverCapacity) apply(svc *api.Service, logger *slog.Logger) {
	svc.SetImportLimit(c.Imports)
	svc.SetHeavyLimit(c.HeavyOps)
	logger.Info("server capacity",
		"max_imports", c.Imports, "max_report_or_analysis", c.HeavyOps, "max_parser_workers", c.ParserWorkers)
}
