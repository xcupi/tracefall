package api

import (
	"os"
	"testing"

	"tracefall/internal/ingest"
)

// The API test binary doubles as the parser worker, so the server's pipeline
// can be tested with parsing in a child process, without building cmd.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "parse-worker" {
		_, _ = ingest.ApplyWorkerLimits()
		out := os.Stdout
		os.Stdout = os.Stderr
		if err := ingest.WorkerMain(os.Stdin, out, ClassifyParseError); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}
