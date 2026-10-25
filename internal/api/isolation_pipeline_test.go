package api

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"
	"tracefall/internal/model"

	"tracefall/internal/ingest"
	"tracefall/internal/parsers"
)

// The whole image pipeline (discover, extract, parse, analyze) with every parse
// in a sandboxed child process. It is the existing end-to-end test, run with the
// isolating runner, so a difference in results would fail its assertions.
func TestIsolation_PipelineEndToEnd(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	sub := ingest.Subprocess{Exe: exe, MemoryMB: 4096, Timeout: 2 * time.Minute, Sandbox: ingest.FindSandbox()}
	if sub.Sandbox == "" {
		t.Log("no sandbox here: running with process limits only")
	}
	counter := &countingRunner{inner: sub}
	ingest.SetParserRunner(counter)
	defer ingest.SetParserRunner(nil)
	TestDiskImage_PipelineIngestsAnImageEndToEnd(t)
	if n := counter.n.Load(); n == 0 {
		t.Fatal("no parse went through the child process")
	} else {
		t.Logf("%d parses ran in a child process", n)
	}
}

// countingRunner counts the parses handed to the runner it wraps.
type countingRunner struct {
	inner ingest.ParserRunner
	n     atomic.Int64
}

func (c *countingRunner) Run(p parsers.ArtifactParser, root, abs string, ctx parsers.ParseContext) (parsers.ParseResult, error) {
	c.n.Add(1)
	return c.inner.Run(p, root, abs, ctx)
}

func (c *countingRunner) RunStream(ctx context.Context, p parsers.ArtifactParser, root, abs string, pc parsers.ParseContext, sink parsers.RecordSink) (*model.ParseCoverage, error) {
	inner, ok := c.inner.(interface {
		RunStream(context.Context, parsers.ArtifactParser, string, string, parsers.ParseContext, parsers.RecordSink) (*model.ParseCoverage, error)
	})
	if !ok {
		return nil, fmt.Errorf("wrapped runner does not support streaming")
	}
	c.n.Add(1)
	return inner.RunStream(ctx, p, root, abs, pc, sink)
}

func TestIsolation_ImportOfEvidenceUsesTheChildProcess(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	sub := ingest.Subprocess{Exe: exe, MemoryMB: 4096, Timeout: 2 * time.Minute, Sandbox: ingest.FindSandbox()}
	ingest.SetParserRunner(sub)
	defer ingest.SetParserRunner(nil)
	TestDiskImage_ImportExtractsParsesAndAnalyzesRealArtifacts(t)
}
