package ingest

import (
	"testing"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
	"tracefall/internal/parsers/mssqlxe"
)

func TestMSSQLXERegistry(t *testing.T) {
	for _, name := range []string{"capture.xel", "capture.sqlaudit", "capture.xel.xml", "capture.xel.jsonl", "capture.sqlaudit.csv"} {
		p := MatchParser(name, nil, Registry())
		if p == nil {
			t.Fatalf("no parser for %s", name)
		}
		if p.ArtifactType() != model.ArtifactMSSQLExtendedEvents && p.ArtifactType() != model.ArtifactMSSQLAudit {
			t.Fatal(p.ArtifactType())
		}
	}
}
func TestMSSQLExternalSandboxDispatch(t *testing.T) { // A non-existent Go worker must not hide a configured-reader failure.
	_, err := (Subprocess{Exe: "/nonexistent-worker"}).Run(mssqlxe.New(), "/", "/nonexistent.xel", parsers.ParseContext{})
	if err == nil {
		t.Fatal("accepted missing reader")
	}
	if _, ok := err.(*ProcessFailure); ok {
		t.Fatalf("binary routed into generic RLIMIT_AS worker: %v", err)
	}
}
