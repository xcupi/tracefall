package ingest

import (
	"context"
	"fmt"
	"path/filepath"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

type streamRunner interface {
	RunStream(context.Context, parsers.ArtifactParser, string, string, parsers.ParseContext, parsers.RecordSink) (*model.ParseCoverage, error)
}

// ParseFileStream stamps bounded parser batches without collecting the file.
func ParseFileStream(ctx context.Context, caseID, collectionID, sourceID, root, rel string, p parsers.ArtifactParser, pc parsers.ParseContext, sink func(ParsedFile) error) (*model.ParseCoverage, error) {
	sp, ok := p.(parsers.StreamingParser)
	if !ok {
		return nil, fmt.Errorf("parser %s does not support streaming", p.Name())
	}
	pc.EvidencePath = filepath.ToSlash(rel)
	abs := filepath.Join(root, filepath.FromSlash(rel))
	consume := func(batch parsers.ParseResult) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return sink(stampResult(caseID, collectionID, sourceID, batch))
	}
	if sr, ok := runner.(streamRunner); ok {
		return sr.RunStream(ctx, p, root, abs, pc, consume)
	}
	// Never bypass a configured isolation runner that lacks the streaming protocol.
	if _, ok := runner.(inProcess); !ok {
		return nil, fmt.Errorf("configured runner does not support streaming")
	}
	return sp.ParseStream(ctx, abs, pc, consume)
}
