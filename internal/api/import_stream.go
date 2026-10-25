package api

import (
	"context"
	"encoding/json"
	"fmt"

	"io"
	"os"
	"time"

	"tracefall/internal/ingest"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

// parsedSpool stages complete sources before persistence so a stopped/failed
// parser never leaves a source labelled imported. Disk, batches and host census
// are bounded separately. Both a source and all staged sources in an import
// have a 1 GiB ceiling; reaching either is a disclosed parse failure, never
// successful EOF. Completed staging retains a closed file handle for its path
// only; each reader reopens it for the duration of one persistence pass.
type parsedSpool struct {
	budget  *stagingBudget
	file    *os.File
	bytes   int64
	count   int
	hosts   map[string]bool
	summary []model.Event
}

type stagingBudget struct{ used, limit int64 }

func newParsedSpool(budget *stagingBudget) (*parsedSpool, error) {
	f, err := os.CreateTemp("", "tracefall-parse-*.partial")
	if err != nil {
		return nil, err
	}
	return &parsedSpool{file: f, hosts: map[string]bool{}, budget: budget}, nil
}
func (p *parsedSpool) close() {
	if p == nil {
		return
	}
	_ = p.file.Close()
	_ = os.Remove(p.file.Name())
	if p.budget != nil {
		p.budget.used -= p.bytes
		p.bytes = 0
	}
}
func (p *parsedSpool) append(b ingest.ParsedFile) error {
	data, err := json.Marshal(b)
	if err != nil {
		return err
	}
	if p.bytes+int64(len(data))+1 > 1<<30 {
		return &ingest.ProcessFailure{Reason: "parser staging reached the 1 GiB job budget; source not imported"}
	}
	size := int64(len(data)) + 1
	if p.budget != nil && size > p.budget.limit-p.budget.used {
		return &ingest.ProcessFailure{Reason: fmt.Sprintf("parser staging reached aggregate per-import byte budget (%d bytes); source not imported", p.budget.limit)}
	}
	for _, e := range b.Events {
		if !p.hosts[e.Host] {
			if len(p.hosts) >= 4096 {
				return &ingest.ProcessFailure{Reason: "parser staging exceeded host census limit; source not imported"}
			}
			p.hosts[e.Host] = true
			p.summary = append(p.summary, model.Event{Host: e.Host})
		}
	}
	if _, err = p.file.Write(append(data, '\n')); err != nil {
		return err
	}
	p.bytes += size
	if p.budget != nil {
		p.budget.used += size
	}
	p.count += len(b.Events)
	return nil
}
func (p *parsedSpool) each(visit func(ingest.ParsedFile) error) error {
	f, err := os.Open(p.file.Name())
	if err != nil {
		return err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	for {
		var b ingest.ParsedFile
		err := dec.Decode(&b)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err = visit(b); err != nil {
			return err
		}
	}
}

func (s *Service) stageStream(caseID, collectionID string, sf model.SourceFile, root string, p parsers.ArtifactParser, pc parsers.ParseContext, prog *progressSink, budget *stagingBudget) (pendingImport, error) {
	spool, err := newParsedSpool(budget)
	if err != nil {
		return pendingImport{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	// Cancellation must reach the child even during its attribution prepass,
	// when no output has yet arrived. The goroutine owns no evidence buffers.
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				if prog.cancelled() {
					cancel()
					return
				}
			}
		}
	}()
	cov, err := ingest.ParseFileStream(ctx, caseID, collectionID, sf.ID, root, sf.Path, p, pc, spool.append)
	cancel()
	<-stopped
	if err != nil {
		spool.close()
		if cov != nil && cov.LimitReached {
			return pendingImport{}, &ingest.ProcessFailure{Reason: err.Error()}
		}
		return pendingImport{}, err
	}
	if err := spool.file.Close(); err != nil {
		spool.close()
		return pendingImport{}, err
	}
	sf.ParseCoverage = cov
	return pendingImport{sourceFile: sf, events: spool.summary, spool: spool}, nil
}

func (p pendingImport) eventCount() int {
	if p.spool != nil {
		return p.spool.count
	}
	return len(p.events)
}
func (p pendingImport) eachBatch(visit func([]model.Event, []model.RawEvidence) error) error {
	if p.spool == nil {
		return visit(p.events, p.raw)
	}
	host, scope := "", ""
	for _, e := range p.events {
		if e.Extra["host_inherited_from"] != "" {
			host = e.Host
			scope = e.Extra["host_inherited_from"]
			break
		}
	}
	return p.spool.each(func(b ingest.ParsedFile) error {
		if host != "" {
			for i := range b.Events {
				if normalizeHost(b.Events[i].Host) == "" {
					markInheritedHost(&b.Events[i], host, scope)
				}
			}
		}
		return visit(b.Events, b.Raw)
	})
}
