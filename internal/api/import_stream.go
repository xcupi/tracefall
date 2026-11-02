package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
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
	compressed bool
	compressor *gzip.Writer
	buffer     bytes.Buffer
	budget     *stagingBudget
	file       *os.File
	bytes      int64
	count      int
	hosts      map[string]bool
	summary    []model.Event
}

type stagingBudget struct{ used, limit int64 }

func newParsedSpool(budget *stagingBudget, artifact ...string) (*parsedSpool, error) {
	return newParsedSpoolIn("", budget, artifact...)
}

func newParsedSpoolIn(dir string, budget *stagingBudget, artifact ...string) (*parsedSpool, error) {
	f, err := os.CreateTemp(dir, "tracefall-parse-*.partial")
	if err != nil {
		return nil, err
	}
	p := &parsedSpool{file: f, hosts: map[string]bool{}, budget: budget}
	if len(artifact) > 0 && (artifact[0] == model.ArtifactMFT || artifact[0] == model.ArtifactUsnJournal || artifact[0] == model.ArtifactSRUM) {
		p.compressed = true
		p.compressor = gzip.NewWriter(&p.buffer)
	}
	return p, nil
}
func (p *parsedSpool) finishWrite() error {
	err := p.file.Close()
	p.compressor = nil
	p.buffer = bytes.Buffer{}
	return err
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
	if p.compressed {
		if len(data) > 16<<20 {
			return &ingest.ProcessFailure{Reason: "decoded staging batch exceeds 16 MiB"}
		}
		p.buffer.Reset()
		p.compressor.Reset(&p.buffer)
		if _, err = p.compressor.Write(append(data, '\n')); err != nil {
			return err
		}
		if err = p.compressor.Close(); err != nil {
			return err
		}
		data = p.buffer.Bytes()
	} else {
		data = append(data, '\n')
	}
	if p.bytes+int64(len(data)) > 1<<30 {
		return &ingest.ProcessFailure{Reason: "parser staging reached the 1 GiB job budget; source not imported"}
	}
	size := int64(len(data))
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
	if _, err = p.file.Write(data); err != nil {
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
	var reader io.Reader = f
	if p.compressed {
		z, err := gzip.NewReader(f)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		defer z.Close()
		reader = z
	}
	dec := json.NewDecoder(reader)
	// Native transport batches stay small for pipe backpressure. Coalesce only
	// during persistence to amortize commits, with independent 1024-event and
	// 16 MiB decoded-serialization bounds; never collect a complete source.
	var pending ingest.ParsedFile
	var pendingBytes int64
	flush := func() error {
		if len(pending.Events) == 0 && len(pending.Raw) == 0 {
			return nil
		}
		err := visit(pending)
		pending = ingest.ParsedFile{}
		pendingBytes = 0
		return err
	}
	for {
		var b ingest.ParsedFile
		before := dec.InputOffset()
		err := dec.Decode(&b)
		if err == io.EOF {
			return flush()
		}
		if err != nil {
			return err
		}
		if !p.compressed || b.Coverage != nil {
			if err := flush(); err != nil {
				return err
			}
			if err = visit(b); err != nil {
				return err
			}
			continue
		}
		size := dec.InputOffset() - before
		if len(pending.Events)+len(b.Events) > 1024 || pendingBytes+size > 16<<20 {
			if err := flush(); err != nil {
				return err
			}
		}
		pending.Events = append(pending.Events, b.Events...)
		pending.Raw = append(pending.Raw, b.Raw...)
		pendingBytes += size
	}
}

func (s *Service) stageStream(caseID, collectionID string, sf model.SourceFile, root string, p parsers.ArtifactParser, pc parsers.ParseContext, prog *progressSink, budget *stagingBudget) (pendingImport, error) {
	spool, err := newParsedSpoolIn(s.parserStagingDir, budget, sf.ArtifactType)
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
			err = &ingest.ProcessFailure{Reason: err.Error()}
		}
		if cov != nil && cov.Ntfs != nil && cov.Ntfs.Failed {
			// Keep what the parser measured: a failed NTFS source stays
			// explainable (class, offset, bytes) instead of reading as nothing.
			return pendingImport{}, &coverageFailure{err: err, cov: cov}
		}
		return pendingImport{}, err
	}
	if err := spool.finishWrite(); err != nil {
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

// coverageFailure carries the parser's coverage alongside a failed source.
type coverageFailure struct {
	err error
	cov *model.ParseCoverage
}

func (e *coverageFailure) Error() string { return e.err.Error() }
func (e *coverageFailure) Unwrap() error { return e.err }

// markStagedFailure marks a source failed, keeping coverage when the failure
// carried it.
func (s *Service) markStagedFailure(id string, err error) {
	var cf *coverageFailure
	if errors.As(err, &cf) {
		_ = s.store.MarkSourceFileFailedWithCoverage(id, cf.cov)
		return
	}
	_ = s.store.MarkSourceFileFailed(id)
}
