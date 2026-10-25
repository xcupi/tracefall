package usnjrnl

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"tracefall/internal/model"
	"tracefall/internal/ntfs"
	"tracefall/internal/parsers"
)

// ParseStream keeps only one synchronous batch. Legacy Parse retains its event
// ceiling; import instead relies on the unchanged worker and staging budgets.
func (p Parser) ParseStream(ctx context.Context, path string, _ parsers.ParseContext, sink parsers.RecordSink) (*model.ParseCoverage, error) {
	cov := &model.ParseCoverage{}
	var batch parsers.ParseResult
	sinkFailed := false
	flush := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(batch.Events) == 0 {
			return nil
		}
		err := sink(batch)
		sinkFailed = err != nil
		batch = parsers.ParseResult{}
		return err
	}
	cancelled := func() bool { return ctx.Err() != nil || (p.cancelled != nil && p.cancelled()) }
	skippedBytes := int64(0)
	firstSkipped := int64(-1)
	gap := func(offset int64, n int) {
		if firstSkipped < 0 {
			firstSkipped = offset
		}
		skippedBytes += int64(n)
	}
	err := ntfs.ScanUsnJournal(path, ntfs.UsnScanOptions{Strict: true, NonRecordRegion: gap, Limits: p.limits, Cancelled: cancelled}, func(r ntfs.UsnRecord) error {
		cov.RecordsRead++
		if r.MajorVersion != 2 && r.MajorVersion != 3 {
			cov.Unmapped++
			return nil
		}
		if r.Timestamp.IsZero() {
			cov.Unmapped++
			return nil
		}
		e, raw := p.eventFor(r, filepath.Base(path))
		batch.Events = append(batch.Events, e)
		batch.Raw = append(batch.Raw, raw)
		cov.Mapped++
		if len(batch.Events) >= 128 {
			return flush()
		}
		return nil
	})
	if skippedBytes > 0 {
		cov.Notes = append(cov.Notes, fmt.Sprintf("USN contains %d bytes in nonzero non-record alignment words (first at offset %d); these bytes were not decoded as journal records. Source coverage is incomplete.", skippedBytes, firstSkipped))
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err == nil {
		err = flush()
	}
	if err != nil {
		cov.LimitReached = errors.Is(err, ntfs.ErrLimitExceeded) || errors.Is(err, ntfs.ErrCancelled) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
		if !cov.LimitReached && !sinkFailed {
			cov.RecordsFailed++
		}
		cov.Notes = append(cov.Notes, "USN stream did not reach complete EOF; emitted batches are partial coverage.")
	}
	return cov, err
}

var _ parsers.StreamingParser = (*Parser)(nil)
