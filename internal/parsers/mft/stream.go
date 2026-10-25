package mft

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"tracefall/internal/model"
	"tracefall/internal/ntfs"
	"tracefall/internal/parsers"
)

// directoryReader uses read-only random access plus a fixed 4096-entry LRU,
// not a directory-cardinality-sized map. Every edge checks the recorded sequence.
type directoryReader struct {
	f      *os.File
	stride int
	size   int64
	limits ntfs.Limits
	cache  map[uint64]*list.Element
	lru    *list.List
}
type directoryEntry struct {
	number   uint64
	sequence uint16
	name     ntfs.FileName
	valid    bool
}

func openDirectories(path string, lim ntfs.Limits) (*directoryReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*directoryReader, error) { f.Close(); return nil, err }
	st, err := f.Stat()
	if err != nil {
		return fail(err)
	}
	if st.Size() > lim.MaxFileBytes {
		return fail(ntfs.ErrLimitExceeded)
	}
	b := make([]byte, 64<<10)
	n, err := f.ReadAt(b, 0)
	if err != nil && err != io.EOF {
		return fail(err)
	}
	b = b[:n]
	stride := 0
	for off := 0; off+48 <= len(b); off += 512 {
		if ntfs.Sniff(b[off:]) {
			s, e := ntfs.DetectRecordSize(b[off:])
			if e == nil && off%s == 0 {
				stride = s
				break
			}
		}
	}
	if stride == 0 {
		return fail(ntfs.ErrNotMFT)
	}
	if st.Size()%int64(stride) != 0 {
		return fail(fmt.Errorf("%w: trailing partial MFT slot", ntfs.ErrCorrupt))
	}
	return &directoryReader{f: f, stride: stride, size: st.Size(), limits: lim, cache: map[uint64]*list.Element{}, lru: list.New()}, nil
}
func (d *directoryReader) get(number uint64) directoryEntry {
	if el := d.cache[number]; el != nil {
		d.lru.MoveToFront(el)
		return el.Value.(directoryEntry)
	}
	e := directoryEntry{number: number}
	if number < uint64(d.size/int64(d.stride)) {
		b := make([]byte, d.stride)
		if _, err := d.f.ReadAt(b, int64(number)*int64(d.stride)); err == nil {
			r, ok, err := ntfs.ParseRecord(b, number, d.limits)
			if err == nil && ok && len(r.Warnings) == 0 && r.IsDirectory && r.IsBaseRecord() {
				e.name, e.valid = r.BestName()
				e.sequence = r.SequenceNumber
			}
		}
	}
	if len(d.cache) >= 4096 {
		el := d.lru.Back()
		delete(d.cache, el.Value.(directoryEntry).number)
		d.lru.Remove(el)
	}
	d.cache[number] = d.lru.PushFront(e)
	return e
}
func (d *directoryReader) path(ctx context.Context, n ntfs.FileName) (string, bool, error) {
	parts := []string{n.Name}
	seen := map[uint64]bool{}
	finish := func(prefix string) string {
		for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
			parts[i], parts[j] = parts[j], parts[i]
		}
		return prefix + strings.Join(parts, "\\")
	}
	current, seq := n.ParentRef, n.ParentSeq
	for depth := 0; depth < 256; depth++ {
		if err := ctx.Err(); err != nil {
			return "", false, err
		}
		if seen[current] {
			return finish("<cycle>\\"), false, nil
		}
		seen[current] = true
		e := d.get(current)
		if !e.valid || e.sequence != seq {
			return finish(fmt.Sprintf("<unresolved:%d>\\", current)), false, nil
		}
		if current == ntfs.RootRecordNumber {
			return finish("\\"), true, nil
		}
		parts = append(parts, e.name.Name)
		current, seq = e.name.ParentRef, e.name.ParentSeq
	}
	return finish("<depth-limit>\\"), false, nil
}

// ParseStream emits every eligible base record, with no in-memory result or
// event-count truncation. The existing byte, process, deadline, transport and
// staging ceilings remain authoritative. Slot count is derived from the byte
// ceiling (minimum valid stride 512), not a memory-retention ceiling.
func (p Parser) ParseStream(ctx context.Context, path string, _ parsers.ParseContext, sink parsers.RecordSink) (*model.ParseCoverage, error) {
	emitted := 0
	cov := &model.ParseCoverage{EmittedEvents: &emitted}
	lim := p.limits
	lim.StrictNames = true
	lim.MaxRecords = int(lim.MaxFileBytes/512) + 1
	d, err := openDirectories(path, lim)
	if err != nil {
		cov.RecordsFailed++
		return cov, err
	}
	defer d.f.Close()
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
	err = ntfs.Scan(path, ntfs.ScanOptions{Strict: true, Limits: lim, Cancelled: cancelled}, func(r ntfs.Record) error {
		cov.RecordsRead++
		if len(r.Warnings) > 0 {
			return fmt.Errorf("%w: MFT record %d: %s", ntfs.ErrCorrupt, r.RecordNumber, strings.Join(r.Warnings, "; "))
		}
		n, ok := r.BestName()
		if !r.IsBaseRecord() || !ok || !r.HasSI || !r.SI.Any() {
			cov.Unmapped++
			return nil
		}
		full, complete, err := d.path(ctx, n)
		if err != nil {
			return err
		}
		events, raw := p.eventsFor(r, n, full, complete, filepath.Base(path))
		for i := range events {
			events[i].Extra["mft_record_offset"] = strconv.FormatUint(r.RecordNumber*uint64(d.stride), 10)
			events[i].Extra["mft_record_size"] = strconv.Itoa(d.stride)
		}
		if len(batch.Events)+len(events) > 128 {
			if err := flush(); err != nil {
				return err
			}
		}
		cov.Mapped++
		emitted += len(events)
		batch.Events = append(batch.Events, events...)
		batch.Raw = append(batch.Raw, raw...)
		if len(batch.Events) >= 128 {
			return flush()
		}
		return nil
	})
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err == nil {
		err = flush()
	}
	if err != nil {
		cov.LimitReached = errors.Is(err, ntfs.ErrLimitExceeded) || errors.Is(err, ntfs.ErrCancelled) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
		if !sinkFailed && !cov.LimitReached {
			cov.RecordsFailed++
		}
		cov.Notes = append(cov.Notes, "MFT stream did not reach complete EOF; emitted batches are partial coverage.")
	}
	return cov, err
}

var _ parsers.StreamingParser = (*Parser)(nil)
