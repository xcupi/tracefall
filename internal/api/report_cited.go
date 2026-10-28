package api

import (
	"context"
	"encoding/json"
	"io"
	"sort"
	"strings"
	"tracefall/internal/model"
)

// forEachReportCited preserves EventsByIDs' historical per-500-IN-query
// multiplicity, but emits the final ID-sorted multiset without retaining rows.
// Only identifier metadata grows with the reference set; each full-row fetch
// is bounded independently of the number of citations.
func forEachReportCited(ctx context.Context, caseID string, ids []string, fetch func([]string) ([]model.Event, error), visit func(model.Event) error) (int, error) {
	counts := map[string]int{}
	seen := map[string]bool{}
	offset := 0
	for _, raw := range ids {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}
		if offset%500 == 0 {
			clear(seen)
		}
		if !seen[id] {
			counts[id]++
			seen[id] = true
		}
		offset++
	}
	keys := make([]string, 0, len(counts))
	for id := range counts {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	n := 0
	for start := 0; start < len(keys); start += 500 {
		if err := ctx.Err(); err != nil {
			return n, err
		}
		end := start + 500
		if end > len(keys) {
			end = len(keys)
		}
		events, err := fetch(keys[start:end])
		if err != nil {
			return n, err
		}
		sort.Slice(events, func(i, j int) bool { return events[i].ID < events[j].ID })
		for _, e := range events {
			if err := ctx.Err(); err != nil {
				return n, err
			}
			if e.CaseID != caseID {
				continue
			}
			for i := 0; i < counts[e.ID]; i++ {
				if err := ctx.Err(); err != nil {
					return n, err
				}
				if err := visit(e); err != nil {
					return n, err
				}
				n++
			}
		}
	}
	return n, ctx.Err()
}

// writeCitedJSON is byte-identical to MarshalIndent of a non-nil []Event.
// Marshal one object at a time, retaining Go's escaping and custom marshaler
// errors. A short write is an error even for a writer returning nil error.
func writeCitedJSON(ctx context.Context, w io.Writer, each func(func(model.Event) error) error) (int, error) {
	write := func(p []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := w.Write(p)
		if err == nil && n != len(p) {
			err = io.ErrShortWrite
		}
		return err
	}
	if err := write([]byte("[")); err != nil {
		return 0, err
	}
	n := 0
	err := each(func(e model.Event) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b, err := json.MarshalIndent(e, "  ", "  ")
		if err != nil {
			return err
		}
		sep := "\n  "
		if n > 0 {
			sep = ",\n  "
		}
		if err := write([]byte(sep)); err != nil {
			return err
		}
		if err := write(b); err != nil {
			return err
		}
		n++
		return nil
	})
	if err != nil {
		return n, err
	}
	end := "]"
	if n > 0 {
		end = "\n]"
	}
	return n, write([]byte(end))
}
