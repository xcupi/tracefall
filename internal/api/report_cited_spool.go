package api

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"sort"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/report"
)

// reportCitedMeta contains exactly the fields explainFinding reads. It is not
// an evidence copy: displayed evidence is fetched separately, in bounded calls.
type reportCitedMeta struct {
	timestamp                        time.Time
	artifact, collection, host, user string
}

func (m reportCitedMeta) event(id string) model.Event {
	return model.Event{ID: id, Timestamp: m.timestamp, ArtifactType: m.artifact, CollectionID: m.collection, Host: m.host, User: m.user}
}

type reportCited struct {
	meta             map[string]reportCitedMeta
	display          map[string]model.Event
	key              []model.Event
	keyOmitted, rows int
}

func (c *reportCited) lookup(id string) (model.Event, bool) {
	if e, ok := c.display[id]; ok {
		return e, true
	}
	m, ok := c.meta[id]
	if !ok {
		return model.Event{}, false
	}
	return m.event(id), true
}

func spoolCitedFile(ctx context.Context, dir string, each func(func(model.Event) error) error) (file report.File, rows int, err error) {
	if err = ctx.Err(); err != nil {
		return
	}
	if err = os.MkdirAll(dir, 0755); err != nil {
		return
	}
	f, err := os.CreateTemp(dir, "cited-events-*.spool")
	if err != nil {
		return report.File{}, 0, err
	}
	path := f.Name()
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(path)
		}
	}()
	h := sha256.New()
	cw := &countWriter{w: io.MultiWriter(f, h)}
	bw := bufio.NewWriterSize(cw, 64*1024)
	rows, err = writeCitedJSON(ctx, bw, each)
	if err != nil {
		return
	}
	if err = bw.Flush(); err != nil {
		return
	}
	if err = ctx.Err(); err != nil {
		return
	}
	if err = f.Close(); err != nil {
		return
	}
	file = report.SpooledFile("cited-events.json", path, hex.EncodeToString(h.Sum(nil)), cw.n)
	return
}

func (s *Service) spoolReportCited(ctx context.Context, caseID string, ids []string, findings []model.Finding, correlations []model.Correlation) (report.File, *reportCited, error) {
	c := &reportCited{meta: map[string]reportCitedMeta{}, display: map[string]model.Event{}}
	each := func(fn func(model.Event) error) error {
		_, err := forEachReportCited(ctx, caseID, ids, s.store.EventsByIDs, func(e model.Event) error {
			c.meta[e.ID] = reportCitedMeta{e.Timestamp, e.ArtifactType, e.CollectionID, e.Host, e.User}
			return fn(e)
		})
		return err
	}
	file, rows, err := spoolCitedFile(ctx, s.reportsDir(caseID), each)
	if err != nil {
		return report.File{}, nil, err
	}
	// Until ownership passes to buildReport, this function owns the spool.
	ok := false
	defer func() {
		if !ok {
			os.Remove(file.Path)
		}
	}()
	c.rows = rows
	less := func(a, b string) bool {
		ta, tb := c.meta[a].timestamp, c.meta[b].timestamp
		if !ta.Equal(tb) {
			return ta.Before(tb)
		}
		return a < b
	}
	selected := map[string]bool{}
	for _, f := range findings {
		resolved := make([]string, 0, len(f.SupportingEvents))
		for _, id := range f.SupportingEvents {
			if _, exists := c.meta[id]; exists {
				resolved = append(resolved, id)
			}
		}
		sort.SliceStable(resolved, func(i, j int) bool { return less(resolved[i], resolved[j]) })
		if len(resolved) > maxFindingEvents {
			resolved = resolved[:maxFindingEvents]
		}
		for _, id := range resolved {
			selected[id] = true
		}
	}
	for _, cor := range correlations {
		n := 0
		for _, id := range cor.EventIDs {
			if _, exists := c.meta[id]; !exists {
				continue
			}
			selected[id] = true
			n++
			if n == maxFindingEvents {
				break
			}
		}
	}
	keys := make([]string, 0, len(c.meta))
	for id := range c.meta {
		keys = append(keys, id)
	}
	sort.Slice(keys, func(i, j int) bool { return less(keys[i], keys[j]) })
	if len(keys) > maxKeyEvents {
		c.keyOmitted = len(keys) - maxKeyEvents
		keys = keys[:maxKeyEvents]
	}
	for _, id := range keys {
		selected[id] = true
	}
	displayIDs := make([]string, 0, len(selected))
	for id := range selected {
		displayIDs = append(displayIDs, id)
	}
	sort.Strings(displayIDs)
	// forEachReportCited also enforces the case boundary on this second fetch.
	if _, err := forEachReportCited(ctx, caseID, displayIDs, s.store.EventsByIDs, func(e model.Event) error { c.display[e.ID] = e; return nil }); err != nil {
		return report.File{}, nil, err
	}
	for _, id := range keys {
		if e, exists := c.display[id]; exists {
			c.key = append(c.key, e)
		}
	}
	ok = true
	return file, c, nil
}
