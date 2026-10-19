package api

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
)

var spoolSeq atomic.Uint64

// spoolTimeline writes the case's timeline CSV to a file in dir and returns the
// file's path, SHA-256 and size. The digest is computed while the CSV is
// written, so the content is never held in memory. The caller owns the file
// and removes it once the bundle is written.
func (s *Service) spoolTimeline(caseID, dir string) (path string, agg *timelineAgg, sum string, size int64, err error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", nil, "", 0, err
	}
	name := "timeline-" + strconv.FormatUint(spoolSeq.Add(1), 10) + "-" + strconv.FormatInt(int64(os.Getpid()), 10) + ".spool"
	path = filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", nil, "", 0, err
	}
	h := sha256.New()
	counter := &countWriter{w: io.MultiWriter(f, h)}
	agg, err = s.streamTimeline(caseID, counter)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
		return "", nil, "", 0, err
	}
	return path, agg, hex.EncodeToString(h.Sum(nil)), counter.n, nil
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
