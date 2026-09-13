package ad1

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const chunkOffsetSize = 8

// chunkTable returns the byte offsets (in the stitched logical stream)
// that bound each of entry's zlib-compressed chunks, plus one trailing
// boundary so the last chunk's compressed length is computable by
// subtraction -- mirrors the reference implementation's FileStream
// construction (see the package doc comment): the chunk table lives at
// entry.zlibMeta, and the entry's first FileMeta offset immediately
// follows the last chunk's compressed data, so it doubles as that
// trailing boundary.
func (c *Container) chunkTable(entry Entry) ([]int64, error) {
	if entry.rawSize == 0 {
		return nil, nil // no data -- see Extract's zero-length short-circuit
	}
	sr := c.reader()

	hdr := make([]byte, chunkOffsetSize)
	if _, err := sr.ReadAt(hdr, int64(entry.zlibMeta)); err != nil {
		return nil, fmt.Errorf("%w: reading chunk count at %d: %v", ErrCorrupt, entry.zlibMeta, err)
	}
	numChunks := binary.LittleEndian.Uint64(hdr)
	// A chunk per byte of chunk_size would already be an ~impossibly
	// fragmented file; bounding by declared size / a sane minimum chunk
	// size (rather than trusting numChunks directly) rejects a hostile
	// value before the multiplication below can overflow or allocate
	// absurdly.
	if numChunks > uint64(c.limits.MaxEntries) {
		return nil, fmt.Errorf("%w: chunk count %d is implausible", ErrLimitExceeded, numChunks)
	}

	raw := make([]byte, int(numChunks)*chunkOffsetSize)
	if numChunks > 0 {
		if _, err := sr.ReadAt(raw, int64(entry.zlibMeta)+chunkOffsetSize); err != nil {
			return nil, fmt.Errorf("%w: reading chunk table at %d: %v", ErrCorrupt, entry.zlibMeta, err)
		}
	}

	offsets := make([]int64, 0, numChunks+1)
	for i := 0; i < int(numChunks); i++ {
		off := binary.LittleEndian.Uint64(raw[i*chunkOffsetSize : (i+1)*chunkOffsetSize])
		if int64(off) < 0 || int64(off) > c.streamLen {
			return nil, fmt.Errorf("%w: chunk offset %d out of bounds", ErrCorrupt, off)
		}
		offsets = append(offsets, int64(off))
	}
	// The trailing boundary: the entry's first metadata item immediately
	// follows its last compressed chunk in the file layout. Entries with
	// no metadata at all (meta == 0) can't happen for a file with data --
	// AD1 always records at least a FileSize/timestamp -- but guard
	// anyway rather than trust that invariant against a hostile input.
	fe, err := c.entryAt(entry.entryOffset)
	if err != nil {
		return nil, err
	}
	if fe.meta == 0 {
		return nil, fmt.Errorf("%w: file entry has data but no trailing metadata boundary", ErrCorrupt)
	}
	if int64(fe.meta) < 0 || int64(fe.meta) > c.streamLen {
		return nil, fmt.Errorf("%w: metadata boundary %d out of bounds", ErrCorrupt, fe.meta)
	}
	offsets = append(offsets, int64(fe.meta))
	return offsets, nil
}

// entryAt re-reads the raw file entry at off -- used by chunkTable and
// Extract, which only have the public Entry (no exported raw offsets
// data) to work from.
func (c *Container) entryAt(off int64) (rawFileEntry, error) {
	return readRawFileEntry(c.reader(), off, c.limits)
}

// Extract writes entry's decompressed content to w, in chunk order. It
// never reads more of the AD1 image into memory than one compressed
// chunk at a time (bounded by the image's declared chunk_size), and never
// writes more than Limits.MaxFileBytes total to w regardless of what the
// entry's own metadata or chunk table claim -- a hostile or corrupt chunk
// that decompresses far larger than declared is truncated and reported
// as ErrLimitExceeded rather than exhausted into an unbounded write, the
// same zlib-bomb defense internal/archive applies to a zip entry.
//
// entry must be one produced by this same Container's Walk (it carries
// an internal offset Walk resolved) -- calling Extract with an Entry from
// a different Container is a programming error, not a data error.
// ExtractPrefix returns at most n leading bytes of entry's decompressed
// content, decompressing only as many chunks as that needs -- normally
// exactly one.
//
// It exists so cataloging can identify an entry by its CONTENT without
// paying to decompress the whole file. A registry hive renamed inside a
// triage image is otherwise invisible: AD1 cataloging cannot stat a file
// or read a header the way directory ingestion can, so it had only the
// name to go on, and a renamed hive was catalogued as unsupported.
func (c *Container) ExtractPrefix(entry Entry, n int) ([]byte, error) {
	if entry.IsDir || entry.rawSize == 0 || n <= 0 {
		return nil, nil
	}
	var buf bytes.Buffer
	// The writer stops accepting once it has n bytes, so Extract's chunk
	// loop ends after the first chunk for any sane n.
	_, err := c.Extract(entry, &prefixWriter{buf: &buf, limit: n})
	if buf.Len() > 0 {
		// A short read is still a usable header; the error (if any) is
		// about the REST of the file, which this call does not want.
		return buf.Bytes(), nil
	}
	if errors.Is(err, errPrefixFull) {
		return buf.Bytes(), nil
	}
	return nil, err
}

var errPrefixFull = errors.New("ad1: prefix complete")

// prefixWriter accepts up to limit bytes and then refuses, which stops
// Extract's chunk loop without it needing to know about prefixes.
type prefixWriter struct {
	buf   *bytes.Buffer
	limit int
}

func (w *prefixWriter) Write(p []byte) (int, error) {
	room := w.limit - w.buf.Len()
	if room <= 0 {
		return 0, errPrefixFull
	}
	if len(p) > room {
		w.buf.Write(p[:room])
		return len(p), errPrefixFull
	}
	w.buf.Write(p)
	return len(p), nil
}

func (c *Container) Extract(entry Entry, w io.Writer) (int64, error) {
	if entry.IsDir {
		return 0, fmt.Errorf("%w: %q is a directory", ErrCorrupt, entry.Path)
	}
	if entry.rawSize == 0 {
		return 0, nil
	}

	offsets, err := c.chunkTable(entry)
	if err != nil {
		return 0, err
	}
	if len(offsets) < 2 {
		// rawSize != 0 but no chunks recorded -- inconsistent, don't
		// silently report a zero-byte file for something that claims to
		// have content.
		return 0, fmt.Errorf("%w: %q declares data but has no chunk table", ErrCorrupt, entry.Path)
	}

	sr := c.reader()
	var written int64
	limit := c.limits.MaxFileBytes

	for i := 0; i < len(offsets)-1; i++ {
		start, end := offsets[i], offsets[i+1]
		if end < start {
			return written, fmt.Errorf("%w: chunk %d has negative length", ErrCorrupt, i)
		}
		compressed := make([]byte, end-start)
		if len(compressed) > 0 {
			if _, err := sr.ReadAt(compressed, start); err != nil {
				return written, fmt.Errorf("%w: reading chunk %d: %v", ErrCorrupt, i, err)
			}
		}

		zr, err := zlib.NewReader(bytes.NewReader(compressed))
		if err != nil {
			return written, fmt.Errorf("%w: chunk %d is not valid zlib data: %v", ErrCorrupt, i, err)
		}
		remaining := limit - written
		if remaining <= 0 {
			zr.Close()
			return written, fmt.Errorf("%w: %q exceeds per-file limit %d bytes", ErrLimitExceeded, entry.Path, limit)
		}
		n, copyErr := io.Copy(w, io.LimitReader(zr, remaining+1))
		written += n
		closeErr := zr.Close()
		if copyErr != nil && !errors.Is(copyErr, io.EOF) {
			return written, fmt.Errorf("%w: decompressing chunk %d: %v", ErrCorrupt, i, copyErr)
		}
		if closeErr != nil {
			return written, fmt.Errorf("%w: chunk %d: %v", ErrCorrupt, i, closeErr)
		}
		if written > limit {
			return written, fmt.Errorf("%w: %q exceeds per-file limit %d bytes (declared size was inaccurate)", ErrLimitExceeded, entry.Path, limit)
		}
	}
	return written, nil
}
