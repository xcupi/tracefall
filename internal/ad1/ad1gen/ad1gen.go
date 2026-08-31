// Package ad1gen builds byte-valid, synthetic AD1v4 images -- the
// write-side companion to internal/ad1's read-only parser, used ONLY to
// produce test fixtures (internal/ad1's own tests, internal/api's AD1
// integration tests, and the checked-in sample at
// testdata/ad1_samples/DiskDrigger.ad1 used for browser verification --
// see that directory's README.md). It is never imported by Tracefall's
// production ingestion path, which only ever reads an AD1 image, never
// writes one -- AD1 images are real forensic evidence created by FTK
// Imager, and Tracefall does not create or emit them.
//
// The layout written here matches internal/ad1's documented derivation
// exactly (see that package's doc comment); the two packages share the
// same structural constants (internal/ad1.MetaFileSize,
// internal/ad1.SegmentHeaderSize, etc.) so there is one source of truth
// for the wire format, not two independently-maintained copies of it.
package ad1gen

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"tracefall/internal/ad1"
)

// File describes one file to place in a synthetic AD1 image. Directories
// are implied by '/' in Path and never listed explicitly.
type File struct {
	Path        string
	Data        []byte
	MD5, SHA1   string // hex digests AD1 itself will report as embedded metadata, or "" for neither
	Modified    time.Time
	NoMetaAtAll bool // omit even the FileSize metadata item, to exercise a reader's raw-size fallback
}

type node struct {
	name     string
	isDir    bool
	children []*node
	file     *File
}

func buildTree(files []File) *node {
	root := &node{isDir: true}
	sorted := append([]File(nil), files...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })

	for i := range sorted {
		f := &sorted[i]
		parts := strings.Split(f.Path, "/")
		cur := root
		for i, part := range parts {
			isLast := i == len(parts)-1
			var child *node
			for _, c := range cur.children {
				if c.name == part {
					child = c
					break
				}
			}
			if child == nil {
				child = &node{name: part, isDir: !isLast}
				cur.children = append(cur.children, child)
			}
			if isLast {
				child.file = f
			}
			cur = child
		}
	}
	return root
}

type builder struct {
	buf       bytes.Buffer
	chunkSize uint32
}

func (b *builder) off() int64          { return int64(b.buf.Len()) }
func (b *builder) putU64(v uint64)     { binary.Write(&b.buf, binary.LittleEndian, v) }
func (b *builder) putU32(v uint32)     { binary.Write(&b.buf, binary.LittleEndian, v) }
func (b *builder) writeStr(s string)   { b.buf.WriteString(s) }
func (b *builder) writeBytes(p []byte) { b.buf.Write(p) }

// writeMetaChain writes a linked list of FileMeta entries for a file (or
// nothing, offset 0, if there's nothing to record) and returns the
// offset of the first one.
func (b *builder) writeMetaChain(f *File) uint64 {
	type item struct {
		typ  uint32
		data []byte
	}
	var items []item
	if !f.NoMetaAtAll {
		items = append(items, item{ad1.MetaFileSize, []byte(strconv.Itoa(len(f.Data)))})
		if !f.Modified.IsZero() {
			items = append(items, item{ad1.MetaDateModified, []byte(f.Modified.UTC().Format("20060102T150405.000000"))})
		}
	}
	if f.MD5 != "" {
		items = append(items, item{ad1.MetaMD5, []byte(f.MD5)})
	}
	if f.SHA1 != "" {
		items = append(items, item{ad1.MetaSHA1, []byte(f.SHA1)})
	}
	if len(items) == 0 {
		return 0
	}

	offsets := make([]int64, len(items))
	for i, it := range items {
		offsets[i] = b.off()
		b.putU64(0) // next -- patched below
		b.putU32(0) // category
		b.putU32(it.typ)
		b.putU32(uint32(len(it.data)))
		b.writeBytes(it.data)
	}
	raw := b.buf.Bytes()
	for i := 0; i < len(items)-1; i++ {
		binary.LittleEndian.PutUint64(raw[offsets[i]:], uint64(offsets[i+1]))
	}
	return uint64(offsets[0])
}

// writeChunkData zlib-compresses data in chunkSize-sized pieces and
// writes just the compressed bytes (no table yet -- see writeChunkTable),
// returning each chunk's start offset. A reader treats the entry's
// metadata offset as the trailing boundary for the LAST chunk's
// compressed size, which only works if the metadata chain is written
// immediately after the chunk data ends -- so callers must write the
// metadata chain next, never before the chunk data.
func (b *builder) writeChunkData(data []byte, chunkSize uint32) []int64 {
	var chunkOffsets []int64
	for len(data) > 0 {
		n := int(chunkSize)
		if n > len(data) {
			n = len(data)
		}
		piece := data[:n]
		data = data[n:]

		chunkOffsets = append(chunkOffsets, b.off())
		var zbuf bytes.Buffer
		zw := zlib.NewWriter(&zbuf)
		zw.Write(piece)
		zw.Close()
		b.writeBytes(zbuf.Bytes())
	}
	return chunkOffsets
}

// writeChunkTable writes the num_chunks + chunks[] table and returns its
// own offset -- position-independent, addressed only by that offset.
func (b *builder) writeChunkTable(chunkOffsets []int64) uint64 {
	tableOff := b.off()
	b.putU64(uint64(len(chunkOffsets)))
	for _, o := range chunkOffsets {
		b.putU64(uint64(o))
	}
	return uint64(tableOff)
}

// writeEntry recursively serializes n (and, for a directory, every
// descendant) and returns its own offset, suitable for use as a parent's
// child or a sibling's next.
func (b *builder) writeEntry(n *node, nextSibling uint64) uint64 {
	myOff := b.off()

	entryType := uint32(ad1.EntryTypeFile)
	if n.isDir {
		entryType = uint32(ad1.EntryTypeDirectory)
	}
	nameBytes := []byte(n.name)

	headerOff := b.off()
	b.putU64(nextSibling) // next
	b.putU64(0)           // child -- patched
	b.putU64(0)           // meta -- patched
	b.putU64(0)           // zlib_meta -- patched
	b.putU64(0)           // size -- patched
	b.putU32(entryType)
	b.putU32(uint32(len(nameBytes)))
	b.writeBytes(nameBytes)
	b.putU64(0) // parent_index -- not read by internal/ad1, written for structural fidelity only

	var childOff, metaOff, zlibMetaOff, size uint64

	if n.isDir {
		// Children are linked via `next`; write back-to-front so each
		// child's `next` can point at the already-known offset of the
		// one written just before it in path order (see the package doc
		// comment -- offsets are independent of on-disk write order in
		// this format).
		var prev uint64
		childOffsets := make([]uint64, len(n.children))
		for i := len(n.children) - 1; i >= 0; i-- {
			off := b.writeEntry(n.children[i], prev)
			childOffsets[i] = off
			prev = off
		}
		if len(n.children) > 0 {
			childOff = childOffsets[0]
		}
	} else {
		f := n.file
		size = uint64(len(f.Data))
		if size > 0 {
			chunkOffsets := b.writeChunkData(f.Data, b.chunkSize)
			metaOff = b.writeMetaChain(f)
			zlibMetaOff = b.writeChunkTable(chunkOffsets)
		} else {
			metaOff = b.writeMetaChain(f)
		}
	}

	raw := b.buf.Bytes()
	binary.LittleEndian.PutUint64(raw[headerOff+8:], childOff)
	binary.LittleEndian.PutUint64(raw[headerOff+16:], metaOff)
	binary.LittleEndian.PutUint64(raw[headerOff+24:], zlibMetaOff)
	binary.LittleEndian.PutUint64(raw[headerOff+32:], size)

	return uint64(myOff)
}

func padTo(s string, n int) string {
	b := make([]byte, n)
	copy(b, s)
	return string(b)
}

// Build returns a complete, single-segment, valid AD1v4 image
// (SegmentedFileHeader + LogicalImageHeader + file tree) containing
// files, with root declared as rootName (e.g. `C:\Users\jdoe\Desktop`).
// chunkSize of 0 defaults to 4096.
func Build(rootName string, files []File, chunkSize uint32) ([]byte, error) {
	if chunkSize == 0 {
		chunkSize = 4096
	}

	tree := buildTree(files)
	b := &builder{chunkSize: chunkSize}

	// Every FileEntry/FileMeta/chunk offset is relative to the stitched
	// logical stream, whose offset 0 is the start of the
	// LogicalImageHeader itself -- see internal/ad1's package doc
	// comment. So the header is written into b.buf first, and the tree
	// is appended to that same buffer.
	nameBytes := []byte(rootName)
	logicalImageHeaderLen := int64(ad1.LogicalImageFixedSize) + int64(len(nameBytes))
	b.writeStr(padTo(ad1.LogicalImageMagicText, 16))
	b.putU32(4)         // version
	b.putU32(1)         // unk1
	b.putU32(chunkSize) // chunk_size
	b.putU64(0)         // metadata_offset (unused by internal/ad1)
	firstFileOffsetFieldPos := b.off()
	b.putU64(0) // first_file_offset -- patched below
	b.putU32(uint32(len(nameBytes)))
	b.writeStr(padTo("AD", 4))
	b.putU64(0x5c) // name_offset
	b.putU64(0)    // attr_guid_offset
	b.putU64(0)    // unk2
	b.putU64(0)    // locs_guid_offset
	b.putU64(0)    // unk3
	b.writeBytes(nameBytes)
	if b.off() != logicalImageHeaderLen {
		return nil, fmt.Errorf("ad1gen: internal error: logical image header length mismatch (wrote %d, expected %d)", b.off(), logicalImageHeaderLen)
	}

	var prev uint64
	rootChildOffsets := make([]uint64, len(tree.children))
	for i := len(tree.children) - 1; i >= 0; i-- {
		off := b.writeEntry(tree.children[i], prev)
		rootChildOffsets[i] = off
		prev = off
	}
	var firstFileOffset uint64
	if len(rootChildOffsets) > 0 {
		firstFileOffset = rootChildOffsets[0]
	}
	raw := b.buf.Bytes()
	binary.LittleEndian.PutUint64(raw[firstFileOffsetFieldPos:], firstFileOffset)

	payload := b.buf.Bytes()

	var seg bytes.Buffer
	seg.WriteString(padTo(ad1.SegmentedFileMagicText, 16))
	binary.Write(&seg, binary.LittleEndian, uint32(1))                                  // unk1
	binary.Write(&seg, binary.LittleEndian, uint32(2))                                  // unk2
	binary.Write(&seg, binary.LittleEndian, uint32(1))                                  // segment_number
	binary.Write(&seg, binary.LittleEndian, uint32(1))                                  // segment_count
	binary.Write(&seg, binary.LittleEndian, uint64(ad1.SegmentHeaderSize+len(payload))) // segment_size
	binary.Write(&seg, binary.LittleEndian, uint32(ad1.SegmentHeaderSize))              // logical_image_offset (a raw file offset -- see internal/ad1's Open)
	seg.Write(make([]byte, 468))                                                        // padding
	seg.Write(payload)

	if seg.Len() != ad1.SegmentHeaderSize+len(payload) {
		return nil, fmt.Errorf("ad1gen: internal error: segment size mismatch (got %d, want %d)", seg.Len(), ad1.SegmentHeaderSize+len(payload))
	}
	return seg.Bytes(), nil
}
