// Package ext4 reads ext2, ext3 and ext4 file systems, read-only. It lists the
// in-use directory tree (files, directories, symbolic links) and reads file
// content through the extent tree (ext4) or the block map (ext2 and ext3).
//
// Not read, and reported as ErrUnsupported rather than guessed around:
// meta_bg group layouts, inline data (content stored in the inode or its
// extended attributes), encrypted files, and inodes whose extents are
// damaged. Deleted inodes are not listed; only names reachable from the root
// are. Metadata checksums are not verified. A set needs_recovery flag is
// reported as a note: journal transactions that were not replayed are not
// applied, so the on-disk state is what is read.
package ext4

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"tracefall/internal/fsvol"
)

// ErrNotExt means the bytes are not an ext2, ext3 or ext4 file system.
var ErrNotExt = errors.New("not an ext2/3/4 file system")

const (
	superOffset  = 1024
	superSize    = 1024
	extMagic     = 0xEF53
	rootIno      = 2
	extentMagic  = 0xF30A
	maxBlockSize = 64 * 1024
	maxExtents   = 4_000_000
	maxDepth     = 5
	maxGDTBytes  = 16 << 20
	iBlockSize   = 60 // the inode's i_block array, in bytes

	incompatFiletype = 0x2
	incompatRecover  = 0x4
	incompatMetaBG   = 0x10
	incompatExtents  = 0x40
	incompat64bit    = 0x80
	incompatFlexBG   = 0x200
	incompatInline   = 0x8000
	compatHasJournal = 0x4

	flagEncrypt = 0x800
	flagExtents = 0x80000
	flagInline  = 0x10000000

	modeTypeMask = 0xF000
	modeDir      = 0x4000
	modeReg      = 0x8000
	modeSymlink  = 0xA000
)

// Volume is an opened ext2/3/4 file system. It implements fsvol.Volume.
type Volume struct {
	r      io.ReaderAt
	size   int64
	info   fsvol.Info
	bs     int64
	isize  int64 // inode size
	ipg    uint64
	inodes uint64
	blocks uint64
	first  uint64
	itable []uint64 // inode table block of each group
	// Notes records conditions the reader saw but did not act on.
	Notes []string
	// Version is "ext2", "ext3" or "ext4", from the superblock's feature flags.
	Version string
}

// Open opens the file system at the start of r, size bytes long.
func Open(r io.ReaderAt, size int64) (*Volume, error) {
	if size < superOffset+superSize {
		return nil, ErrNotExt
	}
	sb := make([]byte, superSize)
	if n, err := r.ReadAt(sb, superOffset); n < superSize {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return nil, fmt.Errorf("reading the superblock: %w", err)
	}
	if u16(sb, 56) != extMagic {
		return nil, ErrNotExt
	}
	logBS := u32(sb, 24)
	if logBS > 6 {
		return nil, corrupt("block size exponent %d", logBS)
	}
	v := &Volume{r: r, size: size, bs: int64(1024) << logBS}
	if v.bs > maxBlockSize {
		return nil, corrupt("block size %d", v.bs)
	}
	rev := u32(sb, 76)
	incompat := u32(sb, 96)
	compat := u32(sb, 92)
	v.isize = 128
	if rev >= 1 {
		v.isize = int64(u16(sb, 88))
		if v.isize < 128 || v.isize > v.bs || v.isize&(v.isize-1) != 0 {
			return nil, corrupt("inode size %d", v.isize)
		}
	}
	is64 := incompat&incompat64bit != 0
	v.inodes = uint64(u32(sb, 0))
	v.first = uint64(u32(sb, 20))
	v.ipg = uint64(u32(sb, 40))
	v.blocks = uint64(u32(sb, 4))
	if is64 {
		v.blocks |= uint64(u32(sb, 0x150)) << 32
	}
	if v.ipg == 0 || v.blocks == 0 || v.blocks <= v.first {
		return nil, corrupt("no blocks or inodes per group")
	}
	bpg := uint64(u32(sb, 32))
	if bpg == 0 {
		return nil, corrupt("no blocks per group")
	}
	groups := (v.blocks - v.first + bpg - 1) / bpg
	if v.inodes != groups*v.ipg {
		return nil, corrupt("inode count %d does not match %d groups of %d", v.inodes, groups, v.ipg)
	}
	if incompat&incompatMetaBG != 0 {
		return nil, fmt.Errorf("%w: meta_bg group layout", fsvol.ErrUnsupported)
	}
	descSize := uint64(32)
	if is64 {
		descSize = uint64(u16(sb, 254))
		if descSize < 64 {
			descSize = 64
		}
	}
	if groups*descSize > maxGDTBytes {
		return nil, corrupt("group descriptor table of %d bytes", groups*descSize)
	}
	gdt := make([]byte, groups*descSize)
	gdtOff := int64(v.first+1) * v.bs
	if gdtOff+int64(len(gdt)) > size {
		return nil, corrupt("group descriptor table is beyond the end of the volume")
	}
	if n, err := r.ReadAt(gdt, gdtOff); n < len(gdt) {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return nil, fmt.Errorf("reading group descriptors: %w", err)
	}
	v.itable = make([]uint64, groups)
	for g := range v.itable {
		d := gdt[uint64(g)*descSize:]
		t := uint64(u32(d, 8))
		if is64 {
			t |= uint64(u32(d, 0x28)) << 32
		}
		if t == 0 || t >= v.blocks {
			return nil, corrupt("group %d inode table at block %d", g, t)
		}
		v.itable[g] = t
	}

	v.Version = "ext2"
	switch {
	case incompat&(incompatExtents|incompat64bit|incompatFlexBG) != 0:
		v.Version = "ext4"
	case compat&compatHasJournal != 0:
		v.Version = "ext3"
	}
	if incompat&incompatRecover != 0 {
		v.Notes = append(v.Notes, "needs_recovery is set: journal transactions that were not replayed are not applied, so the content read is the on-disk state")
	}
	if incompat&incompatInline != 0 {
		v.Notes = append(v.Notes, "inline_data is enabled: files stored inline are reported as unsupported, not read")
	}
	label := sb[120:136]
	if i := strings.IndexByte(string(label), 0); i >= 0 {
		label = label[:i]
	}
	v.info = fsvol.Info{
		Label:       strings.ToValidUTF8(string(label), "\uFFFD"),
		Version:     v.Version,
		Serial:      binary.LittleEndian.Uint64(sb[104:112]),
		ClusterSize: int(v.bs),
		Records:     int64(v.inodes),
		VolumeBytes: int64(v.blocks) * v.bs,
	}
	return v, nil
}

// Info describes the volume.
func (v *Volume) Info() fsvol.Info { return v.info }

func corrupt(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{fsvol.ErrCorrupt}, a...)...)
}

// ---- inodes

type inode struct {
	num   uint64
	mode  uint16
	links uint16
	flags uint32
	size  int64
	dtime uint32
	atime uint32
	ctime uint32
	mtime uint32
	block [iBlockSize]byte
}

func (in *inode) isDir() bool     { return in.mode&modeTypeMask == modeDir }
func (in *inode) isReg() bool     { return in.mode&modeTypeMask == modeReg }
func (in *inode) isSymlink() bool { return in.mode&modeTypeMask == modeSymlink }
func (in *inode) inUse() bool     { return in.links > 0 && in.dtime == 0 }

func (v *Volume) readInode(ino uint64) (*inode, error) {
	if ino == 0 || ino > v.inodes {
		return nil, corrupt("inode %d is out of range", ino)
	}
	g := (ino - 1) / v.ipg
	idx := (ino - 1) % v.ipg
	off := int64(v.itable[g])*v.bs + int64(idx)*v.isize
	if off+v.isize > v.size {
		return nil, corrupt("inode %d is beyond the end of the volume", ino)
	}
	b := make([]byte, v.isize)
	if n, err := v.r.ReadAt(b, off); n < len(b) {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return nil, fmt.Errorf("reading inode %d: %w", ino, err)
	}
	in := &inode{
		num: ino, mode: u16(b, 0), links: u16(b, 26), flags: u32(b, 32),
		dtime: u32(b, 20), atime: u32(b, 8), ctime: u32(b, 12), mtime: u32(b, 16),
	}
	copy(in.block[:], b[40:40+iBlockSize])
	in.size = int64(u32(b, 4))
	if in.isReg() || in.mode&modeTypeMask == 0 {
		in.size |= int64(u32(b, 108)) << 32
	}
	return in, nil
}

// ---- block mapping

// extent maps logical blocks [logical, logical+n) to physical blocks from
// physical on. An uninit extent is allocated but reads as zeros.
type extent struct {
	logical, physical, n uint64
	uninit               bool
}

// blockMap returns the file's extents, sorted by logical block, covering only
// the blocks the file's size reaches. Missing logical blocks are holes.
func (v *Volume) blockMap(in *inode) ([]extent, error) {
	nBlocks := uint64((in.size + v.bs - 1) / v.bs)
	if in.flags&flagExtents != 0 {
		var out []extent
		if err := v.walkExtentNode(in.block[:], 0, &out); err != nil {
			return nil, err
		}
		sort.Slice(out, func(i, j int) bool { return out[i].logical < out[j].logical })
		var prev uint64
		for i, e := range out {
			if e.logical < prev {
				return nil, corrupt("inode %d has overlapping extents", in.num)
			}
			prev = e.logical + e.n
			if e.physical+e.n > v.blocks {
				return nil, corrupt("inode %d has an extent beyond the volume", in.num)
			}
			out[i] = e
		}
		return out, nil
	}
	return v.indirectMap(in, nBlocks)
}

// walkExtentNode reads one extent-tree node held in buf (the inode's i_block
// or a block of the tree) and appends its leaves to out.
func (v *Volume) walkExtentNode(buf []byte, depth int, out *[]extent) error {
	if depth > maxDepth {
		return corrupt("extent tree is deeper than %d", maxDepth)
	}
	if len(buf) < 12 || u16(buf, 0) != extentMagic {
		return corrupt("extent node has no valid header")
	}
	n := int(u16(buf, 2))
	maxEntries := int(u16(buf, 4))
	nodeDepth := int(u16(buf, 6))
	if n > maxEntries || 12+n*12 > len(buf) {
		return corrupt("extent node claims %d entries", n)
	}
	if nodeDepth == 0 {
		for i := 0; i < n; i++ {
			e := buf[12+i*12:]
			ln := uint64(u16(e, 4))
			uninit := false
			if ln > 32768 {
				ln -= 32768
				uninit = true
			}
			if ln == 0 {
				return corrupt("extent with zero length")
			}
			*out = append(*out, extent{
				logical:  uint64(u32(e, 0)),
				n:        ln,
				physical: uint64(u32(e, 8)) | uint64(u16(e, 6))<<32,
				uninit:   uninit,
			})
			if len(*out) > maxExtents {
				return corrupt("more than %d extents", maxExtents)
			}
		}
		return nil
	}
	for i := 0; i < n; i++ {
		e := buf[12+i*12:]
		child := uint64(u32(e, 4)) | uint64(u16(e, 8))<<32
		if child == 0 || child >= v.blocks {
			return corrupt("extent index points at block %d", child)
		}
		block := make([]byte, v.bs)
		if off := int64(child) * v.bs; off+v.bs > v.size {
			return corrupt("extent index block %d is beyond the end of the volume", child)
		}
		if nr, err := v.r.ReadAt(block, int64(child)*v.bs); nr < len(block) {
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			return fmt.Errorf("reading extent block %d: %w", child, err)
		}
		if int(u16(block, 6)) != nodeDepth-1 {
			return corrupt("extent block %d has the wrong depth", child)
		}
		if err := v.walkExtentNode(block, depth+1, out); err != nil {
			return err
		}
	}
	return nil
}

// indirectMap converts the classic block map (ext2 and ext3, and ext4 files
// without extents) into single-block extents for the blocks the file reaches.
func (v *Volume) indirectMap(in *inode, nBlocks uint64) ([]extent, error) {
	per := uint64(v.bs / 4)
	var out []extent
	add := func(logical, physical uint64) {
		if logical >= nBlocks {
			return
		}
		if k := len(out) - 1; k >= 0 && out[k].logical+out[k].n == logical && out[k].physical+out[k].n == physical {
			out[k].n++
			return
		}
		out = append(out, extent{logical: logical, physical: physical, n: 1})
	}
	var rec func(ptr uint64, level int, base uint64) error
	rec = func(ptr uint64, level int, base uint64) error {
		if ptr == 0 || base >= nBlocks {
			return nil
		}
		if ptr >= v.blocks {
			return corrupt("block map points at block %d", ptr)
		}
		if level == 0 {
			add(base, ptr)
			return nil
		}
		block := make([]byte, v.bs)
		if nr, err := v.r.ReadAt(block, int64(ptr)*v.bs); nr < len(block) {
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			return fmt.Errorf("reading indirect block %d: %w", ptr, err)
		}
		sub := uint64(1)
		for i := 1; i < level; i++ {
			sub *= per
		}
		for i := uint64(0); i < per; i++ {
			if err := rec(uint64(u32(block, int(i*4))), level-1, base+i*sub); err != nil {
				return err
			}
		}
		return nil
	}
	for i := 0; i < 12; i++ {
		if err := rec(uint64(u32(in.block[:], i*4)), 0, uint64(i)); err != nil {
			return nil, err
		}
	}
	ind := uint64(12)
	if err := rec(uint64(u32(in.block[:], 12*4)), 1, ind); err != nil {
		return nil, err
	}
	dbl := ind + per
	if err := rec(uint64(u32(in.block[:], 13*4)), 2, dbl); err != nil {
		return nil, err
	}
	tpl := dbl + per*per
	if err := rec(uint64(u32(in.block[:], 14*4)), 3, tpl); err != nil {
		return nil, err
	}
	return out, nil
}

// ---- content

// Reader reads one file's content. It implements fsvol.Reader.
type Reader struct {
	v    *Volume
	size int64
	ext  []extent
}

// Size is the file's length.
func (r *Reader) Size() int64 { return r.size }

// ReadAt reads the file's content. Holes and uninit extents read as zeros.
func (r *Reader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	if off >= r.size {
		return 0, io.EOF
	}
	want := int64(len(p))
	if off+want > r.size {
		want = r.size - off
	}
	bs := r.v.bs
	done := int64(0)
	for done < want {
		pos := off + done
		blk := uint64(pos / bs)
		// The extent that holds blk, if any, and the next one that starts
		// after it, which bounds a hole.
		k := sort.Search(len(r.ext), func(i int) bool { return r.ext[i].logical+r.ext[i].n > blk })
		var end uint64 // logical block where this piece ends
		hit := k < len(r.ext) && r.ext[k].logical <= blk
		if hit {
			end = r.ext[k].logical + r.ext[k].n
		} else if k < len(r.ext) {
			end = r.ext[k].logical
		} else {
			end = uint64((r.size + bs - 1) / bs)
		}
		piece := int64(end)*bs - pos
		if piece > want-done {
			piece = want - done
		}
		buf := p[done : done+piece]
		if hit && !r.ext[k].uninit {
			phys := r.ext[k].physical + (blk - r.ext[k].logical)
			if n, err := r.v.r.ReadAt(buf, int64(phys)*bs+pos%bs); n < len(buf) {
				if err == nil {
					err = io.ErrUnexpectedEOF
				}
				return int(done) + n, fmt.Errorf("reading block %d: %w", phys, err)
			}
		} else {
			clear(buf)
		}
		done += piece
	}
	if done < int64(len(p)) {
		return int(done), io.EOF
	}
	return int(done), nil
}

// AllocatedRanges lists the byte ranges of the file that hold stored blocks.
func (r *Reader) AllocatedRanges() [][2]int64 {
	var out [][2]int64
	for _, e := range r.ext {
		start := int64(e.logical) * r.v.bs
		end := int64(e.logical+e.n) * r.v.bs
		if end > r.size {
			end = r.size
		}
		if start >= end {
			continue
		}
		if k := len(out) - 1; k >= 0 && out[k][1] == start {
			out[k][1] = end
			continue
		}
		out = append(out, [2]int64{start, end})
	}
	return out
}

// OpenStream opens the content of record. ext4 has no named streams, so only
// "" is valid.
func (v *Volume) OpenStream(record uint64, stream string) (fsvol.Reader, error) {
	if stream != "" {
		return nil, fmt.Errorf("%w: no named stream %q", fsvol.ErrNotFound, stream)
	}
	in, err := v.readInode(record)
	if err != nil {
		return nil, err
	}
	if in.isDir() {
		return nil, fmt.Errorf("%w: inode %d is a directory", fsvol.ErrNotFound, record)
	}
	if in.isSymlink() {
		return nil, fmt.Errorf("%w: inode %d is a symbolic link; its target is not read as content", fsvol.ErrUnsupported, record)
	}
	if !in.isReg() {
		// Device nodes, FIFOs and sockets carry no content. They are listed
		// but never read as if they were empty files.
		return nil, fmt.Errorf("%w: inode %d is a special file with no content", fsvol.ErrUnsupported, record)
	}
	if in.flags&flagEncrypt != 0 {
		return nil, fmt.Errorf("%w: inode %d", fsvol.ErrEncrypted, record)
	}
	if in.flags&flagInline != 0 {
		return nil, fmt.Errorf("%w: inode %d stores its content inline", fsvol.ErrUnsupported, record)
	}
	ext, err := v.blockMap(in)
	if err != nil {
		return nil, err
	}
	return &Reader{v: v, size: in.size, ext: ext}, nil
}

// ---- walk

// Walk lists every in-use name reachable from the root, depth first, and
// calls fn for each. A directory that cannot be read is counted as corrupt and
// its subtree is skipped; the walk continues.
func (v *Volume) Walk(fn func(fsvol.File) error) (fsvol.WalkStats, error) {
	var st fsvol.WalkStats
	st.Records = int(v.inodes)
	seenDir := map[uint64]bool{}
	type dirJob struct {
		ino  uint64
		path string
	}
	stack := []dirJob{{rootIno, ""}}
	seenDir[rootIno] = true
	bad := func(ino uint64) {
		st.CorruptCount++
		if len(st.Corrupt) < 20 {
			st.Corrupt = append(st.Corrupt, ino)
		}
	}
	for len(stack) > 0 {
		job := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		dir, err := v.readInode(job.ino)
		if err != nil || !dir.isDir() {
			bad(job.ino)
			continue
		}
		entries, err := v.dirEntries(dir)
		if err != nil {
			bad(job.ino)
			continue
		}
		for _, de := range entries {
			child, err := v.readInode(de.ino)
			if err != nil {
				bad(de.ino)
				continue
			}
			if !child.inUse() {
				continue
			}
			path := job.path + "/" + de.name
			f := fsvol.File{
				Record: child.num,
				Name:   de.name,
				Path:   path,
				IsDir:  child.isDir(),
				InUse:  true,
				Size:   child.size,
			}
			if child.isDir() {
				f.Size = 0
			}
			f.Streams = []fsvol.Stream{{Size: f.Size}}
			if t := ts(child.mtime); !t.IsZero() {
				f.Modified = t
			}
			if t := ts(child.atime); !t.IsZero() {
				f.Accessed = t
			}
			if t := ts(child.ctime); !t.IsZero() {
				f.MFTChanged = t
			}
			st.InUse++
			if err := fn(f); err != nil {
				return st, err
			}
			if child.isDir() && !seenDir[child.num] {
				seenDir[child.num] = true
				stack = append(stack, dirJob{child.num, path})
			}
		}
	}
	return st, nil
}

type dirEntry struct {
	ino  uint64
	name string
}

// dirEntries lists a directory's entries from its blocks. Entries with inode
// 0 (free space, hash index nodes, checksum tails) are skipped. A record that
// does not fit its block ends the listing with an error.
func (v *Volume) dirEntries(dir *inode) ([]dirEntry, error) {
	ext, err := v.blockMap(dir)
	if err != nil {
		return nil, err
	}
	var out []dirEntry
	for _, e := range ext {
		for b := uint64(0); b < e.n; b++ {
			if e.uninit {
				continue
			}
			block := make([]byte, v.bs)
			off := int64(e.physical+b) * v.bs
			if off+v.bs > v.size {
				return nil, corrupt("directory block %d is beyond the end of the volume", e.physical+b)
			}
			if n, err := v.r.ReadAt(block, off); n < len(block) {
				if err == nil {
					err = io.ErrUnexpectedEOF
				}
				return nil, fmt.Errorf("reading directory block: %w", err)
			}
			for pos := 0; pos < len(block); {
				if pos+8 > len(block) {
					return nil, corrupt("directory record at %d overruns its block", pos)
				}
				ino := uint64(u32(block, pos))
				recLen := int(u16(block, pos+4))
				nameLen := int(block[pos+6])
				if recLen < 8 || recLen%4 != 0 || pos+recLen > len(block) || 8+nameLen > recLen {
					return nil, corrupt("directory record at %d has length %d", pos, recLen)
				}
				if ino != 0 && nameLen > 0 {
					name := string(block[pos+8 : pos+8+nameLen])
					if name != "." && name != ".." {
						out = append(out, dirEntry{ino: ino, name: cleanName(name)})
					}
				}
				pos += recLen
			}
		}
	}
	return out, nil
}

// cleanName keeps a name as a single path element: a slash or NUL is replaced
// by "_", and bytes that are not UTF-8 by U+FFFD.
func cleanName(n string) string {
	if !utf8.ValidString(n) {
		n = strings.ToValidUTF8(n, "\uFFFD")
	}
	return strings.Map(func(r rune) rune {
		if r == '/' || r == 0 {
			return '_'
		}
		return r
	}, n)
}

func ts(sec uint32) time.Time {
	if sec == 0 {
		return time.Time{}
	}
	return time.Unix(int64(sec), 0).UTC()
}

func u16(b []byte, o int) uint16 { return binary.LittleEndian.Uint16(b[o:]) }
func u32(b []byte, o int) uint32 { return binary.LittleEndian.Uint32(b[o:]) }
