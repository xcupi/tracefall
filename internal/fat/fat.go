// Package fat reads FAT12, FAT16, FAT32 and exFAT volumes, read-only. It lists
// the in-use directory tree and reads file content through the cluster chain
// (or, for exFAT files that say so, the contiguous run of clusters).
//
// Deleted entries are not listed. FAT frees a deleted file's chain, so its
// content is not recoverable from the FAT in general; only the name would
// survive, and a name alone is not catalogued. A damaged directory entry or
// chain is reported as corrupt and the walk continues.
package fat

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"tracefall/internal/fsvol"
)

// ErrNotFAT means the bytes are not a FAT or exFAT volume.
var ErrNotFAT = errors.New("not a FAT or exFAT volume")

const (
	entrySize   = 32
	maxDirBytes = 16 << 20
	maxFATBytes = 64 << 20
	attrDir     = 0x10
	attrVolume  = 0x08
	attrLFN     = 0x0F
)

// Volume is an opened FAT or exFAT volume. It implements fsvol.Volume.
type Volume struct {
	r    io.ReaderAt
	size int64
	kind string // "FAT12", "FAT16", "FAT32" or "exFAT"

	cluster int64 // bytes per cluster
	dataOff int64 // byte offset of cluster 2
	count   uint32
	fat     []byte

	rootCluster uint32 // FAT32 and exFAT root directory
	fixedOff    int64  // FAT12/16 fixed root directory, byte offset
	fixedLen    int64  // and its length

	info fsvol.Info
}

// Open opens the volume at the start of r, size bytes long.
func Open(r io.ReaderAt, size int64) (*Volume, error) {
	if size < 512 {
		return nil, ErrNotFAT
	}
	bs := make([]byte, 512)
	if n, err := r.ReadAt(bs, 0); n < 512 {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return nil, fmt.Errorf("reading the boot sector: %w", err)
	}
	if string(bs[3:11]) == "EXFAT   " {
		return openExFAT(r, size, bs)
	}
	return openFAT(r, size, bs)
}

func corrupt(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{fsvol.ErrCorrupt}, a...)...)
}

func readFull(r io.ReaderAt, p []byte, off int64) error {
	n, err := r.ReadAt(p, off)
	if n < len(p) {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return err
	}
	return nil
}

func openFAT(r io.ReaderAt, size int64, bs []byte) (*Volume, error) {
	bps := int64(le16(bs, 11))
	spc := int64(bs[13])
	rsvd := int64(le16(bs, 14))
	nfats := int64(bs[16])
	rootEnt := int64(le16(bs, 17))
	tot16 := int64(le16(bs, 19))
	fsz16 := int64(le16(bs, 22))
	tot32 := int64(le32(bs, 32))
	fsz32 := int64(le32(bs, 36))
	if bps < 512 || bps > 4096 || bps&(bps-1) != 0 || spc == 0 || spc&(spc-1) != 0 || spc*bps > 32*1024 {
		return nil, ErrNotFAT
	}
	if nfats == 0 || (bs[510] != 0x55 || bs[511] != 0xAA) {
		return nil, ErrNotFAT
	}
	fatsz := fsz16
	if fatsz == 0 {
		fatsz = fsz32
	}
	tot := tot16
	if tot == 0 {
		tot = tot32
	}
	if fatsz == 0 || tot == 0 {
		return nil, ErrNotFAT
	}
	rootSecs := (rootEnt*entrySize + bps - 1) / bps
	dataStart := rsvd + nfats*fatsz + rootSecs
	if dataStart >= tot {
		return nil, corrupt("no data area")
	}
	count := uint32((tot - dataStart) / spc)
	v := &Volume{r: r, size: size, cluster: bps * spc, count: count}
	v.dataOff = dataStart * bps
	if v.dataOff >= size || tot*bps > size+bps {
		return nil, corrupt("the volume is larger than the image")
	}
	switch {
	case count < 4085:
		v.kind = "FAT12"
	case count < 65525:
		v.kind = "FAT16"
	default:
		v.kind = "FAT32"
	}
	if v.kind == "FAT32" {
		if rootEnt != 0 {
			return nil, corrupt("FAT32 with a fixed root directory")
		}
		v.rootCluster = le32(bs, 44) & 0x0FFFFFFF
		if v.rootCluster < 2 || v.rootCluster >= count+2 {
			return nil, corrupt("FAT32 root cluster %d", v.rootCluster)
		}
	} else {
		v.fixedOff = (rsvd + nfats*fatsz) * bps
		v.fixedLen = rootEnt * entrySize
	}
	fatLen := fatsz * bps
	if fatLen > maxFATBytes {
		return nil, corrupt("FAT of %d bytes", fatLen)
	}
	v.fat = make([]byte, fatLen)
	if err := readFull(r, v.fat, rsvd*bps); err != nil {
		return nil, fmt.Errorf("reading the FAT: %w", err)
	}
	var label []byte
	var serial uint32
	if v.kind == "FAT32" {
		label, serial = bs[71:82], le32(bs, 67)
	} else {
		label, serial = bs[43:54], le32(bs, 39)
	}
	v.info = fsvol.Info{
		Label:       strings.TrimRight(string(label), " \x00"),
		Version:     v.kind,
		Serial:      uint64(serial),
		ClusterSize: int(v.cluster),
		Records:     int64(count),
		VolumeBytes: tot * bps,
	}
	return v, nil
}

func openExFAT(r io.ReaderAt, size int64, bs []byte) (*Volume, error) {
	bpsShift := uint(bs[108])
	spcShift := uint(bs[109])
	if bpsShift < 9 || bpsShift > 12 || spcShift > 25 || bpsShift+spcShift > 25 {
		return nil, corrupt("exFAT sector or cluster shift")
	}
	bps := int64(1) << bpsShift
	fatOff := int64(le32(bs, 80)) * bps
	fatLen := int64(le32(bs, 84)) * bps
	heapOff := int64(le32(bs, 88)) * bps
	count := le32(bs, 92)
	root := le32(bs, 96)
	if count == 0 || root < 2 || root >= count+2 {
		return nil, corrupt("exFAT cluster count %d, root cluster %d", count, root)
	}
	cluster := bps << spcShift
	if heapOff+int64(count)*cluster > size {
		return nil, corrupt("the exFAT cluster heap is beyond the image")
	}
	if fatLen > maxFATBytes {
		return nil, corrupt("FAT of %d bytes", fatLen)
	}
	fat := make([]byte, fatLen)
	if err := readFull(r, fat, fatOff); err != nil {
		return nil, fmt.Errorf("reading the FAT: %w", err)
	}
	v := &Volume{
		r: r, size: size, kind: "exFAT", cluster: cluster, dataOff: heapOff, count: count,
		fat: fat, rootCluster: root,
	}
	v.info = fsvol.Info{
		Version:     "exFAT",
		Serial:      uint64(le32(bs, 100)),
		ClusterSize: int(cluster),
		Records:     int64(count),
		VolumeBytes: int64(le64(bs, 72)) * bps,
	}
	return v, nil
}

// Info describes the volume.
func (v *Volume) Info() fsvol.Info { return v.info }

// clusterOff is the byte offset of cluster c.
func (v *Volume) clusterOff(c uint32) int64 { return v.dataOff + int64(c-2)*v.cluster }

func (v *Volume) validCluster(c uint32) bool { return c >= 2 && c < v.count+2 }

// next returns the FAT entry of cluster c.
func (v *Volume) next(c uint32) (uint32, error) {
	switch v.kind {
	case "FAT12":
		off := int(c) + int(c)/2
		if off+1 >= len(v.fat) {
			return 0, corrupt("FAT entry %d is outside the table", c)
		}
		x := uint32(v.fat[off]) | uint32(v.fat[off+1])<<8
		if c&1 == 1 {
			return x >> 4, nil
		}
		return x & 0xFFF, nil
	case "FAT16":
		off := int(c) * 2
		if off+2 > len(v.fat) {
			return 0, corrupt("FAT entry %d is outside the table", c)
		}
		return uint32(le16(v.fat, off)), nil
	default: // FAT32 and exFAT: 32-bit entries
		off := int(c) * 4
		if off+4 > len(v.fat) {
			return 0, corrupt("FAT entry %d is outside the table", c)
		}
		x := le32(v.fat, off)
		if v.kind == "FAT32" {
			x &= 0x0FFFFFFF
		}
		return x, nil
	}
}

func (v *Volume) endOfChain(x uint32) bool {
	switch v.kind {
	case "FAT12":
		return x >= 0xFF8
	case "FAT16":
		return x >= 0xFFF8
	default:
		return x >= 0x0FFFFFF8
	}
}

// chain follows the FAT from first and returns its clusters in order.
func (v *Volume) chain(first uint32) ([]uint32, error) {
	if first == 0 {
		return nil, nil
	}
	var out []uint32
	c := first
	for {
		if !v.validCluster(c) {
			return nil, corrupt("cluster %d is outside the data area", c)
		}
		out = append(out, c)
		if len(out) > int(v.count) {
			return nil, corrupt("cluster chain from %d loops", first)
		}
		x, err := v.next(c)
		if err != nil {
			return nil, err
		}
		if v.endOfChain(x) {
			return out, nil
		}
		c = x
	}
}

// contiguous returns n clusters from first, for an exFAT file with no FAT
// chain.
func (v *Volume) contiguous(first uint32, n int64) ([]uint32, error) {
	if n == 0 {
		return nil, nil
	}
	if !v.validCluster(first) || int64(first)+n-1 >= int64(v.count)+2 {
		return nil, corrupt("contiguous run from %d of %d clusters is outside the data area", first, n)
	}
	out := make([]uint32, n)
	for i := range out {
		out[i] = first + uint32(i)
	}
	return out, nil
}

// dirJob is one directory still to be read, with its listed path.
type dirJob struct {
	d    dirSource
	path string
}

// dirSource is where a directory's entries are: a list of clusters, or for
// FAT12/16 the fixed root region.
type dirSource struct {
	clusters []uint32
	fixed    bool
}

// dirBytes reads a whole directory and returns the byte offset of each
// 32-byte slot's volume position through entryOff.
func (v *Volume) dirBytes(d dirSource) ([]byte, error) {
	if d.fixed {
		if v.fixedLen > maxDirBytes {
			return nil, corrupt("root directory of %d bytes", v.fixedLen)
		}
		b := make([]byte, v.fixedLen)
		if err := readFull(v.r, b, v.fixedOff); err != nil {
			return nil, fmt.Errorf("reading the root directory: %w", err)
		}
		return b, nil
	}
	if int64(len(d.clusters))*v.cluster > maxDirBytes {
		return nil, corrupt("directory of %d clusters", len(d.clusters))
	}
	out := make([]byte, 0, int64(len(d.clusters))*v.cluster)
	for _, c := range d.clusters {
		b := make([]byte, v.cluster)
		if err := readFull(v.r, b, v.clusterOff(c)); err != nil {
			return nil, fmt.Errorf("reading directory cluster %d: %w", c, err)
		}
		out = append(out, b...)
	}
	return out, nil
}

// entryOff is the volume byte offset of slot i of directory d.
func (v *Volume) entryOff(d dirSource, i int) int64 {
	pos := int64(i) * entrySize
	if d.fixed {
		return v.fixedOff + pos
	}
	return v.clusterOff(d.clusters[pos/v.cluster]) + pos%v.cluster
}

// Reader reads one file's content. It implements fsvol.Reader.
type Reader struct {
	v        *Volume
	size     int64
	clusters []uint32
}

// Size is the file's length.
func (r *Reader) Size() int64 { return r.size }

// ReadAt reads the file's content from its clusters.
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
	done := int64(0)
	for done < want {
		pos := off + done
		idx := pos / r.v.cluster
		if idx >= int64(len(r.clusters)) {
			return int(done), corrupt("the chain ends before the file's %d bytes", r.size)
		}
		in := pos % r.v.cluster
		n := r.v.cluster - in
		if n > want-done {
			n = want - done
		}
		if err := readFull(r.v.r, p[done:done+n], r.v.clusterOff(r.clusters[idx])+in); err != nil {
			return int(done), fmt.Errorf("reading cluster %d: %w", r.clusters[idx], err)
		}
		done += n
	}
	if done < int64(len(p)) {
		return int(done), io.EOF
	}
	return int(done), nil
}

// AllocatedRanges: FAT has no sparse files, so all of a file's bytes are stored.
func (r *Reader) AllocatedRanges() [][2]int64 {
	if r.size == 0 {
		return nil
	}
	return [][2]int64{{0, r.size}}
}

// OpenStream opens the content of a file by its record, the volume offset of
// its directory entry. FAT has no named streams.
func (v *Volume) OpenStream(record uint64, stream string) (fsvol.Reader, error) {
	if stream != "" {
		return nil, fmt.Errorf("%w: no named stream %q", fsvol.ErrNotFound, stream)
	}
	if v.kind == "exFAT" {
		return v.openExFATStream(int64(record))
	}
	b := make([]byte, entrySize)
	if off := int64(record); off < 0 || off+entrySize > v.size {
		return nil, fmt.Errorf("%w: record %d", fsvol.ErrNotFound, record)
	} else if err := readFull(v.r, b, off); err != nil {
		return nil, err
	}
	if b[0] == 0 || b[0] == 0xE5 || b[11]&attrDir != 0 || b[11]&attrVolume != 0 || b[11] == attrLFN {
		return nil, fmt.Errorf("%w: record %d is not a file entry", fsvol.ErrNotFound, record)
	}
	size := int64(le32(b, 28))
	first := uint32(le16(b, 26))
	if v.kind == "FAT32" {
		first |= uint32(le16(b, 20)) << 16
	}
	clusters, err := v.chain(first)
	if err != nil {
		return nil, err
	}
	return &Reader{v: v, size: size, clusters: clusters}, nil
}

func (v *Volume) openExFATStream(off int64) (fsvol.Reader, error) {
	b := make([]byte, 2*entrySize)
	if off < 0 || off+int64(len(b)) > v.size {
		return nil, fmt.Errorf("%w: record %d", fsvol.ErrNotFound, off)
	}
	if err := readFull(v.r, b, off); err != nil {
		return nil, err
	}
	if b[0] != 0x85 || b[0]&0x80 == 0 {
		return nil, fmt.Errorf("%w: record %d is not an in-use file entry", fsvol.ErrNotFound, off)
	}
	s := b[entrySize:]
	if s[0] != 0xC0 {
		return nil, corrupt("file at %d has no stream extension", off)
	}
	flags := s[1]
	size := int64(le64(s, 24))
	first := le32(s, 20)
	var clusters []uint32
	var err error
	if flags&0x02 != 0 {
		n := (size + v.cluster - 1) / v.cluster
		clusters, err = v.contiguous(first, n)
	} else {
		clusters, err = v.chain(first)
	}
	if err != nil {
		return nil, err
	}
	return &Reader{v: v, size: size, clusters: clusters}, nil
}

// ---- helpers

func le16(b []byte, o int) uint16 { return binary.LittleEndian.Uint16(b[o:]) }
func le32(b []byte, o int) uint32 { return binary.LittleEndian.Uint32(b[o:]) }
func le64(b []byte, o int) uint64 { return binary.LittleEndian.Uint64(b[o:]) }

// fatTime decodes a FAT date and time pair. A zero date is no time.
func fatTime(date, tm uint16) time.Time {
	if date == 0 {
		return time.Time{}
	}
	year := 1980 + int(date>>9)
	month := time.Month((date >> 5) & 0xF)
	day := int(date & 0x1F)
	if month < 1 || month > 12 || day < 1 {
		return time.Time{}
	}
	h := int(tm >> 11)
	mi := int((tm >> 5) & 0x3F)
	s := int(tm&0x1F) * 2
	if h > 23 || mi > 59 || s > 59 {
		h, mi, s = 0, 0, 0
	}
	return time.Date(year, month, day, h, mi, s, 0, time.UTC)
}

// exFATTime decodes the exFAT timestamp layout (no seconds-of-day overflow
// handling beyond the field widths).
func exFATTime(ts uint32) time.Time {
	if ts == 0 {
		return time.Time{}
	}
	date := uint16(ts >> 16)
	tm := uint16(ts)
	return fatTime(date, tm)
}

// shortName returns the 8.3 name from an 11-byte directory field.
func shortName(f []byte) string {
	base := strings.TrimRight(string(f[:8]), " ")
	ext := strings.TrimRight(string(f[8:11]), " ")
	if base == "" {
		return ""
	}
	if ext != "" {
		return base + "." + ext
	}
	return base
}

// shortChecksum is the checksum an LFN entry carries for its short name.
func shortChecksum(f []byte) byte {
	var sum byte
	for i := 0; i < 11; i++ {
		sum = ((sum & 1) << 7) + (sum >> 1) + f[i]
	}
	return sum
}

// lfnChars returns the UTF-16 code units of one LFN entry.
func lfnChars(e []byte) []uint16 {
	var out []uint16
	for _, rng := range [][2]int{{1, 11}, {14, 26}, {28, 32}} {
		for o := rng[0]; o < rng[1]; o += 2 {
			out = append(out, le16(e, o))
		}
	}
	return out
}

// decodeUTF16 converts a name, stopping at the first NUL.
func decodeUTF16(u []uint16) string {
	for i, c := range u {
		if c == 0 {
			u = u[:i]
			break
		}
	}
	s := string(utf16.Decode(u))
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "\uFFFD")
	}
	return strings.Map(func(r rune) rune {
		if r == '/' || r == 0 {
			return '_'
		}
		return r
	}, s)
}

// Walk lists every in-use name reachable from the root, depth first. A
// directory that cannot be read is counted as corrupt and skipped.
func (v *Volume) Walk(fn func(fsvol.File) error) (fsvol.WalkStats, error) {
	var st fsvol.WalkStats
	var root dirSource
	if v.kind == "FAT12" || v.kind == "FAT16" {
		root = dirSource{fixed: true}
	} else {
		cl, err := v.chain(v.rootCluster)
		if err != nil {
			return st, err
		}
		root = dirSource{clusters: cl}
	}
	seen := map[uint32]bool{}
	stack := []dirJob{{root, ""}}
	bad := func(n uint32) {
		st.CorruptCount++
		if len(st.Corrupt) < 20 {
			st.Corrupt = append(st.Corrupt, uint64(n))
		}
	}
	for len(stack) > 0 {
		j := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		data, err := v.dirBytes(j.d)
		if err != nil {
			bad(0)
			continue
		}
		var recs []fsvol.File
		var subdirs []dirJob
		if v.kind == "exFAT" {
			recs, subdirs, err = v.parseExFATDir(j.d, data, j.path, &st)
		} else {
			recs, subdirs, err = v.parseFATDir(j.d, data, j.path, &st, seen)
		}
		if err != nil {
			bad(0)
		}
		for _, f := range recs {
			st.InUse++
			if err := fn(f); err != nil {
				return st, err
			}
		}
		stack = append(stack, subdirs...)
	}
	return st, nil
}

// parseFATDir reads one FAT directory. Files go to the returned list; each
// subdirectory becomes a job for the walk, unless it was seen already.
func (v *Volume) parseFATDir(d dirSource, data []byte, path string, st *fsvol.WalkStats, seen map[uint32]bool) ([]fsvol.File, []dirJob, error) {
	var files []fsvol.File
	var subs []dirJob
	var lfn []uint16
	var lfnSum byte
	var lfnNext byte
	for i := 0; i*entrySize < len(data); i++ {
		e := data[i*entrySize : (i+1)*entrySize]
		if e[0] == 0x00 {
			break
		}
		st.Records++
		if e[0] == 0xE5 {
			lfn = nil
			continue
		}
		if e[11] == attrLFN {
			seq := e[0] & 0x1F
			if e[0]&0x40 != 0 {
				lfn = nil
				lfnSum = e[13]
				lfnNext = seq
			}
			if seq == 0 || seq != lfnNext || e[13] != lfnSum {
				lfn = nil
				continue
			}
			lfn = append(lfnChars(e), lfn...)
			lfnNext--
			continue
		}
		if e[11]&attrVolume != 0 {
			lfn = nil
			continue
		}
		name := shortName(e)
		if lfn != nil && lfnNext == 0 && lfnSum == shortChecksum(e) {
			if n := decodeUTF16(lfn); n != "" {
				name = n
			}
		}
		lfn = nil
		if name == "" || name == "." || name == ".." {
			continue
		}
		first := uint32(le16(e, 26))
		if v.kind == "FAT32" {
			first |= uint32(le16(e, 20)) << 16
		}
		off := v.entryOff(d, i)
		if e[11]&attrDir != 0 {
			if first == 0 || seen[first] {
				continue
			}
			seen[first] = true
			cl, err := v.chain(first)
			if err != nil {
				st.CorruptCount++
				continue
			}
			subs = append(subs, dirJob{dirSource{clusters: cl}, path + "/" + name})
			continue
		}
		f := fsvol.File{
			Record:     uint64(off),
			Name:       name,
			Path:       path + "/" + name,
			InUse:      true,
			Size:       int64(le32(e, 28)),
			Attributes: uint32(e[11]),
			Modified:   fatTime(le16(e, 24), le16(e, 22)),
			Accessed:   fatTime(le16(e, 18), 0),
		}
		f.Streams = []fsvol.Stream{{Size: f.Size}}
		files = append(files, f)
	}
	return files, subs, nil
}

// parseExFATDir reads one exFAT directory of in-use file entry sets. A set
// whose checksum does not match is counted as corrupt and skipped.
func (v *Volume) parseExFATDir(d dirSource, data []byte, path string, st *fsvol.WalkStats) ([]fsvol.File, []dirJob, error) {
	var files []fsvol.File
	var subs []dirJob
	for i := 0; (i+1)*entrySize <= len(data); i++ {
		e := data[i*entrySize : (i+1)*entrySize]
		if e[0] == 0x00 {
			break
		}
		if e[0] != 0x85 {
			continue // free, or a non-file entry (bitmap, upcase, label)
		}
		st.Records++
		n := int(e[1])
		if n < 2 || (i+1+n)*entrySize > len(data) {
			st.CorruptCount++
			continue
		}
		set := data[i*entrySize : (i+1+n)*entrySize]
		if exFATChecksum(set) != le16(set, 2) {
			st.CorruptCount++
			i += n
			continue
		}
		s := set[entrySize:]
		if s[0] != 0xC0 {
			st.CorruptCount++
			i += n
			continue
		}
		nameLen := int(s[3])
		flags := s[1]
		first := le32(s, 20)
		size := int64(le64(s, 24))
		var name []uint16
		for k := 2; k <= n; k++ {
			ne := set[k*entrySize : (k+1)*entrySize]
			if ne[0] != 0xC1 {
				break
			}
			for o := 2; o < 32 && len(name) < nameLen; o += 2 {
				name = append(name, le16(ne, o))
			}
		}
		if len(name) > nameLen {
			name = name[:nameLen]
		}
		entryName := decodeUTF16(name)
		attrs := le16(set, 4)
		off := v.entryOff(d, i)
		i += n
		if entryName == "" {
			continue
		}
		if attrs&attrDir != 0 {
			var cl []uint32
			var err error
			if flags&0x02 != 0 {
				cl, err = v.contiguous(first, (int64(size)+v.cluster-1)/v.cluster)
			} else {
				cl, err = v.chain(first)
			}
			if err != nil {
				st.CorruptCount++
				continue
			}
			subs = append(subs, dirJob{dirSource{clusters: cl}, path + "/" + entryName})
			continue
		}
		f := fsvol.File{
			Record:     uint64(off),
			Name:       entryName,
			Path:       path + "/" + entryName,
			InUse:      true,
			Size:       size,
			Attributes: uint32(attrs),
			Modified:   exFATTime(le32(set, 12)),
			Accessed:   exFATTime(le32(set, 16)),
		}
		f.Streams = []fsvol.Stream{{Size: size}}
		files = append(files, f)
	}
	return files, subs, nil
}

// exFATChecksum is the set checksum of an exFAT entry set, skipping the
// checksum field of its primary entry.
func exFATChecksum(set []byte) uint16 {
	var sum uint16
	for i, c := range set {
		if i == 2 || i == 3 {
			continue
		}
		sum = ((sum << 15) | (sum >> 1)) + uint16(c)
	}
	return sum
}
