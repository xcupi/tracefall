package fat

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"unicode/utf16"

	"tracefall/internal/fsvol"
)

// Fixtures are built here from a tree this file writes, so the expected
// content is known. Each image is then checked by the file system's own
// checker (fsck), which is independent of this writer and of the reader: a
// writer mistake shows up as a rejected image, not as a reader bug.

type node struct {
	name string
	dir  bool
	data []byte
	kids []node
}

// tree is the same logical content for every file system.
func tree() []node {
	big := make([]byte, 40000)
	for i := range big {
		big[i] = byte(i*7 + 3)
	}
	evtx := make([]byte, 1200)
	for i := range evtx {
		evtx[i] = byte(i % 251)
	}
	return []node{
		{name: "README.TXT", data: []byte("short readme\n")},
		{name: "Quarterly Report 2024.txt", data: []byte("long name, fragmented across clusters\n")},
		{name: "empty.bin"},
		{name: "big.bin", data: big},
		{name: "logs", dir: true, kids: []node{
			{name: "app.log", data: []byte("2024-01-02 event one\n")},
			{name: "Very Long Event Log Name.evtx", data: evtx},
		}},
	}
}

// expected flattens the tree to path -> content, for files only.
func expected(nodes []node, prefix string, out map[string][]byte) map[string][]byte {
	if out == nil {
		out = map[string][]byte{}
	}
	for _, n := range nodes {
		p := prefix + "/" + n.name
		if n.dir {
			expected(n.kids, p, out)
			continue
		}
		out[p] = n.data
	}
	return out
}

func runTool(t testing.TB, tool string, args ...string) {
	t.Helper()
	if _, err := exec.LookPath(tool); err != nil {
		t.Skipf("%s not installed", tool)
	}
	if out, err := exec.Command(tool, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", tool, args, err, out)
	}
}

// fsckClean runs the file system's checker without changing the image. Exit 0
// means the image is consistent.
func fsckClean(t testing.TB, tool string, args ...string) {
	t.Helper()
	if _, err := exec.LookPath(tool); err != nil {
		t.Skipf("%s not installed", tool)
	}
	if out, err := exec.Command(tool, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s rejects the fixture (the writer is wrong): %v\n%s", tool, err, out)
	}
}

func walkFiles(t testing.TB, v *Volume) map[string]fsvol.File {
	t.Helper()
	out := map[string]fsvol.File{}
	st, err := v.Walk(func(f fsvol.File) error {
		out[f.Path] = f
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if st.CorruptCount != 0 {
		t.Fatalf("walk reported %d corrupt records: %v", st.CorruptCount, st.Corrupt)
	}
	return out
}

func readAllFile(t testing.TB, v *Volume, f fsvol.File) []byte {
	t.Helper()
	r, err := v.OpenStream(f.Record, "")
	if err != nil {
		t.Fatalf("%s: open: %v", f.Path, err)
	}
	var out []byte
	buf := make([]byte, 4096)
	for off := int64(0); ; {
		n, err := r.ReadAt(buf, off)
		out = append(out, buf[:n]...)
		off += int64(n)
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatalf("%s: read at %d: %v", f.Path, off, err)
		}
	}
}

// checkTree compares a walk of the volume with the expected files: each must
// be listed with its size and content, and nothing else may be listed.
func checkTree(t testing.TB, v *Volume, want map[string][]byte) {
	t.Helper()
	got := walkFiles(t, v)
	for p, content := range want {
		f, ok := got[p]
		if !ok {
			t.Errorf("%s is not listed", p)
			continue
		}
		if f.Size != int64(len(content)) {
			t.Errorf("%s: size %d, want %d", p, f.Size, len(content))
		}
		if b := readAllFile(t, v, f); string(b) != string(content) {
			t.Errorf("%s: content differs (%d bytes, want %d)", p, len(b), len(content))
		}
	}
	var extra []string
	for p := range got {
		if _, ok := want[p]; !ok {
			extra = append(extra, p)
		}
	}
	sort.Strings(extra)
	if len(extra) > 0 {
		t.Errorf("unexpected entries listed: %v", extra)
	}
}

// ---- FAT12, FAT16 and FAT32

type fileRec struct {
	name string
	data []byte
	cl   []uint32
}

// dnode is a directory being written: its cluster (0 for the FAT12/16 fixed
// root), and its children in order.
type dnode struct {
	name    string
	cluster uint32
	kids    []child
}

type child struct {
	dir  *dnode
	file *fileRec
}

type fatWriter struct {
	t       testing.TB
	f       *os.File
	kind    string
	bps     int64
	spc     int64
	rsvd    int64
	nfats   int64
	fatsz   int64
	rootEnt int64
	count   uint32
	dataOff int64
	fixed   int64
	used    []bool
}

func newFATFixture(t testing.TB, kind string) (string, *fatWriter) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fat.img")
	size := map[string]string{"FAT12": "4096", "FAT16": "32768", "FAT32": "65536"}[kind]
	typ := map[string]string{"FAT12": "12", "FAT16": "16", "FAT32": "32"}[kind]
	runTool(t, "mkfs.fat", "-C", "-F", typ, "-n", "TESTFAT", path, size)
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	bs := make([]byte, 512)
	if _, err := f.ReadAt(bs, 0); err != nil {
		t.Fatal(err)
	}
	w := &fatWriter{t: t, f: f, kind: kind}
	w.bps = int64(le16(bs, 11))
	w.spc = int64(bs[13])
	w.rsvd = int64(le16(bs, 14))
	w.nfats = int64(bs[16])
	w.rootEnt = int64(le16(bs, 17))
	w.fatsz = int64(le16(bs, 22))
	if w.fatsz == 0 {
		w.fatsz = int64(le32(bs, 36))
	}
	tot := int64(le16(bs, 19))
	if tot == 0 {
		tot = int64(le32(bs, 32))
	}
	rootSecs := (w.rootEnt*32 + w.bps - 1) / w.bps
	w.dataOff = (w.rsvd + w.nfats*w.fatsz + rootSecs) * w.bps
	w.fixed = (w.rsvd + w.nfats*w.fatsz) * w.bps
	w.count = uint32((tot - w.dataOff/w.bps) / w.spc)
	w.used = make([]bool, w.count+2)
	return path, w
}

func (w *fatWriter) clusterBytes() int64 { return w.bps * w.spc }

func (w *fatWriter) clusterOff(c uint32) int64 { return w.dataOff + int64(c-2)*w.clusterBytes() }

func (w *fatWriter) eoc() uint32 {
	switch w.kind {
	case "FAT12":
		return 0xFFF
	case "FAT16":
		return 0xFFFF
	default:
		return 0x0FFFFFFF
	}
}

// setEntry writes a FAT entry into every copy of the table.
func (w *fatWriter) setEntry(c uint32, val uint32) {
	t := w.t
	for k := int64(0); k < w.nfats; k++ {
		base := w.rsvd*w.bps + k*w.fatsz*w.bps
		switch w.kind {
		case "FAT12":
			off := base + int64(c) + int64(c)/2
			b := make([]byte, 2)
			if _, err := w.f.ReadAt(b, off); err != nil {
				t.Fatal(err)
			}
			x := uint16(b[0]) | uint16(b[1])<<8
			if c&1 == 1 {
				x = x&0x000F | uint16(val&0xFFF)<<4
			} else {
				x = x&0xF000 | uint16(val&0xFFF)
			}
			b[0], b[1] = byte(x), byte(x>>8)
			w.f.WriteAt(b, off)
		case "FAT16":
			w.f.WriteAt([]byte{byte(val), byte(val >> 8)}, base+int64(c)*2)
		default:
			b := make([]byte, 4)
			binary.LittleEndian.PutUint32(b, val&0x0FFFFFFF)
			w.f.WriteAt(b, base+int64(c)*4)
		}
	}
}

func (w *fatWriter) alloc() uint32 {
	for c := uint32(2); c < w.count+2; c++ {
		if !w.used[c] {
			w.used[c] = true
			return c
		}
	}
	w.t.Fatal("fixture is out of clusters")
	return 0
}

// chainFiles gives each file its clusters, allocated round robin so that every
// multi-cluster file is fragmented, links them in the FAT, and writes the data.
func (w *fatWriter) chainFiles(files []*fileRec) {
	cb := w.clusterBytes()
	need := map[*fileRec]int{}
	for _, f := range files {
		need[f] = int((int64(len(f.data)) + cb - 1) / cb)
	}
	for progress := true; progress; {
		progress = false
		for _, f := range files {
			if len(f.cl) < need[f] {
				f.cl = append(f.cl, w.alloc())
				progress = true
			}
		}
	}
	for _, f := range files {
		for i, c := range f.cl {
			next := w.eoc()
			if i+1 < len(f.cl) {
				next = f.cl[i+1]
			}
			w.setEntry(c, next)
			end := int64(i+1) * cb
			if end > int64(len(f.data)) {
				end = int64(len(f.data))
			}
			w.f.WriteAt(f.data[int64(i)*cb:end], w.clusterOff(c))
		}
	}
}

// fatTree allocates every directory and file, chains the files, and returns
// the root.
func (w *fatWriter) fatTree(nodes []node) *dnode {
	root := &dnode{name: ""}
	if w.kind != "FAT12" && w.kind != "FAT16" {
		root.cluster = w.alloc()
		w.setEntry(root.cluster, w.eoc())
	}
	var files []*fileRec
	var mk func(d *dnode, list []node)
	mk = func(d *dnode, list []node) {
		for _, n := range list {
			if n.dir {
				sub := &dnode{name: n.name, cluster: w.alloc()}
				w.setEntry(sub.cluster, w.eoc())
				d.kids = append(d.kids, child{dir: sub})
				mk(sub, n.kids)
				continue
			}
			f := &fileRec{name: n.name, data: n.data}
			files = append(files, f)
			d.kids = append(d.kids, child{file: f})
		}
	}
	mk(root, nodes)
	w.chainFiles(files)
	return root
}

// writeDir encodes one directory and writes it to its cluster (or the fixed
// root region). parent is the parent's cluster, 0 for the root.
func (w *fatWriter) writeDir(d *dnode, parent uint32, isRoot bool) {
	t := w.t
	var items []dirItem
	if isRoot {
		items = append(items, dirItem{name: "TESTFAT", attr: attrVolume, label: true})
	} else {
		items = append(items,
			dirItem{name: ".", attr: attrDir, first: d.cluster, dots: true},
			dirItem{name: "..", attr: attrDir, first: parent, dots: true})
	}
	for _, k := range d.kids {
		if k.dir != nil {
			items = append(items, dirItem{name: k.dir.name, attr: attrDir, first: k.dir.cluster})
			continue
		}
		var first uint32
		if len(k.file.cl) > 0 {
			first = k.file.cl[0]
		}
		items = append(items, dirItem{name: k.file.name, attr: 0x20, first: first, size: uint32(len(k.file.data))})
	}
	raw := encodeDir(items)
	switch {
	case isRoot && (w.kind == "FAT12" || w.kind == "FAT16"):
		if int64(len(raw)) > w.rootEnt*32 {
			t.Fatal("fixture root directory is too large")
		}
		w.f.WriteAt(raw, w.fixed)
	default:
		if int64(len(raw)) > w.clusterBytes() {
			t.Fatal("fixture directory does not fit one cluster")
		}
		w.f.WriteAt(raw, w.clusterOff(d.cluster))
	}
	childParent := d.cluster
	if isRoot {
		childParent = 0 // '..' of a directory in the root is cluster 0
	}
	for _, k := range d.kids {
		if k.dir != nil {
			w.writeDir(k.dir, childParent, false)
		}
	}
}

// dirItem is one entry to encode into a directory.
type dirItem struct {
	name  string
	attr  byte
	first uint32
	size  uint32
	label bool
	dots  bool
}

func isShortName(n string) bool {
	base, ext := n, ""
	if i := strings.LastIndexByte(n, '.'); i >= 0 {
		base, ext = n[:i], n[i+1:]
	}
	if base == "" || len(base) > 8 || len(ext) > 3 || strings.ToUpper(n) != n {
		return false
	}
	return !strings.ContainsAny(n, " +,;=[]")
}

// aliasFor is the 8.3 alias written next to a long name.
func aliasFor(long string) string {
	clean := strings.ToUpper(strings.ReplaceAll(long, " ", ""))
	base, ext := clean, ""
	if i := strings.LastIndexByte(clean, '.'); i > 0 {
		base, ext = clean[:i], clean[i+1:]
	}
	if len(base) > 6 {
		base = base[:6]
	}
	if len(ext) > 3 {
		ext = ext[:3]
	}
	if ext == "" {
		return base + "~1"
	}
	return base + "~1." + ext
}

// shortRaw builds the 32-byte short entry for an 8.3 name.
func shortRaw(name string, attr byte, first uint32, size uint32) []byte {
	e := make([]byte, 32)
	for i := 0; i < 11; i++ {
		e[i] = ' '
	}
	base, ext := name, ""
	if i := strings.LastIndexByte(name, '.'); i > 0 {
		base, ext = name[:i], name[i+1:]
	}
	copy(e[0:8], base)
	copy(e[8:11], ext)
	e[11] = attr
	date := uint16((2022-1980)<<9 | 2<<5 | 4)
	tm := uint16(10 << 11)
	binary.LittleEndian.PutUint16(e[14:], tm)
	binary.LittleEndian.PutUint16(e[16:], date)
	binary.LittleEndian.PutUint16(e[20:], uint16(first>>16))
	binary.LittleEndian.PutUint16(e[22:], tm)
	binary.LittleEndian.PutUint16(e[24:], date)
	binary.LittleEndian.PutUint16(e[26:], uint16(first))
	binary.LittleEndian.PutUint32(e[28:], size)
	return e
}

// lfnFor encodes the long-name entries for long, in on-disk order, carrying
// the checksum of the short alias they precede.
func lfnFor(long string, short []byte) [][]byte {
	u := utf16.Encode([]rune(long))
	n := (len(u) + 12) / 13
	sum := shortChecksum(short)
	offs := []int{1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30}
	var out [][]byte
	for seq := n; seq >= 1; seq-- {
		e := make([]byte, 32)
		e[0] = byte(seq)
		if seq == n {
			e[0] |= 0x40
		}
		e[11] = attrLFN
		e[13] = sum
		for i, o := range offs {
			idx := (seq-1)*13 + i
			c := uint16(0xFFFF)
			switch {
			case idx < len(u):
				c = u[idx]
			case idx == len(u):
				c = 0
			}
			binary.LittleEndian.PutUint16(e[o:], c)
		}
		out = append(out, e)
	}
	return out
}

// encodeDir encodes a directory's entries, long names included.
func encodeDir(items []dirItem) []byte {
	var out []byte
	for _, it := range items {
		switch {
		case it.label:
			out = append(out, shortRaw(it.name, attrVolume, 0, 0)...)
		case it.dots:
			e := shortRaw("", attrDir, it.first, 0)
			copy(e[0:11], []byte(it.name+strings.Repeat(" ", 11-len(it.name))))
			out = append(out, e...)
		case isShortName(it.name):
			out = append(out, shortRaw(it.name, it.attr, it.first, it.size)...)
		default:
			short := shortRaw(aliasFor(it.name), it.attr, it.first, it.size)
			for _, l := range lfnFor(it.name, short) {
				out = append(out, l...)
			}
			out = append(out, short...)
		}
	}
	return out
}

func writeFATTree(t testing.TB, kind string) (string, []byte) {
	path, w := newFATFixture(t, kind)
	root := w.fatTree(tree())
	w.writeDir(root, 0, true)
	if kind == "FAT32" {
		w.writeFSInfo()
	}
	return path, nil
}

// writeFSInfo records the free cluster count in the FAT32 FSInfo sector, which
// a checker compares with the FAT.
func (w *fatWriter) writeFSInfo() {
	bs := make([]byte, 512)
	w.f.ReadAt(bs, 0)
	sec := int64(le16(bs, 48))
	used := uint32(0)
	for c := uint32(2); c < w.count+2; c++ {
		if w.used[c] {
			used++
		}
	}
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, w.count-used)
	w.f.WriteAt(b, sec*w.bps+488)
}

func TestFAT_ReadsWhatWasWritten(t *testing.T) {
	for _, kind := range []string{"FAT12", "FAT16", "FAT32"} {
		t.Run(kind, func(t *testing.T) {
			path, _ := writeFATTree(t, kind)
			fsckClean(t, "fsck.fat", "-n", path)
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			st, _ := f.Stat()
			v, err := Open(f, st.Size())
			if err != nil {
				t.Fatal(err)
			}
			if v.kind != kind {
				t.Fatalf("classified as %s, want %s", v.kind, kind)
			}
			checkTree(t, v, expected(tree(), "", nil))
		})
	}
}

// ---- exFAT

type exWriter struct {
	t       testing.TB
	f       *os.File
	cb      int64
	heap    int64
	fatOff  int64
	fatLen  int64
	nfats   int64
	count   uint32
	rootCl  uint32
	bmCl    uint32
	bmLen   int64
	used    []bool
	gapNext uint32
}

func newExFATFixture(t testing.TB) (string, *exWriter) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "exfat.img")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(16 << 20); err != nil {
		t.Fatal(err)
	}
	f.Close()
	runTool(t, "mkfs.exfat", "-n", "TESTEX", path)
	f, err = os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	bs := make([]byte, 512)
	if _, err := f.ReadAt(bs, 0); err != nil {
		t.Fatal(err)
	}
	bps := int64(1) << bs[108]
	w := &exWriter{t: t, f: f}
	w.cb = bps << bs[109]
	w.fatOff = int64(le32(bs, 80)) * bps
	w.fatLen = int64(le32(bs, 84)) * bps
	w.heap = int64(le32(bs, 88)) * bps
	w.count = le32(bs, 92)
	w.rootCl = le32(bs, 96)
	w.nfats = int64(bs[110])
	w.used = make([]bool, w.count+2)
	w.gapNext = 2
	rootBytes := make([]byte, w.cb)
	if _, err := f.ReadAt(rootBytes, w.clusterOff(w.rootCl)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i+32 <= len(rootBytes); i += 32 {
		if rootBytes[i] == 0x81 {
			w.bmCl = le32(rootBytes, i+20)
			w.bmLen = int64(le64(rootBytes, i+24))
		}
	}
	if w.bmCl == 0 {
		t.Fatal("no allocation bitmap entry in the root directory")
	}
	bm := make([]byte, w.bmLen)
	if _, err := f.ReadAt(bm, w.clusterOff(w.bmCl)); err != nil {
		t.Fatal(err)
	}
	for c := uint32(2); c < w.count+2; c++ {
		bit := c - 2
		w.used[c] = bm[bit/8]&(1<<(bit%8)) != 0
	}
	return path, w
}

func (w *exWriter) clusterOff(c uint32) int64 { return w.heap + int64(c-2)*w.cb }

// allocRun reserves n consecutive free clusters and returns the first.
func (w *exWriter) allocRun(n int) uint32 {
	for start := uint32(2); start+uint32(n) <= w.count+2; start++ {
		ok := true
		for c := start; c < start+uint32(n); c++ {
			if w.used[c] {
				ok = false
				start = c
				break
			}
		}
		if ok {
			for c := start; c < start+uint32(n); c++ {
				w.used[c] = true
			}
			return start
		}
	}
	w.t.Fatal("exFAT fixture is out of clusters")
	return 0
}

// allocGap takes the next free cluster after the previous one taken this way,
// leaving the cluster after it free, so the file it belongs to is fragmented.
func (w *exWriter) allocGap() uint32 {
	for c := w.gapNext; c < w.count+2; c++ {
		if !w.used[c] {
			w.used[c] = true
			w.gapNext = c + 2
			return c
		}
	}
	w.t.Fatal("exFAT fixture is out of clusters")
	return 0
}

func (w *exWriter) setFAT(c uint32, val uint32) {
	for k := int64(0); k < w.nfats; k++ {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, val)
		w.f.WriteAt(b, w.fatOff+k*w.fatLen+int64(c)*4)
	}
}

func (w *exWriter) saveBitmap() {
	bm := make([]byte, w.bmLen)
	for c := uint32(2); c < w.count+2; c++ {
		if w.used[c] {
			bit := c - 2
			bm[bit/8] |= 1 << (bit % 8)
		}
	}
	w.f.WriteAt(bm, w.clusterOff(w.bmCl))
}

// exNameHash is the name hash of an exFAT stream entry, computed over the
// upper-cased name (ASCII letters only, which is all the fixture uses).
func exNameHash(u []uint16) uint16 {
	var h uint16
	for _, c := range u {
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		for _, b := range []byte{byte(c), byte(c >> 8)} {
			h = ((h << 15) | (h >> 1)) + uint16(b)
		}
	}
	return h
}

// exSet encodes one exFAT file entry set. contiguous marks a file with no FAT
// chain, whose clusters are first, first+1, ...
func exSet(name string, attr uint16, first uint32, size int64, contiguous bool) []byte {
	u := utf16.Encode([]rune(name))
	nameEntries := (len(u) + 14) / 15
	secondary := 1 + nameEntries
	set := make([]byte, (1+secondary)*32)
	ts := uint32((2022-1980)<<9|2<<5|4)<<16 | uint32(10<<11)
	set[0] = 0x85
	set[1] = byte(secondary)
	binary.LittleEndian.PutUint16(set[4:], attr)
	binary.LittleEndian.PutUint32(set[8:], ts)
	binary.LittleEndian.PutUint32(set[12:], ts)
	binary.LittleEndian.PutUint32(set[16:], ts)
	s := set[32:]
	s[0] = 0xC0
	s[1] = 0x01
	if contiguous {
		s[1] |= 0x02
	}
	s[3] = byte(len(u))
	binary.LittleEndian.PutUint16(s[4:], exNameHash(u))
	binary.LittleEndian.PutUint64(s[8:], uint64(size))
	binary.LittleEndian.PutUint32(s[20:], first)
	binary.LittleEndian.PutUint64(s[24:], uint64(size))
	for k := 0; k < nameEntries; k++ {
		ne := set[(2+k)*32:]
		ne[0] = 0xC1
		for i := 0; i < 15; i++ {
			idx := k*15 + i
			c := uint16(0)
			if idx < len(u) {
				c = u[idx]
			}
			binary.LittleEndian.PutUint16(ne[2+2*i:], c)
		}
	}
	binary.LittleEndian.PutUint16(set[2:], exFATChecksum(set))
	return set
}

type exFile struct {
	name       string
	data       []byte
	contiguous bool
	cl         []uint32
	dir        *exDir
}

type exDir struct {
	name    string
	cluster uint32
	files   []*exFile
	subs    []*exDir
}

// exTree lays out the tree: directories get one contiguous cluster each, and
// files either a contiguous run or a fragmented chain.
func (w *exWriter) exTree(nodes []node, into *exDir) {
	for _, n := range nodes {
		if n.dir {
			sub := &exDir{name: n.name, cluster: w.allocRun(1)}
			into.subs = append(into.subs, sub)
			w.exTree(n.kids, sub)
			continue
		}
		into.files = append(into.files, &exFile{name: n.name, data: n.data, contiguous: n.name != "Quarterly Report 2024.txt" && n.name != "big.bin"})
	}
}

// layoutFiles gives contiguous files runs, and fragmented files clusters
// allocated round robin, then links the fragmented chains in the FAT.
func (w *exWriter) layoutFiles(dir *exDir) {
	var chained []*exFile
	for _, f := range dir.files {
		n := int((int64(len(f.data)) + w.cb - 1) / w.cb)
		if f.contiguous {
			if n > 0 {
				first := w.allocRun(n)
				for i := 0; i < n; i++ {
					f.cl = append(f.cl, first+uint32(i))
				}
			}
			continue
		}
		chained = append(chained, f)
	}
	need := func(f *exFile) int { return int((int64(len(f.data)) + w.cb - 1) / w.cb) }
	for progress := true; progress; {
		progress = false
		for _, f := range chained {
			if len(f.cl) < need(f) {
				c := w.allocGap()
				f.cl = append(f.cl, c)
				progress = true
			}
		}
	}
	for _, f := range chained {
		for i, c := range f.cl {
			next := uint32(0xFFFFFFFF)
			if i+1 < len(f.cl) {
				next = f.cl[i+1]
			}
			w.setFAT(c, next)
		}
	}
	for _, f := range dir.files {
		for i, c := range f.cl {
			end := int64(i+1) * w.cb
			if end > int64(len(f.data)) {
				end = int64(len(f.data))
			}
			w.f.WriteAt(f.data[int64(i)*w.cb:end], w.clusterOff(c))
		}
	}
	for _, s := range dir.subs {
		w.layoutFiles(s)
	}
}

// dirSets is the entry sets of one directory, in order.
func (w *exWriter) dirSets(d *exDir) []byte {
	var out []byte
	for _, s := range d.subs {
		var first uint32 = s.cluster
		out = append(out, exSet(s.name, 0x10, first, w.cb, true)...)
	}
	for _, f := range d.files {
		var first uint32
		if len(f.cl) > 0 {
			first = f.cl[0]
		}
		noChain := len(f.cl) > 0 && (f.contiguous || len(f.cl) == 1)
		out = append(out, exSet(f.name, 0x20, first, int64(len(f.data)), noChain)...)
	}
	return out
}

// writeExDir writes a directory's sets to its cluster, and recurses.
func (w *exWriter) writeExDir(d *exDir) {
	raw := w.dirSets(d)
	if int64(len(raw)) > w.cb {
		w.t.Fatal("exFAT fixture directory does not fit one cluster")
	}
	w.f.WriteAt(raw, w.clusterOff(d.cluster))
	for _, s := range d.subs {
		w.writeExDir(s)
	}
}

func writeExFATTree(t testing.TB) string {
	path, w := newExFATFixture(t)
	root := &exDir{name: "", cluster: w.rootCl}
	w.exTree(tree(), root)
	w.layoutFiles(root)
	// The root keeps its volume entries (bitmap, upcase table, label); the
	// file sets are appended after them.
	rootBytes := make([]byte, w.cb)
	if _, err := w.f.ReadAt(rootBytes, w.clusterOff(w.rootCl)); err != nil {
		t.Fatal(err)
	}
	end := 0
	for end+32 <= len(rootBytes) && rootBytes[end] != 0 {
		end += 32
	}
	sets := w.dirSets(root)
	if int64(end+len(sets)) > w.cb {
		t.Fatal("exFAT fixture root directory does not fit one cluster")
	}
	copy(rootBytes[end:], sets)
	w.f.WriteAt(rootBytes, w.clusterOff(w.rootCl))
	for _, s := range root.subs {
		w.writeExDir(s)
	}
	w.saveBitmap()
	return path
}

func TestExFAT_ReadsWhatWasWritten(t *testing.T) {
	path := writeExFATTree(t)
	fsckClean(t, "fsck.exfat", "-n", path)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, _ := f.Stat()
	v, err := Open(f, st.Size())
	if err != nil {
		t.Fatal(err)
	}
	if v.kind != "exFAT" {
		t.Fatalf("classified as %s", v.kind)
	}
	checkTree(t, v, expected(tree(), "", nil))
}

// ---- damage: a damaged image must produce errors or corrupt counts, never a
// panic.

func TestDamagedImages_NeverPanic(t *testing.T) {
	cases := map[string]func(testing.TB) string{
		"FAT16": func(t testing.TB) string { p, _ := writeFATTree(t, "FAT16"); return p },
		"FAT32": func(t testing.TB) string { p, _ := writeFATTree(t, "FAT32"); return p },
		"exFAT": writeExFATTree,
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			path := mk(t)
			orig, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			seed := uint32(12345)
			next := func(n int) int {
				seed = seed*1664525 + 1013904223
				return int(seed>>8) % n
			}
			for i := 0; i < 200; i++ {
				m := append([]byte(nil), orig...)
				for k := 0; k < 1+next(8); k++ {
					m[next(len(m))] = byte(next(256))
				}
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("mutation %d panicked: %v", i, r)
						}
					}()
					v, err := Open(bytesReaderAt(m), int64(len(m)))
					if err != nil {
						return
					}
					_, _ = v.Walk(func(f fsvol.File) error {
						if r, err := v.OpenStream(f.Record, ""); err == nil {
							buf := make([]byte, 4096)
							_, _ = r.ReadAt(buf, 0)
						}
						return nil
					})
				}()
			}
		})
	}
}

type bytesReaderAt []byte

func (b bytesReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(b)) {
		return 0, io.EOF
	}
	n := copy(p, b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// A fragmented file must be read through its FAT chain, which is the path the
// contiguous files do not exercise. The fixture is checked to be fragmented
// first, so the test cannot pass on a layout that never needed the chain.
func TestFragmentedChains_AreFollowed(t *testing.T) {
	check := func(t testing.TB, v *Volume) {
		t.Helper()
		files := walkFiles(t, v)
		f, ok := files["/big.bin"]
		if !ok {
			t.Fatal("/big.bin is not listed")
		}
		r, err := v.OpenStream(f.Record, "")
		if err != nil {
			t.Fatal(err)
		}
		cl := r.(*Reader).clusters
		if len(cl) < 3 {
			t.Fatalf("/big.bin has %d clusters, want several", len(cl))
		}
		gaps := 0
		for i := 1; i < len(cl); i++ {
			if cl[i] != cl[i-1]+1 {
				gaps++
			}
		}
		if gaps == 0 {
			t.Fatalf("/big.bin is contiguous; the fixture does not exercise the chain")
		}
		if got := readAllFile(t, v, f); string(got) != string(tree()[3].data) {
			t.Fatal("fragmented content differs")
		}
	}
	for _, kind := range []string{"FAT12", "FAT16", "FAT32"} {
		t.Run(kind, func(t *testing.T) {
			path, _ := writeFATTree(t, kind)
			fh, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer fh.Close()
			st, _ := fh.Stat()
			v, err := Open(fh, st.Size())
			if err != nil {
				t.Fatal(err)
			}
			check(t, v)
		})
	}
	t.Run("exFAT", func(t *testing.T) {
		path := writeExFATTree(t)
		fh, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer fh.Close()
		st, _ := fh.Stat()
		v, err := Open(fh, st.Size())
		if err != nil {
			t.Fatal(err)
		}
		check(t, v)
	})
}
