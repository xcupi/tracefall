// Package olecf reads the Microsoft Compound File Binary Format (CFB),
// also called OLE structured storage.
//
// It exists because Windows Jump Lists are CFB containers, but nothing
// here is Jump List specific: CFB is a general filesystem-in-a-file used
// by Thumbs.db, MSI packages and pre-2007 Office documents, so it is a
// format reader in its own right.
//
// # What it does
//
// Opens a container, validates its header, walks its allocation tables
// and directory tree, and hands back named streams as bytes. That is
// all. It never writes, never interprets stream CONTENT, and has no
// opinion about what any stream holds.
//
// # Hostile input
//
// Every sector number, chain length and stream size comes from the file
// being read. A forensic tool reads files written by the subject of the
// investigation, so all of them are treated as hostile:
//
//   - every sector index is bounds-checked against the file's real size
//   - every chain walk is bounded by the number of sectors that exist,
//     so a chain that loops back on itself terminates instead of running
//     forever
//   - a declared stream size larger than the container is refused rather
//     than used to allocate
//   - the directory tree is walked ITERATIVELY with a visited set, so a
//     tree whose siblings point at each other cannot recurse without end
//
// A malformed container returns an error. It never panics, and never
// allocates on the strength of a number it has not checked.
package olecf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode/utf16"
)

var (
	// ErrNotCompoundFile means the header signature or byte order did
	// not match.
	ErrNotCompoundFile = errors.New("olecf: not a compound file")
	// ErrCorrupt means the container is structurally invalid.
	ErrCorrupt = errors.New("olecf: compound file is corrupt or truncated")
	// ErrLimitExceeded means a declared size exceeded a safety ceiling.
	ErrLimitExceeded = errors.New("olecf: compound file exceeds a safety limit")
	// ErrUnsupportedVersion means the major version is one this build
	// does not read.
	ErrUnsupportedVersion = errors.New("olecf: unsupported compound file version")
)

// signature is the fixed 8-byte header magic, D0 CF 11 E0 A1 B1 1A E1.
var signature = [8]byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}

// Sector chain sentinels.
const (
	maxRegSect = 0xFFFFFFFA
	difSect    = 0xFFFFFFFC
	fatSect    = 0xFFFFFFFD
	endOfChain = 0xFFFFFFFE
	freeSect   = 0xFFFFFFFF
)

// Directory entry object types.
const (
	typeUnallocated = 0
	typeStorage     = 1
	typeStream      = 2
	typeRoot        = 5
)

const (
	headerBytes   = 512
	dirEntryBytes = 128
	// miniSectorBytes is fixed by the format at 64.
	miniSectorBytes = 64
	// maxNameChars is the directory entry name field, in UTF-16 units.
	maxNameChars = 32
)

// Limits bounds what one container may consume.
type Limits struct {
	MaxFileBytes   int64
	MaxStreamBytes int64
	MaxEntries     int
}

// DefaultLimits comfortably fit any Jump List -- a large one is a few
// hundred kilobytes -- while bounding a hostile container.
func DefaultLimits() Limits {
	return Limits{
		MaxFileBytes:   256 << 20, // 256 MiB
		MaxStreamBytes: 64 << 20,  // 64 MiB
		MaxEntries:     1 << 16,
	}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxFileBytes <= 0 {
		l.MaxFileBytes = d.MaxFileBytes
	}
	if l.MaxStreamBytes <= 0 {
		l.MaxStreamBytes = d.MaxStreamBytes
	}
	if l.MaxEntries <= 0 {
		l.MaxEntries = d.MaxEntries
	}
	return l
}

// Entry is one directory entry: a stream, a storage, or the root.
type Entry struct {
	// Name is the entry's name, decoded from UTF-16.
	Name string
	// Path is the name joined to its parent storages with "/", so an
	// entry can be located inside a nested container.
	Path string
	Type uint8
	// Index is the entry's position in the directory, which is what a
	// provenance record cites to identify exactly where a stream lived.
	Index int
	// Size is the stream's declared length in bytes. Zero for storages.
	Size int64
	// Created and Modified are the entry's own timestamps, in UTC. Zero
	// when the container recorded none -- which is usual for a Jump
	// List, where Windows leaves them unset.
	Created  time.Time
	Modified time.Time
	// CLSID is the entry's class identifier, when it set one.
	CLSID string
	// startSector is where the entry's stream begins.
	startSector uint32
}

// IsStream reports whether this entry holds data.
func (e Entry) IsStream() bool { return e.Type == typeStream }

// File is an opened compound file.
type File struct {
	// Version is the container's major version: 3 (512-byte sectors) or
	// 4 (4096-byte sectors).
	Version uint16
	// SectorSize is the sector length this container uses.
	SectorSize int
	// Entries is every directory entry, in directory order.
	Entries []Entry
	// Warnings records structural problems that did not prevent the
	// container being read.
	Warnings []string

	data       []byte
	fat        []uint32
	miniFAT    []uint32
	miniStream []byte
	cutoff     uint32
	lim        Limits
}

// Sniff reports whether header begins a compound file.
//
// The signature is eight fixed bytes and the byte-order mark is two
// more; requiring both keeps this from claiming a file that merely
// happens to start with the magic.
func Sniff(header []byte) bool {
	if len(header) < 0x20 {
		return false
	}
	for i := 0; i < 8; i++ {
		if header[i] != signature[i] {
			return false
		}
	}
	// Only little-endian containers exist in practice, and the format
	// defines the field, so a different value is not a compound file
	// this reader should claim.
	return binary.LittleEndian.Uint16(header[0x1C:0x1E]) == 0xFFFE
}

// OpenFile reads and parses a compound file from disk.
func OpenFile(path string, lim Limits) (*File, error) {
	lim = lim.withDefaults()
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > lim.MaxFileBytes {
		return nil, fmt.Errorf("%w: file is %d bytes", ErrLimitExceeded, info.Size())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Open(data, lim)
}

// Open parses a compound file already in memory.
func Open(data []byte, lim Limits) (f *File, err error) {
	lim = lim.withDefaults()
	defer func() {
		if r := recover(); r != nil {
			f, err = nil, fmt.Errorf("%w: recovered from %v", ErrCorrupt, r)
		}
	}()

	if !Sniff(data) {
		return nil, ErrNotCompoundFile
	}
	if len(data) < headerBytes {
		return nil, fmt.Errorf("%w: %d bytes, shorter than the header", ErrCorrupt, len(data))
	}

	major := binary.LittleEndian.Uint16(data[0x1A:0x1C])
	shift := binary.LittleEndian.Uint16(data[0x1E:0x20])
	// The format ties the sector shift to the version. Accepting a
	// mismatch would mean reading every subsequent offset from the wrong
	// stride, so it is refused rather than guessed at.
	switch {
	case major == 3 && shift == 9:
	case major == 4 && shift == 12:
	default:
		return nil, fmt.Errorf("%w: version %d with sector shift %d", ErrUnsupportedVersion, major, shift)
	}
	if miniShift := binary.LittleEndian.Uint16(data[0x20:0x22]); miniShift != 6 {
		return nil, fmt.Errorf("%w: mini sector shift is %d, not 6", ErrUnsupportedVersion, miniShift)
	}

	f = &File{
		Version:    major,
		SectorSize: 1 << shift,
		data:       data,
		cutoff:     binary.LittleEndian.Uint32(data[0x38:0x3C]),
		lim:        lim,
	}
	if f.cutoff == 0 {
		f.cutoff = 4096
	}

	if err := f.readFAT(); err != nil {
		return nil, err
	}
	if err := f.readDirectory(); err != nil {
		return nil, err
	}
	if err := f.readMini(); err != nil {
		return nil, err
	}
	return f, nil
}

// sectorCount is how many whole sectors the file actually holds.
func (f *File) sectorCount() int {
	if len(f.data) <= headerBytes {
		return 0
	}
	return (len(f.data) - headerBytes) / f.SectorSize
}

// sector returns one sector's bytes, or nil when it lies outside the
// file. Every read in this package goes through here.
func (f *File) sector(n uint32) []byte {
	if n > maxRegSect {
		return nil
	}
	start := headerBytes + int(n)*f.SectorSize
	end := start + f.SectorSize
	if start < headerBytes || end > len(f.data) {
		return nil
	}
	return f.data[start:end]
}

// readFAT assembles the file allocation table from the DIFAT.
func (f *File) readFAT() error {
	numFAT := int(binary.LittleEndian.Uint32(f.data[0x2C:0x30]))
	difStart := binary.LittleEndian.Uint32(f.data[0x44:0x48])
	numDIF := int(binary.LittleEndian.Uint32(f.data[0x48:0x4C]))

	if numFAT < 0 || numFAT > f.sectorCount()+1 {
		return fmt.Errorf("%w: header declares %d FAT sectors, more than the file holds", ErrCorrupt, numFAT)
	}

	// The first 109 FAT sector numbers live in the header itself.
	fatSectors := make([]uint32, 0, numFAT)
	for i := 0; i < 109 && len(fatSectors) < numFAT; i++ {
		s := binary.LittleEndian.Uint32(f.data[0x4C+i*4 : 0x50+i*4])
		if s > maxRegSect {
			break
		}
		fatSectors = append(fatSectors, s)
	}

	// Any remainder is chained through DIFAT sectors. Bounded by the
	// number of sectors that exist, so a self-referential chain stops.
	next := difStart
	for steps := 0; next <= maxRegSect && len(fatSectors) < numFAT && steps <= f.sectorCount()+1; steps++ {
		sec := f.sector(next)
		if sec == nil {
			f.Warnings = append(f.Warnings, "a DIFAT sector lies outside the file; the allocation table is incomplete")
			break
		}
		perSector := f.SectorSize/4 - 1
		for i := 0; i < perSector && len(fatSectors) < numFAT; i++ {
			s := binary.LittleEndian.Uint32(sec[i*4 : i*4+4])
			if s > maxRegSect {
				continue
			}
			fatSectors = append(fatSectors, s)
		}
		next = binary.LittleEndian.Uint32(sec[len(sec)-4:])
	}
	if numDIF > 0 && len(fatSectors) < numFAT {
		f.Warnings = append(f.Warnings, fmt.Sprintf(
			"the header declares %d FAT sectors but only %d could be located", numFAT, len(fatSectors)))
	}

	f.fat = make([]uint32, 0, len(fatSectors)*f.SectorSize/4)
	for _, s := range fatSectors {
		sec := f.sector(s)
		if sec == nil {
			f.Warnings = append(f.Warnings, "a FAT sector lies outside the file; some chains cannot be followed")
			continue
		}
		for i := 0; i+4 <= len(sec); i += 4 {
			f.fat = append(f.fat, binary.LittleEndian.Uint32(sec[i:i+4]))
		}
	}
	if len(f.fat) == 0 {
		return fmt.Errorf("%w: the file allocation table is empty or unreadable", ErrCorrupt)
	}
	return nil
}

// chain walks a sector chain, returning its sector numbers.
//
// Bounded twice: by the number of entries in the FAT, and by a visited
// set. A chain that revisits a sector is truncated there and reported --
// a loop in a hostile file must not become an infinite read.
func (f *File) chain(start uint32) ([]uint32, bool) {
	var out []uint32
	seen := make(map[uint32]bool)
	for s := start; s <= maxRegSect; {
		if seen[s] {
			return out, false
		}
		seen[s] = true
		out = append(out, s)
		if int(s) >= len(f.fat) {
			return out, false
		}
		next := f.fat[s]
		if next == endOfChain || next == freeSect || next == fatSect || next == difSect {
			break
		}
		if next > maxRegSect {
			return out, false
		}
		s = next
	}
	return out, true
}

// readChain concatenates a sector chain's bytes, up to size.
func (f *File) readChain(start uint32, size int64) ([]byte, bool) {
	if size < 0 || size > f.lim.MaxStreamBytes {
		return nil, false
	}
	sectors, ok := f.chain(start)
	if len(sectors) == 0 {
		return nil, size == 0
	}
	// Never allocate more than the chain can actually supply, however
	// large the declared size is.
	available := int64(len(sectors)) * int64(f.SectorSize)
	if size > available {
		size = available
	}
	out := make([]byte, 0, size)
	for _, s := range sectors {
		sec := f.sector(s)
		if sec == nil {
			return out, false
		}
		need := size - int64(len(out))
		if need <= 0 {
			break
		}
		if int64(len(sec)) > need {
			sec = sec[:need]
		}
		out = append(out, sec...)
	}
	return out, ok
}

// readDirectory walks the directory chain and decodes every entry.
func (f *File) readDirectory() error {
	first := binary.LittleEndian.Uint32(f.data[0x30:0x34])
	sectors, complete := f.chain(first)
	if !complete {
		f.Warnings = append(f.Warnings, "the directory chain is truncated or loops; some entries may be missing")
	}
	if len(sectors) == 0 {
		return fmt.Errorf("%w: the directory has no sectors", ErrCorrupt)
	}

	perSector := f.SectorSize / dirEntryBytes
	for _, s := range sectors {
		sec := f.sector(s)
		if sec == nil {
			f.Warnings = append(f.Warnings, "a directory sector lies outside the file")
			continue
		}
		for i := 0; i < perSector; i++ {
			if len(f.Entries) >= f.lim.MaxEntries {
				f.Warnings = append(f.Warnings, fmt.Sprintf("stopped at the %d-entry limit", f.lim.MaxEntries))
				return nil
			}
			raw := sec[i*dirEntryBytes : (i+1)*dirEntryBytes]
			e, ok := decodeEntry(raw, len(f.Entries))
			if !ok {
				continue
			}
			f.Entries = append(f.Entries, e)
		}
	}
	if len(f.Entries) == 0 {
		return fmt.Errorf("%w: the directory holds no usable entries", ErrCorrupt)
	}
	f.assignPaths()
	return nil
}

// decodeEntry decodes one 128-byte directory entry.
func decodeEntry(b []byte, index int) (Entry, bool) {
	objType := b[0x42]
	switch objType {
	case typeStorage, typeStream, typeRoot:
	default:
		return Entry{}, false // unallocated
	}

	nameLen := int(binary.LittleEndian.Uint16(b[0x40:0x42]))
	// The field is a byte count INCLUDING the terminating NUL, and can
	// be no larger than the fixed 64-byte field.
	if nameLen < 2 || nameLen > maxNameChars*2 {
		return Entry{}, false
	}
	units := make([]uint16, 0, nameLen/2)
	for i := 0; i+1 < nameLen-2+2 && i+1 < 64; i += 2 {
		u := binary.LittleEndian.Uint16(b[i : i+2])
		if u == 0 {
			break
		}
		units = append(units, u)
	}
	name := sanitize(string(utf16.Decode(units)))
	if name == "" && objType != typeRoot {
		return Entry{}, false
	}

	e := Entry{
		Name:        name,
		Type:        objType,
		Index:       index,
		startSector: binary.LittleEndian.Uint32(b[0x74:0x78]),
		Created:     fileTime(binary.LittleEndian.Uint64(b[0x64:0x6C])),
		Modified:    fileTime(binary.LittleEndian.Uint64(b[0x6C:0x74])),
	}
	size := binary.LittleEndian.Uint64(b[0x78:0x80])
	// A v3 container's size field is 32-bit; the upper half must be
	// ignored rather than read as an enormous stream.
	if size > 1<<40 {
		size &= 0xFFFFFFFF
	}
	e.Size = int64(size)
	if clsid := formatGUID(b[0x50:0x60]); clsid != "00000000-0000-0000-0000-000000000000" {
		e.CLSID = clsid
	}
	return e, true
}

// assignPaths gives every entry a path by walking the directory tree
// from the root.
//
// Iterative, with a visited set. The tree's sibling and child pointers
// come from the file, and a hostile container can point them at each
// other; a recursive walk would exhaust the stack, and an unbounded
// iterative one would not terminate. Entries the walk never reaches keep
// their bare name, so nothing is dropped for being unreachable.
func (f *File) assignPaths() {
	for i := range f.Entries {
		f.Entries[i].Path = f.Entries[i].Name
	}
	if len(f.Entries) == 0 || f.Entries[0].Type != typeRoot {
		return
	}

	type todo struct {
		index  int
		prefix string
	}
	// The root's child subtree is everything below it.
	visited := map[int]bool{0: true}
	queue := []todo{}
	if child, ok := f.childOf(0); ok {
		queue = append(queue, todo{child, ""})
	}

	for len(queue) > 0 && len(visited) <= len(f.Entries) {
		cur := queue[0]
		queue = queue[1:]
		if cur.index < 0 || cur.index >= len(f.Entries) || visited[cur.index] {
			continue
		}
		visited[cur.index] = true
		e := &f.Entries[cur.index]
		e.Path = cur.prefix + e.Name

		raw := f.rawEntry(cur.index)
		if raw == nil {
			continue
		}
		// Siblings share this entry's prefix; a child nests under it.
		for _, off := range []int{0x44, 0x48} {
			if s := int32(binary.LittleEndian.Uint32(raw[off : off+4])); s >= 0 {
				queue = append(queue, todo{int(s), cur.prefix})
			}
		}
		if c := int32(binary.LittleEndian.Uint32(raw[0x4C:0x50])); c >= 0 && e.Type == typeStorage {
			queue = append(queue, todo{int(c), e.Path + "/"})
		}
	}
}

func (f *File) childOf(index int) (int, bool) {
	raw := f.rawEntry(index)
	if raw == nil {
		return 0, false
	}
	c := int32(binary.LittleEndian.Uint32(raw[0x4C:0x50]))
	if c < 0 || int(c) >= len(f.Entries) {
		return 0, false
	}
	return int(c), true
}

// rawEntry returns one directory entry's original 128 bytes.
func (f *File) rawEntry(index int) []byte {
	first := binary.LittleEndian.Uint32(f.data[0x30:0x34])
	sectors, _ := f.chain(first)
	perSector := f.SectorSize / dirEntryBytes
	if perSector == 0 {
		return nil
	}
	secIdx, within := index/perSector, index%perSector
	if secIdx < 0 || secIdx >= len(sectors) {
		return nil
	}
	sec := f.sector(sectors[secIdx])
	if sec == nil {
		return nil
	}
	return sec[within*dirEntryBytes : (within+1)*dirEntryBytes]
}

// readMini loads the mini FAT and the mini stream.
//
// Streams below the container's cutoff -- 4096 bytes by default, which
// is every Jump List LNK -- do not live in ordinary sectors at all. They
// live inside the root entry's own stream, chopped into 64-byte mini
// sectors and chained through a separate table. A reader that skipped
// this would find every Jump List's streams empty.
func (f *File) readMini() error {
	miniFATStart := binary.LittleEndian.Uint32(f.data[0x3C:0x40])
	sectors, complete := f.chain(miniFATStart)
	if !complete {
		f.Warnings = append(f.Warnings, "the mini FAT chain is truncated or loops")
	}
	for _, s := range sectors {
		sec := f.sector(s)
		if sec == nil {
			continue
		}
		for i := 0; i+4 <= len(sec); i += 4 {
			f.miniFAT = append(f.miniFAT, binary.LittleEndian.Uint32(sec[i:i+4]))
		}
	}

	root := f.Entries[0]
	if root.Type != typeRoot {
		f.Warnings = append(f.Warnings, "the first directory entry is not the root; small streams are unavailable")
		return nil
	}
	if root.Size == 0 {
		return nil
	}
	stream, ok := f.readChain(root.startSector, root.Size)
	if !ok {
		f.Warnings = append(f.Warnings, "the mini stream is truncated; some small streams may be incomplete")
	}
	f.miniStream = stream
	return nil
}

// Stream returns one entry's bytes.
//
// Which table the stream lives in is decided by its size against the
// container's own cutoff, exactly as the format specifies.
func (f *File) Stream(e Entry) ([]byte, error) {
	if e.Type != typeStream {
		return nil, fmt.Errorf("%w: %q is not a stream", ErrCorrupt, e.Name)
	}
	if e.Size == 0 {
		return nil, nil
	}
	if e.Size > f.lim.MaxStreamBytes {
		return nil, fmt.Errorf("%w: stream %q declares %d bytes", ErrLimitExceeded, e.Name, e.Size)
	}

	if uint32(e.Size) < f.cutoff {
		return f.readMiniChain(e)
	}
	data, ok := f.readChain(e.startSector, e.Size)
	if !ok && len(data) == 0 {
		return nil, fmt.Errorf("%w: stream %q could not be read", ErrCorrupt, e.Name)
	}
	return data, nil
}

// readMiniChain assembles a small stream from the mini stream.
func (f *File) readMiniChain(e Entry) ([]byte, error) {
	out := make([]byte, 0, e.Size)
	seen := make(map[uint32]bool)
	for s := e.startSector; s <= maxRegSect && int64(len(out)) < e.Size; {
		if seen[s] {
			return out, fmt.Errorf("%w: stream %q chains back on itself", ErrCorrupt, e.Name)
		}
		seen[s] = true

		start := int(s) * miniSectorBytes
		end := start + miniSectorBytes
		if start < 0 || end > len(f.miniStream) {
			return out, fmt.Errorf("%w: stream %q points outside the mini stream", ErrCorrupt, e.Name)
		}
		chunk := f.miniStream[start:end]
		if need := e.Size - int64(len(out)); int64(len(chunk)) > need {
			chunk = chunk[:need]
		}
		out = append(out, chunk...)

		if int(s) >= len(f.miniFAT) {
			break
		}
		next := f.miniFAT[s]
		if next > maxRegSect {
			break
		}
		s = next
	}
	if int64(len(out)) < e.Size {
		return out, fmt.Errorf("%w: stream %q is %d bytes, short of the declared %d",
			ErrCorrupt, e.Name, len(out), e.Size)
	}
	return out, nil
}

// Find returns the first stream whose name matches, case-insensitively.
func (f *File) Find(name string) (Entry, bool) {
	for _, e := range f.Entries {
		if e.IsStream() && strings.EqualFold(e.Name, name) {
			return e, true
		}
	}
	return Entry{}, false
}

// Streams returns every stream entry, in directory order.
func (f *File) Streams() []Entry {
	out := make([]Entry, 0, len(f.Entries))
	for _, e := range f.Entries {
		if e.IsStream() && e.Size > 0 {
			out = append(out, e)
		}
	}
	return out
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 {
			return -1
		}
		return r
	}, s)
}

func formatGUID(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	return fmt.Sprintf("%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		binary.LittleEndian.Uint32(b[0:4]),
		binary.LittleEndian.Uint16(b[4:6]),
		binary.LittleEndian.Uint16(b[6:8]),
		b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

// fileTime converts a Windows FILETIME to UTC, following the rule used
// across the codebase: zero means "not recorded", and a value outside a
// plausible window is discarded rather than shown as a date.
func fileTime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	const ticksPerSecond = 10_000_000
	const epochDelta = 11644473600
	t := time.Unix(int64(ft/ticksPerSecond)-epochDelta, int64(ft%ticksPerSecond)*100).UTC()
	if t.Year() < 1990 || t.Year() > 2200 {
		return time.Time{}
	}
	return t
}
