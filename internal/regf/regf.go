// Package regf reads Windows NT registry hive files (REGF) directly
// from their on-disk binary form -- SYSTEM, SOFTWARE, NTUSER.DAT, SAM,
// SECURITY, UsrClass.dat, or any other hive -- without involving the
// host operating system's registry API. That matters twice over: it is
// what lets Tracefall analyze Windows evidence while running on Linux,
// and it is what keeps the evidence untouched, since nothing here ever
// opens the file for writing, replays a transaction log, or mounts the
// hive.
//
// The format is implemented against libyal's "Windows NT Registry File
// (REGF) format" specification -- see docs/native-artifacts.md for why
// this is hand-written rather than delegated to a library.
//
// Everything in a hive is reached by following 32-bit offsets stored in
// the hive itself, which is to say: by following numbers an attacker
// controls. Every offset is therefore bounds-checked against the hive
// bins data before it is used, every length is capped before it is
// allocated, traversal is iterative with an explicit depth limit, and a
// visited-set makes a cycle terminate rather than loop forever. A
// malformed hive produces an error; it never panics, hangs, or allocates
// without bound.
package regf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode/utf16"
)

// Sentinel errors. Callers distinguish "this isn't a hive at all" from
// "this is a hive Tracefall can't safely read" -- the API layer maps the
// first to "unsupported evidence" and the second to a corrupt-evidence
// error.
var (
	// ErrNotHive means the file does not begin with the REGF signature.
	ErrNotHive = errors.New("regf: not a registry hive (bad signature)")
	// ErrCorrupt means the file IS a hive but its structure is invalid --
	// a bad base block, an offset outside the hive, an impossible length.
	ErrCorrupt = errors.New("regf: hive is corrupt, truncated, or structurally invalid")
	// ErrLimitExceeded means a hard safety ceiling in Limits was reached.
	ErrLimitExceeded = errors.New("regf: hive exceeds a safety limit")
)

const (
	// baseBlockSize is the fixed 512-byte header, and hiveBinsOffset is
	// where hive bins data starts. Every cell offset stored inside the
	// hive is relative to hiveBinsOffset, never to the file start.
	baseBlockSize   = 512
	hiveBinsOffset  = 4096
	regfSignature   = "regf"
	maxCellDataSize = 1 << 24 // 16 MiB: no legitimate single cell approaches this

	// Named key flags (CM_KEY_NODE).
	keyCompName   = 0x0020 // key name is ASCII rather than UTF-16
	valueCompName = 0x0001 // value name is ASCII rather than UTF-16
)

// Registry value type codes (REG_*).
const (
	RegNone                     uint32 = 0
	RegSZ                       uint32 = 1
	RegExpandSZ                 uint32 = 2
	RegBinary                   uint32 = 3
	RegDWord                    uint32 = 4
	RegDWordBigEndian           uint32 = 5
	RegLink                     uint32 = 6
	RegMultiSZ                  uint32 = 7
	RegResourceList             uint32 = 8
	RegFullResourceDescriptor   uint32 = 9
	RegResourceRequirementsList uint32 = 10
	RegQWord                    uint32 = 11
)

// Limits bounds everything this package will read or allocate from one
// hive. Every field is a hard ceiling, not a hint: reaching one stops
// the operation rather than degrading it silently.
type Limits struct {
	MaxFileBytes    int64 // reject a hive larger than this outright
	MaxKeys         int   // stop traversal after this many keys
	MaxValuesPerKey int   // ignore values beyond this many on one key
	MaxDepth        int   // maximum key nesting depth
	MaxNameBytes    int   // maximum key/value name length
	MaxValueBytes   int   // maximum value data length
}

// DefaultLimits are sized so every hive produced by a real Windows
// system passes comfortably while a hostile one cannot exhaust memory. A
// SOFTWARE hive on a busy server is typically 100-200 MB with a few
// hundred thousand keys.
func DefaultLimits() Limits {
	return Limits{
		MaxFileBytes:    512 << 20, // 512 MiB
		MaxKeys:         500_000,
		MaxValuesPerKey: 4096,
		MaxDepth:        32,
		MaxNameBytes:    32 << 10, // 32 KiB
		MaxValueBytes:   1 << 20,  // 1 MiB
	}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxFileBytes <= 0 {
		l.MaxFileBytes = d.MaxFileBytes
	}
	if l.MaxKeys <= 0 {
		l.MaxKeys = d.MaxKeys
	}
	if l.MaxValuesPerKey <= 0 {
		l.MaxValuesPerKey = d.MaxValuesPerKey
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = d.MaxDepth
	}
	if l.MaxNameBytes <= 0 {
		l.MaxNameBytes = d.MaxNameBytes
	}
	if l.MaxValueBytes <= 0 {
		l.MaxValueBytes = d.MaxValueBytes
	}
	return l
}

// Hive is an open, read-only registry hive.
type Hive struct {
	f    *os.File
	size int64
	lim  Limits

	rootOffset   uint32
	binsDataSize uint32
	majorVersion uint32
	minorVersion uint32
	fileType     uint32
	// embeddedName is the hive's own recorded filename (base block offset
	// 48, UTF-16, often the full NT path of the original file). Useful
	// evidence about which hive this is, independent of what the file was
	// renamed to on disk.
	embeddedName string
	lastModified time.Time
}

// Value is one registry value read from a key.
type Value struct {
	Name string // "" means the key's default value
	Type uint32 // REG_* code
	Data []byte // raw data, already length-capped
}

// Key is one registry key: its path, its last-write time, and its values.
// Subkeys are not held here -- traversal hands out keys one at a time so
// a large hive never materializes as a tree in memory.
type Key struct {
	Path      string // backslash-separated, relative to the hive root
	Name      string
	LastWrite time.Time
	Values    []Value
	// SubkeyCount is what the record claims, which is worth reporting
	// separately from how many were actually walked.
	SubkeyCount int
	// Class is the key's class name, a UTF-16 string almost no key
	// carries. It matters because Windows hides the SysKey there:
	// HKLM\SYSTEM\ControlSet00N\Control\Lsa\{JD,Skew1,GBG,Data} store
	// their share of the boot key as class-name hex digits and hold no
	// values at all, so a reader that only looks at values cannot see
	// them. Empty when the key has no class, which is the normal case.
	Class string
}

// Sniff reports whether header looks like a PRIMARY registry hive.
// Content-based, so a hive named "ntuser.dat.bak", or an .evtx renamed
// to SYSTEM, is classified by what it IS.
//
// The magic alone is not enough, and that mattered in practice. A
// registry TRANSACTION LOG -- SAM.LOG1, SYSTEM.LOG2, and so on -- is
// also a REGF file and carries the same four-byte signature. Matching on
// the signature alone catalogued every one of them as a registry hive
// and then failed each at import with "this is a registry transaction
// log, not a hive": twenty files in one real image, each reported as
// broken evidence when nothing was broken at all.
//
// The base block's FILE TYPE field at offset 28 is what distinguishes
// them. Zero is a primary hive; a transaction log carries 1, 2 or 6.
// The field is inside the 512-byte window discovery reads, so this costs
// nothing and moves the decision from parse time to classification time,
// where it belongs. See SniffTransactionLog for the other side of it.
func Sniff(header []byte) bool {
	t, ok := fileTypeOf(header)
	return ok && t == FileTypePrimary
}

// SniffTransactionLog reports whether header is a REGF transaction log
// rather than a primary hive. Catalogers use it to classify these files
// as what they are instead of leaving them unrecognized.
func SniffTransactionLog(header []byte) bool {
	t, ok := fileTypeOf(header)
	return ok && t != FileTypePrimary
}

// FileTypePrimary is the base-block file type of a primary hive -- the
// one with a usable key tree. Transaction logs use other values.
const FileTypePrimary = 0

// fileTypeOf returns the base block's file type, and whether header is a
// REGF file at all.
func fileTypeOf(header []byte) (uint32, bool) {
	if len(header) < 4 || string(header[:4]) != regfSignature {
		return 0, false
	}
	if len(header) < 32 {
		// A REGF signature with no readable file type. Reported as not
		// classifiable rather than assumed to be a primary hive: the
		// point of this check is to stop guessing.
		return 0, false
	}
	return binary.LittleEndian.Uint32(header[28:32]), true
}

// Open validates a hive's base block and returns a handle for read-only
// traversal. The file is opened O_RDONLY and never written to.
func Open(path string, lim Limits) (*Hive, error) {
	lim = lim.withDefaults()

	f, err := os.Open(path) // read-only, always
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if info.Size() > lim.MaxFileBytes {
		f.Close()
		return nil, fmt.Errorf("%w: hive is %d bytes, limit is %d", ErrLimitExceeded, info.Size(), lim.MaxFileBytes)
	}
	if info.Size() < hiveBinsOffset {
		f.Close()
		return nil, fmt.Errorf("%w: file is %d bytes, smaller than a hive's 4096-byte header", ErrCorrupt, info.Size())
	}

	base := make([]byte, baseBlockSize)
	if _, err := io.ReadFull(io.NewSectionReader(f, 0, baseBlockSize), base); err != nil {
		f.Close()
		return nil, fmt.Errorf("%w: reading base block: %v", ErrCorrupt, err)
	}
	if SniffTransactionLog(base) {
		f.Close()
		t, _ := fileTypeOf(base)
		return nil, fmt.Errorf("%w: this is a registry transaction log (file type %d), not a hive", ErrNotHive, t)
	}
	if !Sniff(base) {
		f.Close()
		return nil, ErrNotHive
	}

	h := &Hive{
		f:            f,
		size:         info.Size(),
		lim:          lim,
		majorVersion: binary.LittleEndian.Uint32(base[20:24]),
		minorVersion: binary.LittleEndian.Uint32(base[24:28]),
		fileType:     binary.LittleEndian.Uint32(base[28:32]),
		rootOffset:   binary.LittleEndian.Uint32(base[36:40]),
		binsDataSize: binary.LittleEndian.Uint32(base[40:44]),
		lastModified: fileTime(binary.LittleEndian.Uint64(base[12:20])),
		embeddedName: utf16String(base[48:112]),
	}

	// A transaction log is a REGF file too (file type 1/2/6) but has no
	// usable key tree. Recognizing it explicitly gives a better message
	// than a confusing structural error later.
	if h.fileType != 0 {
		f.Close()
		return nil, fmt.Errorf("%w: this is a registry transaction log (file type %d), not a hive", ErrNotHive, h.fileType)
	}
	// The bins data size the header claims must actually be present. A
	// hive truncated mid-copy is the common real-world case here.
	if int64(hiveBinsOffset)+int64(h.binsDataSize) > h.size {
		// Tolerate the claim being larger than the file by clamping to
		// what exists: every offset is bounds-checked anyway, so this
		// only decides how much of a truncated hive is reachable.
		h.binsDataSize = uint32(h.size - hiveBinsOffset)
	}
	if h.binsDataSize == 0 {
		f.Close()
		return nil, fmt.Errorf("%w: hive contains no bins data", ErrCorrupt)
	}
	return h, nil
}

func (h *Hive) Close() error { return h.f.Close() }

// MajorVersion/MinorVersion/LastModified/EmbeddedName expose base-block
// facts that are evidence in their own right.
func (h *Hive) MajorVersion() uint32    { return h.majorVersion }
func (h *Hive) MinorVersion() uint32    { return h.minorVersion }
func (h *Hive) LastModified() time.Time { return h.lastModified }
func (h *Hive) EmbeddedName() string    { return h.embeddedName }

// readCell returns the data of the cell at a hive-relative offset. This
// is the single choke point through which every attacker-controlled
// offset in the hive passes, so all bounds checking lives here.
func (h *Hive) readCell(offset uint32) ([]byte, error) {
	if offset == 0xffffffff {
		return nil, fmt.Errorf("%w: cell offset is unset", ErrCorrupt)
	}
	// The 4-byte size field must itself be inside the bins data.
	if uint64(offset)+4 > uint64(h.binsDataSize) {
		return nil, fmt.Errorf("%w: cell offset %d is outside the hive", ErrCorrupt, offset)
	}
	abs := int64(hiveBinsOffset) + int64(offset)

	var sizeBuf [4]byte
	if _, err := h.f.ReadAt(sizeBuf[:], abs); err != nil {
		return nil, fmt.Errorf("%w: reading cell size at %d: %v", ErrCorrupt, offset, err)
	}
	// Negative size means allocated, and the magnitude includes the size
	// field itself. A positive size is an unallocated cell, which this
	// package deliberately does not read (see docs/native-artifacts.md).
	raw := int32(binary.LittleEndian.Uint32(sizeBuf[:]))
	if raw >= 0 {
		return nil, fmt.Errorf("%w: cell at %d is unallocated", ErrCorrupt, offset)
	}
	size := int64(-raw)
	if size <= 4 || size > maxCellDataSize {
		return nil, fmt.Errorf("%w: cell at %d has implausible size %d", ErrCorrupt, offset, size)
	}
	if uint64(offset)+uint64(size) > uint64(h.binsDataSize) {
		return nil, fmt.Errorf("%w: cell at %d (size %d) runs past the hive", ErrCorrupt, offset, size)
	}

	data := make([]byte, size-4)
	if _, err := h.f.ReadAt(data, abs+4); err != nil {
		return nil, fmt.Errorf("%w: reading cell data at %d: %v", ErrCorrupt, offset, err)
	}
	return data, nil
}

// namedKey is the decoded fixed portion of an nk record.
type namedKey struct {
	offset      uint32
	name        string
	lastWrite   time.Time
	subkeyCount uint32
	subkeyList  uint32
	valueCount  uint32
	valueList   uint32
	classOffset uint32
	classLength uint16
}

func (h *Hive) readNamedKey(offset uint32) (namedKey, error) {
	cell, err := h.readCell(offset)
	if err != nil {
		return namedKey{}, err
	}
	// 76 bytes of fixed fields before the name string begins.
	if len(cell) < 76 || string(cell[0:2]) != "nk" {
		return namedKey{}, fmt.Errorf("%w: no named key at offset %d", ErrCorrupt, offset)
	}
	flags := binary.LittleEndian.Uint16(cell[2:4])
	nameSize := int(binary.LittleEndian.Uint16(cell[72:74]))
	if nameSize > h.lim.MaxNameBytes {
		return namedKey{}, fmt.Errorf("%w: key name at %d is %d bytes", ErrLimitExceeded, offset, nameSize)
	}
	if 76+nameSize > len(cell) {
		return namedKey{}, fmt.Errorf("%w: key name at %d runs past its cell", ErrCorrupt, offset)
	}
	nameBytes := cell[76 : 76+nameSize]

	var name string
	if flags&keyCompName != 0 {
		name = asciiString(nameBytes)
	} else {
		name = utf16String(nameBytes)
	}

	return namedKey{
		offset:      offset,
		name:        name,
		lastWrite:   fileTime(binary.LittleEndian.Uint64(cell[4:12])),
		subkeyCount: binary.LittleEndian.Uint32(cell[20:24]),
		subkeyList:  binary.LittleEndian.Uint32(cell[28:32]),
		valueCount:  binary.LittleEndian.Uint32(cell[36:40]),
		valueList:   binary.LittleEndian.Uint32(cell[40:44]),
		// Class name offset (48) and length (74) in the nk record. Both
		// are read but the cell they point at is only fetched when a
		// class actually exists -- see readClass.
		classOffset: binary.LittleEndian.Uint32(cell[48:52]),
		classLength: binary.LittleEndian.Uint16(cell[74:76]),
	}, nil
}

// readClass returns a key's class name, or "" when it has none. Almost
// no key does, so the guard below is what keeps this free for the
// overwhelming majority of a walk: no class means no extra cell read.
//
// A class that cannot be read is reported as absent rather than as an
// error. It is optional metadata on a key whose values were read fine,
// and failing the whole key over it would lose evidence that is
// perfectly good.
func (h *Hive) readClass(nk namedKey) string {
	if nk.classLength == 0 || nk.classOffset == 0xffffffff {
		return ""
	}
	if int(nk.classLength) > h.lim.MaxNameBytes {
		return ""
	}
	cell, err := h.readCell(nk.classOffset)
	if err != nil || len(cell) < int(nk.classLength) {
		return ""
	}
	return utf16String(cell[:nk.classLength])
}

// readValues reads a key's value list. Unreadable individual values are
// skipped rather than failing the whole key: one bad vk record should
// not hide the rest of a key's evidence.
func (h *Hive) readValues(nk namedKey) []Value {
	if nk.valueCount == 0 || nk.valueList == 0xffffffff {
		return nil
	}
	count := int(nk.valueCount)
	if count > h.lim.MaxValuesPerKey {
		count = h.lim.MaxValuesPerKey
	}
	list, err := h.readCell(nk.valueList)
	if err != nil {
		return nil
	}
	if count*4 > len(list) {
		count = len(list) / 4
	}

	out := make([]Value, 0, count)
	for i := 0; i < count; i++ {
		vkOffset := binary.LittleEndian.Uint32(list[i*4 : i*4+4])
		v, err := h.readValue(vkOffset)
		if err != nil {
			continue
		}
		out = append(out, v)
	}
	return out
}

func (h *Hive) readValue(offset uint32) (Value, error) {
	cell, err := h.readCell(offset)
	if err != nil {
		return Value{}, err
	}
	if len(cell) < 20 || string(cell[0:2]) != "vk" {
		return Value{}, fmt.Errorf("%w: no value key at offset %d", ErrCorrupt, offset)
	}
	nameSize := int(binary.LittleEndian.Uint16(cell[2:4]))
	dataSize := binary.LittleEndian.Uint32(cell[4:8])
	dataOffset := binary.LittleEndian.Uint32(cell[8:12])
	valueType := binary.LittleEndian.Uint32(cell[12:16])
	flags := binary.LittleEndian.Uint16(cell[16:18])

	if nameSize > h.lim.MaxNameBytes || 20+nameSize > len(cell) {
		return Value{}, fmt.Errorf("%w: value name at %d is invalid", ErrCorrupt, offset)
	}
	var name string
	if nameSize > 0 {
		nameBytes := cell[20 : 20+nameSize]
		if flags&valueCompName != 0 {
			name = asciiString(nameBytes)
		} else {
			name = utf16String(nameBytes)
		}
	}

	data, err := h.readValueData(dataSize, dataOffset)
	if err != nil {
		return Value{}, err
	}
	return Value{Name: name, Type: valueType, Data: data}, nil
}

// readValueData resolves a value's data, which lives in one of three
// places depending on its size: inline in the offset field (the
// "resident" convention, when the size's high bit is set), in a single
// cell, or -- for data above ~16 KiB -- split across a "db" segment list.
func (h *Hive) readValueData(dataSize, dataOffset uint32) ([]byte, error) {
	const residentFlag = 0x80000000
	if dataSize&residentFlag != 0 {
		n := int(dataSize &^ residentFlag)
		if n > 4 {
			n = 4
		}
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, dataOffset)
		return buf[:n], nil
	}
	if dataSize == 0 || dataOffset == 0xffffffff {
		return nil, nil
	}
	if int(dataSize) > h.lim.MaxValueBytes {
		return nil, fmt.Errorf("%w: value data is %d bytes, limit is %d", ErrLimitExceeded, dataSize, h.lim.MaxValueBytes)
	}

	cell, err := h.readCell(dataOffset)
	if err != nil {
		return nil, err
	}
	// Big data: a "db" record points at a list of segment offsets.
	if len(cell) >= 8 && string(cell[0:2]) == "db" {
		return h.readBigData(cell, int(dataSize))
	}
	if int(dataSize) > len(cell) {
		// The cell is smaller than the value claims -- take what is
		// actually there rather than trusting the length field.
		return cell, nil
	}
	return cell[:dataSize], nil
}

func (h *Hive) readBigData(cell []byte, total int) ([]byte, error) {
	segCount := int(binary.LittleEndian.Uint16(cell[2:4]))
	segListOffset := binary.LittleEndian.Uint32(cell[4:8])
	if segCount <= 0 {
		return nil, fmt.Errorf("%w: big data record claims %d segments", ErrCorrupt, segCount)
	}
	segList, err := h.readCell(segListOffset)
	if err != nil {
		return nil, err
	}
	if segCount*4 > len(segList) {
		segCount = len(segList) / 4
	}

	out := make([]byte, 0, total)
	for i := 0; i < segCount && len(out) < total; i++ {
		seg, err := h.readCell(binary.LittleEndian.Uint32(segList[i*4 : i*4+4]))
		if err != nil {
			break
		}
		remaining := total - len(out)
		if len(seg) > remaining {
			seg = seg[:remaining]
		}
		out = append(out, seg...)
	}
	return out, nil
}

// subkeyOffsets resolves a subkey list into the offsets of its named
// keys, following the lf/lh (hashed leaf), li (plain leaf) and ri
// (list-of-lists) variants. ri is the only one that recurses, and it is
// expanded one level only -- which is all the format uses -- so this
// cannot become an unbounded recursion.
func (h *Hive) subkeyOffsets(listOffset uint32) []uint32 {
	if listOffset == 0 || listOffset == 0xffffffff {
		return nil
	}
	cell, err := h.readCell(listOffset)
	if err != nil || len(cell) < 4 {
		return nil
	}
	sig := string(cell[0:2])
	count := int(binary.LittleEndian.Uint16(cell[2:4]))
	body := cell[4:]

	switch sig {
	case "lf", "lh": // 8-byte elements: key offset + name hash
		if count*8 > len(body) {
			count = len(body) / 8
		}
		out := make([]uint32, 0, count)
		for i := 0; i < count; i++ {
			out = append(out, binary.LittleEndian.Uint32(body[i*8:i*8+4]))
		}
		return out

	case "li": // 4-byte elements: key offset only
		if count*4 > len(body) {
			count = len(body) / 4
		}
		out := make([]uint32, 0, count)
		for i := 0; i < count; i++ {
			out = append(out, binary.LittleEndian.Uint32(body[i*4:i*4+4]))
		}
		return out

	case "ri": // 4-byte elements pointing at further lf/lh/li lists
		if count*4 > len(body) {
			count = len(body) / 4
		}
		var out []uint32
		for i := 0; i < count; i++ {
			subList := binary.LittleEndian.Uint32(body[i*4 : i*4+4])
			sub, err := h.readCell(subList)
			if err != nil || len(sub) < 4 {
				continue
			}
			// Only leaf lists are followed from an ri -- an ri pointing
			// at another ri is not something the format produces, and
			// following it would reintroduce unbounded recursion.
			if s := string(sub[0:2]); s != "lf" && s != "lh" && s != "li" {
				continue
			}
			out = append(out, h.subkeyOffsets(subList)...)
			if len(out) > h.lim.MaxKeys {
				return out[:h.lim.MaxKeys]
			}
		}
		return out

	default:
		return nil
	}
}

// Root returns the hive's root key.
func (h *Hive) Root() (Key, error) {
	nk, err := h.readNamedKey(h.rootOffset)
	if err != nil {
		return Key{}, err
	}
	return Key{
		Path:        "",
		Name:        nk.name,
		LastWrite:   nk.lastWrite,
		Values:      h.readValues(nk),
		SubkeyCount: int(nk.subkeyCount),
		Class:       h.readClass(nk),
	}, nil
}

// WalkStats reports what a traversal actually managed to read, so a
// caller can tell a complete walk from one that hit a limit or skipped
// damaged cells rather than assuming it saw everything.
type WalkStats struct {
	KeysVisited  int
	KeysSkipped  int  // unreadable/corrupt cells passed over
	LimitReached bool // MaxKeys or MaxDepth stopped the walk early
}

// Walk visits every reachable key depth-first, calling fn for each. It
// is iterative (an explicit stack, never the goroutine stack), tracks
// visited cell offsets so a cycle terminates, and enforces both the key
// count and depth ceilings. Returning an error from fn stops the walk
// and returns that error.
func (h *Hive) Walk(fn func(Key) error) (WalkStats, error) {
	var stats WalkStats

	root, err := h.readNamedKey(h.rootOffset)
	if err != nil {
		return stats, err
	}

	type frame struct {
		nk    namedKey
		path  string
		depth int
	}
	// visited is keyed by cell offset: a hive whose subkey list points
	// back at an ancestor would otherwise walk forever.
	visited := map[uint32]bool{root.offset: true}
	stack := []frame{{nk: root, path: "", depth: 0}}

	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		if stats.KeysVisited >= h.lim.MaxKeys {
			stats.LimitReached = true
			break
		}
		stats.KeysVisited++

		if err := fn(Key{
			Path:        cur.path,
			Name:        cur.nk.name,
			LastWrite:   cur.nk.lastWrite,
			Values:      h.readValues(cur.nk),
			SubkeyCount: int(cur.nk.subkeyCount),
		}); err != nil {
			return stats, err
		}

		if cur.depth >= h.lim.MaxDepth {
			stats.LimitReached = true
			continue
		}
		for _, off := range h.subkeyOffsets(cur.nk.subkeyList) {
			if visited[off] {
				continue // cycle, or a key genuinely listed twice
			}
			visited[off] = true
			child, err := h.readNamedKey(off)
			if err != nil {
				stats.KeysSkipped++
				continue
			}
			stack = append(stack, frame{nk: child, path: joinPath(cur.path, child.name), depth: cur.depth + 1})
		}
	}
	return stats, nil
}

// OpenKey resolves a backslash-separated path relative to the root,
// case-insensitively (as Windows registry paths are). It reads only the
// keys along the path, so looking up one value in a large hive does not
// walk the hive.
func (h *Hive) OpenKey(path string) (Key, error) {
	nk, err := h.readNamedKey(h.rootOffset)
	if err != nil {
		return Key{}, err
	}
	if path == "" {
		return h.keyFrom(nk, ""), nil
	}

	segments := strings.Split(strings.Trim(path, `\`), `\`)
	if len(segments) > h.lim.MaxDepth {
		return Key{}, fmt.Errorf("%w: path is %d levels deep", ErrLimitExceeded, len(segments))
	}
	built := ""
	for _, want := range segments {
		var found bool
		for _, off := range h.subkeyOffsets(nk.subkeyList) {
			child, err := h.readNamedKey(off)
			if err != nil {
				continue
			}
			if strings.EqualFold(child.name, want) {
				nk, found = child, true
				built = joinPath(built, child.name)
				break
			}
		}
		if !found {
			return Key{}, fmt.Errorf("regf: key %q not found", path)
		}
	}
	return h.keyFrom(nk, built), nil
}

func (h *Hive) keyFrom(nk namedKey, path string) Key {
	return Key{
		Path:        path,
		Name:        nk.name,
		LastWrite:   nk.lastWrite,
		Values:      h.readValues(nk),
		SubkeyCount: int(nk.subkeyCount),
		Class:       h.readClass(nk),
	}
}

// Subkeys returns the immediate subkey names of a key path, without
// walking further. Used to enumerate ControlSet00N and service keys.
func (h *Hive) Subkeys(path string) ([]string, error) {
	nk, err := h.namedKeyAt(path)
	if err != nil {
		return nil, err
	}
	offsets := h.subkeyOffsets(nk.subkeyList)
	out := make([]string, 0, len(offsets))
	for _, off := range offsets {
		child, err := h.readNamedKey(off)
		if err != nil {
			continue
		}
		out = append(out, child.name)
	}
	return out, nil
}

// ChildKeys returns a key's immediate children as fully-read Keys --
// name, last-write time and values -- in one pass over the subkey list.
//
// # Why this exists alongside Subkeys and OpenKey
//
// Enumerating children with Subkeys and then calling OpenKey on each is
// the obvious pattern and is QUADRATIC: OpenKey restarts at the root and
// linearly scans siblings at every level, so a key with N children costs
// O(N) per child and O(N^2) overall. On a real Amcache hive -- one key
// with tens of thousands of children -- that was measured at 9 minutes
// and 30 GiB of allocation for 20,000 entries, against 6 seconds and
// 1 GiB here.
//
// Callers that walk a WIDE key should use this. OpenKey remains right
// for reaching one known path.
func (h *Hive) ChildKeys(path string) ([]Key, error) {
	nk, err := h.namedKeyAt(path)
	if err != nil {
		return nil, err
	}
	offsets := h.subkeyOffsets(nk.subkeyList)
	out := make([]Key, 0, len(offsets))
	for _, off := range offsets {
		child, err := h.readNamedKey(off)
		if err != nil {
			// One unreadable child must not discard its siblings.
			continue
		}
		out = append(out, h.keyFrom(child, joinPath(path, child.name)))
	}
	return out, nil
}

func (h *Hive) namedKeyAt(path string) (namedKey, error) {
	nk, err := h.readNamedKey(h.rootOffset)
	if err != nil {
		return namedKey{}, err
	}
	if path == "" {
		return nk, nil
	}
	for _, want := range strings.Split(strings.Trim(path, `\`), `\`) {
		var found bool
		for _, off := range h.subkeyOffsets(nk.subkeyList) {
			child, err := h.readNamedKey(off)
			if err != nil {
				continue
			}
			if strings.EqualFold(child.name, want) {
				nk, found = child, true
				break
			}
		}
		if !found {
			return namedKey{}, fmt.Errorf("regf: key %q not found", path)
		}
	}
	return nk, nil
}

// ---------- value decoding ----------

// String renders a value as text appropriate to its type. Binary data is
// rendered as a bounded hex string rather than as mojibake, so a value's
// rendering never depends on it happening to contain valid UTF-16.
func (v Value) String() string {
	switch v.Type {
	case RegSZ, RegExpandSZ, RegLink:
		return utf16String(v.Data)
	case RegMultiSZ:
		return strings.Join(v.Strings(), "; ")
	case RegDWord:
		if len(v.Data) >= 4 {
			return fmt.Sprint(binary.LittleEndian.Uint32(v.Data[:4]))
		}
	case RegDWordBigEndian:
		if len(v.Data) >= 4 {
			return fmt.Sprint(binary.BigEndian.Uint32(v.Data[:4]))
		}
	case RegQWord:
		if len(v.Data) >= 8 {
			return fmt.Sprint(binary.LittleEndian.Uint64(v.Data[:8]))
		}
	}
	return hexPreview(v.Data, 64)
}

// Strings splits a REG_MULTI_SZ value into its component strings.
func (v Value) Strings() []string {
	raw := utf16String(v.Data)
	parts := strings.Split(raw, "\x00")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// TypeName renders the REG_* code for display/provenance.
func (v Value) TypeName() string {
	switch v.Type {
	case RegNone:
		return "REG_NONE"
	case RegSZ:
		return "REG_SZ"
	case RegExpandSZ:
		return "REG_EXPAND_SZ"
	case RegBinary:
		return "REG_BINARY"
	case RegDWord:
		return "REG_DWORD"
	case RegDWordBigEndian:
		return "REG_DWORD_BIG_ENDIAN"
	case RegLink:
		return "REG_LINK"
	case RegMultiSZ:
		return "REG_MULTI_SZ"
	case RegResourceList:
		return "REG_RESOURCE_LIST"
	case RegFullResourceDescriptor:
		return "REG_FULL_RESOURCE_DESCRIPTOR"
	case RegResourceRequirementsList:
		return "REG_RESOURCE_REQUIREMENTS_LIST"
	case RegQWord:
		return "REG_QWORD"
	default:
		return fmt.Sprintf("REG_UNKNOWN_%d", v.Type)
	}
}

// ---------- shared helpers ----------

// utf16String decodes little-endian UTF-16, stopping at a trailing NUL
// run. Odd-length input is truncated rather than treated as an error:
// this only ever renders a name for display, and refusing to start over
// one malformed name would be worse than showing what is decodable.
func utf16String(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	n := len(b) &^ 1
	u := make([]uint16, 0, n/2)
	for i := 0; i < n; i += 2 {
		u = append(u, binary.LittleEndian.Uint16(b[i:i+2]))
	}
	// Trim the trailing NUL terminator(s) but keep interior NULs, which
	// REG_MULTI_SZ uses as its separator.
	for len(u) > 0 && u[len(u)-1] == 0 {
		u = u[:len(u)-1]
	}
	return string(utf16.Decode(u))
}

func asciiString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func hexPreview(b []byte, max int) string {
	if len(b) == 0 {
		return ""
	}
	truncated := false
	if len(b) > max {
		b, truncated = b[:max], true
	}
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2+3)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	if truncated {
		out = append(out, '.', '.', '.')
	}
	return string(out)
}

// fileTime converts a Windows FILETIME (100ns intervals since 1601-01-01
// UTC) to a Go time. Zero and implausible values become the zero time
// rather than a date in the year 1601 that would corrupt a timeline.
func fileTime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	const ticksPerSecond = 10_000_000
	const epochDelta = 11644473600 // seconds between 1601-01-01 and 1970-01-01
	secs := int64(ft/ticksPerSecond) - epochDelta
	nsec := int64(ft%ticksPerSecond) * 100
	t := time.Unix(secs, nsec).UTC()
	if t.Year() < 1980 || t.Year() > 2200 {
		return time.Time{}
	}
	return t
}

func joinPath(parent, child string) string {
	if parent == "" {
		return child
	}
	return parent + `\` + child
}
