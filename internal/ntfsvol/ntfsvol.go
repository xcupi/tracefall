// Package ntfsvol reads an NTFS volume directly from its bytes: boot
// sector, $MFT, attributes, data runs, attribute lists, alternate data
// streams, sparse files and deleted entries.
//
// It exists so Tracefall can work from a disk image instead of requiring
// the examiner to export artifacts first. It is read-only, mounts nothing,
// and takes an io.ReaderAt, so it sits on top of any image container and
// any partition.
//
// # How listing works
//
// There is no directory-by-directory traversal. Walk reads the $MFT
// sequentially, which is how forensic tools enumerate NTFS: it finds
// every record, in use or deleted, in one pass over contiguous data, and
// each record names its parent, from which the path is rebuilt. A
// consequence worth stating: deleted entries are listed too, flagged
// InUse=false, and a directory that was deleted and reused shows its old
// children under "/$OrphanFiles".
//
// # What it does not do
//
// Compressed (LZNT1/WOF) and EFS-encrypted data streams are detected and
// reported as ErrCompressed / ErrEncrypted rather than returned as
// garbage. Volume Shadow Copies, $I30 slack, $LogFile replay and the
// backup boot sector are not read.
//
// # Hostile input
//
// Every length, offset and count from the disk is bounds-checked before
// use, update-sequence (fixup) arrays are verified so a torn record is an
// error and never data, and allocation sizes are capped. A damaged record
// is reported through WalkStats and does not stop the walk.
package ntfsvol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"tracefall/internal/fsvol"
	"unicode/utf16"
)

var (
	// ErrNotNTFS means the bytes are not an NTFS volume.
	ErrNotNTFS = errors.New("not an NTFS volume")
	// ErrCorrupt means a structure on the volume is damaged or inconsistent.
	ErrCorrupt = fsvol.ErrCorrupt
	// ErrCompressed means the stream is NTFS-compressed, which is not read.
	ErrCompressed = errors.New("NTFS-compressed data is not supported")
	// ErrEncrypted means the stream is EFS-encrypted.
	ErrEncrypted = errors.New("EFS-encrypted data cannot be read")
	// ErrNotFound means the record or stream does not exist.
	ErrNotFound = fsvol.ErrNotFound
)

func corrupt(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrCorrupt}, a...)...)
}

const (
	attrStandardInformation = 0x10
	attrAttributeList       = 0x20
	attrFileName            = 0x30
	attrVolumeName          = 0x60
	attrVolumeInformation   = 0x70
	attrData                = 0x80
	attrEnd                 = 0xFFFFFFFF

	flagCompressed = 0x0001
	flagEncrypted  = 0x4000
	flagSparse     = 0x8000

	recInUse = 0x0001
	recDir   = 0x0002

	rootRecord = 5

	maxAttrsPerRecord = 4096
	maxRunsPerAttr    = 1 << 20
	maxListEntries    = 1 << 16
	maxExtRecords     = 1024
	maxClusterSize    = 2 << 20
	maxRecordSize     = 64 << 10
	maxPathDepth      = 256
	maxCorruptKept    = 200
)

// Info describes the volume.
type Info struct {
	Label          string
	Version        string
	Serial         uint64
	BytesPerSector int
	ClusterSize    int
	RecordSize     int
	VolumeBytes    int64
	MFTRecords     int64
	// Warnings describe observed format limitations, not acquisition findings.
	Warnings []string
}

// Volume is an opened NTFS volume.
type Volume struct {
	r           io.ReaderAt
	imgSize     int64
	bps         int
	cluster     int
	recordSize  int
	volBytes    int64
	serial      uint64
	mftLCN      int64
	mft         *DataReader
	label       string
	version     string
	mftRecordsN int64
	warnings    []string
}

// Open parses the boot sector and bootstraps the $MFT.
func Open(r io.ReaderAt, size int64) (*Volume, error) {
	b := make([]byte, 512)
	if n, _ := r.ReadAt(b, 0); n < 512 {
		return nil, fmt.Errorf("%w: the volume is smaller than a boot sector", ErrNotNTFS)
	}
	// Some file-system capture volumes omit both DOS boot fields. Recognize
	// only the all-zero pair, not a damaged or partial nonzero signature.
	missingBootFields := b[0] == 0 && b[1] == 0 && b[2] == 0 && b[510] == 0 && b[511] == 0
	if string(b[3:11]) != "NTFS    " || (!missingBootFields && (b[510] != 0x55 || b[511] != 0xAA)) {
		return nil, ErrNotNTFS
	}
	bps := int(binary.LittleEndian.Uint16(b[11:]))
	if bps < 512 || bps > 4096 || bps&(bps-1) != 0 {
		return nil, corrupt("bytes per sector %d", bps)
	}
	spcRaw := int(b[13])
	var spc int
	switch {
	case spcRaw > 0 && spcRaw <= 128 && spcRaw&(spcRaw-1) == 0:
		spc = spcRaw
	case spcRaw > 0x80 && 256-spcRaw <= 12:
		spc = 1 << (256 - spcRaw)
	default:
		return nil, corrupt("sectors per cluster %d", spcRaw)
	}
	cluster := bps * spc
	if cluster > maxClusterSize {
		return nil, corrupt("cluster size %d", cluster)
	}
	var recSize int
	if c := int8(b[64]); c > 0 {
		recSize = int(c) * cluster
	} else if c < 0 && c >= -16 {
		recSize = 1 << uint(-c)
	}
	if recSize < 512 || recSize > maxRecordSize || recSize&(recSize-1) != 0 {
		return nil, corrupt("file record size %d", recSize)
	}
	total := binary.LittleEndian.Uint64(b[40:])
	if total == 0 || total > uint64(size)/uint64(bps)+1 {
		return nil, corrupt("the boot sector declares %d sectors but the image holds %d", total, size/int64(bps))
	}
	volBytes := int64(total) * int64(bps)
	mftLCN := binary.LittleEndian.Uint64(b[48:])
	if mftLCN == 0 || mftLCN > uint64(volBytes)/uint64(cluster) {
		return nil, corrupt("$MFT cluster %d is outside the volume", mftLCN)
	}
	v := &Volume{
		r: r, imgSize: size, bps: bps, cluster: cluster, recordSize: recSize, volBytes: volBytes,
		serial: binary.LittleEndian.Uint64(b[72:]), mftLCN: int64(mftLCN),
	}
	if err := v.bootstrapMFT(); err != nil {
		return nil, err
	}
	if missingBootFields {
		// The relaxed identification requires a live, self-parented root with
		// valid record fixups and attributes, in addition to the MFT bootstrap.
		root, err := v.loadFile(rootRecord)
		if err != nil {
			return nil, corrupt("capture-volume root record: %v", err)
		}
		s, ok := describe(rootRecord, root)
		if !ok || !s.inUse || !s.dir || s.name != "." || s.parent != rootRecord || s.parentSeq != s.seq || root.rec.baseRef != 0 {
			return nil, corrupt("capture-volume root is not a live self-parented directory")
		}
		v.warnings = []string{"DOS boot jump and 0x55AA signature are absent; the NTFS geometry, MFT bootstrap and root record validated. Read-only filesystem access only; these bytes do not establish bootability, acquisition scope or cause. No boot-sector repair was performed."}
	}
	v.readVolumeRecord()
	return v, nil
}

// bootstrapMFT reads record 0 straight from the boot sector's pointer,
// builds a first, possibly partial, view of $MFT from its own runs, then
// resolves its attribute list (a fragmented $MFT lists its extents
// across extension records that live inside the $MFT itself).
func (v *Volume) bootstrapMFT() error {
	buf := make([]byte, v.recordSize)
	off := v.mftLCN * int64(v.cluster)
	if n, err := v.r.ReadAt(buf, off); n < len(buf) {
		return corrupt("reading $MFT record 0: %v", err)
	}
	rec, err := v.parseRecord(buf)
	if err != nil {
		return fmt.Errorf("$MFT record 0: %w", err)
	}
	var first *attr
	for _, a := range rec.attrs {
		if a.typ == attrData && a.name == "" && !a.resident {
			first = a
			break
		}
	}
	if first == nil {
		return corrupt("$MFT record 0 has no non-resident $DATA")
	}
	v.mft = &DataReader{v: v, runs: first.runs, size: first.dataSize, initSize: first.initSize}
	file, err := v.loadFile(0)
	if err != nil {
		return fmt.Errorf("$MFT attribute list: %w", err)
	}
	full := file.dataAttr("")
	if full == nil || full.resident {
		return corrupt("$MFT has no usable $DATA")
	}
	v.mft = &DataReader{v: v, runs: full.runs, size: full.dataSize, initSize: full.initSize}
	if v.mft.size < int64(v.recordSize) {
		return corrupt("$MFT is smaller than one record")
	}
	if err := v.mft.checkCoverage(v.cluster); err != nil {
		return err
	}
	v.mftRecordsN = v.mft.size / int64(v.recordSize)
	return nil
}

func (v *Volume) readVolumeRecord() {
	f, err := v.loadFile(3)
	if err != nil {
		return
	}
	for _, a := range f.attrs {
		switch {
		case a.typ == attrVolumeName && a.resident:
			v.label = decodeUTF16(a.content)
		case a.typ == attrVolumeInformation && a.resident && len(a.content) >= 10:
			v.version = fmt.Sprintf("%d.%d", a.content[8], a.content[9])
		}
	}
}

// Info returns the volume's geometry and identity.
func (v *Volume) Info() Info {
	return Info{Label: v.label, Version: v.version, Serial: v.serial, BytesPerSector: v.bps, ClusterSize: v.cluster,
		RecordSize: v.recordSize, VolumeBytes: v.volBytes, MFTRecords: v.mftRecordsN, Warnings: append([]string(nil), v.warnings...)}
}

// ---- records and attributes

type run struct {
	vcn, length int64
	lcn         int64 // -1 for a sparse run
}

type attr struct {
	typ      uint32
	name     string
	id       uint16
	flags    uint16
	resident bool
	content  []byte

	startVCN, lastVCN             int64
	allocSize, dataSize, initSize int64
	runs                          []run
}

type record struct {
	seq     uint16
	flags   uint16
	baseRef uint64
	attrs   []*attr
}

var errBlank = errors.New("blank record")

func u16(b []byte, o int) uint16 { return binary.LittleEndian.Uint16(b[o:]) }
func u32(b []byte, o int) uint32 { return binary.LittleEndian.Uint32(b[o:]) }
func u64(b []byte, o int) uint64 { return binary.LittleEndian.Uint64(b[o:]) }

func decodeUTF16(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}

// parseRecord validates and decodes one MFT record. buf is modified in
// place (fixups applied).
func (v *Volume) parseRecord(buf []byte) (*record, error) {
	if len(buf) != v.recordSize {
		return nil, corrupt("record buffer of %d bytes", len(buf))
	}
	switch string(buf[:4]) {
	case "FILE":
	case "BAAD":
		return nil, corrupt("record is marked BAAD")
	default:
		return nil, errBlank
	}
	usaOff, usaCount := int(u16(buf, 4)), int(u16(buf, 6))
	if usaCount < 2 || (usaCount-1)*512 != len(buf) || usaOff < 42 || usaOff+2*usaCount > 512-2 {
		return nil, corrupt("update sequence array (offset %d, count %d)", usaOff, usaCount)
	}
	usn := buf[usaOff : usaOff+2]
	for i := 1; i < usaCount; i++ {
		end := i * 512
		if buf[end-2] != usn[0] || buf[end-1] != usn[1] {
			return nil, corrupt("sector %d of the record fails its update sequence check (torn write or damage)", i)
		}
		buf[end-2], buf[end-1] = buf[usaOff+2*i], buf[usaOff+2*i+1]
	}
	first, used := int(u16(buf, 20)), int(u32(buf, 24))
	if first < 42 || first >= len(buf) || used < first || used > len(buf) {
		return nil, corrupt("attribute area [%d,%d)", first, used)
	}
	rec := &record{seq: u16(buf, 16), flags: u16(buf, 22), baseRef: u64(buf, 32)}
	off := first
	for len(rec.attrs) < maxAttrsPerRecord {
		if off+4 > used {
			break
		}
		typ := u32(buf, off)
		if typ == attrEnd {
			break
		}
		if off+16 > used {
			return nil, corrupt("attribute header at %d runs past the record", off)
		}
		length := int(u32(buf, off+4))
		if length < 24 || length%8 != 0 || off+length > used {
			return nil, corrupt("attribute at %d has length %d", off, length)
		}
		a, err := v.parseAttr(buf[off:off+length], typ)
		if err != nil {
			return nil, err
		}
		rec.attrs = append(rec.attrs, a)
		off += length
	}
	return rec, nil
}

func (v *Volume) parseAttr(b []byte, typ uint32) (*attr, error) {
	a := &attr{typ: typ, resident: b[8] == 0, flags: u16(b, 12), id: u16(b, 14)}
	nlen, noff := int(b[9]), int(u16(b, 10))
	if nlen > 0 {
		if noff < 16 || noff+2*nlen > len(b) {
			return nil, corrupt("attribute name outside the attribute")
		}
		a.name = decodeUTF16(b[noff : noff+2*nlen])
	}
	if a.resident {
		clen, coff := int(u32(b, 16)), int(u16(b, 20))
		if coff < 24 || coff > len(b) || clen < 0 || coff+clen > len(b) {
			return nil, corrupt("resident content [%d+%d) outside the attribute", coff, clen)
		}
		a.content = b[coff : coff+clen]
		a.dataSize = int64(clen)
		return a, nil
	}
	if len(b) < 64 {
		return nil, corrupt("non-resident attribute header is truncated")
	}
	a.startVCN, a.lastVCN = int64(u64(b, 16)), int64(u64(b, 24))
	roff := int(u16(b, 32))
	a.allocSize, a.dataSize, a.initSize = int64(u64(b, 40)), int64(u64(b, 48)), int64(u64(b, 56))
	if a.startVCN < 0 || a.lastVCN < a.startVCN-1 || a.allocSize < 0 || a.dataSize < 0 || a.initSize < 0 || roff < 64 || roff > len(b) {
		return nil, corrupt("non-resident attribute fields are implausible")
	}
	runs, err := v.decodeRuns(b[roff:], a.startVCN)
	if err != nil {
		return nil, err
	}
	a.runs = runs
	return a, nil
}

func (v *Volume) decodeRuns(b []byte, startVCN int64) ([]run, error) {
	var out []run
	vcn, lcn := startVCN, int64(0)
	clusters := v.volBytes / int64(v.cluster)
	for i := 0; i < len(b); {
		h := b[i]
		if h == 0 {
			break
		}
		ls, os := int(h&0x0f), int(h>>4)
		if ls == 0 || ls > 8 || os > 8 || i+1+ls+os > len(b) {
			return nil, corrupt("malformed data run header 0x%02x", h)
		}
		var length uint64
		for k := 0; k < ls; k++ {
			length |= uint64(b[i+1+k]) << (8 * k)
		}
		if length == 0 || length > uint64(clusters) {
			return nil, corrupt("data run of %d clusters", length)
		}
		r := run{vcn: vcn, length: int64(length), lcn: -1}
		if os > 0 {
			var off int64
			for k := 0; k < os; k++ {
				off |= int64(b[i+1+ls+k]) << (8 * k)
			}
			if b[i+ls+os]&0x80 != 0 && os < 8 { // sign extend
				off |= -1 << (8 * uint(os))
			}
			lcn += off
			if lcn < 0 || lcn+int64(length) > clusters {
				return nil, corrupt("data run [%d,+%d) is outside the volume", lcn, length)
			}
			r.lcn = lcn
		}
		out = append(out, r)
		if len(out) > maxRunsPerAttr {
			return nil, corrupt("too many data runs")
		}
		vcn += int64(length)
		i += 1 + ls + os
	}
	return out, nil
}

// readRecord reads and parses record n from the $MFT.
func (v *Volume) readRecord(n uint64) (*record, error) {
	if int64(n) < 0 || int64(n) >= v.mftRecordsN && v.mftRecordsN != 0 {
		return nil, fmt.Errorf("%w: record %d is beyond the $MFT (%d records)", ErrNotFound, n, v.mftRecordsN)
	}
	buf := make([]byte, v.recordSize)
	got, err := v.mft.ReadAt(buf, int64(n)*int64(v.recordSize))
	if got < len(buf) {
		return nil, corrupt("reading record %d: %v", n, err)
	}
	rec, err := v.parseRecord(buf)
	if errors.Is(err, errBlank) {
		return nil, fmt.Errorf("%w: record %d is unused", ErrNotFound, n)
	}
	if err != nil {
		return nil, fmt.Errorf("record %d: %w", n, err)
	}
	return rec, nil
}

// file is a base record merged with its extension records.
type file struct {
	rec      *record
	attrs    []*attr
	extCount int
}

func (f *file) dataAttr(name string) *attr {
	for _, a := range f.attrs {
		if a.typ == attrData && a.name == name {
			return a
		}
	}
	for _, a := range f.attrs {
		if a.typ == attrData && strings.EqualFold(a.name, name) {
			return a
		}
	}
	return nil
}

// loadFile reads record n and, if it has an $ATTRIBUTE_LIST, every
// extension record the list names, and merges split attributes.
func (v *Volume) loadFile(n uint64) (*file, error) {
	rec, err := v.readRecord(n)
	if err != nil {
		return nil, err
	}
	if rec.baseRef != 0 {
		return nil, corrupt("record %d is an extension record of %d, not a file", n, rec.baseRef&0xffffffffffff)
	}
	f := &file{rec: rec}
	attrs := append([]*attr(nil), rec.attrs...)

	var list *attr
	for _, a := range rec.attrs {
		if a.typ == attrAttributeList {
			list = a
			break
		}
	}
	if list != nil {
		raw, err := v.attrBytes(list)
		if err != nil {
			return nil, fmt.Errorf("record %d $ATTRIBUTE_LIST: %w", n, err)
		}
		seen := map[uint64]bool{n: true}
		var exts []uint64
		for off, count := 0, 0; off+26 <= len(raw); count++ {
			if count > maxListEntries {
				return nil, corrupt("record %d: attribute list is implausibly long", n)
			}
			elen := int(u16(raw, off+4))
			if elen < 26 || elen%8 != 0 || off+elen > len(raw) {
				return nil, corrupt("record %d: attribute list entry at %d has length %d", n, off, elen)
			}
			ref := u64(raw, off+16) & 0xffffffffffff
			if !seen[ref] {
				seen[ref] = true
				exts = append(exts, ref)
				if len(exts) > maxExtRecords {
					return nil, corrupt("record %d: too many extension records", n)
				}
			}
			off += elen
		}
		for _, e := range exts {
			er, err := v.readRecord(e)
			if err != nil {
				return nil, fmt.Errorf("record %d extension %d: %w", n, e, err)
			}
			if er.baseRef&0xffffffffffff != n {
				return nil, corrupt("record %d lists %d as an extension, but that record belongs to %d", n, e, er.baseRef&0xffffffffffff)
			}
			attrs = append(attrs, er.attrs...)
		}
		f.extCount = len(exts)
	}
	merged, err := mergeAttrs(attrs)
	if err != nil {
		return nil, fmt.Errorf("record %d: %w", n, err)
	}
	f.attrs = merged
	return f, nil
}

// mergeAttrs joins the pieces of non-resident attributes that were split
// across records, ordered by starting VCN, checking they are contiguous.
func mergeAttrs(in []*attr) ([]*attr, error) {
	type key struct {
		typ  uint32
		name string
	}
	groups := map[key][]*attr{}
	var order []key
	for _, a := range in {
		k := key{a.typ, a.name}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], a)
	}
	var out []*attr
	for _, k := range order {
		g := groups[k]
		if len(g) == 1 || g[0].resident {
			for _, a := range g {
				if a.resident || len(g) == 1 {
					out = append(out, a)
				}
			}
			if len(g) > 1 && g[0].resident {
				// Several resident attributes with one name (e.g. FILE_NAME
				// x2): keep them all, they are distinct values.
				out = out[:len(out)-1]
				out = append(out, g...)
			}
			continue
		}
		sort.SliceStable(g, func(i, j int) bool { return g[i].startVCN < g[j].startVCN })
		if g[0].startVCN != 0 {
			return nil, corrupt("attribute 0x%x starts at VCN %d, not 0: an extent is missing", k.typ, g[0].startVCN)
		}
		m := *g[0]
		m.runs = append([]run(nil), g[0].runs...)
		for _, p := range g[1:] {
			if p.resident || p.startVCN != m.lastVCN+1 {
				return nil, corrupt("attribute 0x%x extents are not contiguous (VCN %d after %d)", k.typ, p.startVCN, m.lastVCN)
			}
			m.runs = append(m.runs, p.runs...)
			m.lastVCN = p.lastVCN
			if len(m.runs) > maxRunsPerAttr {
				return nil, corrupt("too many data runs")
			}
		}
		out = append(out, &m)
	}
	return out, nil
}

// attrBytes returns an attribute's full content (resident or read from
// its runs), bounded.
func (v *Volume) attrBytes(a *attr) ([]byte, error) {
	if a.resident {
		return a.content, nil
	}
	if a.dataSize > 64<<20 {
		return nil, corrupt("attribute of %d bytes is implausibly large", a.dataSize)
	}
	dr := &DataReader{v: v, runs: a.runs, size: a.dataSize, initSize: a.initSize}
	if err := dr.checkCoverage(v.cluster); err != nil {
		return nil, err
	}
	b := make([]byte, a.dataSize)
	if n, err := dr.ReadAt(b, 0); n < len(b) {
		return nil, corrupt("reading attribute: %v", err)
	}
	return b, nil
}

// ---- data

// DataReader is a read-only view of one data stream.
type DataReader struct {
	v        *Volume
	resident []byte
	isRes    bool
	runs     []run
	size     int64
	initSize int64
}

// Size is the stream's logical length.
func (d *DataReader) Size() int64 { return d.size }

func (d *DataReader) checkCoverage(cluster int) error {
	if d.isRes || d.size == 0 {
		return nil
	}
	var end int64
	for _, r := range d.runs {
		if r.vcn+r.length > end {
			end = r.vcn + r.length
		}
	}
	if end*int64(cluster) < d.size {
		return corrupt("the data runs cover %d bytes but the stream is %d bytes", end*int64(cluster), d.size)
	}
	return nil
}

// ReadAt implements io.ReaderAt. Sparse regions and bytes past the
// initialized size read as zeros, as NTFS defines them.
func (d *DataReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("ntfsvol: negative offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= d.size {
		return 0, io.EOF
	}
	if want := d.size - off; int64(len(p)) > want {
		p = p[:want]
	}
	total := 0
	if d.isRes {
		total = copy(p, d.resident[off:])
	} else {
		cs := int64(d.v.cluster)
		for total < len(p) {
			pos := off + int64(total)
			vcn := pos / cs
			i := sort.Search(len(d.runs), func(i int) bool { return d.runs[i].vcn+d.runs[i].length > vcn })
			if i == len(d.runs) || d.runs[i].vcn > vcn {
				return total, corrupt("no data run covers VCN %d", vcn)
			}
			r := d.runs[i]
			inRun := pos - r.vcn*cs
			n := int64(len(p) - total)
			if left := r.length*cs - inRun; n > left {
				n = left
			}
			dst := p[total : total+int(n)]
			switch {
			case r.lcn < 0 || pos >= d.initSize:
				for k := range dst {
					dst[k] = 0
				}
			default:
				// bytes beyond the initialized size inside this read are zeros
				readN := int64(len(dst))
				if pos+readN > d.initSize {
					readN = d.initSize - pos
				}
				got, err := d.v.r.ReadAt(dst[:readN], r.lcn*cs+inRun)
				if int64(got) < readN {
					return total + got, corrupt("reading cluster data at LCN %d: %v", r.lcn, err)
				}
				for k := readN; k < int64(len(dst)); k++ {
					dst[k] = 0
				}
			}
			total += int(n)
		}
	}
	if total < len(p) {
		return total, io.EOF
	}
	if off+int64(total) >= d.size {
		return total, io.EOF
	}
	return total, nil
}

// AllocatedRanges returns the [start,end) byte ranges that are backed by
// stored clusters, in order. Sparse holes are omitted, so an extractor can
// write a sparse output file instead of gigabytes of zeros.
func (d *DataReader) AllocatedRanges() [][2]int64 {
	if d.isRes {
		if d.size == 0 {
			return nil
		}
		return [][2]int64{{0, d.size}}
	}
	cs := int64(d.v.cluster)
	var out [][2]int64
	for _, r := range d.runs {
		if r.lcn < 0 {
			continue
		}
		s, e := r.vcn*cs, (r.vcn+r.length)*cs
		if e > d.size {
			e = d.size
		}
		if e > d.initSize {
			e = d.initSize
		}
		if s >= e {
			continue
		}
		if n := len(out); n > 0 && out[n-1][1] == s {
			out[n-1][1] = e
		} else {
			out = append(out, [2]int64{s, e})
		}
	}
	return out
}

// OpenStream opens a data stream of a record: "" for the file's content,
// or the name of an alternate data stream. It works for deleted records.
func (v *Volume) OpenStream(record uint64, stream string) (*DataReader, error) {
	f, err := v.loadFile(record)
	if err != nil {
		return nil, err
	}
	a := f.dataAttr(stream)
	if a == nil {
		return nil, fmt.Errorf("%w: record %d has no data stream %q", ErrNotFound, record, stream)
	}
	if a.flags&flagEncrypted != 0 {
		return nil, ErrEncrypted
	}
	if a.flags&flagCompressed != 0 && !a.resident {
		return nil, ErrCompressed
	}
	if a.resident {
		return &DataReader{v: v, isRes: true, resident: a.content, size: int64(len(a.content)), initSize: int64(len(a.content))}, nil
	}
	dr := &DataReader{v: v, runs: a.runs, size: a.dataSize, initSize: a.initSize}
	if dr.initSize > dr.size {
		dr.initSize = dr.size
	}
	if err := dr.checkCoverage(v.cluster); err != nil {
		return nil, err
	}
	return dr, nil
}

// ---- walking

// Stream, File and WalkStats are the file-system-neutral types of package
// fsvol. The NTFS names are kept so the NTFS code reads as before.
type (
	Stream    = fsvol.Stream
	File      = fsvol.File
	WalkStats = fsvol.WalkStats
)

type node struct {
	name      string
	parent    uint64
	parentSeq uint16
	seq       uint16
	dir       bool
	inUse     bool
}

type summary struct {
	node
	file File
}

func filetime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	const epochDiff = 116444736000000000 // 100ns ticks between 1601 and 1970
	if ft < epochDiff {
		return time.Time{}
	}
	d := ft - epochDiff
	return time.Unix(int64(d/10000000), int64(d%10000000)*100).UTC()
}

func fileNameRank(ns byte) int {
	switch ns {
	case 1: // Win32
		return 0
	case 3: // Win32 and DOS
		return 1
	case 0: // POSIX
		return 2
	default: // DOS short name
		return 3
	}
}

// describe turns a loaded file into its summary.
func describe(n uint64, f *file) (summary, bool) {
	var s summary
	best := 99
	for _, a := range f.attrs {
		if a.typ != attrFileName || !a.resident || len(a.content) < 66 {
			continue
		}
		nl := int(a.content[64])
		if 66+2*nl > len(a.content) {
			continue
		}
		if r := fileNameRank(a.content[65]); r < best {
			best = r
			ref := u64(a.content, 0)
			s.name = decodeUTF16(a.content[66 : 66+2*nl])
			s.parent = ref & 0xffffffffffff
			s.parentSeq = uint16(ref >> 48)
		}
	}
	if best == 99 {
		return summary{}, false
	}
	s.seq = f.rec.seq
	s.dir = f.rec.flags&recDir != 0
	s.inUse = f.rec.flags&recInUse != 0
	s.file = File{
		Record: n, Seq: f.rec.seq, Parent: s.parent, Name: s.name, IsDir: s.dir, InUse: s.inUse, ExtensionRecords: f.extCount,
	}
	for _, a := range f.attrs {
		switch a.typ {
		case attrStandardInformation:
			if a.resident && len(a.content) >= 36 {
				s.file.Created, s.file.Modified = filetime(u64(a.content, 0)), filetime(u64(a.content, 8))
				s.file.MFTChanged, s.file.Accessed = filetime(u64(a.content, 16)), filetime(u64(a.content, 24))
				s.file.Attributes = u32(a.content, 32)
			}
		case attrData:
			st := Stream{Name: a.name, Size: a.dataSize, Resident: a.resident,
				Compressed: a.flags&flagCompressed != 0 && !a.resident, Encrypted: a.flags&flagEncrypted != 0, Sparse: a.flags&flagSparse != 0}
			s.file.Streams = append(s.file.Streams, st)
			if a.name == "" {
				s.file.Size = a.dataSize
			}
		}
	}
	return s, true
}

// forEachRecord reads the whole $MFT sequentially and calls fn for every
// base record that has a name. Unreadable records are counted, not fatal.
func (v *Volume) forEachRecord(stats *WalkStats, fn func(n uint64, f *file) error) error {
	const batch = 512
	buf := make([]byte, batch*v.recordSize)
	for first := int64(0); first < v.mftRecordsN; first += batch {
		count := int64(batch)
		if first+count > v.mftRecordsN {
			count = v.mftRecordsN - first
		}
		chunk := buf[:count*int64(v.recordSize)]
		if got, err := v.mft.ReadAt(chunk, first*int64(v.recordSize)); got < len(chunk) {
			return corrupt("reading the $MFT at record %d: %v", first, err)
		}
		for i := int64(0); i < count; i++ {
			n := uint64(first + i)
			rb := chunk[i*int64(v.recordSize) : (i+1)*int64(v.recordSize)]
			rec, err := v.parseRecord(rb)
			if errors.Is(err, errBlank) {
				continue
			}
			if err != nil {
				stats.CorruptCount++
				if len(stats.Corrupt) < maxCorruptKept {
					stats.Corrupt = append(stats.Corrupt, n)
				}
				continue
			}
			if rec.baseRef != 0 {
				continue // extension record; reached through its base
			}
			f := &file{rec: rec, attrs: rec.attrs}
			for _, a := range rec.attrs {
				if a.typ == attrAttributeList {
					full, err := v.loadFile(n)
					if err != nil {
						stats.CorruptCount++
						if len(stats.Corrupt) < maxCorruptKept {
							stats.Corrupt = append(stats.Corrupt, n)
						}
						f = nil
					} else {
						f = full
					}
					break
				}
			}
			if f == nil {
				continue
			}
			if err := fn(n, f); err != nil {
				return err
			}
		}
	}
	return nil
}

// Walk lists every named MFT entry, in use or deleted, with its full path.
// fn may return an error to stop the walk; that error is returned as is.
func (v *Volume) Walk(fn func(File) error) (WalkStats, error) {
	var stats WalkStats
	nodes := make(map[uint64]node, int(min64(v.mftRecordsN, 1<<22)))
	if err := v.forEachRecord(&stats, func(n uint64, f *file) error {
		if s, ok := describe(n, f); ok {
			nodes[n] = s.node
		}
		return nil
	}); err != nil {
		return stats, err
	}

	paths := map[uint64]string{}
	var resolve func(n uint64, depth int, visiting map[uint64]bool) (string, bool)
	resolve = func(n uint64, depth int, visiting map[uint64]bool) (string, bool) {
		if n == rootRecord {
			return "", true
		}
		if p, ok := paths[n]; ok {
			return p, true
		}
		nd, ok := nodes[n]
		if !ok || depth > maxPathDepth || visiting[n] {
			return "", false
		}
		visiting[n] = true
		defer delete(visiting, n)
		parent, ok := nodes[nd.parent]
		if nd.parent != rootRecord && (!ok || !parent.dir) {
			return "", false
		}
		if nd.parent != rootRecord && nd.inUse && parent.seq != nd.parentSeq {
			return "", false // the parent slot has been reused since
		}
		pp, ok := resolve(nd.parent, depth+1, visiting)
		if !ok {
			return "", false
		}
		p := pp + "/" + cleanName(nd.name)
		if nd.dir {
			paths[n] = p
		}
		return p, true
	}

	return stats, v.walkEmit(&stats, nodes, resolve, fn)
}

func (v *Volume) walkEmit(stats *WalkStats, nodes map[uint64]node,
	resolve func(uint64, int, map[uint64]bool) (string, bool), fn func(File) error) error {
	var second WalkStats
	err := v.forEachRecord(&second, func(n uint64, f *file) error {
		s, ok := describe(n, f)
		if !ok {
			return nil
		}
		stats.Records++
		if s.inUse {
			stats.InUse++
		} else {
			stats.Deleted++
		}
		out := s.file
		if n == rootRecord {
			out.Path = "/"
		} else if p, ok := resolve(n, 0, map[uint64]bool{}); ok {
			out.Path = p
		} else {
			out.Path = "/$OrphanFiles/" + cleanName(s.name)
			out.Orphan = true
		}
		return fn(out)
	})
	// The first pass already counted unreadable records.
	return err
}

// cleanName makes a single name component safe to join into a path.
func cleanName(n string) string {
	switch n {
	case "", ".", "..":
		return "%" + fmt.Sprintf("%02X", []byte(n + "_")[0])
	}
	return strings.Map(func(r rune) rune {
		if r == '/' || r == 0 {
			return '_'
		}
		return r
	}, n)
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// AsVolume presents the volume as an fsvol.Volume, the form the disk-image
// catalog works with.
func (v *Volume) AsVolume() fsvol.Volume { return volumeAdapter{v} }

type volumeAdapter struct{ v *Volume }

func (a volumeAdapter) Info() fsvol.Info {
	i := a.v.Info()
	return fsvol.Info{
		Label: i.Label, Version: i.Version, Serial: i.Serial, ClusterSize: i.ClusterSize,
		Records: i.MFTRecords, VolumeBytes: i.VolumeBytes,
	}
}

func (a volumeAdapter) Walk(fn func(fsvol.File) error) (fsvol.WalkStats, error) {
	return a.v.Walk(fn)
}

func (a volumeAdapter) OpenStream(record uint64, stream string) (fsvol.Reader, error) {
	dr, err := a.v.OpenStream(record, stream)
	if err != nil {
		return nil, err
	}
	return dr, nil
}
