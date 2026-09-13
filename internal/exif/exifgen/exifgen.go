// Package exifgen builds synthetic JPEG files with controlled EXIF
// content, for testing internal/exif.
//
// It exists so the EXIF tests can state the exact bytes they are
// asserting about. A real photograph as a fixture proves the parser
// agrees with one camera; a generated file proves it agrees with the
// specification -- including for the cases no camera in reach produces,
// such as a southern-and-western coordinate, a zero denominator, or an
// IFD whose offset points outside the block.
//
// The generator writes the format as documented, independently of how
// internal/exif reads it. Where the two must agree, that agreement is
// what the tests check.
package exifgen

import (
	"bytes"
	"encoding/binary"
	"sort"
)

// Spec describes the image to build. A zero Spec produces a valid
// minimal JPEG with no EXIF at all, which is itself a case worth testing.
type Spec struct {
	// Width/Height go into the SOF0 frame header. Zero writes 0, which
	// is what a malformed frame header looks like.
	Width, Height int

	// NoEXIF omits the APP1 segment entirely.
	NoEXIF bool

	// BigEndian writes the TIFF block in "MM" order instead of "II".
	BigEndian bool

	Make     string
	Model    string
	Software string
	// DateTime is IFD0's ModifyDate; the two Exif-IFD times are
	// DateTimeOriginal and DateTimeDigitized. Empty omits the tag.
	DateTime          string
	DateTimeOriginal  string
	DateTimeDigitized string
	// OffsetTimeOriginal is EXIF 2.31's UTC offset for DateTimeOriginal,
	// e.g. "+02:00". Empty omits it, which is the common case.
	OffsetTimeOriginal string

	Orientation int
	PixelXDim   int
	PixelYDim   int
	BodySerial  string

	// GPS, when non-nil, writes a GPS IFD.
	GPS *GPS

	// Thumbnail, when non-empty, is embedded as the IFD1 thumbnail --
	// the small preview a camera stores alongside the full image. IFD1
	// records only its offset and length, so what is written here is what
	// a reader must get back byte for byte.
	Thumbnail []byte
	// ThumbnailCompression overrides IFD1's Compression tag. 0 writes
	// the JPEG value (6); set it to 1 to produce the uncompressed-strips
	// form, which is not a servable image and must not be claimed as one.
	ThumbnailCompression int
	// ThumbnailOffsetOverride replaces the computed JPEGInterchangeFormat
	// offset, for testing a directory that points outside the block.
	ThumbnailOffsetOverride int

	// CorruptTIFFMagic writes a TIFF header whose magic number is wrong.
	CorruptTIFFMagic bool
	// BadIFDOffset points IFD0 far outside the EXIF block.
	BadIFDOffset bool
	// LoopingIFD makes IFD0's next-directory pointer point back at IFD0.
	LoopingIFD bool
	// TruncateEXIFTo cuts the EXIF payload to this many bytes while
	// leaving the segment's declared length untouched, which is what a
	// truncated file looks like from the outside.
	TruncateEXIFTo int
}

// GPS describes a GPS IFD. Components are numerator/denominator pairs
// exactly as EXIF stores them, so a test can write 0/0, an absent
// hemisphere, or a coordinate no camera would produce.
type GPS struct {
	LatRef string       // "N" or "S"; empty omits the tag
	Lat    [3][2]uint32 // degrees, minutes, seconds as num/den
	LonRef string       // "E" or "W"; empty omits the tag
	Lon    [3][2]uint32

	OmitLat bool // write no GPSLatitude tag at all
	OmitLon bool

	AltitudeRef *uint16
	Altitude    *[2]uint32

	DateStamp string        // "2021:04:29"
	TimeStamp *[3][2]uint32 // hours, minutes, seconds

	MapDatum string
	// VersionOnly writes a GPS IFD containing nothing but GPSVersionID,
	// which is the common "GPS block present, no position" case.
	VersionOnly bool
}

// EXIF value types.
const (
	typeASCII    = 2
	typeShort    = 3
	typeLong     = 4
	typeRational = 5
	typeByte     = 1
)

type tag struct {
	id    uint16
	typ   uint16
	count uint32
	// inline is the 4-byte value field when the value fits; otherwise
	// data is appended to the value area and the offset is written.
	data []byte
	// isOffset marks a tag whose 4-byte field is a directory offset
	// patched after layout.
	patch string
}

// Build assembles the JPEG.
func Build(s Spec) []byte {
	var out bytes.Buffer
	out.Write([]byte{0xFF, 0xD8}) // SOI

	if !s.NoEXIF {
		payload := buildEXIF(s)
		body := append([]byte("Exif\x00\x00"), payload...)
		declared := len(body) + 2
		if s.TruncateEXIFTo > 0 && s.TruncateEXIFTo < len(body) {
			// The segment still DECLARES its full length; only the bytes
			// are short. That is what truncation looks like.
			body = body[:s.TruncateEXIFTo]
		}
		out.Write([]byte{0xFF, 0xE1})
		binary.Write(&out, binary.BigEndian, uint16(declared))
		out.Write(body)
	}

	// SOF0: precision, height, width, components.
	frame := []byte{8, 0, 0, 0, 0, 1, 0x11, 0x00}
	binary.BigEndian.PutUint16(frame[1:3], uint16(s.Height))
	binary.BigEndian.PutUint16(frame[3:5], uint16(s.Width))
	out.Write([]byte{0xFF, 0xC0})
	binary.Write(&out, binary.BigEndian, uint16(len(frame)+2))
	out.Write(frame)

	// SOS, a byte of "entropy data", EOI. The parser must stop at SOS
	// and never look at what follows.
	out.Write([]byte{0xFF, 0xDA})
	binary.Write(&out, binary.BigEndian, uint16(8))
	out.Write([]byte{1, 0, 0, 0, 0x3F, 0})
	out.Write([]byte{0x00, 0x11, 0x22, 0x33})
	out.Write([]byte{0xFF, 0xD9})

	return out.Bytes()
}

// buildEXIF lays out the TIFF block: header, IFD0, the Exif sub-IFD and
// the GPS sub-IFD, with every out-of-line value appended after the
// directory that references it.
func buildEXIF(s Spec) []byte {
	order := binary.ByteOrder(binary.LittleEndian)
	mark := []byte("II")
	if s.BigEndian {
		order = binary.BigEndian
		mark = []byte("MM")
	}

	ifd0 := []tag{}
	add := func(list *[]tag, t tag) { *list = append(*list, t) }

	if s.Make != "" {
		add(&ifd0, asciiTag(0x010F, s.Make))
	}
	if s.Model != "" {
		add(&ifd0, asciiTag(0x0110, s.Model))
	}
	if s.Orientation != 0 {
		add(&ifd0, shortTag(order, 0x0112, uint16(s.Orientation)))
	}
	if s.Software != "" {
		add(&ifd0, asciiTag(0x0131, s.Software))
	}
	if s.DateTime != "" {
		add(&ifd0, asciiTag(0x0132, s.DateTime))
	}

	exifIFD := []tag{}
	if s.DateTimeOriginal != "" {
		add(&exifIFD, asciiTag(0x9003, s.DateTimeOriginal))
	}
	if s.DateTimeDigitized != "" {
		add(&exifIFD, asciiTag(0x9004, s.DateTimeDigitized))
	}
	if s.OffsetTimeOriginal != "" {
		add(&exifIFD, asciiTag(0x9011, s.OffsetTimeOriginal))
	}
	if s.PixelXDim != 0 {
		add(&exifIFD, longTag(order, 0xA002, uint32(s.PixelXDim)))
	}
	if s.PixelYDim != 0 {
		add(&exifIFD, longTag(order, 0xA003, uint32(s.PixelYDim)))
	}
	if s.BodySerial != "" {
		add(&exifIFD, asciiTag(0xA431, s.BodySerial))
	}

	var gpsIFD []tag
	if s.GPS != nil {
		g := s.GPS
		add(&gpsIFD, tag{id: 0x0000, typ: typeByte, count: 4, data: []byte{2, 3, 0, 0}})
		if !g.VersionOnly {
			if g.LatRef != "" {
				add(&gpsIFD, asciiTag(0x0001, g.LatRef))
			}
			if !g.OmitLat {
				add(&gpsIFD, rationalTag(order, 0x0002, g.Lat[:]))
			}
			if g.LonRef != "" {
				add(&gpsIFD, asciiTag(0x0003, g.LonRef))
			}
			if !g.OmitLon {
				add(&gpsIFD, rationalTag(order, 0x0004, g.Lon[:]))
			}
			if g.AltitudeRef != nil {
				add(&gpsIFD, tag{id: 0x0005, typ: typeByte, count: 1, data: []byte{byte(*g.AltitudeRef)}})
			}
			if g.Altitude != nil {
				add(&gpsIFD, rationalTag(order, 0x0006, [][2]uint32{*g.Altitude}))
			}
			if g.TimeStamp != nil {
				add(&gpsIFD, rationalTag(order, 0x0007, g.TimeStamp[:]))
			}
			if g.MapDatum != "" {
				add(&gpsIFD, asciiTag(0x0012, g.MapDatum))
			}
			if g.DateStamp != "" {
				add(&gpsIFD, asciiTag(0x001D, g.DateStamp))
			}
		}
	}

	if len(exifIFD) > 0 {
		add(&ifd0, tag{id: 0x8769, typ: typeLong, count: 1, patch: "exif"})
	}
	if len(gpsIFD) > 0 {
		add(&ifd0, tag{id: 0x8825, typ: typeLong, count: 1, patch: "gps"})
	}

	// EXIF requires directory entries in ascending tag order.
	sortTags(ifd0)
	sortTags(exifIFD)
	sortTags(gpsIFD)

	// Header: 8 bytes, then IFD0.
	const headerLen = 8
	ifd0Off := headerLen
	ifd0Len := directoryLen(ifd0)
	exifOff := ifd0Off + ifd0Len + valueLen(ifd0)
	exifLen := directoryLen(exifIFD)
	gpsOff := exifOff + exifLen + valueLen(exifIFD)

	if len(exifIFD) == 0 {
		exifOff = 0
		gpsOff = ifd0Off + ifd0Len + valueLen(ifd0)
	}
	if len(gpsIFD) == 0 {
		gpsOff = 0
	}

	// IFD1 -- the thumbnail directory -- follows every other directory,
	// and the thumbnail's own bytes follow it. Its offset tag is relative
	// to the TIFF block, which is what the reader has to get right.
	var ifd1 []tag
	ifd1Off, thumbDataOff := 0, 0
	if len(s.Thumbnail) > 0 {
		after := ifd0Off + ifd0Len + valueLen(ifd0)
		if len(exifIFD) > 0 {
			after = exifOff + exifLen + valueLen(exifIFD)
		}
		if len(gpsIFD) > 0 {
			after = gpsOff + directoryLen(gpsIFD) + valueLen(gpsIFD)
		}
		ifd1Off = after

		compression := s.ThumbnailCompression
		if compression == 0 {
			compression = 6 // JPEG
		}
		add(&ifd1, shortTag(order, 0x0103, uint16(compression)))
		add(&ifd1, longTag(order, 0x0201, 0)) // patched below
		add(&ifd1, longTag(order, 0x0202, uint32(len(s.Thumbnail))))
		sortTags(ifd1)

		thumbDataOff = ifd1Off + directoryLen(ifd1) + valueLen(ifd1)
		if s.ThumbnailOffsetOverride != 0 {
			thumbDataOff = s.ThumbnailOffsetOverride
		}
		for i := range ifd1 {
			if ifd1[i].id == 0x0201 {
				b := make([]byte, 4)
				order.PutUint32(b, uint32(thumbDataOff))
				ifd1[i].data = b
			}
		}
	}

	var buf bytes.Buffer
	buf.Write(mark)
	magic := uint16(42)
	if s.CorruptTIFFMagic {
		magic = 0
	}
	writeU16(&buf, order, magic)
	firstIFD := uint32(ifd0Off)
	if s.BadIFDOffset {
		firstIFD = 0x7FFFFFFF
	}
	writeU32(&buf, order, firstIFD)

	next := uint32(0)
	if len(ifd1) > 0 {
		next = uint32(ifd1Off)
	}
	if s.LoopingIFD {
		next = uint32(ifd0Off)
	}
	writeDirectory(&buf, order, ifd0, ifd0Off, next, map[string]uint32{
		"exif": uint32(exifOff),
		"gps":  uint32(gpsOff),
	})
	if len(exifIFD) > 0 {
		writeDirectory(&buf, order, exifIFD, exifOff, 0, nil)
	}
	if len(gpsIFD) > 0 {
		writeDirectory(&buf, order, gpsIFD, gpsOff, 0, nil)
	}
	if len(ifd1) > 0 {
		writeDirectory(&buf, order, ifd1, ifd1Off, 0, nil)
		// Pad to the declared data offset, then the thumbnail itself, so
		// the bytes really are where IFD1 says they are.
		for buf.Len() < thumbDataOff {
			buf.WriteByte(0)
		}
		buf.Write(s.Thumbnail)
	}
	return buf.Bytes()
}

func sortTags(t []tag) {
	sort.Slice(t, func(i, j int) bool { return t[i].id < t[j].id })
}

func directoryLen(t []tag) int {
	if len(t) == 0 {
		return 0
	}
	return 2 + len(t)*12 + 4
}

func valueLen(t []tag) int {
	n := 0
	for _, e := range t {
		if len(e.data) > 4 {
			n += len(e.data)
			if len(e.data)%2 == 1 {
				n++ // EXIF value offsets are word-aligned
			}
		}
	}
	return n
}

// writeDirectory emits the entry table followed by every out-of-line
// value, with each value's offset written into its entry.
func writeDirectory(buf *bytes.Buffer, order binary.ByteOrder, tags []tag, dirOff int, next uint32, patches map[string]uint32) {
	if len(tags) == 0 {
		return
	}
	valueOff := dirOff + directoryLen(tags)

	writeU16(buf, order, uint16(len(tags)))
	var values bytes.Buffer
	for _, e := range tags {
		writeU16(buf, order, e.id)
		writeU16(buf, order, e.typ)
		writeU32(buf, order, e.count)
		switch {
		case e.patch != "":
			writeU32(buf, order, patches[e.patch])
		case len(e.data) <= 4:
			padded := make([]byte, 4)
			copy(padded, e.data)
			buf.Write(padded)
		default:
			writeU32(buf, order, uint32(valueOff+values.Len()))
			values.Write(e.data)
			if values.Len()%2 == 1 {
				values.WriteByte(0)
			}
		}
	}
	writeU32(buf, order, next)
	buf.Write(values.Bytes())
}

func asciiTag(id uint16, v string) tag {
	b := append([]byte(v), 0)
	return tag{id: id, typ: typeASCII, count: uint32(len(b)), data: b}
}

func shortTag(order binary.ByteOrder, id uint16, v uint16) tag {
	b := make([]byte, 2)
	order.PutUint16(b, v)
	return tag{id: id, typ: typeShort, count: 1, data: b}
}

func longTag(order binary.ByteOrder, id uint16, v uint32) tag {
	b := make([]byte, 4)
	order.PutUint32(b, v)
	return tag{id: id, typ: typeLong, count: 1, data: b}
}

func rationalTag(order binary.ByteOrder, id uint16, vals [][2]uint32) tag {
	b := make([]byte, 0, len(vals)*8)
	for _, v := range vals {
		n := make([]byte, 8)
		order.PutUint32(n[0:4], v[0])
		order.PutUint32(n[4:8], v[1])
		b = append(b, n...)
	}
	return tag{id: id, typ: typeRational, count: uint32(len(vals)), data: b}
}

func writeU16(buf *bytes.Buffer, order binary.ByteOrder, v uint16) {
	b := make([]byte, 2)
	order.PutUint16(b, v)
	buf.Write(b)
}

func writeU32(buf *bytes.Buffer, order binary.ByteOrder, v uint32) {
	b := make([]byte, 4)
	order.PutUint32(b, v)
	buf.Write(b)
}

// DMS is a convenience for whole-number degrees/minutes/seconds.
func DMS(d, m, s uint32) [3][2]uint32 {
	return [3][2]uint32{{d, 1}, {m, 1}, {s, 1}}
}

// DMSFrac builds components with a fractional seconds value, e.g.
// DMSFrac(34, 12, 152, 10) for 34° 12' 15.2".
func DMSFrac(d, m, secNum, secDen uint32) [3][2]uint32 {
	return [3][2]uint32{{d, 1}, {m, 1}, {secNum, secDen}}
}

// MinimalJPEG returns the smallest structurally valid JPEG this package
// can write: SOI, an APP0 header, a frame header declaring 2x2, then SOS
// and EOI. It has no real entropy data, which is exactly right for
// testing that a thumbnail's BYTES are carried through untouched -- the
// point is the copy, not the picture.
func MinimalJPEG() []byte {
	return Build(Spec{Width: 2, Height: 2, NoEXIF: true})
}
