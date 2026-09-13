package exif

import (
	"encoding/binary"
	"math"
	"strconv"
	"strings"
	"time"
)

// EXIF tag numbers this package reads. Anything not listed is skipped;
// no tag is guessed at from its number.
const (
	tagMake                = 0x010F
	tagModel               = 0x0110
	tagOrientation         = 0x0112
	tagSoftware            = 0x0131
	tagDateTime            = 0x0132 // "ModifyDate": when the file was last written by the writing software
	tagExifIFD             = 0x8769
	tagGPSIFD              = 0x8825
	tagExposureTime        = 0x829A
	tagFNumber             = 0x829D
	tagISOSpeedRatings     = 0x8827
	tagDateTimeOriginal    = 0x9003
	tagDateTimeDigitized   = 0x9004
	tagOffsetTime          = 0x9010
	tagOffsetTimeOriginal  = 0x9011
	tagOffsetTimeDigitized = 0x9012
	tagFocalLength         = 0x920A
	tagPixelXDimension     = 0xA002
	tagPixelYDimension     = 0xA003
	tagBodySerialNumber    = 0xA431
	tagLensModel           = 0xA434

	// IFD1's thumbnail tags. JPEGInterchangeFormat is the thumbnail's
	// offset FROM THE START OF THE TIFF BLOCK, not from the start of the
	// file -- see Metadata.ThumbnailOffset.
	tagThumbnailWidth  = 0x0100
	tagThumbnailHeight = 0x0101
	tagCompression     = 0x0103
	tagJPEGIFOffset    = 0x0201
	tagJPEGIFByteCount = 0x0202
)

// GPS IFD tag numbers (EXIF 2.32 table 15).
const (
	gpsVersionID        = 0x0000
	gpsLatitudeRef      = 0x0001
	gpsLatitude         = 0x0002
	gpsLongitudeRef     = 0x0003
	gpsLongitude        = 0x0004
	gpsAltitudeRef      = 0x0005
	gpsAltitude         = 0x0006
	gpsTimeStamp        = 0x0007
	gpsProcessingMethod = 0x001B
	gpsDateStamp        = 0x001D
	gpsImgDirectionRef  = 0x0010
	gpsImgDirection     = 0x0011
	gpsMapDatum         = 0x0012
)

// EXIF value types and their byte widths (0 marks a type this package
// does not size, which is treated as one byte per component and skipped).
var typeSize = map[uint16]int{
	1:  1, // BYTE
	2:  1, // ASCII
	3:  2, // SHORT
	4:  4, // LONG
	5:  8, // RATIONAL
	6:  1, // SBYTE
	7:  1, // UNDEFINED
	8:  2, // SSHORT
	9:  4, // SLONG
	10: 8, // SRATIONAL
	11: 4, // FLOAT
	12: 8, // DOUBLE
}

// orientationNames are the eight documented values of the Orientation
// tag. An undocumented value is reported by its number alone.
var orientationNames = map[int]string{
	1: "normal",
	2: "mirrored horizontally",
	3: "rotated 180°",
	4: "mirrored vertically",
	5: "mirrored horizontally then rotated 270° clockwise",
	6: "rotated 90° clockwise",
	7: "mirrored horizontally then rotated 90° clockwise",
	8: "rotated 270° clockwise",
}

// tiffReader holds one EXIF block and the byte order it declared.
type tiffReader struct {
	data  []byte
	order binary.ByteOrder
	lim   Limits
}

func (t tiffReader) u16(off int) (uint16, bool) {
	if off < 0 || off+2 > len(t.data) {
		return 0, false
	}
	return t.order.Uint16(t.data[off : off+2]), true
}

func (t tiffReader) u32(off int) (uint32, bool) {
	if off < 0 || off+4 > len(t.data) {
		return 0, false
	}
	return t.order.Uint32(t.data[off : off+4]), true
}

// entry is one decoded 12-byte IFD entry, with its value bytes already
// located and bounds-checked.
type entry struct {
	tag   uint16
	typ   uint16
	count uint32
	value []byte // the value's bytes, inline or resolved through the offset
	ok    bool   // false when the value lay outside the block
}

func (t tiffReader) ascii(e entry) string {
	if !e.ok {
		return ""
	}
	b := e.value
	if t.lim.MaxStringBytes > 0 && len(b) > t.lim.MaxStringBytes {
		b = b[:t.lim.MaxStringBytes]
	}
	// EXIF ASCII values are NUL-terminated; trailing NULs and padding
	// whitespace are stripped, and any embedded NUL truncates -- but the
	// characters themselves are never otherwise altered.
	if i := indexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return strings.TrimSpace(string(b))
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

func (t tiffReader) int(e entry) (int, bool) {
	if !e.ok || e.count == 0 {
		return 0, false
	}
	switch e.typ {
	case 3:
		if len(e.value) < 2 {
			return 0, false
		}
		return int(t.order.Uint16(e.value[:2])), true
	case 4, 9:
		if len(e.value) < 4 {
			return 0, false
		}
		return int(int32(t.order.Uint32(e.value[:4]))), true
	case 1, 6, 7:
		if len(e.value) < 1 {
			return 0, false
		}
		return int(e.value[0]), true
	}
	return 0, false
}

// rationals decodes a RATIONAL or SRATIONAL value into the numerator and
// denominator pairs the file stored, without dividing them.
func (t tiffReader) rationals(e entry) []Rational {
	if !e.ok || (e.typ != 5 && e.typ != 10) {
		return nil
	}
	n := int(e.count)
	if t.lim.MaxRationals > 0 && n > t.lim.MaxRationals {
		n = t.lim.MaxRationals
	}
	out := make([]Rational, 0, n)
	for i := 0; i < n; i++ {
		off := i * 8
		if off+8 > len(e.value) {
			break
		}
		num := t.order.Uint32(e.value[off : off+4])
		den := t.order.Uint32(e.value[off+4 : off+8])
		if e.typ == 10 {
			out = append(out, Rational{Num: int64(int32(num)), Den: int64(int32(den))})
		} else {
			out = append(out, Rational{Num: int64(num), Den: int64(den)})
		}
	}
	return out
}

// readIFD decodes one image file directory. Every offset in an EXIF
// block is attacker-controlled, so each is bounds-checked against the
// block and every count is capped before anything is allocated.
func (t tiffReader) readIFD(off int, m *Metadata) (entries []entry, next int) {
	count, ok := t.u16(off)
	if !ok {
		m.warn(t.lim, "an EXIF directory offset ("+strconv.Itoa(off)+
			") lies outside the EXIF block; that directory was not read")
		return nil, 0
	}
	n := int(count)
	if t.lim.MaxIFDEntries > 0 && n > t.lim.MaxIFDEntries {
		m.warn(t.lim, "an EXIF directory declares "+strconv.Itoa(n)+
			" entries; only the first "+strconv.Itoa(t.lim.MaxIFDEntries)+" were read")
		n = t.lim.MaxIFDEntries
	}

	entries = make([]entry, 0, n)
	for i := 0; i < n; i++ {
		base := off + 2 + i*12
		tag, ok1 := t.u16(base)
		typ, ok2 := t.u16(base + 2)
		cnt, ok3 := t.u32(base + 4)
		if !ok1 || !ok2 || !ok3 {
			m.warn(t.lim, "an EXIF directory ends before the "+strconv.Itoa(i+1)+
				" entries it declares; the entries read before that point are reported")
			break
		}

		e := entry{tag: tag, typ: typ, count: cnt}
		width := typeSize[typ]
		if width == 0 {
			// An unknown value type has an unknown size. It is recorded
			// as unreadable rather than guessed at.
			entries = append(entries, e)
			continue
		}
		size := int64(width) * int64(cnt)
		if size < 0 || size > int64(len(t.data)) {
			entries = append(entries, e)
			continue
		}
		if size <= 4 {
			if base+8+int(size) <= len(t.data) {
				e.value = t.data[base+8 : base+8+int(size)]
				e.ok = true
			}
		} else {
			ptr, ok := t.u32(base + 8)
			if ok && int64(ptr)+size <= int64(len(t.data)) {
				e.value = t.data[int(ptr) : int(ptr)+int(size)]
				e.ok = true
			}
		}
		entries = append(entries, e)
	}

	if v, ok := t.u32(off + 2 + n*12); ok {
		next = int(v)
	}
	return entries, next
}

// decodeTIFF walks the EXIF block: IFD0, then the Exif sub-IFD and the
// GPS sub-IFD it points at.
func (m *Metadata) decodeTIFF(data []byte, lim Limits) {
	if len(data) < 8 {
		m.warn(lim, "the EXIF block is too short to contain a TIFF header; no EXIF values were read")
		return
	}

	var order binary.ByteOrder
	switch {
	case data[0] == 'I' && data[1] == 'I':
		order = binary.LittleEndian
		m.ByteOrder = "little-endian (II)"
	case data[0] == 'M' && data[1] == 'M':
		order = binary.BigEndian
		m.ByteOrder = "big-endian (MM)"
	default:
		m.warn(lim, "the EXIF block does not begin with a TIFF byte-order mark; no EXIF values were read")
		return
	}
	if order.Uint16(data[2:4]) != 42 {
		m.warn(lim, "the EXIF block's TIFF header is missing its magic number; no EXIF values were read")
		return
	}

	t := tiffReader{data: data, order: order, lim: lim}
	ifd0Off := int(order.Uint32(data[4:8]))

	// visited guards against a directory chain that points back into
	// itself, which would otherwise loop forever on a crafted file.
	visited := map[int]bool{}
	budget := lim.MaxIFDs
	if budget <= 0 {
		budget = 16
	}

	var exifOff, gpsOff int

	// The chain is IFD0, then IFD1, then any further directories. Their
	// positions are what give them meaning: IFD0 describes the image and
	// IFD1 describes the THUMBNAIL, and the two share tag numbers. Applying
	// IFD0's reading to IFD1 would let a thumbnail's 256x192 dimensions or
	// its own orientation overwrite the real image's.
	for off, index := ifd0Off, 0; off != 0 && budget > 0; budget, index = budget-1, index+1 {
		if visited[off] {
			m.warn(lim, "the EXIF directory chain points back to a directory already read; "+
				"the chain was not followed further")
			break
		}
		visited[off] = true

		entries, next := t.readIFD(off, m)
		switch index {
		case 0:
			for _, e := range entries {
				switch e.tag {
				case tagExifIFD:
					if v, ok := t.int(e); ok {
						exifOff = v
					}
				case tagGPSIFD:
					if v, ok := t.int(e); ok {
						gpsOff = v
					}
				}
			}
			m.applyIFD0(t, entries)
		case 1:
			m.applyThumbnailIFD(t, entries, lim)
		}
		off = next
	}

	if exifOff != 0 && !visited[exifOff] {
		visited[exifOff] = true
		entries, _ := t.readIFD(exifOff, m)
		m.applyExifIFD(t, entries)
	}
	if gpsOff != 0 && !visited[gpsOff] {
		visited[gpsOff] = true
		entries, _ := t.readIFD(gpsOff, m)
		m.applyGPSIFD(t, entries, lim)
	}

	m.attachOffsets()
}

func (m *Metadata) applyIFD0(t tiffReader, entries []entry) {
	for _, e := range entries {
		switch e.tag {
		case tagMake:
			m.Make = t.ascii(e)
		case tagModel:
			m.Model = t.ascii(e)
		case tagSoftware:
			m.Software = t.ascii(e)
		case tagOrientation:
			if v, ok := t.int(e); ok {
				m.Orientation = v
				m.OrientationName = orientationNames[v]
			}
		case tagDateTime:
			m.addTime("DateTime", t.ascii(e),
				"when the writing software last saved this file, as that software's own clock read it. "+
					"This is the image's ModifyDate. It is NOT the filesystem's modification time, and it is "+
					"NOT when the photograph was taken")
		}
	}
}

func (m *Metadata) applyExifIFD(t tiffReader, entries []entry) {
	var offOriginal, offDigitized, offDateTime string
	for _, e := range entries {
		switch e.tag {
		case tagOffsetTime:
			offDateTime = t.ascii(e)
		case tagOffsetTimeOriginal:
			offOriginal = t.ascii(e)
		case tagOffsetTimeDigitized:
			offDigitized = t.ascii(e)
		}
	}

	for _, e := range entries {
		switch e.tag {
		case tagDateTimeOriginal:
			m.addTimeWithOffset("DateTimeOriginal", t.ascii(e), offOriginal,
				"when the camera recorded the exposure -- when the photograph was TAKEN, as the camera's own "+
					"clock read it. It is not a filesystem time and it is not a file creation time")
		case tagDateTimeDigitized:
			m.addTimeWithOffset("DateTimeDigitized", t.ascii(e), offDigitized,
				"when the image was digitized. For a digital camera this equals the exposure time; for a "+
					"scan it is when the scan was made, not when the original was shot")
		case tagPixelXDimension:
			if v, ok := t.int(e); ok {
				m.EXIFWidth = v
			}
		case tagPixelYDimension:
			if v, ok := t.int(e); ok {
				m.EXIFHeight = v
			}
		case tagBodySerialNumber:
			m.BodySerial = t.ascii(e)
		case tagLensModel:
			m.LensModel = t.ascii(e)
		case tagISOSpeedRatings:
			if v, ok := t.int(e); ok {
				m.ISO = v
			}
		case tagExposureTime:
			if r := t.rationals(e); len(r) > 0 {
				v := r[0]
				m.ExposureTime = &v
			}
		case tagFNumber:
			if r := t.rationals(e); len(r) > 0 {
				v := r[0]
				m.FNumber = &v
			}
		case tagFocalLength:
			if r := t.rationals(e); len(r) > 0 {
				v := r[0]
				m.FocalLength = &v
			}
		}
	}

	// The image's own DateTime, if it was in IFD0, may have a zone
	// recorded here.
	if offDateTime != "" {
		for i := range m.Times {
			if m.Times[i].Tag == "DateTime" {
				m.Times[i].Offset = offDateTime
				m.Times[i].HasZone = true
			}
		}
	}
}

func (m *Metadata) applyGPSIFD(t tiffReader, entries []entry, lim Limits) {
	g := GPS{Present: true}

	for _, e := range entries {
		switch e.tag {
		case gpsVersionID:
			if e.ok && len(e.value) >= 4 {
				parts := make([]string, 0, 4)
				for _, b := range e.value[:4] {
					parts = append(parts, strconv.Itoa(int(b)))
				}
				g.VersionID = strings.Join(parts, ".")
			}
		case gpsLatitudeRef:
			g.LatRef = t.ascii(e)
		case gpsLongitudeRef:
			g.LonRef = t.ascii(e)
		case gpsLatitude:
			g.LatDMS = t.rationals(e)
		case gpsLongitude:
			g.LonDMS = t.rationals(e)
		case gpsAltitude:
			if r := t.rationals(e); len(r) > 0 {
				v := r[0]
				g.AltitudeRational = &v
			}
		case gpsAltitudeRef:
			if v, ok := t.int(e); ok {
				switch v {
				case 0:
					g.AltitudeRef = "above sea level"
				case 1:
					g.AltitudeRef = "below sea level"
				default:
					g.AltitudeRef = "undocumented GPSAltitudeRef value " + strconv.Itoa(v)
				}
			}
		case gpsTimeStamp:
			if r := t.rationals(e); len(r) == 3 {
				g.TimeStampRaw = formatGPSTime(r)
			}
		case gpsDateStamp:
			g.DateStampRaw = t.ascii(e)
		case gpsImgDirection:
			if r := t.rationals(e); len(r) > 0 {
				if v, ok := r[0].Float(); ok {
					g.ImgDirection = &v
				}
			}
		case gpsImgDirectionRef:
			switch ref := t.ascii(e); ref {
			case "T":
				g.ImgDirectionRef = "true north"
			case "M":
				g.ImgDirectionRef = "magnetic north"
			default:
				g.ImgDirectionRef = ref
			}
		case gpsMapDatum:
			g.MapDatum = t.ascii(e)
		case gpsProcessingMethod:
			g.ProcessingMethod = decodeUndefinedText(e)
		}
	}

	lat, latOK := dmsToDecimal(g.LatDMS, g.LatRef, "N", "S")
	lon, lonOK := dmsToDecimal(g.LonDMS, g.LonRef, "E", "W")

	switch {
	case latOK && lonOK:
		g.Lat, g.Lon = lat, lon
		g.Decoded = true
		g.Method = "derived from the three EXIF RATIONAL components (degrees, minutes, seconds) " +
			"signed by GPSLatitudeRef/GPSLongitudeRef; the stored components are retained alongside"
		g.LatRaw = formatDMS(g.LatDMS, g.LatRef)
		g.LonRaw = formatDMS(g.LonDMS, g.LonRef)
		g.Granularity, g.GranularityKm, g.GranularityNote = granularity(g.LatDMS, g.LonDMS)
	case len(g.LatDMS) > 0 || len(g.LonDMS) > 0:
		// One coordinate without the other is not a position. It is kept
		// and reported as incomplete rather than half-used.
		if len(g.LatDMS) > 0 {
			g.LatRaw = formatDMS(g.LatDMS, g.LatRef)
		}
		if len(g.LonDMS) > 0 {
			g.LonRaw = formatDMS(g.LonDMS, g.LonRef)
		}
		m.warn(lim, "the GPS block holds only one of latitude and longitude, or a hemisphere reference "+
			"is missing; no coordinate was derived and none was assumed")
	}

	if g.AltitudeRational != nil {
		if v, ok := g.AltitudeRational.Float(); ok {
			if g.AltitudeRef == "below sea level" {
				v = -v
			}
			g.Altitude = &v
		}
	}

	if g.DateStampRaw != "" && g.TimeStampRaw != "" {
		// GPS date and time are UTC by specification -- the one EXIF
		// time that is an absolute instant rather than a wall-clock
		// reading.
		if ts, err := time.Parse("2006:01:02 15:04:05", g.DateStampRaw+" "+g.TimeStampRaw); err == nil {
			g.TimeStamp = ts.UTC()
		}
	}

	m.GPS = g
}

// decodeUndefinedText reads a GPS UNDEFINED value that carries a
// character-code prefix ("ASCII\0\0\0", "UNICODE\0", ...). Only the ASCII
// form is decoded; anything else is reported by its prefix rather than
// mis-decoded into mojibake.
func decodeUndefinedText(e entry) string {
	if !e.ok || len(e.value) < 8 {
		return ""
	}
	prefix := strings.TrimRight(string(e.value[:8]), "\x00")
	body := e.value[8:]
	if strings.EqualFold(prefix, "ASCII") {
		if i := indexByte(body, 0); i >= 0 {
			body = body[:i]
		}
		return strings.TrimSpace(string(body))
	}
	if prefix == "" {
		return ""
	}
	return "(" + prefix + "-encoded value, not decoded)"
}

// dmsToDecimal converts EXIF's three rational components to signed
// decimal degrees. It returns false unless BOTH a full component triple
// and a valid hemisphere reference are present: a coordinate missing its
// hemisphere is ambiguous by a whole sign, and guessing one would put a
// position on the wrong side of the equator or the meridian.
func dmsToDecimal(dms []Rational, ref, positive, negative string) (float64, bool) {
	if len(dms) != 3 {
		return 0, false
	}
	ref = strings.ToUpper(strings.TrimSpace(ref))
	if ref != positive && ref != negative {
		return 0, false
	}
	deg, ok1 := dms[0].Float()
	min, ok2 := dms[1].Float()
	sec, ok3 := dms[2].Float()
	if !ok1 || !ok2 || !ok3 {
		return 0, false
	}
	v := deg + min/60 + sec/3600
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, false
	}
	if ref == negative {
		v = -v
	}
	return v, true
}

// formatDMS renders the stored components in the sexagesimal form the
// file holds. A component with a denominator other than 1 is shown as the
// fraction it is, so nothing is rounded away in the rendering.
func formatDMS(dms []Rational, ref string) string {
	if len(dms) != 3 {
		return ""
	}
	part := func(r Rational, unit string) string {
		if r.Den == 1 {
			return strconv.FormatInt(r.Num, 10) + unit
		}
		if v, ok := r.Float(); ok {
			return trimFloat(v) + unit + " (" + r.String() + ")"
		}
		return r.String() + unit
	}
	return part(dms[0], "°") + " " + part(dms[1], "'") + " " + part(dms[2], `"`) + " " + ref
}

func formatGPSTime(r []Rational) string {
	if len(r) != 3 {
		return ""
	}
	h, ok1 := r[0].Float()
	m, ok2 := r[1].Float()
	s, ok3 := r[2].Float()
	if !ok1 || !ok2 || !ok3 {
		return ""
	}
	return strconv.Itoa(int(h)) + ":" + pad2(int(m)) + ":" + pad2(int(s))
}

func pad2(v int) string {
	if v < 10 && v >= 0 {
		return "0" + strconv.Itoa(v)
	}
	return strconv.Itoa(v)
}

// granularity reports the finest unit the stored components actually
// resolve.
//
// This is computed from the components, not assumed: a coordinate written
// as 16°/1 0°/1 0°/1 names a whole degree and nothing finer, and any
// conclusion drawn from it -- including which country contains it --
// inherits that uncertainty. Reporting the derived decimal without
// reporting this would make a ±55 km position look like a ±1 m one.
func granularity(lat, lon []Rational) (string, float64, string) {
	if len(lat) != 3 || len(lon) != 3 {
		return "", 0, ""
	}
	nonZero := func(r Rational) bool { return r.Num != 0 }
	fractional := func(r Rational) bool { return r.Den > 1 && r.Num%r.Den != 0 }

	finest := "degree"
	for _, set := range [][]Rational{lat, lon} {
		if fractional(set[2]) {
			finest = "sub-second"
			break
		}
		if nonZero(set[2]) {
			if finest == "degree" || finest == "arcminute" {
				finest = "arcsecond"
			}
			continue
		}
		if nonZero(set[1]) || fractional(set[1]) {
			if finest == "degree" {
				finest = "arcminute"
			}
		}
	}

	// One degree of latitude is ~111 km; an arcminute ~1.85 km; an
	// arcsecond ~31 m. Longitude spacing shrinks with latitude, so these
	// are the upper bound, which is the safe direction for a caveat.
	var km float64
	switch finest {
	case "degree":
		km = 111
	case "arcminute":
		km = 1.85
	case "arcsecond":
		km = 0.031
	default:
		return finest, 0, "the coordinate is stored to finer than one arcsecond"
	}

	note := "the stored components resolve no finer than one " + finest +
		", so this coordinate locates a point to within roughly " + trimFloat(km) + " km. " +
		"This is a property of what the image recorded, not of the conversion"
	if finest == "degree" {
		note += ". Whole-degree minutes and seconds mean either that the writer rounded the position " +
			"or that it genuinely fell on the degree line; the image does not say which"
	}
	return finest, km, note
}

func trimFloat(v float64) string {
	s := strconv.FormatFloat(v, 'f', -1, 64)
	return s
}

// addTime records an EXIF datetime with the meaning of that specific tag.
func (m *Metadata) addTime(tag, raw, meaning string) {
	m.addTimeWithOffset(tag, raw, "", meaning)
}

func (m *Metadata) addTimeWithOffset(tag, raw, offset, meaning string) {
	if raw == "" {
		return
	}
	ts := Timestamp{Tag: tag, Raw: raw, Meaning: meaning, Offset: offset}
	// EXIF's datetime format. A value that does not match is kept as the
	// literal it is, with no time -- rather than being coerced into one.
	if t, err := time.Parse("2006:01:02 15:04:05", strings.TrimSpace(raw)); err == nil {
		if offset != "" {
			if withZone, err := time.Parse("2006:01:02 15:04:05-07:00", strings.TrimSpace(raw)+offset); err == nil {
				ts.Time = withZone.UTC()
				ts.HasZone = true
				m.Times = append(m.Times, ts)
				return
			}
		}
		// No zone was recorded. The digits are kept exactly as written
		// and carried as UTC so they can be ordered, but HasZone stays
		// false and the parser above states that this is a wall-clock
		// reading rather than an absolute instant.
		ts.Time = t.UTC()
	}
	m.Times = append(m.Times, ts)
}

// attachOffsets fills in the zone-absent explanation once every time has
// been collected.
func (m *Metadata) attachOffsets() {
	for i := range m.Times {
		if m.Times[i].HasZone {
			continue
		}
		m.Times[i].Meaning += ". No UTC offset is recorded for it (the image carries no OffsetTime tag), " +
			"so it is a wall-clock reading from the writing device's clock and not a point in absolute time"
	}
}

// applyThumbnailIFD reads IFD1, the directory describing the thumbnail
// image most cameras embed alongside the full-size one.
//
// Only its LOCATION is recorded, never its bytes. The thumbnail is a
// display concern and is read on demand straight out of the evidence
// file by byte range (see EmbeddedThumbnail), so parsing a collection of
// photographs does not carry a few kilobytes of picture per image
// through the whole pipeline -- and so a thumbnail served to a browser
// is provably the bytes that are in the evidence, at a byte range the
// record names.
func (m *Metadata) applyThumbnailIFD(t tiffReader, entries []entry, lim Limits) {
	var off, length, width, height, compression int
	for _, e := range entries {
		v, ok := t.int(e)
		if !ok {
			continue
		}
		switch e.tag {
		case tagJPEGIFOffset:
			off = v
		case tagJPEGIFByteCount:
			length = v
		case tagThumbnailWidth:
			width = v
		case tagThumbnailHeight:
			height = v
		case tagCompression:
			compression = v
		}
	}
	if off <= 0 || length <= 0 {
		return
	}
	// Compression 6 is "JPEG (old-style)", which is what a JPEG-encoded
	// EXIF thumbnail carries. An uncompressed (compression 1) thumbnail
	// is raw strips, not a servable image, and is not claimed as one.
	// A directory that states no compression at all is accepted only if
	// the bytes actually start with a JPEG marker, checked below.
	if compression != 0 && compression != 6 && compression != 7 {
		return
	}
	if off+length > len(t.data) {
		m.warn(lim, "the EXIF thumbnail's declared byte range lies outside the EXIF block; "+
			"no thumbnail location was recorded")
		return
	}
	if !Sniff(t.data[off : off+length]) {
		return
	}

	m.ThumbnailOffset = off
	m.ThumbnailLength = length
	m.ThumbnailWidth = width
	m.ThumbnailHeight = height
}
