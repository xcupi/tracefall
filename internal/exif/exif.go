// Package exif reads image metadata out of JPEG evidence without
// decoding the image.
//
// # What this reads, and what it deliberately does not
//
// A JPEG is a sequence of marker segments followed by entropy-coded
// pixel data. Everything this package needs -- the EXIF APP1 segment and
// the frame header that states the image's dimensions -- sits in the
// marker segments, so parsing stops at the start-of-scan marker and the
// pixel data is never read, let alone decompressed. A 9 MB photograph
// costs a few kilobytes of I/O here.
//
// # What an EXIF record asserts
//
// That the software which wrote the file recorded these values. Nothing
// more. EXIF is ordinary file content: a camera writes it, and so does
// any editor, exporter, messaging app or forger downstream. A Make and
// Model identify the device that CLAIMED to produce the image; a GPS
// coordinate is a position the writer recorded, not an observation
// Tracefall made. Every field this package returns is reported as an
// EXIF claim, and the parser above it says so on every event.
//
// # Timestamps
//
// EXIF holds several times with genuinely different meanings, and this
// package keeps them apart and labelled rather than collapsing them into
// one "image time". None of them is a filesystem timestamp, and this
// package never reads one: a file's mtime describes the file as it was
// collected, which is a different fact about a different object.
//
// Most EXIF times carry NO timezone. They are wall-clock readings from
// the writing device's own clock. Where EXIF 2.31's OffsetTime tags are
// present the zone is recorded and reported; where they are absent that
// absence is reported too, rather than a zone being assumed.
package exif

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"
)

// Limits bound what one image may cost to read. They exist because an
// image is attacker-supplied data: every one of them is a cap on work
// driven by a number inside the file.
type Limits struct {
	MaxEXIFBytes   int // maximum APP1 payload read into memory
	MaxIFDEntries  int // maximum directory entries decoded from one IFD
	MaxIFDs        int // maximum image file directories visited in total
	MaxStringBytes int // maximum bytes taken from one ASCII value
	MaxRationals   int // maximum rational components read from one value
	MaxMarkerScan  int // maximum marker segments walked before giving up
	MaxWarnings    int // maximum warnings retained
}

// DefaultLimits are far above any real camera output: a large EXIF block
// from a phone is tens of kilobytes and holds a few dozen tags.
func DefaultLimits() Limits {
	return Limits{
		MaxEXIFBytes:   1 << 20,
		MaxIFDEntries:  512,
		MaxIFDs:        16,
		MaxStringBytes: 4096,
		MaxRationals:   64,
		MaxMarkerScan:  1024,
		MaxWarnings:    64,
	}
}

// ErrNotJPEG reports that the file is not a JPEG. It is distinct from a
// parse failure on purpose: "this is not an image" and "this image is
// damaged" are different findings about different evidence.
var ErrNotJPEG = errors.New("exif: not a JPEG image")

// Rational is one EXIF RATIONAL or SRATIONAL value, kept as the numerator
// and denominator the file actually stored. The original pair is retained
// alongside every derived decimal so a conversion can always be checked
// against what was written.
type Rational struct {
	Num int64
	Den int64
}

// Float returns the value as a float64, and whether it is defined. A zero
// denominator is not an error in EXIF -- cameras write 0/0 for "no value"
// -- so it is reported as undefined rather than as a failure.
func (r Rational) Float() (float64, bool) {
	if r.Den == 0 {
		return 0, false
	}
	return float64(r.Num) / float64(r.Den), true
}

// String renders the stored pair, never the quotient: "23/1" is what the
// file holds and "23" is an interpretation of it.
func (r Rational) String() string {
	return strconv.FormatInt(r.Num, 10) + "/" + strconv.FormatInt(r.Den, 10)
}

// Timestamp is one EXIF time with its meaning attached.
type Timestamp struct {
	Tag     string    // the EXIF tag name, e.g. "DateTimeOriginal"
	Meaning string    // what this particular time means, in full
	Raw     string    // the literal as stored, e.g. "2021:04:29 15:20:43"
	Time    time.Time // parsed value; zero when the literal was not a valid EXIF datetime
	Offset  string    // the OffsetTime* value for this tag, when the image recorded one
	// HasZone reports whether the image stated this time's UTC offset.
	// When false, Time carries the wall-clock digits as written and is
	// NOT a point in absolute time.
	HasZone bool
}

// GPS is the decoded GPS IFD.
type GPS struct {
	// Present reports that a GPS IFD existed. It does NOT mean a
	// coordinate was recorded: a GPS block holding only a version tag is
	// common, and is reported as present with Decoded false.
	Present bool
	// Decoded reports that a latitude AND a longitude were both read and
	// converted. Only then are Lat/Lon meaningful.
	Decoded bool

	LatRef string // "N" or "S", exactly as stored
	LonRef string // "E" or "W", exactly as stored

	// LatDMS/LonDMS are the three RATIONAL components EXIF actually
	// stores -- degrees, minutes, seconds -- kept unconverted.
	LatDMS []Rational
	LonDMS []Rational

	// LatRaw/LonRaw render the stored components in their original
	// sexagesimal form, e.g. `16° 0' 0" S`, so the decimal below can
	// always be traced back to what the file said.
	LatRaw string
	LonRaw string

	// Lat/Lon are DERIVED: degrees + minutes/60 + seconds/3600, signed by
	// the hemisphere reference. They are not stored in the image.
	Lat float64
	Lon float64

	// Method names how Lat/Lon were obtained, so the derivation is part
	// of the record rather than an assumption about it.
	Method string

	// Granularity describes the finest unit the stored components
	// actually resolve, computed from the components themselves. A
	// coordinate written as whole degrees locates a point no better than
	// the degree it names, and a country determination made from it
	// inherits that uncertainty.
	Granularity     string
	GranularityKm   float64
	GranularityNote string

	AltitudeRational *Rational
	Altitude         *float64 // metres; sign applied from GPSAltitudeRef
	AltitudeRef      string   // "above sea level" | "below sea level" | raw value when undocumented

	// TimeStamp is the GPS fix time. Unlike every other EXIF time this
	// one IS in UTC by specification, and it is kept separate for that
	// reason. It is set only when both GPSDateStamp and GPSTimeStamp
	// were present and valid.
	TimeStamp    time.Time
	TimeStampRaw string
	DateStampRaw string

	ImgDirection     *float64
	ImgDirectionRef  string
	MapDatum         string
	ProcessingMethod string

	VersionID string
}

// Metadata is everything read from one image file.
type Metadata struct {
	Format string // "jpeg"

	// Width/Height come from the JPEG frame header -- the image's actual
	// stored dimensions. EXIFWidth/EXIFHeight are the PixelXDimension and
	// PixelYDimension tags, which are what the writer CLAIMED. They are
	// kept apart because a disagreement between them is itself worth
	// seeing.
	Width, Height         int
	EXIFWidth, EXIFHeight int

	HasEXIF   bool
	ByteOrder string // "little-endian (II)" or "big-endian (MM)"

	Make            string
	Model           string
	Software        string
	BodySerial      string
	LensModel       string
	Orientation     int
	OrientationName string

	ExposureTime *Rational
	FNumber      *Rational
	FocalLength  *Rational
	ISO          int

	Times []Timestamp
	GPS   GPS

	// EXIFOffset is the offset IN THE FILE of the TIFF block inside the
	// APP1 EXIF segment, so any value here can be traced to a byte range
	// in the evidence.
	EXIFOffset int64

	// Thumbnail* locate the thumbnail image a camera embeds in IFD1.
	// ThumbnailOffset is relative to the TIFF block, so the thumbnail's
	// position in the FILE is EXIFOffset + ThumbnailOffset. The bytes
	// themselves are deliberately NOT held here: they are read on demand
	// (see EmbeddedThumbnail) rather than carried through parsing.
	//
	// ThumbnailLength of 0 means this image embeds no usable thumbnail,
	// which is common for edited and exported images.
	ThumbnailOffset int
	ThumbnailLength int
	ThumbnailWidth  int
	ThumbnailHeight int

	Warnings []string
}

// Time returns the timestamp recorded for tag, and whether it exists.
func (m Metadata) Time(tag string) (Timestamp, bool) {
	for _, t := range m.Times {
		if t.Tag == tag {
			return t, true
		}
	}
	return Timestamp{}, false
}

// Sniff reports whether header begins with the JPEG start-of-image
// marker followed by another marker.
//
// FF D8 alone is two bytes and appears by chance; requiring the FF that
// opens the next segment is the cheapest check that is actually
// structural. Detection is content-only: an extension is not evidence,
// and a JPEG carried out of a triage image may arrive under any name.
func Sniff(header []byte) bool {
	return len(header) >= 3 && header[0] == 0xFF && header[1] == 0xD8 && header[2] == 0xFF
}

// ParseFile reads absPath's marker segments.
//
// It never returns a partially-invented Metadata: a value that could not
// be read is absent, not defaulted. A truncated or malformed image yields
// whatever was decoded before the damage, with the damage recorded in
// Warnings -- an incomplete artifact is partial evidence, and reporting
// nothing would lose the part that was intact.
func ParseFile(absPath string, lim Limits) (Metadata, error) {
	f, err := os.Open(absPath)
	if err != nil {
		return Metadata{}, err
	}
	defer f.Close()
	return Parse(f, lim)
}

// Parse reads JPEG marker segments from r. r is read strictly forward and
// never fully buffered.
func Parse(r io.Reader, lim Limits) (Metadata, error) {
	br := bufio.NewReaderSize(r, 64<<10)

	soi := make([]byte, 2)
	if _, err := io.ReadFull(br, soi); err != nil {
		return Metadata{}, ErrNotJPEG
	}
	if soi[0] != 0xFF || soi[1] != 0xD8 {
		return Metadata{}, ErrNotJPEG
	}

	m := Metadata{Format: "jpeg"}
	offset := int64(2)

	for seg := 0; ; seg++ {
		if lim.MaxMarkerScan > 0 && seg >= lim.MaxMarkerScan {
			m.warn(lim, "stopped after "+strconv.Itoa(lim.MaxMarkerScan)+
				" marker segments: the file declares more than this build walks")
			break
		}

		marker, consumed, err := nextMarker(br)
		offset += consumed
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				return m, err
			}
			m.warn(lim, "the file ended while looking for the next JPEG marker at byte offset "+
				strconv.FormatInt(offset, 10)+": everything decoded before this point is reported")
			break
		}

		// SOS begins entropy-coded pixel data and EOI ends the image.
		// Both are where reading stops: no marker segment this package
		// cares about follows, and stepping into the scan would mean
		// reading the picture.
		if marker == 0xDA || marker == 0xD9 {
			break
		}
		// Standalone markers carry no length field.
		if marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7) {
			continue
		}

		var lenBuf [2]byte
		if _, err := io.ReadFull(br, lenBuf[:]); err != nil {
			m.warn(lim, "the file ended inside the length field of marker 0x"+
				strconv.FormatUint(uint64(marker), 16)+" at byte offset "+strconv.FormatInt(offset, 10))
			break
		}
		segLen := int(binary.BigEndian.Uint16(lenBuf[:]))
		offset += 2
		if segLen < 2 {
			m.warn(lim, "marker 0x"+strconv.FormatUint(uint64(marker), 16)+" at byte offset "+
				strconv.FormatInt(offset, 10)+" declares an impossible segment length of "+
				strconv.Itoa(segLen)+"; parsing stops here")
			break
		}
		payloadLen := segLen - 2

		switch {
		case marker == 0xE1 && !m.HasEXIF:
			consumedPayload, err := m.readAPP1(br, payloadLen, offset, lim)
			offset += consumedPayload
			if err != nil {
				m.warn(lim, "the EXIF segment at byte offset "+strconv.FormatInt(offset, 10)+
					" could not be read: "+err.Error())
			}
		case isFrameHeader(marker):
			consumedPayload, err := m.readFrameHeader(br, payloadLen, lim)
			offset += consumedPayload
			if err != nil {
				m.warn(lim, "the frame header at byte offset "+strconv.FormatInt(offset, 10)+
					" could not be read: "+err.Error())
			}
		default:
			n, err := discard(br, payloadLen)
			offset += n
			if err != nil {
				m.warn(lim, "the file ended inside marker 0x"+strconv.FormatUint(uint64(marker), 16)+
					" at byte offset "+strconv.FormatInt(offset, 10))
				return m, nil
			}
		}
	}

	return m, nil
}

// nextMarker reads forward to the next marker byte, tolerating the fill
// bytes the JPEG specification permits between segments.
func nextMarker(br *bufio.Reader) (byte, int64, error) {
	var consumed int64
	// Find the 0xFF that introduces the marker.
	for {
		b, err := br.ReadByte()
		if err != nil {
			return 0, consumed, err
		}
		consumed++
		if b == 0xFF {
			break
		}
	}
	// Any number of 0xFF fill bytes may precede the marker code.
	for {
		b, err := br.ReadByte()
		if err != nil {
			return 0, consumed, err
		}
		consumed++
		if b != 0xFF {
			return b, consumed, nil
		}
	}
}

// isFrameHeader reports whether marker is a start-of-frame carrying the
// image's dimensions. C4 (Huffman tables), C8 (reserved) and CC
// (arithmetic coding conditioning) share the range and are not frames.
func isFrameHeader(marker byte) bool {
	if marker < 0xC0 || marker > 0xCF {
		return false
	}
	switch marker {
	case 0xC4, 0xC8, 0xCC:
		return false
	}
	return true
}

// readFrameHeader takes the image's true dimensions from the frame
// header. This reads five bytes of header; it does not decode the frame.
func (m *Metadata) readFrameHeader(br *bufio.Reader, payloadLen int, lim Limits) (int64, error) {
	if payloadLen < 5 {
		if n, err := discard(br, payloadLen); err != nil {
			return n, err
		}
		return int64(payloadLen), errors.New("frame header is shorter than its fixed fields")
	}
	head := make([]byte, 5)
	if _, err := io.ReadFull(br, head); err != nil {
		return 0, err
	}
	// Only the FIRST frame header seen sets the dimensions; a progressive
	// JPEG carries several and the first is the image.
	if m.Height == 0 && m.Width == 0 {
		m.Height = int(binary.BigEndian.Uint16(head[1:3]))
		m.Width = int(binary.BigEndian.Uint16(head[3:5]))
	}
	n, err := discard(br, payloadLen-5)
	return int64(5) + n, err
}

// readAPP1 reads an APP1 segment and, if it is the EXIF one, decodes it.
func (m *Metadata) readAPP1(br *bufio.Reader, payloadLen int, offset int64, lim Limits) (int64, error) {
	const exifHeader = "Exif\x00\x00"
	if payloadLen < len(exifHeader) {
		n, err := discard(br, payloadLen)
		return n, err
	}
	// APP1 also carries XMP ("http://ns.adobe.com/xap/1.0/\x00"), which
	// is a different format and not claimed here.
	head := make([]byte, len(exifHeader))
	if _, err := io.ReadFull(br, head); err != nil {
		return 0, err
	}
	if string(head) != exifHeader {
		n, err := discard(br, payloadLen-len(head))
		return int64(len(head)) + n, err
	}

	tiffLen := payloadLen - len(exifHeader)
	read := tiffLen
	if lim.MaxEXIFBytes > 0 && read > lim.MaxEXIFBytes {
		read = lim.MaxEXIFBytes
		m.warn(lim, "the EXIF block is "+strconv.Itoa(tiffLen)+" bytes; only the first "+
			strconv.Itoa(read)+" were read")
	}
	tiff := make([]byte, read)
	if _, err := io.ReadFull(br, tiff); err != nil {
		// A truncated EXIF block is still worth decoding as far as it
		// goes, so what was read is kept rather than discarded.
		m.warn(lim, "the EXIF block ends before the length its segment declares; "+
			"it was read as far as the file allows")
	}
	skipped, _ := discard(br, tiffLen-read)

	m.HasEXIF = true
	m.EXIFOffset = offset + int64(len(exifHeader))
	m.decodeTIFF(tiff, lim)
	return int64(len(head)) + int64(read) + skipped, nil
}

func discard(br *bufio.Reader, n int) (int64, error) {
	if n <= 0 {
		return 0, nil
	}
	got, err := br.Discard(n)
	return int64(got), err
}

func (m *Metadata) warn(lim Limits, msg string) {
	if lim.MaxWarnings > 0 && len(m.Warnings) >= lim.MaxWarnings {
		return
	}
	m.Warnings = append(m.Warnings, msg)
}

// EmbeddedThumbnail returns the JPEG thumbnail a camera stored inside
// absPath's EXIF block, or ok=false when the image embeds none.
//
// It reads the thumbnail's bytes STRAIGHT OUT OF THE EVIDENCE FILE at
// the byte range IFD1 names, and returns them unchanged. Nothing is
// decoded, scaled or re-encoded, so what a viewer displays is literally
// a range of bytes present in the evidence -- and the returned offset
// and length say which range, so the claim can be checked.
//
// The file is opened read-only and is never modified.
func EmbeddedThumbnail(absPath string, lim Limits) (jpeg []byte, offset int64, ok bool, err error) {
	m, err := ParseFile(absPath, lim)
	if err != nil {
		return nil, 0, false, err
	}
	if m.ThumbnailLength <= 0 {
		return nil, 0, false, nil
	}

	at := m.EXIFOffset + int64(m.ThumbnailOffset)
	f, err := os.Open(absPath)
	if err != nil {
		return nil, 0, false, err
	}
	defer f.Close()

	buf := make([]byte, m.ThumbnailLength)
	if _, err := f.ReadAt(buf, at); err != nil {
		return nil, 0, false, fmt.Errorf("exif: reading the embedded thumbnail at byte %d: %w", at, err)
	}
	if !Sniff(buf) {
		// The directory pointed somewhere that is not a JPEG. Reporting
		// "no thumbnail" is correct; returning the bytes anyway would
		// hand a viewer whatever happened to be at that offset.
		return nil, 0, false, nil
	}
	return buf, at, true, nil
}
