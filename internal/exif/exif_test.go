package exif_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tracefall/internal/exif"
	"tracefall/internal/exif/exifgen"
)

func parse(t *testing.T, data []byte) exif.Metadata {
	t.Helper()
	m, err := exif.Parse(bytes.NewReader(data), exif.DefaultLimits())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return m
}

// photo is a JPEG shaped like real phone output: a camera, a full set of
// times, and a southern/eastern coordinate.
func photo() exifgen.Spec {
	return exifgen.Spec{
		Width: 4160, Height: 3120,
		PixelXDim: 4160, PixelYDim: 3120,
		Make: "LG Electronics", Model: "LM-Q725K",
		Software:          "GIMP 2.10.18",
		DateTime:          "2021:04:29 15:33:32",
		DateTimeOriginal:  "2021:04:29 15:20:43",
		DateTimeDigitized: "2021:04:29 15:20:43",
		Orientation:       6,
		GPS: &exifgen.GPS{
			LatRef: "S", Lat: exifgen.DMS(16, 0, 0),
			LonRef: "E", Lon: exifgen.DMS(23, 0, 0),
		},
	}
}

func TestParse_JPEGWithEXIF(t *testing.T) {
	m := parse(t, exifgen.Build(photo()))

	if !m.HasEXIF {
		t.Fatal("HasEXIF = false")
	}
	if m.Format != "jpeg" {
		t.Errorf("Format = %q", m.Format)
	}
	if m.Width != 4160 || m.Height != 3120 {
		t.Errorf("dimensions = %dx%d, want 4160x3120", m.Width, m.Height)
	}
	if m.EXIFWidth != 4160 || m.EXIFHeight != 3120 {
		t.Errorf("EXIF dimensions = %dx%d", m.EXIFWidth, m.EXIFHeight)
	}
	if m.Make != "LG Electronics" || m.Model != "LM-Q725K" {
		t.Errorf("make/model = %q / %q", m.Make, m.Model)
	}
	if m.Software != "GIMP 2.10.18" {
		t.Errorf("Software = %q", m.Software)
	}
	if m.Orientation != 6 || m.OrientationName != "rotated 90° clockwise" {
		t.Errorf("orientation = %d / %q", m.Orientation, m.OrientationName)
	}
	if m.ByteOrder != "little-endian (II)" {
		t.Errorf("ByteOrder = %q", m.ByteOrder)
	}
}

func TestParse_JPEGWithoutEXIFIsStillAnImage(t *testing.T) {
	m := parse(t, exifgen.Build(exifgen.Spec{Width: 800, Height: 600, NoEXIF: true}))

	if m.HasEXIF {
		t.Error("HasEXIF = true for an image with no APP1 segment")
	}
	if m.Format != "jpeg" {
		t.Errorf("Format = %q; the file is still an image", m.Format)
	}
	if m.Width != 800 || m.Height != 600 {
		t.Errorf("dimensions = %dx%d; the frame header is readable without EXIF", m.Width, m.Height)
	}
	if m.GPS.Present {
		t.Error("GPS.Present = true for an image with no EXIF")
	}
	if len(m.Times) != 0 {
		t.Errorf("got %d timestamps from an image with no EXIF", len(m.Times))
	}
}

func TestParse_BigEndianEXIF(t *testing.T) {
	spec := photo()
	spec.BigEndian = true
	m := parse(t, exifgen.Build(spec))

	if m.ByteOrder != "big-endian (MM)" {
		t.Errorf("ByteOrder = %q", m.ByteOrder)
	}
	if m.Make != "LG Electronics" {
		t.Errorf("Make = %q; big-endian values must decode identically", m.Make)
	}
	if !m.GPS.Decoded || m.GPS.Lat != -16 || m.GPS.Lon != 23 {
		t.Errorf("GPS = %+v", m.GPS)
	}
}

// ---------------- GPS ----------------

func TestGPS_SouthernAndEasternHemisphere(t *testing.T) {
	m := parse(t, exifgen.Build(photo()))
	g := m.GPS

	if !g.Present || !g.Decoded {
		t.Fatalf("GPS present=%v decoded=%v", g.Present, g.Decoded)
	}
	if g.Lat != -16 {
		t.Errorf("Lat = %v, want -16 (S must negate)", g.Lat)
	}
	if g.Lon != 23 {
		t.Errorf("Lon = %v, want 23 (E stays positive)", g.Lon)
	}
	if g.LatRaw != `16° 0' 0" S` {
		t.Errorf("LatRaw = %q", g.LatRaw)
	}
	if g.LonRaw != `23° 0' 0" E` {
		t.Errorf("LonRaw = %q", g.LonRaw)
	}
	// The stored components must survive alongside the derived decimal.
	if len(g.LatDMS) != 3 || g.LatDMS[0].Num != 16 || g.LatDMS[0].Den != 1 {
		t.Errorf("LatDMS = %+v; the original rationals must be preserved", g.LatDMS)
	}
	if !strings.Contains(g.Method, "RATIONAL") {
		t.Errorf("Method = %q; the derivation must be stated", g.Method)
	}
}

func TestGPS_NorthernAndWesternHemisphere(t *testing.T) {
	spec := photo()
	spec.GPS = &exifgen.GPS{
		LatRef: "N", Lat: exifgen.DMS(40, 41, 21),
		LonRef: "W", Lon: exifgen.DMS(74, 2, 40),
	}
	g := parse(t, exifgen.Build(spec)).GPS

	wantLat := 40 + 41.0/60 + 21.0/3600
	wantLon := -(74 + 2.0/60 + 40.0/3600)
	if math.Abs(g.Lat-wantLat) > 1e-9 {
		t.Errorf("Lat = %v, want %v", g.Lat, wantLat)
	}
	if math.Abs(g.Lon-wantLon) > 1e-9 {
		t.Errorf("Lon = %v, want %v (W must negate)", g.Lon, wantLon)
	}
	if g.Lon >= 0 {
		t.Error("a western longitude must be negative")
	}
}

func TestGPS_FractionalSecondsArePreservedNotRounded(t *testing.T) {
	spec := photo()
	// 34° 12' 15.2" S -- the example from the requirement.
	spec.GPS = &exifgen.GPS{
		LatRef: "S", Lat: exifgen.DMSFrac(34, 12, 152, 10),
		LonRef: "E", Lon: exifgen.DMS(18, 25, 30),
	}
	g := parse(t, exifgen.Build(spec)).GPS

	want := -(34 + 12.0/60 + 15.2/3600)
	if math.Abs(g.Lat-want) > 1e-12 {
		t.Errorf("Lat = %.12f, want %.12f", g.Lat, want)
	}
	// The raw rendering must remain traceable to the derived decimal:
	// the stored fraction is shown, not a rounded reading of it.
	if !strings.Contains(g.LatRaw, "152/10") {
		t.Errorf("LatRaw = %q; the stored fraction must be visible", g.LatRaw)
	}
	if g.LatDMS[2].Num != 152 || g.LatDMS[2].Den != 10 {
		t.Errorf("seconds component = %+v, want 152/10", g.LatDMS[2])
	}
	if g.Granularity != "sub-second" {
		t.Errorf("Granularity = %q, want sub-second", g.Granularity)
	}
}

// Whole-degree components locate a point no better than the degree they
// name, and the record must say so rather than presenting a ±55 km
// position as an exact one.
func TestGPS_WholeDegreeGranularityIsReported(t *testing.T) {
	g := parse(t, exifgen.Build(photo())).GPS

	if g.Granularity != "degree" {
		t.Errorf("Granularity = %q, want degree", g.Granularity)
	}
	if g.GranularityKm < 100 {
		t.Errorf("GranularityKm = %v; a whole degree is about 111 km", g.GranularityKm)
	}
	if !strings.Contains(g.GranularityNote, "degree") {
		t.Errorf("GranularityNote = %q", g.GranularityNote)
	}
}

func TestGPS_ArcsecondGranularity(t *testing.T) {
	spec := photo()
	spec.GPS = &exifgen.GPS{
		LatRef: "S", Lat: exifgen.DMS(17, 55, 28),
		LonRef: "E", Lon: exifgen.DMS(25, 51, 24),
	}
	if got := parse(t, exifgen.Build(spec)).GPS.Granularity; got != "arcsecond" {
		t.Errorf("Granularity = %q, want arcsecond", got)
	}
}

func TestGPS_MissingBlockIsNotAnEmptyCoordinate(t *testing.T) {
	spec := photo()
	spec.GPS = nil
	g := parse(t, exifgen.Build(spec)).GPS

	if g.Present {
		t.Error("GPS.Present = true when no GPS IFD exists")
	}
	if g.Decoded {
		t.Error("GPS.Decoded = true with no GPS block")
	}
	if g.Lat != 0 || g.Lon != 0 {
		t.Errorf("a missing GPS block yielded %v,%v", g.Lat, g.Lon)
	}
}

// A GPS block holding only a version tag is common. It is present, and
// it is not a position -- 0,0 must never be reported as one.
func TestGPS_VersionOnlyBlockIsPresentButNotDecoded(t *testing.T) {
	spec := photo()
	spec.GPS = &exifgen.GPS{VersionOnly: true}
	g := parse(t, exifgen.Build(spec)).GPS

	if !g.Present {
		t.Error("GPS.Present = false; the block exists")
	}
	if g.Decoded {
		t.Error("GPS.Decoded = true for a block with no coordinate -- that would report 0,0 as a position")
	}
}

// A hemisphere reference is worth a whole sign. Guessing one would put a
// position on the wrong side of the equator.
func TestGPS_MissingHemisphereRefIsNotGuessed(t *testing.T) {
	spec := photo()
	spec.GPS = &exifgen.GPS{
		Lat:    exifgen.DMS(16, 0, 0), // no LatRef
		LonRef: "E", Lon: exifgen.DMS(23, 0, 0),
	}
	m := parse(t, exifgen.Build(spec))

	if m.GPS.Decoded {
		t.Error("a coordinate with no GPSLatitudeRef was decoded; the sign would be a guess")
	}
	if len(m.Warnings) == 0 {
		t.Error("the incomplete coordinate must be reported in Warnings")
	}
}

func TestGPS_LatitudeWithoutLongitudeIsNotHalfUsed(t *testing.T) {
	spec := photo()
	spec.GPS = &exifgen.GPS{LatRef: "S", Lat: exifgen.DMS(16, 0, 0), OmitLon: true}
	m := parse(t, exifgen.Build(spec))

	if m.GPS.Decoded {
		t.Error("a latitude with no longitude was decoded as a position")
	}
	if m.GPS.LatRaw == "" {
		t.Error("the latitude that WAS stored should still be reported")
	}
}

func TestGPS_ZeroDenominatorIsUndefinedNotZero(t *testing.T) {
	spec := photo()
	spec.GPS = &exifgen.GPS{
		LatRef: "S", Lat: [3][2]uint32{{16, 1}, {0, 0}, {0, 1}},
		LonRef: "E", Lon: exifgen.DMS(23, 0, 0),
	}
	m := parse(t, exifgen.Build(spec))
	if m.GPS.Decoded {
		t.Error("a component with a zero denominator was treated as a value")
	}
}

func TestGPS_AltitudeAndFixTime(t *testing.T) {
	spec := photo()
	ref := uint16(0)
	alt := [2]uint32{1350, 10}
	ts := [3][2]uint32{{13, 1}, {20, 1}, {43, 1}}
	spec.GPS = &exifgen.GPS{
		LatRef: "S", Lat: exifgen.DMS(16, 0, 0),
		LonRef: "E", Lon: exifgen.DMS(23, 0, 0),
		AltitudeRef: &ref, Altitude: &alt,
		DateStamp: "2021:04:29", TimeStamp: &ts,
		MapDatum: "WGS-84",
	}
	g := parse(t, exifgen.Build(spec)).GPS

	if g.Altitude == nil || math.Abs(*g.Altitude-135) > 1e-9 {
		t.Errorf("Altitude = %v, want 135", g.Altitude)
	}
	if g.AltitudeRef != "above sea level" {
		t.Errorf("AltitudeRef = %q", g.AltitudeRef)
	}
	if g.TimeStamp.IsZero() {
		t.Fatal("GPS fix time was not decoded")
	}
	if got := g.TimeStamp.Format("2006-01-02T15:04:05Z"); got != "2021-04-29T13:20:43Z" {
		t.Errorf("fix time = %s", got)
	}
	if g.MapDatum != "WGS-84" {
		t.Errorf("MapDatum = %q", g.MapDatum)
	}
}

func TestGPS_BelowSeaLevelAltitudeIsNegative(t *testing.T) {
	spec := photo()
	ref := uint16(1)
	alt := [2]uint32{420, 1}
	spec.GPS = &exifgen.GPS{
		LatRef: "N", Lat: exifgen.DMS(31, 30, 0),
		LonRef: "E", Lon: exifgen.DMS(35, 29, 0),
		AltitudeRef: &ref, Altitude: &alt,
	}
	g := parse(t, exifgen.Build(spec)).GPS
	if g.Altitude == nil || *g.Altitude != -420 {
		t.Errorf("Altitude = %v, want -420", g.Altitude)
	}
}

// ---------------- Timestamps ----------------

func TestTimes_EachCarriesItsOwnMeaning(t *testing.T) {
	m := parse(t, exifgen.Build(photo()))

	dto, ok := m.Time("DateTimeOriginal")
	if !ok {
		t.Fatal("DateTimeOriginal not found")
	}
	if dto.Raw != "2021:04:29 15:20:43" {
		t.Errorf("raw = %q", dto.Raw)
	}
	if got := dto.Time.Format("2006-01-02T15:04:05"); got != "2021-04-29T15:20:43" {
		t.Errorf("parsed = %s", got)
	}
	if !strings.Contains(dto.Meaning, "TAKEN") {
		t.Errorf("DateTimeOriginal meaning = %q", dto.Meaning)
	}
	// The specific misreading this must prevent.
	for _, bad := range []string{"file creation", "creation time", "filesystem"} {
		if strings.Contains(strings.ToLower(dto.Meaning), bad) &&
			!strings.Contains(strings.ToLower(dto.Meaning), "not a "+bad) &&
			!strings.Contains(strings.ToLower(dto.Meaning), "not a file creation") {
			t.Errorf("DateTimeOriginal is described using %q: %s", bad, dto.Meaning)
		}
	}

	mod, ok := m.Time("DateTime")
	if !ok {
		t.Fatal("DateTime (ModifyDate) not found")
	}
	if mod.Raw != "2021:04:29 15:33:32" {
		t.Errorf("DateTime raw = %q", mod.Raw)
	}
	if mod.Meaning == dto.Meaning {
		t.Error("ModifyDate and DateTimeOriginal share a meaning; they are different facts")
	}

	if _, ok := m.Time("DateTimeDigitized"); !ok {
		t.Error("DateTimeDigitized not found")
	}
}

func TestTimes_AbsentZoneIsReportedNotAssumed(t *testing.T) {
	dto, _ := parse(t, exifgen.Build(photo())).Time("DateTimeOriginal")
	if dto.HasZone {
		t.Error("HasZone = true when the image records no OffsetTime tag")
	}
	if !strings.Contains(dto.Meaning, "No UTC offset") {
		t.Errorf("the absent zone must be stated: %q", dto.Meaning)
	}
}

func TestTimes_RecordedZoneIsApplied(t *testing.T) {
	spec := photo()
	spec.OffsetTimeOriginal = "+02:00"
	dto, ok := parse(t, exifgen.Build(spec)).Time("DateTimeOriginal")
	if !ok {
		t.Fatal("DateTimeOriginal not found")
	}
	if !dto.HasZone {
		t.Fatal("HasZone = false when OffsetTimeOriginal is present")
	}
	if got := dto.Time.Format("2006-01-02T15:04:05Z"); got != "2021-04-29T13:20:43Z" {
		t.Errorf("with +02:00 the UTC instant is %s, want 2021-04-29T13:20:43Z", got)
	}
	if dto.Offset != "+02:00" {
		t.Errorf("Offset = %q", dto.Offset)
	}
}

func TestTimes_UnparsableLiteralIsKeptWithNoTime(t *testing.T) {
	spec := photo()
	spec.DateTimeOriginal = "not a timestamp"
	dto, ok := parse(t, exifgen.Build(spec)).Time("DateTimeOriginal")
	if !ok {
		t.Fatal("the tag should still be reported")
	}
	if dto.Raw != "not a timestamp" {
		t.Errorf("Raw = %q; the literal must be preserved", dto.Raw)
	}
	if !dto.Time.IsZero() {
		t.Errorf("Time = %v; an unparsable literal must not be coerced into a time", dto.Time)
	}
}

// ---------------- Detection ----------------

func TestSniff(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want bool
	}{
		{"jpeg", exifgen.Build(photo()), true},
		{"jpeg no exif", exifgen.Build(exifgen.Spec{Width: 1, Height: 1, NoEXIF: true}), true},
		{"empty", nil, false},
		{"two bytes", []byte{0xFF, 0xD8}, false},
		{"png", []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A}, false},
		{"zip", []byte{'P', 'K', 3, 4}, false},
		{"text", []byte("this is not an image at all"), false},
	}
	for _, tt := range tests {
		if got := exif.Sniff(tt.in); got != tt.want {
			t.Errorf("%s: Sniff = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestParse_NonImageIsRefusedAsNotAnImage(t *testing.T) {
	for _, in := range [][]byte{
		[]byte("MZ\x90\x00 this is a PE binary"),
		[]byte("<?xml version=\"1.0\"?><x/>"),
		{},
		{0xFF},
	} {
		_, err := exif.Parse(bytes.NewReader(in), exif.DefaultLimits())
		if !errors.Is(err, exif.ErrNotJPEG) {
			t.Errorf("Parse(%q) err = %v, want ErrNotJPEG", in, err)
		}
	}
}

// A renamed JPEG is still a JPEG: nothing here reads the file's name.
func TestParseFile_RenamedJPEGIsStillRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "invoice.docx")
	if err := os.WriteFile(path, exifgen.Build(photo()), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := exif.ParseFile(path, exif.DefaultLimits())
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if !m.HasEXIF || m.Make != "LG Electronics" {
		t.Errorf("a renamed JPEG was not read: %+v", m)
	}
}

// ---------------- Damage ----------------

func TestParse_TruncationNeverPanicsAndKeepsWhatWasRead(t *testing.T) {
	full := exifgen.Build(photo())
	for cut := 0; cut < len(full); cut++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic at cut %d: %v", cut, r)
				}
			}()
			_, _ = exif.Parse(bytes.NewReader(full[:cut]), exif.DefaultLimits())
		}()
	}
}

func TestParse_MalformedEXIFIsAControlledResult(t *testing.T) {
	cases := []struct {
		name string
		spec exifgen.Spec
	}{
		{"corrupt tiff magic", func() exifgen.Spec { s := photo(); s.CorruptTIFFMagic = true; return s }()},
		{"ifd offset outside block", func() exifgen.Spec { s := photo(); s.BadIFDOffset = true; return s }()},
		{"looping ifd chain", func() exifgen.Spec { s := photo(); s.LoopingIFD = true; return s }()},
		{"truncated exif payload", func() exifgen.Spec { s := photo(); s.TruncateEXIFTo = 40; return s }()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic: %v", r)
				}
			}()
			m, err := exif.Parse(bytes.NewReader(exifgen.Build(tc.spec)), exif.DefaultLimits())
			if err != nil {
				t.Fatalf("malformed EXIF must not fail the whole parse: %v", err)
			}
			if len(m.Warnings) == 0 {
				t.Error("damage must be recorded in Warnings, not swallowed")
			}
			// Whatever else happened, nothing may be invented.
			if m.GPS.Decoded && (m.GPS.Lat == 0 && m.GPS.Lon == 0) {
				t.Error("a 0,0 coordinate was reported as decoded")
			}
		})
	}
}

// Every byte offset in a JPEG is attacker-controlled. Flipping single
// bytes must never panic, whatever it does to the values.
func TestParse_ByteFlipsNeverPanic(t *testing.T) {
	full := exifgen.Build(photo())
	for i := 0; i < len(full); i++ {
		for _, v := range []byte{0x00, 0xFF, 0x7F} {
			mutated := make([]byte, len(full))
			copy(mutated, full)
			mutated[i] = v
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("panic on byte %d set to 0x%02X: %v", i, v, r)
					}
				}()
				_, _ = exif.Parse(bytes.NewReader(mutated), exif.DefaultLimits())
			}()
		}
	}
}

func TestParse_LimitsAreEnforced(t *testing.T) {
	lim := exif.DefaultLimits()
	lim.MaxEXIFBytes = 24
	m, err := exif.Parse(bytes.NewReader(exifgen.Build(photo())), lim)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(m.Warnings) == 0 {
		t.Error("a truncated read must be recorded")
	}
}

func TestParse_IsDeterministic(t *testing.T) {
	data := exifgen.Build(photo())
	first := parse(t, data)
	for i := 0; i < 20; i++ {
		got := parse(t, data)
		if got.Make != first.Make || got.GPS.Lat != first.GPS.Lat || got.GPS.Lon != first.GPS.Lon ||
			len(got.Times) != len(first.Times) || got.GPS.LatRaw != first.GPS.LatRaw {
			t.Fatalf("run %d differs from the first", i)
		}
	}
}

func TestRational(t *testing.T) {
	if v, ok := (exif.Rational{Num: 152, Den: 10}).Float(); !ok || math.Abs(v-15.2) > 1e-12 {
		t.Errorf("Float = %v, %v", v, ok)
	}
	if _, ok := (exif.Rational{Num: 1, Den: 0}).Float(); ok {
		t.Error("a zero denominator must be undefined, not an error and not a value")
	}
	// String renders the STORED pair, never the quotient.
	if got := (exif.Rational{Num: 152, Den: 10}).String(); got != "152/10" {
		t.Errorf("String = %q, want 152/10", got)
	}
}

// The parser must stop at the start-of-scan marker: a 9 MB photograph
// must not cost 9 MB of reads.
func TestParse_StopsBeforeEntropyData(t *testing.T) {
	data := exifgen.Build(photo())
	// Append a large block after EOI. A parser that reads to the end of
	// the file would consume it; one that stops at SOS never sees it.
	padded := append(data, bytes.Repeat([]byte{0xAB}, 4<<20)...)

	counted := &countingReader{r: bytes.NewReader(padded)}
	if _, err := exif.Parse(counted, exif.DefaultLimits()); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if counted.n > 1<<20 {
		t.Errorf("read %d bytes from a %d-byte file; parsing must stop at the scan", counted.n, len(padded))
	}
}

type countingReader struct {
	r *bytes.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// ---------------- Embedded thumbnail (IFD1) ----------------

func TestThumbnail_LocationIsRecordedNotTheBytes(t *testing.T) {
	spec := photo()
	spec.Thumbnail = exifgen.MinimalJPEG()
	data := exifgen.Build(spec)
	m := parse(t, data)

	if m.ThumbnailLength != len(spec.Thumbnail) {
		t.Errorf("ThumbnailLength = %d, want %d", m.ThumbnailLength, len(spec.Thumbnail))
	}
	if m.ThumbnailOffset <= 0 {
		t.Fatalf("ThumbnailOffset = %d", m.ThumbnailOffset)
	}
	// The offset is relative to the TIFF block; EXIFOffset locates that
	// block in the file. Together they must name the thumbnail's bytes.
	at := int(m.EXIFOffset) + m.ThumbnailOffset
	if at+m.ThumbnailLength > len(data) {
		t.Fatalf("the recorded range %d+%d lies outside the %d-byte file", at, m.ThumbnailLength, len(data))
	}
	if !bytes.Equal(data[at:at+m.ThumbnailLength], spec.Thumbnail) {
		t.Error("the recorded byte range does not hold the thumbnail that was embedded")
	}
}

// IFD1 describes the THUMBNAIL. Reading it as another IFD0 would let a
// 256x192 preview overwrite the real image's dimensions.
func TestThumbnail_IFD1DoesNotOverwriteTheImagesOwnValues(t *testing.T) {
	spec := photo()
	spec.Thumbnail = exifgen.MinimalJPEG()
	m := parse(t, exifgen.Build(spec))

	if m.Width != 4160 || m.Height != 3120 {
		t.Errorf("image dimensions became %dx%d; IFD1 must not overwrite IFD0", m.Width, m.Height)
	}
	if m.Make != "LG Electronics" {
		t.Errorf("Make = %q", m.Make)
	}
	if !m.GPS.Decoded || m.GPS.Lat != -16 {
		t.Errorf("GPS was disturbed by the thumbnail directory: %+v", m.GPS)
	}
}

func TestThumbnail_AbsentIsReportedAsAbsent(t *testing.T) {
	m := parse(t, exifgen.Build(photo()))
	if m.ThumbnailLength != 0 {
		t.Errorf("ThumbnailLength = %d for an image with no IFD1", m.ThumbnailLength)
	}
	_, _, ok, err := exif.EmbeddedThumbnail(writeTemp(t, exifgen.Build(photo())), exif.DefaultLimits())
	if err != nil {
		t.Fatalf("EmbeddedThumbnail: %v", err)
	}
	if ok {
		t.Error("EmbeddedThumbnail reported a thumbnail for an image that embeds none")
	}
}

// A directory pointing outside the block, or at bytes that are not a
// JPEG, must yield no thumbnail rather than whatever is at that offset.
func TestThumbnail_BadDirectoryYieldsNothing(t *testing.T) {
	cases := []struct {
		name string
		spec func() exifgen.Spec
	}{
		{"offset outside the block", func() exifgen.Spec {
			s := photo()
			s.Thumbnail = exifgen.MinimalJPEG()
			s.ThumbnailOffsetOverride = 1 << 20
			return s
		}},
		{"uncompressed strips, not a JPEG", func() exifgen.Spec {
			s := photo()
			s.Thumbnail = exifgen.MinimalJPEG()
			s.ThumbnailCompression = 1
			return s
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := exifgen.Build(tc.spec())
			m := parse(t, data)
			if m.ThumbnailLength != 0 {
				t.Errorf("ThumbnailLength = %d; a bad directory must yield no thumbnail", m.ThumbnailLength)
			}
			_, _, ok, _ := exif.EmbeddedThumbnail(writeTemp(t, data), exif.DefaultLimits())
			if ok {
				t.Error("EmbeddedThumbnail returned bytes from a bad directory")
			}
		})
	}
}

func TestEmbeddedThumbnail_DoesNotModifyTheFile(t *testing.T) {
	spec := photo()
	spec.Thumbnail = exifgen.MinimalJPEG()
	data := exifgen.Build(spec)
	path := writeTemp(t, data)

	before := sha256.Sum256(data)
	if _, _, _, err := exif.EmbeddedThumbnail(path, exif.DefaultLimits()); err != nil {
		t.Fatalf("EmbeddedThumbnail: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(after) != before {
		t.Error("reading the embedded thumbnail modified the evidence file")
	}
}

func writeTemp(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "photo.jpg")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
