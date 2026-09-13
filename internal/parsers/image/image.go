// Package image turns image-file metadata into normalized evidence.
//
// # What these events assert
//
// That the file CONTAINS these metadata values. EXIF is ordinary file
// content: a camera writes it, and so does every editor, exporter,
// messaging app and forger that touches the file afterwards. A Make and
// Model name the device that CLAIMED to produce the image. A coordinate
// is a position the writer recorded, not one Tracefall observed.
//
// So these are metadata events, never execution, never user activity, and
// never proof of who owned a camera. Every event says so.
//
// # Two artifacts, deliberately
//
// An image's metadata and an image's embedded location are separate
// events with separate artifact types. A position is a far stronger claim
// than a camera model and it is the field an analyst filters a case down
// to; merging them would bury a handful of located images among thousands
// that carry no location at all.
//
// # Country
//
// The country on a GPS event is DERIVED -- an offline point-in-polygon
// test against a bundled boundary dataset (see internal/geo), performed
// by Tracefall. It is not in the image. The event separates the observed
// coordinate from the derived country and names the dataset that produced
// it, so the derivation can be checked or disputed.
package image

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"tracefall/internal/browsercache"
	"tracefall/internal/exif"
	"tracefall/internal/geo"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

const parserName = "image@1"

// Parser implements parsers.ArtifactParser, parsers.ContentDetector and
// parsers.EventArtifactTypeSource.
type Parser struct {
	limits exif.Limits
}

func New() *Parser { return &Parser{limits: exif.DefaultLimits()} }

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactImageMetadata }

// EventArtifactTypes declares that this parser's events also carry the
// GPS artifact type, so it is labelled, filterable and counted as its own
// artifact rather than classified as unrecognized.
func (Parser) EventArtifactTypes() []string {
	return []string{model.ArtifactImageGPS}
}

// Detect deliberately matches NOTHING by filename.
//
// A .jpg extension is not evidence that a file is an image, and an image
// carried out of a triage image may arrive under any name or none.
// Claiming a file by extension would classify a mislabelled file as a
// supported artifact and then fail to parse it, reporting a parse failure
// where the honest answer is "this is not an image". Detection is
// structural only; see DetectContent.
func (Parser) Detect(string) bool { return false }

// DetectContent identifies a JPEG by its start-of-image marker followed
// by the marker that opens the first segment.
func (Parser) DetectContent(header []byte) bool { return exif.Sniff(header) }

// DetectPath keeps this parser out of a browser cache directory.
//
// A JPEG signature says "this is a picture" and nothing more, which
// makes this the broadest content detector in the registry -- and a
// Chromium cache holds hundreds of cached response bodies that really
// are JPEGs. On one real image, 84 of them. They are already correctly
// catalogued as browser-cache evidence, and claiming them as standalone
// images both lost that context and told an analyst filtering "browser
// cache" that 84 entries had vanished.
//
// The cached image is not lost by this: it stays catalogued as the cache
// entry it is, which is the more specific and more useful classification
// -- a picture that arrived over HTTP through a named browser profile,
// not a file someone put on the disk. Reading EXIF out of cached bodies
// would need the cache entry's own artifact to carry it, which is a
// different change from this one.
//
// See parsers.PathScopedDetector.
func (Parser) DetectPath(relPath string) bool {
	return !browsercache.InCacheDirectory("/" + strings.ToLower(relPath))
}

func (p Parser) Parse(absPath string) (parsers.ParseResult, error) {
	m, err := exif.ParseFile(absPath, p.limits)
	if err != nil {
		if errors.Is(err, exif.ErrNotJPEG) {
			return parsers.ParseResult{}, fmt.Errorf(
				"image: %s is not a JPEG image", filepath.Base(absPath))
		}
		return parsers.ParseResult{}, fmt.Errorf("image: %w", err)
	}

	name := filepath.Base(absPath)
	base := baseExtra(m, name)

	var out parsers.ParseResult

	ev, raw := metadataEvent(m, name, base)
	out.Events = append(out.Events, ev)
	out.Raw = append(out.Raw, raw)

	if m.GPS.Decoded {
		gev, graw := gpsEvent(m, name, base)
		out.Events = append(out.Events, gev)
		out.Raw = append(out.Raw, graw)
	}

	return out, nil
}

// baseExtra is the description of the image itself, shared by both
// events so they never disagree about the file they came from.
func baseExtra(m exif.Metadata, name string) map[string]string {
	extra := map[string]string{
		"artifact_class": "image_metadata",
		"image_file":     name,
		"source_file":    name,
		"image_format":   m.Format,
		"exif_present":   strconv.FormatBool(m.HasEXIF),
	}

	if m.Width > 0 && m.Height > 0 {
		extra["image_dimensions"] = strconv.Itoa(m.Width) + " x " + strconv.Itoa(m.Height)
		extra["image_width"] = strconv.Itoa(m.Width)
		extra["image_height"] = strconv.Itoa(m.Height)
		extra["image_dimensions_source"] = "the JPEG frame header, which describes the stored image"
	}
	// The writer's claimed dimensions are kept separate, and a
	// disagreement with the frame header is called out rather than
	// silently resolved -- it is a sign the file was re-encoded or edited.
	if m.EXIFWidth > 0 && m.EXIFHeight > 0 {
		extra["exif_dimensions"] = strconv.Itoa(m.EXIFWidth) + " x " + strconv.Itoa(m.EXIFHeight)
		if m.Width > 0 && m.Height > 0 && (m.EXIFWidth != m.Width || m.EXIFHeight != m.Height) {
			extra["dimensions_disagree"] = "the EXIF PixelXDimension/PixelYDimension tags disagree with the " +
				"JPEG frame header. Both are reported as stored; a disagreement usually means the file was " +
				"re-encoded or edited after the metadata was written"
		}
	}

	if !m.HasEXIF {
		extra["exif_note"] = "this image carries no EXIF block. That is normal for images produced by " +
			"screenshots, exports and many applications, and it is not evidence of tampering."
		return extra
	}

	extra["exif_byte_order"] = m.ByteOrder
	extra["exif_offset"] = strconv.FormatInt(m.EXIFOffset, 10)

	if m.Make != "" {
		extra["camera_make"] = m.Make
	}
	if m.Model != "" {
		extra["camera_model"] = m.Model
	}
	if m.Make != "" || m.Model != "" {
		extra["device_attribution"] = "the Make/Model tags name the device the metadata CLAIMS produced this " +
			"image. They are file content and can be written or altered by any software; they are not proof " +
			"of which device took the photograph, and they say nothing about who owned it."
	}
	if m.Software != "" {
		extra["writing_software"] = m.Software
		extra["writing_software_meaning"] = "the software that last wrote this file's metadata. When it is " +
			"an editor rather than a camera, the EXIF values below were passed through -- and possibly " +
			"changed by -- that software."
	}
	if m.BodySerial != "" {
		extra["camera_body_serial"] = m.BodySerial
	}
	if m.LensModel != "" {
		extra["lens_model"] = m.LensModel
	}
	if m.Orientation != 0 {
		extra["image_orientation"] = strconv.Itoa(m.Orientation)
		if m.OrientationName != "" {
			extra["image_orientation_name"] = m.OrientationName
		}
	}
	if m.ISO > 0 {
		extra["exposure_iso"] = strconv.Itoa(m.ISO)
	}
	if m.ExposureTime != nil {
		extra["exposure_time"] = m.ExposureTime.String() + " s"
	}
	if m.FNumber != nil {
		extra["exposure_f_number"] = m.FNumber.String()
	}
	if m.FocalLength != nil {
		extra["focal_length"] = m.FocalLength.String() + " mm"
	}

	// Every EXIF time, each labelled with what it means. None is
	// presented as a filesystem timestamp and none is renamed.
	for _, t := range m.Times {
		key := "exif_" + strings.ToLower(t.Tag)
		extra[key] = t.Raw
		extra[key+"_meaning"] = t.Meaning
		if t.Offset != "" {
			extra[key+"_utc_offset"] = t.Offset
		}
	}

	if len(m.Warnings) > 0 {
		extra["parse_warnings"] = strings.Join(m.Warnings, "; ")
	}
	return extra
}

// metadataEvent is the one event every claimed image produces.
//
// Its time is DateTimeOriginal when the image recorded one. An image
// without it has no event time: the file's own mtime is when the evidence
// was collected, which is a different fact about a different object, and
// substituting it would put a fabricated instant on the timeline.
func metadataEvent(m exif.Metadata, name string, base map[string]string) (model.Event, model.RawEvidence) {
	const ref = "image:metadata"

	extra := copyExtra(base)
	ev := model.Event{
		EventType:       model.EventImageMetadataRecorded,
		ArtifactType:    model.ArtifactImageMetadata,
		Parser:          parserName,
		FilePath:        name,
		Confidence:      1.0,
		SourceReference: ref,
	}

	if t, ok := m.Time("DateTimeOriginal"); ok && !t.Time.IsZero() {
		ev.Timestamp = t.Time
		extra["timestamp_meaning"] = t.Meaning
		extra["timestamp_source"] = "EXIF DateTimeOriginal"
		if !t.HasZone {
			extra["timestamp_zone"] = "none recorded. The digits are shown as the device's clock wrote them; " +
				"they are not a UTC instant, and the device's clock may have been wrong or in any timezone."
		} else {
			extra["timestamp_zone"] = "UTC offset " + t.Offset + ", as the image recorded it"
		}
	} else {
		extra["timestamp_meaning"] = "no time is recorded for this event"
		extra["timestamp_basis"] = "this image records no EXIF DateTimeOriginal. The file's own modification " +
			"time describes the file as it was collected, not when the image was produced, and is not " +
			"substituted here."
	}

	extra["evidence_meaning"] = "metadata embedded in an image file. It records what the writing software " +
		"stored, which is not the same as what happened: EXIF is ordinary file content and can be written, " +
		"edited or removed by anything that touches the file. This is not evidence that the image was opened, " +
		"viewed or executed on this machine."

	ev.Extra = extra
	raw, _ := json.Marshal(rawRecord(m, name))
	return ev, model.RawEvidence{SourceReference: ref, Raw: string(raw)}
}

// gpsEvent is produced only when a full coordinate was decoded. An image
// with a GPS block but no usable position produces no GPS event.
func gpsEvent(m exif.Metadata, name string, base map[string]string) (model.Event, model.RawEvidence) {
	const ref = "image:gps"
	g := m.GPS

	extra := copyExtra(base)
	extra["artifact_class"] = "image_gps"

	// OBSERVED: what the file holds.
	extra["gps_latitude_raw"] = g.LatRaw
	extra["gps_longitude_raw"] = g.LonRaw
	extra["gps_latitude_ref"] = g.LatRef
	extra["gps_longitude_ref"] = g.LonRef
	extra["gps_components_observed"] = "GPSLatitude " + rationalList(g.LatDMS) +
		" / GPSLongitude " + rationalList(g.LonDMS) +
		" -- the EXIF RATIONAL numerator/denominator pairs exactly as stored"

	// DERIVED: what conversion produces from it.
	extra["gps_latitude"] = formatCoord(g.Lat)
	extra["gps_longitude"] = formatCoord(g.Lon)
	extra["gps_coordinates"] = formatCoord(g.Lat) + ", " + formatCoord(g.Lon)
	extra["gps_decimal_derivation"] = g.Method
	extra["gps_observation_note"] = "the coordinate is what the image RECORDS, not a position Tracefall " +
		"observed. EXIF GPS is file content: it can be written by a camera, rewritten by an editor, copied " +
		"between files, or fabricated. It places the WRITER's claimed position, not necessarily the device " +
		"or the user."

	if g.Granularity != "" {
		extra["gps_precision"] = g.Granularity
		extra["gps_precision_note"] = g.GranularityNote
	}

	if g.Altitude != nil {
		extra["gps_altitude"] = strconv.FormatFloat(*g.Altitude, 'f', -1, 64) + " m"
		if g.AltitudeRational != nil {
			extra["gps_altitude_raw"] = g.AltitudeRational.String()
		}
		if g.AltitudeRef != "" {
			extra["gps_altitude_reference"] = g.AltitudeRef
		}
	}
	if g.ImgDirection != nil {
		extra["gps_image_direction"] = strconv.FormatFloat(*g.ImgDirection, 'f', -1, 64)
		if g.ImgDirectionRef != "" {
			extra["gps_image_direction_reference"] = g.ImgDirectionRef
		}
	}
	if g.MapDatum != "" {
		extra["gps_map_datum"] = g.MapDatum
	}
	if g.ProcessingMethod != "" {
		extra["gps_processing_method"] = g.ProcessingMethod
	}
	if g.VersionID != "" {
		extra["gps_version_id"] = g.VersionID
	}
	if g.TimeStampRaw != "" {
		extra["gps_time_raw"] = g.TimeStampRaw
	}
	if g.DateStampRaw != "" {
		extra["gps_date_raw"] = g.DateStampRaw
	}

	country := resolveCountry(g, extra)

	extra["evidence_meaning"] = "a geographic coordinate embedded in this image's EXIF GPS block. It is " +
		"evidence that the image CARRIES this position, not that any person or device was there: metadata " +
		"travels with a copied file and can be edited. Any country shown is DERIVED by Tracefall from the " +
		"coordinate, not read from the image."

	ev := model.Event{
		EventType:       model.EventImageGPSRecorded,
		ArtifactType:    model.ArtifactImageGPS,
		Parser:          parserName,
		FilePath:        name,
		Confidence:      1.0,
		SourceReference: ref,
		Extra:           extra,
	}

	switch {
	case !g.TimeStamp.IsZero():
		// GPSDateStamp/GPSTimeStamp are UTC by specification -- the one
		// EXIF time that is an absolute instant.
		ev.Timestamp = g.TimeStamp
		extra["timestamp_meaning"] = "the GPS fix time, from GPSDateStamp and GPSTimeStamp. Unlike every " +
			"other EXIF time this one is UTC by specification, and it dates the position fix itself."
		extra["timestamp_source"] = "EXIF GPSDateStamp + GPSTimeStamp (UTC)"
	default:
		if t, ok := m.Time("DateTimeOriginal"); ok && !t.Time.IsZero() {
			ev.Timestamp = t.Time
			extra["timestamp_meaning"] = "the EXIF DateTimeOriginal -- when the exposure was recorded, " +
				"as the device's own clock read it. The GPS block in this image carries NO time of its own, " +
				"so the coordinate is placed at the exposure time. That is when the position was written " +
				"into the file, not necessarily when the fix was obtained."
			extra["timestamp_source"] = "EXIF DateTimeOriginal (the GPS block records no time)"
			if !t.HasZone {
				extra["timestamp_zone"] = "none recorded. The digits are shown as the device's clock wrote " +
					"them; they are not a UTC instant."
			}
		} else {
			extra["timestamp_meaning"] = "no time is recorded for this event"
			extra["timestamp_basis"] = "this image's GPS block records no time and the image records no " +
				"DateTimeOriginal. No filesystem time is substituted."
		}
	}

	rawMap := rawRecord(m, name)
	rawMap["derived_country"] = country
	raw, _ := json.Marshal(rawMap)
	return ev, model.RawEvidence{SourceReference: ref, Raw: string(raw)}
}

// resolveCountry performs the offline lookup and writes the result into
// extra, keeping observed and derived strictly apart. A lookup that finds
// nothing records "unavailable" with the reason -- never a nearest guess.
func resolveCountry(g exif.GPS, extra map[string]string) map[string]any {
	res, err := geo.Lookup(g.Lat, g.Lon)
	if err != nil {
		extra["country"] = "unavailable"
		extra["country_status"] = "not determined: " + err.Error()
		extra["geolocation_method"] = geo.Method
		return map[string]any{"country": nil, "status": err.Error()}
	}

	extra["geolocation_method"] = res.Method
	if ds := res.Dataset.String(); ds != "" {
		extra["geolocation_dataset"] = ds
		extra["geolocation_dataset_version"] = res.Dataset.Version
		extra["geolocation_dataset_source"] = res.Dataset.SourceURL
		extra["geolocation_dataset_license"] = res.Dataset.License
	}
	extra["country_derivation"] = "DERIVED by Tracefall from the coordinate above, by an offline " +
		"point-in-polygon test. It is not stored in the image and the image does not name a country."

	if !res.Found {
		extra["country"] = "unavailable"
		extra["country_status"] = res.Reason
		if res.NearestCountry != "" {
			extra["country_nearest_land"] = res.NearestCountry + " (" +
				strconv.FormatFloat(res.NearestDistanceKm, 'f', 2, 64) + " km away) -- context only, " +
				"not an attribution"
		}
	} else {
		extra["country"] = res.Country
		if res.ISOA2 != "" {
			extra["country_iso_a2"] = res.ISOA2
		}
		if res.ISOA3 != "" {
			extra["country_iso_a3"] = res.ISOA3
		}
		extra["country_confidence"] = res.Confidence
		if res.Reason != "" {
			extra["country_confidence_note"] = res.Reason
		}
		extra["country_boundary_distance_km"] = strconv.FormatFloat(res.BoundaryDistanceKm, 'f', 2, 64)
	}

	return map[string]any{
		"country":                 res.Country,
		"iso_a2":                  res.ISOA2,
		"iso_a3":                  res.ISOA3,
		"found":                   res.Found,
		"confidence":              res.Confidence,
		"boundary_distance_km":    res.BoundaryDistanceKm,
		"reason":                  res.Reason,
		"method":                  res.Method,
		"dataset":                 res.Dataset.Source,
		"dataset_version":         res.Dataset.Version,
		"dataset_source_url":      res.Dataset.SourceURL,
		"dataset_source_sha256":   res.Dataset.SourceSHA256,
		"dataset_license":         res.Dataset.License,
		"nearest_country_context": res.NearestCountry,
	}
}

func rawRecord(m exif.Metadata, name string) map[string]any {
	times := make([]map[string]any, 0, len(m.Times))
	for _, t := range m.Times {
		e := map[string]any{"tag": t.Tag, "raw": t.Raw, "meaning": t.Meaning, "utc_offset_recorded": t.HasZone}
		if t.Offset != "" {
			e["utc_offset"] = t.Offset
		}
		if !t.Time.IsZero() {
			e["parsed"] = t.Time.Format("2006-01-02T15:04:05Z")
		}
		times = append(times, e)
	}

	rec := map[string]any{
		"image_file":      name,
		"format":          m.Format,
		"frame_width":     m.Width,
		"frame_height":    m.Height,
		"exif_width":      m.EXIFWidth,
		"exif_height":     m.EXIFHeight,
		"exif_present":    m.HasEXIF,
		"exif_byte_order": m.ByteOrder,
		"exif_offset":     m.EXIFOffset,
		"make":            m.Make,
		"model":           m.Model,
		"software":        m.Software,
		"body_serial":     m.BodySerial,
		"lens_model":      m.LensModel,
		"orientation":     m.Orientation,
		"times":           times,
		"warnings":        m.Warnings,
		"evidence_meaning": "image metadata as stored in the file. EXIF is file content written by whatever " +
			"last saved the image, not an independent observation.",
	}

	if m.GPS.Present {
		gps := map[string]any{
			"present":              true,
			"decoded":              m.GPS.Decoded,
			"latitude_ref":         m.GPS.LatRef,
			"longitude_ref":        m.GPS.LonRef,
			"latitude_components":  rationalStrings(m.GPS.LatDMS),
			"longitude_components": rationalStrings(m.GPS.LonDMS),
			"latitude_raw":         m.GPS.LatRaw,
			"longitude_raw":        m.GPS.LonRaw,
		}
		if m.GPS.Decoded {
			gps["latitude_decimal"] = m.GPS.Lat
			gps["longitude_decimal"] = m.GPS.Lon
			gps["derivation"] = m.GPS.Method
			gps["granularity"] = m.GPS.Granularity
			gps["granularity_km"] = m.GPS.GranularityKm
		}
		if m.GPS.Altitude != nil {
			gps["altitude_m"] = *m.GPS.Altitude
		}
		if m.GPS.AltitudeRational != nil {
			gps["altitude_raw"] = m.GPS.AltitudeRational.String()
		}
		if !m.GPS.TimeStamp.IsZero() {
			gps["fix_time_utc"] = m.GPS.TimeStamp.Format("2006-01-02T15:04:05Z")
		}
		if m.GPS.MapDatum != "" {
			gps["map_datum"] = m.GPS.MapDatum
		}
		rec["gps"] = gps
	}
	return rec
}

func copyExtra(src map[string]string) map[string]string {
	out := make(map[string]string, len(src)+24)
	for k, v := range src {
		out[k] = v
	}
	return out
}

// formatCoord renders a decimal coordinate without rounding away
// precision the components carried: 7 places is about 11 mm, finer than
// any EXIF rational resolves, and trailing zeros are trimmed.
func formatCoord(v float64) string {
	s := strconv.FormatFloat(v, 'f', 7, 64)
	s = strings.TrimRight(s, "0")
	return strings.TrimSuffix(s, ".")
}

func rationalList(r []exif.Rational) string {
	return "[" + strings.Join(rationalStrings(r), ", ") + "]"
}

func rationalStrings(r []exif.Rational) []string {
	out := make([]string, 0, len(r))
	for _, v := range r {
		out = append(out, v.String())
	}
	return out
}
