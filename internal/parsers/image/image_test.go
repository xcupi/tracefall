package image_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tracefall/internal/exif/exifgen"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
	imageparser "tracefall/internal/parsers/image"
)

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

func write(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func parse(t *testing.T, name string, spec exifgen.Spec) parsers.ParseResult {
	t.Helper()
	res, err := imageparser.New().Parse(write(t, name, exifgen.Build(spec)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return res
}

func eventOfType(res parsers.ParseResult, artifact string) (model.Event, bool) {
	for _, e := range res.Events {
		if e.ArtifactType == artifact {
			return e, true
		}
	}
	return model.Event{}, false
}

func TestParser_Identity(t *testing.T) {
	p := imageparser.New()
	if p.Name() != "image@1" {
		t.Errorf("Name = %q", p.Name())
	}
	if p.ArtifactType() != model.ArtifactImageMetadata {
		t.Errorf("ArtifactType = %q", p.ArtifactType())
	}
	// The GPS artifact type must be declared, or it would be classified
	// as unrecognized and lose its label, filter and priority.
	types := p.EventArtifactTypes()
	if len(types) != 1 || types[0] != model.ArtifactImageGPS {
		t.Errorf("EventArtifactTypes = %v", types)
	}
}

func TestDetect_IsStructuralNotByName(t *testing.T) {
	p := imageparser.New()

	// An extension proves nothing either way.
	if p.Detect("Users/j/Pictures/photo.jpg") {
		t.Error("Detect claimed a file by its extension")
	}
	if !p.DetectContent(exifgen.Build(photo())) {
		t.Error("DetectContent missed a JPEG")
	}
	for _, in := range [][]byte{
		[]byte("MZ\x90\x00"),
		{0x89, 'P', 'N', 'G'},
		[]byte("<?xml version=\"1.0\"?>"),
		{},
		{0xFF, 0xD8},
	} {
		if p.DetectContent(in) {
			t.Errorf("DetectContent claimed a non-JPEG: %q", in)
		}
	}
}

// A file with a .jpg extension that is not an image must not be claimed.
func TestParse_NonImageIsRefusedAsNotAnImage(t *testing.T) {
	_, err := imageparser.New().Parse(write(t, "impostor.jpg", []byte("MZ this is a PE binary, not a photo")))
	if err == nil {
		t.Fatal("Parse accepted a non-image")
	}
	if !strings.Contains(err.Error(), "is not a JPEG image") {
		t.Errorf("err = %v; it must say the file is not an image", err)
	}
}

func TestParse_ProducesMetadataAndGPSEventsWithProvenance(t *testing.T) {
	res := parse(t, "20210429_152043.jpg", photo())

	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want 2 (metadata + GPS)", len(res.Events))
	}
	if len(res.Raw) != len(res.Events) {
		t.Fatalf("%d raw records for %d events; they must pair 1:1", len(res.Raw), len(res.Events))
	}
	seen := map[string]bool{}
	for i, ev := range res.Events {
		if ev.Parser != "image@1" {
			t.Errorf("event %d Parser = %q", i, ev.Parser)
		}
		if ev.FilePath != "20210429_152043.jpg" {
			t.Errorf("event %d FilePath = %q", i, ev.FilePath)
		}
		if ev.SourceReference == "" {
			t.Errorf("event %d has no SourceReference", i)
		}
		if res.Raw[i].SourceReference != ev.SourceReference {
			t.Errorf("event %d: raw reference %q != event reference %q",
				i, res.Raw[i].SourceReference, ev.SourceReference)
		}
		if seen[ev.SourceReference] {
			t.Errorf("duplicate source reference %q", ev.SourceReference)
		}
		seen[ev.SourceReference] = true
	}
}

func TestParse_GPSEventSeparatesObservedFromDerived(t *testing.T) {
	res := parse(t, "photo.jpg", photo())
	ev, ok := eventOfType(res, model.ArtifactImageGPS)
	if !ok {
		t.Fatal("no GPS event")
	}
	x := ev.Extra

	// OBSERVED.
	if x["gps_latitude_raw"] != `16° 0' 0" S` {
		t.Errorf("gps_latitude_raw = %q", x["gps_latitude_raw"])
	}
	if x["gps_longitude_raw"] != `23° 0' 0" E` {
		t.Errorf("gps_longitude_raw = %q", x["gps_longitude_raw"])
	}
	if !strings.Contains(x["gps_components_observed"], "16/1") {
		t.Errorf("the stored rationals must be reported: %q", x["gps_components_observed"])
	}

	// DERIVED.
	if x["gps_latitude"] != "-16" || x["gps_longitude"] != "23" {
		t.Errorf("decimal = %q, %q", x["gps_latitude"], x["gps_longitude"])
	}
	if x["gps_coordinates"] != "-16, 23" {
		t.Errorf("gps_coordinates = %q", x["gps_coordinates"])
	}
	if !strings.Contains(x["gps_decimal_derivation"], "RATIONAL") {
		t.Errorf("the derivation must be stated: %q", x["gps_decimal_derivation"])
	}

	// The country is derived, and the record says so.
	if x["country"] == "" {
		t.Error("no country was derived")
	}
	if !strings.Contains(x["country_derivation"], "DERIVED") {
		t.Errorf("country_derivation = %q; it must not read as something the image stored", x["country_derivation"])
	}
	if x["geolocation_method"] == "" || x["geolocation_dataset"] == "" {
		t.Errorf("method = %q, dataset = %q; both must travel with the result",
			x["geolocation_method"], x["geolocation_dataset"])
	}
	if x["geolocation_dataset_version"] == "" {
		t.Error("the dataset version must be recorded")
	}
	if !strings.Contains(x["gps_observation_note"], "not a position Tracefall observed") {
		t.Errorf("gps_observation_note = %q", x["gps_observation_note"])
	}
}

// The whole-degree caveat must survive to the event: a ±55 km position
// must not be presented as an exact one.
func TestParse_CoordinatePrecisionIsReportedOnTheEvent(t *testing.T) {
	ev, _ := eventOfType(parse(t, "photo.jpg", photo()), model.ArtifactImageGPS)
	if ev.Extra["gps_precision"] != "degree" {
		t.Errorf("gps_precision = %q", ev.Extra["gps_precision"])
	}
	if !strings.Contains(ev.Extra["gps_precision_note"], "111") {
		t.Errorf("the precision note must quantify the uncertainty: %q", ev.Extra["gps_precision_note"])
	}
}

func TestParse_ImageWithoutGPSProducesNoGPSEvent(t *testing.T) {
	spec := photo()
	spec.GPS = nil
	res := parse(t, "photo.jpg", spec)

	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(res.Events))
	}
	if _, ok := eventOfType(res, model.ArtifactImageGPS); ok {
		t.Error("a GPS event was produced for an image with no GPS block")
	}
	if res.Events[0].ArtifactType != model.ArtifactImageMetadata {
		t.Errorf("ArtifactType = %q", res.Events[0].ArtifactType)
	}
}

// A GPS block with no coordinate must not become a 0,0 position.
func TestParse_GPSBlockWithoutACoordinateProducesNoGPSEvent(t *testing.T) {
	spec := photo()
	spec.GPS = &exifgen.GPS{VersionOnly: true}
	res := parse(t, "photo.jpg", spec)

	if _, ok := eventOfType(res, model.ArtifactImageGPS); ok {
		t.Error("a GPS event was produced from a block holding no coordinate")
	}
}

func TestParse_JPEGWithoutEXIFIsStillAnEvent(t *testing.T) {
	res := parse(t, "screenshot.jpg", exifgen.Spec{Width: 800, Height: 600, NoEXIF: true})

	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(res.Events))
	}
	ev := res.Events[0]
	if ev.Extra["exif_present"] != "false" {
		t.Errorf("exif_present = %q", ev.Extra["exif_present"])
	}
	if ev.Extra["image_dimensions"] != "800 x 600" {
		t.Errorf("image_dimensions = %q; the frame header is readable without EXIF", ev.Extra["image_dimensions"])
	}
	if !ev.Timestamp.IsZero() {
		t.Errorf("Timestamp = %v; an image with no EXIF time must have no event time", ev.Timestamp)
	}
	if !strings.Contains(ev.Extra["timestamp_basis"], "not substituted") {
		t.Errorf("the basis must state that the file's mtime is not used: %q", ev.Extra["timestamp_basis"])
	}
	if !strings.Contains(ev.Extra["exif_note"], "not evidence of tampering") {
		t.Errorf("a missing EXIF block must not read as suspicious: %q", ev.Extra["exif_note"])
	}
}

func TestParse_TimestampIsDateTimeOriginalAndSaysSo(t *testing.T) {
	res := parse(t, "photo.jpg", photo())
	ev, _ := eventOfType(res, model.ArtifactImageMetadata)

	if got := ev.Timestamp.Format("2006-01-02T15:04:05"); got != "2021-04-29T15:20:43" {
		t.Errorf("Timestamp = %s, want the DateTimeOriginal 2021-04-29T15:20:43", got)
	}
	if ev.Extra["timestamp_source"] != "EXIF DateTimeOriginal" {
		t.Errorf("timestamp_source = %q", ev.Extra["timestamp_source"])
	}
	if !strings.Contains(ev.Extra["timestamp_zone"], "none recorded") {
		t.Errorf("the missing zone must be stated: %q", ev.Extra["timestamp_zone"])
	}
	// The forbidden misreading.
	if strings.Contains(strings.ToLower(ev.Extra["timestamp_meaning"]), "file creation time") &&
		!strings.Contains(strings.ToLower(ev.Extra["timestamp_meaning"]), "not a file creation time") {
		t.Errorf("DateTimeOriginal is described as a file creation time: %q", ev.Extra["timestamp_meaning"])
	}
	// Each EXIF time keeps its own label.
	for _, tag := range []string{"exif_datetimeoriginal", "exif_datetimedigitized", "exif_datetime"} {
		if ev.Extra[tag] == "" {
			t.Errorf("%s is missing", tag)
		}
		if ev.Extra[tag+"_meaning"] == "" {
			t.Errorf("%s has no meaning attached", tag)
		}
	}
}

// The GPS block here carries no time of its own, and the event must say
// which time it is standing on.
func TestParse_GPSEventExplainsWhichTimeItUses(t *testing.T) {
	ev, _ := eventOfType(parse(t, "photo.jpg", photo()), model.ArtifactImageGPS)

	if ev.Timestamp.IsZero() {
		t.Fatal("the GPS event has no time although the image records DateTimeOriginal")
	}
	if !strings.Contains(ev.Extra["timestamp_meaning"], "GPS block in this image carries NO time of its own") {
		t.Errorf("timestamp_meaning = %q", ev.Extra["timestamp_meaning"])
	}
}

func TestParse_GPSFixTimeIsUsedWhenPresentAndLabelledUTC(t *testing.T) {
	spec := photo()
	ts := [3][2]uint32{{13, 1}, {20, 1}, {43, 1}}
	spec.GPS.DateStamp = "2021:04:29"
	spec.GPS.TimeStamp = &ts

	ev, _ := eventOfType(parse(t, "photo.jpg", spec), model.ArtifactImageGPS)
	if got := ev.Timestamp.Format("2006-01-02T15:04:05Z"); got != "2021-04-29T13:20:43Z" {
		t.Errorf("Timestamp = %s, want the GPS fix time", got)
	}
	if !strings.Contains(ev.Extra["timestamp_meaning"], "UTC by specification") {
		t.Errorf("the GPS fix time must be labelled UTC: %q", ev.Extra["timestamp_meaning"])
	}
}

func TestParse_EventsAreNotPresentedAsActivity(t *testing.T) {
	res := parse(t, "photo.jpg", photo())
	for _, ev := range res.Events {
		switch ev.EventType {
		case model.EventProcessCreate, model.EventLogonSuccess, model.EventPrefetchExecution:
			t.Errorf("EventType = %q; image metadata is not activity", ev.EventType)
		}
		meaning := ev.Extra["evidence_meaning"]
		if !strings.Contains(meaning, "not") {
			t.Errorf("evidence_meaning does not say what this is NOT: %q", meaning)
		}
	}
	ev, _ := eventOfType(res, model.ArtifactImageMetadata)
	if !strings.Contains(ev.Extra["device_attribution"], "who owned it") {
		t.Errorf("Make/Model must not imply camera ownership: %q", ev.Extra["device_attribution"])
	}
	if !strings.Contains(ev.Extra["evidence_meaning"], "not evidence that the image was opened") {
		t.Errorf("evidence_meaning = %q", ev.Extra["evidence_meaning"])
	}
}

// An image that was resaved by an editor is worth flagging, because the
// EXIF below it passed through that editor.
func TestParse_WritingSoftwareIsReported(t *testing.T) {
	ev, _ := eventOfType(parse(t, "photo.jpg", photo()), model.ArtifactImageMetadata)
	if ev.Extra["writing_software"] != "GIMP 2.10.18" {
		t.Errorf("writing_software = %q", ev.Extra["writing_software"])
	}
	if !strings.Contains(ev.Extra["writing_software_meaning"], "possibly changed") {
		t.Errorf("writing_software_meaning = %q", ev.Extra["writing_software_meaning"])
	}
}

func TestParse_RenamedJPEGIsStillParsed(t *testing.T) {
	res, err := imageparser.New().Parse(write(t, "notes.txt", exifgen.Build(photo())))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Events) != 2 {
		t.Fatalf("got %d events from a renamed JPEG", len(res.Events))
	}
	ev, _ := eventOfType(res, model.ArtifactImageMetadata)
	if ev.Extra["camera_make"] != "LG Electronics" {
		t.Errorf("camera_make = %q", ev.Extra["camera_make"])
	}
}

func TestParse_TruncatedImageIsAControlledResult(t *testing.T) {
	full := exifgen.Build(photo())
	for _, cut := range []int{4, 30, 200, len(full) / 2, len(full) - 5} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic at cut %d: %v", cut, r)
				}
			}()
			_, _ = imageparser.New().Parse(write(t, "photo.jpg", full[:cut]))
		}()
	}
}

func TestParse_MalformedEXIFDoesNotFabricateValues(t *testing.T) {
	spec := photo()
	spec.BadIFDOffset = true
	res := parse(t, "photo.jpg", spec)

	ev, _ := eventOfType(res, model.ArtifactImageMetadata)
	if ev.Extra["camera_make"] != "" {
		t.Errorf("camera_make = %q for an unreadable directory; nothing may be invented", ev.Extra["camera_make"])
	}
	if ev.Extra["parse_warnings"] == "" {
		t.Error("the damage must be reported on the event")
	}
	if _, ok := eventOfType(res, model.ArtifactImageGPS); ok {
		t.Error("a GPS event was produced from an unreadable EXIF block")
	}
}

func TestParse_IsDeterministic(t *testing.T) {
	path := write(t, "photo.jpg", exifgen.Build(photo()))
	first, err := imageparser.New().Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		got, err := imageparser.New().Parse(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Events) != len(first.Events) {
			t.Fatalf("run %d: event count changed", i)
		}
		for j := range got.Events {
			if got.Raw[j].Raw != first.Raw[j].Raw {
				t.Fatalf("run %d: raw record %d differs", i, j)
			}
			for k, v := range first.Events[j].Extra {
				if got.Events[j].Extra[k] != v {
					t.Fatalf("run %d: event %d extra[%q] differs", i, j, k)
				}
			}
		}
	}
}

// A coordinate the dataset attributes to no country must be reported as
// unavailable, never filled in.
func TestParse_MidOceanCoordinateReportsCountryUnavailable(t *testing.T) {
	spec := photo()
	spec.GPS = &exifgen.GPS{
		LatRef: "N", Lat: exifgen.DMS(35, 0, 0),
		LonRef: "W", Lon: exifgen.DMS(40, 0, 0),
	}
	ev, ok := eventOfType(parse(t, "photo.jpg", spec), model.ArtifactImageGPS)
	if !ok {
		t.Fatal("no GPS event; the coordinate is valid and must still be reported")
	}
	if ev.Extra["country"] != "unavailable" {
		t.Errorf("country = %q, want unavailable", ev.Extra["country"])
	}
	if ev.Extra["country_status"] == "" {
		t.Error("an unavailable country must explain itself")
	}
	// The coordinate itself is still preserved.
	if ev.Extra["gps_coordinates"] != "35, -40" {
		t.Errorf("gps_coordinates = %q; the position must survive a failed country lookup",
			ev.Extra["gps_coordinates"])
	}
}
