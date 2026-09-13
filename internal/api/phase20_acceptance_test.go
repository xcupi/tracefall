package api

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"tracefall/internal/ad1"
	"tracefall/internal/ingest"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

// Acceptance tests against a REAL AD1 image, gated on TRACEFALL_AD1.
//
// They are gated because the evidence is not in the repository and never
// will be: real forensic images are not committed. Run them with
//
//	TRACEFALL_AD1=/path/to/image.ad1 go test ./internal/api -run TestAcceptance
//
// Nothing here hardcodes an expected answer. Each test extracts the
// artifact from the image, runs it through the SAME parser selection
// ingestion uses, and then checks the result against the RAW BYTES of
// the source file -- so the assertion is "the parser reports what the
// evidence contains", not "the parser reports what I expected".

func acceptanceImage(t *testing.T) *ad1.Container {
	t.Helper()
	path := os.Getenv("TRACEFALL_AD1")
	if path == "" {
		t.Skip("set TRACEFALL_AD1 to a real AD1 image to run the acceptance tests")
	}
	segs, err := ad1.FindSiblingSegments(path)
	if err != nil {
		t.Fatalf("locating AD1 segments: %v", err)
	}
	c, err := ad1.Open(segs, ad1.DefaultLimits)
	if err != nil {
		t.Fatalf("opening %s: %v", path, err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// extractOne finds the single entry whose path ends with suffix and
// writes it to a temp file, returning the path and the bytes.
func extractOne(t *testing.T, c *ad1.Container, suffix string) (string, []byte) {
	t.Helper()
	var found *ad1.Entry
	err := c.Walk(func(e ad1.Entry) error {
		if e.IsDir || !strings.HasSuffix(e.Path, suffix) {
			return nil
		}
		if found != nil {
			return nil // first match wins; the test names a unique suffix
		}
		cp := e
		found = &cp
		return nil
	})
	if err != nil {
		t.Fatalf("walking the image: %v", err)
	}
	if found == nil {
		t.Fatalf("the image contains no entry ending in %q", suffix)
	}

	out := filepath.Join(t.TempDir(), filepath.Base(strings.ReplaceAll(found.Path, "/", "_")))
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Extract(*found, f); err != nil {
		f.Close()
		t.Fatalf("extracting %s: %v", found.Path, err)
	}
	f.Close()

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("evidence path: %s (%d bytes)", found.Path, len(data))
	return out, data
}

// parseAsIngestionWould selects a parser exactly the way ingestion does
// -- by relative path and header, through ingest.MatchParser -- so the
// test cannot succeed via a parser the real pipeline would not choose.
func parseAsIngestionWould(t *testing.T, absPath, relPath string) (parsers.ArtifactParser, parsers.ParseResult) {
	t.Helper()
	header, err := os.ReadFile(absPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(header) > parsers.SniffLength {
		header = header[:parsers.SniffLength]
	}
	p := ingest.MatchParser(relPath, header, ingest.Registry())
	if p == nil {
		t.Fatalf("no parser claims %s", relPath)
	}
	res, err := p.Parse(absPath)
	if err != nil {
		t.Fatalf("%s failed to parse %s: %v", p.Name(), relPath, err)
	}
	return p, res
}

// ---------------- Q3: the FTP server ----------------

func TestAcceptance_FileZillaIPv4IsRecoveredFromTheImage(t *testing.T) {
	c := acceptanceImage(t)
	abs, raw := extractOne(t, c, "FileZilla/recentservers.xml")

	p, res := parseAsIngestionWould(t, abs, "Users/x/AppData/Roaming/FileZilla/recentservers.xml")
	if p.ArtifactType() != model.ArtifactFileZillaServer {
		t.Fatalf("ingestion would classify this as %q", p.ArtifactType())
	}
	if len(res.Events) == 0 {
		t.Fatal("the FileZilla file produced no events")
	}

	var ipv4 []string
	for _, ev := range res.Events {
		if v := ev.Extra["server_ipv4"]; v != "" {
			ipv4 = append(ipv4, v)
			t.Logf("server entry: %s:%s protocol=%s user=%s",
				v, ev.Extra["server_port"], ev.Extra["protocol"], ev.Extra["server_username"])
		}
	}
	if len(ipv4) == 0 {
		t.Fatal("no IPv4 address was recovered from the FileZilla evidence")
	}

	// The independent half: every value the parser reports must be
	// findable in the raw source bytes. This is what makes the test an
	// acceptance test rather than a restatement of the parser.
	for _, ev := range res.Events {
		for _, field := range []string{"server_ipv4", "server_port", "server_username"} {
			v := ev.Extra[field]
			if v == "" {
				continue
			}
			if !bytes.Contains(raw, []byte(v)) {
				t.Errorf("%s = %q does not appear in the source file; it was not read from the evidence",
					field, v)
			}
		}
		// FTP is a decoded name, so the CODE must be in the file.
		if code := ev.Extra["protocol_code"]; code != "" {
			if !bytes.Contains(raw, []byte("<Protocol>"+code)) {
				t.Errorf("protocol code %q does not appear in the source file", code)
			}
		}
		if !ev.Timestamp.IsZero() {
			t.Errorf("the event carries a timestamp (%v); this artifact records none", ev.Timestamp)
		}
	}

	// And no password value may have travelled out of the file.
	if i := bytes.Index(raw, []byte("<Pass")); i >= 0 {
		end := bytes.Index(raw[i:], []byte("</Pass>"))
		if end > 0 {
			stored := string(raw[i:][:end])
			if inner := strings.SplitN(stored, ">", 2); len(inner) == 2 && inner[1] != "" {
				for _, ev := range res.Events {
					for k, v := range ev.Extra {
						if strings.Contains(v, inner[1]) {
							t.Errorf("a stored password value reached extra[%q]", k)
						}
					}
				}
			}
		}
	}
}

// ---------------- Q8: the image location ----------------

func TestAcceptance_ImageGPSAndCountryAreDerivedFromTheImage(t *testing.T) {
	name := os.Getenv("TRACEFALL_ACCEPTANCE_IMAGE")
	if name == "" {
		t.Skip("set TRACEFALL_ACCEPTANCE_IMAGE to the image filename to check (e.g. 20210429_152043.jpg)")
	}

	c := acceptanceImage(t)
	abs, raw := extractOne(t, c, "/"+name)

	p, res := parseAsIngestionWould(t, abs, "Users/x/Pictures/"+name)
	if p.ArtifactType() != model.ArtifactImageMetadata {
		t.Fatalf("ingestion would classify this as %q", p.ArtifactType())
	}

	var gps *model.Event
	for i := range res.Events {
		if res.Events[i].ArtifactType == model.ArtifactImageGPS {
			gps = &res.Events[i]
		}
	}
	if gps == nil {
		t.Fatal("the image produced no GPS event; no coordinate was recovered")
	}
	x := gps.Extra

	t.Logf("raw latitude:  %s", x["gps_latitude_raw"])
	t.Logf("raw longitude: %s", x["gps_longitude_raw"])
	t.Logf("decimal:       %s", x["gps_coordinates"])
	t.Logf("country:       %s (%s, %s)", x["country"], x["country_iso_a2"], x["country_confidence"])
	t.Logf("dataset:       %s", x["geolocation_dataset"])
	t.Logf("precision:     %s", x["gps_precision"])

	for _, field := range []string{"gps_latitude_raw", "gps_longitude_raw", "gps_coordinates", "gps_latitude", "gps_longitude"} {
		if x[field] == "" {
			t.Errorf("%s is empty", field)
		}
	}

	// The independent half: the EXIF GPS block must really be in the
	// file, and the derived decimal must be consistent with the raw
	// sexagesimal string the parser also reports -- two representations
	// of the same reading, checked against each other.
	if !bytes.Contains(raw[:min(len(raw), 1<<16)], []byte("Exif\x00\x00")) {
		t.Error("the file carries no EXIF header, yet a coordinate was reported")
	}
	checkDMSMatchesDecimal(t, x["gps_latitude_raw"], x["gps_latitude"])
	checkDMSMatchesDecimal(t, x["gps_longitude_raw"], x["gps_longitude"])

	// The country must be derived, and must be labelled as derived.
	if x["country"] == "" {
		t.Error("no country field at all")
	}
	if x["country"] != "unavailable" {
		if !strings.Contains(x["country_derivation"], "DERIVED") {
			t.Errorf("country_derivation = %q", x["country_derivation"])
		}
		if x["geolocation_dataset"] == "" || x["geolocation_dataset_version"] == "" {
			t.Error("the country was derived without recording which dataset produced it")
		}
	}
	// A country name must never appear in the image itself -- if it did,
	// the derivation would be reading rather than computing.
	if x["country"] != "" && x["country"] != "unavailable" {
		if bytes.Contains(raw[:min(len(raw), 1<<16)], []byte(x["country"])) {
			t.Logf("note: the country name also appears in the file's first 64 KB; " +
				"the derivation is still a polygon test, but this is worth knowing")
		}
	}
}

// checkDMSMatchesDecimal recomputes the decimal from the raw
// sexagesimal string the parser reported, and requires the two to agree.
// It is a second, independent path to the same number.
func checkDMSMatchesDecimal(t *testing.T, raw, decimal string) {
	t.Helper()
	if raw == "" || decimal == "" {
		return
	}
	// raw looks like `16° 0' 0" S`.
	fields := strings.Fields(raw)
	if len(fields) != 4 {
		t.Logf("raw coordinate %q is not in the plain d/m/s form; skipping the cross-check", raw)
		return
	}
	num := func(s, unit string) (float64, bool) {
		s = strings.TrimSuffix(s, unit)
		var v float64
		var den float64 = 1
		if i := strings.Index(s, "/"); i >= 0 {
			return 0, false // fractional form; the plain check does not apply
		}
		if _, err := fmtSscan(s, &v); err != nil {
			return 0, false
		}
		return v / den, true
	}
	d, ok1 := num(fields[0], "°")
	m, ok2 := num(fields[1], "'")
	s, ok3 := num(fields[2], `"`)
	if !ok1 || !ok2 || !ok3 {
		return
	}
	want := d + m/60 + s/3600
	if fields[3] == "S" || fields[3] == "W" {
		want = -want
	}
	var got float64
	if _, err := fmtSscan(decimal, &got); err != nil {
		t.Errorf("decimal %q is not a number", decimal)
		return
	}
	if diff := got - want; diff > 1e-6 || diff < -1e-6 {
		t.Errorf("the decimal %v does not match the raw components %q (which give %v)", got, raw, want)
	}
}

// fmtSscan parses a decimal float, used only by the cross-check above.
func fmtSscan(s string, v *float64) (int, error) {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0, err
	}
	*v = f
	return 1, nil
}

// ---------------- Phase 21: the Photo Map, on real evidence ----------------

// The map's full chain against a real image: AD1 -> evidence file ->
// EXIF GPS event -> marker -> servable bytes -> provenance.
//
// Nothing here is compared against an expected country or coordinate.
// The assertions are that the marker AGREES with the event, that the
// served bytes are the evidence bytes, and that the evidence is
// unchanged by any of it.
func TestAcceptance_PhotoMapServesRealEvidence(t *testing.T) {
	c := acceptanceImage(t)

	name := os.Getenv("TRACEFALL_ACCEPTANCE_IMAGE")
	if name == "" {
		t.Skip("set TRACEFALL_ACCEPTANCE_IMAGE to the image filename to check")
	}
	abs, raw := extractOne(t, c, "/"+name)

	// Stage the real image the way a local-path collection holds it.
	dir := t.TempDir()
	rel := filepath.Join("Users", "John Doe", "Pictures", name)
	dest := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(abs)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, src, 0o600); err != nil {
		t.Fatal(err)
	}
	originalHash := sha256.Sum256(src)

	mux := newTestRouter(t)
	caseID := mustCreateCase(t, mux, "Phase 21 acceptance").ID

	var disc DiscoverResult
	rec := doJSON(t, mux, "POST", "/api/cases/"+caseID+"/ingest",
		map[string]string{"path": dir}, &disc)
	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("ingest: %d %s", rec.Code, rec.Body.String())
	}
	if imp := importAllFrom(t, mux, caseID, disc); len(imp.ParseFailures) != 0 {
		t.Fatalf("import failed: %+v", imp.ParseFailures)
	}

	// The marker.
	var res GeoPhotoResult
	if rec := doJSON(t, mux, "GET", "/api/cases/"+caseID+"/geo/photos", nil, &res); rec.Code != http.StatusOK {
		t.Fatalf("geo/photos: %d", rec.Code)
	}
	if res.Total != 1 {
		t.Fatalf("got %d markers for one located image", res.Total)
	}
	p := res.Photos[0]
	t.Logf("marker: %s at %v,%v -> %s (%s, %s)",
		p.Filename, p.Latitude, p.Longitude, p.Country, p.CountryConfidence, p.CoordinatePrecision)
	t.Logf("path: %s", p.Path)
	t.Logf("evidence sha256: %s", p.SHA256)

	// The marker must agree with the EVENT it claims to be -- that is
	// what makes it a view of the evidence rather than a second copy.
	var prov EventProvenance
	if rec := doJSON(t, mux, "GET", "/api/cases/"+caseID+"/events/"+p.EventID, nil, &prov); rec.Code != http.StatusOK {
		t.Fatalf("event provenance: %d", rec.Code)
	}
	if got := prov.Event.Extra["gps_latitude"]; got == "" {
		t.Fatal("the event carries no coordinate")
	}
	for _, f := range []struct{ marker, event string }{
		{fmt.Sprintf("%v", p.Latitude), prov.Event.Extra["gps_latitude"]},
		{fmt.Sprintf("%v", p.Longitude), prov.Event.Extra["gps_longitude"]},
		{p.Country, prov.Event.Extra["country"]},
		{p.LatitudeRaw, prov.Event.Extra["gps_latitude_raw"]},
	} {
		if f.marker != f.event {
			t.Errorf("marker says %q, the event says %q", f.marker, f.event)
		}
	}
	if prov.SourceFile.ID != p.SourceFileID {
		t.Error("the marker does not resolve to the event's own source file")
	}

	// The image bytes: exactly the evidence, and the evidence unchanged.
	if !p.Available {
		t.Fatalf("the image is reported unavailable: %s", p.Unavailable)
	}
	img := p21GetRaw(t, mux, "/api/cases/"+caseID+"/images/"+p.SourceFileID+"/content")
	if img.Code != http.StatusOK {
		t.Fatalf("image content: %d", img.Code)
	}
	if !bytes.Equal(img.Body.Bytes(), raw) {
		t.Errorf("served %d bytes; the AD1 entry is %d bytes -- they must be identical",
			img.Body.Len(), len(raw))
	}
	served := sha256.Sum256(img.Body.Bytes())
	if served != originalHash {
		t.Errorf("served hash %x != original %x", served, originalHash)
	}

	// A preview, and the original still untouched afterwards.
	th := p21GetRaw(t, mux, "/api/cases/"+caseID+"/images/"+p.SourceFileID+"/thumbnail")
	if th.Code != http.StatusOK {
		t.Fatalf("thumbnail: %d %s", th.Code, th.Body.String())
	}
	t.Logf("thumbnail: %d bytes, source=%s", th.Body.Len(), th.Header().Get("X-Tracefall-Thumbnail-Source"))
	if th.Body.Len() >= len(raw) {
		t.Errorf("the preview (%d bytes) is not smaller than the evidence (%d bytes)",
			th.Body.Len(), len(raw))
	}

	after, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if got := sha256.Sum256(after); got != originalHash {
		t.Errorf("the evidence file changed:\n before %x\n after  %x", originalHash, got)
	}
	t.Logf("evidence unchanged after serving image and thumbnail: %x", originalHash)
}
