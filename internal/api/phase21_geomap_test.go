package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tracefall/internal/exif/exifgen"
	"tracefall/internal/geo"
	"tracefall/internal/model"
)

// Phase 21: the Photo Map's API -- the marker dataset, the two image
// endpoints, and the authorization boundary around evidence bytes.

func p21Photo(latRef string, lat [3][2]uint32, lonRef string, lon [3][2]uint32, taken string) []byte {
	return exifgen.Build(exifgen.Spec{
		Width: 4160, Height: 3120,
		Make: "LG Electronics", Model: "LM-Q725K",
		DateTimeOriginal: taken,
		GPS: &exifgen.GPS{
			LatRef: latRef, Lat: lat,
			LonRef: lonRef, Lon: lon,
		},
		Thumbnail: exifgen.MinimalJPEG(),
	})
}

// p21Dir holds two located photos, one image with no coordinate, and a
// non-image artifact -- so every "must not appear" has something real to
// exclude.
func p21Dir() map[string][]byte {
	return map[string][]byte{
		"Users/John Doe/Pictures/south.jpg": p21Photo(
			"S", exifgen.DMS(16, 0, 0), "E", exifgen.DMS(23, 0, 0), "2021:04:29 15:20:43"),
		"Users/John Doe/Pictures/north.jpg": p21Photo(
			"N", exifgen.DMS(10, 0, 0), "E", exifgen.DMS(11, 0, 0), "2021:04:29 15:22:21"),
		"Users/John Doe/Pictures/nogps.jpg": exifgen.Build(exifgen.Spec{
			Width: 800, Height: 600, Make: "ACME", DateTimeOriginal: "2021:04:29 16:00:00",
		}),
		"Windows/Prefetch/UPDATER.EXE-11223344.pf": p15Prefetch(),
	}
}

func p21Case(t *testing.T, mux http.Handler) string {
	t.Helper()
	c := mustCreateCase(t, mux, "Phase 21 "+t.Name())
	disc := discoverBinaryDir(t, mux, c.ID, p21Dir())
	if imp := importAllFrom(t, mux, c.ID, disc); len(imp.ParseFailures) != 0 {
		t.Fatalf("fixture failed to parse: %+v", imp.ParseFailures)
	}
	return c.ID
}

func p21Photos(t *testing.T, mux http.Handler, caseID, query string) GeoPhotoResult {
	t.Helper()
	var out GeoPhotoResult
	rec := doJSON(t, mux, "GET", "/api/cases/"+caseID+"/geo/photos"+query, nil, &out)
	if rec.Code != http.StatusOK {
		t.Fatalf("geo/photos: %d %s", rec.Code, rec.Body.String())
	}
	return out
}

// ---------------- The marker dataset ----------------

func TestGeoMap_ListsOnlyGPSBearingImages(t *testing.T) {
	mux := newTestRouter(t)
	caseID := p21Case(t, mux)

	res := p21Photos(t, mux, caseID, "")
	if res.Total != 2 {
		t.Fatalf("got %d photos, want 2", res.Total)
	}
	names := map[string]bool{}
	for _, p := range res.Photos {
		names[p.Filename] = true
	}
	if names["nogps.jpg"] {
		t.Error("an image with no coordinate appeared on the map")
	}
	// And the map must SAY how many it is not showing, or it reads as
	// "these are all the images in the case".
	if res.ImagesWithoutGPS != 1 {
		t.Errorf("ImagesWithoutGPS = %d, want 1", res.ImagesWithoutGPS)
	}
	if !strings.Contains(res.Note, "DERIVED") {
		t.Errorf("the dataset note must say the country is derived: %q", res.Note)
	}
}

func TestGeoMap_MarkerCarriesObservedAndDerivedSeparately(t *testing.T) {
	mux := newTestRouter(t)
	caseID := p21Case(t, mux)

	var south *GeoPhoto
	for i, p := range p21Photos(t, mux, caseID, "").Photos {
		if p.Filename == "south.jpg" {
			south = &p21Photos(t, mux, caseID, "").Photos[i]
		}
	}
	if south == nil {
		t.Fatal("south.jpg is not on the map")
	}

	// Observed.
	if south.Latitude != -16 || south.Longitude != 23 {
		t.Errorf("coordinate = %v,%v want -16,23", south.Latitude, south.Longitude)
	}
	if south.LatitudeRaw != `16° 0' 0" S` {
		t.Errorf("LatitudeRaw = %q", south.LatitudeRaw)
	}
	if south.EXIFTaken != "2021:04:29 15:20:43" {
		t.Errorf("EXIFTaken = %q", south.EXIFTaken)
	}
	// Derived.
	if south.Country == "" {
		t.Error("no country was derived")
	}
	if south.CoordinatePrecision != "degree" {
		t.Errorf("CoordinatePrecision = %q", south.CoordinatePrecision)
	}
	// Provenance.
	if south.SourceFileID == "" || south.EventID == "" || south.CollectionID == "" {
		t.Errorf("marker is missing provenance: %+v", south)
	}
	if south.Path == "" || !strings.HasSuffix(south.Path, "south.jpg") {
		t.Errorf("Path = %q", south.Path)
	}
	if south.SHA256 == "" {
		t.Error("the marker does not carry the evidence hash")
	}
	if !south.Available {
		t.Errorf("Available = false: %s", south.Unavailable)
	}
}

// The map must point at the EXISTING event, not a copy.
func TestGeoMap_MarkerEventIsTheTimelineEvent(t *testing.T) {
	mux := newTestRouter(t)
	caseID := p21Case(t, mux)
	res := p21Photos(t, mux, caseID, "")

	gps := searchEvents(t, mux, caseID, vals("artifact_type", model.ArtifactImageGPS, "page_size", "50"))
	byID := map[string]bool{}
	for _, e := range gps.Items {
		byID[e.ID] = true
	}
	if len(byID) != res.Total {
		t.Fatalf("%d GPS events but %d markers; the map must not create or drop events",
			len(byID), res.Total)
	}
	for _, p := range res.Photos {
		if !byID[p.EventID] {
			t.Errorf("marker %s references event %s, which is not an image_gps event in this case",
				p.Filename, p.EventID)
		}
		// The event must be reachable through the ordinary provenance
		// endpoint -- that is what "View timeline event" relies on.
		rec := doJSON(t, mux, "GET", "/api/cases/"+caseID+"/events/"+p.EventID, nil, nil)
		if rec.Code != http.StatusOK {
			t.Errorf("event %s is not retrievable: %d", p.EventID, rec.Code)
		}
	}
}

func TestGeoMap_FiltersNarrowTheDataset(t *testing.T) {
	mux := newTestRouter(t)
	caseID := p21Case(t, mux)

	all := p21Photos(t, mux, caseID, "")
	if len(all.Countries) < 2 {
		t.Skipf("fixture resolved %d countries; nothing to filter between", len(all.Countries))
	}

	byCountry := p21Photos(t, mux, caseID, "?country="+all.Countries[0])
	if byCountry.Total != 1 {
		t.Errorf("country filter returned %d photos, want 1", byCountry.Total)
	}
	for _, p := range byCountry.Photos {
		if p.Country != all.Countries[0] {
			t.Errorf("country filter returned a photo from %q", p.Country)
		}
	}
	// The facet list must stay the FULL set, or the dropdown empties
	// itself as it is used.
	if len(byCountry.Countries) != len(all.Countries) {
		t.Errorf("filtering shrank the country facet from %d to %d",
			len(all.Countries), len(byCountry.Countries))
	}

	byName := p21Photos(t, mux, caseID, "?filename=south")
	if byName.Total != 1 || byName.Photos[0].Filename != "south.jpg" {
		t.Errorf("filename filter returned %d photos: %+v", byName.Total, byName.Photos)
	}

	byDate := p21Photos(t, mux, caseID, "?from=2021-04-29&to=2021-04-29")
	if byDate.Total != 2 {
		t.Errorf("date filter returned %d photos, want both", byDate.Total)
	}
	none := p21Photos(t, mux, caseID, "?from=2020-01-01&to=2020-01-02")
	if none.Total != 0 {
		t.Errorf("a range with no photos returned %d", none.Total)
	}
}

func TestGeoMap_BadDateIsRejectedNotIgnored(t *testing.T) {
	mux := newTestRouter(t)
	caseID := p21Case(t, mux)
	rec := doJSON(t, mux, "GET", "/api/cases/"+caseID+"/geo/photos?from=not-a-date", nil, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("a malformed date returned %d; it must be refused, not silently dropped", rec.Code)
	}
}

func TestGeoMap_EmptyCaseSaysSoRatherThanReturningNothing(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Phase 21 empty")
	res := p21Photos(t, mux, c.ID, "")

	if res.Total != 0 {
		t.Errorf("Total = %d for a case with no evidence", res.Total)
	}
	if res.Photos == nil {
		t.Error("Photos is null; it must be an empty list so the UI can render an empty state")
	}
	if res.Note == "" {
		t.Error("even an empty result must state what a marker means")
	}
}

func TestGeoMap_IsDeterministic(t *testing.T) {
	mux := newTestRouter(t)
	caseID := p21Case(t, mux)

	first, _ := json.Marshal(p21Photos(t, mux, caseID, ""))
	for i := 0; i < 10; i++ {
		got, _ := json.Marshal(p21Photos(t, mux, caseID, ""))
		if !bytes.Equal(got, first) {
			t.Fatalf("run %d returned a different dataset", i)
		}
	}
}

// ---------------- Image bytes ----------------

func p21SourceFileID(t *testing.T, mux http.Handler, caseID, filename string) string {
	t.Helper()
	for _, p := range p21Photos(t, mux, caseID, "").Photos {
		if p.Filename == filename {
			return p.SourceFileID
		}
	}
	t.Fatalf("no marker for %s", filename)
	return ""
}

func p21GetRaw(t *testing.T, mux http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// The forensic requirement: what the browser receives is what is in the
// evidence, byte for byte.
func TestImageContent_ServesTheOriginalBytesUnmodified(t *testing.T) {
	mux := newTestRouter(t)
	caseID := p21Case(t, mux)
	sfID := p21SourceFileID(t, mux, caseID, "south.jpg")

	rec := p21GetRaw(t, mux, "/api/cases/"+caseID+"/images/"+sfID+"/content")
	if rec.Code != http.StatusOK {
		t.Fatalf("content: %d %s", rec.Code, rec.Body.String())
	}

	want := p21Dir()["Users/John Doe/Pictures/south.jpg"]
	got := rec.Body.Bytes()
	if !bytes.Equal(got, want) {
		t.Fatalf("served %d bytes, evidence is %d bytes -- they must be identical", len(got), len(want))
	}
	if h := rec.Header().Get("Content-Type"); h != "image/jpeg" {
		t.Errorf("Content-Type = %q", h)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("the response does not forbid content sniffing")
	}
	// The hash on the wire must be the EVIDENCE hash, so a viewer can
	// state which bytes it showed.
	sum := sha256.Sum256(want)
	if h := rec.Header().Get("X-Tracefall-Evidence-SHA256"); h != hexOf(sum[:]) {
		t.Errorf("evidence hash header = %q, want %s", h, hexOf(sum[:]))
	}
	if !strings.Contains(rec.Header().Get("Cache-Control"), "private") {
		t.Error("evidence must not be cacheable by a shared cache")
	}
}

// Serving an image must not touch the evidence on disk.
func TestImageContent_DoesNotModifyTheEvidence(t *testing.T) {
	mux := newTestRouter(t)
	caseID := p21Case(t, mux)
	sfID := p21SourceFileID(t, mux, caseID, "south.jpg")

	before := p21Photos(t, mux, caseID, "")
	var wantHash string
	for _, p := range before.Photos {
		if p.SourceFileID == sfID {
			wantHash = p.SHA256
		}
	}

	// Fetch the image and a thumbnail, twice each.
	for i := 0; i < 2; i++ {
		p21GetRaw(t, mux, "/api/cases/"+caseID+"/images/"+sfID+"/content")
		p21GetRaw(t, mux, "/api/cases/"+caseID+"/images/"+sfID+"/thumbnail")
	}

	after := p21Photos(t, mux, caseID, "")
	for _, p := range after.Photos {
		if p.SourceFileID == sfID && p.SHA256 != wantHash {
			t.Errorf("the evidence hash changed from %s to %s", wantHash, p.SHA256)
		}
	}
}

func TestImageThumbnail_IsMarkedDerived(t *testing.T) {
	mux := newTestRouter(t)
	caseID := p21Case(t, mux)
	sfID := p21SourceFileID(t, mux, caseID, "south.jpg")

	rec := p21GetRaw(t, mux, "/api/cases/"+caseID+"/images/"+sfID+"/thumbnail")
	if rec.Code != http.StatusOK {
		t.Fatalf("thumbnail: %d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-Tracefall-Derived") != "thumbnail" {
		t.Error("a generated preview must declare itself derived on the wire")
	}
	if src := rec.Header().Get("X-Tracefall-Thumbnail-Source"); src == "" {
		t.Error("the response does not say where the preview came from")
	}
	// It must NOT carry the evidence hash: a preview is not the evidence.
	if rec.Header().Get("X-Tracefall-Evidence-SHA256") != "" {
		t.Error("the thumbnail response carries an evidence hash; it is not evidence")
	}
}

// The cache must live outside every evidence directory, or a generated
// file becomes catalogable as evidence.
func TestImageThumbnail_CacheLivesOutsideTheEvidenceTree(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	caseID := p21Case(t, mux)
	sfID := p21SourceFileID(t, mux, caseID, "south.jpg")

	p21GetRaw(t, mux, "/api/cases/"+caseID+"/images/"+sfID+"/thumbnail")

	cachePath, err := svc.files.ThumbnailPath(caseID, sfID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("the thumbnail was not cached: %v", err)
	}
	if strings.Contains(filepath.ToSlash(cachePath), "/evidence/") {
		t.Errorf("the thumbnail cache is inside an evidence directory: %s", cachePath)
	}
	if !strings.Contains(filepath.ToSlash(cachePath), "/derived/") {
		t.Errorf("the thumbnail is not under the derived directory: %s", cachePath)
	}
}

// A derived artifact must not outlive the evidence it came from.
func TestImageThumbnail_IsRemovedWithItsEvidence(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	caseID := p21Case(t, mux)
	sfID := p21SourceFileID(t, mux, caseID, "south.jpg")

	p21GetRaw(t, mux, "/api/cases/"+caseID+"/images/"+sfID+"/thumbnail")
	cachePath, _ := svc.files.ThumbnailPath(caseID, sfID)
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("precondition: the thumbnail was not cached: %v", err)
	}

	rec := doJSON(t, mux, "DELETE", "/api/cases/"+caseID+"/evidence/"+sfID, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(cachePath); !os.IsNotExist(err) {
		t.Errorf("the cached preview survived the deletion of its evidence: %v", err)
	}
}

// ---------------- Authorization ----------------

// Changing the ID in the URL must not reach another case's evidence.
func TestImageContent_CrossCaseAccessIsRefused(t *testing.T) {
	mux := newTestRouter(t)
	caseA := p21Case(t, mux)
	caseB := mustCreateCase(t, mux, "Phase 21 other case").ID
	sfID := p21SourceFileID(t, mux, caseA, "south.jpg")

	for _, path := range []string{
		"/api/cases/" + caseB + "/images/" + sfID + "/content",
		"/api/cases/" + caseB + "/images/" + sfID + "/thumbnail",
	} {
		rec := p21GetRaw(t, mux, path)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s returned %d, want 404", path, rec.Code)
		}
		if bytes.Contains(rec.Body.Bytes(), []byte{0xFF, 0xD8, 0xFF}) {
			t.Errorf("%s returned image bytes across a case boundary", path)
		}
	}
}

// An ID that exists elsewhere and an ID that never existed must be
// indistinguishable, or the endpoint confirms what other cases hold.
func TestImageContent_UnknownAndForeignIDsAnswerAlike(t *testing.T) {
	mux := newTestRouter(t)
	caseA := p21Case(t, mux)
	caseB := mustCreateCase(t, mux, "Phase 21 probe").ID
	real := p21SourceFileID(t, mux, caseA, "south.jpg")

	foreign := p21GetRaw(t, mux, "/api/cases/"+caseB+"/images/"+real+"/content")
	invented := p21GetRaw(t, mux, "/api/cases/"+caseB+"/images/11111111-2222-3333-4444-555555555555/content")

	if foreign.Code != invented.Code {
		t.Errorf("a foreign ID answers %d and an invented one %d; the difference confirms the file exists",
			foreign.Code, invented.Code)
	}
	if foreign.Body.String() != invented.Body.String() {
		t.Errorf("the two responses differ:\n foreign  %s\n invented %s",
			foreign.Body.String(), invented.Body.String())
	}
}

// The endpoint must not become a general-purpose file reader.
func TestImageContent_NonImageEvidenceIsRefused(t *testing.T) {
	mux := newTestRouter(t)
	caseID := p21Case(t, mux)

	var prefetchID string
	var files struct {
		Items []TriagedSourceFile `json:"items"`
	}
	var cols []model.Collection
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/evidence", nil, &cols)
	if len(cols) == 0 {
		t.Fatal("no collections")
	}
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/evidence/"+cols[0].ID+"/files?page_size=100", nil, &files)
	for _, f := range files.Items {
		if strings.HasSuffix(f.Path, ".pf") {
			prefetchID = f.ID
		}
	}
	if prefetchID == "" {
		t.Fatal("the Prefetch fixture was not catalogued")
	}

	rec := p21GetRaw(t, mux, "/api/cases/"+caseID+"/images/"+prefetchID+"/content")
	if rec.Code != http.StatusNotFound {
		t.Errorf("a Prefetch file was served through the image endpoint: %d", rec.Code)
	}
}

// The browser never supplies a path, but the ID reaches the filesystem,
// so traversal shapes must be refused rather than resolved.
func TestImageContent_TraversalShapedIDsAreRefused(t *testing.T) {
	mux := newTestRouter(t)
	caseID := p21Case(t, mux)

	for _, id := range []string{
		"..", "../..", "..%2f..%2fetc%2fpasswd", "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"/etc/passwd", "....//....//etc/passwd", "a/../../../../etc/passwd",
	} {
		for _, kind := range []string{"content", "thumbnail"} {
			rec := p21GetRaw(t, mux, "/api/cases/"+caseID+"/images/"+id+"/"+kind)
			if rec.Code == http.StatusOK {
				t.Errorf("traversal id %q via %s returned 200", id, kind)
			}
			if bytes.Contains(rec.Body.Bytes(), []byte("root:")) {
				t.Fatalf("traversal id %q read a host file", id)
			}
		}
	}
}

// Deleted evidence keeps its record: the metadata and provenance survive,
// and only the bytes become unavailable.
func TestImageContent_DeletedEvidenceIsGoneNotForgotten(t *testing.T) {
	mux := newTestRouter(t)
	caseID := p21Case(t, mux)
	sfID := p21SourceFileID(t, mux, caseID, "south.jpg")

	if rec := doJSON(t, mux, "DELETE", "/api/cases/"+caseID+"/evidence/"+sfID, nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("delete: %d", rec.Code)
	}

	rec := p21GetRaw(t, mux, "/api/cases/"+caseID+"/images/"+sfID+"/content")
	if rec.Code == http.StatusOK {
		t.Error("a deleted image's bytes were still served")
	}
	if !strings.Contains(rec.Body.String(), "metadata and provenance are unaffected") {
		t.Errorf("the refusal does not explain what survives: %s", rec.Body.String())
	}
}

// ---------------- Basemap ----------------

func TestBasemap_IsOfflineAndIdentifiesItsDataset(t *testing.T) {
	mux := newTestRouter(t)
	var out geo.Outlines
	rec := doJSON(t, mux, "GET", "/api/geo/basemap", nil, &out)
	if rec.Code != http.StatusOK {
		t.Fatalf("basemap: %d", rec.Code)
	}
	if len(out.Rings) == 0 {
		t.Fatal("the basemap has no outlines")
	}
	if out.Dataset.Version == "" || out.Dataset.Source == "" {
		t.Error("the basemap does not identify the dataset it was drawn from")
	}
	// The outlines are a picture, and must say so -- nothing may use
	// them to attribute a coordinate.
	if !strings.Contains(out.Note, "not the boundaries") {
		t.Errorf("Note = %q; it must say these are for drawing only", out.Note)
	}
	if out.SimplifiedToleranceDeg <= 0 {
		t.Error("the basemap does not state how much it was simplified")
	}
	// Every ring is a flat lon/lat run, so an odd length is malformed.
	for i, r := range out.Rings {
		if len(r)%2 != 0 {
			t.Fatalf("ring %d has an odd coordinate count (%d)", i, len(r))
		}
	}
}

// The drawn outlines must never be what a country is decided from.
func TestBasemap_IsNotUsedForAttribution(t *testing.T) {
	// A point well inside Zambia resolves through the FULL polygons.
	full, err := geo.Lookup(-16, 23)
	if err != nil {
		t.Fatal(err)
	}
	if !full.Found {
		t.Fatal("the lookup dataset does not contain the test point")
	}
	if !strings.Contains(full.Method, "offline") {
		t.Errorf("Method = %q", full.Method)
	}
	// The simplified outlines carry no country identity at all, which is
	// the structural guarantee: there is nothing there to attribute with.
	out, err := geo.DrawingOutlines()
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := json.Marshal(out)
	if bytes.Contains(blob, []byte(`"name"`)) || bytes.Contains(blob, []byte(`"iso_a2"`)) {
		t.Error("the drawing outlines carry country identity; they could then be mistaken for the lookup")
	}
}

// newTestRouterWithService returns the router and the Service behind it,
// so a test can check where a generated file actually landed on disk.
func newTestRouterWithService(t *testing.T) (http.Handler, *Service) {
	t.Helper()
	svc := newTestService(t)
	return routerFor(svc), svc
}

// clientHandler adapts an authenticated test client to http.Handler, so
// the same fixture helpers work signed-in and signed-out.
type clientHandler struct{ c *client }

func (h clientHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var body any
	if r.Body != nil {
		raw, _ := io.ReadAll(r.Body)
		if len(raw) > 0 {
			body = json.RawMessage(raw)
		}
	}
	rec := h.c.do(r.Method, r.URL.RequestURI(), body)
	for k, vs := range rec.Header() {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(rec.Code)
	_, _ = w.Write(rec.Body.Bytes())
}

func hexOf(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexdigits[v>>4]
		out[i*2+1] = hexdigits[v&0x0F]
	}
	return string(out)
}

// ---------------- Authentication ----------------

// Image bytes are evidence. With authentication on, an anonymous caller
// must not reach them -- nor the marker dataset, nor the basemap.
func TestGeoMap_RequiresAuthenticationWhenEnabled(t *testing.T) {
	f := newAuthFixture(t, time.Hour)
	f.mustCreateUser(t, "analyst", "correct-horse-battery", model.RoleAnalyst)
	c, rec := f.login(t, "analyst", "correct-horse-battery")
	if rec.Code != http.StatusOK {
		t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
	}

	// The authenticated client drives the same helpers by adapting its
	// session-carrying do() to http.Handler.
	ch := clientHandler{c}
	caseID := p21Case(t, ch)
	sfID := p21SourceFileID(t, ch, caseID, "south.jpg")

	// Authenticated: everything works.
	for _, path := range []string{
		"/api/cases/" + caseID + "/geo/photos",
		"/api/cases/" + caseID + "/images/" + sfID + "/content",
		"/api/cases/" + caseID + "/images/" + sfID + "/thumbnail",
		"/api/geo/basemap",
	} {
		if rec := c.do("GET", path, nil); rec.Code != http.StatusOK {
			t.Errorf("authenticated GET %s = %d", path, rec.Code)
		}
	}

	// Anonymous: refused, and no image bytes leak in the body.
	for _, path := range []string{
		"/api/cases/" + caseID + "/geo/photos",
		"/api/cases/" + caseID + "/images/" + sfID + "/content",
		"/api/cases/" + caseID + "/images/" + sfID + "/thumbnail",
		"/api/geo/basemap",
	} {
		rec := p21GetRaw(t, f.mux, path)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("anonymous GET %s = %d, want 401", path, rec.Code)
		}
		if bytes.Contains(rec.Body.Bytes(), []byte{0xFF, 0xD8, 0xFF}) {
			t.Errorf("anonymous GET %s returned JPEG bytes", path)
		}
	}
}
