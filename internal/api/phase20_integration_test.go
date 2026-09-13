package api

import (
	"net/http"
	"strings"
	"testing"

	"tracefall/internal/exif/exifgen"
	"tracefall/internal/model"
)

// End-to-end tests for Phase 20's two artifacts -- FileZilla connection
// evidence and image EXIF/GPS metadata -- through ingestion, the
// Timeline, its filters, and provenance.

const p20RecentServers = `<?xml version="1.0" encoding="UTF-8"?>
<FileZilla3 version="3.53.1" platform="windows">
	<RecentServers>
		<Server>
			<Host>192.168.1.20</Host>
			<Port>21</Port>
			<Protocol>0</Protocol>
			<Type>0</Type>
			<User>kali</User>
			<Logontype>2</Logontype>
			<PasvMode>MODE_DEFAULT</PasvMode>
			<EncodingType>Auto</EncodingType>
			<BypassProxy>0</BypassProxy>
		</Server>
	</RecentServers>
</FileZilla3>`

// p20FileZillaSettings is the OTHER XML file in the same directory. It
// shares the FileZilla3 root and must never be claimed as connection
// evidence.
const p20FileZillaSettings = `<?xml version="1.0"?>
<FileZilla3 version="3.53.1" platform="windows">
	<Settings>
		<Setting name="Use Pasv mode">1</Setting>
		<Setting name="External address resolver">http://ip.filezilla-project.org/ip.php</Setting>
	</Settings>
</FileZilla3>`

func p20Photo() []byte {
	return exifgen.Build(exifgen.Spec{
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
	})
}

// p20Dir is the shape a real profile has: FileZilla's two XML files side
// by side, a located photograph, an image with no EXIF, and an unrelated
// artifact so a filter has something to exclude.
func p20Dir() map[string][]byte {
	return map[string][]byte{
		"Users/John Doe/AppData/Roaming/FileZilla/recentservers.xml": []byte(p20RecentServers),
		"Users/John Doe/AppData/Roaming/FileZilla/filezilla.xml":     []byte(p20FileZillaSettings),
		"Users/John Doe/Pictures/Contact/20210429_152043.jpg":        p20Photo(),
		"Users/John Doe/Pictures/screenshot.jpg": exifgen.Build(
			exifgen.Spec{Width: 800, Height: 600, NoEXIF: true}),
		"Windows/Prefetch/UPDATER.EXE-11223344.pf": p15Prefetch(),
	}
}

func p20Case(t *testing.T, mux http.Handler) (string, DiscoverResult) {
	t.Helper()
	c := mustCreateCase(t, mux, "Phase 20 "+t.Name())
	disc := discoverBinaryDir(t, mux, c.ID, p20Dir())
	imp := importAllFrom(t, mux, c.ID, disc)
	if len(imp.ParseFailures) != 0 {
		t.Fatalf("fixture failed to parse: %+v", imp.ParseFailures)
	}
	return c.ID, disc
}

// ---------------- Classification ----------------

// The settings file shares recentservers.xml's root element. Claiming it
// would catalogue configuration as connection evidence and then fail it
// at import.
func TestPhase20_SettingsFileIsNotClaimedAsConnectionEvidence(t *testing.T) {
	mux := newTestRouter(t)
	_, disc := p20Case(t, mux)

	for _, f := range disc.SourceFiles {
		switch {
		case strings.HasSuffix(f.Path, "recentservers.xml"):
			if f.ArtifactType != model.ArtifactFileZillaServer {
				t.Errorf("recentservers.xml classified as %q, want %q", f.ArtifactType, model.ArtifactFileZillaServer)
			}
			if !f.Supported {
				t.Error("recentservers.xml is not marked supported")
			}
		case strings.HasSuffix(f.Path, "filezilla.xml"):
			if f.ArtifactType == model.ArtifactFileZillaServer {
				t.Error("filezilla.xml, which holds settings, was claimed as connection evidence")
			}
		}
	}
}

func TestPhase20_ImagesAreClassifiedByContent(t *testing.T) {
	mux := newTestRouter(t)
	_, disc := p20Case(t, mux)

	found := 0
	for _, f := range disc.SourceFiles {
		if !strings.HasSuffix(f.Path, ".jpg") {
			continue
		}
		found++
		if f.ArtifactType != model.ArtifactImageMetadata {
			t.Errorf("%s classified as %q, want %q", f.Path, f.ArtifactType, model.ArtifactImageMetadata)
		}
	}
	if found != 2 {
		t.Fatalf("classified %d images, want 2", found)
	}
}

// Adding the broadest content detector in the registry must not take
// files away from more specific parsers.
func TestPhase20_ExistingClassificationIsUnchanged(t *testing.T) {
	mux := newTestRouter(t)
	_, disc := p20Case(t, mux)

	for _, f := range disc.SourceFiles {
		if strings.HasSuffix(f.Path, ".pf") && f.ArtifactType != model.ArtifactPrefetch {
			t.Errorf("Prefetch file classified as %q", f.ArtifactType)
		}
	}
}

// A cached response body really is a JPEG, and it is already catalogued
// as browser-cache evidence. The image parser must not take it: on one
// real image that moved 84 files out of the cache picture.
func TestPhase20_CachedImagesStayBrowserCacheEvidence(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Phase 20 cache")

	cachePath := "Users/John Doe/AppData/Local/Google/Chrome/User Data/Default/Cache/f_000042"
	files := map[string][]byte{
		cachePath: p20Photo(),
		// The same bytes outside a cache directory MUST be claimed, so
		// this proves the path scope and not merely that nothing matched.
		"Users/John Doe/Pictures/holiday.jpg": p20Photo(),
	}
	disc := discoverBinaryDir(t, mux, c.ID, files)

	got := map[string]string{}
	for _, f := range disc.SourceFiles {
		got[f.Path] = f.ArtifactType
	}
	if got[cachePath] == model.ArtifactImageMetadata {
		t.Errorf("a cached response body was claimed as a standalone image")
	}
	if got[cachePath] == "" {
		t.Error("the cached body lost its classification entirely")
	}
	if got["Users/John Doe/Pictures/holiday.jpg"] != model.ArtifactImageMetadata {
		t.Errorf("an image outside a cache directory was classified as %q; the path scope is too broad",
			got["Users/John Doe/Pictures/holiday.jpg"])
	}
}

// ---------------- Timeline ----------------

func TestPhase20_ArtifactsAreOfferedAsTimelineFilters(t *testing.T) {
	mux := newTestRouter(t)
	caseID, _ := p20Case(t, mux)

	var facets EventFacetsResponse
	if rec := doJSON(t, mux, "GET", "/api/cases/"+caseID+"/events/facets", nil, &facets); rec.Code != http.StatusOK {
		t.Fatalf("facets: %d", rec.Code)
	}

	want := map[string]string{
		model.ArtifactFileZillaServer: "FileZilla server entry",
		model.ArtifactImageMetadata:   "Image metadata (EXIF)",
		model.ArtifactImageGPS:        "Image location (EXIF GPS)",
	}
	got := map[string]string{}
	for _, a := range facets.ArtifactTypes {
		got[a.Value] = a.Label
	}
	for artifact, label := range want {
		if got[artifact] == "" {
			t.Errorf("%s is not offered in the artifact filter", artifact)
			continue
		}
		if got[artifact] != label {
			t.Errorf("%s is labelled %q, want %q", artifact, got[artifact], label)
		}
		// The raw parser/implementation name must not be the label.
		if strings.Contains(got[artifact], "@") || got[artifact] == artifact {
			t.Errorf("%s is labelled with an implementation name: %q", artifact, got[artifact])
		}
	}

	wantEvents := []string{
		model.EventFileZillaServerEntry,
		model.EventImageMetadataRecorded,
		model.EventImageGPSRecorded,
	}
	offered := map[string]bool{}
	for _, e := range facets.EventTypes {
		offered[e.Value] = true
	}
	for _, et := range wantEvents {
		if !offered[et] {
			t.Errorf("event type %s is not offered in the event-type filter", et)
		}
	}
}

func TestPhase20_ArtifactFilterReturnsOnlyItsOwnEvents(t *testing.T) {
	mux := newTestRouter(t)
	caseID, _ := p20Case(t, mux)

	all := searchEvents(t, mux, caseID, vals("page_size", "100"))
	if all.Total == 0 {
		t.Fatal("the case has no events")
	}

	for _, artifact := range []string{
		model.ArtifactFileZillaServer,
		model.ArtifactImageMetadata,
		model.ArtifactImageGPS,
	} {
		got := searchEvents(t, mux, caseID, vals("artifact_type", artifact, "page_size", "100"))
		if got.Total == 0 {
			t.Errorf("filtering by %s returned nothing", artifact)
			continue
		}
		for _, e := range got.Items {
			if e.ArtifactType != artifact {
				t.Errorf("filtering by %s returned a %q event", artifact, e.ArtifactType)
			}
		}
		if got.Total >= all.Total {
			t.Errorf("filtering by %s did not narrow the timeline", artifact)
		}
	}

	// The two image artifacts must be separable: an image with no GPS
	// must not appear under the GPS filter.
	gps := searchEvents(t, mux, caseID, vals("artifact_type", model.ArtifactImageGPS, "page_size", "100"))
	if gps.Total != 1 {
		t.Errorf("the GPS filter returned %d events; only one of the two images carries a coordinate", gps.Total)
	}
	meta := searchEvents(t, mux, caseID, vals("artifact_type", model.ArtifactImageMetadata, "page_size", "100"))
	if meta.Total != 2 {
		t.Errorf("the image-metadata filter returned %d events, want 2", meta.Total)
	}
}

func TestPhase20_FileZillaServerReachesTheTimelineWithItsAddress(t *testing.T) {
	mux := newTestRouter(t)
	caseID, _ := p20Case(t, mux)

	got := searchEvents(t, mux, caseID, vals("artifact_type", model.ArtifactFileZillaServer, "page_size", "50"))
	if got.Total != 1 {
		t.Fatalf("got %d FileZilla events, want 1", got.Total)
	}
	ev := got.Items[0]

	if ev.Extra["server_ipv4"] != "192.168.1.20" {
		t.Errorf("server_ipv4 = %q", ev.Extra["server_ipv4"])
	}
	if ev.Extra["protocol"] != "FTP" {
		t.Errorf("protocol = %q", ev.Extra["protocol"])
	}
	if ev.Extra["server_port"] != "21" {
		t.Errorf("server_port = %q", ev.Extra["server_port"])
	}
	if ev.Extra["server_username"] != "kali" {
		t.Errorf("server_username = %q", ev.Extra["server_username"])
	}
	if !ev.Timestamp.IsZero() {
		t.Errorf("Timestamp = %v; the artifact records no time", ev.Timestamp)
	}
	if ev.SourceFileID == "" || ev.CollectionID == "" {
		t.Error("the event lost its provenance")
	}
}

func TestPhase20_ImageGPSReachesTheTimelineWithObservedAndDerivedValues(t *testing.T) {
	mux := newTestRouter(t)
	caseID, _ := p20Case(t, mux)

	got := searchEvents(t, mux, caseID, vals("artifact_type", model.ArtifactImageGPS, "page_size", "50"))
	if got.Total != 1 {
		t.Fatalf("got %d GPS events, want 1", got.Total)
	}
	ev := got.Items[0]

	if ev.Extra["gps_latitude_raw"] != `16° 0' 0" S` {
		t.Errorf("gps_latitude_raw = %q", ev.Extra["gps_latitude_raw"])
	}
	if ev.Extra["gps_coordinates"] != "-16, 23" {
		t.Errorf("gps_coordinates = %q", ev.Extra["gps_coordinates"])
	}
	if ev.Extra["country"] != "Zambia" {
		t.Errorf("country = %q", ev.Extra["country"])
	}
	if !strings.Contains(ev.Extra["country_derivation"], "DERIVED") {
		t.Errorf("the country must be marked derived: %q", ev.Extra["country_derivation"])
	}
	if ev.Extra["geolocation_dataset"] == "" || ev.Extra["geolocation_method"] == "" {
		t.Error("the dataset and method must reach the timeline")
	}
	if ev.FilePath != "20210429_152043.jpg" {
		t.Errorf("FilePath = %q", ev.FilePath)
	}
}

// ---------------- Security ----------------

// A stored FileZilla password must not reach the timeline, its search
// index, or any event field.
func TestPhase20_FileZillaPasswordIsNotSearchableOrStored(t *testing.T) {
	const secret = "P20SECRETPASSWORD"
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Phase 20 password")

	withPass := strings.Replace(p20RecentServers,
		"<Logontype>2</Logontype>",
		`<Logontype>1</Logontype><Pass encoding="base64">`+secret+`</Pass>`, 1)
	files := map[string][]byte{
		"Users/John Doe/AppData/Roaming/FileZilla/recentservers.xml": []byte(withPass),
	}
	disc := discoverBinaryDir(t, mux, c.ID, files)
	if imp := importAllFrom(t, mux, c.ID, disc); len(imp.ParseFailures) != 0 {
		t.Fatalf("import failed: %+v", imp.ParseFailures)
	}

	// The password must not be findable by searching for it.
	hits := searchEvents(t, mux, c.ID, vals("q", secret, "page_size", "50"))
	if hits.Total != 0 {
		t.Errorf("searching for the password returned %d events", hits.Total)
	}

	got := searchEvents(t, mux, c.ID, vals("artifact_type", model.ArtifactFileZillaServer, "page_size", "50"))
	if got.Total != 1 {
		t.Fatalf("got %d events", got.Total)
	}
	ev := got.Items[0]
	if ev.Extra["password_present"] != "true" {
		t.Errorf("password_present = %q; the presence must still be reported", ev.Extra["password_present"])
	}
	for k, v := range ev.Extra {
		if strings.Contains(v, secret) {
			t.Errorf("the password reached extra[%q]", k)
		}
	}
}

// These are observations. Neither may become a Finding on its own.
func TestPhase20_NeitherArtifactCreatesFindings(t *testing.T) {
	mux := newTestRouter(t)
	caseID, _ := p20Case(t, mux)

	if rec := doJSON(t, mux, "POST", "/api/cases/"+caseID+"/analyze", nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("analyze: %d %s", rec.Code, rec.Body.String())
	}

	var findings []model.Finding
	if rec := doJSON(t, mux, "GET", "/api/cases/"+caseID+"/findings", nil, &findings); rec.Code != http.StatusOK {
		t.Fatalf("findings: %d", rec.Code)
	}
	for _, f := range findings {
		for _, artifact := range []string{"filezilla", "image_gps", "image_metadata"} {
			if strings.Contains(strings.ToLower(f.Title+f.Description), artifact) {
				t.Errorf("a finding was raised from a Phase 20 observation: %q", f.Title)
			}
		}
	}
}
