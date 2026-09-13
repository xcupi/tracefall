package api

import (
	"regexp"
	"strings"
	"testing"
)

// UI wiring for the Photo Map. These assert what the browser will
// actually render, so a control that exists in the design but never
// reaches the page fails here rather than in front of an analyst.

func TestUI_PhotoMapIsInTheCaseNavigation(t *testing.T) {
	src := string(appJS(t))

	block := src[strings.Index(src, "const CASE_NAV"):]
	block = block[:strings.Index(block, "\n];")]
	if !strings.Contains(block, `key: "geomap"`) {
		t.Fatal("CASE_NAV has no geomap entry, so the page is unreachable from the sidebar")
	}
	if !strings.Contains(block, `label: "Photo Map"`) {
		t.Errorf("the navigation entry is not labelled Photo Map:\n%s", block)
	}
	// It must be case-scoped: the sidebar builds #/cases/{id}/{key}.
	if !strings.Contains(src, "renderGeoMapTab") {
		t.Error("no render function is wired for the geomap tab")
	}
	if !regexp.MustCompile(`case "geomap":\s*\n\s*await renderGeoMapTab`).MatchString(src) {
		t.Error("renderTabContent does not dispatch the geomap tab")
	}
}

// The map's whole forensic job is keeping the observed coordinate apart
// from the derived country.
func TestUI_MapCardSeparatesObservedFromDerived(t *testing.T) {
	src := string(appJS(t))
	fn := uiFunction(t, src, "function geoRenderSide(")

	obs := strings.Index(fn, "Observed &mdash; stored in the file")
	der := strings.Index(fn, "Derived &mdash; computed by Tracefall")
	if obs < 0 || der < 0 {
		t.Fatal("the photo card has no observed/derived section headings")
	}
	if obs > der {
		t.Error("the derived section comes before the observed one")
	}
	observed, derived := fn[obs:der], fn[der:]

	for _, want := range []string{"latitude_raw", "longitude_raw", "exif_taken", "camera_make"} {
		if !strings.Contains(observed, want) {
			t.Errorf("the observed section does not render %s", want)
		}
	}
	for _, want := range []string{"p.country", "country_iso", "country_confidence", "coordinate_precision"} {
		if !strings.Contains(derived, want) {
			t.Errorf("the derived section does not render %s", want)
		}
	}
	if strings.Contains(observed, "p.country") {
		t.Error("the country is rendered as observed; it is derived and is not in the image")
	}
	// Matched across whitespace: the sentence is wrapped in the source.
	derivedClaim := regexp.MustCompile(`country is derived\s+from that\s+coordinate by Tracefall and is not stored in the image`)
	if !derivedClaim.MatchString(fn) {
		t.Error("the card does not state that the country is derived")
	}
}

// Every action the popup promises must be wired.
func TestUI_MapCardOffersTheFourActions(t *testing.T) {
	src := string(appJS(t))
	fn := uiFunction(t, src, "function geoRenderSide(")

	for _, want := range []string{"View image", "Show metadata", "View evidence", "View timeline event"} {
		if !strings.Contains(fn, want) {
			t.Errorf("the photo card has no %q action", want)
		}
	}
	// Evidence and Timeline are real routes, not placeholders.
	if !strings.Contains(fn, "/evidence") || !strings.Contains(fn, "/summary?event=") {
		t.Error("the evidence and timeline actions do not link to real routes")
	}
	// The card must carry provenance the analyst can check.
	for _, want := range []string{"Source path", "Collection", "Evidence SHA-256"} {
		if !strings.Contains(fn, want) {
			t.Errorf("the photo card does not show %s", want)
		}
	}
	// And it must use the shared Copy control rather than a second one.
	if !strings.Contains(fn, "detailCell(") {
		t.Error("the card does not use detailCell, so its values get no Copy control")
	}
}

// A marker is only ever placed at the coordinate the evidence carries.
func TestUI_MarkersUseTheStoredCoordinateOnly(t *testing.T) {
	src := string(appJS(t))
	cluster := uiFunction(t, src, "function geoCluster(")
	if !strings.Contains(cluster, "vp.toScreen(p.longitude, p.latitude)") {
		t.Error("markers are not projected from the photo's own longitude/latitude")
	}
	// Nothing may position a marker from a country, a name or a path.
	for _, forbidden := range []string{"p.country", "p.filename", "p.path"} {
		if strings.Contains(cluster, forbidden) {
			t.Errorf("marker placement reads %s; a position must come only from the coordinate", forbidden)
		}
	}
}

func TestUI_ClusteringIsPresentAndCountsAreShown(t *testing.T) {
	src := string(appJS(t))
	draw := uiFunction(t, src, "function geoDrawMarkers(")

	if !strings.Contains(draw, "geo-cluster") || !strings.Contains(draw, "geo-cluster-count") {
		t.Error("markers are not clustered, or a cluster shows no count")
	}
	if !strings.Contains(draw, "c.photos.length") {
		t.Error("the cluster badge does not show how many photos it holds")
	}
	// Off-screen markers must not become DOM.
	if !strings.Contains(draw, "rect.width + 120") {
		t.Error("markers are not viewport-culled, so a large case would render every one")
	}
	// Photos at identical coordinates cannot be separated by zooming and
	// must be listed instead.
	zoom := uiFunction(t, src, "function geoZoomToCluster(")
	if !strings.Contains(zoom, "allSame") || !strings.Contains(zoom, "geoShowClusterMembers") {
		t.Error("a cluster of photos at one coordinate is not expanded into a list")
	}
}

// Thumbnails must be fetched lazily -- only for markers actually drawn,
// and only once.
func TestUI_ThumbnailsAreFetchedLazilyAndOnce(t *testing.T) {
	src := string(appJS(t))
	preload := uiFunction(t, src, "function geoPreloadThumb(")

	if !strings.Contains(preload, "geoThumbCache.has(p.source_file_id)") {
		t.Error("a thumbnail can be requested more than once per photo")
	}
	draw := uiFunction(t, src, "function geoDrawMarkers(")
	if !strings.Contains(draw, "geoPreloadThumb") {
		t.Error("thumbnails are never requested for drawn markers")
	}
	// A cluster costs one preview, not one per member.
	if strings.Count(draw, "geoPreloadThumb") != 2 {
		t.Errorf("expected exactly two preload calls (single marker, cluster lead); found %d",
			strings.Count(draw, "geoPreloadThumb"))
	}
	// A failed preview degrades to a labelled placeholder.
	tag := uiFunction(t, src, "function geoThumbTag(")
	if !strings.Contains(tag, "geo-thumb-missing") {
		t.Error("a broken or unavailable preview has no placeholder")
	}
}

// The lightbox shows the real evidence bytes and says so.
func TestUI_LightboxServesEvidenceAndStatesItsHash(t *testing.T) {
	src := string(appJS(t))
	fn := uiFunction(t, src, "function geoOpenLightbox(")

	if !strings.Contains(fn, "/content") {
		t.Error("the lightbox does not load the original image endpoint")
	}
	if !strings.Contains(fn, "Original evidence bytes, served unmodified") {
		t.Error("the lightbox does not state that it is showing unmodified evidence")
	}
	if !strings.Contains(fn, "p.sha256") {
		t.Error("the lightbox does not show which bytes it is displaying")
	}
	// Fit / zoom / pan / close.
	for _, want := range []string{`data-lb="fit"`, `data-lb="in"`, `data-lb="out"`, `data-lb="close"`, `data-lb="full"`} {
		if !strings.Contains(fn, want) {
			t.Errorf("the viewer has no %s control", want)
		}
	}
	if !strings.Contains(fn, "pointermove") {
		t.Error("the viewer cannot be panned")
	}
	if !strings.Contains(fn, `e.key === "Escape"`) {
		t.Error("the viewer cannot be closed with Escape")
	}
	// The metadata header, with observed and derived labelled.
	if !strings.Contains(fn, "(observed)") || !strings.Contains(fn, "(derived)") {
		t.Error("the viewer header does not distinguish observed from derived")
	}
	// A failure must preserve the record rather than blanking it.
	if !strings.Contains(fn, "metadata and provenance are unaffected") {
		t.Error("a failed image load does not explain what survives")
	}
	// Nothing may decode the evidence into a buffer.
	if strings.Contains(fn, "canvas") || strings.Contains(fn, "createImageBitmap") {
		t.Error("the viewer decodes the image itself; it should use ordinary browser rendering")
	}
}

// Map and Timeline are two views of ONE event.
func TestUI_MapAndTimelineReferenceTheSameEvent(t *testing.T) {
	src := string(appJS(t))

	card := uiFunction(t, src, "function geoRenderSide(")
	if !strings.Contains(card, "summary?event=${encodeURIComponent(") {
		t.Error("the map does not link to the timeline event by id")
	}
	panel := uiFunction(t, src, "function imageGeoPanel(")
	if !strings.Contains(panel, "data-geo-focus") || !strings.Contains(panel, "/geomap") {
		t.Error("a timeline GPS event offers no way back to the map")
	}
	// The map must select the event it was sent, not a lookalike.
	if !strings.Contains(src, "geoState.photos.some((p) => p.event_id === target)") {
		t.Error("the map does not focus the event the timeline link named")
	}
}

// The empty state must be an explanation, never a blank map.
func TestUI_EmptyStateExplainsRatherThanShowingABlankMap(t *testing.T) {
	src := string(appJS(t))
	fn := uiFunction(t, src, "function geoMapShell(")

	if !strings.Contains(fn, "No geolocated photos found in this case.") {
		t.Error("the empty state does not use the required wording")
	}
	if !strings.Contains(fn, "images_without_gps") {
		t.Error("the empty state does not say how many images carry no coordinate")
	}
	if !strings.Contains(fn, "nothing is placed on the map at a guessed position") {
		t.Error("the empty state does not rule out guessed positions")
	}
	// Images without GPS must never become markers.
	shell := uiFunction(t, src, "function geoFilterBar(")
	if !strings.Contains(shell, "Showing only images with GPS") {
		t.Error("the filter bar does not state that only GPS-bearing images are shown")
	}
}

// Photos with no timestamp must be shown, and must not be given an
// invented position in a sequence.
func TestUI_UntimedPhotosAreNotOrderedIntoASequence(t *testing.T) {
	src := string(appJS(t))
	sort := uiFunction(t, src, "function geoSortPhotos(")

	if !strings.Contains(sort, "if (a.timestamp) return -1") {
		t.Error("untimed photos are not separated from timed ones when sorting")
	}
	list := uiFunction(t, src, "function geoSortedList(")
	if !strings.Contains(list, "not placed in a sequence the evidence does not support") {
		t.Error("the list does not explain how untimed photos are ordered")
	}
	// All three orderings the requirement asks for.
	for _, want := range []string{`case "filename"`, `case "country"`} {
		if !strings.Contains(sort, want) {
			t.Errorf("sorting does not offer %s", want)
		}
	}
}

// The basemap is drawn from the bundled dataset, with no tile request.
func TestUI_MapMakesNoExternalRequest(t *testing.T) {
	src := string(appJS(t))
	start := strings.Index(src, "// ---------------- Photo Map (Phase 21)")
	end := strings.Index(src[start:], "// ---------------- Router")
	if start < 0 || end < 0 {
		t.Fatal("could not isolate the Photo Map section")
	}
	section := src[start : start+end]

	for _, forbidden := range []string{
		"tile.openstreetmap", "https://", "http://", "mapbox", "google.com/maps", "cdn.",
	} {
		if strings.Contains(section, forbidden) {
			t.Errorf("the map section references an external resource: %q", forbidden)
		}
	}
	if !strings.Contains(section, "/geo/basemap") {
		t.Error("the map does not load the bundled offline basemap")
	}
}
