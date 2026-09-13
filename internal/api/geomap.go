package api

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"tracefall/internal/geo"
	"tracefall/internal/model"
	"tracefall/internal/store"
	"tracefall/internal/thumb"
)

// The Photo Map's server side.
//
// # It creates no evidence
//
// Every marker on the map IS an existing image_gps event, read back out
// of the event store. Nothing here parses an image, derives a
// coordinate, or writes a row: the map is a second VIEW of events the
// EXIF parser already produced, which is why a marker and its timeline
// row can never disagree.
//
// # Serving image bytes
//
// The browser never names a path. It names a SOURCE FILE ID, which is
// resolved against the case in the URL and refused unless the file
// belongs to it -- the same check SourceFileProvenanceFor makes. The
// path is then built from the collection's own evidence directory and
// re-verified to be inside it. A caller who edits the ID in the URL gets
// a 404, whether the ID is another case's, invented, or deleted.

// ErrImageUnavailable reports that an authorized image's bytes cannot be
// served -- not imported, deleted, or missing from disk. Distinct from
// ErrSourceFileNotFound so the UI can keep showing the metadata and
// provenance for evidence whose bytes are gone, rather than pretending
// the record does not exist.
var ErrImageUnavailable = errors.New("image bytes are not available")

// ErrNotAnImage reports that a source file exists in this case but is
// not an image artifact. It stops the image endpoints from becoming a
// general-purpose file reader for anything catalogued in a case.
var ErrNotAnImage = errors.New("this evidence file is not an image")

// GeoPhoto is one map marker: an image whose EXIF recorded a coordinate.
//
// Observed and derived stay separate here exactly as they do on the
// event, because the map is where they are most likely to be conflated
// -- a country name rendered beside a pin looks like something the
// camera wrote.
type GeoPhoto struct {
	// EventID is the image_gps event this marker IS. The map creates no
	// event of its own; this is the identifier the Timeline uses.
	EventID string `json:"event_id"`
	// MetadataEventID is the image_metadata event from the same file,
	// when one is present, so "show metadata" can reach the full EXIF
	// record rather than only the GPS subset.
	MetadataEventID string `json:"metadata_event_id,omitempty"`
	// SourceFileID addresses the evidence file for image and provenance
	// requests. It is an opaque handle, never a path.
	SourceFileID string `json:"source_file_id"`
	CollectionID string `json:"collection_id"`
	// CollectionLabel is the human-facing "Collection #2", so the card
	// does not have to show a UUID to say where evidence came from.
	CollectionLabel string `json:"collection_label,omitempty"`

	Filename string `json:"filename"`
	// Path is the file's location in the evidence, shown as context. It
	// is not proof the image was opened, copied or created there.
	Path string `json:"path"`

	// OBSERVED -- read out of the file.
	Latitude       float64 `json:"latitude"`
	Longitude      float64 `json:"longitude"`
	LatitudeRaw    string  `json:"latitude_raw,omitempty"`
	LongitudeRaw   string  `json:"longitude_raw,omitempty"`
	EXIFTaken      string  `json:"exif_taken,omitempty"`
	CameraMake     string  `json:"camera_make,omitempty"`
	CameraModel    string  `json:"camera_model,omitempty"`
	ImageDimension string  `json:"image_dimensions,omitempty"`

	// DERIVED -- computed by Tracefall from the coordinate above.
	Country             string `json:"country,omitempty"`
	CountryISO          string `json:"country_iso,omitempty"`
	CountryConfidence   string `json:"country_confidence,omitempty"`
	CoordinatePrecision string `json:"coordinate_precision,omitempty"`

	// Timestamp is the event's own time, or nil when the artifact
	// recorded none. A photo with no time still appears on the map; it
	// simply cannot be ordered, and nothing invents an order for it.
	Timestamp *time.Time `json:"timestamp,omitempty"`

	// SHA256 is Tracefall's own hash of the evidence file, so a viewer
	// can state which bytes it is showing.
	SHA256 string `json:"sha256,omitempty"`
	// Available reports whether the image bytes can actually be served.
	// False keeps the marker and its metadata on the map with a clear
	// "image unavailable" state, rather than dropping evidence because
	// its pixels are missing.
	Available   bool   `json:"available"`
	Unavailable string `json:"unavailable_reason,omitempty"`
}

// GeoPhotoResult is the map's dataset.
type GeoPhotoResult struct {
	Photos []GeoPhoto `json:"photos"`
	// Total is how many GPS-bearing images the case holds, before
	// paging. Countries and Collections are the facet values present in
	// the WHOLE set, so a filter dropdown does not shrink as it is used.
	Total       int      `json:"total"`
	Countries   []string `json:"countries"`
	Collections []string `json:"collections"`
	// ImagesWithoutGPS is how many image artifacts the case holds that
	// carry no usable coordinate. They are deliberately NOT on the map,
	// and saying how many there are is what stops the map reading as
	// "these are all the images".
	ImagesWithoutGPS int `json:"images_without_gps"`
	// Note states what a marker means.
	Note string `json:"note"`
}

// GeoPhotoFilter narrows the map's dataset. Every field is optional; the
// zero value returns every GPS-bearing image in the case.
type GeoPhotoFilter struct {
	Countries     []string
	CollectionIDs []string
	Filename      string
	From, To      time.Time
	Limit, Offset int
}

// maxGeoPhotos bounds one page of markers. A map cannot usefully show
// more at once, and the browser should not be handed more DOM than it
// can cluster.
const maxGeoPhotos = 2000

// GeoPhotos returns the case's GPS-bearing images as map markers.
//
// It reads image_gps events -- the events the EXIF parser already
// produced -- and never re-parses an image. The query is case-scoped by
// store.SearchEvents, which refuses an empty case entirely, so a marker
// from another case cannot appear.
func (s *Service) GeoPhotos(caseID string, f GeoPhotoFilter) (GeoPhotoResult, error) {
	if _, err := s.GetCase(caseID); err != nil {
		return GeoPhotoResult{}, err
	}

	events, _, err := s.store.SearchEvents(store.EventQuery{
		CaseID:        caseID,
		ArtifactTypes: []string{model.ArtifactImageGPS},
		CollectionIDs: f.CollectionIDs,
		From:          f.From,
		To:            f.To,
	})
	if err != nil {
		return GeoPhotoResult{}, err
	}

	// The metadata event from the same file, so "show metadata" can open
	// the full EXIF record. Looked up once rather than per marker.
	metaByFile := map[string]string{}
	metaEvents, _, err := s.store.SearchEvents(store.EventQuery{
		CaseID:        caseID,
		ArtifactTypes: []string{model.ArtifactImageMetadata},
	})
	if err != nil {
		return GeoPhotoResult{}, err
	}
	for _, e := range metaEvents {
		if _, seen := metaByFile[e.SourceFileID]; !seen {
			metaByFile[e.SourceFileID] = e.ID
		}
	}

	collectionLabels, err := s.collectionLabels(caseID)
	if err != nil {
		return GeoPhotoResult{}, err
	}

	out := GeoPhotoResult{
		Note: "Each marker is an image whose EXIF GPS block recorded a coordinate. The position is what the " +
			"image CONTAINS -- not a sighting: metadata travels with a copied file and can be edited. Any " +
			"country shown is DERIVED by Tracefall from the coordinate and is not stored in the image.",
	}

	countrySet := map[string]bool{}
	collectionSet := map[string]bool{}
	sfCache := map[string]model.SourceFile{}

	for _, e := range events {
		p, ok := s.geoPhotoFrom(e, metaByFile, collectionLabels, sfCache)
		if !ok {
			continue
		}
		if p.Country != "" {
			countrySet[p.Country] = true
		}
		if p.CollectionID != "" {
			collectionSet[p.CollectionID] = true
		}
		if len(f.Countries) > 0 && !containsFold(f.Countries, p.Country) {
			continue
		}
		// Matched here rather than through store.EventQuery.Filename,
		// whose field-scoped search reads the process-name columns -- an
		// image event populates none of them, so that filter silently
		// matched nothing. The marker's own name and path are what an
		// analyst means by "filename" on this screen.
		if f.Filename != "" && !matchesFilename(p, f.Filename) {
			continue
		}
		out.Photos = append(out.Photos, p)
	}

	// Deterministic order before paging: newest first, then filename, so
	// two identical requests always return the same page. Photos with no
	// timestamp sort after those that have one -- they are not placed in
	// an invented position among them.
	sort.SliceStable(out.Photos, func(i, j int) bool {
		a, b := out.Photos[i], out.Photos[j]
		switch {
		case a.Timestamp != nil && b.Timestamp != nil && !a.Timestamp.Equal(*b.Timestamp):
			return a.Timestamp.After(*b.Timestamp)
		case a.Timestamp != nil && b.Timestamp == nil:
			return true
		case a.Timestamp == nil && b.Timestamp != nil:
			return false
		}
		if a.Filename != b.Filename {
			return a.Filename < b.Filename
		}
		return a.EventID < b.EventID
	})

	out.Total = len(out.Photos)
	out.Countries = sortedKeys(countrySet)
	out.Collections = sortedKeys(collectionSet)

	limit := f.Limit
	if limit <= 0 || limit > maxGeoPhotos {
		limit = maxGeoPhotos
	}
	if f.Offset > 0 {
		if f.Offset >= len(out.Photos) {
			out.Photos = nil
		} else {
			out.Photos = out.Photos[f.Offset:]
		}
	}
	if len(out.Photos) > limit {
		out.Photos = out.Photos[:limit]
	}
	if out.Photos == nil {
		out.Photos = []GeoPhoto{}
	}

	// How many images are NOT here. Counted from the metadata events,
	// one per image, minus those that produced a GPS event.
	withGPS := map[string]bool{}
	for _, e := range events {
		withGPS[e.SourceFileID] = true
	}
	for _, e := range metaEvents {
		if !withGPS[e.SourceFileID] {
			out.ImagesWithoutGPS++
		}
	}

	return out, nil
}

// geoPhotoFrom turns one image_gps event into a marker. An event whose
// coordinate cannot be read back as two numbers is SKIPPED rather than
// plotted at a default position -- a marker at 0,0 is a fabricated
// location.
func (s *Service) geoPhotoFrom(e model.Event, metaByFile map[string]string,
	collectionLabels map[string]string, sfCache map[string]model.SourceFile) (GeoPhoto, bool) {

	lat, okLat := parseCoord(e.Extra["gps_latitude"])
	lon, okLon := parseCoord(e.Extra["gps_longitude"])
	if !okLat || !okLon {
		return GeoPhoto{}, false
	}

	p := GeoPhoto{
		EventID:             e.ID,
		MetadataEventID:     metaByFile[e.SourceFileID],
		SourceFileID:        e.SourceFileID,
		CollectionID:        e.CollectionID,
		CollectionLabel:     collectionLabels[e.CollectionID],
		Filename:            e.FilePath,
		Latitude:            lat,
		Longitude:           lon,
		LatitudeRaw:         e.Extra["gps_latitude_raw"],
		LongitudeRaw:        e.Extra["gps_longitude_raw"],
		EXIFTaken:           e.Extra["exif_datetimeoriginal"],
		CameraMake:          e.Extra["camera_make"],
		CameraModel:         e.Extra["camera_model"],
		ImageDimension:      e.Extra["image_dimensions"],
		Country:             e.Extra["country"],
		CountryISO:          e.Extra["country_iso_a2"],
		CountryConfidence:   e.Extra["country_confidence"],
		CoordinatePrecision: e.Extra["gps_precision"],
	}
	if !e.Timestamp.IsZero() {
		t := e.Timestamp
		p.Timestamp = &t
	}

	sf, ok := sfCache[e.SourceFileID]
	if !ok {
		var err error
		sf, err = s.store.GetSourceFile(e.SourceFileID)
		if err == nil {
			sfCache[e.SourceFileID] = sf
		}
	}
	if sf.ID != "" {
		p.Path = sf.Path
		p.SHA256 = sf.SHA256
		if p.Filename == "" {
			p.Filename = sf.OriginalFilename
		}
	}

	// Whether the bytes can be served is decided the same way the image
	// endpoint decides it, so the card never offers "View image" for a
	// picture that will 404.
	if _, err := s.imagePath(e.CaseID, e.SourceFileID); err != nil {
		p.Available = false
		p.Unavailable = imageUnavailableReason(err)
	} else {
		p.Available = true
	}
	return p, true
}

func imageUnavailableReason(err error) string {
	switch {
	case errors.Is(err, ErrImageUnavailable):
		return "this image's bytes are not on disk: the evidence file was deleted, or was catalogued " +
			"but never imported. Its metadata and provenance are unaffected."
	case errors.Is(err, ErrSourceFileNotFound):
		return "the evidence record for this image is no longer present in this case"
	default:
		return "this image's bytes cannot be read"
	}
}

// imagePath resolves an image source file to its bytes on disk, and is
// the single authorization point for every image the API serves.
//
// Three independent checks, because this is the one place a browser's
// input reaches the filesystem:
//
//  1. The source file must belong to THIS case. An ID from another case
//     is refused as not-found -- the same answer an invented ID gets, so
//     the response cannot be used to probe for other cases' evidence.
//  2. It must be an IMAGE artifact. Without this the endpoint would
//     serve any catalogued file -- a registry hive, a memory dump --
//     through an <img> tag.
//  3. The resolved path must lie inside the collection's own evidence
//     directory, re-verified after joining. sf.Path comes from a
//     catalogued archive entry and is already validated on the way in;
//     this is the second layer, because a path that escapes here reads
//     arbitrary host files.
func (s *Service) imagePath(caseID, sourceFileID string) (string, error) {
	sf, err := s.store.GetSourceFile(sourceFileID)
	if err != nil || sf.CaseID != caseID {
		return "", ErrSourceFileNotFound
	}
	if sf.ArtifactType != model.ArtifactImageMetadata && sf.ArtifactType != model.ArtifactImageGPS {
		return "", ErrNotAnImage
	}
	if sf.DeletedAt != nil {
		return "", ErrImageUnavailable
	}

	// The collection's OWN recorded evidence directory, not an assumed
	// layout. An uploaded or AD1 collection extracts into a directory
	// Tracefall manages; a local-path collection's evidence stays
	// wherever the investigator pointed Tracefall and is never copied
	// (see docs/ad1-ingestion.md). Assuming the managed path reported
	// every local-path image as "bytes not on disk" while the file sat
	// there readable.
	//
	// This value comes from the collection row, never from the request,
	// so using it does not widen what a caller can reach: the caller
	// still only supplies a source file ID, and it still has to belong
	// to this case.
	col, err := s.store.GetCollection(sf.CollectionID)
	if err != nil || col.CaseID != caseID {
		return "", ErrSourceFileNotFound
	}
	base := col.EvidenceDirectory
	if base == "" {
		base = s.files.EvidenceDir(caseID, sf.CollectionID)
	}
	evidenceDir, err := filepath.Abs(base)
	if err != nil {
		return "", ErrImageUnavailable
	}
	full := filepath.Join(evidenceDir, filepath.FromSlash(sf.Path))
	rel, relErr := filepath.Rel(evidenceDir, full)
	if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) ||
		filepath.IsAbs(rel) {
		return "", ErrImageUnavailable
	}
	info, err := os.Stat(full)
	if err != nil || info.IsDir() {
		return "", ErrImageUnavailable
	}
	return full, nil
}

// ImageFile returns an authorized image's path on disk and its evidence
// record, for a handler to stream. The bytes are served EXACTLY as
// stored: nothing re-encodes, rotates, or strips metadata from evidence
// on its way to a browser.
func (s *Service) ImageFile(caseID, sourceFileID string) (string, model.SourceFile, error) {
	path, err := s.imagePath(caseID, sourceFileID)
	if err != nil {
		return "", model.SourceFile{}, err
	}
	sf, err := s.store.GetSourceFile(sourceFileID)
	if err != nil {
		return "", model.SourceFile{}, ErrSourceFileNotFound
	}
	return path, sf, nil
}

// ImageThumbnail returns a small preview of an authorized image,
// generating it on first request and caching it under the case's derived
// directory.
//
// Lazy by design: a collection of ten thousand photographs costs nothing
// until someone looks at one. The cache lives OUTSIDE every evidence
// directory (see casefiles.DerivedDir), so a generated file is never
// catalogued, hashed or mistaken for evidence.
func (s *Service) ImageThumbnail(caseID, sourceFileID string) (thumb.Result, error) {
	path, err := s.imagePath(caseID, sourceFileID)
	if err != nil {
		return thumb.Result{}, err
	}

	cachePath, err := s.files.ThumbnailPath(caseID, sourceFileID)
	if err != nil {
		return thumb.Result{}, err
	}
	if cached, err := os.ReadFile(cachePath); err == nil && len(cached) > 0 {
		return thumb.Result{
			JPEG:   cached,
			Source: "cache",
			Note: "a previously generated preview for this evidence file, cached outside the evidence " +
				"directory. The evidence itself is unchanged.",
		}, nil
	}

	res, err := thumb.Generate(path, thumb.DefaultLimits())
	if err != nil {
		return thumb.Result{}, err
	}

	// A cache write that fails is not an error the analyst needs: the
	// preview was produced and can be produced again.
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err == nil {
		_ = os.WriteFile(cachePath, res.JPEG, 0o644)
	}
	return res, nil
}

// Basemap returns the simplified country outlines the map draws.
//
// Offline: they come from the boundary dataset already compiled into the
// binary, so the map needs no tile server, no API key and no network
// request. They are a PICTURE and nothing more -- the country on a
// marker is decided server-side against the full polygons (see
// internal/geo), never against these.
func (s *Service) Basemap() (geo.Outlines, error) {
	return geo.DrawingOutlines()
}

func (s *Service) collectionLabels(caseID string) (map[string]string, error) {
	cols, err := s.store.ListCollections(caseID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(cols))
	for i, c := range cols {
		out[c.ID] = fmt.Sprintf("Collection #%d", i+1)
	}
	return out, nil
}

func parseCoord(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	var v float64
	if _, err := fmt.Sscanf(s, "%g", &v); err != nil {
		return 0, false
	}
	// A coordinate outside the valid range is not a position, and must
	// not be plotted anywhere.
	if v != v || v < -180 || v > 180 {
		return 0, false
	}
	return v, true
}

// matchesFilename is a case-insensitive substring match over the two
// names a photo has: its own filename and the path it was collected
// from. Both, because an analyst narrowing a map by "Contact" means the
// folder just as often as the file.
func matchesFilename(p GeoPhoto, term string) bool {
	term = strings.ToLower(term)
	return strings.Contains(strings.ToLower(p.Filename), term) ||
		strings.Contains(strings.ToLower(p.Path), term)
}

func containsFold(list []string, v string) bool {
	for _, s := range list {
		if strings.EqualFold(s, v) {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
