// Package geo answers one question, offline and deterministically: which
// country contains this coordinate?
//
// # Why it is bundled rather than queried
//
// Resolving a coordinate against a web geocoder would make a forensic
// conclusion depend on a third party's database at the moment the
// analysis happened to run -- unreproducible, unauditable, and a network
// disclosure of evidence to boot. Tracefall makes no network calls, and a
// country attribution is a claim that has to be defensible months later
// in exactly the form it was made. So the boundaries ship with the
// binary, identified by source, version and hash (see DATASET.md), and
// the same coordinate always yields the same answer from the same build.
//
// # What a result asserts, and what it does not
//
// That the coordinate falls inside a polygon this dataset attributes to
// this country. That is a DERIVED fact about a coordinate, never
// something an image or a document recorded. Callers must present it as
// derived; nothing here is observed evidence.
//
// The dataset is generalized -- boundaries are simplified to roughly two
// kilometres at 1:50m scale -- so a point near a border may lie on either
// side of the true line. A result within that distance of its own
// boundary is flagged rather than asserted flatly, and a point in no
// polygon at all returns no country rather than the nearest one.
package geo

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sync"
)

// countriesGz is the bundled boundary dataset. It is built by
// ./geogen from the upstream file named in DATASET.md and is
// byte-reproducible from it.
//
//go:embed countries.json.gz
var countriesGz []byte

// Method names how a country was determined. It travels onto every
// event so the derivation is part of the record.
const Method = "offline point-in-polygon test against a bundled country-boundary dataset"

// Confidence qualifies a match against the dataset's own accuracy.
const (
	// ConfidenceInside: the point is inside a country's polygon and
	// further from its boundary than the dataset's generalization error,
	// so the simplification cannot have moved it across the line.
	ConfidenceInside = "inside"
	// ConfidenceNearBoundary: the point is inside a polygon but closer to
	// its edge than the dataset can resolve. The country named is what
	// this dataset says; a finer dataset could disagree.
	ConfidenceNearBoundary = "near_boundary"
	// ConfidenceNone: no polygon contains the point.
	ConfidenceNone = "none"
)

// nearestContextKm bounds how far Lookup will look for the nearest land
// when reporting a no-country result. Beyond this the answer is simply
// "open water" and naming a landmass hundreds of kilometres away adds
// nothing an analyst can use.
const nearestContextKm = 50

// ErrInvalidCoordinate reports a latitude or longitude outside the range
// a coordinate can occupy. It is an error rather than an empty result
// because it means the input was not a position at all.
var ErrInvalidCoordinate = errors.New("geo: coordinate is outside the valid range")

// Result is one country lookup.
type Result struct {
	// Found reports whether a country contains the coordinate. When
	// false, Country is empty -- never a nearest guess, and never a
	// placeholder that could be read as a name.
	Found bool

	Country string // English country name as the dataset records it
	ISOA2   string // ISO 3166-1 alpha-2, empty when the dataset assigns none
	ISOA3   string // ISO 3166-1 alpha-3, empty when the dataset assigns none

	Confidence string // ConfidenceInside | ConfidenceNearBoundary | ConfidenceNone
	// BoundaryDistanceKm is the great-circle distance from the point to
	// the nearest edge of the polygon that contains it. Zero and
	// meaningless when Found is false.
	BoundaryDistanceKm float64

	// Reason explains a Found=false result in terms an analyst can act
	// on, and qualifies a near-boundary one.
	Reason string

	// Nearest* describe the closest land polygon when NO country contains
	// the coordinate. They are CONTEXT, never the answer: a point in the
	// mid-Atlantic has a nearest country too. Country stays empty in that
	// case and these fields are what distinguish "4 km off a coast" from
	// "1,600 km from anywhere".
	NearestCountry    string
	NearestISOA2      string
	NearestISOA3      string
	NearestDistanceKm float64

	Method  string
	Dataset Dataset
}

// Dataset identifies the bundled boundaries, so a result can always say
// which geography produced it.
type Dataset struct {
	Source           string  `json:"source"`
	Version          string  `json:"version"`
	SourceURL        string  `json:"source_url"`
	SourceSHA256     string  `json:"source_sha256"`
	License          string  `json:"license"`
	CoordPrecision   int     `json:"coordinate_precision"`
	SimplificationKm float64 `json:"simplification_km"`
}

// String renders the dataset compactly for a single evidence field.
func (d Dataset) String() string {
	if d.Source == "" {
		return ""
	}
	return d.Source + " v" + d.Version
}

type country struct {
	Name     string           `json:"name"`
	ISOA2    string           `json:"iso_a2"`
	ISOA3    string           `json:"iso_a3"`
	Polygons [][][][2]float64 `json:"polygons"`

	// bounds is the axis-aligned box around every polygon, computed at
	// load time. Almost every candidate is rejected by four float
	// comparisons, which is what keeps a per-image lookup free.
	bounds [][4]float64 // per polygon: minLon, minLat, maxLon, maxLat
}

type bundleFile struct {
	Dataset
	Countries []country `json:"countries"`
}

var (
	once    sync.Once
	loaded  *bundleFile
	loadErr error
)

// load decompresses and indexes the bundled dataset exactly once, however
// many images are parsed. The result is immutable after load, so every
// concurrent lookup shares it without copying or locking.
func load() (*bundleFile, error) {
	once.Do(func() {
		zr, err := gzip.NewReader(bytes.NewReader(countriesGz))
		if err != nil {
			loadErr = fmt.Errorf("geo: opening bundled dataset: %w", err)
			return
		}
		defer zr.Close()

		var b bundleFile
		if err := json.NewDecoder(zr).Decode(&b); err != nil {
			loadErr = fmt.Errorf("geo: decoding bundled dataset: %w", err)
			return
		}
		for i := range b.Countries {
			c := &b.Countries[i]
			c.bounds = make([][4]float64, 0, len(c.Polygons))
			for _, poly := range c.Polygons {
				c.bounds = append(c.bounds, boundsOf(poly))
			}
		}
		loaded = &b
	})
	return loaded, loadErr
}

// DatasetInfo reports which boundaries this build carries, without
// performing a lookup.
func DatasetInfo() (Dataset, error) {
	b, err := load()
	if err != nil {
		return Dataset{}, err
	}
	return b.Dataset, nil
}

// Lookup returns the country containing (lat, lon).
//
// It never invents a country. A coordinate over water, over Antarctica's
// unclaimed sectors, or anywhere else the dataset attributes to no
// country returns Found=false with a reason -- not the nearest landmass.
func Lookup(lat, lon float64) (Result, error) {
	if math.IsNaN(lat) || math.IsNaN(lon) || math.IsInf(lat, 0) || math.IsInf(lon, 0) ||
		lat < -90 || lat > 90 || lon < -180 || lon > 180 {
		return Result{}, fmt.Errorf("%w: latitude %v, longitude %v", ErrInvalidCoordinate, lat, lon)
	}

	b, err := load()
	if err != nil {
		return Result{}, err
	}

	res := Result{Method: Method, Dataset: b.Dataset, Confidence: ConfidenceNone}

	for i := range b.Countries {
		c := &b.Countries[i]
		for pi, poly := range c.Polygons {
			bb := c.bounds[pi]
			if lon < bb[0] || lon > bb[2] || lat < bb[1] || lat > bb[3] {
				continue
			}
			if !inPolygon(lon, lat, poly) {
				continue
			}
			res.Found = true
			res.Country = c.Name
			res.ISOA2 = c.ISOA2
			res.ISOA3 = c.ISOA3
			res.BoundaryDistanceKm = distanceToPolygonKm(lon, lat, poly)
			if res.BoundaryDistanceKm <= b.SimplificationKm {
				res.Confidence = ConfidenceNearBoundary
				res.Reason = fmt.Sprintf(
					"the coordinate lies %.2f km from this country's boundary as the dataset draws it, "+
						"within the dataset's own generalization error of about %.1f km. The country named is "+
						"what these boundaries say; a higher-resolution dataset could place it in a neighbour.",
					res.BoundaryDistanceKm, b.SimplificationKm)
			} else {
				res.Confidence = ConfidenceInside
			}
			return res, nil
		}
	}

	// Nothing contains the point. Before reporting no country, check
	// whether it lies within the dataset's own generalization error of
	// one -- because at 1:50m scale a coastline is drawn slightly inland,
	// and a genuinely land-based coordinate in a coastal city routinely
	// falls a kilometre outside the polygon it belongs to. Cape Town,
	// Manhattan, Singapore and Hong Kong all do. Reporting "no country"
	// for them would be a dataset artefact presented as a finding.
	//
	// The rescue is bounded by the SAME error the dataset declares, and
	// it is never reported as a plain containment: the confidence says
	// near-boundary and the reason says the point is outside the drawn
	// polygon.
	if name, a2, a3, km, ok := NearestBoundary(lat, lon, b.SimplificationKm); ok && km <= b.SimplificationKm {
		res.Found = true
		res.Country, res.ISOA2, res.ISOA3 = name, a2, a3
		res.BoundaryDistanceKm = km
		res.Confidence = ConfidenceNearBoundary
		res.Reason = fmt.Sprintf(
			"the coordinate falls just OUTSIDE this country's boundary as the dataset draws it, by %.2f km "+
				"-- within the dataset's own generalization error of about %.1f km, which draws coastlines "+
				"and borders slightly inland. The country named is the nearest boundary within that error; "+
				"a higher-resolution dataset would settle it.",
			km, b.SimplificationKm)
		return res, nil
	}

	res.Reason = "the coordinate falls inside no country polygon in this dataset, and is further from every " +
		"boundary than the dataset's generalization error can account for. That is the expected result for a " +
		"position over open water or in a territory the dataset attributes to no country; no nearest country " +
		"is substituted."
	// Context only, never an attribution: how far the point is from the
	// closest land this dataset draws. A coordinate 4 km off a coast and
	// one in the mid-Atlantic are both "no country", and an analyst needs
	// to tell them apart.
	if name, a2, a3, km, ok := NearestBoundary(lat, lon, nearestContextKm); ok && km <= nearestContextKm {
		res.NearestCountry, res.NearestISOA2, res.NearestISOA3 = name, a2, a3
		res.NearestDistanceKm = km
		res.Reason += fmt.Sprintf(" The closest land in this dataset is %s, %.2f km away; that is context "+
			"about where the point sits, NOT a country attribution.", name, km)
	}
	return res, nil
}

func boundsOf(poly [][][2]float64) [4]float64 {
	bb := [4]float64{math.Inf(1), math.Inf(1), math.Inf(-1), math.Inf(-1)}
	for _, ring := range poly {
		for _, pt := range ring {
			bb[0] = math.Min(bb[0], pt[0])
			bb[1] = math.Min(bb[1], pt[1])
			bb[2] = math.Max(bb[2], pt[0])
			bb[3] = math.Max(bb[3], pt[1])
		}
	}
	return bb
}

// inPolygon is a ray-casting test against the outer ring, with any inner
// rings (holes -- an enclave such as Lesotho inside South Africa)
// excluding the point again.
func inPolygon(lon, lat float64, poly [][][2]float64) bool {
	if len(poly) == 0 || !inRing(lon, lat, poly[0]) {
		return false
	}
	for _, hole := range poly[1:] {
		if inRing(lon, lat, hole) {
			return false
		}
	}
	return true
}

func inRing(x, y float64, ring [][2]float64) bool {
	inside := false
	n := len(ring)
	if n < 3 {
		return false
	}
	j := n - 1
	for i := 0; i < n; i++ {
		xi, yi := ring[i][0], ring[i][1]
		xj, yj := ring[j][0], ring[j][1]
		if (yi > y) != (yj > y) {
			xCross := (xj-xi)*(y-yi)/(yj-yi) + xi
			if x < xCross {
				inside = !inside
			}
		}
		j = i
	}
	return inside
}

// distanceToPolygonKm is the shortest distance from the point to any edge
// of the polygon, used only to qualify a match against the dataset's
// generalization error.
//
// Distances are computed on a local equirectangular approximation:
// longitude degrees are scaled by cos(latitude). Over the few kilometres
// that matter here the error is far below the simplification the check is
// comparing against.
func distanceToPolygonKm(lon, lat float64, poly [][][2]float64) float64 {
	const kmPerDegree = 111.319
	cosLat := math.Cos(lat * math.Pi / 180)
	best := math.Inf(1)
	for _, ring := range poly {
		n := len(ring)
		for i := 0; i < n; i++ {
			a := ring[i]
			b := ring[(i+1)%n]
			d := pointSegmentDistance(
				(lon-a[0])*cosLat, lat-a[1],
				0, 0,
				(b[0]-a[0])*cosLat, b[1]-a[1],
			)
			if d < best {
				best = d
			}
		}
	}
	if math.IsInf(best, 1) {
		return 0
	}
	return best * kmPerDegree
}

// pointSegmentDistance is the distance from (px,py) to the segment from
// (ax,ay) to (bx,by), in the same units as its inputs.
func pointSegmentDistance(px, py, ax, ay, bx, by float64) float64 {
	dx, dy := bx-ax, by-ay
	if dx == 0 && dy == 0 {
		return math.Hypot(px-ax, py-ay)
	}
	t := ((px-ax)*dx + (py-ay)*dy) / (dx*dx + dy*dy)
	t = math.Max(0, math.Min(1, t))
	return math.Hypot(px-(ax+t*dx), py-(ay+t*dy))
}

// NearestBoundary reports the closest country polygon to a coordinate and
// its distance, regardless of containment. It exists for the caller that
// needs to say how far outside every boundary a point fell, and for the
// near-boundary rescue in Lookup.
//
// It is NOT a country attribution: a coordinate in mid-ocean has a
// nearest country too, and reporting that as its location would be the
// invention this package exists to avoid.
func NearestBoundary(lat, lon float64, withinKm float64) (name, isoA2, isoA3 string, km float64, ok bool) {
	b, err := load()
	if err != nil {
		return "", "", "", 0, false
	}
	// Expand the bounding-box filter by the search radius, converted to
	// degrees at this latitude, so a polygon just out of the box is still
	// considered while mid-ocean lookups still reject almost everything.
	const kmPerDegree = 111.319
	padLat := withinKm / kmPerDegree
	cosLat := math.Max(0.01, math.Abs(math.Cos(lat*math.Pi/180)))
	padLon := withinKm / (kmPerDegree * cosLat)

	best := math.Inf(1)
	for i := range b.Countries {
		c := &b.Countries[i]
		for pi, poly := range c.Polygons {
			bb := c.bounds[pi]
			if lon < bb[0]-padLon || lon > bb[2]+padLon || lat < bb[1]-padLat || lat > bb[3]+padLat {
				continue
			}
			if d := distanceToPolygonKm(lon, lat, poly); d < best {
				best = d
				name, isoA2, isoA3 = c.Name, c.ISOA2, c.ISOA3
			}
		}
	}
	if math.IsInf(best, 1) {
		return "", "", "", 0, false
	}
	return name, isoA2, isoA3, best, true
}
