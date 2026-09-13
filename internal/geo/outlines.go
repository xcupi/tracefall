package geo

import (
	"math"
	"sort"
	"sync"
)

// Outlines are country boundaries SIMPLIFIED FOR DRAWING.
//
// They exist so Tracefall can draw a recognizable world map with no tile
// server, no API key, and no network request -- the same bundled
// Natural Earth polygons the country lookup uses, thinned to something a
// browser can render at interactive frame rates.
//
// # These are not the evidence
//
// The simplification is lossy and deliberately so. A drawn outline is a
// PICTURE; the country a coordinate falls in is decided by Lookup
// against the FULL polygons, server-side, and never by anything derived
// here. Nothing in this file may be used to attribute a coordinate to a
// country, and nothing does: Outlines returns no lookup function and the
// map view never performs one.
type Outlines struct {
	// Dataset identifies the boundaries these were thinned from, so a
	// drawn map can say what it is drawing.
	Dataset Dataset `json:"dataset"`
	// SimplifiedToleranceDeg is the perpendicular distance, in degrees,
	// below which a vertex was dropped.
	SimplifiedToleranceDeg float64 `json:"simplified_tolerance_deg"`
	// Note states what these outlines are for, and what they are not.
	Note string `json:"note"`
	// Rings are flat [lon,lat,lon,lat,...] coordinate runs. Flat arrays
	// rather than nested pairs because this is JSON on its way to a
	// canvas: the nested form roughly doubles the payload for the same
	// picture.
	Rings [][]float64 `json:"rings"`
	// Points is the total vertex count retained, so a caller can see the
	// size of what it asked for.
	Points int `json:"points"`
}

var (
	outlineOnce sync.Once
	outlineVal  Outlines
	outlineErr  error
)

// outlineToleranceDeg is the Douglas-Peucker tolerance used for the
// drawn basemap: about 5.5 km at the equator.
//
// Chosen by eye against what the map is for -- national outlines
// recognizable enough to place a marker in a continent, at a payload a
// browser can parse in a few milliseconds. It is far coarser than the
// dataset's own accuracy, which is exactly why it may not be used for
// attribution.
const outlineToleranceDeg = 0.08

// outlineMinRingPoints drops a ring that simplification reduces to
// fewer than this. Below three points there is no shape left to draw --
// and small islands at this tolerance collapse to specks that cost
// payload and add nothing.
const outlineMinRingPoints = 4

// DrawingOutlines returns the simplified boundaries, computing them once
// per process and sharing the immutable result.
//
// The cost is paid on the first map load, not at startup: a deployment
// that never opens the map never spends it.
func DrawingOutlines() (Outlines, error) {
	outlineOnce.Do(func() {
		b, err := load()
		if err != nil {
			outlineErr = err
			return
		}

		out := Outlines{
			Dataset:                b.Dataset,
			SimplifiedToleranceDeg: outlineToleranceDeg,
			Note: "Country outlines simplified for DRAWING only. They are a picture, not the boundaries " +
				"any country determination is made against: that is done server-side against the full " +
				"polygons of the same dataset. Do not measure anything with these.",
		}

		// Sorted by country name so the payload is byte-identical across
		// runs -- a map that renders differently on reload for no reason
		// is a map an analyst stops trusting.
		names := make([]string, 0, len(b.Countries))
		byName := map[string][]*country{}
		for i := range b.Countries {
			c := &b.Countries[i]
			if _, seen := byName[c.Name]; !seen {
				names = append(names, c.Name)
			}
			byName[c.Name] = append(byName[c.Name], c)
		}
		sort.Strings(names)

		for _, name := range names {
			for _, c := range byName[name] {
				for _, poly := range c.Polygons {
					for _, ring := range poly {
						simplified := simplifyRing(ring, outlineToleranceDeg)
						if len(simplified) < outlineMinRingPoints {
							continue
						}
						// Rounded to two decimals -- about 1.1 km, an
						// order of magnitude finer than the tolerance
						// above, so it costs the picture nothing and
						// roughly halves the payload. Consecutive points
						// that collapse onto each other are dropped.
						flat := make([]float64, 0, len(simplified)*2)
						var lastX, lastY float64
						for i, pt := range simplified {
							x := math.Round(pt[0]*100) / 100
							y := math.Round(pt[1]*100) / 100
							if i > 0 && x == lastX && y == lastY {
								continue
							}
							flat = append(flat, x, y)
							lastX, lastY = x, y
						}
						if len(flat) < outlineMinRingPoints*2 {
							continue
						}
						out.Rings = append(out.Rings, flat)
						out.Points += len(flat) / 2
					}
				}
			}
		}
		outlineVal = out
	})
	return outlineVal, outlineErr
}

// simplifyRing is Douglas-Peucker, iterative rather than recursive so a
// pathological ring cannot exhaust the stack.
func simplifyRing(ring [][2]float64, tolerance float64) [][2]float64 {
	if len(ring) <= 2 {
		return ring
	}

	keep := make([]bool, len(ring))
	keep[0] = true
	keep[len(ring)-1] = true

	type span struct{ lo, hi int }
	stack := []span{{0, len(ring) - 1}}
	for len(stack) > 0 {
		s := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if s.hi <= s.lo+1 {
			continue
		}

		maxDist, maxIdx := 0.0, -1
		for i := s.lo + 1; i < s.hi; i++ {
			d := perpendicularDistance(ring[i], ring[s.lo], ring[s.hi])
			if d > maxDist {
				maxDist, maxIdx = d, i
			}
		}
		if maxIdx < 0 || maxDist <= tolerance {
			continue
		}
		keep[maxIdx] = true
		stack = append(stack, span{s.lo, maxIdx}, span{maxIdx, s.hi})
	}

	out := make([][2]float64, 0, len(ring))
	for i, k := range keep {
		if k {
			out = append(out, ring[i])
		}
	}
	return out
}

// perpendicularDistance is the distance from p to the line through a
// and b, in degrees. Degrees rather than kilometres because the
// tolerance is a drawing threshold, not a measurement.
func perpendicularDistance(p, a, b [2]float64) float64 {
	dx, dy := b[0]-a[0], b[1]-a[1]
	if dx == 0 && dy == 0 {
		return math.Hypot(p[0]-a[0], p[1]-a[1])
	}
	// |cross product| / |b-a|
	return math.Abs(dy*p[0]-dx*p[1]+b[0]*a[1]-b[1]*a[0]) / math.Hypot(dx, dy)
}
