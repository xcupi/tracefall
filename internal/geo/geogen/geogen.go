// Command geogen builds internal/geo's bundled country-boundary dataset
// from an upstream Natural Earth GeoJSON file.
//
// It exists so the bundled dataset is REPRODUCIBLE rather than merely
// present. The upstream file is identified by URL and by SHA-256, and
// this tool refuses to run against a file whose hash does not match, so
// regenerating the bundle from the documented input always produces the
// same bytes -- and a bundle that cannot be reproduced is a bundle whose
// provenance has broken.
//
// It performs NO network access. The upstream file is fetched separately
// and passed in by path; see internal/geo/DATASET.md for the command.
//
// Usage:
//
//	go run ./internal/geo/geogen -in ne_50m_admin_0_countries.geojson -out internal/geo/countries.json.gz
package main

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"sort"
)

// The upstream file this bundle is built from. Changing any of these
// means changing the dataset, and the values are restated in the bundle
// itself so a deployed binary can report where its geography came from.
const (
	sourceName    = "Natural Earth 1:50m Cultural Vectors -- Admin 0 Countries"
	sourceVersion = "5.1.2"
	sourceURL     = "https://raw.githubusercontent.com/nvkelso/natural-earth-vector/v5.1.2/geojson/ne_50m_admin_0_countries.geojson"
	sourceSHA256  = "3e458fc036ad0a66411f2c1e6cac49c5d7bfb81cb1123bc513b22511a2b7fdeb"
	sourceLicense = "Public domain. Natural Earth places no restrictions on use: " +
		"https://www.naturalearthdata.com/about/terms-of-use/"

	// coordPrecision is how many decimal places of longitude/latitude
	// are retained. Four places is about 11 m at the equator -- roughly
	// two orders of magnitude finer than the 1:50m source's own
	// generalization, so rounding here discards no information the
	// source ever carried.
	coordPrecision = 4

	// simplificationKm is the upstream dataset's own generalization
	// error, stated by Natural Earth for the 1:50m scale. It is carried
	// into the bundle so the lookup can say when a point is close enough
	// to a boundary that the dataset cannot settle which side it is on.
	simplificationKm = 2.0
)

type geojson struct {
	Features []struct {
		Properties map[string]any `json:"properties"`
		Geometry   struct {
			Type        string          `json:"type"`
			Coordinates json.RawMessage `json:"coordinates"`
		} `json:"geometry"`
	} `json:"features"`
}

type country struct {
	Name     string           `json:"name"`
	ISOA2    string           `json:"iso_a2"`
	ISOA3    string           `json:"iso_a3"`
	Polygons [][][][2]float64 `json:"polygons"` // polygon -> ring -> point -> [lon,lat]
}

type bundle struct {
	Source           string    `json:"source"`
	Version          string    `json:"version"`
	SourceURL        string    `json:"source_url"`
	SourceSHA256     string    `json:"source_sha256"`
	License          string    `json:"license"`
	CoordPrecision   int       `json:"coordinate_precision"`
	SimplificationKm float64   `json:"simplification_km"`
	Countries        []country `json:"countries"`
}

func main() {
	in := flag.String("in", "", "path to the upstream Natural Earth GeoJSON file")
	out := flag.String("out", "internal/geo/countries.json.gz", "path to write the bundled dataset to")
	flag.Parse()

	if *in == "" {
		fatal("-in is required; see internal/geo/DATASET.md for how to fetch the upstream file")
	}
	raw, err := os.ReadFile(*in)
	if err != nil {
		fatal("reading %s: %v", *in, err)
	}

	sum := sha256.Sum256(raw)
	got := hex.EncodeToString(sum[:])
	if got != sourceSHA256 {
		fatal("input hash mismatch\n  expected %s\n  got      %s\n"+
			"This is not the documented upstream file. Refusing to build a bundle whose provenance cannot be stated.",
			sourceSHA256, got)
	}

	var gj geojson
	if err := json.Unmarshal(raw, &gj); err != nil {
		fatal("parsing %s: %v", *in, err)
	}

	b := bundle{
		Source:           sourceName,
		Version:          sourceVersion,
		SourceURL:        sourceURL,
		SourceSHA256:     sourceSHA256,
		License:          sourceLicense,
		CoordPrecision:   coordPrecision,
		SimplificationKm: simplificationKm,
	}

	for _, f := range gj.Features {
		c := country{
			Name:  str(f.Properties, "NAME_EN", "NAME", "NAME_LONG"),
			ISOA2: iso(f.Properties, "ISO_A2", "ISO_A2_EH"),
			ISOA3: iso(f.Properties, "ISO_A3", "ISO_A3_EH"),
		}
		if c.Name == "" {
			// A feature with no name cannot be reported as a country, so
			// it is dropped rather than bundled under an invented label.
			continue
		}
		polys, err := coordinates(f.Geometry.Type, f.Geometry.Coordinates)
		if err != nil {
			fatal("feature %q: %v", c.Name, err)
		}
		c.Polygons = polys
		b.Countries = append(b.Countries, c)
	}

	// Sorted so the output is byte-identical across runs regardless of
	// how the input happened to be ordered.
	sort.Slice(b.Countries, func(i, j int) bool {
		if b.Countries[i].Name != b.Countries[j].Name {
			return b.Countries[i].Name < b.Countries[j].Name
		}
		return b.Countries[i].ISOA3 < b.Countries[j].ISOA3
	})

	encoded, err := json.Marshal(b)
	if err != nil {
		fatal("encoding bundle: %v", err)
	}

	f, err := os.Create(*out)
	if err != nil {
		fatal("creating %s: %v", *out, err)
	}
	// BestCompression and no header metadata: gzip records a modification
	// time by default, which would make every rebuild differ.
	zw, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err != nil {
		fatal("gzip: %v", err)
	}
	if _, err := zw.Write(encoded); err != nil {
		fatal("writing %s: %v", *out, err)
	}
	if err := zw.Close(); err != nil {
		fatal("closing gzip stream: %v", err)
	}
	if err := f.Close(); err != nil {
		fatal("closing %s: %v", *out, err)
	}

	written, _ := os.ReadFile(*out)
	outSum := sha256.Sum256(written)
	fmt.Printf("countries: %d\nuncompressed: %d bytes\nwritten: %s (%d bytes)\nsha256: %s\n",
		len(b.Countries), len(encoded), *out, len(written), hex.EncodeToString(outSum[:]))
}

func str(p map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := p[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// iso reads an ISO code, treating Natural Earth's "-99" placeholder as
// absent. An empty code is correct for a territory with no assigned code;
// substituting one would invent an identifier.
func iso(p map[string]any, keys ...string) string {
	for _, k := range keys {
		v, ok := p[k].(string)
		if ok && v != "" && v != "-99" {
			return v
		}
	}
	return ""
}

func coordinates(typ string, raw json.RawMessage) ([][][][2]float64, error) {
	switch typ {
	case "Polygon":
		var poly [][][2]float64
		if err := json.Unmarshal(raw, &poly); err != nil {
			return nil, err
		}
		return [][][][2]float64{round(poly)}, nil
	case "MultiPolygon":
		var multi [][][][2]float64
		if err := json.Unmarshal(raw, &multi); err != nil {
			return nil, err
		}
		out := make([][][][2]float64, 0, len(multi))
		for _, p := range multi {
			out = append(out, round(p))
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported geometry type %q", typ)
	}
}

func round(poly [][][2]float64) [][][2]float64 {
	scale := math.Pow(10, coordPrecision)
	out := make([][][2]float64, 0, len(poly))
	for _, ring := range poly {
		r := make([][2]float64, 0, len(ring))
		for _, pt := range ring {
			r = append(r, [2]float64{
				math.Round(pt[0]*scale) / scale,
				math.Round(pt[1]*scale) / scale,
			})
		}
		out = append(out, r)
	}
	return out
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "geogen: "+format+"\n", args...)
	os.Exit(1)
}
