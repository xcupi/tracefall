package geo_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"os"
	"strings"
	"sync"
	"testing"

	"tracefall/internal/geo"
)

// The bundled dataset's identity. If these change, DATASET.md must
// change with them -- that is the point of asserting them here.
const (
	wantDatasetVersion = "5.1.2"
	wantBundleSHA256   = "b198451e08619593dfa4757d8fb4e76b9c7cb9bd66d3ddf7b4598203c4030761"
)

func TestDataset_IdentityMatchesItsDocumentation(t *testing.T) {
	d, err := geo.DatasetInfo()
	if err != nil {
		t.Fatalf("DatasetInfo: %v", err)
	}
	if d.Version != wantDatasetVersion {
		t.Errorf("dataset version = %q, want %q -- update DATASET.md and this test together",
			d.Version, wantDatasetVersion)
	}
	if !strings.Contains(d.Source, "Natural Earth") {
		t.Errorf("Source = %q", d.Source)
	}
	if !strings.Contains(strings.ToLower(d.License), "public domain") {
		t.Errorf("License = %q; the bundle must carry its licensing", d.License)
	}
	if !strings.HasPrefix(d.SourceURL, "https://") {
		t.Errorf("SourceURL = %q; the upstream file must be identified", d.SourceURL)
	}
	if len(d.SourceSHA256) != 64 {
		t.Errorf("SourceSHA256 = %q; the upstream file must be identified by hash", d.SourceSHA256)
	}
	if d.SimplificationKm <= 0 {
		t.Errorf("SimplificationKm = %v; the dataset must declare its own accuracy", d.SimplificationKm)
	}
}

// The embedded file is the evidence base for every country attribution.
// A silent swap must fail the suite.
func TestDataset_BundledFileIsTheDocumentedOne(t *testing.T) {
	raw, err := os.ReadFile("countries.json.gz")
	if err != nil {
		t.Fatalf("reading the bundled dataset: %v", err)
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != wantBundleSHA256 {
		t.Errorf("bundled dataset sha256 = %s\nwant %s\nregenerate with ./geogen and update DATASET.md",
			got, wantBundleSHA256)
	}
}

func TestLookup_InsideACountry(t *testing.T) {
	tests := []struct {
		name        string
		lat, lon    float64
		wantCountry string
		wantISO     string
	}{
		{"western Zambia", -16, 23, "Zambia", "ZM"},
		{"Tokyo", 35.68, 139.69, "Japan", "JP"},
		{"central Kenya", -1.28, 36.82, "Kenya", "KE"},
		{"Paris", 48.85, 2.35, "France", "FR"},
		{"Johannesburg", -26.2, 28.04, "South Africa", "ZA"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := geo.Lookup(tt.lat, tt.lon)
			if err != nil {
				t.Fatalf("Lookup: %v", err)
			}
			if !r.Found {
				t.Fatalf("Found = false: %s", r.Reason)
			}
			if r.Country != tt.wantCountry {
				t.Errorf("Country = %q, want %q", r.Country, tt.wantCountry)
			}
			if r.ISOA2 != tt.wantISO {
				t.Errorf("ISOA2 = %q, want %q", r.ISOA2, tt.wantISO)
			}
			if r.Method == "" || !strings.Contains(r.Method, "offline") {
				t.Errorf("Method = %q; the derivation must be stated and must be offline", r.Method)
			}
			if r.Dataset.Version == "" {
				t.Error("the result must carry the dataset version that produced it")
			}
		})
	}
}

// A hole in a polygon is a real country, not part of the one surrounding
// it. Lesotho sits entirely inside South Africa.
func TestLookup_EnclaveIsNotAttributedToItsNeighbour(t *testing.T) {
	r, err := geo.Lookup(-29.6, 28.2)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if r.Country != "Lesotho" {
		t.Errorf("Country = %q, want Lesotho -- an enclave must not be absorbed by the country around it",
			r.Country)
	}
}

// The Zambia/Zimbabwe border at Victoria Falls: two points a few
// kilometres apart on opposite sides.
func TestLookup_NearABoundaryIsFlaggedNotAsserted(t *testing.T) {
	r, err := geo.Lookup(-17.93, 25.83)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !r.Found {
		t.Fatalf("Found = false at a land point: %s", r.Reason)
	}
	if r.Confidence != geo.ConfidenceNearBoundary {
		t.Errorf("Confidence = %q at %.2f km from the boundary, want %q",
			r.Confidence, r.BoundaryDistanceKm, geo.ConfidenceNearBoundary)
	}
	if r.Reason == "" {
		t.Error("a near-boundary result must explain itself")
	}
	if r.BoundaryDistanceKm <= 0 {
		t.Errorf("BoundaryDistanceKm = %v", r.BoundaryDistanceKm)
	}
}

// A point well inside a country must NOT be flagged: the caveat has to
// mean something.
func TestLookup_WellInsideIsNotFlagged(t *testing.T) {
	r, _ := geo.Lookup(-16, 23)
	if r.Confidence != geo.ConfidenceInside {
		t.Errorf("Confidence = %q for a point %.0f km from any border, want %q",
			r.Confidence, r.BoundaryDistanceKm, geo.ConfidenceInside)
	}
	if r.BoundaryDistanceKm < 50 {
		t.Errorf("BoundaryDistanceKm = %v; this point is deep inside Zambia", r.BoundaryDistanceKm)
	}
}

// At 1:50m a coastline is drawn slightly inland, so genuinely land-based
// coordinates in coastal cities fall just outside. Reporting "no
// country" for them would be a dataset artefact presented as a finding.
func TestLookup_CoastalPointsAreRescuedWithinTheDatasetError(t *testing.T) {
	tests := []struct {
		name        string
		lat, lon    float64
		wantCountry string
	}{
		{"Cape Town", -33.9, 18.4, "South Africa"},
		{"Manhattan", 40.7, -74.0, "United States of America"},
		{"Singapore", 1.29, 103.85, "Singapore"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := geo.Lookup(tt.lat, tt.lon)
			if err != nil {
				t.Fatalf("Lookup: %v", err)
			}
			if !r.Found || r.Country != tt.wantCountry {
				t.Fatalf("Country = %q (found=%v), want %q", r.Country, r.Found, tt.wantCountry)
			}
			// Rescued, never presented as a plain containment.
			if r.Confidence != geo.ConfidenceNearBoundary {
				t.Errorf("Confidence = %q, want %q -- a rescued point must be qualified",
					r.Confidence, geo.ConfidenceNearBoundary)
			}
		})
	}
}

func TestLookup_OutsideEveryCountryReturnsNoCountry(t *testing.T) {
	tests := []struct {
		name     string
		lat, lon float64
	}{
		{"mid-Atlantic", 35, -40},
		{"equatorial Atlantic", 0, -30},
		{"south Pacific", -40, -120},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := geo.Lookup(tt.lat, tt.lon)
			if err != nil {
				t.Fatalf("Lookup: %v", err)
			}
			if r.Found {
				t.Errorf("a mid-ocean coordinate was attributed to %q", r.Country)
			}
			if r.Country != "" {
				t.Errorf("Country = %q; it must be empty, never a nearest guess", r.Country)
			}
			if r.Confidence != geo.ConfidenceNone {
				t.Errorf("Confidence = %q, want %q", r.Confidence, geo.ConfidenceNone)
			}
			if r.Reason == "" {
				t.Error("a no-country result must explain itself")
			}
		})
	}
}

// Context is not attribution: a point in territorial water names the
// nearest land WITHOUT being attributed to it.
func TestLookup_NearestLandIsContextNotAttribution(t *testing.T) {
	r, err := geo.Lookup(-33.9, 18.1) // ~24 km off Cape Town
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if r.Found {
		t.Fatalf("a point 24 km offshore was attributed to %q", r.Country)
	}
	if r.NearestCountry == "" {
		t.Error("the nearest land should be reported as context")
	}
	if r.Country != "" {
		t.Errorf("Country = %q; the nearest land must never become the answer", r.Country)
	}
	if !strings.Contains(r.Reason, "NOT a country attribution") {
		t.Errorf("the reason must say the nearest land is not the answer: %q", r.Reason)
	}
}

func TestLookup_InvalidCoordinatesAreRejected(t *testing.T) {
	tests := []struct {
		name     string
		lat, lon float64
	}{
		{"latitude above 90", 91, 0},
		{"latitude below -90", -90.001, 0},
		{"longitude above 180", 0, 180.5},
		{"longitude below -180", 0, -181},
		{"NaN latitude", math.NaN(), 0},
		{"NaN longitude", 0, math.NaN()},
		{"infinite latitude", math.Inf(1), 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := geo.Lookup(tt.lat, tt.lon)
			if !errors.Is(err, geo.ErrInvalidCoordinate) {
				t.Fatalf("err = %v, want ErrInvalidCoordinate", err)
			}
			if r.Found || r.Country != "" {
				t.Errorf("an invalid coordinate produced a country: %+v", r)
			}
		})
	}
}

// The exact bounds are valid positions, not errors.
func TestLookup_BoundaryCoordinatesAreValid(t *testing.T) {
	for _, p := range [][2]float64{{90, 0}, {-90, 0}, {0, 180}, {0, -180}} {
		if _, err := geo.Lookup(p[0], p[1]); err != nil {
			t.Errorf("Lookup(%v, %v) = %v; the range bounds are valid coordinates", p[0], p[1], err)
		}
	}
}

func TestLookup_IsDeterministic(t *testing.T) {
	first, err := geo.Lookup(-16, 23)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		got, err := geo.Lookup(-16, 23)
		if err != nil {
			t.Fatal(err)
		}
		if got != first {
			t.Fatalf("run %d differs:\n got %+v\nwant %+v", i, got, first)
		}
	}
}

// The dataset is loaded once and shared immutably, so concurrent lookups
// must be safe and must agree.
func TestLookup_IsConcurrencySafe(t *testing.T) {
	var wg sync.WaitGroup
	results := make([]geo.Result, 64)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r, err := geo.Lookup(-16, 23)
			if err != nil {
				t.Error(err)
				return
			}
			results[i] = r
		}(i)
	}
	wg.Wait()
	for i, r := range results {
		if r.Country != "Zambia" {
			t.Fatalf("goroutine %d got %q", i, r.Country)
		}
	}
}

// No ISO code is better than an invented one. Natural Earth writes "-99"
// for territories it assigns no code, and that must never reach a result.
func TestLookup_NoISOCodeIsInvented(t *testing.T) {
	// Kosovo has no assigned ISO 3166-1 alpha-3.
	r, err := geo.Lookup(42.6, 21.0)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Found {
		t.Skip("the dataset does not cover this point; nothing to assert")
	}
	for _, code := range []string{r.ISOA2, r.ISOA3} {
		if code == "-99" {
			t.Errorf("the dataset's %q placeholder reached a result as an ISO code", code)
		}
	}
}

func BenchmarkLookup(b *testing.B) {
	if _, err := geo.Lookup(-16, 23); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := geo.Lookup(-16, 23); err != nil {
			b.Fatal(err)
		}
	}
}
