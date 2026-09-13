# Bundled country-boundary dataset

`countries.json.gz` is the geography Tracefall uses to answer "which
country contains this coordinate?". It is compiled into the binary, so a
country attribution is offline, deterministic, and reproducible from a
named upstream file months after the analysis ran.

## Source

| | |
|---|---|
| Dataset | Natural Earth 1:50m Cultural Vectors — Admin 0 Countries |
| Version | 5.1.2 |
| URL | <https://raw.githubusercontent.com/nvkelso/natural-earth-vector/v5.1.2/geojson/ne_50m_admin_0_countries.geojson> |
| Upstream SHA-256 | `3e458fc036ad0a66411f2c1e6cac49c5d7bfb81cb1123bc513b22511a2b7fdeb` |
| License | Public domain. Natural Earth places no restrictions on use of its data: <https://www.naturalearthdata.com/about/terms-of-use/> |
| Features | 242 |

Natural Earth was chosen because it is public domain (no attribution
obligation to propagate into exported reports), versioned by release tag,
and small enough at 1:50m to embed without shipping a 24 MB binary.

## Reproducing the bundle

The generator performs no network access. Fetch the upstream file, then
build:

```bash
curl -sSLo /tmp/ne_50m.geojson https://raw.githubusercontent.com/nvkelso/natural-earth-vector/v5.1.2/geojson/ne_50m_admin_0_countries.geojson
go run ./internal/geo/geogen -in /tmp/ne_50m.geojson -out internal/geo/countries.json.gz
```

`geogen` verifies the input's SHA-256 against the value above and refuses
to run on anything else, so the bundle cannot silently come from a
different file. Output is byte-identical across runs:

| | |
|---|---|
| Bundle SHA-256 | `b198451e08619593dfa4757d8fb4e76b9c7cb9bd66d3ddf7b4598203c4030761` |
| Size | 673,678 bytes gzipped (1,864,845 uncompressed) |

`internal/geo`'s tests assert both the embedded dataset's identity and
that its declared version reaches the events, so a bundle swapped without
updating this file fails the suite.

## What is kept, and what is dropped

Natural Earth carries about a hundred properties per feature. The bundle
keeps three — `NAME_EN`, `ISO_A2`, `ISO_A3` — plus the geometry.

* Natural Earth writes `-99` where it assigns no ISO code (Kosovo,
  Somaliland, Northern Cyprus and five others). That is stored as an
  **empty** code, never as a substituted one.
* A feature with no name is dropped rather than bundled under an invented
  label.
* Coordinates are rounded to 4 decimal places, about 11 m at the equator.
  That is roughly two orders of magnitude finer than the source's own
  generalization, so it discards nothing the source carried.

## Accuracy, and how the lookup handles it

The 1:50m scale generalizes boundaries to roughly **2 km**. This is
recorded in the bundle as `simplification_km` and the lookup uses it in
two places rather than ignoring it:

* A point inside a polygon but **within 2 km of its edge** is reported
  with confidence `near_boundary`, not as a flat containment. A
  higher-resolution dataset could place it in a neighbour.
* A point **outside every polygon but within 2 km of one** is attributed
  to that country, also as `near_boundary`. Coastlines at this scale are
  drawn slightly inland, so genuinely land-based coordinates in coastal
  cities fall just outside — Cape Town by 1.74 km, Manhattan by 0.84 km,
  Singapore by 1.15 km, Hong Kong by 0.54 km. Reporting "no country" for
  those would be a dataset artefact presented as a finding.

Beyond that error the result is **no country**, with the distance to the
nearest land reported separately as context. The lookup never substitutes
a nearest country for a containment.

## Upgrading

Changing resolution or release means: update the four constants at the
top of `geogen.go`, re-run the command above, update the two hashes and
the feature count here, and update the expected dataset version in
`internal/geo/geo_test.go`. The tests will tell you if you missed one.
