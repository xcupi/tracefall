# Photo Map

A case-scoped map of every image in the evidence whose EXIF recorded a
coordinate. Reachable from the case sidebar; there is no global map,
because a marker only means something inside the case whose evidence
produced it.

> **The map location comes from embedded EXIF GPS metadata. Country is
> derived from the coordinate and is not stored directly in the image.**

---

## What a marker asserts

A marker says: *this file contains this coordinate.* That is all.

* It is **not a sighting.** EXIF travels with a copied file. An image
  downloaded from a messaging app, exported from an editor, or dropped on
  the disk by an installer carries whatever coordinate its writer put
  there. The position places the **writer's claim**, not a device and not
  a person.
* It is **not evidence the image was opened or viewed** on this machine.
  The path is filesystem context, nothing more.
* The **country is derived**, by Tracefall, after the fact — an offline
  point-in-polygon test against a bundled boundary dataset. The image
  does not name a country.

Every surface keeps observed and derived apart, and says which is which:

| | Observed — in the file | Derived — computed by Tracefall |
|---|---|---|
| Photo card | `16° 0' 0" S` / `23° 0' 0" E`, EXIF times, Make, Model | decimal coordinate, country, ISO code, confidence, precision |
| Lightbox header | `GPS -16, 23 (observed)` | `Zambia (derived)` |
| Marker position | the stored coordinate | *nothing* — see below |

A marker's screen position is projected from `latitude`/`longitude`
**only**. Nothing places a marker from a country, a filename, or a path,
and a test asserts that the clustering code reads no such field.

## Which images appear

Only images with a **fully decoded** coordinate: both components and both
hemisphere references. This is the map's default and only dataset —
"Only images with GPS" is stated in the filter bar rather than left
implicit.

An image is excluded when it has no GPS block, has a GPS block with no
coordinate (very common — a version tag alone), or has a coordinate that
cannot be decoded. Excluded images are **not** placed at a guessed
position, at 0,0, or at their country's centre. They remain fully
available in Evidence and on the Timeline, and the map reports how many
there are, so it never reads as *"these are all the images"*.

With nothing to show, the page says **"No geolocated photos found in this
case."** and explains what was found instead — never an empty map.

## The map itself

Drawn in the browser onto a canvas, from country outlines shipped inside
the binary. **No tile server, no API key, no network request.**

That is a deliberate trade. A raster tile provider would give streets and
terrain; it would also disclose, one tile request at a time, exactly
which coordinates are being investigated — to a third party, from an
analyst's machine, for evidence that may be under legal privilege.
Tracefall makes no network calls, and the map does not become the
exception. What is drawn is a political outline: enough to place a
photograph in a country and sanity-check a coordinate, which is what the
artifact supports.

The outlines come from the same Natural Earth dataset the country lookup
uses (see [`internal/geo/DATASET.md`](../internal/geo/DATASET.md)),
simplified to ~9 km for drawing. **They are a picture, not the
boundaries.** A country determination is made server-side against the
full polygons; nothing may attribute a coordinate from the drawn
outlines, and the payload deliberately carries no country names or ISO
codes at all, so there is nothing there to attribute *with*.

Pan by dragging, zoom with the wheel, the `+`/`−` buttons or the arrow
and `+`/`−` keys, and **Fit** frames every photo.

### Clustering

Photos closer together than a marker's width are grouped into one marker
carrying a count. Clicking a cluster zooms to fit its members.

Photos at **identical** coordinates cannot be separated by zooming — a
common case, since many devices round positions. Clicking such a cluster
lists its members instead of zooming forever, and each entry opens its
own photo.

Only markers on screen become DOM elements, so a case with thousands of
photographs still renders a handful.

## Image preview and the viewer

Thumbnails are fetched **lazily**: only for markers actually drawn, and
once per photo per session. A map load generates none — asserted by a
test that loads 40 photos and checks that zero previews exist until three
are viewed.

**View image** opens a lightbox showing the *original evidence bytes*
from the authorized endpoint, rendered by the browser's own image
pipeline. Nothing decodes the file into a JavaScript buffer, so a
50-megapixel image costs what the browser costs and no more. Fit, 100%,
zoom in/out, drag to pan, `Esc` or **Close** to leave. The header shows
filename, GPS (observed), country (derived) and the EXIF timestamp; the
footer states the evidence SHA-256 so a viewer can say which bytes it
displayed.

If the bytes cannot be served, the viewer says so and **keeps the
record**: metadata and provenance are unaffected and stay on screen.

### Thumbnails are derived artifacts

Two sources, preferred in order:

1. **The camera's own EXIF thumbnail**, copied out of the evidence by
   byte range. Nothing is decoded or re-encoded — the preview is
   literally a range of bytes present in the file, and the result records
   which range so the claim can be checked. 14 of the 26 images in one
   real triage image carry one.
2. **A downscale**, for images that embed none. This decodes and
   re-encodes into a new buffer, bounded by a pixel limit so a declared
   60000×60000 JPEG cannot exhaust memory.

Either way:

* The original is opened **read-only** and is never written, moved or
  re-saved. Tests hash the evidence before and after generating a preview
  and require the digests to match.
* Previews are cached under `cases/<id>/derived/thumbnails/`, **outside
  every evidence directory** — so a generated file can never be
  catalogued as evidence, walked by discovery, or included in a
  collection's integrity hash.
* The response carries `X-Tracefall-Derived: thumbnail` and names its
  source. It deliberately does **not** carry an evidence hash: a preview
  is not the evidence.
* A preview is deleted with the evidence it came from.

## Serving image bytes: the security model

The browser **never names a path.** It names an opaque source file ID,
and every request passes three independent checks before a byte is read:

1. **Case ownership.** The source file must belong to the case in the
   URL. Another case's ID is refused.
2. **Artifact type.** It must be an image artifact — otherwise the
   endpoint would serve any catalogued file, a registry hive or a memory
   dump, through an `<img>` tag.
3. **Path containment.** The path is built from the collection's own
   recorded evidence directory and re-verified to resolve inside it after
   joining.

A foreign ID and an invented ID return **the same 404 with the same
body**, so the endpoint cannot be used to probe what other cases hold — a
test asserts the two responses are byte-identical. Deleted evidence
returns 410 with an explanation that the metadata and provenance survive.

Both routes sit behind the same authentication as the rest of `/api`;
with auth enabled, an anonymous request gets 401 and no image bytes.

| Route | Serves |
|---|---|
| `GET /api/cases/{id}/geo/photos` | the marker dataset (filters: country, filename, date range, collection) |
| `GET /api/cases/{id}/images/{sourceFileID}/content` | original evidence bytes, unmodified |
| `GET /api/cases/{id}/images/{sourceFileID}/thumbnail` | a derived preview |
| `GET /api/geo/basemap` | the offline country outlines |

## Provenance

Every marker carries the whole chain, and the card shows it:

```
marker → image_gps event → source file → collection → original AD1/evidence
```

**View evidence** goes to the case's evidence view; **View timeline
event** goes to the event itself. The card shows the source path, the
collection label, the evidence SHA-256 and the event time.

The map **creates nothing.** A marker *is* an existing `image_gps` event,
read back out of the event store — the map neither parses an image nor
derives a coordinate. That is why the two directions can address the same
record: a Timeline GPS event offers **View on map**, which opens the map
with that exact photo selected, and the map links back to the same event
ID. A test asserts the marker count equals the `image_gps` event count
and that every marker's event is retrievable through the ordinary
provenance endpoint.

## Ordering

Chronological by default, or by filename or country.

Photos with **no recorded time** are shown, listed after the timed ones
in filename order, and labelled as such. They are never interleaved into
a sequence the evidence does not establish, and **no movement between
photos is inferred** — the map draws points, never a path between them.

## Coordinate precision

Many devices store rounded positions. The event carries the granularity
the stored components actually resolve, and the card shows it: a
coordinate written as whole degrees locates a point to within about
111 km, and a country derived from one inherits that uncertainty. A
country whose polygon the point sits close to is reported with
`near_boundary` confidence rather than asserted flatly.
