package api

import (
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"tracefall/internal/thumb"
)

// Photo Map HTTP surface.
//
// All three case-scoped routes go through withSecurity like every other
// /api route, so authentication and authorization are enforced before a
// handler here runs. The image routes then apply the evidence-level
// check in Service.imagePath: right case, actually an image, path inside
// the collection's own evidence directory.

func (h *handlers) geoPhotos(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	f := GeoPhotoFilter{
		Countries:     splitFilterValues(q["country"]),
		CollectionIDs: splitFilterValues(q["collection_id"]),
		Filename:      strings.TrimSpace(q.Get("filename")),
	}

	// The SAME date parsing the Timeline uses, in the analyst's own
	// display timezone -- so "29 April" means the same day on both
	// screens. A second implementation here is exactly how the two views
	// end up disagreeing about which photos fall in a range.
	loc, err := h.as(r).displayLocation()
	if h.fail(w, err) {
		return
	}
	from, to, _, err := resolveDateRange(q, loc)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	f.From, f.To = from, to

	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, "limit must be a non-negative integer")
			return
		}
		f.Limit = n
	}
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, "offset must be a non-negative integer")
			return
		}
		f.Offset = n
	}

	res, err2 := h.as(r).GeoPhotos(r.PathValue("id"), f)
	if h.fail(w, err2) {
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// imageContent streams an evidence image's ORIGINAL BYTES.
//
// http.ServeContent is used rather than a hand-rolled copy so range
// requests, conditional requests and Content-Length come out right for
// an <img> tag and a lightbox. It reads; it never writes. The bytes on
// the wire are byte-for-byte the bytes in the evidence file: nothing
// here decodes, re-encodes, rotates or strips metadata.
func (h *handlers) imageContent(w http.ResponseWriter, r *http.Request) {
	path, sf, err := h.as(r).ImageFile(r.PathValue("id"), r.PathValue("sourceFileID"))
	if h.failImage(w, err) {
		return
	}

	f, err := os.Open(path)
	if err != nil {
		h.failImage(w, ErrImageUnavailable)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		h.failImage(w, ErrImageUnavailable)
		return
	}

	// Served as an image for display, and as an attachment-safe name
	// only. A JPEG is the only artifact type that reaches here (see
	// Service.imagePath), so the type is not sniffed from the bytes.
	w.Header().Set("Content-Type", "image/jpeg")
	// Evidence is immutable once imported, and the URL is keyed by an
	// immutable source file ID, so the browser may cache it -- privately:
	// this is case evidence and must not land in a shared cache.
	w.Header().Set("Cache-Control", "private, max-age=3600")
	// The bytes are evidence, not a document to be interpreted by the
	// browser as anything else.
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", "inline; filename=\""+safeFilename(sf.OriginalFilename)+"\"")
	if sf.SHA256 != "" {
		// The evidence file's own hash, so a viewer can state which
		// bytes it is showing. Weak-comparison-safe as an ETag because
		// it identifies the exact content.
		w.Header().Set("ETag", "\""+sf.SHA256+"\"")
		w.Header().Set("X-Tracefall-Evidence-SHA256", sf.SHA256)
	}

	http.ServeContent(w, r, sf.OriginalFilename, info.ModTime(), f)
}

// imageThumbnail serves a small DERIVED preview.
//
// The response says what it is: an embedded EXIF thumbnail copied out of
// the evidence, or a rendering Tracefall produced. Neither is evidence,
// and the header names which one so a viewer never presents a rendering
// as the file's content.
func (h *handlers) imageThumbnail(w http.ResponseWriter, r *http.Request) {
	res, err := h.as(r).ImageThumbnail(r.PathValue("id"), r.PathValue("sourceFileID"))
	if err != nil {
		if errors.Is(err, thumb.ErrNotRenderable) {
			// The evidence is fine; it just cannot be previewed. That is
			// a displayable fact, not a server fault.
			writeError(w, http.StatusUnsupportedMediaType,
				"no preview can be produced from this file; its metadata and provenance are unaffected")
			return
		}
		if h.failImage(w, err) {
			return
		}
		return
	}

	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Cache-Control", "private, max-age=3600")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// A derived artifact says so on the wire, not only in the UI.
	w.Header().Set("X-Tracefall-Derived", "thumbnail")
	if res.Source != "" {
		w.Header().Set("X-Tracefall-Thumbnail-Source", res.Source)
	}
	http.ServeContent(w, r, "thumbnail.jpg", time.Time{}, strings.NewReader(string(res.JPEG)))
}

// basemap serves the offline country outlines the map draws.
//
// Case-independent -- it is world geography, not evidence -- but still
// behind the same authentication as everything else under /api, because
// an unauthenticated endpoint is a door regardless of what is behind it.
func (h *handlers) basemap(w http.ResponseWriter, r *http.Request) {
	out, err := h.as(r).Basemap()
	if h.fail(w, err) {
		return
	}
	// Immutable for the life of the binary: it is derived from a dataset
	// compiled into it.
	w.Header().Set("Cache-Control", "private, max-age=86400")
	writeJSON(w, http.StatusOK, out)
}

// failImage maps the image errors onto responses.
//
// ErrSourceFileNotFound and ErrNotAnImage both answer 404. That is
// deliberate: a request for another case's file, an invented ID, and a
// real ID that is not an image must be INDISTINGUISHABLE, or the
// endpoint becomes a way to confirm what exists in cases the caller
// cannot read.
func (h *handlers) failImage(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, ErrSourceFileNotFound), errors.Is(err, ErrNotAnImage):
		writeError(w, http.StatusNotFound, "image not found")
		return true
	case errors.Is(err, ErrImageUnavailable):
		writeError(w, http.StatusGone,
			"this image's bytes are not available: the evidence file was deleted, or was catalogued "+
				"but never imported. Its metadata and provenance are unaffected.")
		return true
	default:
		return h.fail(w, err)
	}
}

// safeFilename strips anything that could break out of the quoted
// filename in a Content-Disposition header.
func safeFilename(name string) string {
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == '"' || r == '\\' || r == '/' || r == 0x7F {
			return '_'
		}
		return r
	}, name)
	if name == "" {
		return "image.jpg"
	}
	if len(name) > 200 {
		name = name[:200]
	}
	return name
}

func splitFilterValues(vals []string) []string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		for _, part := range strings.Split(v, ",") {
			if p := strings.TrimSpace(part); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}
