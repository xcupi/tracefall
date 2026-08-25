// Package web embeds and serves Tracefall's minimal dashboard. It is a
// pure JSON consumer of internal/api's HTTP surface (see static/app.js)
// and contains no forensic analysis logic of its own -- the UI must never
// become responsible for detection or correlation decisions.
package web

import (
	"embed"
	"net/http"
)

//go:embed static
var staticFS embed.FS

// StaticHandler serves the embedded static/ tree as-is (so
// "/static/app.js" resolves to the embedded "static/app.js"). Mount it at
// the "/static/" prefix.
func StaticHandler() http.Handler {
	return http.FileServer(http.FS(staticFS))
}

// Index serves the dashboard shell for every non-API route. Tracefall's
// frontend uses hash-based routing (see static/app.js), so every page the
// browser navigates to is the same document -- the server only ever needs
// to hand back index.html itself.
func Index() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := staticFS.ReadFile("static/index.html")
		if err != nil {
			http.Error(w, "index not found", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(data)
	}
}
