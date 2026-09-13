// Package browserdb recognizes the SQLite databases a browser profile
// holds that Tracefall does NOT parse.
//
// It exists to stop a classification lie. Browser history is one
// database in a profile that holds a dozen; the rest are cookies, saved
// logins, favicons, autofill, media playback state, quota bookkeeping
// and so on. Claiming all of them as "browser history" and then failing
// each at import told an analyst that 25 files of evidence were broken,
// when nothing was broken and none of them was history.
//
// Recognizing a file is NOT parsing it. Everything here is catalogued as
// present, named, and explicitly unsupported. No event, timestamp, URL
// or hash is produced from any of it, and nothing here is a claim about
// what the database contains -- only about which database it is.
package browserdb

import (
	"path"
	"strings"
)

// Kind is what a recognized-but-unparsed browser database is.
type Kind string

const (
	// KindNone means the file was not recognized as a browser database.
	KindNone Kind = ""

	KindCookies     Kind = "cookies"
	KindCredentials Kind = "saved_credentials"
	KindFavicons    Kind = "favicons"
	KindAutofill    Kind = "autofill_and_form_data"
	KindMedia       Kind = "media_playback"
	KindTopSites    Kind = "top_sites"
	KindShortcuts   Kind = "omnibox_shortcuts"
	KindPrediction  Kind = "network_prediction"
	KindQuota       Kind = "storage_quota"
	KindReporting   Kind = "reporting_and_nel"
	KindWebStorage  Kind = "web_storage"
	KindExtension   Kind = "extension_or_component"
	KindNotify      Kind = "windows_notifications"
	KindOther       Kind = "other_browser_database"
)

// Description is a one-line, factual statement of what each kind is,
// for the analyst reading a catalog. It says what the file IS, never
// what it might contain.
var Description = map[Kind]string{
	KindCookies:     "browser cookie store",
	KindCredentials: "browser saved-credential store",
	KindFavicons:    "browser favicon cache",
	KindAutofill:    "browser autofill and form data",
	KindMedia:       "browser media playback history",
	KindTopSites:    "browser most-visited-sites cache",
	KindShortcuts:   "browser address-bar shortcut database",
	KindPrediction:  "browser network prediction database",
	KindQuota:       "browser storage quota bookkeeping",
	KindReporting:   "browser reporting and network error logging",
	KindWebStorage:  "web storage database used by a site or extension",
	KindExtension:   "browser extension or component database",
	KindNotify:      "Windows notification platform database",
	KindOther:       "browser-related database",
}

// byName maps the exact filenames Chromium and Firefox define. Exact
// names, not patterns: a file called "Cookies" in a browser profile is
// the cookie store, and a file called "Cookies.txt" somewhere else is
// not, and guessing between them is how misclassification starts.
var byName = map[string]Kind{
	// Chromium.
	"cookies":                          KindCookies,
	"safe browsing cookies":            KindCookies,
	"extension cookies":                KindCookies,
	"login data":                       KindCredentials,
	"login data for account":           KindCredentials,
	"favicons":                         KindFavicons,
	"web data":                         KindAutofill,
	"affiliation database":             KindCredentials,
	"media history":                    KindMedia,
	"top sites":                        KindTopSites,
	"shortcuts":                        KindShortcuts,
	"network action predictor":         KindPrediction,
	"quotamanager":                     KindQuota,
	"reporting and nel":                KindReporting,
	"trust tokens":                     KindOther,
	"databases.db":                     KindWebStorage,
	"heavy_ad_intervention_opt_out.db": KindOther,
	"previews_opt_out.db":              KindOther,
	"publisher_info_db":                KindOther,
	"publisher_info_db-journal":        KindOther,
	// Firefox.
	"cookies.sqlite":       KindCookies,
	"formhistory.sqlite":   KindAutofill,
	"favicons.sqlite":      KindFavicons,
	"permissions.sqlite":   KindOther,
	"content-prefs.sqlite": KindOther,
	"webappsstore.sqlite":  KindWebStorage,
	"storage.sqlite":       KindWebStorage,
	"protections.sqlite":   KindOther,
	"key4.db":              KindCredentials,
	"cert9.db":             KindOther,
	// Windows / platform databases that live near browser data and were
	// swept up by the same over-broad SQLite match.
	"wpndatabase.db":  KindNotify,
	"queue.sqlite3":   KindOther,
	"database.sqlite": KindOther,
}

// Recognize identifies a browser-related database by its filename and,
// where the name settles nothing, by the directory it sits in.
//
// It is only ever consulted for files that are actually SQLite
// databases, which the caller establishes from the file's own bytes.
// Name alone never makes something a browser database here.
func Recognize(relPath string, isSQLite bool) Kind {
	if !isSQLite {
		return KindNone
	}
	base := strings.ToLower(path.Base(strings.ReplaceAll(relPath, "\\", "/")))
	if k, ok := byName[base]; ok {
		return k
	}
	// Unnamed SQLite inside a browser profile. Recognized as browser
	// data without claiming which -- that is honest, and it is what the
	// analyst needs to know to decide whether to look further.
	if InBrowserProfile(relPath) {
		return KindOther
	}
	return KindNone
}

// browserProfileMarkers are directory segments that identify a browser's
// own data directory. Each is a vendor path component, so a user folder
// that merely happens to be called "Default" does not match.
var browserProfileMarkers = []string{
	"/google/chrome/", "/chromium/", "/microsoft/edge/", "/bravesoftware/",
	"/opera software/", "/vivaldi/", "/yandex/", "/mozilla/firefox/",
	"/mozilla/thunderbird/", "/waterfox/", "/librewolf/", "/tor browser/",
}

// InBrowserProfile reports whether relPath is inside a browser's data
// directory.
func InBrowserProfile(relPath string) bool {
	p := "/" + strings.ToLower(strings.Trim(strings.ReplaceAll(relPath, "\\", "/"), "/"))
	for _, m := range browserProfileMarkers {
		if strings.Contains(p, m) {
			return true
		}
	}
	return false
}
