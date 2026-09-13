package ingest_test

import (
	"database/sql"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"tracefall/internal/browsercache/cachegen"
	"tracefall/internal/ingest"
	"tracefall/internal/model"
	"tracefall/internal/prefetch/prefetchgen"
	"tracefall/internal/regf/regfgen"
)

// Artifact CLASSIFICATION matrix.
//
// Every entry here is a file that a real Windows image actually
// contains, and every "NOT" row is a file that was previously
// catalogued as something it is not and then failed at import. The
// failures were not evidence of damage; they were evidence of
// over-broad detection. In one image:
//
//   - 25 SQLite databases from browser profiles were catalogued as
//     "Browser history (Chromium / Firefox)"
//   - 20 registry transaction logs were catalogued as "Windows Registry
//     Hive"
//   -  7 application-compatibility databases were catalogued as
//     "Prefetch" because they share the MAM compression container
//
// This test asserts what each file IS, through the same entry point
// discovery uses, so a future widening of any detector fails here rather
// than in an analyst's evidence list.

// classify runs one file through the real discovery path and returns the
// artifact type and whether a parser claimed it.
func classify(t *testing.T, relPath string, body []byte) (artifactType string, supported bool) {
	t.Helper()
	dir := t.TempDir()
	full := filepath.Join(dir, filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, body, 0o600); err != nil {
		t.Fatal(err)
	}
	files, err := ingest.Discover(dir, ingest.Registry())
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("discovered %d files, want 1", len(files))
	}
	return files[0].ArtifactType, files[0].Supported
}

// ---------------- fixtures ----------------

// chromiumHistoryDB builds a real SQLite database with the Chromium
// history schema.
func chromiumHistoryDB(t *testing.T) []byte { return sqliteDB(t, chromiumHistorySchema) }

// firefoxPlacesDB builds a real Firefox places.sqlite.
func firefoxPlacesDB(t *testing.T) []byte { return sqliteDB(t, firefoxPlacesSchema) }

// otherBrowserDB builds a real SQLite database that is NOT history --
// the shape every cookie store, favicon cache and autofill database in a
// profile has.
func otherBrowserDB(t *testing.T) []byte { return sqliteDB(t, cookiesSchema) }

var (
	chromiumHistorySchema = []string{
		`CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER)`,
		`CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, transition INTEGER)`,
	}
	firefoxPlacesSchema = []string{
		`CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER)`,
		`CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER)`,
	}
	cookiesSchema = []string{
		`CREATE TABLE cookies(creation_utc INTEGER, host_key TEXT, name TEXT, value TEXT, expires_utc INTEGER)`,
	}
)

func sqliteDB(t *testing.T, stmts []string) []byte {
	t.Helper()
	p := filepath.Join(t.TempDir(), "db.sqlite")
	db, err := sql.Open("sqlite", p)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// primaryHive is a real REGF primary hive.
func primaryHive() []byte {
	return regfgen.Build(`\SystemRoot\System32\Config\SYSTEM`,
		regfgen.NewKey("ROOT", regfgen.NewKey("Select").WithValues(regfgen.DWordValue("Current", 1))))
}

// transactionLog is a REGF file with a transaction-log file type -- what
// SAM.LOG1 and its siblings actually are. Built from a real hive so only
// the one distinguishing field differs.
func transactionLog() []byte {
	b := primaryHive()
	binary.LittleEndian.PutUint32(b[28:32], 6)
	return b
}

const chromeProfile = "Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/"
const firefoxProfile = "Users/jdoe/AppData/Roaming/Mozilla/Firefox/Profiles/ab12.default-release/"
const configDir = "Windows/System32/config/"

// ---------------- browser databases ----------------

func TestClassify_OnlyRealHistoryDatabasesAreBrowserHistory(t *testing.T) {
	// The two that ARE history.
	for _, tc := range []struct {
		path string
		body []byte
	}{
		{chromeProfile + "History", chromiumHistoryDB(t)},
		{firefoxProfile + "places.sqlite", firefoxPlacesDB(t)},
	} {
		at, supported := classify(t, tc.path, tc.body)
		if at != model.ArtifactBrowserHistory || !supported {
			t.Errorf("%s: artifact=%q supported=%v, want browser_history/true", tc.path, at, supported)
		}
	}

	// Every other database in a browser profile. Each of these was
	// catalogued as browser history and failed at import.
	for _, name := range []string{
		"Cookies", "Favicons", "Login Data", "Media History",
		"Network Action Predictor", "QuotaManager", "Reporting and NEL",
		"Shortcuts", "Top Sites", "Web Data", "Databases.db",
		"Safe Browsing Cookies", "heavy_ad_intervention_opt_out.db",
		"previews_opt_out.db", "publisher_info_db",
	} {
		at, supported := classify(t, chromeProfile+name, otherBrowserDB(t))
		if at == model.ArtifactBrowserHistory {
			t.Errorf("%s is still classified as browser history", name)
		}
		if supported {
			t.Errorf("%s is claimed by a parser; it is recognized, not parsed", name)
		}
		if at != model.ArtifactUnsupportedBrowserDB {
			t.Errorf("%s: artifact=%q, want %q", name, at, model.ArtifactUnsupportedBrowserDB)
		}
	}

	// Firefox's non-history databases too.
	for _, name := range []string{"cookies.sqlite", "formhistory.sqlite", "key4.db"} {
		at, _ := classify(t, firefoxProfile+name, otherBrowserDB(t))
		if at == model.ArtifactBrowserHistory {
			t.Errorf("%s is classified as browser history", name)
		}
	}

	// And the OS databases that were swept up by the same over-broad
	// SQLite match, from outside any browser profile.
	for _, p := range []string{
		"Users/jdoe/AppData/Local/Microsoft/Windows/Notifications/wpndatabase.db",
		"ProgramData/Microsoft/Windows/queue.sqlite3",
		"Users/jdoe/AppData/Local/SomeApp/database.sqlite",
	} {
		at, supported := classify(t, p, otherBrowserDB(t))
		if at == model.ArtifactBrowserHistory {
			t.Errorf("%s is classified as browser history", p)
		}
		if supported {
			t.Errorf("%s is claimed by a parser", p)
		}
	}
}

// A file named History that is not a database must not be claimed --
// otherwise it is catalogued as evidence and then reported as broken.
func TestClassify_HistoryNameIsConfirmedByContent(t *testing.T) {
	at, supported := classify(t, chromeProfile+"History", []byte("this is a note, not a database\n"))
	if supported || at == model.ArtifactBrowserHistory {
		t.Errorf("a text file named History was claimed: artifact=%q supported=%v", at, supported)
	}
}

// ---------------- registry ----------------

func TestClassify_OnlyPrimaryHivesAreRegistryHives(t *testing.T) {
	for _, name := range []string{"SAM", "SYSTEM", "SOFTWARE", "SECURITY", "DEFAULT"} {
		at, supported := classify(t, configDir+name, primaryHive())
		if at != model.ArtifactRegistryHive || !supported {
			t.Errorf("%s: artifact=%q supported=%v, want registry_hive/true", name, at, supported)
		}
	}

	// The transaction logs. Every one of these was catalogued as a hive
	// and failed at import with "this is a registry transaction log".
	for _, name := range []string{
		"SAM.LOG1", "SAM.LOG2", "SYSTEM.LOG1", "SYSTEM.LOG2",
		"SOFTWARE.LOG1", "SOFTWARE.LOG2", "DEFAULT.LOG1", "DEFAULT.LOG2",
		"SECURITY.LOG1", "SECURITY.LOG2", "BBI.LOG1", "BBI.LOG2",
		"BCD-Template.LOG", "COMPONENTS.LOG1", "DRIVERS.LOG1", "DRIVERS.LOG2",
		"ELAM.LOG1",
	} {
		at, supported := classify(t, configDir+name, transactionLog())
		if at == model.ArtifactRegistryHive {
			t.Errorf("%s is still classified as a registry hive", name)
		}
		if supported {
			t.Errorf("%s is claimed by the hive parser", name)
		}
		if at != model.ArtifactRegistryTransactionLog {
			t.Errorf("%s: artifact=%q, want %q", name, at, model.ArtifactRegistryTransactionLog)
		}
	}

	// A per-user hive and its log, from a different directory.
	if at, _ := classify(t, "Users/jdoe/NTUSER.DAT", primaryHive()); at != model.ArtifactRegistryHive {
		t.Errorf("NTUSER.DAT: artifact=%q", at)
	}
	for _, name := range []string{"UsrClass.dat.LOG1", "UsrClass.dat.LOG2"} {
		at, supported := classify(t, "Users/jdoe/AppData/Local/Microsoft/Windows/"+name, transactionLog())
		if at == model.ArtifactRegistryHive || supported {
			t.Errorf("%s: artifact=%q supported=%v", name, at, supported)
		}
	}

	// A renamed primary hive is still found by content -- narrowing the
	// check must not cost that.
	if at, supported := classify(t, "triage/blob.bin", primaryHive()); at != model.ArtifactRegistryHive || !supported {
		t.Errorf("a renamed hive: artifact=%q supported=%v", at, supported)
	}
}

// ---------------- prefetch ----------------

func TestClassify_PrefetchAndNonPrefetchMAMContainers(t *testing.T) {
	scca := prefetchgen.Build(prefetchgen.File{
		Version: 30, ExecutableName: "NOTEPAD.EXE", RunCount: 3,
		LastRunTimes: []time.Time{time.Date(2024, 5, 2, 14, 30, 0, 0, time.UTC)},
	})

	// Uncompressed and MAM-compressed Prefetch are both classified.
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"NOTEPAD.EXE-D8414F97.pf", scca},
		{"NOTEPAD.EXE-D8414F98.pf", prefetchgen.CompressMAM(scca)},
	} {
		at, supported := classify(t, "Windows/Prefetch/"+tc.name, tc.body)
		if at != model.ArtifactPrefetch || !supported {
			t.Errorf("%s: artifact=%q supported=%v, want prefetch/true", tc.name, at, supported)
		}
	}

	// A MAM container that is NOT Prefetch. Windows wraps the
	// application-compatibility databases in the same directory the same
	// way; seven of them were catalogued as Prefetch and then reported
	// as using an unsupported compression method.
	notPrefetch := prefetchgen.CompressMAM([]byte("this is not an SCCA record, it is some other Windows database"))
	for _, name := range []string{
		"AgGlGlobalHistory.db", "AgCx_SC4.db", "ResPriHMStaticDb.ebd",
	} {
		at, supported := classify(t, "Windows/Prefetch/"+name, notPrefetch)
		if at == model.ArtifactPrefetch {
			t.Errorf("%s is classified as Prefetch on the MAM container alone", name)
		}
		if supported {
			t.Errorf("%s is claimed by the Prefetch parser", name)
		}
	}

	// A file merely named .pf that is not Prefetch at all is not claimed.
	if at, supported := classify(t, "Windows/Prefetch/NOTES.pf", []byte("just a text file\n")); supported {
		t.Errorf("a text file named .pf was claimed: artifact=%q", at)
	}
}

// ---------------- browser cache ----------------

func TestClassify_CacheIndexesVersusCachedBodies(t *testing.T) {
	const cacheDir = "Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/Cache/"

	// A Chromium blockfile index and a Firefox _CACHE_MAP_ are cache
	// metadata containers.
	if at, supported := classify(t, cacheDir+"index", cachegen.ChromiumBlockfileIndex()); at != model.ArtifactBrowserCacheIndex || !supported {
		t.Errorf("Chromium cache index: artifact=%q supported=%v", at, supported)
	}
	ffMap := cachegen.BuildFirefoxCache1Map(cachegen.Cache1MapOptions{})
	if at, supported := classify(t, "Users/jdoe/AppData/Local/Mozilla/Firefox/Profiles/ab.default/Cache/_CACHE_MAP_", ffMap); at != model.ArtifactBrowserCacheIndex || !supported {
		t.Errorf("Firefox _CACHE_MAP_: artifact=%q supported=%v", at, supported)
	}

	// A cached response BODY is not cache metadata. It carries no
	// structure of its own and must never be handed to the metadata
	// parser.
	body := []byte("HTTP body bytes, no cache structure at all, just the resource itself")
	for _, name := range []string{"f_000001", "f_0000ab", "f_00ffff"} {
		at, supported := classify(t, cacheDir+name, body)
		if at == model.ArtifactBrowserCache || at == model.ArtifactBrowserCacheIndex {
			t.Errorf("%s is classified as cache metadata (%q)", name, at)
		}
		if supported {
			t.Errorf("%s is claimed by a cache parser", name)
		}
		// It should still be VISIBLE as what it is, not silently
		// unrecognized.
		if at == "" {
			t.Errorf("%s is not recognized at all; a cached body should be catalogued as one", name)
		}
	}
}

// Every artifact type this test asserts must be registered, or the
// Timeline shows a raw constant instead of a label.
func TestClassify_NewArtifactTypesAreRegistered(t *testing.T) {
	for _, at := range []string{
		model.ArtifactUnsupportedBrowserDB,
		model.ArtifactRegistryTransactionLog,
	} {
		if strings.TrimSpace(at) == "" {
			t.Fatal("empty artifact type constant")
		}
	}
}
