package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
	parser "tracefall/internal/parsers/registry"
	"tracefall/internal/regf"
)

// Registry transaction-log companions are extracted from a disk image together
// with their hive, so the replay that already exists sees them. The fixture is
// described in companion_fixture_test.go.

type companionRun struct {
	svc   *Service
	c     model.Case
	col   model.Collection
	files map[string]model.SourceFile
	truth companionTruth
}

// hiveIDs selects the registry hives only: the NTFS metadata files of a freshly
// formatted fixture volume ($LogFile and the like) are not what is under test.
func (r companionRun) hiveIDs() []string {
	var ids []string
	for _, f := range r.files {
		if f.ArtifactType == model.ArtifactRegistryHive && f.Supported {
			ids = append(ids, f.ID)
		}
	}
	return ids
}

func (r companionRun) abs(p string) string {
	return filepath.Join(r.col.EvidenceDirectory, filepath.FromSlash(p))
}

func companionRaw(t *testing.T) string {
	t.Helper()
	return rawFixture(t, strings.TrimSuffix(companionImage, ".dd.gz"))
}

func discoverCompanionImage(t *testing.T) companionRun {
	t.Helper()
	svc, c := newImageCase(t)
	res, err := svc.DiscoverEvidenceFromPath(c.ID, companionRaw(t))
	if err != nil {
		t.Fatal(err)
	}
	return companionRun{svc: svc, c: c, col: res.Collection, files: catalogPaths(t, svc, res.Collection.ID), truth: loadCompanionTruth(t)}
}

func importCompanionImage(t *testing.T) companionRun {
	t.Helper()
	r := discoverCompanionImage(t)
	ids := r.hiveIDs()
	imp, err := r.svc.ImportEvidence(r.c.ID, r.col.ID, ids)
	if err != nil {
		t.Fatal(err)
	}
	if len(imp.ParseFailures) != 0 {
		t.Fatalf("parse failures: %+v", imp.ParseFailures)
	}
	r.files = catalogPaths(t, r.svc, r.col.ID)
	return r
}

func (r companionRun) eventsOf(t *testing.T, path string) []model.Event {
	t.Helper()
	sf, ok := r.files[path]
	if !ok {
		t.Fatalf("%s is not in the catalog", path)
	}
	all, err := r.svc.store.ListEventsByCollection(r.col.ID)
	if err != nil {
		t.Fatal(err)
	}
	var out []model.Event
	for _, e := range all {
		if e.SourceFileID == sf.ID {
			out = append(out, e)
		}
	}
	return out
}

func hasValue(events []model.Event, data string) bool {
	for _, e := range events {
		if strings.Contains(e.Extra["registry_value_data"], data) {
			return true
		}
	}
	return false
}

func (r companionRun) replay(t *testing.T, hive string) *model.HiveReplay {
	t.Helper()
	sf := r.files[hive]
	if sf.ParseCoverage == nil || sf.ParseCoverage.HiveReplay == nil {
		t.Fatalf("%s: no hive replay status recorded (coverage %+v)", hive, sf.ParseCoverage)
	}
	return sf.ParseCoverage.HiveReplay
}

const (
	v1cfg = "vol1/" + cfgDir
)

func TestCompanion_LogsAreExtractedBesideTheirHiveWithRecordedHashes(t *testing.T) {
	r := importCompanionImage(t)
	for _, p := range []string{
		v1cfg + "SYSTEM.LOG1", v1cfg + "SYSTEM.LOG2", v1cfg + "SOFTWARE.log1", v1cfg + "SECURITY.LOG1", v1cfg + "DEFAULT.LOG1",
		"vol1/Users/alice/NTUSER.DAT.LOG1", "vol1/Users/alice/AppData/Local/Microsoft/Windows/UsrClass.dat.LOG1",
		"vol1/Windows/AppCompat/Programs/Amcache.hve.LOG1",
	} {
		want := r.truth.Files[p]
		if want == "" {
			t.Fatalf("fixture manifest lacks %s", p)
		}
		if got := fileSHA256(t, r.abs(p)); got != want {
			t.Errorf("%s: extracted bytes hash %s, want %s", p, got, want)
		}
		if r.files[p].SHA256 != want {
			t.Errorf("%s: recorded sha256 %q, want %q", p, r.files[p].SHA256, want)
		}
	}
}

func TestCompanion_NeverPullsLogsOfAnotherHiveDirectoryOrVolume(t *testing.T) {
	r := importCompanionImage(t)
	for _, p := range []string{
		"vol2/" + cfgDir + "SAM.LOG1",      // same name, other volume
		"vol1/Users/carol/NTUSER.DAT.LOG1", // hive's name, other directory, no hive beside it
		v1cfg + "RegBack/SOFTWARE.LOG1",    // never existed: parent's log must not be copied down
		v1cfg + "RegBack/SOFTWARE.log1",    // idem
		"vol1/Users/bob/NTUSER.DAT.LOG1",   // idem
		"vol1/" + cfgDir + "SAM.LOG1",      // idem
		"vol1/Users/alice/SYSTEM.LOG1",     // idem
		"vol1/Users/alice/NTUSER.DAT.LOG2", // never existed
	} {
		if _, err := os.Stat(r.abs(p)); err == nil {
			t.Errorf("%s was extracted but belongs to no extracted hive", p)
		}
	}
	// Their rows are not labeled as companions either.
	for _, p := range []string{"vol2/" + cfgDir + "SAM.LOG1", "vol1/Users/carol/NTUSER.DAT.LOG1"} {
		sf, ok := r.files[p]
		if !ok {
			t.Fatalf("%s should still be cataloged", p)
		}
		if sf.ParseCoverage != nil && sf.ParseCoverage.CompanionOf != "" {
			t.Errorf("%s is labeled companion-of %q", p, sf.ParseCoverage.CompanionOf)
		}
		if sf.SHA256 != "" {
			t.Errorf("%s has a hash although it was not extracted", p)
		}
	}
	// The hives that have no log of their own say so instead of borrowing one.
	for _, hive := range []string{v1cfg + "SAM", v1cfg + "RegBack/SOFTWARE", "vol1/Users/bob/NTUSER.DAT"} {
		hr := r.replay(t, hive)
		if hr.State != "no_logs" || len(hr.Companions) != 0 {
			t.Errorf("%s: %+v, want no_logs with no companions", hive, hr)
		}
		if !strings.Contains(hr.Reason, "no transaction log") || !strings.Contains(hr.Reason, "disk image") {
			t.Errorf("%s: reason does not say the image holds no log beside it: %q", hive, hr.Reason)
		}
	}
}

func TestCompanion_ReplayChangesAppearOnlyBecauseTheLogsWereExtracted(t *testing.T) {
	r := importCompanionImage(t)
	sw := r.eventsOf(t, v1cfg+"SOFTWARE")
	if !hasValue(sw, `C:\Users\Public\final.exe`) || !hasValue(sw, `C:\Users\Public\mid.exe`) {
		t.Fatalf("SOFTWARE: values that exist only in SOFTWARE.log1 are missing from the events")
	}
	sys := r.eventsOf(t, v1cfg+"SYSTEM")
	if !hasValue(sys, `C:\Users\Public\mid.exe`) || !hasValue(sys, `C:\Users\Public\final.exe`) {
		t.Fatalf("SYSTEM: the chain LOG1 -> LOG2 was not replayed")
	}
	nu := r.eventsOf(t, "vol1/Users/alice/NTUSER.DAT")
	if !hasValue(nu, `C:\Users\Public\final.exe`) {
		t.Fatalf("NTUSER.DAT: value that exists only in NTUSER.DAT.LOG1 is missing")
	}
	for _, e := range sw {
		if e.Extra["hive_state"] != "replayed" {
			t.Errorf("SOFTWARE event is not marked replayed: %v", e.Extra)
		}
	}
	// Negative control: the very same primary file, extracted alone, shows none of it.
	alone := filepath.Join(t.TempDir(), "SOFTWARE")
	b, err := os.ReadFile(r.abs(v1cfg + "SOFTWARE"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(alone, b, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := parser.New().ParseWithContext(alone, parsers.ParseContext{EvidencePath: "SOFTWARE"})
	if err != nil {
		t.Fatal(err)
	}
	if hasValue(res.Events, `C:\Users\Public\final.exe`) || hasValue(res.Events, `C:\Users\Public\mid.exe`) {
		t.Fatal("the log-only change is visible without the log: the control proves nothing")
	}
	if res.Coverage == nil || res.Coverage.HiveReplay == nil || res.Coverage.HiveReplay.State != "no_logs" {
		t.Errorf("without its logs the hive should say no_logs, got %+v", res.Coverage)
	}
}

func TestCompanion_PerHiveReplayStatusIsRecorded(t *testing.T) {
	r := importCompanionImage(t)
	for _, tc := range []struct {
		hive      string
		state     string
		logs      []string // companion file names, in order
		applied   []string
		cleanOnly bool
	}{
		{v1cfg + "SYSTEM", "replayed", []string{"SYSTEM.LOG1", "SYSTEM.LOG2"}, []string{"SYSTEM.LOG1", "SYSTEM.LOG2"}, false},
		{v1cfg + "SOFTWARE", "replayed", []string{"SOFTWARE.log1"}, []string{"SOFTWARE.log1"}, false},
		{v1cfg + "SECURITY", "clean", []string{"SECURITY.LOG1"}, nil, true},
		{v1cfg + "DEFAULT", "replayed", []string{"DEFAULT.LOG1"}, []string{"DEFAULT.LOG1"}, false},
		{"vol1/Users/alice/NTUSER.DAT", "replayed", []string{"NTUSER.DAT.LOG1"}, []string{"NTUSER.DAT.LOG1"}, false},
		{"vol1/Users/alice/AppData/Local/Microsoft/Windows/UsrClass.dat", "replayed", []string{"UsrClass.dat.LOG1"}, []string{"UsrClass.dat.LOG1"}, false},
		{"vol1/Windows/AppCompat/Programs/Amcache.hve", "replayed", []string{"Amcache.hve.LOG1"}, []string{"Amcache.hve.LOG1"}, false},
	} {
		hr := r.replay(t, tc.hive)
		if hr.State != tc.state {
			t.Errorf("%s: state %q, want %q (%s)", tc.hive, hr.State, tc.state, hr.Reason)
		}
		var got []string
		for _, c := range hr.Companions {
			got = append(got, filepath.Base(c.Path))
			if c.Status != model.CompanionExtracted || c.SHA256 != r.truth.Files[c.Path] || c.SHA256 == "" {
				t.Errorf("%s: companion %+v, want extracted with the manifest hash %s", tc.hive, c, r.truth.Files[c.Path])
			}
		}
		if strings.Join(got, ",") != strings.Join(tc.logs, ",") {
			t.Errorf("%s: companions %v, want %v", tc.hive, got, tc.logs)
		}
		if strings.Join(hr.LogsApplied, ",") != strings.Join(tc.applied, ",") {
			t.Errorf("%s: logs applied %v, want %v", tc.hive, hr.LogsApplied, tc.applied)
		}
		if tc.cleanOnly && r.files[tc.hive].ParseCoverage.Incomplete() {
			t.Errorf("%s: a clean hive with an unused log must not be flagged incomplete", tc.hive)
		}
	}
}

func TestCompanion_LogsAreLabeledAndAreNotIndependentEvidence(t *testing.T) {
	r := importCompanionImage(t)
	logs := map[string]string{ // log -> hive
		v1cfg + "SYSTEM.LOG1":              v1cfg + "SYSTEM",
		v1cfg + "SYSTEM.LOG2":              v1cfg + "SYSTEM",
		v1cfg + "SOFTWARE.log1":            v1cfg + "SOFTWARE",
		v1cfg + "SECURITY.LOG1":            v1cfg + "SECURITY",
		"vol1/Users/alice/NTUSER.DAT.LOG1": "vol1/Users/alice/NTUSER.DAT",
	}
	for lp, hive := range logs {
		sf := r.files[lp]
		if sf.ParseCoverage == nil || sf.ParseCoverage.CompanionOf != hive {
			t.Errorf("%s: companion_of = %+v, want %s", lp, sf.ParseCoverage, hive)
		}
		if sf.ImportStatus != model.SourceFileUnsupported || sf.EventCount != 0 || sf.Supported {
			t.Errorf("%s: a companion is not parsed evidence: %+v", lp, sf)
		}
		if n := len(r.eventsOf(t, lp)); n != 0 {
			t.Errorf("%s: %d events attributed to a transaction log", lp, n)
		}
		tr := triage(sf)
		if tr.CompanionOf != hive {
			t.Errorf("%s: triage CompanionOf = %q", lp, tr.CompanionOf)
		}
		if tr.UnsupportedReason != "" || !strings.Contains(tr.Note, hive) {
			t.Errorf("%s: a companion must not read as an unsupported gap: reason %q note %q", lp, tr.UnsupportedReason, tr.Note)
		}
	}
	// Strays stay what they were: unsupported, unlabeled.
	stray := triage(r.files["vol2/"+cfgDir+"SAM.LOG1"])
	if stray.CompanionOf != "" {
		t.Errorf("a log with no hive beside it is labeled companion-of %q", stray.CompanionOf)
	}
}

func TestCompanion_CatalogLabelsLogsAtDiscoveryBeforeAnythingIsExtracted(t *testing.T) {
	r := discoverCompanionImage(t)
	sf := r.files[v1cfg+"SYSTEM.LOG1"]
	if sf.ParseCoverage == nil || sf.ParseCoverage.CompanionOf != v1cfg+"SYSTEM" {
		t.Fatalf("SYSTEM.LOG1 at discovery: %+v", sf.ParseCoverage)
	}
	if _, err := os.Stat(r.abs(v1cfg + "SYSTEM.LOG1")); err == nil {
		t.Error("discovery must not extract anything")
	}
	files, _ := r.svc.store.ListSourceFilesByCollection(r.col.ID)
	var triaged []TriagedSourceFile
	for _, f := range files {
		triaged = append(triaged, triage(f))
	}
	cov := computeCoverage(triaged)
	if cov.Companions != 8 {
		t.Errorf("coverage companions = %d, want 8 (SYSTEM x2, SOFTWARE, SECURITY, DEFAULT, NTUSER, UsrClass, Amcache)", cov.Companions)
	}
}

func TestCompanion_OversizeLogFailsVisiblyAndTheHiveIsStillParsed(t *testing.T) {
	old := maxCompanionLogBytes
	maxCompanionLogBytes = 1024
	t.Cleanup(func() { maxCompanionLogBytes = old })
	r := importCompanionImage(t)
	if _, err := os.Stat(r.abs(v1cfg + "DEFAULT.LOG1")); err == nil {
		t.Error("an oversize log was extracted")
	}
	hr := r.replay(t, v1cfg+"DEFAULT")
	if hr.State != "no_logs" {
		t.Errorf("state = %q, want no_logs", hr.State)
	}
	if len(hr.Companions) != 1 || hr.Companions[0].Status != model.CompanionOversize || hr.Companions[0].SizeBytes == 0 {
		t.Fatalf("companions = %+v, want one oversize entry with its size", hr.Companions)
	}
	if !strings.Contains(hr.Reason, "DEFAULT.LOG1") || !strings.Contains(hr.Reason, "not extracted") {
		t.Errorf("reason must name the log that was not extracted: %q", hr.Reason)
	}
	sf := r.files[v1cfg+"DEFAULT"]
	if sf.ImportStatus != model.SourceFileImported {
		t.Errorf("the hive itself must still be imported, status %s", sf.ImportStatus)
	}
	if sf.ParseCoverage == nil || !sf.ParseCoverage.Incomplete() {
		t.Errorf("the missing log must make the hive's coverage incomplete: %+v", sf.ParseCoverage)
	}
	if !strings.Contains(strings.Join(sf.ParseCoverage.Notes, " "), "DEFAULT.LOG1") {
		t.Errorf("coverage notes do not name the log: %v", sf.ParseCoverage.Notes)
	}
}

func TestCompanion_ReimportAndRepeatedExtractionChangeNothing(t *testing.T) {
	r := importCompanionImage(t)
	before := map[string]string{}
	for p := range r.truth.Files {
		if strings.Contains(strings.ToUpper(p), ".LOG") {
			if _, err := os.Stat(r.abs(p)); err == nil {
				before[p] = fileSHA256(t, r.abs(p))
			}
		}
	}
	if len(before) != 8 {
		t.Fatalf("extracted companions = %d, want 8", len(before))
	}
	n1, _ := r.svc.store.CountEvents(r.c.ID)
	if _, err := r.svc.ImportEvidence(r.c.ID, r.col.ID, r.hiveIDs()); err != nil {
		t.Fatal(err)
	}
	// Extract every hive again, as the bootkey and time-zone helpers do.
	for _, p := range []string{v1cfg + "SYSTEM", v1cfg + "SOFTWARE", "vol1/Users/alice/NTUSER.DAT"} {
		if err := r.svc.extractDiskImageEntry(r.c.ID, r.col.ID, r.files[p]); err != nil {
			t.Fatal(err)
		}
	}
	n2, _ := r.svc.store.CountEvents(r.c.ID)
	if n1 != n2 {
		t.Errorf("events %d -> %d after a second import", n1, n2)
	}
	for p, h := range before {
		if got := fileSHA256(t, r.abs(p)); got != h {
			t.Errorf("%s changed", p)
		}
	}
	after := catalogPaths(t, r.svc, r.col.ID)
	if len(after) != len(r.files) {
		t.Errorf("catalog rows %d -> %d", len(r.files), len(after))
	}
	// No file other than the cataloged ones appeared.
	var extra []string
	_ = filepath.Walk(r.col.EvidenceDirectory, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			rel, _ := filepath.Rel(r.col.EvidenceDirectory, p)
			if _, ok := after[filepath.ToSlash(rel)]; !ok {
				extra = append(extra, rel)
			}
		}
		return nil
	})
	if len(extra) != 0 {
		t.Errorf("files outside the catalog: %v", extra)
	}
}

func TestCompanion_BootKeyAndTimeZoneHelpersSeeTheSameReplayedState(t *testing.T) {
	r := discoverCompanionImage(t)
	sys := r.files[v1cfg+"SYSTEM"]
	path, ok := r.svc.materializeForRead(r.c.ID, r.col.ID, r.col, sys)
	if !ok {
		t.Fatal("SYSTEM could not be materialized")
	}
	if _, err := os.Stat(r.abs(v1cfg + "SYSTEM.LOG2")); err != nil {
		t.Fatalf("materializing the hive for a helper left its log behind: %v", err)
	}
	h, err := regf.OpenReplayed(path, regf.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if st := h.Recovery().State; st != regf.RecoveryReplayed {
		t.Errorf("helper-side state = %s, want replayed", st)
	}
}
