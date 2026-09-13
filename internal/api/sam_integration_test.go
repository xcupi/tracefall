package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/sam/samgen"
)

// End-to-end tests for Windows SAM account and NTLM hash evidence
// (Phase 18): ingestion, Timeline visibility, provenance, the deletion
// lifecycle, and the security boundaries around credential material.

const (
	samHashJDoe = "8846f7eaee8fb117ad06bdd830b7586c"
	samHashSvc  = "e19ccf75ee54e06b06a5907af13cef42"
)

func samHexBytes(s string) []byte {
	out := make([]byte, len(s)/2)
	for i := range out {
		out[i] = samNibble(s[i*2])<<4 | samNibble(s[i*2+1])
	}
	return out
}

func samNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

func samFixtureAccounts() []samgen.Account {
	return []samgen.Account{
		{RID: 500, Username: "Administrator", ACBFlags: 0x0211},
		{
			RID: 1001, Username: "jdoe", FullName: "J Doe",
			NTLM: samHexBytes(samHashJDoe), ACBFlags: 0x0214,
			LastLogon:       time.Date(2024, 5, 2, 14, 30, 0, 0, time.UTC),
			LastPasswordSet: time.Date(2024, 1, 9, 8, 15, 0, 0, time.UTC),
			LoginCount:      14,
		},
		{
			RID: 1002, Username: "svc_backup",
			NTLM: samHexBytes(samHashSvc), ACBFlags: 0x0210,
		},
	}
}

// samConfigDir is the shape a real triage collection has: SAM and SYSTEM
// side by side in Windows\System32\config.
func samConfigDir(withSystem bool) map[string][]byte {
	files := map[string][]byte{
		"Windows/System32/config/SAM": samgen.SAMHive(samgen.Options{Accounts: samFixtureAccounts()}),
	}
	if withSystem {
		files["Windows/System32/config/SYSTEM"] = samgen.SystemHive(nil)
	}
	return files
}

// samMixedDir adds an unrelated artifact, so "filtering by Windows SAM"
// is a filter that has something to exclude.
func samMixedDir(t *testing.T) map[string][]byte {
	files := samConfigDir(true)
	files["Windows/Prefetch/UPDATER.EXE-11223344.pf"] = p15Prefetch()
	return files
}

func samCaseWith(t *testing.T, mux http.Handler, withSystem bool) (string, DiscoverResult) {
	t.Helper()
	c := mustCreateCase(t, mux, "SAM "+t.Name())
	files := samConfigDir(withSystem)
	if withSystem {
		files = samMixedDir(t)
	}
	disc := discoverBinaryDir(t, mux, c.ID, files)
	imp := importAllFrom(t, mux, c.ID, disc)
	if len(imp.ParseFailures) != 0 {
		t.Fatalf("fixture failed to parse: %+v", imp.ParseFailures)
	}
	return c.ID, disc
}

// The SAM hive must reach the Timeline as its own artifact, and
// filtering by it must return only account events.
func TestSAM_TimelineArtifactFilterReturnsOnlyAccountEvents(t *testing.T) {
	mux := newTestRouter(t)
	caseID, _ := samCaseWith(t, mux, true)

	all := searchEvents(t, mux, caseID, vals("page_size", "200"))
	if all.Total == 0 {
		t.Fatal("the case has no events at all")
	}

	// The artifact must be offered as a filter option.
	var facets EventFacetsResponse
	rec := doJSON(t, mux, "GET", "/api/cases/"+caseID+"/events/facets", nil, &facets)
	if rec.Code != http.StatusOK {
		t.Fatalf("facets: %d", rec.Code)
	}
	var offered bool
	for _, a := range facets.ArtifactTypes {
		if a.Value == model.ArtifactSAM {
			offered = true
			if a.Label != "Windows SAM" {
				t.Errorf("the SAM artifact is offered as %q, want %q", a.Label, "Windows SAM")
			}
		}
		if a.Value == model.ArtifactRegistryHive && a.Label == "Windows SAM" {
			t.Error("the generic registry hive artifact is labelled Windows SAM")
		}
	}
	if !offered {
		t.Fatal("Windows SAM is not offered in the artifact filter for a case containing a SAM hive")
	}

	// Filtering by it returns accounts, and nothing else.
	got := searchEvents(t, mux, caseID, vals("artifact_type", model.ArtifactSAM, "page_size", "200"))
	if got.Total != 3 {
		t.Fatalf("filtering by Windows SAM returned %d events, want 3 accounts", got.Total)
	}
	for _, e := range got.Items {
		if e.ArtifactType != model.ArtifactSAM {
			t.Errorf("artifact filter returned a %q event", e.ArtifactType)
		}
		if e.EventType != model.EventSAMLocalAccount {
			t.Errorf("artifact filter returned event type %q", e.EventType)
		}
	}
	if got.Total >= all.Total {
		t.Error("the artifact filter did not narrow the timeline")
	}
}

// Account, RID and hash must all be present on the event the Timeline
// serves.
func TestSAM_AccountRIDAndHashAreVisibleInTheTimeline(t *testing.T) {
	mux := newTestRouter(t)
	caseID, _ := samCaseWith(t, mux, true)
	res := searchEvents(t, mux, caseID, vals("artifact_type", model.ArtifactSAM, "page_size", "200"))

	byRID := map[string]TimelineEvent{}
	for _, e := range res.Items {
		byRID[e.Extra["rid"]] = e
	}
	e, ok := byRID["1001"]
	if !ok {
		t.Fatal("no event for RID 1001")
	}
	if e.Extra["account_name"] != "jdoe" {
		t.Errorf("account_name %q", e.Extra["account_name"])
	}
	if e.Extra["ntlm_hash"] != samHashJDoe {
		t.Errorf("ntlm_hash %q, want %q", e.Extra["ntlm_hash"], samHashJDoe)
	}
	if e.Extra["ntlm_hash_status"] != "decoded" {
		t.Errorf("ntlm_hash_status %q", e.Extra["ntlm_hash_status"])
	}
	if byRID["1002"].Extra["ntlm_hash"] != samHashSvc {
		t.Errorf("svc_backup hash %q", byRID["1002"].Extra["ntlm_hash"])
	}
	// The one with no stored hash is reported as such, not invented.
	if h := byRID["500"].Extra["ntlm_hash"]; h != "" {
		t.Errorf("Administrator was given hash %q", h)
	}
}

// Provenance: SAM hive -> source evidence -> collection, with the raw
// record intact.
func TestSAM_ProvenanceTracesBackToTheHive(t *testing.T) {
	mux := newTestRouter(t)
	caseID, disc := samCaseWith(t, mux, true)
	res := searchEvents(t, mux, caseID, vals("artifact_type", model.ArtifactSAM, "q", "jdoe", "page_size", "50"))
	if res.Total == 0 {
		t.Fatal("no jdoe account event")
	}
	ev := res.Items[0]

	var prov struct {
		Event      model.Event `json:"event"`
		SourceFile struct {
			Path   string `json:"path"`
			Parser string `json:"parser"`
			SHA256 string `json:"sha256"`
		} `json:"source_file"`
		RawEvidence struct {
			Raw string `json:"raw"`
		} `json:"raw_evidence"`
	}
	rec := doJSON(t, mux, "GET", "/api/cases/"+caseID+"/events/"+ev.ID, nil, &prov)
	if rec.Code != http.StatusOK {
		t.Fatalf("provenance: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.HasSuffix(prov.SourceFile.Path, "System32/config/SAM") {
		t.Errorf("source file is %q, want the SAM hive", prov.SourceFile.Path)
	}
	if prov.SourceFile.Parser == "" || prov.SourceFile.SHA256 == "" {
		t.Error("the source file has no parser or no hash; the integrity model is broken for SAM")
	}
	if prov.Event.CollectionID != disc.Collection.ID {
		t.Errorf("event collection %q, want %q", prov.Event.CollectionID, disc.Collection.ID)
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(prov.RawEvidence.Raw), &raw); err != nil {
		t.Fatalf("raw evidence is not JSON: %v", err)
	}
	if raw["account_name"] != "jdoe" || raw["ntlm_hash"] != samHashJDoe {
		t.Errorf("raw record does not carry the account: %v", raw)
	}
	if raw["boot_key_source"] != "Windows/System32/config/SYSTEM" {
		t.Errorf("raw record does not name the boot key source: %v", raw["boot_key_source"])
	}
}

// Deleting the evidence must remove the derived account events.
func TestSAM_DeletingTheEvidenceRemovesTheAccountEvents(t *testing.T) {
	mux := newTestRouter(t)
	caseID, disc := samCaseWith(t, mux, true)
	if n := searchEvents(t, mux, caseID, vals("artifact_type", model.ArtifactSAM)).Total; n != 3 {
		t.Fatalf("expected 3 SAM events before deletion, got %d", n)
	}

	if rec := deleteCollection(t, mux, caseID, disc.Collection.ID); rec.Code != http.StatusOK {
		t.Fatalf("deleting the collection: %d %s", rec.Code, rec.Body.String())
	}
	if n := searchEvents(t, mux, caseID, vals("artifact_type", model.ArtifactSAM)).Total; n != 0 {
		t.Errorf("%d SAM account events survived deletion of their evidence", n)
	}
	// And the artifact stops being offered as a filter.
	var facets EventFacetsResponse
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/events/facets", nil, &facets)
	for _, a := range facets.ArtifactTypes {
		if a.Value == model.ArtifactSAM {
			t.Error("Windows SAM is still offered in the artifact filter after its evidence was deleted")
		}
	}
}

// Without the SYSTEM hive the accounts still appear, and each says why
// its hash is missing rather than appearing to have none.
func TestSAM_WithoutSystemHiveAccountsStillAppearWithAStatedReason(t *testing.T) {
	mux := newTestRouter(t)
	caseID, _ := samCaseWith(t, mux, false)
	res := searchEvents(t, mux, caseID, vals("artifact_type", model.ArtifactSAM, "page_size", "50"))
	if res.Total != 3 {
		t.Fatalf("got %d account events, want 3", res.Total)
	}
	for _, e := range res.Items {
		if e.Extra["ntlm_hash"] != "" {
			t.Errorf("RID %s produced a hash with no SYSTEM hive", e.Extra["rid"])
		}
		if e.Extra["ntlm_hash_status"] == "" || e.Extra["ntlm_hash_unavailable_reason"] == "" {
			t.Errorf("RID %s does not say why its hash is missing", e.Extra["rid"])
		}
	}
}

// SECURITY: the hash must never be reachable through free-text search.
// Search reads a named allowlist of fields; ntlm_hash is not one, so an
// analyst cannot make the search index leak credential material, and a
// hash cannot be confirmed by guessing it into the search box.
func TestSAM_HashIsNotReachableThroughSearch(t *testing.T) {
	mux := newTestRouter(t)
	caseID, _ := samCaseWith(t, mux, true)

	if n := searchEvents(t, mux, caseID, vals("q", samHashJDoe, "page_size", "50")).Total; n != 0 {
		t.Errorf("searching for the NTLM hash returned %d events; the hash is in the search index", n)
	}
	// Every field-scoped search too.
	for _, field := range []string{"filename", "path", "url", "domain", "ip", "command_line", "original_path"} {
		if n := searchEvents(t, mux, caseID, vals("q", samHashJDoe, "q_field", field)).Total; n != 0 {
			t.Errorf("field search %q found the hash", field)
		}
	}
	// The account name, by contrast, must be searchable -- that is
	// ordinary evidence.
	if n := searchEvents(t, mux, caseID, vals("q", "jdoe", "page_size", "50")).Total; n == 0 {
		t.Error("the account name is not searchable")
	}
}

// SECURITY: the hash must never appear in a URL. Every timeline request
// is a GET whose query string lands in logs and history.
func TestSAM_HashNeverAppearsInARequestURL(t *testing.T) {
	mux := newTestRouter(t)
	caseID, _ := samCaseWith(t, mux, true)
	res := searchEvents(t, mux, caseID, vals("artifact_type", model.ArtifactSAM, "page_size", "50"))

	// The event's own identifiers -- which is what the UI puts in URLs --
	// must not carry the hash.
	for _, e := range res.Items {
		for name, v := range map[string]string{
			"id": e.ID, "source_reference": e.SourceReference,
			"registry_path": e.RegistryPath, "file_path": e.FilePath, "user": e.User,
		} {
			if strings.Contains(strings.ToLower(v), samHashJDoe) {
				t.Errorf("the hash is in the event's %s: %q", name, v)
			}
		}
	}
	// And a request carrying it must not become a 200 that confirms it.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET",
		"/api/cases/"+caseID+"/events?q="+url.QueryEscape(samHashJDoe), nil))
	if rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), `"total":0`) == false {
		var out EventSearchResponse
		if json.Unmarshal(rec.Body.Bytes(), &out) == nil && out.Total != 0 {
			t.Errorf("a URL carrying the hash returned %d events", out.Total)
		}
	}
}

// SECURITY: credential material must not be in the Detail column. That
// column is rendered into every row and is what the row's Copy button
// copies; the hash belongs in the event's own detail view.
func TestSAM_HashIsNotTheTimelineDetailValue(t *testing.T) {
	mux := newTestRouter(t)
	caseID, _ := samCaseWith(t, mux, true)
	res := searchEvents(t, mux, caseID, vals("artifact_type", model.ArtifactSAM, "page_size", "50"))
	for _, e := range res.Items {
		// The fields eventDetailValue reads, in its own order.
		for _, v := range []string{e.CommandLine, e.RegistryPath, e.FilePath, e.NetworkDest} {
			if strings.Contains(strings.ToLower(v), samHashJDoe) {
				t.Errorf("the hash is in a Detail-column field: %q", v)
			}
		}
	}
}

// SAM evidence must not become a Finding or an Investigation.
func TestSAM_CreatesNoFindingsOrInvestigations(t *testing.T) {
	mux := newTestRouter(t)
	caseID, _ := samCaseWith(t, mux, true)

	var findings []model.Finding
	if rec := doJSON(t, mux, "GET", "/api/cases/"+caseID+"/findings", nil, &findings); rec.Code != http.StatusOK {
		t.Fatalf("findings: %d", rec.Code)
	}
	for _, f := range findings {
		blob, _ := json.Marshal(f)
		if strings.Contains(string(blob), samHashJDoe) || strings.Contains(string(blob), "sam_local_account") {
			t.Errorf("SAM evidence produced finding %q", f.Title)
		}
	}
	var investigations []model.Investigation
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/investigations", nil, &investigations)
	for _, inv := range investigations {
		blob, _ := json.Marshal(inv)
		if strings.Contains(string(blob), samHashJDoe) {
			t.Errorf("an investigation carries the hash: %q", inv.Title)
		}
	}
}

// The event must not be given a timestamp by the storage or API layers
// either -- a SAM account record has none.
func TestSAM_TimelineEventHasNoTimestamp(t *testing.T) {
	mux := newTestRouter(t)
	caseID, _ := samCaseWith(t, mux, true)
	res := searchEvents(t, mux, caseID, vals("artifact_type", model.ArtifactSAM, "page_size", "50"))
	for _, e := range res.Items {
		if !e.Timestamp.IsZero() {
			t.Errorf("RID %s was given timestamp %v", e.Extra["rid"], e.Timestamp)
		}
	}
}
