package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"tracefall/internal/ad1/ad1gen"
	"tracefall/internal/model"
	"tracefall/internal/sam/samgen"
)

// Phase 19: SAM + SYSTEM boot-key derivation across an evidence
// collection.
//
// THE REGRESSION THESE EXIST FOR
//
// Boot-key lookup used to happen inside the SAM parser, by scanning the
// directory the SAM was in. That is correct for a directory of already
// extracted files and WRONG for an AD1 image, because AD1 entries are
// materialized one at a time immediately before each is parsed -- so at
// the moment the SAM is parsed, the SYSTEM hive beside it in the image
// has not been written yet. On real evidence the gap was 6.2 seconds and
// every hash came back "encrypted, no SYSTEM hive" while the SYSTEM hive
// sat in the very same collection.
//
// TestBootKey_AD1CollectionDecodesHashes is the test that fails if that
// design ever comes back.

func samAD1Image(t *testing.T, withSystem bool) []byte {
	t.Helper()
	files := []ad1gen.File{
		{
			Path: "Windows/System32/config/SAM",
			Data: samgen.SAMHive(samgen.Options{Accounts: samFixtureAccounts()}),
		},
	}
	if withSystem {
		files = append(files, ad1gen.File{
			Path: "Windows/System32/config/SYSTEM",
			Data: samgen.SystemHive(nil),
		})
	}
	return buildAD1(t, `C:\`, files)
}

func importAD1(t *testing.T, mux http.Handler, img []byte, name string) (string, DiscoverResult) {
	t.Helper()
	return importAD1Tolerant(t, mux, img, name, false)
}

// importAD1Tolerant imports an AD1. allowFailures is for the tests that
// deliberately feed a damaged SYSTEM hive: that hive failing to PARSE is
// the correct outcome, and is a separate question from whether the SAM
// still produced its accounts.
func importAD1Tolerant(t *testing.T, mux http.Handler, img []byte, name string, allowFailures bool) (string, DiscoverResult) {
	t.Helper()
	c := mustCreateCase(t, mux, "SAM bootkey "+t.Name())
	rec := uploadAD1(t, mux, c.ID, img, name)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload AD1: %d %s", rec.Code, rec.Body.String())
	}
	var disc DiscoverResult
	mustDecode(t, rec, &disc)
	imp := importAllFrom(t, mux, c.ID, disc)
	if !allowFailures && len(imp.ParseFailures) != 0 {
		t.Fatalf("parse failures: %+v", imp.ParseFailures)
	}
	for _, f := range imp.ParseFailures {
		if !strings.Contains(f.Path, "SYSTEM") {
			t.Fatalf("unexpected parse failure: %+v", f)
		}
	}
	return c.ID, disc
}

func samEventsByRID(t *testing.T, mux http.Handler, caseID string) map[string]TimelineEvent {
	t.Helper()
	res := searchEvents(t, mux, caseID, vals("artifact_type", model.ArtifactSAM, "page_size", "100"))
	out := map[string]TimelineEvent{}
	for _, e := range res.Items {
		out[e.Extra["rid"]] = e
	}
	return out
}

// THE regression test. An AD1 holding both hives must decode the hashes,
// whatever order the entries are materialized in.
func TestBootKey_AD1CollectionDecodesHashes(t *testing.T) {
	mux := newTestRouter(t)
	caseID, _ := importAD1(t, mux, samAD1Image(t, true), "sam-and-system.ad1")

	byRID := samEventsByRID(t, mux, caseID)
	if len(byRID) != 3 {
		t.Fatalf("got %d SAM account events, want 3", len(byRID))
	}
	e, ok := byRID["1001"]
	if !ok {
		t.Fatal("no event for RID 1001")
	}
	if e.Extra["ntlm_hash_status"] != "decoded" {
		t.Fatalf("hash status %q, want \"decoded\" -- the SYSTEM hive is in the same AD1. reason: %s / %s",
			e.Extra["ntlm_hash_status"], e.Extra["ntlm_hash_unavailable_reason"], e.Extra["boot_key_reason"])
	}
	if e.Extra["ntlm_hash"] != samHashJDoe {
		t.Errorf("ntlm_hash %q, want %q", e.Extra["ntlm_hash"], samHashJDoe)
	}
	if e.Extra["account_name"] != "jdoe" {
		t.Errorf("account_name %q", e.Extra["account_name"])
	}
	// The cryptographic dependency must be named.
	if e.Extra["boot_key_source"] != "Windows/System32/config/SYSTEM" {
		t.Errorf("boot_key_source %q", e.Extra["boot_key_source"])
	}
	if e.Extra["boot_key_status"] != "derived" {
		t.Errorf("boot_key_status %q", e.Extra["boot_key_status"])
	}
	if e.Extra["boot_key_source_sha256"] == "" {
		t.Error("the SYSTEM hive that supplied the key is not identified by hash")
	}
	if e.Extra["boot_key_control_set"] != "ControlSet001" {
		t.Errorf("boot_key_control_set %q; which control set was live is part of where the key came from",
			e.Extra["boot_key_control_set"])
	}
	// And a second account decodes from the same key -- derived once.
	if byRID["1002"].Extra["ntlm_hash"] != samHashSvc {
		t.Errorf("svc_backup hash %q", byRID["1002"].Extra["ntlm_hash"])
	}
}

// The same AD1 without a SYSTEM hive: accounts present, hashes
// explicitly ENCRYPTED (not "missing"), with an actionable reason.
func TestBootKey_AD1WithoutSystemReportsEncryptedNotMissing(t *testing.T) {
	mux := newTestRouter(t)
	caseID, _ := importAD1(t, mux, samAD1Image(t, false), "sam-only.ad1")

	e := samEventsByRID(t, mux, caseID)["1001"]
	if e.Extra["ntlm_hash"] != "" {
		t.Errorf("a hash was produced with no SYSTEM hive: %q", e.Extra["ntlm_hash"])
	}
	if e.Extra["ntlm_hash_status"] != "encrypted_system_hive_missing" {
		t.Errorf("hash status %q, want encrypted_system_hive_missing", e.Extra["ntlm_hash_status"])
	}
	// The material EXISTS, and the event must say so rather than reading
	// as "this account has no hash".
	if e.Extra["ntlm_hash_present_but_encrypted"] != "true" {
		t.Error("the event does not record that the hash material is present but encrypted")
	}
	reason := e.Extra["ntlm_hash_unavailable_reason"]
	if !strings.Contains(reason, "present") || !strings.Contains(reason, "encrypted") {
		t.Errorf("the reason does not say the hash is present and encrypted: %q", reason)
	}
	if !strings.Contains(reason, "SYSTEM") {
		t.Errorf("the reason does not name what to collect: %q", reason)
	}
	if e.Extra["boot_key_status"] != "system_hive_missing" {
		t.Errorf("boot_key_status %q", e.Extra["boot_key_status"])
	}
	// The account itself is intact.
	if e.Extra["account_name"] != "jdoe" || e.Extra["logon_count"] != "14" {
		t.Errorf("account evidence lost: %+v", e.Extra)
	}
}

// A SYSTEM hive that is present but unusable is a DIFFERENT state from
// one that is absent, because the remedy differs.
func TestBootKey_UnusableSystemIsDistinctFromMissing(t *testing.T) {
	fullSystem := samgen.SystemHive(nil)
	for _, tc := range []struct {
		name   string
		system []byte
	}{
		{"no SysKey class names", samgen.SystemHiveWithoutSysKey()},
		// Cut just past the base block, so the hive opens and its cells
		// are gone -- the case a partially recovered file produces.
		{"truncated", samgen.Truncate(fullSystem, 4200)},
		{"corrupt", samgen.Corrupt(fullSystem, 4200, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)},
		{"not a hive at all", []byte(strings.Repeat("this is not a registry hive\n", 400))},
		{"a different hive", samgen.NonSAMHive()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			img := buildAD1(t, `C:\`, []ad1gen.File{
				{Path: "Windows/System32/config/SAM",
					Data: samgen.SAMHive(samgen.Options{Accounts: samFixtureAccounts()})},
				{Path: "Windows/System32/config/SYSTEM", Data: tc.system},
			})
			mux := newTestRouter(t)
			caseID, _ := importAD1Tolerant(t, mux, img, "bad-system.ad1", true)

			e := samEventsByRID(t, mux, caseID)["1001"]
			if e.Extra["account_name"] != "jdoe" {
				t.Fatalf("the account itself was lost: %+v", e.Extra)
			}
			// THE invariant: a damaged SYSTEM hive must never yield a
			// hash that is not the real one. Either it decodes correctly
			// (a truncation that happened to spare the SysKey cells is a
			// legitimate success) or it decodes nothing.
			if h := e.Extra["ntlm_hash"]; h != "" && h != samHashJDoe {
				t.Fatalf("a damaged SYSTEM hive produced a WRONG hash: %q", h)
			}
			if e.Extra["ntlm_hash"] != "" {
				return // decoded, and correctly
			}
			status := e.Extra["ntlm_hash_status"]
			if status != "encrypted_system_hive_unusable" && status != "encrypted_system_hive_missing" {
				t.Fatalf("hash status %q", status)
			}
			// Whichever it is, it must be explained and must never read
			// as "this account has no hash".
			if e.Extra["ntlm_hash_present_but_encrypted"] != "true" {
				t.Error("the event does not record that the hash material is present")
			}
			if e.Extra["boot_key_reason"] == "" && e.Extra["ntlm_hash_unavailable_reason"] == "" {
				t.Error("no reason was recorded")
			}
		})
	}
}

// A boot key that is not this SAM's must never yield a plausible hash.
// The RC4 domain-key record carries a checksum, which is what catches it.
func TestBootKey_WrongKeyNeverProducesAFalseHash(t *testing.T) {
	mux := newTestRouter(t)
	wrong := make([]byte, 16)
	for i := range wrong {
		wrong[i] = byte(0xA0 + i)
	}
	img := buildAD1(t, `C:\`, []ad1gen.File{
		// A SAM written under the DEFAULT key, in the legacy format so
		// the checksum applies...
		{Path: "Windows/System32/config/SAM",
			Data: samgen.SAMHive(samgen.Options{Accounts: samFixtureAccounts(), Legacy: true})},
		// ...and a SYSTEM hive carrying a DIFFERENT key.
		{Path: "Windows/System32/config/SYSTEM", Data: samgen.SystemHive(wrong)},
	})
	caseID, _ := importAD1(t, mux, img, "mismatched.ad1")

	for rid, e := range samEventsByRID(t, mux, caseID) {
		if e.Extra["ntlm_hash"] != "" {
			t.Errorf("RID %s: a mismatched boot key produced hash %q", rid, e.Extra["ntlm_hash"])
		}
	}
	e := samEventsByRID(t, mux, caseID)["1001"]
	if e.Extra["ntlm_hash_status"] != "encrypted_system_hive_unusable" {
		t.Errorf("hash status %q, want encrypted_system_hive_unusable", e.Extra["ntlm_hash_status"])
	}
	if !strings.Contains(e.Extra["ntlm_hash_unavailable_reason"]+e.Extra["boot_key_reason"], "checksum") {
		t.Errorf("the mismatch was not explained as a key that does not fit: %q / %q",
			e.Extra["ntlm_hash_unavailable_reason"], e.Extra["boot_key_reason"])
	}
}

// A RENAMED SYSTEM hive must still supply the key: candidates are
// verified by content, and the name only orders the search.
func TestBootKey_RenamedSystemHiveStillSuppliesTheKey(t *testing.T) {
	mux := newTestRouter(t)
	img := buildAD1(t, `C:\`, []ad1gen.File{
		{Path: "triage/hives/hive-01.bin",
			Data: samgen.SAMHive(samgen.Options{Accounts: samFixtureAccounts()})},
		{Path: "triage/hives/hive-02.bin", Data: samgen.SystemHive(nil)},
	})
	caseID, _ := importAD1(t, mux, img, "renamed.ad1")

	e := samEventsByRID(t, mux, caseID)["1001"]
	if e.Extra["ntlm_hash"] != samHashJDoe {
		t.Fatalf("hash %q from a renamed SYSTEM hive (status %q, reason %q)",
			e.Extra["ntlm_hash"], e.Extra["ntlm_hash_status"], e.Extra["boot_key_reason"])
	}
	if e.Extra["boot_key_source"] != "triage/hives/hive-02.bin" {
		t.Errorf("boot_key_source %q", e.Extra["boot_key_source"])
	}
}

// A hive named SYSTEM that is not one must not be trusted just because
// of the name: the actual SYSTEM hive elsewhere in the collection wins.
func TestBootKey_DecoyNamedSystemDoesNotBlockTheRealOne(t *testing.T) {
	mux := newTestRouter(t)
	img := buildAD1(t, `C:\`, []ad1gen.File{
		{Path: "Windows/System32/config/SAM",
			Data: samgen.SAMHive(samgen.Options{Accounts: samFixtureAccounts()})},
		// A valid registry hive called SYSTEM that carries no SysKey.
		{Path: "Windows/System32/config/SYSTEM", Data: samgen.SystemHiveWithoutSysKey()},
		// The real one, under another name.
		{Path: "backup/registry-copy.dat", Data: samgen.SystemHive(nil)},
	})
	caseID, _ := importAD1(t, mux, img, "decoy.ad1")

	e := samEventsByRID(t, mux, caseID)["1001"]
	if e.Extra["ntlm_hash"] != samHashJDoe {
		t.Fatalf("hash %q; the real SYSTEM hive was not reached past the decoy (status %q)",
			e.Extra["ntlm_hash"], e.Extra["ntlm_hash_status"])
	}
	if e.Extra["boot_key_source"] != "backup/registry-copy.dat" {
		t.Errorf("boot_key_source %q", e.Extra["boot_key_source"])
	}
}

// The SYSTEM hive is used even when the analyst imported ONLY the SAM:
// it is the collection that supplies the key, not the selection.
func TestBootKey_SystemUsedEvenWhenOnlyTheSAMWasSelected(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "SAM only selection")
	rec := uploadAD1(t, mux, c.ID, samAD1Image(t, true), "both.ad1")
	if rec.Code != http.StatusOK {
		t.Fatalf("upload: %d", rec.Code)
	}
	var disc DiscoverResult
	mustDecode(t, rec, &disc)

	var samID string
	for _, sf := range disc.SourceFiles {
		if strings.HasSuffix(sf.Path, "config/SAM") {
			samID = sf.ID
		}
	}
	if samID == "" {
		t.Fatal("the SAM was not catalogued")
	}
	// Import the SAM alone.
	var imp ImportResult
	r := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/evidence/"+disc.Collection.ID+"/import",
		map[string]any{"source_file_ids": []string{samID}}, &imp)
	if r.Code != http.StatusOK {
		t.Fatalf("import: %d %s", r.Code, r.Body.String())
	}

	e := samEventsByRID(t, mux, c.ID)["1001"]
	if e.Extra["ntlm_hash"] != samHashJDoe {
		t.Errorf("hash %q; a SYSTEM hive catalogued in the same collection should still supply the key "+
			"(status %q, reason %q)", e.Extra["ntlm_hash"], e.Extra["ntlm_hash_status"], e.Extra["boot_key_reason"])
	}
}

// Multiple accounts and multiple RIDs, all decoded from one derivation.
func TestBootKey_MultipleAccountsShareOneDerivation(t *testing.T) {
	mux := newTestRouter(t)
	accts := make([]samgen.Account, 0, 40)
	for i := 0; i < 40; i++ {
		a := samgen.Account{RID: uint32(1000 + i), Username: "u" + itoa19(i), ACBFlags: 0x0010}
		if i%2 == 0 {
			a.NTLM = samHexBytes(samHashSvc)
		}
		accts = append(accts, a)
	}
	img := buildAD1(t, `C:\`, []ad1gen.File{
		{Path: "Windows/System32/config/SAM", Data: samgen.SAMHive(samgen.Options{Accounts: accts})},
		{Path: "Windows/System32/config/SYSTEM", Data: samgen.SystemHive(nil)},
	})
	caseID, _ := importAD1(t, mux, img, "many.ad1")

	byRID := samEventsByRID(t, mux, caseID)
	if len(byRID) != 40 {
		t.Fatalf("got %d accounts, want 40", len(byRID))
	}
	decoded := 0
	sources := map[string]bool{}
	for rid, e := range byRID {
		sources[e.Extra["boot_key_source"]] = true
		if e.Extra["ntlm_hash"] == "" {
			continue
		}
		decoded++
		if e.Extra["ntlm_hash"] != samHashSvc {
			t.Fatalf("RID %s decoded to %q", rid, e.Extra["ntlm_hash"])
		}
	}
	if decoded != 20 {
		t.Errorf("%d accounts decoded, want 20", decoded)
	}
	// One key, one source, for every account.
	if len(sources) != 1 {
		t.Errorf("accounts report %d different boot key sources: %v", len(sources), sources)
	}
}

// Repeated imports of identical evidence must produce identical output.
func TestBootKey_DeterministicAcrossRuns(t *testing.T) {
	img := samAD1Image(t, true)
	var first string
	for i := 0; i < 3; i++ {
		mux := newTestRouter(t)
		caseID, _ := importAD1(t, mux, img, "det.ad1")
		var got []string
		for _, rid := range []string{"500", "1001", "1002"} {
			e := samEventsByRID(t, mux, caseID)[rid]
			got = append(got, rid+"|"+e.Extra["account_name"]+"|"+e.Extra["ntlm_hash"]+"|"+
				e.Extra["ntlm_hash_status"]+"|"+e.Extra["boot_key_source"])
		}
		joined := strings.Join(got, "\n")
		if i == 0 {
			first = joined
			continue
		}
		if joined != first {
			t.Fatalf("run %d differs:\n%s\n--- run 0 ---\n%s", i, joined, first)
		}
	}
}

// Provenance must reach the SAM record, the SAM file, the collection,
// and the original AD1 -- and must also name the SYSTEM hive the hash
// was decoded with.
func TestBootKey_ProvenanceNamesBothHives(t *testing.T) {
	mux := newTestRouter(t)
	caseID, disc := importAD1(t, mux, samAD1Image(t, true), "provenance.ad1")
	e := samEventsByRID(t, mux, caseID)["1001"]

	var prov struct {
		Event      model.Event `json:"event"`
		SourceFile struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"source_file"`
		RawEvidence struct {
			Raw string `json:"raw"`
		} `json:"raw_evidence"`
	}
	rec := doJSON(t, mux, "GET", "/api/cases/"+caseID+"/events/"+e.ID, nil, &prov)
	if rec.Code != http.StatusOK {
		t.Fatalf("provenance: %d", rec.Code)
	}
	if prov.SourceFile.Path != "Windows/System32/config/SAM" {
		t.Errorf("source file %q", prov.SourceFile.Path)
	}
	if prov.SourceFile.SHA256 == "" {
		t.Error("the SAM has no hash recorded")
	}
	if prov.Event.CollectionID != disc.Collection.ID {
		t.Errorf("collection %q", prov.Event.CollectionID)
	}
	if disc.Collection.OriginalFilename != "provenance.ad1" {
		t.Errorf("the collection does not name the original AD1: %q", disc.Collection.OriginalFilename)
	}
	if disc.Collection.IntegritySHA512 == "" {
		t.Error("the collection has no integrity hash")
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(prov.RawEvidence.Raw), &raw); err != nil {
		t.Fatal(err)
	}
	if raw["boot_key_source"] != "Windows/System32/config/SYSTEM" {
		t.Errorf("the raw record does not name the SYSTEM hive: %v", raw["boot_key_source"])
	}
	if raw["boot_key_status"] != "derived" {
		t.Errorf("raw boot_key_status %v", raw["boot_key_status"])
	}
}

// Neither hive may be modified by processing.
func TestBootKey_NeitherHiveIsModified(t *testing.T) {
	mux := newTestRouter(t)
	samBytes := samgen.SAMHive(samgen.Options{Accounts: samFixtureAccounts()})
	sysBytes := samgen.SystemHive(nil)
	img := buildAD1(t, `C:\`, []ad1gen.File{
		{Path: "Windows/System32/config/SAM", Data: samBytes},
		{Path: "Windows/System32/config/SYSTEM", Data: sysBytes},
	})
	caseID, disc := importAD1(t, mux, img, "integrity.ad1")

	// The catalog's own hashes must match the bytes that went in.
	want := map[string]string{
		"Windows/System32/config/SAM":    sha256Hex(samBytes),
		"Windows/System32/config/SYSTEM": sha256Hex(sysBytes),
	}
	var files []model.SourceFile
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/evidence/"+disc.Collection.ID+"/files?page_size=50", nil, &struct {
		Items *[]model.SourceFile `json:"items"`
	}{Items: &files})
	seen := 0
	for _, sf := range files {
		if w, ok := want[sf.Path]; ok && sf.SHA256 != "" {
			seen++
			if sf.SHA256 != w {
				t.Errorf("%s hash %s, want %s -- the file was modified", sf.Path, sf.SHA256, w)
			}
		}
	}
	if seen != 2 {
		t.Errorf("checked %d of 2 hives", seen)
	}
}

// Deleting the evidence removes the derived account events.
func TestBootKey_DeletionLifecycle(t *testing.T) {
	mux := newTestRouter(t)
	caseID, disc := importAD1(t, mux, samAD1Image(t, true), "lifecycle.ad1")
	if n := len(samEventsByRID(t, mux, caseID)); n != 3 {
		t.Fatalf("%d accounts before deletion", n)
	}
	if rec := deleteCollection(t, mux, caseID, disc.Collection.ID); rec.Code != http.StatusOK {
		t.Fatalf("delete: %d", rec.Code)
	}
	if n := len(samEventsByRID(t, mux, caseID)); n != 0 {
		t.Errorf("%d account events survived deletion", n)
	}
}

// A decoded hash must still be kept out of search, findings and
// correlations -- decoding it does not change what it is.
func TestBootKey_DecodedHashStaysOutOfSearchAndFindings(t *testing.T) {
	mux := newTestRouter(t)
	caseID, _ := importAD1(t, mux, samAD1Image(t, true), "security.ad1")

	if n := searchEvents(t, mux, caseID, vals("q", samHashJDoe, "page_size", "50")).Total; n != 0 {
		t.Errorf("the decoded hash is searchable (%d hits)", n)
	}
	var findings []model.Finding
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/findings", nil, &findings)
	for _, f := range findings {
		blob, _ := json.Marshal(f)
		if strings.Contains(string(blob), samHashJDoe) {
			t.Errorf("a finding carries the hash: %q", f.Title)
		}
	}
	var corrs []model.Correlation
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/correlations", nil, &corrs)
	for _, c := range corrs {
		blob, _ := json.Marshal(c)
		if strings.Contains(string(blob), samHashJDoe) || strings.Contains(string(blob), "sam_local_account") {
			t.Errorf("a correlation carries SAM credential evidence: %q", c.Type)
		}
	}
	// And the SAM event is still not an execution or a logon.
	for _, e := range samEventsByRID(t, mux, caseID) {
		if e.EventType != model.EventSAMLocalAccount {
			t.Errorf("event type %q", e.EventType)
		}
		if !e.Timestamp.IsZero() {
			t.Errorf("a SAM account event was given timestamp %v", e.Timestamp)
		}
	}
}

// sha256Hex is the hash the catalog records for a file, computed here
// independently so the assertion is against the bytes the test wrote.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func itoa19(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
