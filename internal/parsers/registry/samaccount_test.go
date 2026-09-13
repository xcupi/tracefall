package registry_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tracefall/internal/correlate"
	"tracefall/internal/detect"
	"tracefall/internal/ingest"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
	"tracefall/internal/parsers/registry"
	"tracefall/internal/sam/samgen"
)

// Fixture hashes. Opaque constants; nothing turns a password into one.
const (
	fxHashJDoe = "8846f7eaee8fb117ad06bdd830b7586c"
	fxHashSvc  = "e19ccf75ee54e06b06a5907af13cef42"
)

// samCase writes a SAM (and optionally a SYSTEM beside it, as a real
// config directory holds them) and parses it.
func samCase(t *testing.T, accounts []samgen.Account, withSystem bool, opts ...func(*samgen.Options)) []model.Event {
	t.Helper()
	dir := t.TempDir()
	o := samgen.Options{Accounts: accounts}
	for _, f := range opts {
		f(&o)
	}
	samPath := filepath.Join(dir, "SAM")
	if err := os.WriteFile(samPath, samgen.SAMHive(o), 0o600); err != nil {
		t.Fatal(err)
	}
	if withSystem {
		if err := os.WriteFile(filepath.Join(dir, "SYSTEM"), samgen.SystemHive(o.BootKey), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	res, err := registry.New().Parse(samPath)
	if err != nil {
		t.Fatalf("parsing SAM: %v", err)
	}
	var out []model.Event
	for _, e := range res.Events {
		if e.ArtifactType == model.ArtifactSAM {
			out = append(out, e)
		}
	}
	return out
}

func fixtureAccounts() []samgen.Account {
	return []samgen.Account{
		{
			RID: 500, Username: "Administrator", ACBFlags: 0x0211,
			KeyLastWrite: time.Date(2024, 3, 1, 9, 0, 0, 0, time.UTC),
		},
		{
			RID: 1001, Username: "jdoe", FullName: "J Doe",
			NTLM: hexBytes(fxHashJDoe), ACBFlags: 0x0214,
			LastLogon:             time.Date(2024, 5, 2, 14, 30, 0, 0, time.UTC),
			LastPasswordSet:       time.Date(2024, 1, 9, 8, 15, 0, 0, time.UTC),
			LastIncorrectPassword: time.Date(2024, 5, 1, 22, 5, 0, 0, time.UTC),
			LoginCount:            14, FailedLoginCount: 2,
			KeyLastWrite: time.Date(2024, 5, 2, 14, 30, 0, 0, time.UTC),
		},
	}
}

func hexBytes(s string) []byte {
	out := make([]byte, len(s)/2)
	for i := range out {
		out[i] = hexNibble(s[i*2])<<4 | hexNibble(s[i*2+1])
	}
	return out
}

func hexNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

func findRID(t *testing.T, events []model.Event, rid string) model.Event {
	t.Helper()
	for _, e := range events {
		if e.Extra["rid"] == rid {
			return e
		}
	}
	t.Fatalf("no SAM event for RID %s (got %d events)", rid, len(events))
	return model.Event{}
}

// The whole point: username, RID and NTLM hash, from a real binary hive,
// through the normal parser entry point.
func TestSAM_ExtractsUsernameRIDAndNTLMHash(t *testing.T) {
	events := samCase(t, fixtureAccounts(), true)
	if len(events) != 2 {
		t.Fatalf("got %d SAM events, want 2", len(events))
	}
	e := findRID(t, events, "1001")
	if e.Extra["account_name"] != "jdoe" {
		t.Errorf("account name %q", e.Extra["account_name"])
	}
	if e.User != "jdoe" {
		t.Errorf("event user %q", e.User)
	}
	if e.Extra["ntlm_hash"] != fxHashJDoe {
		t.Errorf("ntlm_hash %q, want %q", e.Extra["ntlm_hash"], fxHashJDoe)
	}
	if e.Extra["ntlm_hash_status"] != "decoded" {
		t.Errorf("hash status %q", e.Extra["ntlm_hash_status"])
	}
	if e.ArtifactType != model.ArtifactSAM {
		t.Errorf("artifact type %q, want %q", e.ArtifactType, model.ArtifactSAM)
	}
	if e.EventType != model.EventSAMLocalAccount {
		t.Errorf("event type %q, want %q", e.EventType, model.EventSAMLocalAccount)
	}
}

// The artifact must be its own thing, not the generic hive artifact --
// that is what makes "Windows SAM" a usable Timeline filter.
func TestSAM_ArtifactTypeIsDistinctFromTheGenericHive(t *testing.T) {
	if model.ArtifactSAM == model.ArtifactRegistryHive {
		t.Fatal("the SAM artifact type is the generic registry hive type")
	}
	// The parser must DECLARE it, or the capability registry and the
	// Timeline's artifact filter never learn it exists.
	var declared bool
	for _, a := range registry.New().EventArtifactTypes() {
		if a == model.ArtifactSAM {
			declared = true
		}
	}
	if !declared {
		t.Error("the registry parser does not declare the SAM artifact type")
	}
	// The FILE stays a registry hive, which is what it is.
	if registry.New().ArtifactType() != model.ArtifactRegistryHive {
		t.Error("the parser's file-level artifact type changed")
	}
}

// A SAM account record has no time of its own, and neither the hive's
// nor the file's mtime may be substituted for one.
func TestSAM_EventCarriesNoTimestamp(t *testing.T) {
	for _, e := range samCase(t, fixtureAccounts(), true) {
		if !e.Timestamp.IsZero() {
			t.Errorf("RID %s carries timestamp %v; a SAM account record has no event time",
				e.Extra["rid"], e.Timestamp)
		}
		if e.Extra["timestamp_meaning"] == "" || e.Extra["timestamp_basis"] == "" {
			t.Errorf("RID %s does not explain its lack of a timestamp", e.Extra["rid"])
		}
	}
}

// The account's own timestamps must survive, each labelled with what it
// actually means.
func TestSAM_AccountTimestampsArePreservedAndLabelled(t *testing.T) {
	e := findRID(t, samCase(t, fixtureAccounts(), true), "1001")
	for field, want := range map[string]string{
		"last_logon":              "2024-05-02T14:30:00Z",
		"password_last_set":       "2024-01-09T08:15:00Z",
		"last_incorrect_password": "2024-05-01T22:05:00Z",
	} {
		if e.Extra[field] != want {
			t.Errorf("%s = %q, want %q", field, e.Extra[field], want)
		}
		if e.Extra[field+"_meaning"] == "" {
			t.Errorf("%s has no stated meaning", field)
		}
	}
	// "never" must be reported as never, not as a zero date and not
	// omitted.
	if e.Extra["account_expires"] != "never" {
		t.Errorf("account_expires = %q, want %q", e.Extra["account_expires"], "never")
	}
	// The key's write time is metadata about the record, and says so.
	if !strings.Contains(e.Extra["registry_last_write_meaning"], "not an account event") {
		t.Errorf("the key write time is not marked as record metadata: %q", e.Extra["registry_last_write_meaning"])
	}
}

// Without the SYSTEM hive there is no hash, and the event must SAY so
// rather than look like an account with no password.
func TestSAM_WithoutSystemHiveReportsWhyTheHashIsMissing(t *testing.T) {
	e := findRID(t, samCase(t, fixtureAccounts(), false), "1001")
	if e.Extra["ntlm_hash"] != "" {
		t.Errorf("a hash was produced with no SYSTEM hive: %q", e.Extra["ntlm_hash"])
	}
	if e.Extra["ntlm_hash_status"] != "encrypted_system_hive_missing" {
		t.Errorf("hash status %q", e.Extra["ntlm_hash_status"])
	}
	reason := e.Extra["ntlm_hash_unavailable_reason"] + " " + e.Extra["boot_key_reason"]
	if !strings.Contains(reason, "SYSTEM") {
		t.Errorf("the reason does not name the SYSTEM hive: %q", reason)
	}
	// The account itself is still fully readable.
	if e.Extra["account_name"] != "jdoe" || e.Extra["logon_count"] != "14" {
		t.Errorf("account evidence was lost with the hash: %+v", e.Extra)
	}
}

// A renamed SYSTEM hive beside the SAM must still supply the boot key:
// the candidate is verified by content, not by its name.
func TestSAM_BootKeyFoundInARenamedSystemHive(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SAM"),
		samgen.SAMHive(samgen.Options{Accounts: fixtureAccounts()}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SYSTEM_from_triage.bin"),
		samgen.SystemHive(nil), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := registry.New().Parse(filepath.Join(dir, "SAM"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range res.Events {
		if e.ArtifactType == model.ArtifactSAM && e.Extra["rid"] == "1001" {
			if e.Extra["ntlm_hash"] != fxHashJDoe {
				t.Errorf("hash %q from a renamed SYSTEM hive", e.Extra["ntlm_hash"])
			}
			if e.Extra["boot_key_source"] != "SYSTEM_from_triage.bin" {
				t.Errorf("the boot key source was recorded as %q", e.Extra["boot_key_source"])
			}
			return
		}
	}
	t.Fatal("no SAM event for RID 1001")
}

// An account with no stored hash must not be given the empty-password
// constant that some tools substitute.
func TestSAM_NoStoredHashIsNotInvented(t *testing.T) {
	e := findRID(t, samCase(t, fixtureAccounts(), true), "500")
	if e.Extra["ntlm_hash"] != "" {
		t.Errorf("a hash was reported for an account that stores none: %q", e.Extra["ntlm_hash"])
	}
	if e.Extra["ntlm_hash_status"] != "not_stored" {
		t.Errorf("hash status %q", e.Extra["ntlm_hash_status"])
	}
	if !strings.Contains(e.Extra["ntlm_hash_unavailable_reason"], "convention") {
		t.Errorf("the reason does not explain the substituted-constant convention: %q",
			e.Extra["ntlm_hash_unavailable_reason"])
	}
}

// The event must not read as activity of any kind.
func TestSAM_EventIsNotExecutionLogonOrPersistence(t *testing.T) {
	for _, e := range samCase(t, fixtureAccounts(), true) {
		for _, wrong := range []string{
			model.EventProcessCreate, model.EventLogonSuccess, model.EventLogonFailure,
			model.EventRegistryPersistence, model.EventRegistryRunKey,
			model.EventPrefetchExecution, model.EventNTLMAuth,
		} {
			if e.EventType == wrong {
				t.Fatalf("a SAM account event is typed as %q", wrong)
			}
		}
		// Nothing that would make it look like a process.
		if e.ProcessName != "" || e.ProcessPath != "" || e.CommandLine != "" {
			t.Errorf("a SAM account event carries process fields: %q %q %q",
				e.ProcessName, e.ProcessPath, e.CommandLine)
		}
		if !strings.Contains(e.Extra["evidence_meaning"], "not a record of any activity") &&
			!strings.Contains(e.Extra["evidence_meaning"], "not of any activity") {
			t.Errorf("evidence_meaning does not say this is not activity: %q", e.Extra["evidence_meaning"])
		}
	}
}

// Credential evidence must never become a Finding or a Correlation on
// its own. A machine having local accounts is what a machine looks like.
func TestSAM_ProducesNoFindingsAndNoCorrelations(t *testing.T) {
	events := samCase(t, fixtureAccounts(), true)
	if len(events) == 0 {
		t.Fatal("no events to test")
	}
	findings := detect.Run("case-1", events)
	if len(findings) != 0 {
		for _, f := range findings {
			t.Errorf("SAM evidence produced finding %q (%s)", f.Title, f.RuleID)
		}
	}
	corrs := correlate.Run("case-1", events)
	if len(corrs) != 0 {
		for _, c := range corrs {
			t.Errorf("SAM evidence produced correlation %q", c.Type)
		}
	}
}

// The hash must not reach a correlation key even when SAM events are
// analysed alongside real activity.
func TestSAM_HashNeverEntersACorrelationKey(t *testing.T) {
	events := samCase(t, fixtureAccounts(), true)
	events = append(events,
		model.Event{
			Timestamp: time.Date(2024, 5, 2, 14, 31, 0, 0, time.UTC),
			Host:      "WS01", User: "jdoe", EventType: model.EventLogonSuccess,
			ArtifactType: model.ArtifactWindowsEventLog,
		},
		model.Event{
			Timestamp: time.Date(2024, 5, 2, 14, 32, 0, 0, time.UTC),
			Host:      "WS01", User: "jdoe", EventType: model.EventProcessCreate,
			ProcessName: "cmd.exe", ArtifactType: model.ArtifactWindowsEventLog,
		},
	)
	for _, c := range correlate.Run("case-1", events) {
		blob, _ := json.Marshal(c)
		if strings.Contains(string(blob), fxHashJDoe) {
			t.Errorf("an NTLM hash reached correlation %q", c.Type)
		}
		for _, id := range c.EventIDs {
			for _, e := range events {
				if e.ID == id && e.ArtifactType == model.ArtifactSAM {
					t.Errorf("a SAM account event was pulled into correlation %q", c.Type)
				}
			}
		}
	}
}

// Multiple accounts, and a large account count. The traversal must stay
// linear -- ChildKeys is a single pass, which is why.
func TestSAM_ManyAccounts(t *testing.T) {
	const n = 800
	accts := make([]samgen.Account, 0, n)
	for i := 0; i < n; i++ {
		a := samgen.Account{RID: uint32(1000 + i), Username: "user" + itoa(i), ACBFlags: 0x0010}
		if i%3 == 0 {
			a.NTLM = hexBytes(fxHashSvc)
		}
		accts = append(accts, a)
	}
	start := time.Now()
	events := samCase(t, accts, true)
	elapsed := time.Since(start)
	if len(events) != n {
		t.Fatalf("got %d events, want %d", len(events), n)
	}
	hashes := 0
	for _, e := range events {
		if e.Extra["ntlm_hash"] != "" {
			hashes++
			if e.Extra["ntlm_hash"] != fxHashSvc {
				t.Fatalf("RID %s decoded to %q", e.Extra["rid"], e.Extra["ntlm_hash"])
			}
		}
	}
	if want := (n + 2) / 3; hashes != want {
		t.Errorf("%d accounts carry a hash, want %d", hashes, want)
	}
	if elapsed > 30*time.Second {
		t.Errorf("%d accounts took %s", n, elapsed)
	}
	t.Logf("%d SAM accounts parsed in %s", n, elapsed)
}

// Deterministic: identical bytes, identical events, same order.
func TestSAM_Deterministic(t *testing.T) {
	var first []string
	for i := 0; i < 3; i++ {
		var got []string
		for _, e := range samCase(t, fixtureAccounts(), true) {
			got = append(got, e.SourceReference+"|"+e.Extra["account_name"]+"|"+e.Extra["ntlm_hash"])
		}
		if i == 0 {
			first = got
			continue
		}
		if strings.Join(got, ",") != strings.Join(first, ",") {
			t.Fatalf("run %d: %v\nrun 0: %v", i, got, first)
		}
	}
}

// A hive that is not a SAM must contribute no account events, whatever
// it is called -- detection is structural.
func TestSAM_NonSAMHiveNamedSAMProducesNoAccountEvents(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "SAM")
	if err := os.WriteFile(p, samgen.NonSAMHive(), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := registry.New().Parse(p)
	if err != nil {
		t.Fatalf("a valid non-SAM hive failed to parse: %v", err)
	}
	for _, e := range res.Events {
		if e.ArtifactType == model.ArtifactSAM {
			t.Errorf("a SOFTWARE hive named SAM produced a SAM account event")
		}
	}
}

// A random file named SAM must be reported as UNRECOGNIZED, not claimed
// as a hive and then failed at import. That is the misleading outcome
// this phase set out to remove.
func TestSAM_RandomFileNamedSAMIsNotClaimedAsAHive(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SAM"),
		[]byte("this is a note about the SAM hive, not a hive\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	files, err := ingest.Discover(dir, ingest.Registry())
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("discovered %d files", len(files))
	}
	if files[0].Supported {
		t.Errorf("a text file named SAM was claimed as supported evidence by %q", files[0].Parser)
	}
	if files[0].Parser != "" {
		t.Errorf("a text file named SAM was assigned parser %q", files[0].Parser)
	}
}

// A real hive is still claimed by name, and a renamed one by content --
// neither path regressed.
func TestSAM_RealHivesAreStillDetectedByNameAndByContent(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SAM"),
		samgen.SAMHive(samgen.Options{Accounts: fixtureAccounts()}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "renamed-hive.dat"),
		samgen.SystemHive(nil), 0o600); err != nil {
		t.Fatal(err)
	}
	files, err := ingest.Discover(dir, ingest.Registry())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if !f.Supported || f.ArtifactType != model.ArtifactRegistryHive {
			t.Errorf("%s: supported=%v type=%q parser=%q", f.Path, f.Supported, f.ArtifactType, f.Parser)
		}
	}
}

// A truncated or corrupted SAM must never produce a wrong account or a
// wrong hash, and must never panic.
func TestSAM_TruncatedAndCorruptedHivesAreSafe(t *testing.T) {
	full := samgen.SAMHive(samgen.Options{Accounts: fixtureAccounts()})
	for n := 0; n < len(full); n += 11 {
		dir := t.TempDir()
		p := filepath.Join(dir, "SAM")
		if err := os.WriteFile(p, samgen.Truncate(full, n), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "SYSTEM"), samgen.SystemHive(nil), 0o600); err != nil {
			t.Fatal(err)
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("truncation to %d bytes panicked: %v", n, r)
				}
			}()
			res, err := registry.New().Parse(p)
			if err != nil {
				return
			}
			for _, e := range res.Events {
				if e.ArtifactType != model.ArtifactSAM {
					continue
				}
				if h := e.Extra["ntlm_hash"]; h != "" && h != fxHashJDoe {
					t.Fatalf("truncation to %d produced hash %q", n, h)
				}
				if u := e.Extra["account_name"]; u != "" && u != "jdoe" && u != "Administrator" {
					t.Fatalf("truncation to %d produced account %q", n, u)
				}
			}
		}()
	}
}

// The raw evidence record must carry the hash and the account, so
// provenance can show exactly what was read.
func TestSAM_RawEvidenceCarriesTheRecord(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SAM"),
		samgen.SAMHive(samgen.Options{Accounts: fixtureAccounts()}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SYSTEM"), samgen.SystemHive(nil), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := registry.New().Parse(filepath.Join(dir, "SAM"))
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for i, e := range res.Events {
		if e.ArtifactType != model.ArtifactSAM || e.Extra["rid"] != "1001" {
			continue
		}
		found = true
		var raw map[string]any
		if err := json.Unmarshal([]byte(res.Raw[i].Raw), &raw); err != nil {
			t.Fatalf("raw evidence is not JSON: %v", err)
		}
		if raw["ntlm_hash"] != fxHashJDoe {
			t.Errorf("raw ntlm_hash %v", raw["ntlm_hash"])
		}
		if raw["account_name"] != "jdoe" || raw["rid"] != float64(1001) {
			t.Errorf("raw account %v rid %v", raw["account_name"], raw["rid"])
		}
		if raw["boot_key_source"] != "SYSTEM" {
			t.Errorf("raw boot_key_source %v", raw["boot_key_source"])
		}
		if res.Raw[i].SourceReference != e.SourceReference {
			t.Errorf("raw evidence is not paired to its event")
		}
	}
	if !found {
		t.Fatal("no SAM event for RID 1001")
	}
}

// Nothing anywhere in the SAM path may produce a plaintext password.
func TestSAM_NoPlaintextPasswordIsEverProduced(t *testing.T) {
	events := samCase(t, fixtureAccounts(), true)
	for _, e := range events {
		blob, _ := json.Marshal(e)
		low := strings.ToLower(string(blob))
		for _, banned := range []string{"plaintext", "cleartext", "cracked", "recovered password"} {
			if strings.Contains(low, banned) {
				t.Errorf("a SAM event contains %q: %s", banned, blob)
			}
		}
		// The hash must be labelled a hash, never a password.
		if e.Extra["ntlm_hash"] != "" {
			m := e.Extra["ntlm_hash_meaning"]
			if !strings.Contains(m, "PASSWORD HASH") || !strings.Contains(m, "NOT a password") {
				t.Errorf("the hash is not labelled as a hash: %q", m)
			}
		}
	}
	// And the parser package holds no cracking capability.
	src, err := os.ReadFile("samaccount.go")
	if err != nil {
		t.Fatal(err)
	}
	var code strings.Builder
	for _, line := range strings.Split(string(src), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		code.WriteString(strings.ToLower(line) + "\n")
	}
	for _, banned := range []string{"hashcat", "wordlist", "bruteforce", "rainbow", "crack"} {
		if strings.Contains(code.String(), banned) {
			t.Errorf("samaccount.go contains %q in code", banned)
		}
	}
}

var _ parsers.ArtifactParser = registry.New()

func itoa(i int) string {
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
