package sam_test

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"tracefall/internal/regf"
	"tracefall/internal/sam"
	"tracefall/internal/sam/samgen"
)

// Fixture hashes. Opaque 16-byte constants -- nothing in Tracefall
// converts a password into one of these, and nothing converts one back.
const (
	hashJDoe  = "8846f7eaee8fb117ad06bdd830b7586c"
	hashSvc   = "e19ccf75ee54e06b06a5907af13cef42"
	hashAdmin = "31d6cfe0d16ae931b73c59d7e0c089c0"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeHive(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func openHive(t *testing.T, path string) *regf.Hive {
	t.Helper()
	h, err := regf.Open(path, regf.DefaultLimits())
	if err != nil {
		t.Fatalf("opening %s: %v", path, err)
	}
	t.Cleanup(func() { h.Close() })
	return h
}

// bootKeyFrom builds a SYSTEM hive for the default key and extracts it
// back, which is itself the boot-key round trip.
func bootKeyFrom(t *testing.T) sam.BootKeyResult {
	t.Helper()
	sysPath := writeHive(t, "SYSTEM", samgen.SystemHive(nil))
	res := sam.BootKey(openHive(t, sysPath))
	if !res.OK() {
		t.Fatalf("BootKey: %s (%s)", res.Status, res.Reason)
	}
	return res
}

func twoAccounts() []samgen.Account {
	return []samgen.Account{
		{
			RID: 500, Username: "Administrator", FullName: "Built-in admin",
			NTLM: nil, ACBFlags: 0x0211,
			KeyLastWrite: time.Date(2024, 3, 1, 9, 0, 0, 0, time.UTC),
		},
		{
			RID: 1001, Username: "jdoe", FullName: "J Doe", Comment: "standard user",
			ACBFlags:              0x0214,
			LastLogon:             time.Date(2024, 5, 2, 14, 30, 0, 0, time.UTC),
			LastPasswordSet:       time.Date(2024, 1, 9, 8, 15, 0, 0, time.UTC),
			LastIncorrectPassword: time.Date(2024, 5, 1, 22, 5, 0, 0, time.UTC),
			LoginCount:            14, FailedLoginCount: 2,
			KeyLastWrite: time.Date(2024, 5, 2, 14, 30, 0, 0, time.UTC),
		},
	}
}

// The central test. A hash the test chose is wrapped by the generator in
// the encoding direction and unwrapped by the reader in the decoding
// direction; getting the same bytes back exercises the whole chain --
// boot key, domain password encryption key, per-account DES layer.
func TestAccounts_NTLMHashRoundTripsExactly(t *testing.T) {
	for _, tc := range []struct {
		name   string
		legacy bool
	}{
		{"AES (Windows 10 1607 and later)", false},
		{"RC4 (earlier Windows)", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			accts := twoAccounts()
			accts[1].NTLM = mustHex(t, hashJDoe)

			samPath := writeHive(t, "SAM", samgen.SAMHive(samgen.Options{
				Accounts: accts, Legacy: tc.legacy,
			}))
			res, err := sam.Accounts(openHive(t, samPath), bootKeyFrom(t))
			if err != nil {
				t.Fatal(err)
			}
			if !res.HashesDecodable {
				t.Fatal("hashes reported as not decodable although a boot key was supplied")
			}
			if len(res.Accounts) != 2 {
				t.Fatalf("got %d accounts, want 2", len(res.Accounts))
			}
			a := res.Accounts[1]
			if a.RID != 1001 || a.Username != "jdoe" {
				t.Fatalf("account 1 is RID %d %q, want 1001 jdoe", a.RID, a.Username)
			}
			if a.HashStatus != sam.HashDecoded {
				t.Fatalf("hash status %q, want present (note: %s)", a.HashStatus, a.HashNote)
			}
			if a.NTLMHash != hashJDoe {
				t.Errorf("NTLM hash round-tripped to %q, want %q", a.NTLMHash, hashJDoe)
			}
			wantFormat := "aes"
			if tc.legacy {
				wantFormat = "rc4"
			}
			if a.HashFormat != wantFormat {
				t.Errorf("hash format %q, want %q", a.HashFormat, wantFormat)
			}
		})
	}
}

// An account with no stored hash must be reported as such -- and must
// NOT be given the empty-string NTLM constant that some tools print
// there. That constant is an inference, not a reading.
func TestAccounts_NoStoredHashIsReportedNotInvented(t *testing.T) {
	samPath := writeHive(t, "SAM", samgen.SAMHive(samgen.Options{Accounts: twoAccounts()}))
	res, err := sam.Accounts(openHive(t, samPath), bootKeyFrom(t))
	if err != nil {
		t.Fatal(err)
	}
	a := res.Accounts[0]
	if a.Username != "Administrator" {
		t.Fatalf("account 0 is %q", a.Username)
	}
	if a.HashStatus != sam.HashNotStored {
		t.Errorf("hash status %q, want %q", a.HashStatus, sam.HashNotStored)
	}
	if a.NTLMHash != "" {
		t.Errorf("a hash value %q was reported for an account that stores none", a.NTLMHash)
	}
	if a.NTLMHash == hashAdmin {
		t.Error("the empty-password NTLM constant was substituted for a missing hash")
	}
	if a.HashNote == "" {
		t.Error("no explanation was recorded for the missing hash")
	}
}

// Without the SYSTEM hive there is no boot key, and therefore no hash.
// Everything else about the account must still be readable: that is the
// difference between "we could not decode this" and "we found nothing".
func TestAccounts_WithoutBootKeyReportsEncryptedButStillReadsAccounts(t *testing.T) {
	accts := twoAccounts()
	accts[1].NTLM = mustHex(t, hashJDoe)
	samPath := writeHive(t, "SAM", samgen.SAMHive(samgen.Options{Accounts: accts}))

	res, err := sam.Accounts(openHive(t, samPath), sam.BootKeyResult{})
	if err != nil {
		t.Fatal(err)
	}
	if res.HashesDecodable {
		t.Error("hashes reported decodable with no boot key")
	}
	a := res.Accounts[1]
	if a.HashStatus != sam.HashEncryptedSystemMissing {
		t.Errorf("hash status %q, want %q", a.HashStatus, sam.HashEncryptedSystemMissing)
	}
	if a.NTLMHash != "" {
		t.Errorf("a hash was produced without a boot key: %q", a.NTLMHash)
	}
	if !strings.Contains(a.HashNote, "SYSTEM") {
		t.Errorf("the note does not say the SYSTEM hive is what is missing: %q", a.HashNote)
	}
	// The rest of the record must be intact.
	if a.Username != "jdoe" || a.RID != 1001 {
		t.Errorf("account identity lost: RID %d %q", a.RID, a.Username)
	}
	if a.LoginCount != 14 || len(a.ACBNames) == 0 {
		t.Errorf("account metadata lost: logins=%d flags=%v", a.LoginCount, a.ACBNames)
	}
}

// A SYSTEM hive whose Lsa keys have no class names cannot supply a boot
// key. It must fail, not return a wrong one.
func TestBootKey_MissingSysKeyFailsCleanly(t *testing.T) {
	p := writeHive(t, "SYSTEM", samgen.SystemHiveWithoutSysKey())
	res := sam.BootKey(openHive(t, p))
	if res.OK() {
		t.Fatal("a SYSTEM hive with no SysKey class names produced a boot key")
	}
	if res.Status != sam.BootKeyUnusable {
		t.Errorf("status %q, want %q", res.Status, sam.BootKeyUnusable)
	}
	if res.Reason == "" {
		t.Error("the failure was not explained")
	}
}

// A boot key that is not the one this SAM was written with must not
// silently yield plausible-looking hashes.
func TestAccounts_WrongBootKeyDoesNotSilentlyProduceHashes(t *testing.T) {
	accts := twoAccounts()
	accts[1].NTLM = mustHex(t, hashJDoe)
	samPath := writeHive(t, "SAM", samgen.SAMHive(samgen.Options{Accounts: accts, Legacy: true}))

	wrong := make([]byte, 16)
	for i := range wrong {
		wrong[i] = byte(i)
	}
	res, err := sam.Accounts(openHive(t, samPath), sam.BootKeyResult{Key: wrong, Status: sam.BootKeyDerived, Source: "SYSTEM"})
	if err != nil {
		t.Fatal(err)
	}
	// The RC4 domain key record carries a checksum, so a wrong boot key
	// is caught rather than producing garbage hashes.
	if res.HashesDecodable {
		t.Fatal("a wrong boot key was accepted")
	}
	a := res.Accounts[1]
	if a.NTLMHash != "" {
		t.Errorf("a wrong boot key produced a hash: %q", a.NTLMHash)
	}
	if !strings.Contains(a.HashNote, "checksum") {
		t.Errorf("the failure was not explained as a key mismatch: %q", a.HashNote)
	}
}

func TestAccounts_UsernameRIDAndMetadata(t *testing.T) {
	accts := twoAccounts()
	accts[1].NTLM = mustHex(t, hashJDoe)
	samPath := writeHive(t, "SAM", samgen.SAMHive(samgen.Options{Accounts: accts}))
	res, err := sam.Accounts(openHive(t, samPath), bootKeyFrom(t))
	if err != nil {
		t.Fatal(err)
	}
	a := res.Accounts[1]
	if a.FullName != "J Doe" || a.Comment != "standard user" {
		t.Errorf("full name %q comment %q", a.FullName, a.Comment)
	}
	if got := a.LastLogon.UTC().Format(time.RFC3339); got != "2024-05-02T14:30:00Z" {
		t.Errorf("last logon %s", got)
	}
	if got := a.LastPasswordSet.UTC().Format(time.RFC3339); got != "2024-01-09T08:15:00Z" {
		t.Errorf("last password set %s", got)
	}
	if got := a.LastIncorrectPassword.UTC().Format(time.RFC3339); got != "2024-05-01T22:05:00Z" {
		t.Errorf("last incorrect password %s", got)
	}
	if !a.AccountExpires.IsZero() {
		t.Errorf("account expiry should stay zero for 'never', got %v", a.AccountExpires)
	}
	if a.FailedLoginCount != 2 {
		t.Errorf("failed login count %d", a.FailedLoginCount)
	}
	// The built-in admin fixture is disabled; jdoe is not.
	if !res.Accounts[0].Disabled {
		t.Error("the disabled account is not reported disabled")
	}
	if a.Disabled {
		t.Error("an enabled account is reported disabled")
	}
	if !contains(a.ACBNames, "normal_account") || !contains(a.ACBNames, "password_does_not_expire") {
		t.Errorf("account control flags decoded as %v", a.ACBNames)
	}
}

// An F record whose RID disagrees with the key name is not trusted for
// the flags and counters that share it -- but the account, its name and
// its hash still come through, because those come from V.
func TestAccounts_FRecordRIDMismatchIsNotTrusted(t *testing.T) {
	accts := twoAccounts()
	accts[1].NTLM = mustHex(t, hashJDoe)
	accts[1].BadRIDInF = true
	samPath := writeHive(t, "SAM", samgen.SAMHive(samgen.Options{Accounts: accts}))
	res, err := sam.Accounts(openHive(t, samPath), bootKeyFrom(t))
	if err != nil {
		t.Fatal(err)
	}
	a := res.Accounts[1]
	if a.RID != 1001 {
		t.Errorf("RID taken from the disputed F record: %d", a.RID)
	}
	if a.ACBFlags != 0 || a.LoginCount != 0 {
		t.Errorf("flags/counters were taken from an F record whose RID disagrees: %#x %d", a.ACBFlags, a.LoginCount)
	}
	if a.NTLMHash != hashJDoe {
		t.Errorf("the hash, which comes from V, was lost: %q", a.NTLMHash)
	}
}

// An account with no F record at all still yields name, RID and hash.
func TestAccounts_MissingFRecordStillYieldsTheAccount(t *testing.T) {
	accts := twoAccounts()
	accts[1].NTLM = mustHex(t, hashJDoe)
	accts[1].OmitF = true
	samPath := writeHive(t, "SAM", samgen.SAMHive(samgen.Options{Accounts: accts}))
	res, err := sam.Accounts(openHive(t, samPath), bootKeyFrom(t))
	if err != nil {
		t.Fatal(err)
	}
	a := res.Accounts[1]
	if a.Username != "jdoe" || a.NTLMHash != hashJDoe {
		t.Errorf("account lost when F was absent: %q %q", a.Username, a.NTLMHash)
	}
	if !a.LastLogon.IsZero() {
		t.Error("a logon time appeared from nowhere with no F record")
	}
}

// A V record cut short must not read past itself, and must not produce
// half a username or half a hash.
func TestAccounts_TruncatedVRecordIsRefusedNotHalfRead(t *testing.T) {
	for _, n := range []int{1, 16, 0x40, 0xCB, 0xCC, 0xD0, 0x120} {
		accts := twoAccounts()
		accts[1].NTLM = mustHex(t, hashJDoe)
		accts[1].TruncateV = n

		samPath := writeHive(t, "SAM", samgen.SAMHive(samgen.Options{Accounts: accts}))
		res, err := sam.Accounts(openHive(t, samPath), bootKeyFrom(t))
		if err != nil {
			t.Fatalf("V truncated to %d bytes failed the whole hive: %v", n, err)
		}
		for _, a := range res.Accounts {
			if a.RID != 1001 {
				continue
			}
			if a.NTLMHash != "" && a.NTLMHash != hashJDoe {
				t.Errorf("V truncated to %d bytes produced a wrong hash %q", n, a.NTLMHash)
			}
			if a.Username != "" && a.Username != "jdoe" {
				t.Errorf("V truncated to %d bytes produced a wrong username %q", n, a.Username)
			}
		}
	}
}

// Detection is structural. A valid hive that is not a SAM is rejected,
// and a SAM is accepted whatever it is called.
func TestDetect_StructuralNotByName(t *testing.T) {
	samPath := writeHive(t, "definitely-not-called-sam.bin",
		samgen.SAMHive(samgen.Options{Accounts: twoAccounts()}))
	if !sam.Detect(openHive(t, samPath)) {
		t.Error("a renamed SAM was not detected")
	}
	other := writeHive(t, "SAM", samgen.NonSAMHive())
	if sam.Detect(openHive(t, other)) {
		t.Error("a SOFTWARE hive named SAM was detected as a SAM")
	}
	if _, err := sam.Accounts(openHive(t, other), sam.BootKeyResult{}); err == nil {
		t.Error("Accounts succeeded on a hive that is not a SAM")
	}
}

// A SAM with no domain record cannot have its hashes unwrapped. The
// accounts must still be listed.
func TestAccounts_MissingDomainRecordStillListsAccounts(t *testing.T) {
	accts := twoAccounts()
	accts[1].NTLM = mustHex(t, hashJDoe)
	samPath := writeHive(t, "SAM", samgen.SAMHive(samgen.Options{Accounts: accts, OmitDomainF: true}))
	res, err := sam.Accounts(openHive(t, samPath), bootKeyFrom(t))
	if err != nil {
		t.Fatal(err)
	}
	if res.HashesDecodable {
		t.Error("hashes reported decodable with no domain record")
	}
	if len(res.Accounts) != 2 {
		t.Fatalf("accounts lost: %d", len(res.Accounts))
	}
	if res.Accounts[1].NTLMHash != "" {
		t.Error("a hash was produced with no password encryption key")
	}
}

// The username must come from the account's own V record; the Names
// index is only a fallback.
func TestAccounts_UsernameSurvivesWithoutTheNamesIndex(t *testing.T) {
	accts := twoAccounts()
	accts[1].NTLM = mustHex(t, hashJDoe)
	samPath := writeHive(t, "SAM", samgen.SAMHive(samgen.Options{Accounts: accts, OmitNamesIndex: true}))
	res, err := sam.Accounts(openHive(t, samPath), bootKeyFrom(t))
	if err != nil {
		t.Fatal(err)
	}
	if res.Accounts[1].Username != "jdoe" {
		t.Errorf("username %q", res.Accounts[1].Username)
	}
}

// Many accounts: correctness and a bound on the work done. ChildKeys is
// a single pass; the Subkeys-then-OpenKey shape this replaced was
// quadratic and would not finish in a reasonable time here.
func TestAccounts_ManyAccountsAreAllReadAndAreNotQuadratic(t *testing.T) {
	const n = 1500
	accts := make([]samgen.Account, 0, n)
	for i := 0; i < n; i++ {
		a := samgen.Account{
			RID: uint32(1000 + i), Username: "user" + itoa(i),
			ACBFlags: 0x0010, LoginCount: uint16(i % 100),
		}
		if i%2 == 0 {
			a.NTLM = mustHex(t, hashSvc)
		}
		accts = append(accts, a)
	}
	samPath := writeHive(t, "SAM", samgen.SAMHive(samgen.Options{Accounts: accts}))

	start := time.Now()
	res, err := sam.Accounts(openHive(t, samPath), bootKeyFrom(t))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Accounts) != n {
		t.Fatalf("read %d accounts, want %d", len(res.Accounts), n)
	}
	// Ordering is deterministic: by RID.
	for i := 1; i < len(res.Accounts); i++ {
		if res.Accounts[i-1].RID >= res.Accounts[i].RID {
			t.Fatalf("accounts are not in RID order at %d", i)
		}
	}
	withHash := 0
	for _, a := range res.Accounts {
		if a.HashStatus == sam.HashDecoded {
			withHash++
			if a.NTLMHash != hashSvc {
				t.Fatalf("RID %d decoded to %q", a.RID, a.NTLMHash)
			}
		}
	}
	if withHash != n/2 {
		t.Errorf("%d accounts carry a hash, want %d", withHash, n/2)
	}
	if elapsed > 20*time.Second {
		t.Errorf("%d accounts took %s, which suggests traversal is not linear", n, elapsed)
	}
	t.Logf("%d accounts parsed in %s", n, elapsed)
}

// Parsing the same bytes twice must give the same answer.
func TestAccounts_Deterministic(t *testing.T) {
	accts := twoAccounts()
	accts[1].NTLM = mustHex(t, hashJDoe)
	hive := samgen.SAMHive(samgen.Options{Accounts: accts})
	// The generator itself must be deterministic, or fixtures are not
	// reproducible.
	if string(hive) != string(samgen.SAMHive(samgen.Options{Accounts: accts})) {
		t.Fatal("the fixture generator is not deterministic")
	}
	bk := bootKeyFrom(t)
	var first []sam.Account
	for i := 0; i < 3; i++ {
		p := writeHive(t, "SAM", hive)
		res, err := sam.Accounts(openHive(t, p), bk)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = res.Accounts
			continue
		}
		if len(res.Accounts) != len(first) {
			t.Fatalf("run %d returned %d accounts, first returned %d", i, len(res.Accounts), len(first))
		}
		for j := range first {
			if !sameAccount(res.Accounts[j], first[j]) {
				t.Fatalf("run %d differs at account %d: %+v vs %+v", i, j, res.Accounts[j], first[j])
			}
		}
	}
}

// sameAccount compares every field, including the flag-name slice that
// stops sam.Account being directly comparable.
func sameAccount(a, b sam.Account) bool {
	if len(a.ACBNames) != len(b.ACBNames) {
		return false
	}
	for i := range a.ACBNames {
		if a.ACBNames[i] != b.ACBNames[i] {
			return false
		}
	}
	a.ACBNames, b.ACBNames = nil, nil
	return reflect.DeepEqual(a, b)
}

// Truncating and corrupting the hive itself must never panic and must
// never invent an account. This is the fuzz-shaped boundary sweep around
// the binary reader.
func TestAccounts_TruncatedAndCorruptedHivesNeverPanicOrInvent(t *testing.T) {
	accts := twoAccounts()
	accts[1].NTLM = mustHex(t, hashJDoe)
	full := samgen.SAMHive(samgen.Options{Accounts: accts})
	bk := bootKeyFrom(t)

	// Every truncation length, stepped so the test stays quick but the
	// step never lines up with a cell boundary.
	for n := 0; n < len(full); n += 7 {
		p := writeHive(t, "SAM", samgen.Truncate(full, n))
		res, err := func() (res sam.Result, err error) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("truncation to %d bytes panicked: %v", n, r)
				}
			}()
			h, oerr := regf.Open(p, regf.DefaultLimits())
			if oerr != nil {
				return sam.Result{}, oerr
			}
			defer h.Close()
			return sam.Accounts(h, bk)
		}()
		if err != nil {
			continue // refused, which is a correct outcome
		}
		for _, a := range res.Accounts {
			if a.NTLMHash != "" && a.NTLMHash != hashJDoe {
				t.Fatalf("truncation to %d bytes produced hash %q", n, a.NTLMHash)
			}
			if a.Username != "" && a.Username != "jdoe" && a.Username != "Administrator" {
				t.Fatalf("truncation to %d bytes produced username %q", n, a.Username)
			}
		}
	}

	// Corruption at a spread of offsets across the whole file.
	for off := 0; off < len(full); off += 61 {
		p := writeHive(t, "SAM", samgen.Corrupt(full, off, 0xFF, 0xFF, 0xFF, 0xFF))
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("corruption at %d panicked: %v", off, r)
				}
			}()
			h, err := regf.Open(p, regf.DefaultLimits())
			if err != nil {
				return
			}
			defer h.Close()
			res, err := sam.Accounts(h, bk)
			if err != nil {
				return
			}
			for _, a := range res.Accounts {
				if a.NTLMHash != "" && a.NTLMHash != hashJDoe {
					t.Fatalf("corruption at %d produced hash %q", off, a.NTLMHash)
				}
			}
		}()
	}
}

// Nothing in this package may turn a hash back into anything. This is a
// source-level guard so the boundary cannot be crossed by accident.
func TestNoPasswordRecoveryCapability(t *testing.T) {
	for _, f := range []string{"sam.go", "samgen/samgen.go"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		// Comments are stripped first: the package documentation says
		// in words that it does none of this, and that sentence must
		// not be what trips the guard. What is under test is the CODE.
		var code strings.Builder
		for _, line := range strings.Split(string(src), "\n") {
			t := strings.TrimSpace(line)
			if strings.HasPrefix(t, "//") {
				continue
			}
			code.WriteString(strings.ToLower(line))
			code.WriteString("\n")
		}
		low := code.String()
		for _, banned := range []string{
			"wordlist", "dictionary", "bruteforce", "brute-force",
			"hashcat", "johntheripper", "rainbow", "crack",
			"md4", "ntowf", "password :=", "plaintext",
		} {
			if strings.Contains(low, banned) {
				t.Errorf("%s contains %q in code; this package must hold no password-recovery capability", f, banned)
			}
		}
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

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
