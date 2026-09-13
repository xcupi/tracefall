package api

import (
	"strings"
	"testing"

	"tracefall/internal/sam"
)

// UI regression tests for Windows SAM credential evidence (Phase 18).
// These read app.js and assert what only the frontend can express.

// The Timeline must offer the artifact under a name an analyst looking
// for the SAM would actually try, distinct from the generic hive.
func TestSAMUI_ArtifactLabelIsWindowsSAMAndDistinct(t *testing.T) {
	src := string(appJS(t))
	if !strings.Contains(src, `sam_account: "Windows SAM"`) {
		t.Error(`app.js does not label the SAM artifact "Windows SAM"`)
	}
	if strings.Contains(src, `registry_hive: "Windows SAM"`) {
		t.Error("the generic registry hive artifact is labelled Windows SAM")
	}
}

// The account event must be categorised as an account record -- never as
// execution, a logon, or user activity.
func TestSAMUI_EventIsCategorisedAsAnAccountRecord(t *testing.T) {
	src := string(appJS(t))
	if !strings.Contains(src, `sam_local_account: "account"`) {
		t.Error("the SAM account event is not categorised as an account record")
	}
	for _, wrong := range []string{
		`sam_local_account: "execution"`, `sam_local_account: "authentication"`,
		`sam_local_account: "user_activity"`, `sam_local_account: "persistence"`,
	} {
		if strings.Contains(src, wrong) {
			t.Errorf("the SAM account event is categorised as %q", wrong)
		}
	}
	if !strings.Contains(src, `account: "Account / Credential"`) {
		t.Error("the account category has no display label")
	}
}

// The Detail column must show the account, not the near-identical
// registry key -- and never the hash.
func TestSAMUI_DetailColumnShowsTheAccountNotTheHash(t *testing.T) {
	body := functionBody(t, appJS(t), "function eventDetailValue(")
	if !strings.Contains(body, "sam_account: extra.account_name") {
		t.Error("the Detail column does not show the account name for a SAM event")
	}
	if strings.Contains(body, "ntlm_hash") {
		t.Error("eventDetailValue reads the NTLM hash; credential material must not be in the Detail column")
	}
}

// The hash is shown in exactly one place: the event's own detail view.
func TestSAMUI_HashIsShownOnlyInTheCredentialPanel(t *testing.T) {
	src := string(appJS(t))
	panel := functionBody(t, appJS(t), "function credentialPanel(")
	if panel == "" {
		t.Fatal("there is no credentialPanel renderer")
	}
	if !strings.Contains(panel, "x.ntlm_hash") {
		t.Error("the credential panel does not render the hash")
	}
	if !strings.Contains(panel, `ev.event_type !== "sam_local_account"`) {
		t.Error("the credential panel is not gated on the SAM account event type")
	}
	// Exactly one renderer may read ntlm_hash.
	if n := strings.Count(src, "ntlm_hash"); n == 0 {
		t.Fatal("app.js never reads the hash at all")
	}
	for _, fn := range []string{"function timelineRow(", "function eventDetailValue("} {
		if strings.Contains(functionBody(t, appJS(t), fn), "ntlm_hash") {
			t.Errorf("%s reads the NTLM hash", fn)
		}
	}
}

// Copy must use the SAME mechanism the rest of the Timeline uses, and
// must carry the complete hash whatever the display shows.
func TestSAMUI_HashIsCopiedInFullThroughTheSharedMechanism(t *testing.T) {
	panel := functionBody(t, appJS(t), "function credentialPanel(")

	if !strings.Contains(panel, "detailCell(x.ntlm_hash") {
		t.Error("the hash is not rendered through detailCell, so it does not get the shared Copy control")
	}
	// Displayed truncated...
	if !strings.Contains(panel, "truncateAt:") {
		t.Error("the hash is not displayed truncated")
	}
	// ...but detailCell always carries the COMPLETE value in data-copy,
	// which is what the shared handler copies. Pinned here so the two
	// cannot drift apart.
	cell := functionBody(t, appJS(t), "function detailCell(")
	if !strings.Contains(cell, `data-copy="${esc(str)}"`) {
		t.Error("detailCell no longer carries the complete value for Copy")
	}
	if !strings.Contains(cell, "const at = (opts && opts.truncateAt)") {
		t.Error("detailCell's truncation length is not overridable, so the hash cannot be shown shorter")
	}
	wire := functionBody(t, appJS(t), "function wireDetailCells(")
	if !strings.Contains(wire, "copyText(btn.dataset.copy)") {
		t.Error("the copy handler does not copy the complete stored value")
	}
	// The panel must actually be wired up, or its buttons do nothing.
	loader := functionBody(t, appJS(t), "async function loadProvenanceInto(")
	if !strings.Contains(loader, "credentialPanel(") || !strings.Contains(loader, "wireDetailCells(box)") {
		t.Error("the credential panel is not rendered and wired into the event detail view")
	}
}

// The wording must never let a reader mistake a hash for a password.
func TestSAMUI_HashIsLabelledAHashNotAPassword(t *testing.T) {
	panel := functionBody(t, appJS(t), "function credentialPanel(")
	if !strings.Contains(panel, "NTLM hash") {
		t.Error("the hash field is not labelled as an NTLM hash")
	}
	low := strings.ToLower(panel)
	for _, banned := range []string{"plaintext", "cleartext", "crack", "\"password\"", "recovered"} {
		if strings.Contains(low, banned) {
			t.Errorf("the credential panel contains %q", banned)
		}
	}
	// A missing hash must be explained, not left blank.
	if !strings.Contains(panel, "ntlm_hash_unavailable_reason") {
		t.Error("the panel does not explain why a hash is unavailable")
	}
	if !strings.Contains(panel, "not available") {
		t.Error("the panel does not state when a hash is unavailable")
	}
}

// The panel must show the account's timestamps and say the event has
// none of its own.
func TestSAMUI_PanelSeparatesAccountTimesFromTheEventTime(t *testing.T) {
	panel := functionBody(t, appJS(t), "function credentialPanel(")
	for _, field := range []string{"last_logon", "password_last_set", "last_incorrect_password"} {
		if !strings.Contains(panel, field) {
			t.Errorf("the panel does not show %s", field)
		}
	}
	if !strings.Contains(panel, "timestamp_basis") {
		t.Error("the panel does not state why the event carries no timestamp of its own")
	}
}

// The panel needs styling, or it renders as an unreadable run of text.
func TestSAMUI_CredentialPanelIsStyled(t *testing.T) {
	css := styleCSS(t)
	for _, rule := range []string{".cred-panel", ".cred-label", ".cred-value", ".cred-note", ".provenance-text"} {
		if !strings.Contains(css, rule) {
			t.Errorf("style.css has no %s rule", rule)
		}
	}
}

// ---------------- Phase 19: hash status wording ----------------

// "not available" was wrong for an encrypted hash. The material exists;
// what is missing is a second file. The UI must say so, and must say
// something different for an account that genuinely stores no hash.
func TestSAMUI_EncryptedHashIsNotWordedAsMissing(t *testing.T) {
	body := functionBody(t, appJS(t), "function hashStateLabel(")
	if body == "" {
		t.Fatal("there is no hashStateLabel renderer")
	}
	for status, want := range map[string]string{
		"encrypted_system_hive_missing":  "Encrypted",
		"encrypted_system_hive_unusable": "Encrypted",
		"encrypted_data_unavailable":     "Encrypted",
		"unsupported":                    "Encrypted",
	} {
		idx := strings.Index(body, `"`+status+`"`)
		if idx < 0 {
			t.Errorf("hashStateLabel does not handle %q", status)
			continue
		}
		// The wording for this case, up to the next case label.
		rest := body[idx:]
		if end := strings.Index(rest[1:], "case "); end > 0 {
			rest = rest[:end]
		}
		if !strings.Contains(rest, want) {
			t.Errorf("%s is not worded as %q: %s", status, want, strings.TrimSpace(rest))
		}
		if strings.Contains(rest, "not available") || strings.Contains(rest, "Not available") {
			t.Errorf("%s is worded as \"not available\"; the hash material exists", status)
		}
		if !strings.Contains(rest, "encrypted: true") {
			t.Errorf("%s is not flagged as encrypted, so it renders like a missing hash", status)
		}
	}

	// The two remedies must be distinguishable at a glance.
	if !strings.Contains(body, "SYSTEM hive required") {
		t.Error(`a missing SYSTEM hive is not worded "SYSTEM hive required"`)
	}
	if !strings.Contains(body, "SYSTEM hive could not be used") {
		t.Error(`an unusable SYSTEM hive is not worded "SYSTEM hive could not be used"`)
	}
	// And an account with no stored hash must NOT say "encrypted".
	notStored := body[strings.Index(body, `"not_stored"`):]
	if end := strings.Index(notStored[1:], "case "); end > 0 {
		notStored = notStored[:end]
	}
	if strings.Contains(notStored, "Encrypted") {
		t.Error("an account that stores no hash is described as encrypted")
	}
	if !strings.Contains(notStored, "encrypted: false") {
		t.Error("an account that stores no hash is flagged as encrypted")
	}
}

// The panel must show the status explicitly, and name the SYSTEM hive
// the hash was decoded with.
func TestSAMUI_PanelShowsStatusAndBootKeySource(t *testing.T) {
	panel := functionBody(t, appJS(t), "function credentialPanel(")

	if !strings.Contains(panel, `add("Hash status", "decoded")`) {
		t.Error(`a decoded hash does not show the status "decoded"`)
	}
	if !strings.Contains(panel, `add("Hash status", x.ntlm_hash_status`) {
		t.Error("a non-decoded hash does not show its status")
	}
	if !strings.Contains(panel, "boot_key_source") {
		t.Error("the panel does not name the SYSTEM hive that supplied the boot key")
	}
	if !strings.Contains(panel, `add("Boot key source"`) {
		t.Error("the boot key source has no label")
	}
	if !strings.Contains(panel, "hashStateLabel(") {
		t.Error("the panel does not use hashStateLabel, so encrypted and missing render alike")
	}
	// The encrypted state must be styled differently from a missing one.
	if !strings.Contains(panel, "cred-encrypted") {
		t.Error("an encrypted hash is not styled distinctly from a missing one")
	}
	css := styleCSS(t)
	if !strings.Contains(css, ".cred-encrypted") {
		t.Error("style.css has no .cred-encrypted rule")
	}
}

// The status strings the frontend switches on must be the ones the
// backend emits. A silent rename on either side would make every hash
// fall through to the default "Not available" wording -- exactly the bug
// this phase set out to fix.
func TestSAMUI_StatusVocabularyMatchesTheBackend(t *testing.T) {
	body := functionBody(t, appJS(t), "function hashStateLabel(")
	for _, status := range []string{
		string(sam.HashNotStored),
		string(sam.HashEncryptedSystemMissing),
		string(sam.HashEncryptedSystemUnusable),
		string(sam.HashEncryptedDataUnavailable),
		string(sam.HashUnsupported),
	} {
		if !strings.Contains(body, `"`+status+`"`) {
			t.Errorf("the UI does not handle backend status %q; it would render as \"Not available\"", status)
		}
	}
	// "decoded" is handled by the presence of the hash itself, and the
	// panel must say so rather than routing it through hashStateLabel.
	if string(sam.HashDecoded) != "decoded" {
		t.Errorf("the decoded status constant is %q; the UI writes \"decoded\" literally", sam.HashDecoded)
	}
}
