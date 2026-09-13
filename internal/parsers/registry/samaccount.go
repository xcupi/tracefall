package registry

// Windows SAM local-account and NTLM-hash evidence (Phase 18).
//
// This is the extraction pass for the SAM hive, alongside the UserAssist,
// ShellBags, Amcache and MRU passes. It sits inside the registry parser
// for the same reason those do: ingest.Discover gives a file to exactly
// ONE parser, and a SAM hive is a REGF file. A separate top-level parser
// would have to take the file away from registry@1 entirely, which would
// silently stop a SAM contributing the persistence and key-last-write
// evidence it contributes today. The decoding itself lives in its own
// package, internal/sam, and the events carry their own artifact type --
// so an analyst filtering the Timeline sees "Windows SAM", not "Windows
// Registry Hive".
//
// THE BOOT KEY, AND WHERE IT COMES FROM
//
// A SAM hive does not contain the key its hashes are wrapped under. That
// key is the machine's SysKey, and it lives in the SYSTEM hive. So a SAM
// on its own can yield every account, RID, flag and timestamp, and no
// hash at all -- which is a fact about the format, not a shortcoming to
// paper over.
//
// The key therefore arrives as COLLECTION-SCOPED CONTEXT
// (parsers.ParseContext): the import derives it once, from the SYSTEM
// hive in the same evidence collection, before any file is parsed.
//
// An earlier design looked for a SYSTEM hive next to the SAM ON DISK.
// That works for a directory of already-extracted files and fails for an
// AD1 image, because AD1 entries are materialized one at a time
// immediately before each is parsed -- so at the moment the SAM is
// parsed, the SYSTEM hive beside it in the image has not been written
// yet. Measured on real evidence, the SAM was extracted 6.2 seconds
// before the SYSTEM, and every hash came back "encrypted, no SYSTEM
// hive" while the SYSTEM hive sat in the very same collection. The
// filesystem scan is kept only as a FALLBACK for a caller that supplies
// no context at all, and it can no longer be the reason a hash fails to
// decode.
//
// Nothing here recovers a password. See internal/sam.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
	"tracefall/internal/regf"
	"tracefall/internal/sam"
)

// samAccountEvents extracts local accounts from a SAM hive. A no-op for
// every other hive: a SOFTWARE hive with no SAM tree is a valid artifact
// with zero account records, not an error.
func (p Parser) samAccountEvents(h *regf.Hive, absPath string, hiveType HiveType, ctx parsers.ParseContext) ([]model.Event, []model.RawEvidence) {
	// Structure, not filename. classifyHive's answer is not enough on
	// its own -- it can key off a name -- so the account tree itself is
	// what decides.
	if !sam.Detect(h) {
		return nil, nil
	}

	boot := bootKeyFromContext(ctx)
	if boot.Status == sam.BootKeyNoSystemHive && ctx.BootKeyStatus == "" {
		// No context at all: a direct Parse call, or a caller that
		// predates collection context. Fall back to looking beside the
		// SAM on disk, which is correct whenever the files are already
		// extracted. It is a fallback, not the mechanism.
		boot = p.bootKeyBesideSAM(absPath)
	}

	res, err := sam.Accounts(h, boot)
	if err != nil {
		return nil, nil
	}

	var events []model.Event
	var raws []model.RawEvidence
	for _, a := range res.Accounts {
		ev, raw := samAccountEvent(a, res, hiveType)
		events = append(events, ev)
		raws = append(raws, raw)
	}
	return events, raws
}

// bootKeyFromContext converts the collection-scoped context the import
// prepared into the form internal/sam consumes.
func bootKeyFromContext(ctx parsers.ParseContext) sam.BootKeyResult {
	if len(ctx.BootKey) == 16 {
		return sam.BootKeyResult{
			Key:          ctx.BootKey,
			Status:       sam.BootKeyDerived,
			Source:       ctx.BootKeySource,
			SourceSHA256: ctx.BootKeySHA256,
			ControlSet:   ctx.BootKeyControlSet,
		}
	}
	status := sam.BootKeyStatus(ctx.BootKeyStatus)
	if status == "" {
		status = sam.BootKeyNoSystemHive
	}
	return sam.BootKeyResult{Status: status, Source: ctx.BootKeySource, Reason: ctx.BootKeyReason}
}

// bootKeyBesideSAM is the FALLBACK path: look for a SYSTEM hive in the
// same directory as the SAM. Correct whenever the collection's files are
// already on disk, which is every case except an AD1 mid-import -- and
// that case is handled by collection context, above.
//
// A candidate is verified by CONTENT: it must actually yield a boot key.
// A renamed SYSTEM hive is therefore still found, and a file merely
// called SYSTEM is not used.
func (p Parser) bootKeyBesideSAM(samPath string) sam.BootKeyResult {
	dir := filepath.Dir(samPath)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return sam.BootKeyResult{
			Status: sam.BootKeyNoSystemHive,
			Reason: "the directory holding the SAM hive could not be read, so no SYSTEM hive could be looked for.",
		}
	}

	var candidates []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.EqualFold(e.Name(), "SYSTEM") {
			candidates = append([]string{e.Name()}, candidates...)
			continue
		}
		if isHiveSidecar(e.Name()) {
			continue
		}
		candidates = append(candidates, e.Name())
	}

	tried := 0
	lastReason := ""
	for _, name := range candidates {
		if tried >= maxBootKeyCandidates {
			break
		}
		path := filepath.Join(dir, name)
		info, statErr := os.Stat(path)
		if statErr != nil || info.Size() < 4096 {
			continue
		}
		sh, oerr := regf.Open(path, p.limits)
		if oerr != nil {
			continue
		}
		tried++
		res := sam.BootKey(sh)
		sh.Close()
		if res.OK() {
			res.Source = name
			return res
		}
		if strings.EqualFold(name, "SYSTEM") {
			// A file that IS the SYSTEM hive by name and failed is worth
			// reporting specifically: "the SYSTEM you have will not do"
			// is a different problem from "you have no SYSTEM".
			lastReason = res.Reason
		}
	}
	if lastReason != "" {
		return sam.BootKeyResult{Status: sam.BootKeyUnusable, Source: "SYSTEM", Reason: lastReason}
	}
	return sam.BootKeyResult{
		Status: sam.BootKeyNoSystemHive,
		Reason: "No SYSTEM hive carrying a machine boot key was found in this evidence.",
	}
}

// isHiveSidecar reports whether a filename is one of the transaction
// logs, backups or slack files that sit beside a hive and are not one.
func isHiveSidecar(name string) bool {
	lower := strings.ToLower(name)
	for _, suffix := range []string{".log", ".log1", ".log2", ".blf", ".bak"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return strings.Contains(lower, "regtrans") || strings.Contains(lower, "fileslack")
}

const maxBootKeyCandidates = 64

// samAccountEvent turns one decoded account into a timeline event.
//
// The event carries NO TIMESTAMP. A SAM account record does not say when
// it was written, and the hive's or the file's modification time would
// be a different fact wearing this event's clothes. The account's own
// timestamps travel as labelled fields instead, each saying what it
// means.
func samAccountEvent(a sam.Account, res sam.Result, hiveType HiveType) (model.Event, model.RawEvidence) {
	keyPath := rootedPath(hiveType, `SAM\Domains\Account\Users\`+fmt.Sprintf("%08X", a.RID))

	extra := map[string]string{
		"artifact_class":     "sam_account",
		"registry_hive_type": string(hiveType),
		"registry_key":       keyPath,
		"account_name":       a.Username,
		"rid":                strconv.FormatUint(uint64(a.RID), 10),
		// Local, always. A SAM holds the machine's own accounts; a
		// domain account is never in one, and saying so stops a reader
		// assuming this is domain-wide evidence.
		"account_scope": "local account on this machine (a SAM hive never holds domain accounts)",

		"evidence_meaning": "Windows local account credential evidence: this account exists in the machine's " +
			"SAM database. It is a record of an ACCOUNT, not of any activity -- nobody logged on, nothing ran, " +
			"and no password was changed at the time this event appears. Every local machine has these records.",

		// The event's own time, stated rather than left to inference.
		"timestamp_meaning": "no time is recorded for this event",
		"timestamp_basis": "A SAM account record carries no timestamp of its own. The account's stored times " +
			"(last logon, password last set, last incorrect password) are reported as separate labelled fields " +
			"and are not used as this event's time. Neither the hive's nor the file's modification time is " +
			"substituted: those describe the file, not the account.",

		"ntlm_hash_status": string(a.HashStatus),
	}

	if a.FullName != "" {
		extra["account_full_name"] = a.FullName
	}
	if a.Comment != "" {
		extra["account_comment"] = a.Comment
	}
	if a.ACBFlags != 0 {
		extra["account_control_flags"] = fmt.Sprintf("0x%04X", a.ACBFlags)
		extra["account_control"] = strings.Join(a.ACBNames, ", ")
		extra["account_disabled"] = strconv.FormatBool(a.Disabled)
	} else {
		extra["account_control"] = "not available: this account's fixed record could not be read, " +
			"or its RID disagreed with the key it was stored under"
	}

	// Each timestamp says what it is. None of them is the event's time.
	addAccountTime(extra, "last_logon", a.LastLogon,
		"the last time this account logged on, as the SAM recorded it. Not necessarily complete: "+
			"the SAM stores one value, while the Security event log records every logon")
	addAccountTime(extra, "password_last_set", a.LastPasswordSet,
		"when this account's password was last set. A password-change FACT, recorded on the account -- "+
			"not an event observed at that instant")
	addAccountTime(extra, "last_incorrect_password", a.LastIncorrectPassword,
		"the last time an incorrect password was presented for this account")
	addAccountTime(extra, "account_expires", a.AccountExpires,
		"when this account is set to expire")
	if !a.KeyLastWrite.IsZero() {
		extra["registry_last_write"] = a.KeyLastWrite.UTC().Format("2006-01-02T15:04:05Z")
		extra["registry_last_write_meaning"] = "when this account's registry key was last written. " +
			"Metadata about the record, not an account event"
	}
	if a.ACBFlags != 0 {
		extra["logon_count"] = strconv.FormatUint(uint64(a.LoginCount), 10)
		extra["failed_logon_count"] = strconv.FormatUint(uint64(a.FailedLoginCount), 10)
	}

	// The hash. Decoded, absent, or present-but-encrypted -- the reader
	// is told which, and the three are never worded alike.
	switch {
	case a.HashStatus == sam.HashDecoded:
		extra["ntlm_hash"] = a.NTLMHash
		extra["ntlm_hash_format"] = a.HashFormat
		extra["ntlm_hash_meaning"] = "This is the account's stored NTLM PASSWORD HASH, decoded from the SAM " +
			"using the machine boot key held in the SYSTEM hive. It is NOT a password and it is NOT " +
			"reversible into one. Tracefall does not attempt to recover passwords from hashes."

	case a.HashStatus.Encrypted():
		// The material EXISTS. Saying only "not available" here would
		// read as "this account has no hash", which is a different and
		// wrong forensic statement.
		extra["ntlm_hash_present_but_encrypted"] = "true"
		extra["ntlm_hash_unavailable_reason"] = a.HashNote
		if a.HashFormat != "" {
			extra["ntlm_hash_format"] = a.HashFormat
		}

	default:
		extra["ntlm_hash_unavailable_reason"] = a.HashNote
	}

	// The cryptographic dependency, recorded on every account event
	// whether or not this one had a hash: an analyst reading a decoded
	// hash must be able to see which SECOND file it stands on.
	extra["boot_key_status"] = string(res.BootKey.Status)
	if res.BootKey.Source != "" {
		extra["boot_key_source"] = res.BootKey.Source
		extra["boot_key_source_meaning"] = "The SYSTEM hive that supplied the machine boot key. The NT hashes " +
			"in this SAM cannot be decoded without it, so it is part of the evidence any decoded hash rests on."
	}
	if res.BootKey.SourceSHA256 != "" {
		extra["boot_key_source_sha256"] = res.BootKey.SourceSHA256
	}
	if res.BootKey.ControlSet > 0 {
		extra["boot_key_control_set"] = fmt.Sprintf("ControlSet%03d", res.BootKey.ControlSet)
	}
	if res.BootKey.Reason != "" {
		extra["boot_key_reason"] = res.BootKey.Reason
	}

	ev := model.Event{
		// Deliberately zero. See the comment above and
		// model.EventSAMLocalAccount.
		Host:         "",
		User:         a.Username,
		EventType:    model.EventSAMLocalAccount,
		RegistryPath: keyPath,
		ArtifactType: model.ArtifactSAM,
		Parser:       parserName,
		// 1.0: every field here is read from a fixed, documented
		// structure and cross-checked (the RID in the fixed record
		// against the key name it is stored under). Nothing is inferred.
		Confidence:      1.0,
		SourceReference: "sam:rid=" + strconv.FormatUint(uint64(a.RID), 10),
		Extra:           extra,
	}

	raw := map[string]any{
		"artifact":               "windows_sam_local_account",
		"hive_type":              string(hiveType),
		"key_path":               keyPath,
		"rid":                    a.RID,
		"account_name":           a.Username,
		"account_full_name":      a.FullName,
		"account_comment":        a.Comment,
		"account_control_flags":  fmt.Sprintf("0x%04X", a.ACBFlags),
		"account_control":        a.ACBNames,
		"account_disabled":       a.Disabled,
		"logon_count":            a.LoginCount,
		"failed_logon_count":     a.FailedLoginCount,
		"last_logon":             timeOrNil(a.LastLogon),
		"password_last_set":      timeOrNil(a.LastPasswordSet),
		"last_incorrect_login":   timeOrNil(a.LastIncorrectPassword),
		"account_expires":        timeOrNil(a.AccountExpires),
		"key_last_write":         timeOrNil(a.KeyLastWrite),
		"ntlm_hash_status":       string(a.HashStatus),
		"ntlm_hash_format":       a.HashFormat,
		"hashes_decodable":       res.HashesDecodable,
		"boot_key_status":        string(res.BootKey.Status),
		"boot_key_source":        res.BootKey.Source,
		"boot_key_source_sha256": res.BootKey.SourceSHA256,
		"boot_key_reason":        res.BootKey.Reason,
	}
	if a.HashStatus == sam.HashDecoded {
		raw["ntlm_hash"] = a.NTLMHash
	} else {
		raw["ntlm_hash_present_but_encrypted"] = a.HashStatus.Encrypted()
		raw["ntlm_hash_unavailable_reason"] = a.HashNote
	}
	rawJSON, _ := json.Marshal(raw)
	return ev, model.RawEvidence{SourceReference: ev.SourceReference, Raw: string(rawJSON)}
}

// addAccountTime records one account timestamp with the meaning it
// actually has. A zero FILETIME is Windows saying "never", which is
// itself evidence and is reported as such rather than omitted -- and is
// never replaced by a file or hive modification time.
func addAccountTime(extra map[string]string, field string, t time.Time, meaning string) {
	if t.IsZero() {
		extra[field] = "never"
		extra[field+"_meaning"] = meaning + ". The record stores zero here, which is Windows recording " +
			"that this has never happened -- not that the value is unknown"
		return
	}
	extra[field] = t.UTC().Format("2006-01-02T15:04:05Z")
	extra[field+"_meaning"] = meaning
}
