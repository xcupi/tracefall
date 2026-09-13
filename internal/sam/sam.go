// Package sam decodes Windows local account records out of a SAM
// registry hive: the account name, its RID, its account-control flags
// and timestamps, and -- when the SYSTEM hive's boot key is also
// available -- the stored NTLM password hash.
//
// # WHAT THIS PACKAGE IS NOT
//
// It does not crack passwords, and it contains no wordlist, no brute
// force, and no hash-to-plaintext step of any kind. An NTLM hash is the
// evidence; recovering the password from it is a separate activity that
// Tracefall does not perform. Nothing here ever produces a plaintext
// password.
//
// WHAT "DECRYPTING" MEANS HERE
//
// A SAM hive does not store the NT hash in the clear. It stores it
// wrapped twice: once under a per-account key derived from the RID, and
// once under the domain's Password Encryption Key, which is itself
// wrapped under the machine's boot key (the "SysKey"). The boot key is
// not in the SAM at all -- it is scattered across four class names in
// the SYSTEM hive. Unwrapping those layers with keys that are themselves
// in the evidence recovers the stored hash exactly as Windows stored it.
// It is a decode, not an attack, and the result is still a hash.
//
// The consequence worth stating plainly: WITHOUT THE SYSTEM HIVE THERE
// IS NO HASH. That is not a limitation of this reader, it is what the
// format is. Accounts are still reported -- name, RID, flags, timestamps
// are all readable from the SAM alone -- with the hash marked
// unavailable and the reason recorded, rather than guessed at.
//
// STRUCTURES DECODED
//
//   - SAM\Domains\Account\F            domain record, holds the wrapped
//     Password Encryption Key at offset 0x68
//   - SAM\Domains\Account\Users\<RID>  one key per account, named as the
//     RID in uppercase hex
//   - ...\<RID>\V                      the variable-length record: a
//     table of (offset,length) pairs at the front, string and hash data
//     from 0xCC onward
//   - ...\<RID>\F                      the fixed 80-byte account record:
//     timestamps, RID, account-control flags, logon counters
//   - ...\Users\Names\<name>           one key per account name, whose
//     default value's TYPE field carries the RID
//
// Every offset used here is from the published SAM layout (MS-SAMR
// section 2.2.11 for the key derivation and hash wrapping, and the
// long-established public description of the V and F records). Nothing
// is guessed: a field this package is not confident it can decode is
// left unset rather than filled with a plausible-looking value, because
// a wrong username or a wrong hash in a report is worse than a missing
// one.
package sam

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"tracefall/internal/regf"
)

// Registry paths. The SAM hive's own root is "SAM", so a key path
// relative to the hive root repeats it once -- that is the file's real
// shape, not a mistake.
const (
	accountKey  = `SAM\Domains\Account`
	usersKey    = `SAM\Domains\Account\Users`
	namesKey    = `SAM\Domains\Account\Users\Names`
	lsaKeyFmt   = `ControlSet%03d\Control\Lsa\%s`
	selectKey   = `Select`
	maxAccounts = 100_000 // a bound, not an expectation; see Accounts
)

// ErrNotSAM reports that a hive is a valid registry hive but is not a
// SAM: it does not hold the account structures. Used by detection, which
// must be able to tell "this is a SAM" from "this is some other hive"
// without relying on the filename.
var ErrNotSAM = errors.New("sam: hive does not contain SAM account structures")

// HashStatus says what happened to an account's NTLM hash. It exists so
// "no hash" is never silently indistinguishable from "hash not looked
// for" -- an analyst reading a report has to be able to tell why a hash
// column is empty.
type HashStatus string

const (
	// HashDecoded means an NTLM hash was decoded from the hive. The
	// underlying material was encrypted; it has been unwrapped with keys
	// that were themselves in the evidence.
	HashDecoded HashStatus = "decoded"

	// HashNotStored means the account record explicitly carries no NT
	// hash. Commonly this means no password is set.
	//
	// Distinct from every "encrypted" status below, and the distinction
	// is the whole point: "there is nothing here" and "there is
	// something here that could not be read" are different findings.
	//
	// Tools that print 31d6cfe0d16ae931b73c59d7e0c089c0 in this case are
	// printing the NTLM hash of the EMPTY STRING as a convention. That
	// value is not stored in the hive and this package never emits it:
	// it would be an inference presented as a reading.
	HashNotStored HashStatus = "not_stored"

	// HashEncryptedSystemMissing means the hash IS present and IS
	// readable, and is still encrypted because no SYSTEM hive was
	// available to supply the machine boot key.
	//
	// Never describe this as "not available" on its own. The material
	// exists; what is missing is a second piece of evidence, and telling
	// an analyst to go and collect it is actionable in a way that "not
	// available" is not.
	HashEncryptedSystemMissing HashStatus = "encrypted_system_hive_missing"

	// HashEncryptedSystemUnusable means a SYSTEM hive was found and
	// could not yield a usable boot key -- corrupt, truncated, missing
	// its SysKey class names, or carrying a key this SAM rejects.
	// Separated from the missing case because the remedy differs: one
	// says "collect SYSTEM", the other says "the SYSTEM you collected
	// will not do".
	HashEncryptedSystemUnusable HashStatus = "encrypted_system_hive_unusable"

	// HashEncryptedDataUnavailable means the wrapped hash itself could
	// not be read out of the account record -- the entry points outside
	// the record, or the record is truncated across it.
	HashEncryptedDataUnavailable HashStatus = "encrypted_data_unavailable"

	// HashUnsupported means the wrapping is a shape this package does
	// not decode. Reported rather than guessed at.
	HashUnsupported HashStatus = "unsupported"
)

// Encrypted reports whether the hash material EXISTS in the hive but
// could not be decoded. Used by presentation layers so an encrypted
// hash is never worded as though the account had none.
func (h HashStatus) Encrypted() bool {
	switch h {
	case HashEncryptedSystemMissing, HashEncryptedSystemUnusable,
		HashEncryptedDataUnavailable, HashUnsupported:
		return true
	}
	return false
}

// BootKeyStatus says what happened when a boot key was sought.
type BootKeyStatus string

const (
	// BootKeyDerived means a 16-byte machine boot key was obtained.
	BootKeyDerived BootKeyStatus = "derived"
	// BootKeyNoSystemHive means no SYSTEM hive was available at all.
	BootKeyNoSystemHive BootKeyStatus = "system_hive_missing"
	// BootKeyUnusable means a SYSTEM hive was found but could not
	// yield a key. Reason carries the specifics.
	BootKeyUnusable BootKeyStatus = "system_hive_unusable"
)

// BootKeyResult is a boot-key derivation attempt, successful or not.
// It travels as one value so a caller can never end up holding a key
// without also holding where it came from, or a failure without a
// reason.
type BootKeyResult struct {
	Key    []byte
	Status BootKeyStatus
	// Source is the evidence path of the SYSTEM hive the key came from.
	Source string
	// SourceSHA256 is that file's hash, so provenance can name the
	// cryptographic dependency exactly.
	SourceSHA256 string
	// ControlSet is the numbered control set the key was read from.
	ControlSet int
	// Reason explains a non-derived status in a sentence.
	Reason string
}

// OK reports whether a usable key was derived.
func (r BootKeyResult) OK() bool { return r.Status == BootKeyDerived && len(r.Key) == 16 }

// Account is one local account read out of a SAM hive.
type Account struct {
	RID      uint32
	Username string
	FullName string
	Comment  string

	// NTLMHash is 32 lowercase hex characters, or "" when HashStatus is
	// anything other than HashDecoded. It is a PASSWORD HASH. It is not
	// a password, and it is not reversible into one.
	NTLMHash   string
	HashStatus HashStatus
	// HashNote explains a non-present status in a sentence an analyst
	// can put in a report.
	HashNote string
	// HashFormat is the wrapping the hive used: "rc4" (pre-1607) or
	// "aes" (Windows 10 1607 and later). Empty when there was no hash
	// blob to classify.
	HashFormat string

	// ACBFlags is the raw account-control word; ACBNames is its decoded
	// form. Both are reported: the names are for reading, the raw value
	// is so nothing is lost if a bit is one this package has no name for.
	ACBFlags uint16
	ACBNames []string
	Disabled bool

	// Timestamps. Each is zero when the record stores zero, which for
	// these fields is Windows' way of saying "never" -- not "unknown",
	// and never to be replaced by a file or hive mtime.
	LastLogon             time.Time
	LastPasswordSet       time.Time
	LastIncorrectPassword time.Time
	AccountExpires        time.Time
	// KeyLastWrite is the RID key's own last-write time. It is metadata
	// ABOUT the record, not an account event, and is labelled that way
	// wherever it surfaces.
	KeyLastWrite time.Time

	LoginCount       uint16
	FailedLoginCount uint16
}

// Result is everything one SAM hive yielded.
type Result struct {
	Accounts []Account
	// BootKey records the cryptographic dependency: which SYSTEM hive
	// supplied the machine boot key, or why none did. Carried on the
	// result so provenance can name the second piece of evidence a
	// decoded hash stands on.
	BootKey BootKeyResult
	// HashesDecodable is false when no usable boot key was available,
	// which makes every present hash encrypted rather than decoded.
	HashesDecodable bool
	// Truncated reports that maxAccounts stopped enumeration.
	Truncated bool
}

// Detect reports whether an open hive is a SAM, by looking for the
// account structures rather than at any filename. A renamed SAM passes;
// a SOFTWARE hive, an NTUSER.DAT, and a text file called "SAM" do not.
func Detect(h *regf.Hive) bool {
	if _, err := h.OpenKey(usersKey); err != nil {
		return false
	}
	// Users alone is not enough: the domain record has to be there too,
	// or this is not a SAM whose accounts can be read.
	_, err := h.OpenKey(accountKey)
	return err == nil
}

// ---------------- Boot key (SysKey) ----------------

// bootKeyTransform is the fixed permutation Windows applies to the 16
// bytes assembled from the four Lsa class names. Published as part of
// the long-documented SysKey scheme.
var bootKeyTransform = [16]int{8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7}

var lsaKeyNames = [4]string{"JD", "Skew1", "GBG", "Data"}

// DetectSystem reports whether an open hive is a SYSTEM hive capable of
// supplying a boot key.
//
// Structural, never by filename: a renamed SYSTEM hive passes, and a
// SOFTWARE hive, an NTUSER.DAT or a hive merely CALLED SYSTEM does not.
// The test is the thing that matters -- Select\Current names a control
// set, and that control set's four Lsa keys carry class names. A hive
// that has those IS the SYSTEM hive for this machine in every sense
// this package needs; one that does not cannot supply a key however it
// is named.
func DetectSystem(h *regf.Hive) bool {
	return BootKey(h).OK()
}

// BootKey extracts the machine boot key from an open SYSTEM hive.
//
// The key is not stored as a value. Each of four subkeys under
// Control\Lsa carries eight hex digits as its CLASS NAME -- a field
// almost nothing else in the registry uses, which is precisely why it
// was chosen. The 32 digits are concatenated in a fixed key order,
// decoded, and permuted.
//
// Every failure returns a REASON rather than a bare error, because the
// reason is what an analyst acts on: "this SYSTEM hive is truncated" and
// "this hive is not a SYSTEM hive" call for different next steps.
func BootKey(system *regf.Hive) BootKeyResult {
	fail := func(format string, args ...any) BootKeyResult {
		return BootKeyResult{Status: BootKeyUnusable, Reason: fmt.Sprintf(format, args...)}
	}

	set, err := currentControlSet(system)
	if err != nil {
		return fail("%s", err.Error())
	}

	var digits strings.Builder
	for _, name := range lsaKeyNames {
		path := fmt.Sprintf(lsaKeyFmt, set, name)
		k, kerr := system.OpenKey(path)
		if kerr != nil {
			return fail("this hive has no %s key; it is either not a SYSTEM hive or is damaged across the "+
				"SysKey structures", path)
		}
		class := k.Class
		if len(class) < 8 {
			return fail("%s carries no SysKey class name. A SYSTEM hive from a machine using a SysKey "+
				"startup password, or one whose class-name cells are damaged, cannot supply a boot key", path)
		}
		digits.WriteString(class[:8])
	}

	scrambled, derr := hex.DecodeString(digits.String())
	if derr != nil || len(scrambled) != 16 {
		return fail("the four SysKey class names are not 32 hexadecimal digits, so this hive cannot supply " +
			"a boot key")
	}
	out := make([]byte, 16)
	for i, from := range bootKeyTransform {
		out[i] = scrambled[from]
	}
	return BootKeyResult{Key: out, Status: BootKeyDerived, ControlSet: set}
}

// currentControlSet reads HKLM\SYSTEM\Select\Current, which says which
// numbered control set is the live one. Guessed at nowhere: if Select is
// unreadable the caller is told, rather than ControlSet001 being assumed
// -- a machine whose current set is 002 would otherwise have its boot
// key read from a stale one.
func currentControlSet(system *regf.Hive) (int, error) {
	k, err := system.OpenKey(selectKey)
	if err != nil {
		return 0, errors.New("this hive has no Select key, so it is not a SYSTEM hive")
	}
	for _, v := range k.Values {
		if !strings.EqualFold(v.Name, "Current") || len(v.Data) < 4 {
			continue
		}
		n := int(binary.LittleEndian.Uint32(v.Data[:4]))
		if n <= 0 || n > 999 {
			return 0, fmt.Errorf("Select\\Current is %d, which is not a control set number", n)
		}
		return n, nil
	}
	return 0, errors.New("Select\\Current is not present, so the live control set cannot be identified")
}

// ---------------- Hashed boot key (the domain PEK) ----------------

var (
	qwertyConst = []byte("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\x00")
	digitsConst = []byte("0123456789012345678901234567890123456789\x00")
	ntPassword  = []byte("NTPASSWORD\x00")
)

// hashedBootKey unwraps the domain Password Encryption Key held in
// SAM\Domains\Account's F value at offset 0x68. Two wrappings exist: an
// AES one (revision 2, Windows 10 1607 and later) and an RC4/MD5 one
// (revision 1). Both are decoded; anything else is refused.
func hashedBootKey(sam *regf.Hive, bootKey []byte) ([]byte, string, error) {
	k, err := sam.OpenKey(accountKey)
	if err != nil {
		return nil, "", fmt.Errorf("sam: %w", err)
	}
	f := valueData(k, "F")
	const keyOffset = 0x68
	if len(f) < keyOffset+8 {
		return nil, "", errors.New("sam: domain F record is too short to hold a password encryption key")
	}
	blob := f[keyOffset:]
	revision := binary.LittleEndian.Uint32(blob[0:4])

	switch revision {
	case 2:
		// SAM_KEY_DATA_AES: revision, length, checksum length, data
		// length, 16-byte salt, then the wrapped key.
		if len(blob) < 32 {
			return nil, "", errors.New("sam: AES password encryption key record is truncated")
		}
		dataLen := int(binary.LittleEndian.Uint32(blob[12:16]))
		salt := blob[16:32]
		data := blob[32:]
		if dataLen < 0 || dataLen > len(data) {
			return nil, "", errors.New("sam: AES password encryption key claims more data than it holds")
		}
		out, err := aesCBCDecrypt(bootKey, data[:dataLen], salt)
		if err != nil {
			return nil, "", fmt.Errorf("sam: unwrapping AES password encryption key: %w", err)
		}
		if len(out) < 16 {
			return nil, "", errors.New("sam: unwrapped AES password encryption key is too short")
		}
		return out[:16], "aes", nil

	case 1:
		// SAM_KEY_DATA: revision, length, 16-byte salt, 16-byte key,
		// 16-byte checksum. The checksum is verified, because a wrong
		// key here silently produces wrong hashes for every account --
		// which is exactly the failure that must never be reported as a
		// success.
		if len(blob) < 8+16+16+16 {
			return nil, "", errors.New("sam: RC4 password encryption key record is truncated")
		}
		salt := blob[8:24]
		wrapped := blob[24:56] // key + checksum
		sum := md5.Sum(concat(salt, qwertyConst, bootKey, digitsConst))
		c, err := rc4.NewCipher(sum[:])
		if err != nil {
			return nil, "", fmt.Errorf("sam: %w", err)
		}
		out := make([]byte, 32)
		c.XORKeyStream(out, wrapped)
		check := md5.Sum(concat(out[:16], digitsConst, out[:16], qwertyConst))
		if !bytes.Equal(check[:], out[16:]) {
			return nil, "", errors.New("sam: password encryption key checksum failed; " +
				"the boot key does not match this SAM (a SysKey startup password may be in use)")
		}
		return out[:16], "rc4", nil

	default:
		return nil, "", fmt.Errorf("sam: password encryption key revision %d is not a format this reader decodes", revision)
	}
}

// ---------------- Accounts ----------------

// Accounts reads every local account in the hive.
//
// boot may be a zero/failed BootKeyResult, in which case names, RIDs,
// flags and timestamps are still returned and every present hash is
// marked encrypted with the reason attached -- the SAM alone cannot
// yield one, and that is a property of the format rather than of this
// reader.
func Accounts(sam *regf.Hive, boot BootKeyResult) (Result, error) {
	if !Detect(sam) {
		return Result{}, ErrNotSAM
	}

	var res Result
	res.BootKey = boot
	if res.BootKey.Status == "" {
		// A caller that supplied no result at all is saying there was no
		// SYSTEM hive. Made explicit here so no code path can produce an
		// account whose hash status has no stated reason.
		res.BootKey.Status = BootKeyNoSystemHive
		if res.BootKey.Reason == "" {
			res.BootKey.Reason = "no SYSTEM hive was available in this evidence."
		}
	}

	// The domain password encryption key is unwrapped ONCE per hive, not
	// once per account: it is a property of the SAM, and every account's
	// hash is wrapped under the same one.
	var pek []byte
	var pekFormat string
	if boot.OK() {
		var err error
		pek, pekFormat, err = hashedBootKey(sam, boot.Key)
		if err != nil {
			// A boot key that does not fit this SAM. The hive was found
			// and read; it is the wrong one, or a SysKey startup
			// password is in use. That is "unusable", not "missing".
			res.BootKey.Status = BootKeyUnusable
			res.BootKey.Reason = err.Error()
		} else {
			res.HashesDecodable = true
		}
	}

	ridToName := accountNames(sam)

	// ChildKeys is a single-pass enumeration (added in an earlier phase
	// for exactly this reason): the obvious Subkeys-then-OpenKey-each
	// shape re-walks the subkey list once per child and turns a hive
	// with many accounts into quadratic work.
	kids, err := sam.ChildKeys(usersKey)
	if err != nil {
		return Result{}, fmt.Errorf("sam: enumerating accounts: %w", err)
	}

	for _, k := range kids {
		if len(res.Accounts) >= maxAccounts {
			res.Truncated = true
			break
		}
		// "Names" is a sibling index, not an account.
		if strings.EqualFold(k.Name, "Names") {
			continue
		}
		rid, ok := ridFromKeyName(k.Name)
		if !ok {
			continue
		}
		acct, ok := decodeAccount(k, rid, pek, pekFormat, res.BootKey)
		if !ok {
			continue
		}
		if acct.Username == "" {
			// The V record's name field failed, but the Names index may
			// still know it. Used only as a fallback, never to override.
			acct.Username = ridToName[rid]
		}
		res.Accounts = append(res.Accounts, acct)
	}

	sort.Slice(res.Accounts, func(i, j int) bool { return res.Accounts[i].RID < res.Accounts[j].RID })
	return res, nil
}

// accountNames reads the Names index, whose subkey NAME is the account
// name and whose default value's TYPE field -- not its data -- carries
// the RID. An odd encoding, but a documented and stable one.
func accountNames(sam *regf.Hive) map[uint32]string {
	out := map[uint32]string{}
	kids, err := sam.ChildKeys(namesKey)
	if err != nil {
		return out
	}
	for _, k := range kids {
		for _, v := range k.Values {
			if v.Name == "" && v.Type > 0 {
				out[v.Type] = k.Name
				break
			}
		}
	}
	return out
}

// ridFromKeyName parses the RID out of a Users subkey name, which
// Windows writes as eight uppercase hex digits.
func ridFromKeyName(name string) (uint32, bool) {
	if len(name) != 8 {
		return 0, false
	}
	n, err := strconv.ParseUint(name, 16, 32)
	if err != nil {
		return 0, false
	}
	return uint32(n), true
}

// V record: a table of 4-byte (offset, length) pairs at the front, with
// every offset relative to the start of the data area at 0xCC.
const (
	vDataStart      = 0xCC
	vNameOffset     = 0x0C
	vFullNameOffset = 0x18
	vCommentOffset  = 0x24
	vNTHashOffset   = 0xA8
)

// F record offsets. The RID at 0x30 is cross-checked against the key
// name rather than trusted on its own.
const (
	fLastLogon             = 0x08
	fLastPasswordSet       = 0x18
	fAccountExpires        = 0x20
	fLastIncorrectPassword = 0x28
	fRID                   = 0x30
	fACBFlags              = 0x38
	fFailedLoginCount      = 0x40
	fLoginCount            = 0x42
	fSize                  = 0x44
)

func decodeAccount(k regf.Key, rid uint32, pek []byte, pekFormat string, boot BootKeyResult) (Account, bool) {
	v := valueData(k, "V")
	if len(v) < vDataStart {
		return Account{}, false
	}
	acct := Account{RID: rid, KeyLastWrite: k.LastWrite}
	data := v[vDataStart:]

	acct.Username = vString(v, data, vNameOffset)
	acct.FullName = vString(v, data, vFullNameOffset)
	acct.Comment = vString(v, data, vCommentOffset)

	decodeF(&acct, valueData(k, "F"), rid)
	decodeHash(&acct, v, data, pek, pekFormat, boot)
	return acct, true
}

// vString reads one length-prefixed UTF-16 field out of the V record.
// An entry whose offset or length runs past the record is treated as
// absent -- a truncated or hostile V must not be able to read outside
// its own bytes, and half a name is not a name.
func vString(v, data []byte, entry int) string {
	if entry+8 > len(v) {
		return ""
	}
	off := int(binary.LittleEndian.Uint32(v[entry : entry+4]))
	length := int(binary.LittleEndian.Uint32(v[entry+4 : entry+8]))
	if length <= 0 || off < 0 || off > len(data) || length > len(data)-off {
		return ""
	}
	return utf16LE(data[off : off+length])
}

func decodeF(acct *Account, f []byte, keyRID uint32) {
	if len(f) < fSize {
		return
	}
	acct.LastLogon = fileTime(binary.LittleEndian.Uint64(f[fLastLogon:]))
	acct.LastPasswordSet = fileTime(binary.LittleEndian.Uint64(f[fLastPasswordSet:]))
	acct.AccountExpires = fileTime(binary.LittleEndian.Uint64(f[fAccountExpires:]))
	acct.LastIncorrectPassword = fileTime(binary.LittleEndian.Uint64(f[fLastIncorrectPassword:]))

	// The F record repeats the RID the key name already gave. They are
	// compared rather than one being preferred: if they disagree the
	// record is not what this reader thinks it is, so the flags and
	// counters that share it are left unset instead of being reported
	// with false confidence.
	if binary.LittleEndian.Uint32(f[fRID:]) != keyRID {
		return
	}
	acct.ACBFlags = binary.LittleEndian.Uint16(f[fACBFlags:])
	acct.ACBNames = acbNames(acct.ACBFlags)
	acct.Disabled = acct.ACBFlags&acbDisabled != 0
	acct.FailedLoginCount = binary.LittleEndian.Uint16(f[fFailedLoginCount:])
	acct.LoginCount = binary.LittleEndian.Uint16(f[fLoginCount:])
}

// decodeHash unwraps the stored NT hash, or records exactly why it could
// not. It never substitutes a value.
func decodeHash(acct *Account, v, data []byte, pek []byte, pekFormat string, boot BootKeyResult) {
	if vNTHashOffset+8 > len(v) {
		acct.HashStatus = HashEncryptedDataUnavailable
		acct.HashNote = "this account record is too short to hold an NT hash entry, so whether a hash is " +
			"stored cannot be determined from it"
		return
	}
	off := int(binary.LittleEndian.Uint32(v[vNTHashOffset:]))
	length := int(binary.LittleEndian.Uint32(v[vNTHashOffset+4:]))
	if length == 0 {
		acct.HashStatus = HashNotStored
		acct.HashNote = noHashNote
		return
	}
	if off < 0 || off > len(data) || length > len(data)-off {
		acct.HashStatus = HashEncryptedDataUnavailable
		acct.HashNote = "this account record says it holds an NT hash, but the entry points outside the " +
			"record. The hash material cannot be read; no value is guessed at"
		return
	}
	blob := data[off : off+length]

	// The wrapping is told apart by the header, not by the hive's
	// version: a 4-byte little-endian 0x14 introduces the old RC4 form.
	newStyle := !(len(blob) >= 4 && blob[0] == 0x14 && blob[1] == 0 && blob[2] == 0 && blob[3] == 0)
	if newStyle {
		acct.HashFormat = "aes"
	} else {
		acct.HashFormat = "rc4"
	}

	// A blob carrying only its header and salt is an account with no
	// stored hash, whatever its length field says.
	if (newStyle && length <= 24) || (!newStyle && length < 20) {
		acct.HashStatus = HashNotStored
		acct.HashNote = noHashNote
		return
	}

	// From here the hash material EXISTS and is readable. Everything
	// below is "encrypted and could not be decoded", never "no hash".
	if len(pek) == 0 {
		switch boot.Status {
		case BootKeyNoSystemHive:
			acct.HashStatus = HashEncryptedSystemMissing
			acct.HashNote = "This account's NT hash is present in the SAM and is still encrypted. Decoding it " +
				"needs the machine boot key, which lives in the SYSTEM hive and not in the SAM. " +
				"Collect Windows\\System32\\config\\SYSTEM from the same machine to decode it."
		default:
			acct.HashStatus = HashEncryptedSystemUnusable
			acct.HashNote = "This account's NT hash is present in the SAM and is still encrypted. A SYSTEM " +
				"hive was found but could not supply a usable boot key."
		}
		if boot.Reason != "" {
			acct.HashNote += " " + boot.Reason
		}
		return
	}

	raw, err := unwrapHash(blob, pek, acct.RID, newStyle)
	if err != nil {
		acct.HashStatus = HashUnsupported
		acct.HashNote = "This account's NT hash is present in the SAM and is still encrypted. " + err.Error()
		return
	}
	acct.NTLMHash = hex.EncodeToString(raw)
	acct.HashStatus = HashDecoded
	acct.HashNote = ""
	_ = pekFormat
}

const noHashNote = "this account record stores no NT hash, which normally means no password is set. " +
	"No hash value is reported: the constant some tools print here is the NTLM hash of the empty " +
	"string, which is a convention rather than a value read from this hive"

// unwrapHash removes the two layers Windows puts around a stored NT
// hash: the domain key layer (AES-CBC on modern systems, RC4 on older
// ones) and then the per-account DES layer keyed on the RID.
func unwrapHash(blob, pek []byte, rid uint32, newStyle bool) ([]byte, error) {
	var inner []byte
	if newStyle {
		// SAM_HASH_AES: PEKID(2) Revision(2) DataOffset(4) Salt(16)
		// Hash(...). The salt starts at 8, NOT at 16 -- the domain key
		// record two fields up has a different shape and its salt IS at
		// 16, which is exactly the confusion the round-trip fixture
		// exists to catch. Getting this wrong yields 16 plausible-looking
		// bytes rather than an error.
		if len(blob) < 24+16 {
			return nil, errors.New("the AES-wrapped NT hash record is too short to decode")
		}
		out, err := aesCBCDecrypt(pek, blob[24:], blob[8:24])
		if err != nil {
			return nil, fmt.Errorf("unwrapping the AES-wrapped NT hash: %w", err)
		}
		if len(out) < 16 {
			return nil, errors.New("the unwrapped NT hash is shorter than 16 bytes")
		}
		inner = out[:16]
	} else {
		// PEKID(2) Revision(2) Hash(16)
		if len(blob) < 20 {
			return nil, errors.New("the RC4-wrapped NT hash record is too short to decode")
		}
		var ridLE [4]byte
		binary.LittleEndian.PutUint32(ridLE[:], rid)
		sum := md5.Sum(concat(pek[:16], ridLE[:], ntPassword))
		c, err := rc4.NewCipher(sum[:])
		if err != nil {
			return nil, err
		}
		inner = make([]byte, 16)
		c.XORKeyStream(inner, blob[4:20])
	}
	return desUnwrap(inner, rid)
}

// desUnwrap removes the per-account layer. MS-SAMR 2.2.11.1.3 derives
// two 7-byte DES keys from the RID; each half of the hash is decrypted
// under one of them.
func desUnwrap(inner []byte, rid uint32) ([]byte, error) {
	if len(inner) != 16 {
		return nil, errors.New("the NT hash is not 16 bytes")
	}
	k1, k2 := deriveDESKeys(rid)
	c1, err := des.NewCipher(k1)
	if err != nil {
		return nil, err
	}
	c2, err := des.NewCipher(k2)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 16)
	c1.Decrypt(out[0:8], inner[0:8])
	c2.Decrypt(out[8:16], inner[8:16])
	return out, nil
}

// deriveDESKeys is MS-SAMR 2.2.11.1.3: the RID's four little-endian
// bytes are dealt into two 7-byte patterns, each expanded to a parity-
// bearing 8-byte DES key.
func deriveDESKeys(rid uint32) ([]byte, []byte) {
	var r [4]byte
	binary.LittleEndian.PutUint32(r[:], rid)
	a := []byte{r[0], r[1], r[2], r[3], r[0], r[1], r[2]}
	b := []byte{r[3], r[0], r[1], r[2], r[3], r[0], r[1]}
	return expandDESKey(a), expandDESKey(b)
}

// expandDESKey turns 7 key bytes into the 8 bytes DES wants, shifting
// each byte left one bit to leave room for the (ignored) parity bit.
func expandDESKey(k []byte) []byte {
	out := make([]byte, 8)
	out[0] = k[0] >> 1
	out[1] = ((k[0] & 0x01) << 6) | (k[1] >> 2)
	out[2] = ((k[1] & 0x03) << 5) | (k[2] >> 3)
	out[3] = ((k[2] & 0x07) << 4) | (k[3] >> 4)
	out[4] = ((k[3] & 0x0f) << 3) | (k[4] >> 5)
	out[5] = ((k[4] & 0x1f) << 2) | (k[5] >> 6)
	out[6] = ((k[5] & 0x3f) << 1) | (k[6] >> 7)
	out[7] = k[6] & 0x7f
	for i := range out {
		out[i] <<= 1
	}
	return out
}

// aesCBCDecrypt decrypts whole blocks only. The trailing partial block a
// SAM record often carries is not padding to be stripped, it is simply
// not part of the ciphertext, so it is dropped rather than guessed at.
func aesCBCDecrypt(key, data, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != aes.BlockSize {
		return nil, errors.New("initialisation vector is not one AES block")
	}
	n := len(data) - len(data)%aes.BlockSize
	if n == 0 {
		return nil, errors.New("no complete AES block to decrypt")
	}
	out := make([]byte, n)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data[:n])
	return out, nil
}

// ---------------- Account control flags ----------------

const acbDisabled = 0x0001

var acbFlagNames = []struct {
	bit  uint16
	name string
}{
	{0x0001, "account_disabled"},
	{0x0002, "home_directory_required"},
	{0x0004, "password_not_required"},
	{0x0008, "temporary_duplicate_account"},
	{0x0010, "normal_account"},
	{0x0020, "mns_logon_account"},
	{0x0040, "interdomain_trust_account"},
	{0x0080, "workstation_trust_account"},
	{0x0100, "server_trust_account"},
	{0x0200, "password_does_not_expire"},
	{0x0400, "account_auto_locked"},
	{0x0800, "encrypted_text_password_allowed"},
	{0x1000, "smartcard_required"},
	{0x2000, "trusted_for_delegation"},
	{0x4000, "not_delegated"},
	{0x8000, "use_des_key_only"},
}

func acbNames(flags uint16) []string {
	var out []string
	for _, f := range acbFlagNames {
		if flags&f.bit != 0 {
			out = append(out, f.name)
		}
	}
	return out
}

// ---------------- small helpers ----------------

func valueData(k regf.Key, name string) []byte {
	for _, v := range k.Values {
		if strings.EqualFold(v.Name, name) {
			return v.Data
		}
	}
	return nil
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func utf16LE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return strings.TrimRight(string(utf16.Decode(u)), "\x00")
}

// epochDelta is the gap between the FILETIME epoch (1601) and Unix.
const epochDelta = 11644473600

// fileTime converts a Windows FILETIME. Zero means "never" and stays
// zero: it must never become a real-looking timestamp, and it must never
// be filled in from a file or hive modification time.
func fileTime(ft uint64) time.Time {
	if ft == 0 || ft == 0x7FFFFFFFFFFFFFFF {
		return time.Time{}
	}
	secs := int64(ft/10_000_000) - epochDelta
	// The same plausibility window the other native readers use. A value
	// outside it is a misread field, not a date.
	if secs < -2208988800 || secs > 7258118400 {
		return time.Time{}
	}
	return time.Unix(secs, int64(ft%10_000_000)*100).UTC()
}
