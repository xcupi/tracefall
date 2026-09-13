// Package samgen builds synthetic Windows SAM and SYSTEM hives in
// memory, for TEST FIXTURES ONLY.
//
// A real SAM names real people and carries real credential material, so
// one can never be committed to a repository. Every account, RID, hash
// and boot key produced here is invented.
//
// It is also the reader's real check. The generator WRAPS a hash the
// test chose, following the published layout in the encoding direction;
// internal/sam UNWRAPS it in the decoding direction. A round trip that
// returns the exact bytes the test put in exercises the whole chain --
// boot key, domain password encryption key, per-account DES layer --
// and it fails if either direction drifts. Testing the reader against
// its own output would prove nothing, so the two are written from the
// structure definitions independently rather than sharing code.
//
// There is no password anywhere in this package. Hashes are opaque
// 16-byte fixture constants; nothing converts a password into one, and
// nothing converts one back.
//
// It lives outside internal/sam so no production code can import a SAM
// writer by accident: Tracefall must never write a hive.
package samgen

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"
	"unicode/utf16"

	"tracefall/internal/regf/regfgen"
)

// Account describes one account to write into a synthetic SAM.
type Account struct {
	RID      uint32
	Username string
	FullName string
	Comment  string

	// NTLM is the 16-byte hash to store. Nil writes an account record
	// that carries no hash at all, which is what Windows does for an
	// account with no password set.
	NTLM []byte

	ACBFlags              uint16
	LastLogon             time.Time
	LastPasswordSet       time.Time
	LastIncorrectPassword time.Time
	AccountExpires        time.Time
	LoginCount            uint16
	FailedLoginCount      uint16
	KeyLastWrite          time.Time

	// OmitF writes the account with no F record, so the reader's
	// "flags and timestamps unavailable" path can be exercised.
	OmitF bool
	// BadRIDInF writes an F record whose RID disagrees with the key
	// name, which must make the reader distrust that record.
	BadRIDInF bool
	// TruncateV cuts the V record to this many bytes when non-zero.
	TruncateV int
}

// Options controls how a synthetic SAM is built.
type Options struct {
	Accounts []Account
	// BootKey is the 16-byte machine key the hashes are wrapped under.
	// The matching SYSTEM hive is built by SystemHive with the same
	// value. Nil uses DefaultBootKey.
	BootKey []byte
	// Legacy writes the pre-Windows-10-1607 RC4/MD5 wrapping instead of
	// the AES one, so both formats a real reader meets are covered.
	Legacy bool
	// OmitDomainF writes a SAM with no domain record, which is a hive
	// whose hashes cannot be unwrapped at all.
	OmitDomainF bool
	// OmitNamesIndex leaves out the Names index. Names must still come
	// from each account's own V record.
	OmitNamesIndex bool
}

// DefaultBootKey is an arbitrary fixed 16-byte value, so fixtures are
// reproducible byte for byte.
var DefaultBootKey = []byte{
	0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
	0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
}

// pekPlain is the domain password encryption key the generator uses. It
// is wrapped under the boot key in the domain F record exactly as
// Windows wraps it.
var pekPlain = []byte{
	0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18,
	0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90,
}

// pekSalt is the fixed salt/IV for the domain key record.
var pekSalt = []byte{
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
}

// hashSalt is the per-account AES salt. Fixed for reproducibility.
var hashSalt = []byte{
	0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04,
	0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
}

var (
	qwertyConst = []byte("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\x00")
	digitsConst = []byte("0123456789012345678901234567890123456789\x00")
	ntPassword  = []byte("NTPASSWORD\x00")
)

// SAMHive builds a complete synthetic SAM hive.
func SAMHive(opt Options) []byte {
	bootKey := opt.BootKey
	if len(bootKey) == 0 {
		bootKey = DefaultBootKey
	}

	users := regfgen.NewKey("Users")
	names := regfgen.NewKey("Names")

	for _, a := range opt.Accounts {
		v := buildV(a, opt.Legacy)
		if a.TruncateV > 0 && a.TruncateV < len(v) {
			v = v[:a.TruncateV]
		}
		vals := []regfgen.Value{regfgen.BinaryValue("V", v)}
		if !a.OmitF {
			vals = append(vals, regfgen.BinaryValue("F", buildF(a)))
		}
		users.Subkeys = append(users.Subkeys,
			regfgen.NewKey(fmt.Sprintf("%08X", a.RID)).
				WithValues(vals...).
				WithLastWrite(a.KeyLastWrite))

		if !opt.OmitNamesIndex {
			// The Names index stores the RID in the default value's TYPE
			// field, not its data. Odd, but that is the format.
			names.Subkeys = append(names.Subkeys,
				regfgen.NewKey(a.Username).WithValues(regfgen.Value{Name: "", Type: a.RID}))
		}
	}
	if !opt.OmitNamesIndex {
		users.Subkeys = append(users.Subkeys, names)
	}

	account := regfgen.NewKey("Account", users)
	if !opt.OmitDomainF {
		account.WithValues(regfgen.BinaryValue("F", buildDomainF(bootKey, opt.Legacy)))
	}
	root := regfgen.NewKey("ROOT",
		regfgen.NewKey("SAM",
			regfgen.NewKey("Domains", account,
				regfgen.NewKey("Builtin")),
			regfgen.NewKey("RXACT")))
	return regfgen.Build(`\SystemRoot\System32\Config\SAM`, root)
}

// SystemHive builds a synthetic SYSTEM hive carrying bootKey in the four
// Lsa class names, scrambled the way Windows scrambles it.
func SystemHive(bootKey []byte) []byte {
	if len(bootKey) == 0 {
		bootKey = DefaultBootKey
	}
	// The reader un-permutes; the generator permutes, so the two are
	// inverse rather than the same table applied twice.
	transform := [16]int{8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7}
	scrambled := make([]byte, 16)
	for i, from := range transform {
		scrambled[from] = bootKey[i]
	}
	digits := hex.EncodeToString(scrambled)

	lsa := regfgen.NewKey("Lsa",
		regfgen.NewKey("JD").WithClass(digits[0:8]),
		regfgen.NewKey("Skew1").WithClass(digits[8:16]),
		regfgen.NewKey("GBG").WithClass(digits[16:24]),
		regfgen.NewKey("Data").WithClass(digits[24:32]),
	)
	root := regfgen.NewKey("ROOT",
		regfgen.NewKey("Select").WithValues(regfgen.DWordValue("Current", 1)),
		regfgen.NewKey("ControlSet001", regfgen.NewKey("Control", lsa)),
	)
	return regfgen.Build(`\SystemRoot\System32\Config\SYSTEM`, root)
}

// SystemHiveWithoutSysKey builds a SYSTEM hive whose Lsa keys carry no
// class names, so boot-key extraction must fail cleanly rather than
// producing a wrong key.
func SystemHiveWithoutSysKey() []byte {
	lsa := regfgen.NewKey("Lsa",
		regfgen.NewKey("JD"), regfgen.NewKey("Skew1"),
		regfgen.NewKey("GBG"), regfgen.NewKey("Data"))
	root := regfgen.NewKey("ROOT",
		regfgen.NewKey("Select").WithValues(regfgen.DWordValue("Current", 1)),
		regfgen.NewKey("ControlSet001", regfgen.NewKey("Control", lsa)),
	)
	return regfgen.Build(`\SystemRoot\System32\Config\SYSTEM`, root)
}

// NonSAMHive builds a valid registry hive that is NOT a SAM, so
// detection can be shown to reject it on structure rather than name.
func NonSAMHive() []byte {
	root := regfgen.NewKey("ROOT",
		regfgen.NewKey("Microsoft",
			regfgen.NewKey("Windows").WithValues(regfgen.StringValue("Version", "10.0"))))
	return regfgen.Build(`\SystemRoot\System32\Config\SOFTWARE`, root)
}

// ---------------- record building ----------------

const (
	vDataStart      = 0xCC
	vNameOffset     = 0x0C
	vFullNameOffset = 0x18
	vCommentOffset  = 0x24
	vNTHashOffset   = 0xA8
	vLMHashOffset   = 0x9C
)

// buildV assembles the variable-length account record: a header of
// (offset, length) pairs followed by the data they point into.
func buildV(a Account, legacy bool) []byte {
	header := make([]byte, vDataStart)
	var data []byte

	put := func(entry int, blob []byte) {
		binary.LittleEndian.PutUint32(header[entry:], uint32(len(data)))
		binary.LittleEndian.PutUint32(header[entry+4:], uint32(len(blob)))
		data = append(data, blob...)
	}
	put(vNameOffset, utf16LE(a.Username))
	put(vFullNameOffset, utf16LE(a.FullName))
	put(vCommentOffset, utf16LE(a.Comment))
	// No LM hash is ever written: it is obsolete, and this package has
	// no reason to produce one.
	put(vLMHashOffset, nil)
	put(vNTHashOffset, wrapHash(a.NTLM, a.RID, legacy))

	return append(header, data...)
}

// wrapHash produces the stored form of an NT hash: the per-account DES
// layer first, then the domain key layer.
func wrapHash(ntlm []byte, rid uint32, legacy bool) []byte {
	if len(ntlm) != 16 {
		// No hash stored. Windows still writes the header, so the reader
		// meets a real "no hash" record rather than an absent field.
		if legacy {
			return []byte{0x14, 0x00, 0x00, 0x00}
		}
		out := make([]byte, 24)
		binary.LittleEndian.PutUint16(out[0:], 1) // PEKID
		binary.LittleEndian.PutUint16(out[2:], 2) // revision
		binary.LittleEndian.PutUint32(out[4:], 0) // no data
		copy(out[8:24], hashSalt)
		return out
	}

	inner := desWrap(ntlm, rid)

	if legacy {
		var ridLE [4]byte
		binary.LittleEndian.PutUint32(ridLE[:], rid)
		sum := md5.Sum(concat(pekPlain, ridLE[:], ntPassword))
		c, _ := rc4.NewCipher(sum[:])
		enc := make([]byte, 16)
		c.XORKeyStream(enc, inner)
		out := []byte{0x14, 0x00, 0x00, 0x00}
		return append(out, enc...)
	}

	// SAM_HASH_AES: PEKID(2) Revision(2) DataOffset(4) Salt(16) then the
	// ciphertext -- 24 bytes of header, not 32.
	enc := aesCBCEncrypt(pekPlain, pad16(inner), hashSalt)
	out := make([]byte, 24)
	binary.LittleEndian.PutUint16(out[0:], 1)
	binary.LittleEndian.PutUint16(out[2:], 2)
	binary.LittleEndian.PutUint32(out[4:], uint32(len(enc)))
	copy(out[8:24], hashSalt)
	return append(out, enc...)
}

// desWrap is the inverse of the reader's per-account layer.
func desWrap(hash []byte, rid uint32) []byte {
	k1, k2 := deriveDESKeys(rid)
	c1, _ := des.NewCipher(k1)
	c2, _ := des.NewCipher(k2)
	out := make([]byte, 16)
	c1.Encrypt(out[0:8], hash[0:8])
	c2.Encrypt(out[8:16], hash[8:16])
	return out
}

const (
	fLastLogon             = 0x08
	fLastPasswordSet       = 0x18
	fAccountExpires        = 0x20
	fLastIncorrectPassword = 0x28
	fRID                   = 0x30
	fACBFlags              = 0x38
	fFailedLoginCount      = 0x40
	fLoginCount            = 0x42
	fSize                  = 0x50
)

func buildF(a Account) []byte {
	f := make([]byte, fSize)
	binary.LittleEndian.PutUint64(f[fLastLogon:], toFileTime(a.LastLogon))
	binary.LittleEndian.PutUint64(f[fLastPasswordSet:], toFileTime(a.LastPasswordSet))
	binary.LittleEndian.PutUint64(f[fAccountExpires:], toFileTime(a.AccountExpires))
	binary.LittleEndian.PutUint64(f[fLastIncorrectPassword:], toFileTime(a.LastIncorrectPassword))
	rid := a.RID
	if a.BadRIDInF {
		rid = a.RID ^ 0xFFFF
	}
	binary.LittleEndian.PutUint32(f[fRID:], rid)
	binary.LittleEndian.PutUint16(f[fACBFlags:], a.ACBFlags)
	binary.LittleEndian.PutUint16(f[fFailedLoginCount:], a.FailedLoginCount)
	binary.LittleEndian.PutUint16(f[fLoginCount:], a.LoginCount)
	return f
}

// buildDomainF writes the domain record whose offset 0x68 holds the
// password encryption key wrapped under the boot key.
func buildDomainF(bootKey []byte, legacy bool) []byte {
	const keyOffset = 0x68
	f := make([]byte, keyOffset)

	if legacy {
		// SAM_KEY_DATA: revision, length, salt, key, checksum.
		sum := md5.Sum(concat(pekSalt, qwertyConst, bootKey, digitsConst))
		c, _ := rc4.NewCipher(sum[:])
		check := md5.Sum(concat(pekPlain, digitsConst, pekPlain, qwertyConst))
		plain := append(append([]byte{}, pekPlain...), check[:]...)
		enc := make([]byte, 32)
		c.XORKeyStream(enc, plain)

		blob := make([]byte, 8)
		binary.LittleEndian.PutUint32(blob[0:], 1)  // revision
		binary.LittleEndian.PutUint32(blob[4:], 56) // length
		blob = append(blob, pekSalt...)
		blob = append(blob, enc...)
		return append(f, blob...)
	}

	// SAM_KEY_DATA_AES: revision, length, checksum length, data length,
	// salt, wrapped key.
	enc := aesCBCEncrypt(bootKey, pad16(pekPlain), pekSalt)
	blob := make([]byte, 16)
	binary.LittleEndian.PutUint32(blob[0:], 2) // revision
	binary.LittleEndian.PutUint32(blob[4:], uint32(16+len(enc)))
	binary.LittleEndian.PutUint32(blob[8:], 0)
	binary.LittleEndian.PutUint32(blob[12:], uint32(len(enc)))
	blob = append(blob, pekSalt...)
	blob = append(blob, enc...)
	return append(f, blob...)
}

// ---------------- crypto helpers (encode direction) ----------------

func aesCBCEncrypt(key, data, iv []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	out := make([]byte, len(data))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, data)
	return out
}

// pad16 extends to a whole AES block with zeroes. The reader deliberately
// does not strip padding -- it takes the first 16 bytes -- so the trailing
// block is inert either way.
func pad16(b []byte) []byte {
	if len(b)%16 == 0 {
		return b
	}
	out := make([]byte, len(b)+(16-len(b)%16))
	copy(out, b)
	return out
}

func deriveDESKeys(rid uint32) ([]byte, []byte) {
	var r [4]byte
	binary.LittleEndian.PutUint32(r[:], rid)
	a := []byte{r[0], r[1], r[2], r[3], r[0], r[1], r[2]}
	b := []byte{r[3], r[0], r[1], r[2], r[3], r[0], r[1]}
	return expandDESKey(a), expandDESKey(b)
}

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

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func utf16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[i*2:], c)
	}
	return b
}

const epochDelta = 11644473600

func toFileTime(t time.Time) uint64 {
	if t.IsZero() {
		return 0
	}
	return uint64((t.Unix()+epochDelta)*10_000_000) + uint64(t.Nanosecond()/100)
}

// Truncate cuts a hive to n bytes, for boundary tests.
func Truncate(hive []byte, n int) []byte {
	if n >= len(hive) {
		return hive
	}
	out := make([]byte, n)
	copy(out, hive)
	return out
}

// Corrupt flips the bytes at off, for tests that must show a damaged
// hive is refused rather than half-read.
func Corrupt(hive []byte, off int, b ...byte) []byte {
	out := make([]byte, len(hive))
	copy(out, hive)
	for i, v := range b {
		if off+i < len(out) {
			out[off+i] = v
		}
	}
	return out
}
