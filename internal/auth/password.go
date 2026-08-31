// Package auth holds Tracefall's password hashing and session-token
// primitives.
//
// It deliberately depends on nothing outside the standard library.
// Tracefall is deployed as a single self-contained binary into
// environments that may have no package mirror and no outbound network,
// and a credential-handling dependency is the last place to accept a
// supply-chain risk for convenience.
package auth

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Password hashing uses PBKDF2-HMAC-SHA256.
//
// # Why PBKDF2 and not bcrypt/scrypt/argon2
//
// Those three live in golang.org/x/crypto, which Tracefall does not
// depend on. PBKDF2 entered the Go standard library in 1.24, is
// standardized (RFC 8018, NIST SP 800-132) and remains an approved
// password KDF. It is memory-cheap, which is a genuine weakness against
// a GPU attacker compared with argon2id -- accepted deliberately here,
// because the alternative is adding a dependency to a forensic tool that
// must build and audit as a closed set. If Tracefall ever vendors
// x/crypto for another reason, argon2id is the upgrade, and the stored
// format below carries an algorithm tag precisely so that migration does
// not need a flag day.
const (
	// pbkdf2Iterations is deliberately high. Login happens rarely and
	// interactively; a few hundred milliseconds is invisible to the
	// analyst and expensive for an attacker with the database.
	pbkdf2Iterations = 600_000
	saltBytes        = 16
	keyBytes         = 32
	algoPBKDF2SHA256 = "pbkdf2-sha256"
)

// ErrInvalidHash means a stored hash is not in a format this build can
// verify -- corrupt, truncated, or written by a future algorithm.
var ErrInvalidHash = errors.New("auth: stored password hash is not in a recognized format")

// HashPassword returns an encoded hash of password.
//
// The encoding is self-describing: algorithm, iteration count, salt and
// key, so a future build can verify an old hash and re-hash it on the
// next successful login without a migration.
//
//	pbkdf2-sha256$600000$<base64 salt>$<base64 key>
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: generating salt: %w", err)
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iterations, keyBytes)
	if err != nil {
		return "", fmt.Errorf("auth: deriving key: %w", err)
	}
	return strings.Join([]string{
		algoPBKDF2SHA256,
		strconv.Itoa(pbkdf2Iterations),
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	}, "$"), nil
}

// VerifyPassword reports whether password matches encoded.
//
// The comparison is constant-time. An error is returned only for a hash
// this build cannot parse -- a wrong password is (false, nil), so a
// caller cannot accidentally treat "bad password" as "system error" and
// log or surface them differently.
func VerifyPassword(encoded, password string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != algoPBKDF2SHA256 {
		return false, ErrInvalidHash
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 {
		return false, ErrInvalidHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false, ErrInvalidHash
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false, ErrInvalidHash
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
	if err != nil {
		return false, ErrInvalidHash
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// NewSessionToken returns a cryptographically random session token.
//
// 32 bytes from crypto/rand: not guessable, and never derived from the
// username, time, or any other value an attacker can influence or
// observe.
func NewSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: generating session token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashSessionToken returns the value STORED for a session token.
//
// The database holds only this hash. A stolen database therefore yields
// no usable session cookies -- the same reasoning that keeps passwords
// out of the database, applied to the credential that stands in for one.
//
// A plain SHA-256 is correct here and PBKDF2 would be wrong: the token
// is 256 bits of uniform randomness, so there is no low-entropy secret
// to protect against brute force, and a slow hash on every authenticated
// request would be a self-inflicted denial of service.
func HashSessionToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawStdEncoding.EncodeToString(sum[:])
}
