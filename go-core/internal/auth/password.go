// Package auth ports webshare_app/security/auth.py password semantics.
//
// Supported stored formats (parity with verify_password):
//
//	pbkdf2:<hash>:<iterations>$<salt>$<hexhash>  (Werkzeug v7.1+, stdlib PBKDF2)
//	64-char hex SHA-256 of the password            (legacy v4-v7.0)
//	plaintext                                       (legacy v3)
//
// Passwords are never logged. Comparisons are constant-time.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"strconv"
	"strings"
)

// DefaultIterations matches Werkzeug's pbkdf2 default used by hash_password.
const DefaultIterations = 1000000

// IsWerkzeugHash reports the current Werkzeug PBKDF2 hash format.
func IsWerkzeugHash(value string) bool {
	return strings.HasPrefix(value, "pbkdf2:") && strings.Contains(value, "$")
}

// IsLegacySHA256 reports the legacy unsalted SHA-256 hex format.
func IsLegacySHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// NeedsRehash reports whether a stored value should be migrated to PBKDF2
// after a successful login (parity with needs_password_rehash).
func NeedsRehash(stored string) bool {
	return stored != "" && !IsWerkzeugHash(stored)
}

// HashPassword creates a Werkzeug-compatible pbkdf2:sha256 hash.
func HashPassword(password string) (string, error) {
	saltBytes := make([]byte, 16)
	if _, err := rand.Read(saltBytes); err != nil {
		return "", err
	}
	salt := base64.StdEncoding.EncodeToString(saltBytes)
	sum := pbkdf2([]byte(password), []byte(salt), DefaultIterations, 32, sha256.New)
	return "pbkdf2:sha256:" + strconv.Itoa(DefaultIterations) + "$" + salt + "$" + hex.EncodeToString(sum), nil
}

// VerifyPassword checks a provided password against any supported stored
// format. Empty inputs never verify. Unknown $-formats fail closed.
func VerifyPassword(stored, provided string) bool {
	if stored == "" || provided == "" {
		return false
	}
	if strings.Contains(stored, "$") {
		return verifyWerkzeug(stored, provided)
	}
	if len(stored) == 64 {
		sum := sha256.Sum256([]byte(provided))
		return subtle.ConstantTimeCompare([]byte(stored), []byte(hex.EncodeToString(sum[:]))) == 1
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(provided)) == 1
}

func verifyWerkzeug(stored, provided string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 3 {
		return false
	}
	var hashName string
	var iterations int
	method := strings.Split(parts[0], ":")
	if len(method) == 3 && method[0] == "pbkdf2" {
		hashName = method[1]
		n, err := strconv.Atoi(method[2])
		if err != nil || n <= 0 {
			return false
		}
		iterations = n
	} else {
		// scrypt and other Werkzeug formats are never produced by this
		// app (hash_password only emits pbkdf2:sha256). Fail closed.
		return false
	}
	var newHash func() hash.Hash
	var keyLen int
	switch hashName {
	case "sha256":
		newHash, keyLen = sha256.New, 32
	case "sha512":
		newHash, keyLen = sha512.New, 64
	case "sha1":
		newHash, keyLen = sha1.New, 20
	default:
		return false
	}
	want, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	got := pbkdf2([]byte(provided), []byte(parts[1]), iterations, keyLen, newHash)
	if len(got) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// pbkdf2 is RFC 8018 PBKDF2-HMAC (stdlib has no exported primitive).
func pbkdf2(password, salt []byte, iterations, keyLen int, newHash func() hash.Hash) []byte {
	hLen := newHash().Size()
	blocks := (keyLen + hLen - 1) / hLen
	out := make([]byte, 0, blocks*hLen)
	var counter [4]byte
	for i := 1; i <= blocks; i++ {
		counter[0] = byte(i >> 24)
		counter[1] = byte(i >> 16)
		counter[2] = byte(i >> 8)
		counter[3] = byte(i)
		mac := hmac.New(newHash, password)
		mac.Write(salt)
		mac.Write(counter[:])
		u := mac.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for j := 1; j < iterations; j++ {
			mac = hmac.New(newHash, password)
			mac.Write(u)
			u = mac.Sum(nil)
			for k := range t {
				t[k] ^= u[k]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}
