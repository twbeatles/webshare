package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
)

// CSRF token semantics (parity with webshare_app/security/csrf.py).
//
// The token lives in the server session (_csrf_token, one per session) and
// the client returns it via form field "csrf_token", header
// "X-CSRF-Token", or JSON body "csrf_token" — first non-empty wins.
// Validation is constant-time; the token is single-use nowhere (session.get,
// not pop) so multiple tabs keep working.

// GenerateCSRFToken creates a session CSRF token (secrets.token_hex(32)).
func GenerateCSRFToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// ValidateCSRFToken checks the provided token against the session token.
func ValidateCSRFToken(sessionToken, formValue, headerValue, jsonValue string) bool {
	if sessionToken == "" {
		return false
	}
	provided := formValue
	if provided == "" {
		provided = headerValue
	}
	if provided == "" {
		provided = jsonValue
	}
	if provided == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(sessionToken), []byte(provided)) == 1
}
