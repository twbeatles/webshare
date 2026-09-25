package auth

import (
	"bytes"
	"compress/zlib"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

// Flask session cookie compatibility.
//
// Reference: Flask 3.1.3 SecureCookieSessionInterface with itsdangerous
// 2.2.0 URLSafeTimedSerializer(salt="cookie-session", key_derivation="hmac",
// digest SHA-1). Algorithms below mirror itsdangerous signer.py/timed.py/
// encoding.py exactly: urlsafe-base64 without padding, big-endian minimal
// timestamps, derived_key = HMAC-SHA1(secret, salt), sig =
// HMAC-SHA1(derived, value), constant-time compare.
//
// Payload JSON is parsed, never compared byte-wise, so Go-minted cookies
// (sorted keys) and Python-minted cookies (insertion order) verify both ways.

// SessionCookieSalt is Flask's session signer salt.
const SessionCookieSalt = "cookie-session"

// FlaskPermanentLifetime is Flask's default permanent_session_lifetime used
// as cookie max_age when opening sessions (31 days).
const FlaskPermanentLifetime = 31 * 24 * time.Hour

// ErrBadSignature is returned for malformed or forged cookies.
var ErrBadSignature = errors.New("bad session signature")

// ErrExpired is returned for correctly signed but too-old cookies.
var ErrExpired = errors.New("session signature expired")

// FlaskCodec signs and verifies Flask session cookies.
type FlaskCodec struct {
	// Secret is the Flask secret_key.
	Secret string
	// Salt is the signer salt ("cookie-session" in production).
	Salt string
}

func b64encodeRaw(b []byte) string {
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b)
}

func b64decodeRaw(s string) ([]byte, error) {
	if strings.ContainsAny(s, " \t\r\n") {
		return nil, errors.New("invalid base64")
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(s)
}

func (c FlaskCodec) deriveKey(secret string) []byte {
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write([]byte(c.Salt))
	return mac.Sum(nil)
}

// Sign creates a session cookie value for payload (JSON object), applying
// the itsdangerous URLSafe compression rule: zlib-compress when it saves
// more than one byte, marked with a "." prefix.
func (c FlaskCodec) Sign(payload map[string]any) (string, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return c.signRaw(dumpPayload(raw), time.Now().Unix()), nil
}

// dumpPayload mirrors URLSafeSerializerMixin.dump_payload.
func dumpPayload(raw []byte) string {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	_, _ = w.Write(raw)
	_ = w.Close()
	if buf.Len() < len(raw)-1 {
		return "." + b64encodeRaw(buf.Bytes())
	}
	return b64encodeRaw(raw)
}

// loadPayload mirrors URLSafeSerializerMixin.load_payload.
func loadPayload(part string) ([]byte, error) {
	raw := part
	compressed := false
	if strings.HasPrefix(raw, ".") {
		raw = raw[1:]
		compressed = true
	}
	decoded, err := b64decodeRaw(raw)
	if err != nil {
		return nil, err
	}
	if !compressed {
		return decoded, nil
	}
	r, err := zlib.NewReader(bytes.NewReader(decoded))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func (c FlaskCodec) signRaw(b64payload string, timestamp int64) string {
	var tsBytes [8]byte
	binary.BigEndian.PutUint64(tsBytes[:], uint64(timestamp))
	ts := b64encodeRaw(trimLeadingZeros(tsBytes[:]))
	value := b64payload + "." + ts
	mac := hmac.New(sha1.New, c.deriveKey(c.Secret))
	mac.Write([]byte(value))
	return value + "." + b64encodeRaw(mac.Sum(nil))
}

func trimLeadingZeros(b []byte) []byte {
	i := 0
	for i < len(b) && b[i] == 0 {
		i++
	}
	return b[i:]
}

// Verify decodes a session cookie. A nil maxAge disables the age check
// (mirrors itsdangerous max_age=None); pass FlaskPermanentLifetime for
// Flask's open_session behavior. Any non-nil maxAge — including zero or
// negative values — is enforced exactly like itsdangerous.
func (c FlaskCodec) Verify(cookie string, maxAge *time.Duration, now time.Time) (map[string]any, error) {
	value, sig, ok := splitLast(cookie, ".")
	if !ok {
		return nil, ErrBadSignature
	}
	sigBytes, err := b64decodeRaw(sig)
	if err != nil {
		return nil, ErrBadSignature
	}
	mac := hmac.New(sha1.New, c.deriveKey(c.Secret))
	mac.Write([]byte(value))
	if subtle.ConstantTimeCompare(sigBytes, mac.Sum(nil)) != 1 {
		return nil, ErrBadSignature
	}
	b64payload, b64ts, ok := splitLast(value, ".")
	if !ok {
		return nil, ErrBadSignature
	}
	tsBytes, err := b64decodeRaw(b64ts)
	if err != nil {
		return nil, ErrBadSignature
	}
	ts := int64(binary.BigEndian.Uint64(leftPad8(tsBytes)))
	payloadBytes, err := loadPayload(b64payload)
	if err != nil {
		return nil, ErrBadSignature
	}
	if maxAge != nil {
		age := now.Unix() - ts
		if age > int64(*maxAge/time.Second) || age < 0 {
			return nil, ErrExpired
		}
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, ErrBadSignature
	}
	if payload == nil {
		return nil, ErrBadSignature
	}
	return payload, nil
}

func splitLast(s, sep string) (string, string, bool) {
	i := strings.LastIndex(s, sep)
	if i < 0 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

func leftPad8(b []byte) []byte {
	if len(b) > 8 {
		return b[len(b)-8:]
	}
	out := make([]byte, 8)
	copy(out[8-len(b):], b)
	return out
}

// SessionExpired mirrors factory.py: last_active older than timeoutMinutes
// (strictly greater) means the session is expired.
func SessionExpired(lastActiveUnix float64, timeoutMinutes int, nowUnix float64) bool {
	if timeoutMinutes <= 0 {
		return false
	}
	return nowUnix-lastActiveUnix > float64(timeoutMinutes*60)
}
