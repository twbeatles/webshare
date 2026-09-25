package auth

import (
	"encoding/json"
	"testing"
	"time"
)

func TestFlaskSessionVectors(t *testing.T) {
	var vectors struct {
		Secret string `json:"secret"`
		Cases  []struct {
			Name    string         `json:"name"`
			Cookie  string         `json:"cookie"`
			Payload map[string]any `json:"payload"`
			Secret  string         `json:"secret"`
			MaxAge  *int64         `json:"max_age"`
			Expect  string         `json:"expect"`
		} `json:"cases"`
	}
	loadVectors(t, "session_vectors.json", &vectors)
	now := time.Now()
	for _, c := range vectors.Cases {
		secret := c.Secret
		if secret == "" {
			secret = vectors.Secret
		}
		codec := FlaskCodec{Secret: secret, Salt: SessionCookieSalt}
		perm := FlaskPermanentLifetime
		maxAge := &perm
		if c.MaxAge != nil {
			d := time.Duration(*c.MaxAge) * time.Second
			maxAge = &d
		}
		payload, err := codec.Verify(c.Cookie, maxAge, now)
		switch c.Expect {
		case "valid":
			if err != nil {
				t.Errorf("%s: verify failed: %v", c.Name, err)
				continue
			}
			for k, want := range c.Payload {
				got, ok := payload[k]
				if !ok {
					t.Errorf("%s: missing key %q", c.Name, k)
					continue
				}
				if stringify(got) != stringify(want) {
					t.Errorf("%s: key %q = %v, want %v", c.Name, k, got, want)
				}
			}
		case "invalid":
			if err != ErrBadSignature {
				t.Errorf("%s: err = %v, want ErrBadSignature", c.Name, err)
			}
		case "expired":
			if err != ErrExpired {
				t.Errorf("%s: err = %v, want ErrExpired", c.Name, err)
			}
		default:
			t.Errorf("%s: unknown expectation %q", c.Name, c.Expect)
		}
	}
}

// stringify canonicalizes a decoded JSON scalar for comparison (both sides
// pass through encoding/json, so 1788000000.0 and 1788000000 compare equal).
func stringify(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

func TestFlaskCodecRoundTrip(t *testing.T) {
	a := FlaskCodec{Secret: "round-trip-secret", Salt: SessionCookieSalt}
	b := FlaskCodec{Secret: "round-trip-secret", Salt: SessionCookieSalt}
	payload := map[string]any{
		"logged_in":   true,
		"role":        "guest",
		"session_id":  "0123456789abcdef0123456789abcdef",
		"language":    "ko",
		"last_active": 1788000000.5,
	}
	cookie, err := a.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	perm := FlaskPermanentLifetime
	got, err := b.Verify(cookie, &perm, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got["role"] != "guest" || got["logged_in"] != true {
		t.Fatalf("round trip mismatch: %v", got)
	}
}

func TestSessionExpired(t *testing.T) {
	now := 1788000000.0
	if !SessionExpired(now-3601, 60, now) {
		t.Error("61 min idle with 60 min timeout should expire")
	}
	if SessionExpired(now-3600, 60, now) {
		t.Error("exactly 60 min idle must NOT expire (strict >)")
	}
	if SessionExpired(now-10, 60, now) {
		t.Error("fresh session expired")
	}
}
