package auth

import (
	"strings"
	"testing"
)

func TestGenerateCSRFTokenFormat(t *testing.T) {
	a, err := GenerateCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("tokens not unique")
	}
	if len(a) != 64 {
		t.Errorf("token length = %d, want 64", len(a))
	}
	for _, c := range a {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatalf("non-hex token: %q", a)
		}
	}
}

func TestValidateCSRFTokenSources(t *testing.T) {
	const session = "session-token-abc123"
	if !ValidateCSRFToken(session, "session-token-abc123", "", "") {
		t.Error("form token rejected")
	}
	if !ValidateCSRFToken(session, "", "session-token-abc123", "") {
		t.Error("header token rejected")
	}
	if !ValidateCSRFToken(session, "", "", "session-token-abc123") {
		t.Error("json token rejected")
	}
	// First non-empty wins: wrong form value is NOT rescued by a right header.
	if ValidateCSRFToken(session, "wrong", "session-token-abc123", "") {
		t.Error("form value should take precedence")
	}
	if ValidateCSRFToken("", "session-token-abc123", "", "") {
		t.Error("missing session token accepted")
	}
	if ValidateCSRFToken(session, "", "", "") {
		t.Error("missing provided token accepted")
	}
	if ValidateCSRFToken(session, "wrong", "", "") {
		t.Error("wrong token accepted")
	}
}
