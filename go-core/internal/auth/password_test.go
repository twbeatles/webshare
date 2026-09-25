package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func fixturePath(name string) string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "tests", "fixtures", "go_migration", "milestone_b", name)
}

func loadVectors(t *testing.T, name string, v any) {
	t.Helper()
	data, err := os.ReadFile(fixturePath(name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyPasswordVectors(t *testing.T) {
	var vectors struct {
		Cases []struct {
			Stored   string `json:"stored"`
			Provided string `json:"provided"`
			Expect   bool   `json:"expect"`
		} `json:"cases"`
	}
	loadVectors(t, "password_vectors.json", &vectors)
	if len(vectors.Cases) == 0 {
		t.Fatal("no password vectors")
	}
	for i, c := range vectors.Cases {
		if got := VerifyPassword(c.Stored, c.Provided); got != c.Expect {
			t.Errorf("case %d: VerifyPassword(%q, %q) = %v, want %v", i, c.Stored, c.Provided, got, c.Expect)
		}
	}
}

func TestHashPasswordRoundTrip(t *testing.T) {
	h, err := HashPassword("round-trip-secret")
	if err != nil {
		t.Fatal(err)
	}
	if !IsWerkzeugHash(h) {
		t.Fatalf("hash not werkzeug format: %q", h)
	}
	if !VerifyPassword(h, "round-trip-secret") {
		t.Fatal("fresh hash does not verify")
	}
	if VerifyPassword(h, "round-trip-secreu") {
		t.Fatal("wrong password verified")
	}
	if NeedsRehash(h) {
		t.Fatal("fresh hash flagged for rehash")
	}
	if !NeedsRehash("plaintext") {
		t.Fatal("plaintext not flagged for rehash")
	}
}

func TestVerifyPasswordFailClosed(t *testing.T) {
	// Formats the app never produces must not verify.
	for _, stored := range []string{
		"scrypt:32768:8:1$salt$abcd",
		"pbkdf2:md5:1000$salt$abcd",
		"pbkdf2:sha256:notanint$salt$abcd",
		"pbkdf2:sha256:1000$salt$zzzz",
		"argon2$foo",
	} {
		if VerifyPassword(stored, "anything") {
			t.Errorf("VerifyPassword(%q) = true, want false", stored)
		}
	}
}
