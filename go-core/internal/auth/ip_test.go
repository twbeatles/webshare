package auth

import (
	"testing"
	"time"
)

func TestExtractClientIPVectors(t *testing.T) {
	var vectors struct {
		XFF []struct {
			XFF  string `json:"xff"`
			Hops int    `json:"hops"`
			Out  string `json:"out"`
		} `json:"xff_extract"`
	}
	loadVectors(t, "ip_vectors.json", &vectors)
	for i, c := range vectors.XFF {
		if got := ExtractClientIP(c.XFF, c.Hops); got != c.Out {
			t.Errorf("case %d: ExtractClientIP(%q, %d) = %q, want %q", i, c.XFF, c.Hops, got, c.Out)
		}
	}
}

func TestRealIPSpoofing(t *testing.T) {
	// Untrusted peer: headers ignored.
	if got := RealIP("9.9.9.9", "1.2.3.4", "", []string{"10.0.0.1"}, 1); got != "9.9.9.9" {
		t.Errorf("spoofed XFF trusted: %q", got)
	}
	// Trusted proxy: XFF honored with hop semantics.
	if got := RealIP("10.0.0.1", "1.2.3.4, 10.0.0.1", "", []string{"10.0.0.1"}, 1); got != "1.2.3.4" {
		t.Errorf("trusted XFF ignored: %q", got)
	}
	// Trusted proxy, empty XFF: X-Real-IP fallback, else peer.
	if got := RealIP("10.0.0.1", "", "1.2.3.5", []string{"10.0.0.1"}, 1); got != "1.2.3.5" {
		t.Errorf("X-Real-IP fallback failed: %q", got)
	}
	if got := RealIP("10.0.0.1", "", "", []string{"10.0.0.1"}, 1); got != "10.0.0.1" {
		t.Errorf("peer fallback failed: %q", got)
	}
}

func TestWhitelistVectors(t *testing.T) {
	var vectors struct {
		WL []struct {
			Whitelist []string `json:"whitelist"`
			IP        string   `json:"ip"`
			Expect    bool     `json:"expect"`
		} `json:"whitelist"`
		Limits struct {
			MaxAttempts  int `json:"max_attempts"`
			BlockMinutes int `json:"block_minutes"`
		} `json:"limits"`
	}
	loadVectors(t, "ip_vectors.json", &vectors)
	for i, c := range vectors.WL {
		if got := Whitelisted(c.IP, c.Whitelist); got != c.Expect {
			t.Errorf("case %d: Whitelisted(%q, %v) = %v, want %v", i, c.IP, c.Whitelist, got, c.Expect)
		}
	}
	if vectors.Limits.MaxAttempts != DefaultMaxAttempts || vectors.Limits.BlockMinutes != DefaultBlockMinutes {
		t.Errorf("limit constants diverged: %+v", vectors.Limits)
	}
}

func TestBlockTrackerLifecycle(t *testing.T) {
	tr := NewBlockTracker()
	now := time.Now()
	tr.now = func() time.Time { return now }

	if blocked, _ := tr.Blocked("1.2.3.4"); blocked {
		t.Fatal("unknown IP blocked")
	}
	for i := 0; i < DefaultMaxAttempts-1; i++ {
		tr.Record("1.2.3.4", false)
		if blocked, _ := tr.Blocked("1.2.3.4"); blocked {
			t.Fatalf("blocked after %d failures", i+1)
		}
	}
	tr.Record("1.2.3.4", false)
	blocked, remaining := tr.Blocked("1.2.3.4")
	if !blocked || remaining <= 0 {
		t.Fatalf("not blocked after %d failures (remaining=%d)", DefaultMaxAttempts, remaining)
	}
	// Success clears.
	tr.Record("1.2.3.4", true)
	if blocked, _ := tr.Blocked("1.2.3.4"); blocked {
		t.Fatal("success did not clear record")
	}
	if tr.Unblock("1.2.3.4") {
		t.Fatal("unblock reported phantom record")
	}
}

func TestBlockTrackerExpiry(t *testing.T) {
	tr := NewBlockTracker()
	now := time.Now()
	tr.now = func() time.Time { return now }
	for i := 0; i < DefaultMaxAttempts; i++ {
		tr.Record("5.6.7.8", false)
	}
	now = now.Add(time.Duration(DefaultBlockMinutes+1) * time.Minute)
	if blocked, _ := tr.Blocked("5.6.7.8"); blocked {
		t.Fatal("expired block still active")
	}
	// Expired block is dropped: re-blocking needs a full fresh count.
	if tr.Unblock("5.6.7.8") {
		t.Fatal("expired record not dropped")
	}
}
