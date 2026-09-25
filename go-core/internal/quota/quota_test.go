package quota

import (
	"testing"
	"time"
)

func TestQuotaLifecycle(t *testing.T) {
	tr := NewTracker()
	now := time.Now()
	tr.now = func() time.Time { return now }

	if Key("sid1", "1.2.3.4") != "session:sid1" {
		t.Error("session key wrong")
	}
	if Key("", "1.2.3.4") != "ip:1.2.3.4" {
		t.Error("ip key wrong")
	}
	if Key("", "") != "ip:unknown" {
		t.Error("unknown key wrong")
	}

	// Unlimited by default (0 limits).
	ok, _, res := tr.Reserve("session:s", true, 100, 0, 0)
	if !ok {
		t.Fatal("unlimited reserve denied")
	}
	// Count limit: 1 per key.
	ok, _, _ = tr.Reserve("session:q", true, 0, 1, 0)
	if !ok {
		t.Fatal("first reserve denied")
	}
	if ok, msg, _ := tr.Reserve("session:q", true, 0, 1, 0); ok {
		t.Error("count limit not enforced")
	} else if msg != "Daily download limit exceeded (1)" {
		t.Errorf("count message = %q", msg)
	}
	// Bandwidth limit: 512KB fits in 1MB, one more byte overflows.
	if ok, _, _ := tr.Reserve("session:b", false, 512*1024, 0, 1); !ok {
		t.Fatal("first byte reserve denied")
	}
	if ok, msg, _ := tr.Reserve("session:b", false, 512*1024+1, 0, 1); ok {
		t.Error("bandwidth limit not enforced")
	} else if msg != "Daily bandwidth limit exceeded (1MB)" {
		t.Errorf("bandwidth message = %q", msg)
	}
	// Rollback restores.
	tr.Rollback(res)
	tr.Rollback(Reservation{})
	// New day resets.
	now = now.Add(25 * time.Hour)
	if ok, _, _ := tr.Reserve("session:q", true, 0, 1, 0); !ok {
		t.Error("next-day reserve denied")
	}
}
