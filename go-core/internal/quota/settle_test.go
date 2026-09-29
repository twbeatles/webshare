package quota

import "testing"

// ISSUE-006: reservations settle down to actual delivered bytes.
func TestSettleRefundsUndeliveredBytes(t *testing.T) {
	tr := NewTracker()
	ok, _, res := tr.Reserve("session:s", true, 1000, 0, 0)
	if !ok {
		t.Fatal("reserve denied")
	}
	tr.Settle(res, 400)
	if got := tr.entries["session:s"].bytes; got != 400 {
		t.Errorf("bytes after settle = %d, want 400", got)
	}
	if got := tr.entries["session:s"].count; got != 1 {
		t.Errorf("count after settle = %d, want 1 (kept)", got)
	}
	// Settlement never charges extra when actual exceeds the projection.
	tr.Settle(res, 5000)
	if got := tr.entries["session:s"].bytes; got != 400 {
		t.Errorf("bytes after over-settle = %d, want 400", got)
	}
	// Degenerate inputs are no-ops.
	tr.Settle(Reservation{}, 10)
	tr.Settle(Reservation{Key: "missing", Bytes: 5}, 0)
	if got := tr.entries["session:s"].bytes; got != 400 {
		t.Errorf("bytes after no-op settles = %d, want 400", got)
	}
}
