package quota

import "testing"

// A new session from the same ip cannot reset the daily limit (audit
// ISSUE-008): every client reservation also charges the ip key.
func TestReserveClientReloginKeepsIPUsage(t *testing.T) {
	tr := NewTracker()
	first := KeySet("s1", "10.0.0.5")
	for i := 0; i < 2; i++ {
		if ok, msg, _ := tr.ReserveClient(first, true, 10, 2, 0); !ok {
			t.Fatalf("download %d refused: %s", i, msg)
		}
	}
	second := KeySet("s2", "10.0.0.5")
	if ok, _, _ := tr.ReserveClient(second, true, 10, 2, 0); ok {
		t.Fatalf("re-login reset the daily download limit")
	}
	if ok, _ := tr.CheckClient(second, true, 0, 2, 0); ok {
		t.Fatalf("CheckClient allowed after limit")
	}
}

func TestClientReservationRollbackAndSettleAllKeys(t *testing.T) {
	tr := NewTracker()
	keys := KeySet("s1", "10.0.0.5")
	ok, _, res := tr.ReserveClient(keys, true, 1000, 0, 0)
	if !ok || len(res.Keys) != 2 {
		t.Fatalf("reserve = %v %+v", ok, res)
	}
	tr.Settle(res, 400)
	for _, k := range keys {
		if e := tr.entries[k]; e.bytes != 400 || e.count != 1 {
			t.Fatalf("%s after settle = %+v", k, *e)
		}
	}
	tr.Rollback(Reservation{Keys: keys, Count: 1, Bytes: 400})
	for _, k := range keys {
		if e := tr.entries[k]; e.bytes != 0 || e.count != 0 {
			t.Fatalf("%s after rollback = %+v", k, *e)
		}
	}
}

func TestKeySetWithoutSession(t *testing.T) {
	if got := KeySet("", "10.0.0.5"); len(got) != 1 || got[0] != "ip:10.0.0.5" {
		t.Fatalf("KeySet = %v", got)
	}
}
