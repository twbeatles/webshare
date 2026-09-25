package share

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s := &Store{
		root: t.TempDir(), links: map[string]*Link{},
		attempts: map[string]*attempt{}, now: time.Now,
	}
	return s
}

func TestAccessLifecycle(t *testing.T) {
	s := testStore(t)
	if _, ae := s.Access("nope"); ae == nil || ae.Status != 404 {
		t.Fatalf("missing = %+v", ae)
	}
	s.Create("tok", &Link{Path: "a.txt", Expires: time.Now().Add(time.Hour), MaxDownloads: 1})
	snap, ae := s.Access("tok")
	if ae != nil || snap.Path != "a.txt" {
		t.Fatalf("access = %+v %+v", snap, ae)
	}
	if ok, _ := s.ReserveDownload("tok"); !ok {
		t.Fatalf("reserve failed")
	}
	if _, ae := s.Access("tok"); ae == nil || ae.Status != 429 {
		t.Fatalf("over-limit = %+v", ae)
	}
	s.RollbackDownload("tok")
	if _, ae := s.Access("tok"); ae != nil {
		t.Fatalf("after rollback = %+v", ae)
	}
}

func TestExpiryAndList(t *testing.T) {
	s := testStore(t)
	s.Create("old", &Link{Path: "x", Expires: time.Now().Add(-time.Minute)})
	if _, ae := s.Access("old"); ae == nil || ae.Status != 410 {
		t.Fatalf("expired = %+v", ae)
	}
	if s.Get("old") != nil {
		t.Fatalf("expired link kept")
	}
	s.Create("fresh", &Link{Path: "y", Expires: time.Now().Add(time.Hour)})
	active := s.ListActive()
	if len(active) != 1 || active[0].Token != "fresh" {
		t.Fatalf("active = %+v", active)
	}
}

func TestPasswordAttempts(t *testing.T) {
	s := testStore(t)
	if blocked, _ := s.CheckBlocked("1.1.1.1", "tok"); blocked {
		t.Fatalf("fresh blocked")
	}
	for i := 0; i < MaxAttempts; i++ {
		s.RecordAttempt("1.1.1.1", "tok", false)
	}
	blocked, remaining := s.CheckBlocked("1.1.1.1", "tok")
	if !blocked || remaining <= 0 {
		t.Fatalf("blocked=%v remaining=%d", blocked, remaining)
	}
	s.RecordAttempt("1.1.1.1", "tok", true)
	if blocked, _ := s.CheckBlocked("1.1.1.1", "tok"); blocked {
		t.Fatalf("still blocked after success")
	}
	// Attempts persisted with newline-joined keys.
	data, err := os.ReadFile(filepath.Join(s.root, AttemptsFile))
	if err != nil {
		t.Fatalf("attempts file: %v", err)
	}
	_ = data
	s2 := &Store{root: s.root, links: map[string]*Link{}, attempts: map[string]*attempt{}, now: time.Now}
	s2.LoadAttempts()
	if len(s2.attempts) != 0 {
		t.Fatalf("reloaded attempts = %v", s2.attempts)
	}
}

func TestLinksPersistRoundtrip(t *testing.T) {
	s := testStore(t)
	exp := time.Now().Add(2 * time.Hour).Truncate(time.Second)
	s.Create("abc", &Link{
		Path: "d/f.txt", Expires: exp, CreatedBy: "admin",
		MaxDownloads: 3, DownloadCount: 1, CreatedAt: time.Now().Truncate(time.Second),
	})
	s2 := &Store{root: s.root, links: map[string]*Link{}, attempts: map[string]*attempt{}, now: time.Now}
	s2.LoadLinks()
	got := s2.Get("abc")
	if got == nil {
		t.Fatalf("link not reloaded")
	}
	if got.Path != "d/f.txt" || got.MaxDownloads != 3 || got.DownloadCount != 1 {
		t.Fatalf("reloaded = %+v", got)
	}
	// Naive datetimes compare as wall clock (mirrors Python naive compare).
	if FormatNaive(got.Expires) != FormatNaive(exp) {
		t.Fatalf("expires = %v want %v", got.Expires, exp)
	}
}

func TestNewTokenShape(t *testing.T) {
	tok, err := NewToken()
	if err != nil || len(tok) != 22 {
		t.Fatalf("token = %q %v", tok, err)
	}
}
